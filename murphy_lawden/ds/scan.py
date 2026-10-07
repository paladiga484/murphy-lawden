"""After the download: judge every real file, run the AV engine, quarantine on --apply.

Read-only unless told otherwise. Quarantine *moves* (never deletes): the file goes
to Murphy's state dir with a `.quarantined` suffix and no permissions, and an
index records where it came from and its SHA-256, so you can look the hash up
yourself (Murphy never uploads anything).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import sys
import time
from pathlib import Path

from .. import clamav
from ..core import run
from . import names
from .names import CRIT, HIGH, Hit
from .state import QUARANTINE

WINDOWS = sys.platform == "win32"
PARTIAL = ".!qb"


def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for d in list(dirnames):
            p = Path(dirpath) / d
            if p.is_symlink():
                yield p
        for f in filenames:
            yield Path(dirpath) / f


def judge_tree(root: Path) -> list[Hit]:
    files = list(_walk(root))
    sizes = []
    for f in files:
        try:
            sizes.append((str(f), f.lstat().st_size))
        except OSError:
            pass
    media = names.media_context([(n.removesuffix(".!qB"), s) for n, s in sizes], root.name)
    real_root = root.resolve()
    hits: list[Hit] = []
    for f in files:
        shown = str(f)
        name = shown[:-len(PARTIAL)] if shown.lower().endswith(PARTIAL) else shown
        if f.is_symlink():
            try:
                target = f.resolve()
                inside = target == real_root or real_root in target.parents
            except (OSError, RuntimeError):
                inside = False
            if not inside:
                hits.append(Hit(CRIT, shown, f"symlink pointing outside the folder → "
                                             f"{os.readlink(f)} (writes through it land elsewhere)"))
            continue
        try:
            regular = stat.S_ISREG(f.lstat().st_mode)
        except OSError:
            continue
        if not regular:                 # FIFO/socket/device: reading it could hang or worse
            hits.append(Hit(HIGH, shown, "not a regular file (FIFO, socket or device node)"))
            continue
        base = root if root.is_dir() else root.parent
        mine = names.judge_name(os.path.relpath(name, base), media)
        try:
            with open(f, "rb") as fh:
                mine += names.judge_header(name, fh.read(16))
        except OSError:
            pass
        if not WINDOWS:
            try:
                if f.stat().st_mode & 0o111 and names.ext(name) in names.MEDIA | names.DOCS:
                    mine.append(Hit(HIGH, shown, "media/document file with the executable bit set"))
            except OSError:
                pass
        for h in mine:
            h.path = shown                 # always the real on-disk path
        hits += mine
    return hits


# ---- engines ---------------------------------------------------------------- #
def av_linux(root: Path) -> tuple[list[Hit], list[str]]:
    notes = []
    if not clamav.available():
        return [], ["ClamAV not installed — no signature scan (`sudo pacman -S clamav`)"]
    st = clamav.db_status()
    if not st.present:
        return [], [f"ClamAV has no signatures ({st.detail}) — run `sudo freshclam`"]
    if st.age_days is not None and st.age_days > 7:
        notes.append(f"ClamAV {st.detail} — stale; `sudo freshclam` before trusting a clean result")
    rc, out = run(["clamscan", "-r", "-i", "--no-summary", "--stdout",
                   "--scan-archive=yes", "--alert-encrypted=yes", "--alert-macros=yes",
                   "--max-filesize=4000M", "--max-scansize=4000M", str(root)], timeout=6 * 3600)
    hits = []
    for line in out.splitlines():
        if line.rstrip().endswith("FOUND"):
            path, _, sig = line.rpartition(":")
            sig = sig.replace("FOUND", "").strip()
            level = HIGH if sig.startswith("Heuristics.Encrypted") else CRIT
            hits.append(Hit(level, path.strip(), f"ClamAV: {sig}"))
    if rc not in (0, 1):
        notes.append(f"clamscan exited {rc} — some files could not be scanned")
    return hits, notes


def _mpcmdrun() -> Path | None:
    for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),):
        p = Path(base) / "Windows Defender" / "MpCmdRun.exe"
        if p.exists():
            return p
    plat = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft/Windows Defender/Platform"
    found = sorted(plat.glob("*/MpCmdRun.exe")) if plat.is_dir() else []
    return found[-1] if found else None


def av_windows(root: Path) -> tuple[list[Hit], list[str]]:
    exe = _mpcmdrun()
    if not exe:
        return [], ["Microsoft Defender's MpCmdRun.exe not found — no signature scan"]
    run([str(exe), "-SignatureUpdate"], timeout=600)
    rc, out = run([str(exe), "-Scan", "-ScanType", "3", "-File", str(root),
                   "-DisableRemediation"], timeout=6 * 3600)
    hits = []
    threat = ""
    for line in out.splitlines():
        s = line.strip()
        if s.lower().startswith("threat"):
            threat = s.split(":", 1)[-1].strip()
        elif s.lower().startswith("file") and threat:
            hits.append(Hit(CRIT, s.split(":", 1)[-1].strip(), f"Defender: {threat}"))
    if rc == 2 and not hits:
        hits.append(Hit(CRIT, str(root), "Defender reports threats (see Windows Security → history)"))
    notes = [] if rc in (0, 2) else [f"MpCmdRun exited {rc}"]
    return hits, notes


def engines(root: Path) -> tuple[list[Hit], list[str]]:
    return av_windows(root) if WINDOWS else av_linux(root)


# ---- quarantine ------------------------------------------------------------- #
def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _index() -> Path:
    return QUARANTINE / "index.json"


def quarantine(path: Path, reasons: list[str]) -> dict:
    QUARANTINE.mkdir(parents=True, exist_ok=True)
    if not WINDOWS:
        os.chmod(QUARANTINE, 0o700)
    qid = time.strftime("%Y%m%d-%H%M%S") + "-" + hashlib.sha1(str(path).encode()).hexdigest()[:6]
    dest_dir = QUARANTINE / qid
    dest_dir.mkdir()
    entry = {"id": qid, "original": str(path), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
             "reasons": reasons}
    if path.is_symlink():
        entry["symlink_to"] = os.readlink(path)
        path.unlink()
    elif not stat.S_ISREG(path.lstat().st_mode):     # FIFO/socket/device: no content to keep
        entry["special"] = stat.filemode(path.lstat().st_mode)
        path.unlink()
    else:
        entry["sha256"] = _sha256(path)
        dest = dest_dir / (path.name + ".quarantined")
        shutil.move(str(path), dest)
        if not WINDOWS:
            os.chmod(dest, 0)
        entry["stored"] = str(dest)
    idx = listing()
    idx.append(entry)
    _index().write_text(json.dumps(idx, indent=2))
    return entry


def listing() -> list[dict]:
    try:
        return json.loads(_index().read_text())
    except (OSError, ValueError):
        return []
