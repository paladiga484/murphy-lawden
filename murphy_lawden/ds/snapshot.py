"""`ds snapshot` — a known-good point to come back to, taken before you torrent.

Three layers, each used when the machine has it:

  * the persistence manifest (every OS, no root): a hash of every file in the places
    malware uses to start itself again — autostart, systemd user units, shell
    startup files, ~/.local/bin, desktop entries, D-Bus services, SSH keys, cron —
    plus the Run keys of every Wine/Proton prefix, and a copy of the small files.
    This is what `ds nuke` compares against to tell you what changed.
  * a read-only btrfs snapshot of /home (sudo): the whole home as it was, which a
    program running as you cannot alter or delete. Taken right after the manifest,
    so it also holds a tamper-proof copy of it.
  * a snapper snapshot of / (sudo, when snapper is set up): the system, bootable
    from the GRUB menu if it ever comes to that.

On Windows the system layer is a System Restore point.

A btrfs snapshot costs nothing when taken but pins whatever later changes, so only
the newest KEEP are kept; `ds snapshot --drop` removes them all.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from ..core import have, run
from . import state

WINDOWS = sys.platform == "win32"
HOME = Path.home()
DIR = state.state_dir() / "snapshots"
HOME_SNAPS = Path("/home/.murphy-snapshots")
KEEP = 2
COPY_MAX = 4 << 20          # files bigger than this are hashed by size+mtime and not copied
HASH_MAX = 64 << 20

# where a program running as you can make itself start again
SPOTS = [".config/autostart", ".config/systemd/user", ".config/environment.d", ".config/fish",
         ".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv",
         ".xprofile", ".xinitrc", ".xsession", ".pam_environment", ".local/bin",
         ".local/share/applications", ".local/share/dbus-1/services", ".config/hypr",
         ".config/niri", ".config/plasma-workspace/env", ".config/plasma-workspace/shutdown",
         ".config/mimeapps.list", ".ssh/authorized_keys", ".ssh/config", ".ssh/rc",
         ".gnupg/gpg-agent.conf", ".config/pip/pip.conf", ".npmrc", ".gitconfig",
         ".config/git/config"]
# changes here are routine, not persistence: fish rewrites its universal variables all the
# time, and Claude Code's launcher symlink moves with every update
IGNORE = {".config/fish/fish_variables", ".local/bin/claude"}
# Murphy's own watchers (exact names only — a look-alike name is still reported)
for _u in ("murphy-ds-sentinel.path", "murphy-ds-sentinel.service", "murphy-ds-sentinel.timer",
           "murphy-ds-autoscan.path", "murphy-ds-autoscan.service",
           "murphy-ds-ipfilter.service", "murphy-ds-ipfilter.timer"):
    IGNORE.add(f".config/systemd/user/{_u}")
IGNORE |= {".config/systemd/user/default.target.wants/murphy-ds-sentinel.path",
           ".config/systemd/user/default.target.wants/murphy-ds-autoscan.path",
           ".config/systemd/user/timers.target.wants/murphy-ds-sentinel.timer",
           ".config/systemd/user/timers.target.wants/murphy-ds-ipfilter.timer"}
WIN_SPOTS = ["AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"]
# Wine/Proton prefixes: a Windows program's "start me at login" lives in the prefix registry
PREFIX_ROOTS = [".wine", ".local/share/Steam/steamapps/compatdata", ".local/share/lutris/prefixes",
                "Games", "Torrents"]
_RUN_SECTIONS = re.compile(r"^\[(Software\\\\(?:Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\"
                           r"(?:Run|RunOnce|RunServices|Policies\\\\Explorer\\\\Run)|"
                           r"Software\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Winlogon)\]", re.I)


def _digest(p: Path) -> str:
    st = p.lstat()
    if p.is_symlink():
        return "link:" + os.readlink(p)
    if st.st_size > HASH_MAX:
        return f"big:{st.st_size}:{int(st.st_mtime)}"
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _walk_spot(rel: str):
    p = HOME / rel
    if p.is_symlink() or p.is_file():
        yield p
    elif p.is_dir():
        for root, dirs, files in os.walk(p):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for f in files:
                yield Path(root, f)


def _prefixes() -> list[Path]:
    """Every Wine/Proton prefix under the usual roots (the folder holding system.reg)."""
    found = []
    for rel in PREFIX_ROOTS:
        base = HOME / rel
        if not base.is_dir():
            continue
        for root, dirs, files in os.walk(base):
            if "user.reg" in files and "system.reg" in files:
                found.append(Path(root))
                dirs[:] = []                       # nothing to find inside a prefix
            elif Path(root).name == "drive_c" or len(Path(root).relative_to(base).parts) > 6:
                dirs[:] = []
    return found


def run_keys(prefix: Path) -> list[str]:
    """`section: value` for every autostart entry in a prefix's registry."""
    out = []
    for hive in ("user.reg", "system.reg"):
        try:
            text = (prefix / hive).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        section = None
        for line in text.splitlines():
            if line.startswith("["):
                section = line if _RUN_SECTIONS.match(line) else None
            elif section and line.startswith('"'):
                if "Winlogon" in section and not line.lower().startswith(('"shell"', '"userinit"')):
                    continue
                out.append(f"{hive}:{section.split(']')[0][1:]}:{line}")
    return out


def crontab() -> str:
    if WINDOWS or not have("crontab"):
        return ""
    rc, out = run(["crontab", "-l"])
    return out if rc == 0 else ""


def manifest() -> dict:
    files = {}
    for rel in (WIN_SPOTS if WINDOWS else SPOTS):
        for p in _walk_spot(rel):
            if str(p.relative_to(HOME)) in IGNORE:
                continue
            try:
                files[str(p.relative_to(HOME))] = _digest(p)
            except OSError:
                continue
    return {"taken": time.strftime("%Y-%m-%d %H:%M:%S"), "files": files, "crontab": crontab(),
            "run_keys": {str(p.relative_to(HOME)): run_keys(p) for p in _prefixes()}}


def _sudo(cmd: list[str]) -> int:
    return subprocess.run(["sudo", *cmd]).returncode


def btrfs_home() -> bool:
    if WINDOWS or not have("btrfs"):
        return False
    return run(["stat", "-f", "-c", "%T", "/home"])[1].strip() == "btrfs"


def snapper_root() -> bool:
    return not WINDOWS and have("snapper") and "root" in run(["snapper", "list-configs"])[1]


def take(out, layers: bool = True) -> int:
    sid = time.strftime("%Y%m%d-%H%M%S")
    d = DIR / sid
    d.mkdir(parents=True)
    os.chmod(DIR, 0o700)
    m = manifest()
    (d / "manifest.json").write_text(json.dumps(m, indent=1))
    with tarfile.open(d / "spots.tar.gz", "w:gz") as tar:
        for rel in m["files"]:
            p = HOME / rel
            try:
                if p.is_symlink() or p.stat().st_size <= COPY_MAX:
                    tar.add(p, arcname=rel, recursive=False)
            except OSError:
                continue
    nkeys = sum(len(v) for v in m["run_keys"].values())
    out("+", f"persistence manifest: {len(m['files'])} startup files, {len(m['run_keys'])} Wine/Proton "
             f"prefixes ({nkeys} autostart entries) → {d}")
    meta = {"id": sid}
    if layers and WINDOWS:
        rc, _ = run(["powershell", "-NoProfile", "-Command",
                     "Checkpoint-Computer -Description 'murphy ds: pre-torrent' "
                     "-RestorePointType MODIFY_SETTINGS"], timeout=300)
        out("+" if rc == 0 else "!", "Windows restore point " + ("created" if rc == 0 else
            "failed — needs an admin terminal, and System Protection on for C:"))
    elif layers:
        if btrfs_home():
            dest = HOME_SNAPS / f"pre-torrent-{sid}"
            ok = _sudo(["sh", "-c", f"mkdir -p {HOME_SNAPS} && chmod 755 {HOME_SNAPS} && "
                                    f"btrfs subvolume snapshot -r /home {dest} >/dev/null"]) == 0
            if ok:
                meta["home"] = str(dest)
                out("+", f"read-only snapshot of /home: {dest} (nothing running as you can change it)")
            else:
                out("!", "btrfs snapshot of /home failed (sudo refused?)")
        else:
            out("=", "/home is not btrfs: no whole-home snapshot, the manifest copy is the fallback")
        if snapper_root():
            desc = f"murphy ds: pre-torrent {sid}"
            rc = subprocess.run(["sudo", "snapper", "-c", "root", "create", "--print-number",
                                 "--description", desc, "--userdata", "important=yes"],
                                capture_output=True, text=True)
            num = snapper_number(desc) if rc.returncode == 0 else None
            if num is not None:
                meta["snapper"] = num
                out("+", f"snapper snapshot #{num} of / — bootable from the GRUB "
                         "snapshots menu if the system itself is ever in doubt")
            else:
                why = (rc.stderr or rc.stdout).strip().splitlines()[-1:] or [f"exit {rc.returncode}"]
                out("!", f"snapper snapshot of / not confirmed ({why[0]}) — check: sudo snapper -c root list")
        else:
            out("=", "no snapper config for /: system snapshot skipped")
    (d / "meta.json").write_text(json.dumps(meta))
    _prune(out)
    return 0


def snapper_number(desc: str) -> int | None:
    """Find a snapshot by its (unique) description — sturdier than parsing --print-number,
    whose output a sudo pseudo-terminal (use_pty) can mangle."""
    rc = subprocess.run(["sudo", "snapper", "-c", "root", "--machine-readable", "csv", "list",
                         "--columns", "number,description"], capture_output=True, text=True)
    for line in rc.stdout.splitlines():
        num, _, d = line.strip().partition(",")
        if d.strip().strip('"') == desc and num.isdigit():
            return int(num)
    return None


def listing() -> list[dict]:
    snaps = []
    for d in sorted(DIR.glob("*/meta.json")) if DIR.is_dir() else []:
        try:
            meta = json.loads(d.read_text())
        except (OSError, ValueError):
            continue
        meta["dir"] = str(d.parent)
        snaps.append(meta)
    return snaps


def latest() -> dict | None:
    s = listing()
    return s[-1] if s else None


def _drop_one(meta: dict, out) -> None:
    if meta.get("home") and Path(meta["home"]).exists():
        if _sudo(["btrfs", "subvolume", "delete", meta["home"]]) == 0:
            out("+", f"dropped {meta['home']}")
    if meta.get("snapper") is not None:
        if _sudo(["snapper", "-c", "root", "delete", str(meta["snapper"])]) == 0:
            out("+", f"dropped snapper #{meta['snapper']}")
    shutil.rmtree(meta["dir"], ignore_errors=True)


def _prune(out) -> None:
    for meta in listing()[:-KEEP]:
        out("=", f"keeping the newest {KEEP} — dropping {meta['id']}")
        _drop_one(meta, out)


def drop_all(out) -> int:
    for meta in listing():
        _drop_one(meta, out)
    out("+", "no pre-torrent snapshots left")
    return 0


def _in_home_snap(meta: dict, rel) -> Path | None:
    """Where `~/rel` lives inside the /home snapshot, if there is one."""
    if not meta.get("home"):
        return None
    try:
        return Path(meta["home"]) / HOME.relative_to("/home") / rel
    except ValueError:                             # a home outside /home isn't in that snapshot
        return None


def stored_manifest(meta: dict) -> tuple[dict | None, str]:
    """The manifest to trust: the copy inside the read-only home snapshot when there
    is one (nothing running as you could have edited it), else the local one."""
    try:
        rel = Path(meta["dir"]).relative_to(HOME)
    except ValueError:
        rel = None
    snap = _in_home_snap(meta, rel) if rel is not None else None
    if snap is not None:
        p = snap / "manifest.json"
        try:
            return json.loads(p.read_text()), "read-only snapshot"
        except (OSError, ValueError):
            pass
    try:
        return json.loads((Path(meta["dir"]) / "manifest.json").read_text()), \
            "local copy (a program running as you could have edited it)"
    except (OSError, ValueError):
        return None, ""


def compare(meta: dict) -> dict:
    """What changed in the startup places since the snapshot."""
    then, source = stored_manifest(meta)
    if then is None:
        return {"error": "the snapshot's manifest is missing"}
    now = manifest()
    a = {k: v for k, v in then["files"].items() if k not in IGNORE}   # older baselines kept them
    b = now["files"]
    keys_then = {k for v in then["run_keys"].values() for k in v}
    # Murphy's own files (the qBittorrent jail): accepted only if byte-identical to what it writes
    try:
        from . import jail
        for path, text in jail.expected().items():
            rel = str(path.relative_to(HOME))
            if rel in b and path.is_file() and path.read_text(errors="replace") == text:
                b = {k: v for k, v in b.items() if k != rel}
                a = {k: v for k, v in a.items() if k != rel}
    except (OSError, ValueError, ImportError):
        pass
    return {"source": source, "taken": then["taken"],
            "new": sorted(set(b) - set(a)),
            "changed": sorted(k for k in set(a) & set(b) if a[k] != b[k]),
            "removed": sorted(set(a) - set(b)),
            "crontab": then["crontab"] != now["crontab"],
            "run_keys": sorted({f"{p}: {k}" for p, v in now["run_keys"].items()
                                for k in v if k not in keys_then})}


def restore_file(meta: dict, rel: str) -> bool:
    """Put one startup file back as it was in the snapshot."""
    dest = HOME / rel
    src = _in_home_snap(meta, rel)
    if src is not None:
        if src.exists() or src.is_symlink():
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.is_symlink() or dest.exists():
                dest.unlink()
            shutil.copy2(src, dest, follow_symlinks=False)
            return True
    try:
        with tarfile.open(Path(meta["dir"]) / "spots.tar.gz") as tar:
            member = tar.getmember(rel)
            try:
                tar.extract(member, HOME, filter="data")
            except TypeError:                      # Python before 3.12 has no filter
                tar.extract(member, HOME)
            return True
    except (OSError, KeyError, tarfile.TarError):
        return False
