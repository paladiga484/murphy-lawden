"""`ds autoscan` — scan every finished download the moment it lands, tell you the verdict.

A systemd --user path unit watches the torrent folder. qBittorrent keeps unfinished
data in `.incomplete/` and moves a torrent into the folder when it completes; that
move wakes the path unit, which runs `murphy ds autoscan`. It judges only what is
new since the last run (names, headers, ClamAV) and raises a desktop notification.
It never moves or deletes anything — `murphy ds scan --apply` is still your call.

It runs on the host, outside the client's sandbox, so the torrent client never needs
permission to start programs on your machine.
"""
from __future__ import annotations

import os
import shlex
import shutil
import time
from pathlib import Path

from ..core import have, run
from . import names, scan, state
from .names import CRIT, HIGH, WARN

UNIT = "murphy-ds-autoscan"
UNIT_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd/user"
STAMP = state.state_dir() / "autoscan.stamp"
LOG = state.state_dir() / "autoscan.log"
SKIP = {".incomplete"}


def _new_entries(folder: Path, since: float) -> list[Path]:
    out = []
    for p in folder.iterdir() if folder.is_dir() else ():
        if p.name in SKIP:
            continue
        try:
            if p.lstat().st_ctime > since:      # ctime moves on rename, so a completed move counts
                out.append(p)
        except OSError:
            continue
    return sorted(out)


def _notify(title: str, body: str, urgency: str) -> None:
    if have("notify-send"):
        run(["notify-send", "-a", "Murphy", "-u", urgency, "-i", "security-high", title, body])


def _log(line: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line + "\n")


def run_autoscan(folder: Path, ink) -> int:
    try:
        since = STAMP.stat().st_mtime
    except OSError:
        since = time.time() - 3600          # first run: only the last hour, not the whole archive
    worst_rc = 0
    for _ in range(5):                      # things may land while we scan; loop until quiet
        started = time.time()
        entries = _new_entries(folder, since)
        if not entries:
            break
        for entry in entries:
            hits = scan.judge_tree(entry)
            av_hits, notes = scan.engines(entry)
            hits += av_hits
            level = names.worst(hits)
            shown = names.safe(entry.name)
            top = next((h for h in sorted(hits, key=lambda h: -names.RANK[h.level])), None)
            reason = names.safe(top.reason) if top else ""
            if level == CRIT:
                _notify(f"Murphy: DO NOT OPEN — {shown}", f"{reason}\nmurphy ds scan --apply to quarantine",
                        "critical")
                worst_rc = max(worst_rc, 3)
            elif level == HIGH:
                _notify(f"Murphy: dangerous — {shown}", f"{reason}\nOnly through `murphy ds run`.",
                        "critical")
                worst_rc = max(worst_rc, 2)
            elif level == WARN:
                _notify(f"Murphy: caution — {shown}", reason, "normal")
                worst_rc = max(worst_rc, 1)
            else:
                _notify(f"Murphy: {shown} looks clean", "No red flags; ClamAV found nothing."
                        + (f"\n{notes[0]}" if notes else ""), "low")
            _log(f"{level or 'CLEAN'} {entry} {reason}")
            print(f"  {level or 'CLEAN':5} {shown}" + (f" — {reason}" if reason else ""))
        since = started
        STAMP.parent.mkdir(parents=True, exist_ok=True)
        STAMP.touch()
        os.utime(STAMP, (started, started))
    if not STAMP.exists():
        STAMP.parent.mkdir(parents=True, exist_ok=True)
        STAMP.touch()
    return worst_rc


def _murphy_cmd() -> list[str]:
    exe = shutil.which("murphy")
    if exe:
        return [exe]
    return [shutil.which("python3") or "python3",
            str(Path(__file__).resolve().parents[2] / "murphy.py")]


def install(folder: Path, out) -> int:
    if not have("systemctl"):
        out("x", "systemd isn't available")
        return 2
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = " ".join(shlex.quote(c) for c in _murphy_cmd())
    (UNIT_DIR / f"{UNIT}.path").write_text(
        "[Unit]\nDescription=Murphy ds: watch the torrent folder for finished downloads\n\n"
        f"[Path]\nPathChanged={folder}\nUnit={UNIT}.service\n\n"
        "[Install]\nWantedBy=default.target\n")
    (UNIT_DIR / f"{UNIT}.service").write_text(
        "[Unit]\nDescription=Murphy ds: scan newly finished downloads\n\n"
        "[Service]\nType=oneshot\n"
        f"ExecStart={cmd} ds --folder {shlex.quote(str(folder))} autoscan\n"
        "Nice=10\nIOSchedulingClass=idle\n")
    ok = (run(["systemctl", "--user", "daemon-reload"])[0] == 0
          and run(["systemctl", "--user", "enable", "--now", f"{UNIT}.path"])[0] == 0)
    STAMP.parent.mkdir(parents=True, exist_ok=True)
    STAMP.touch()                           # start from now; old downloads aren't re-announced
    out("+" if ok else "x", f"autoscan: watching {folder} — every finished download gets scanned "
                            "and you get a notification with the verdict")
    return 0 if ok else 1


def uninstall(out) -> int:
    run(["systemctl", "--user", "disable", "--now", f"{UNIT}.path"])
    for ext in ("path", "service"):
        (UNIT_DIR / f"{UNIT}.{ext}").unlink(missing_ok=True)
    run(["systemctl", "--user", "daemon-reload"])
    out("+", "autoscan: removed")
    return 0


def status() -> tuple[bool, str]:
    rc, out = run(["systemctl", "--user", "is-active", f"{UNIT}.path"])
    return out.strip() == "active", out.strip() or "not installed"
