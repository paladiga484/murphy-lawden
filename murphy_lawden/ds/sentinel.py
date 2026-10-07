"""`ds sentinel` — a desktop notification the moment something tries to make itself
start again.

Two systemd *user* units (no root, removable with --uninstall):
  * a path unit watching the startup places — autostart, systemd user units, shell
    and fish startup files, ~/.local/bin, desktop entries, D-Bus services — and the
    registry of every Wine/Proton prefix, where a Windows program registers itself
    to run at login;
  * a timer that runs the same check every 30 minutes and shortly after login, for
    anything the path unit can't watch (your crontab, new prefixes).

Either one runs `murphy ds snapshot --check --notify`: it compares against your last
`ds snapshot` and, only if something changed, pops a critical notification saying
what. The same finding is announced once, not every half hour.

It only reports. What to do about it stays your call: `murphy ds snapshot --restore`
puts startup files back; if the change was yours, `murphy ds snapshot` takes a new
baseline and the alert stops.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

from ..core import have, run
from . import snapshot, state

UNIT = "murphy-ds-sentinel"
UNIT_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd/user"
LAST = state.state_dir() / "sentinel.last"


def _murphy_cmd() -> list[str]:
    from .autoscan import _murphy_cmd as mc
    return mc()


def watched() -> list[Path]:
    """Every existing startup place, plus each prefix's registry hives."""
    paths = []
    for rel in snapshot.SPOTS:
        p = snapshot.HOME / rel
        if p.is_dir():
            paths.append(p)
            paths += [Path(r) for r, _, _ in os.walk(p)][1:8]   # a few subfolders (fish/conf.d …)
        elif p.exists():
            paths.append(p)
    for prefix in snapshot._prefixes():
        paths += [prefix / h for h in ("user.reg", "system.reg") if (prefix / h).exists()]
    seen, out = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def install(out) -> int:
    if not have("systemctl"):
        out("x", "systemd isn't available")
        return 2
    if snapshot.latest() is None:
        out("!", "no snapshot yet — taking a baseline first (the check compares against it)")
        snapshot.take(out, layers=False)
    cmd = " ".join(shlex.quote(c) for c in _murphy_cmd())
    UNIT_DIR.mkdir(parents=True, exist_ok=True)
    paths = watched()
    (UNIT_DIR / f"{UNIT}.service").write_text(
        "[Unit]\nDescription=Murphy ds: did anything make itself start again?\n\n"
        f"[Service]\nType=oneshot\nExecStart={cmd} ds snapshot --check --notify\n"
        "Nice=10\nIOSchedulingClass=idle\n")
    (UNIT_DIR / f"{UNIT}.path").write_text(
        "[Unit]\nDescription=Murphy ds: watch the places malware starts itself from\n\n[Path]\n"
        + "".join(f"PathChanged={p}\n" for p in paths)
        + f"Unit={UNIT}.service\n\n[Install]\nWantedBy=default.target\n")
    (UNIT_DIR / f"{UNIT}.timer").write_text(
        "[Unit]\nDescription=Murphy ds: re-check the startup places every 30 minutes\n\n"
        f"[Timer]\nOnStartupSec=3min\nOnUnitActiveSec=30min\nUnit={UNIT}.service\n\n"
        "[Install]\nWantedBy=timers.target\n")
    ok = run(["systemctl", "--user", "daemon-reload"])[0] == 0 and \
        run(["systemctl", "--user", "enable", "--now", f"{UNIT}.path", f"{UNIT}.timer"])[0] == 0
    out("+" if ok else "x", f"sentinel: watching {len(paths)} startup places and prefix registries, "
                            "plus a check every 30 minutes — you get a notification if anything changes")
    out("=", "re-run `murphy ds sentinel --install` after adding games (new prefixes get watched)")
    return 0 if ok else 1


def uninstall(out) -> int:
    run(["systemctl", "--user", "disable", "--now", f"{UNIT}.path", f"{UNIT}.timer"])
    for ext in ("path", "timer", "service"):
        (UNIT_DIR / f"{UNIT}.{ext}").unlink(missing_ok=True)
    run(["systemctl", "--user", "daemon-reload"])
    LAST.unlink(missing_ok=True)
    out("+", "sentinel: removed")
    return 0


def status() -> tuple[bool, str]:
    p = run(["systemctl", "--user", "is-active", f"{UNIT}.path"])[1].strip()
    t = run(["systemctl", "--user", "is-active", f"{UNIT}.timer"])[1].strip()
    return p == "active" and t == "active", f"path {p or 'not installed'}, timer {t or 'not installed'}"


def notify(d: dict) -> None:
    """One critical notification per distinct finding set."""
    lines = [f"new: ~/{r}" for r in d["new"]] + [f"changed: ~/{r}" for r in d["changed"]] \
        + [f"removed: ~/{r}" for r in d["removed"]] + [f"Windows autostart: {k}" for k in d["run_keys"]] \
        + (["your crontab changed"] if d["crontab"] else [])
    if not lines:
        LAST.unlink(missing_ok=True)
        return
    digest = hashlib.sha256("\n".join(lines).encode()).hexdigest()
    try:
        if LAST.read_text().strip() == digest:
            return
    except OSError:
        pass
    LAST.parent.mkdir(parents=True, exist_ok=True)
    LAST.write_text(digest)
    body = "\n".join(lines[:6]) + (f"\n… and {len(lines) - 6} more" if len(lines) > 6 else "") \
        + "\n\nmurphy ds snapshot --check   (yours? murphy ds snapshot)"
    if shutil.which("notify-send"):
        subprocess.run(["notify-send", "-u", "critical", "-a", "Murphy Lawden",
                        "Murphy: something changed where programs start themselves", body],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
