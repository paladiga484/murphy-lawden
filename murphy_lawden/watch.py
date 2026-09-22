"""``murphy watch`` — the optional sentinel daemon.

Murphy is amnesiac: a scan writes nothing. ``watch`` is the one long-running
mode, and it keeps faith with that promise. By default it holds the baseline in
memory and only speaks up when your security *posture changes* — a check that
was passing starts failing, a fresh malware/IOC indicator appears, or the
hardening score drops. It is a tripwire, not a logger.

Nothing touches disk unless you opt in:

  * ``--state DIR``          persist the baseline so drift survives a restart.
  * ``--install-service``    write an *optional* systemd **user** unit (removable
                             with ``--uninstall-service``); Murphy writes the
                             file but never enables it for you.

Everything here is stdlib-only and failure-tolerant, exactly like the checks.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Importing these registers every check with the core registry (same as the CLI).
from . import checks_linux   # noqa: F401
from . import checks_malware  # noqa: F401
from . import checks_android  # noqa: F401
from . import checks_firmware  # noqa: F401
from .core import Status, detect_host, run_checks
from .rules import load_pack, run_pack

SERVICE_NAME = "murphy-watch.service"


# --------------------------------------------------------------------------- #
#  Collecting the posture (checks + bundled packs), no argparse needed
# --------------------------------------------------------------------------- #
_BUNDLED_PACKS = Path(__file__).resolve().parent.parent / "packs"


def _collect() -> tuple[object, list]:
    """Run the read-only checks + the bundled pack library, deduped — the same
    posture a plain ``murphy scan`` sees, minus anything that needs the network."""
    host = detect_host()
    findings = list(run_checks(host))
    if _BUNDLED_PACKS.is_dir():
        for pack in sorted(_BUNDLED_PACKS.glob("*.json")):
            try:
                findings += list(run_pack(load_pack(str(pack)), host, pack_name=pack.name))
            except Exception:
                pass  # a broken pack must never take the sentinel down
    seen: set[str] = set()
    out = []
    for f in findings:
        if f.dedupe_key:
            if f.dedupe_key in seen:
                continue
            seen.add(f.dedupe_key)
        out.append(f)
    return host, out


def _snapshot(findings: list) -> dict:
    """Reduce findings to the comparable essence: which checks fail/warn, which
    malware indicators are live, and the score."""
    from .cli import score, grade, is_malware_finding

    def key(f):
        return f"{f.id}|{f.title}"

    fails = {key(f): f.severity.name for f in findings if f.status == Status.FAIL}
    warns = {key(f): f.severity.name for f in findings if f.status == Status.WARN}
    mal = sorted(key(f) for f in findings
                 if is_malware_finding(f) and f.status in (Status.FAIL, Status.WARN))
    s = score(findings)
    return {"fails": fails, "warns": warns, "mal": mal, "score": s, "grade": grade(s)}


def _diff(old: dict, new: dict) -> tuple[list[tuple[str, str]], int]:
    """Return (events, score_delta). Each event is (kind, label)."""
    events: list[tuple[str, str]] = []
    for k in sorted(set(new["fails"]) - set(old["fails"])):
        events.append(("REGRESSED", f"{k.split('|', 1)[1]}  [{new['fails'][k]}]"))
    for k in sorted(set(new["mal"]) - set(old["mal"])):
        events.append(("MALWARE", k.split("|", 1)[1]))
    for k in sorted(set(new["warns"]) - set(old["warns"]) - set(new["fails"])):
        events.append(("new-warn", k.split("|", 1)[1]))
    for k in sorted(set(old["fails"]) - set(new["fails"])):
        events.append(("cleared", k.split("|", 1)[1]))
    return events, new["score"] - old["score"]


# --------------------------------------------------------------------------- #
#  Persistence (opt-in via --state)
# --------------------------------------------------------------------------- #
def _state_file(state_dir: str) -> Path:
    return Path(os.path.expanduser(state_dir)) / "watch-baseline.json"


def _load_state(state_dir: str) -> dict | None:
    try:
        return json.loads(_state_file(state_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _save_state(state_dir: str, snap: dict) -> None:
    try:
        p = _state_file(state_dir)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(snap, indent=2), encoding="utf-8")
    except OSError:
        pass


# --------------------------------------------------------------------------- #
#  Alerting
# --------------------------------------------------------------------------- #
def _notify(title: str, body: str) -> None:
    """Best-effort desktop notification; silently no-ops where unavailable."""
    try:
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", "-u", "critical", title, body],
                           capture_output=True, timeout=5)
        elif shutil.which("terminal-notifier"):  # macOS
            subprocess.run(["terminal-notifier", "-title", title, "-message", body],
                           capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass


def _stamp() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _emit(ink, events: list[tuple[str, str]], ds: int, snap: dict, notify: bool) -> None:
    bad = [e for e in events if e[0] in ("REGRESSED", "MALWARE")]
    head = f"[{_stamp()}] posture changed · score {snap['score']}/100 (grade {snap['grade']})"
    if ds:
        head += f" · {'▼' if ds < 0 else '▲'}{abs(ds)}"
    print((ink.red_b if bad else ink.amber)(head))
    for kind, label in events:
        color = {"REGRESSED": ink.red_b, "MALWARE": ink.red_b,
                 "new-warn": ink.amber, "cleared": ink.green}.get(kind, ink.dim)
        print("  " + color(f"{kind:>9}") + f"  {label}")
    sys.stdout.flush()
    if notify and bad:
        _notify("Murphy Lawden — posture regressed",
                "; ".join(f"{k}: {l}" for k, l in bad[:4]))


# --------------------------------------------------------------------------- #
#  systemd user unit (optional, Linux only)
# --------------------------------------------------------------------------- #
def _exec_start(args) -> str:
    exe = shutil.which("murphy")
    invoke = [exe] if exe else [sys.executable,
                                str(Path(__file__).resolve().parent.parent / "murphy.py")]
    invoke += ["watch", "--interval", str(args.interval), "--notify"]
    if getattr(args, "state", None):
        invoke += ["--state", os.path.abspath(os.path.expanduser(args.state))]
    return " ".join(invoke)


def _unit_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "systemd" / "user" / SERVICE_NAME


def _install_service(args, ink) -> int:
    if sys.platform != "linux" or not shutil.which("systemctl"):
        print(ink.amber("murphy watch: --install-service needs systemd (Linux). "
                        "Run `murphy watch` under your own supervisor instead."))
        return 1
    unit = f"""\
[Unit]
Description=Murphy Lawden — security posture sentinel
Documentation=man:murphy(1)
After=default.target

[Service]
Type=simple
ExecStart={_exec_start(args)}
Restart=on-failure
RestartSec=30
Nice=10

[Install]
WantedBy=default.target
"""
    path = _unit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(unit, encoding="utf-8")
    except OSError as e:
        print(ink.red_b(f"murphy watch: couldn't write {path} ({e})."))
        return 1
    print(ink.green(f"✓ wrote {path}"))
    print(ink.dim("  Optional — Murphy did NOT enable it. Start it yourself when ready:"))
    print(ink.cyan("    systemctl --user daemon-reload"))
    print(ink.cyan(f"    systemctl --user enable --now {SERVICE_NAME}"))
    print(ink.dim(f"  Watch it:   journalctl --user -u {SERVICE_NAME} -f"))
    print(ink.dim(f"  Remove it:  murphy watch --uninstall-service"))
    return 0


def _uninstall_service(ink) -> int:
    path = _unit_path()
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "disable", "--now", SERVICE_NAME],
                       capture_output=True)
    removed = False
    try:
        if path.exists():
            path.unlink()
            removed = True
    except OSError as e:
        print(ink.red_b(f"murphy watch: couldn't remove {path} ({e})."))
        return 1
    if shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)
    print(ink.green(f"✓ removed {SERVICE_NAME}") if removed
          else ink.dim(f"{SERVICE_NAME} was not installed — nothing to remove."))
    return 0


# --------------------------------------------------------------------------- #
#  Entry point
# --------------------------------------------------------------------------- #
def run_watch(args, ink) -> int:
    if getattr(args, "install_service", False):
        return _install_service(args, ink)
    if getattr(args, "uninstall_service", False):
        return _uninstall_service(ink)

    interval = max(30, int(getattr(args, "interval", 300)))
    notify = getattr(args, "notify", False)
    state_dir = getattr(args, "state", None)

    _, findings = _collect()
    snap = _snapshot(findings)
    prev = _load_state(state_dir) if state_dir else None

    if prev is None:
        where = f" · baseline persisted to {state_dir}" if state_dir else " · baseline in memory"
        print(ink.dim(f"[{_stamp()}] murphy watch — armed · score {snap['score']}/100 "
                      f"(grade {snap['grade']}) · {len(snap['fails'])} failing, "
                      f"{len(snap['mal'])} malware indicator(s){where}"))
        if snap["fails"] or snap["mal"]:
            print(ink.amber("  (starting posture already has issues — run `murphy scan` "
                            "for the full report; watch reports CHANGES from here)"))
    else:
        events, ds = _diff(prev, snap)
        if events:
            _emit(ink, events, ds, snap, notify)
        else:
            print(ink.dim(f"[{_stamp()}] no drift since last baseline · "
                          f"score {snap['score']}/100"))
    if state_dir:
        _save_state(state_dir, snap)

    if getattr(args, "once", False):
        return 1 if (snap["fails"] or snap["mal"]) else 0

    print(ink.dim(f"  watching every {interval}s — Ctrl-C to stop."))
    baseline = snap
    try:
        while True:
            time.sleep(interval)
            try:
                _, findings = _collect()
            except Exception as e:
                print(ink.amber(f"[{_stamp()}] scan hiccup ({e}) — will retry next tick"))
                continue
            cur = _snapshot(findings)
            events, ds = _diff(baseline, cur)
            if events:
                _emit(ink, events, ds, cur, notify)
            baseline = cur
            if state_dir:
                _save_state(state_dir, cur)
    except KeyboardInterrupt:
        print(ink.dim(f"\n[{_stamp()}] murphy watch — stood down."))
    return 0
