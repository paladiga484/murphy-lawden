"""`ds lock` on Linux — the torrent folder where nothing runs, and the routes around it closed.

Layers, each recorded in the ledger so `ds unlock` reverses exactly what it did:
  mount    a systemd bind mount of the folder onto itself with noexec,nosuid,nodev:
           no ELF, no AppImage, no script by path, no binfmt hand-off can start there
  binfmt   Wine's binfmt handler off, so an .exe with +x anywhere doesn't silently
           launch Wine with your full network and home
  shim     ~/.local/bin/wine: `wine <file in the folder>` goes to the cage instead
           (noexec can't stop `wine x.exe` — Wine *reads* the file, it doesn't exec it)
  mime     double-clicking a Windows program opens `murphy ds run`, not Wine
  qbit     qBittorrent saves into the folder, never-legit file types excluded, etc.

Runs as you; the root steps go through `sudo` one command at a time.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from ..core import have, run
from . import cage, qbit, state

MARK = "# murphy-ds-shim"
BINFMT_MASK = Path("/etc/binfmt.d/wine.conf")
SHIM = Path.home() / ".local/bin/wine"
DESKTOP = Path.home() / ".local/share/applications/murphy-ds-run.desktop"
WIN_MIME = ["application/x-ms-dos-executable", "application/x-msdownload", "application/x-msi",
            "application/x-ms-shortcut", "application/x-bat", "application/x-mswinurl",
            "application/vnd.microsoft.portable-executable"]


def _murphy_cmd() -> list[str]:
    exe = shutil.which("murphy")
    if exe:
        return [exe]
    return [sys.executable, str(Path(__file__).resolve().parents[2] / "murphy.py")]


def _sudo(cmd: list[str], data: str | None = None) -> int:
    return subprocess.run(["sudo", *cmd], input=data, text=True,
                          stdout=subprocess.DEVNULL if data else None).returncode


def unit_name(folder: Path) -> str:
    rc, out = run(["systemd-escape", "--path", "--suffix=mount", str(folder)])
    return out.strip()


def mount_opts(folder: Path) -> set[str]:
    rc, out = run(["findmnt", "-n", "-o", "TARGET,OPTIONS", "--mountpoint", str(folder)])
    if rc != 0 or not out.strip():
        return set()
    return set(out.split(None, 1)[1].strip().split(","))


def locked(folder: Path) -> bool:
    return {"noexec", "nosuid", "nodev"} <= mount_opts(folder)


def _binfmt_wine() -> list[Path]:
    root = Path("/proc/sys/fs/binfmt_misc")
    out = []
    for p in root.iterdir() if root.is_dir() else ():
        if p.name in ("register", "status"):
            continue
        try:
            txt = p.read_text()
        except OSError:
            continue
        if "enabled" in txt.splitlines()[0] and "wine" in txt:
            out.append(p)
    return out


def _mime_default(t: str) -> str:
    return run(["xdg-mime", "query", "default", t])[1].strip()


def _mimeapps() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "mimeapps.list"


def _mime_user_lines() -> dict:
    """The user's own [Default Applications] entries for WIN_MIME (None = not set)."""
    try:
        lines = _mimeapps().read_text().splitlines()
    except OSError:
        lines = []
    got, sec = {t: None for t in WIN_MIME}, ""
    for line in lines:
        s = line.strip()
        if s.startswith("["):
            sec = s
        elif sec == "[Default Applications]" and "=" in s:
            k, v = s.split("=", 1)
            if k in got:
                got[k] = v
    return got


def _mime_restore(saved: dict) -> None:
    f = _mimeapps()
    try:
        lines = f.read_text().splitlines()
    except OSError:
        return
    out, sec = [], ""
    for line in lines:
        s = line.strip()
        if s.startswith("["):
            sec = s
        elif sec == "[Default Applications]" and "=" in s and s.split("=", 1)[0] in saved:
            k = s.split("=", 1)[0]
            if saved[k] is not None:
                out.append(f"{k}={saved[k]}")
            continue
        out.append(line)
    f.write_text("\n".join(out) + "\n")


def secure_boot() -> str:
    for p in Path("/sys/firmware/efi/efivars").glob("SecureBoot-*"):
        try:
            return "on" if p.read_bytes()[-1] == 1 else "off"
        except OSError:
            return "unknown"
    return "no UEFI"


# --------------------------------------------------------------------------- #
def lock(folder: Path, out) -> int:
    if os.geteuid() == 0:
        out("!", "run `murphy ds lock` as yourself — it asks sudo for the root steps")
        return 2
    led = state.load()
    if led.get("folder") and Path(led["folder"]) != folder:
        out("!", f"already locked {led['folder']} — `murphy ds unlock` it first")
        return 2
    led["folder"] = str(folder)
    state.save(led)
    fails = 0

    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)

    # 1. noexec mount
    if locked(folder):
        out("=", f"mount: {folder} already noexec,nosuid,nodev")
    else:
        unit = unit_name(folder)
        body = ("[Unit]\nDescription=Murphy ds: nothing runs from the torrent folder\n\n"
                f"[Mount]\nWhat={folder}\nWhere={folder}\nType=none\n"
                "Options=bind,noexec,nosuid,nodev\n\n[Install]\nWantedBy=local-fs.target\n")
        path = f"/etc/systemd/system/{unit}"
        state.remember(led, "mount", "unit", path)     # before: a half-done step must be undoable
        ok = (_sudo(["tee", path], body) == 0 and _sudo(["systemctl", "daemon-reload"]) == 0
              and _sudo(["systemctl", "enable", "--now", unit]) == 0 and locked(folder))
        out("+" if ok else "x", f"mount: {folder} → noexec,nosuid,nodev ({unit})")
        fails += not ok

    # 2. Wine's binfmt handler
    entries = _binfmt_wine()
    if not entries:
        out("=", "binfmt: no Wine handler registered")
    else:
        src = Path("/usr/lib/binfmt.d/wine.conf")
        ok = True
        if src.exists() and not BINFMT_MASK.exists():
            ok = _sudo(["ln", "-s", "/dev/null", str(BINFMT_MASK)]) == 0
            if ok:
                state.remember(led, "binfmt", "mask", str(BINFMT_MASK))
        for e in entries:
            ok = _sudo(["tee", str(e)], "0") == 0 and ok
        state.remember(led, "binfmt", "entries", [e.name for e in entries])
        out("+" if ok else "x", f"binfmt: {', '.join(e.name for e in entries)} off "
                                "(an .exe with +x no longer launches Wine by itself)")
        fails += not ok

    # 3. wine shim
    real_wine = shutil.which("wine", path=os.pathsep.join(
        p for p in os.environ.get("PATH", "").split(os.pathsep)
        if Path(p).resolve() != SHIM.parent.resolve()))
    if SHIM.exists() and MARK not in SHIM.read_text(errors="replace"):
        out("!", f"shim: {SHIM} exists and isn't Murphy's — left alone")
    elif not real_wine:
        out("=", "shim: Wine not installed")
    else:
        mc = " ".join(shlex.quote(c) for c in _murphy_cmd())
        SHIM.parent.mkdir(parents=True, exist_ok=True)
        SHIM.write_text(f"""#!/bin/sh
{MARK} — anything inside the locked torrent folder goes to the cage
LOCK={shlex.quote(str(folder.resolve()))}
for a in "$@"; do
  case "$a" in -*|/unix|start|/wait) continue ;; esac
  p=$(realpath -m -- "$a" 2>/dev/null) || continue
  case "$p/" in "$LOCK"/*) exec {mc} ds run --auto -- "$p" ;; esac
done
exec {shlex.quote(real_wine)} "$@"
""")
        SHIM.chmod(0o755)
        state.remember(led, "shim", "path", str(SHIM))
        out("+", f"shim: `wine <file in {folder.name}>` now opens the cage")

    # 4. double-click routing
    if have("xdg-mime"):
        mc = " ".join(shlex.quote(c) for c in _murphy_cmd())
        DESKTOP.parent.mkdir(parents=True, exist_ok=True)
        DESKTOP.write_text("[Desktop Entry]\nType=Application\nName=Run in Murphy cage\n"
                           f"Exec={mc} ds run --auto -- %f\nTerminal=true\nNoDisplay=true\n"
                           f"MimeType={';'.join(WIN_MIME)};\n")
        state.remember(led, "mime", "desktop", str(DESKTOP))
        for t, p in _mime_user_lines().items():
            state.remember(led, "mime_prev", t, p)
        rc = run(["xdg-mime", "default", DESKTOP.name, *WIN_MIME])[0]
        out("+" if rc == 0 else "x", "mime: double-clicking a Windows program opens the cage")
        fails += rc != 0

    # 5. qBittorrent
    if not qbit.config_path().exists() and not have("qbittorrent"):
        out("=", "qbittorrent: not installed")
    elif qbit.running():
        out("x", "qbittorrent: running — close it and re-run `murphy ds lock` "
                 "(it rewrites its config on exit and would undo this)")
        fails += 1
    else:
        changed = qbit.apply_lock(folder, led, state.remember)
        out("+" if changed else "=", "qbittorrent: " + ("; ".join(changed) if changed
                                                        else "already pointed at the lock"))
    return 1 if fails else 0


def unlock(out) -> int:
    led = state.load()
    if not led:
        out("=", "nothing to unlock — no ledger")
        return 0
    fails = 0
    unit_path = led.get("mount", {}).get("unit")
    if unit_path:
        unit = Path(unit_path).name
        _sudo(["systemctl", "disable", "--now", unit])  # fails harmlessly if it never started
        ok = _sudo(["rm", "-f", unit_path]) == 0 and _sudo(["systemctl", "daemon-reload"]) == 0
        out("+" if ok else "x", f"mount: {unit} removed (folder and files kept)")
        if ok:
            led.pop("mount")
        fails += not ok
    if "binfmt" in led:
        ok = True
        if led["binfmt"].get("mask") and BINFMT_MASK.is_symlink() \
                and os.readlink(BINFMT_MASK) == "/dev/null":
            ok = _sudo(["rm", "-f", str(BINFMT_MASK)]) == 0
        for name in led["binfmt"].get("entries", []):
            entry = Path("/proc/sys/fs/binfmt_misc") / name
            if entry.exists():                      # still registered, just switched off
                ok = _sudo(["tee", str(entry)], "1") == 0 and ok
            else:                                   # dropped by a reboot under the mask
                ok = _sudo(["systemctl", "restart", "systemd-binfmt.service"]) == 0 and ok
        out("+" if ok else "x", "binfmt: Wine handler restored")
        if ok:
            led.pop("binfmt")
        fails += not ok
    if "shim" in led:
        if SHIM.exists() and MARK in SHIM.read_text(errors="replace"):
            SHIM.unlink()
        led.pop("shim")
        out("+", "shim: removed")
    if "mime" in led:
        _mime_restore(led.get("mime_prev", {}))
        DESKTOP.unlink(missing_ok=True)
        led.pop("mime")
        led.pop("mime_prev", None)
        out("+", "mime: previous handlers restored")
    if "qbit" in led:
        if qbit.running():
            out("x", "qbittorrent: running — close it and re-run unlock")
            fails += 1
        else:
            qbit.restore(led)
            led.pop("qbit")
            out("+", "qbittorrent: original settings restored")
    if set(led) <= {"folder"}:
        state.LEDGER.unlink(missing_ok=True)
    else:
        state.save(led)
    return 1 if fails else 0


def status(folder: Path, out) -> None:
    out("+" if locked(folder) else "x", f"mount: {folder} "
        + ("noexec,nosuid,nodev" if locked(folder) else "NOT locked — programs can run from it"))
    wine = _binfmt_wine()
    out("x" if wine else "+", "binfmt: " + (f"{', '.join(e.name for e in wine)} still launches Wine"
                                            if wine else "no Wine auto-launch"))
    shim_ok = SHIM.exists() and MARK in SHIM.read_text(errors="replace")
    out("+" if shim_ok else "x", "shim: " + ("wine → cage for the folder" if shim_ok else "not installed"))
    mime = _mime_default(WIN_MIME[0]) if have("xdg-mime") else ""
    out("+" if mime == DESKTOP.name else "x", f"mime: .exe double-click → {mime or '(nothing)'}")
    ok, why = cage.available()
    out("+" if ok else "x", "cage: " + ("bubblewrap + user namespaces ready" if ok else why))
    sb = secure_boot()
    out("+" if sb == "on" else "!", f"secure boot: {sb}"
        + ("" if sb == "on" else " — a bootkit that gets root would survive reboots; "
                                 "enabling it is your call (firmware setup)"))
