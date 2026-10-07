"""`ds jail` — qBittorrent itself in a sandbox: it can only write into the torrent folder.

The torrent client is the one program that talks to strangers all day, so it gets
the smallest world that still works:

  * your home is an empty tmpfs; it sees only the torrent folder (read-write, still
    noexec), its own config / data / cache folders, your Downloads and Desktop
    read-only (to open .torrent files), its blocklist, and your theme and fonts;
  * the OS read-only, a private /tmp, its own PID and IPC namespaces;
  * the network stays shared — it has to reach peers — and qBittorrent's own VPN
    binding still decides which interface;
  * a window through the restricted Wayland socket (no screen capture, no virtual
    keyboard), falling back to the plain socket only on a compositor without it;
  * D-Bus through a filtering proxy: notifications and the tray icon, nothing else
    (no systemd, no secrets, no portals to open files outside);
  * the cage's system-call filter, and Landlock: it can start /usr programs (its
    search plugins run python3) but nothing it downloaded or wrote.

`murphy ds jail --install` makes every way of starting qBittorrent go through this:
the app-menu entry, magnet links and .torrent double-clicks, and the `qbittorrent`
command (a ~/.local/bin shim). `--uninstall` removes both.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from contextlib import ExitStack
from pathlib import Path

from . import cage, landlock, qbit, seccomp, state, wlsec

HOME = Path.home()
UID = os.getuid()
MARK = "# murphy-ds-jail"
SHIM = HOME / ".local/bin/qbittorrent"
DESKTOP = HOME / ".local/share/applications/org.qbittorrent.qBittorrent.desktop"
SYSTEM_DESKTOP = Path("/usr/share/applications/org.qbittorrent.qBittorrent.desktop")
REAL = "/usr/bin/qbittorrent"
THEME_RO = [".config/qt5ct", ".config/qt6ct", ".config/kdeglobals", ".config/Kvantum",
            ".config/fontconfig", ".config/gtk-3.0", ".config/gtk-4.0", ".local/share/fonts",
            ".local/share/icons", ".local/share/color-schemes", ".icons", ".fonts"]


def _xdg(var: str, default: str) -> Path:
    return Path(os.environ.get(var) or HOME / default)


def folders() -> dict[str, list[Path]]:
    led = state.load()
    torrents = Path(led.get("folder") or state.default_folder())
    rw = [torrents, qbit.config_path().parent,
          _xdg("XDG_DATA_HOME", ".local/share") / "qBittorrent",
          _xdg("XDG_CACHE_HOME", ".cache") / "qBittorrent"]
    ro = [HOME / "Downloads", HOME / "Desktop", *(HOME / t for t in THEME_RO)]
    from . import ipfilter
    if ipfilter.FILE.exists():
        ro.append(ipfilter.FILE)
    return {"rw": rw, "ro": [p for p in ro if p.exists()]}


def running_unjailed() -> list[int]:
    """qBittorrent processes sharing our root — i.e. not inside a jail."""
    me = os.stat("/")
    out = []
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            if (d / "comm").read_text().strip() != "qbittorrent":
                continue
            r = os.stat(d / "root")
        except OSError:
            continue
        if (r.st_dev, r.st_ino) == (me.st_dev, me.st_ino):
            out.append(int(d.name))
    return out


def _dbus_proxy(stack: ExitStack) -> str | None:
    """A filtered session-bus socket: notifications and tray only."""
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if not bus and os.path.exists(f"/run/user/{UID}/bus"):
        bus = f"unix:path=/run/user/{UID}/bus"
    if not bus or not shutil.which("xdg-dbus-proxy"):
        return None
    import tempfile
    d = tempfile.mkdtemp(prefix="qbit-bus-", dir=os.environ.get("XDG_RUNTIME_DIR") or None)
    sock = os.path.join(d, "bus")
    p = subprocess.Popen(["xdg-dbus-proxy", bus, sock, "--filter",
                          "--talk=org.freedesktop.Notifications",
                          "--talk=org.kde.StatusNotifierWatcher",
                          # the proxy can't wildcard a "-": in the jail's PID namespace Qt's tray
                          # name is StatusNotifierItem-<pid>-<n> with a small, predictable pid
                          *(f"--own=org.kde.StatusNotifierItem-{p}-{n}" for p in (2, 3, 4) for n in (1, 2, 3))],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stack.callback(lambda: (p.terminate(), shutil.rmtree(d, ignore_errors=True)))
    for _ in range(60):
        if os.path.exists(sock):
            return sock
        time.sleep(0.05)
    return None


def build(argv: list[str], wayland: str | None, bus: str | None, x11: bool = False) -> list[str]:
    f = folders()
    rt = f"/run/user/{UID}"
    cmd = ["bwrap", "--unshare-pid", "--unshare-ipc", "--die-with-parent", "--new-session",
           *cage._root_fs(),
           "--ro-bind-try", "/var/cache/fontconfig", "/var/cache/fontconfig",
           "--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve",   # DNS via resolved
           "--ro-bind", "/sys", "/sys", "--proc", "/proc", "--dev", "/dev",
           "--dev-bind-try", "/dev/dri", "/dev/dri",
           "--tmpfs", "/tmp", "--tmpfs", "/home", "--tmpfs", "/root",
           "--dir", str(HOME), "--dir", rt, "--chmod", "0700", rt]
    for p in f["rw"]:
        p.mkdir(parents=True, exist_ok=True)
        cmd += ["--bind", str(p), str(p)]
    for p in f["ro"]:
        cmd += ["--ro-bind", str(p), str(p)]
    env = {"XDG_RUNTIME_DIR": rt}
    if wayland:
        cmd += ["--ro-bind", wayland, f"{rt}/wayland-0"]
        env.update(WAYLAND_DISPLAY="wayland-0", QT_QPA_PLATFORM="wayland")
        cmd += ["--unsetenv", "DISPLAY"]
    elif x11:
        cmd += ["--ro-bind", "/tmp/.X11-unix", "/tmp/.X11-unix"]
    if bus:
        cmd += ["--ro-bind", bus, f"{rt}/bus"]
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={rt}/bus"
    else:
        cmd += ["--unsetenv", "DBUS_SESSION_BUS_ADDRESS"]
    for k, v in env.items():
        cmd += ["--setenv", k, v]
    if seccomp.supported():
        cmd += ["--seccomp", str(cage._data_fd(seccomp.program()))]
    # it may start /usr programs (python3 for search plugins), never anything it wrote
    lock = ["/usr/bin/python3", "-I", "-c", landlock.CODE, "/usr", "/opt", "--"]
    cmd += ["--chdir", str(HOME), "--", *lock, *argv]
    return cmd


def launch(args: list[str], out) -> int:
    if args[:1] and args[0] in ("--version", "-v", "--help", "-h"):
        os.execv(REAL, [REAL, *args])
    free = running_unjailed()
    if free:
        out("x", f"qBittorrent is already running outside the jail (pid {', '.join(map(str, free))}). "
                 "Quit it (File → Exit), then start it again — it will come up jailed.")
        return 2
    with ExitStack() as stack:
        wl = x11 = None
        if os.environ.get("WAYLAND_DISPLAY"):
            try:
                wl = stack.enter_context(wlsec.RestrictedSocket(app_id="murphy.ds.qbittorrent"))
            except (OSError, wlsec.WaylandError):
                wl = wlsec._display_path()
                out("!", "this compositor can't restrict Wayland clients — qBittorrent gets the plain socket")
        elif os.environ.get("DISPLAY"):
            x11 = True
            out("!", "X11 session: an X11 window can read other windows' keystrokes — prefer Wayland")
        bus = _dbus_proxy(stack)
        cmd = build([REAL, *args], wl, bus, bool(x11))
        p = subprocess.Popen(cmd, pass_fds=tuple(cage._FDS), stdin=subprocess.DEVNULL)
        while cage._FDS:
            os.close(cage._FDS.pop())
        return p.wait()


def expected() -> dict[Path, str]:
    """Exactly what install writes. The sentinel accepts these files only when their
    content matches byte for byte — a lookalike with the marker is still reported."""
    from .lock_linux import _murphy_cmd
    mc = " ".join(_murphy_cmd())
    files = {SHIM: f"#!/bin/sh\n{MARK} — qBittorrent only ever starts inside its sandbox\n"
                   f"exec {mc} ds jail -- \"$@\"\n"}
    if SYSTEM_DESKTOP.exists():
        lines = []
        for line in SYSTEM_DESKTOP.read_text().splitlines():
            if line.startswith("Exec="):
                line = f"Exec={mc} ds jail -- %U"
            elif line.startswith("TryExec="):
                continue
            lines.append(line)
        files[DESKTOP] = "\n".join(lines) + f"\n{MARK}\n"
    return files


def install(out) -> int:
    for path, text in expected().items():
        if path.exists() and MARK not in path.read_text(errors="replace"):
            out("!", f"{path} exists and isn't Murphy's — left alone")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        if path == SHIM:
            path.chmod(0o755)
            out("+", "`qbittorrent` command → jailed")
        else:
            out("+", "app menu, magnet links and .torrent files → jailed")
    if running_unjailed():
        out("!", "qBittorrent is running unjailed right now — quit it and start it again")
    return 0


def uninstall(out) -> int:
    for p in (SHIM, DESKTOP):
        if p.exists() and MARK in p.read_text(errors="replace"):
            p.unlink()
    out("+", "jail removed — qBittorrent starts normally again")
    return 0


def status() -> str:
    on = SHIM.exists() and MARK in SHIM.read_text(errors="replace") and DESKTOP.exists()
    live = "running unjailed!" if running_unjailed() else ""
    return ("every launch goes through the jail" if on else "not installed (`murphy ds jail --install`)") \
        + (f" — but {live}" if live else "")
