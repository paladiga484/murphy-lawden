"""`ds jail` — qBittorrent itself in a sandbox: it can only write into the torrent folder.

The torrent client is the one program that talks to strangers all day, so it gets
the smallest world that still works:

  * your home is an empty tmpfs; it sees only the torrent folder (read-write, still
    noexec), its own config / data / cache folders, its blocklist, and your theme
    and fonts. A .torrent you open from elsewhere is copied in (torrent
    folder/.incoming) rather than showing it the folder it came from;
  * the OS read-only, with the cage's masked /etc (a passwd that knows only you, no
    host keys or disk UUIDs) and /proc; a private /tmp; its own PID, IPC, UTS and
    cgroup namespaces and a user namespace that can't make more (most kernel
    exploits need one); no GPU and no /sys (it draws in software); a blank
    machine-id; and none of your session's environment beyond locale and theme —
    no tokens or socket paths a shell happened to export;
  * the network stays shared — it has to reach peers — and qBittorrent's own VPN
    binding still decides which interface. Landlock scoping keeps it off the
    abstract unix sockets that sharing exposes (Xwayland's among them);
  * a window through the restricted Wayland socket (no screen capture, no virtual
    keyboard), behind murphy's filter (wlsec.FilteredSocket): the clipboard stays —
    you paste magnet links — but idle watching, shortcut grabs and the like don't;
  * no D-Bus at all by default. `--tray on` gives it one through xdg-dbus-proxy —
    notifications and the tray icon, nothing else — and that proxy, which parses
    what the jail sends, runs in a bwrap of its own;
  * the cage's system-call filter, and Landlock: it can start /usr programs (its
    search plugins run python3) but nothing it downloaded or wrote.

`murphy ds jail --install` makes every way of starting qBittorrent go through this:
the app-menu entry, magnet links and .torrent double-clicks, and the `qbittorrent`
command (a ~/.local/bin shim). `--uninstall` removes both.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
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
# what it may keep from your session's environment: locale, theme, scaling, cursor
ENV_KEPT = ("HOME", "USER", "LOGNAME", "LANG", "LANGUAGE", "TZ", "QT_QPA_PLATFORMTHEME",
            "QT_STYLE_OVERRIDE", "QT_SCALE_FACTOR", "QT_SCREEN_SCALE_FACTORS", "QT_FONT_DPI",
            "QT_AUTO_SCREEN_SCALE_FACTOR", "QT_ENABLE_HIGHDPI_SCALING",
            "QT_SCALE_FACTOR_ROUNDING_POLICY", "XCURSOR_THEME", "XCURSOR_SIZE",
            "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "XDG_DATA_DIRS", "XDG_CONFIG_DIRS",
            "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME",
            "KDE_FULL_SESSION", "KDE_SESSION_VERSION", "DESKTOP_SESSION", "GTK_THEME")
SETTINGS = state.state_dir() / "jail.json"


def _xdg(var: str, default: str) -> Path:
    return Path(os.environ.get(var) or HOME / default)


def folders() -> dict[str, list[Path]]:
    led = state.load()
    torrents = Path(led.get("folder") or state.default_folder())
    rw = [torrents, qbit.config_path().parent,
          _xdg("XDG_DATA_HOME", ".local/share") / "qBittorrent",
          _xdg("XDG_CACHE_HOME", ".cache") / "qBittorrent"]
    ro = [HOME / t for t in THEME_RO]
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


def tray_on() -> bool:
    try:
        return bool(json.loads(SETTINGS.read_text()).get("tray"))
    except (OSError, ValueError):
        return False


def set_tray(on: bool, out) -> int:
    SETTINGS.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS.write_text(json.dumps({"tray": on}))
    out("+", "tray icon and notifications: " + ("on — through a filtered D-Bus proxy, itself sandboxed"
             if on else "off — no D-Bus in the jail at all") + " (from qBittorrent's next start)")
    return 0


def _dbus_proxy(stack: ExitStack) -> str | None:
    """A filtered session-bus socket: notifications and tray only. The proxy reads
    everything the jail sends, so it gets a bwrap of its own: no network, no home,
    only the real bus socket and the folder its own socket goes in."""
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS") or f"unix:path=/run/user/{UID}/bus"
    path = bus[len("unix:path="):].split(",")[0] if bus.startswith("unix:path=") else ""
    if not path or not os.path.exists(path) or not shutil.which("xdg-dbus-proxy"):
        return None
    import tempfile
    d = tempfile.mkdtemp(prefix="qbit-bus-", dir=os.environ.get("XDG_RUNTIME_DIR") or None)
    sock = os.path.join(d, "bus")
    cmd = ["bwrap", "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent",
           "--new-session", "--clearenv", *cage._root_fs(), "--proc", "/proc", "--dev", "/dev",
           "--tmpfs", "/tmp", "--ro-bind", path, path, "--bind", d, d]
    if seccomp.supported():
        cmd += ["--seccomp", str(cage._data_fd(seccomp.program()))]
    cmd += ["--", "xdg-dbus-proxy", f"unix:path={path}", sock, "--filter",
            "--talk=org.freedesktop.Notifications",
            "--talk=org.kde.StatusNotifierWatcher",
            # the proxy can't wildcard a "-": in the jail's PID namespace Qt's tray
            # name is StatusNotifierItem-<pid>-<n> with a small, predictable pid
            *(f"--own=org.kde.StatusNotifierItem-{p}-{n}" for p in (2, 3, 4) for n in (1, 2, 3))]
    p = subprocess.Popen(cmd, pass_fds=tuple(cage._FDS), stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    while cage._FDS:
        os.close(cage._FDS.pop())
    stack.callback(lambda: (p.terminate(), shutil.rmtree(d, ignore_errors=True)))
    for _ in range(60):
        if os.path.exists(sock):
            return sock
        time.sleep(0.05)
    return None


def build(argv: list[str], wayland: str | None, bus: str | None, x11: bool = False) -> list[str]:
    f = folders()
    rt = f"/run/user/{UID}"
    user = os.environ.get("USER") or HOME.name
    cmd = ["bwrap", "--unshare-user", "--disable-userns", "--unshare-pid", "--unshare-ipc",
           "--unshare-uts", "--hostname", "localhost", "--unshare-cgroup-try",
           "--die-with-parent", "--new-session", "--clearenv",
           *cage._root_fs(),
           *cage.etc_args(user, str(HOME), "localhost"),
           "--ro-bind-data", str(cage._data_fd(os.urandom(16).hex().encode() + b"\n")), "/etc/machine-id",
           "--ro-bind-try", "/var/cache/fontconfig", "/var/cache/fontconfig",
           "--ro-bind-try", "/run/systemd/resolve", "/run/systemd/resolve",   # DNS via resolved
           "--proc", "/proc", *cage.proc_args(), "--dev", "/dev",
           "--tmpfs", "/tmp", "--tmpfs", "/home", "--tmpfs", "/root",
           "--dir", str(HOME), "--dir", rt, "--chmod", "0700", rt]
    for p in f["rw"]:
        p.mkdir(parents=True, exist_ok=True)
        cmd += ["--bind", str(p), str(p)]
    for p in f["ro"]:
        cmd += ["--ro-bind", str(p), str(p)]
    env = {k: v for k, v in os.environ.items() if k in ENV_KEPT or k.startswith("LC_")}
    env.update(PATH="/usr/local/bin:/usr/bin", XDG_RUNTIME_DIR=rt, QT_QUICK_BACKEND="software",
               LIBGL_ALWAYS_SOFTWARE="1")
    if wayland:
        cmd += ["--ro-bind", wayland, f"{rt}/wayland-0"]
        env.update(WAYLAND_DISPLAY="wayland-0", QT_QPA_PLATFORM="wayland")
    elif x11:
        cmd += ["--ro-bind", "/tmp/.X11-unix", "/tmp/.X11-unix"]
        env["DISPLAY"] = os.environ.get("DISPLAY", ":0")
    if bus:
        cmd += ["--ro-bind", bus, f"{rt}/bus"]
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={rt}/bus"
    for k, v in env.items():
        cmd += ["--setenv", k, v]
    if seccomp.supported():
        cmd += ["--seccomp", str(cage._data_fd(seccomp.program()))]
    # it may start /usr programs (python3 for search plugins), never anything it wrote
    lock = ["/usr/bin/python3", "-I", "-c", landlock.CODE, "/usr", "/opt", "--"]
    cmd += ["--chdir", str(HOME), "--", *lock, *argv]
    return cmd


def _stage(args: list[str], out=None) -> list[str]:
    """Copy .torrent files from outside the jail's folders into torrent folder/.incoming.

    That folder is writable from inside the jail, so a compromised client could have
    left a symlink there (as .incoming itself, or under the torrent's name) for us to
    write through. Nothing here follows one: .incoming is opened with O_NOFOLLOW and
    each copy is a new file (O_EXCL), named afresh if the name is taken."""
    rw = folders()["rw"]
    staged = []
    inbox_fd = None
    try:
        for a in args:
            p = Path(a[7:] if a.startswith("file://") else a)
            if p.suffix.lower() == ".torrent" and p.is_file() \
                    and not any(p.resolve().is_relative_to(d.resolve()) for d in rw):
                try:
                    if inbox_fd is None:
                        inbox_fd = _open_inbox(rw[0])
                    a = str(rw[0] / ".incoming" / _place(inbox_fd, p))
                except OSError as e:
                    if out:
                        out("x", f"{rw[0] / '.incoming'} isn't a plain folder any more ({e.strerror}) - "
                                 f"{p.name} not handed over; delete .incoming and open it again")
                    continue
            staged.append(a)
    finally:
        if inbox_fd is not None:
            os.close(inbox_fd)
    return staged


def _open_inbox(torrents: Path) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    top = os.open(torrents, flags)
    try:
        try:
            os.mkdir(".incoming", 0o700, dir_fd=top)
        except FileExistsError:
            pass
        return os.open(".incoming", flags, dir_fd=top)      # ELOOP if it is a symlink
    finally:
        os.close(top)


def _place(inbox_fd: int, src: Path) -> str:
    """Copy src into the inbox as a brand-new file; returns the name used."""
    stem, n = src.stem, 0
    data = src.read_bytes()
    while True:
        name = f"{stem}.torrent" if n == 0 else f"{stem}-{n}.torrent"
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=inbox_fd)
        except FileExistsError:
            n += 1
            continue
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return name


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
                out("!", "this compositor can't restrict Wayland clients — only murphy's filter "
                         "stands between qBittorrent and the privileged interfaces")
            wl = stack.enter_context(wlsec.FilteredSocket(wl, wlsec.APP_GLOBALS))
        elif os.environ.get("DISPLAY"):
            x11 = True
            out("!", "X11 session: an X11 window can read other windows' keystrokes — prefer Wayland")
        bus = _dbus_proxy(stack) if tray_on() else None
        cmd = build([REAL, *_stage(args, out)], wl, bus, bool(x11))
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
        + ("; tray/notifications on (`--tray off`)" if tray_on() else "; no D-Bus (`--tray on` for a tray icon)") \
        + (f" — but {live}" if live else "")
