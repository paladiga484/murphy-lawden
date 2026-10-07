"""The cage — bubblewrap, set up so a hostile program has nothing to reach.

Inside the cage:
  * no network at all: its own empty network namespace, loopback only. No
    route out, no DNS, and no abstract sockets (X11's included) from the host.
  * no home: /home is an empty tmpfs. SSH keys, browser profiles, wallets and
    your documents do not exist in there, so there is nothing to encrypt or steal.
  * the OS read-only (/usr, /etc); no /run, no D-Bus, no systemd, no
    pipewire — the doors a sandboxed program would use to start something
    *outside* the sandbox are simply not mounted.
  * no sound unless you ask. --audio gives a private, play-only sound server
    (audio.py): no microphone, no capture, no module loading. Never the desktop's socket.
  * no display unless you ask. --gui gives a *restricted* Wayland socket
    (security-context-v1): the compositor withholds virtual keyboard/pointer,
    screen capture and clipboard snooping from it. Never X11, never the raw socket.
  * no new user namespaces, a fresh session (no terminal injection), its own
    PID/IPC/UTS namespaces, and it dies with Murphy.
  * a system-call filter (seccomp.py): the kernel interfaces exploits use and games
    don't — BPF, io_uring, perf, userfaultfd, keyrings, mounts, module loading —
    answer "operation not permitted".
  * nothing starts from a writable place (landlock.py): a dropped Linux program in
    /tmp, the prefix or the output folder can be written but never run.
  * a made-up identity: its own /etc/machine-id (kept per prefix, so a game sees a
    stable one) and hostname, and with --gpu the disk serials, network cards (MAC
    addresses), firmware and DMI tables are hidden from /sys.
  * one writable place: the output folder, which lives in the locked folder,
    so anything it produces is itself unrunnable outside a cage.

Windows programs run under Wine with a throwaway prefix in the cage's tmpfs —
it is created and destroyed with every run, so nothing persists between runs.
`--proton` (proton.py) is the exception: its prefix is kept, in the output folder.
"""
from __future__ import annotations

import os
import resource
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from ..core import have
from . import landlock, seccomp

_FDS: list[int] = []        # data handed to bwrap by file descriptor, closed after spawn
SYS_HIDDEN = ("/sys/class/net", "/sys/block", "/sys/class/block", "/sys/class/nvme",
              "/sys/firmware", "/sys/class/dmi", "/sys/devices/virtual/dmi")


def _data_fd(data: bytes) -> int:
    """A memory-only file holding `data`, inheritable by bwrap."""
    fd = os.memfd_create("murphy-cage", 0)
    os.write(fd, data)
    os.lseek(fd, 0, os.SEEK_SET)
    os.set_inheritable(fd, True)
    _FDS.append(fd)
    return fd

SCRATCH = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "murphy-ds"
CAGE_HOME = "/home/cage"
MAX_FILE = 64 << 30           # RLIMIT_FSIZE: one file may not exceed 64 GiB (archive bombs)


def available() -> tuple[bool, str]:
    if not have("bwrap"):
        return False, "bubblewrap (bwrap) is not installed — `sudo pacman -S bubblewrap`"
    userns = Path("/proc/sys/kernel/unprivileged_userns_clone")
    if userns.exists() and userns.read_text().strip() == "0":
        return False, "kernel.unprivileged_userns_clone=0 — the cage needs user namespaces"
    maxns = Path("/proc/sys/user/max_user_namespaces")
    if maxns.exists() and maxns.read_text().strip() == "0":
        return False, "user.max_user_namespaces=0 — the cage needs user namespaces"
    return True, ""


def _root_fs() -> list[str]:
    args = ["--ro-bind", "/usr", "/usr"]
    for d in ("bin", "sbin", "lib", "lib64", "lib32"):
        p = Path("/" + d)
        if p.is_symlink():
            args += ["--symlink", os.readlink(p), "/" + d]
        elif p.is_dir():
            args += ["--ro-bind", "/" + d, "/" + d]
    args += ["--ro-bind", "/etc", "/etc"]
    if Path("/opt").is_dir():
        args += ["--ro-bind", "/opt", "/opt"]
    return args


def build(argv: list[str], binds_ro: list[tuple[str, str]], binds_rw: list[tuple[str, str]],
          wayland: str | None = None, gpu: bool = False, chdir: str = CAGE_HOME,
          extra_env: dict | None = None, pulse: str | None = None,
          machine_id: str | None = None, exec_app: bool = True) -> list[str]:
    cmd = ["bwrap",
           "--unshare-all", "--unshare-user", "--disable-userns",
           "--die-with-parent", "--new-session",
           "--hostname", "cage",
           "--clearenv",
           *_root_fs(),
           "--proc", "/proc",
           "--dev", "/dev",
           "--tmpfs", "/tmp",
           "--perms", "0700", "--dir", "/tmp/xdg-cage",
           "--tmpfs", "/var/tmp",
           "--tmpfs", "/home",
           "--tmpfs", "/root",
           "--dir", CAGE_HOME,
           "--dir", "/cage",
           ]
    import uuid
    mid = (machine_id or uuid.uuid4().hex) + "\n"
    # only over files that exist: /etc is read-only in the cage, a new file can't be made there
    if Path("/etc/machine-id").is_file():
        cmd += ["--ro-bind-data", str(_data_fd(mid.encode())), "/etc/machine-id"]
    if Path("/etc/hostname").is_file():
        cmd += ["--ro-bind-data", str(_data_fd(b"cage\n")), "/etc/hostname"]
    if seccomp.supported():
        cmd += ["--seccomp", str(_data_fd(seccomp.program()))]
    env = {
        "PATH": "/usr/local/bin:/usr/bin",
        "HOME": CAGE_HOME,
        "USER": "cage",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "TERM": os.environ.get("TERM", "xterm-256color"),
        "WINEPREFIX": CAGE_HOME + "/.wine",
        "WINEDEBUG": "-all",
        "XDG_RUNTIME_DIR": "/tmp/xdg-cage",
        "WINEDLLOVERRIDES": "winemenubuilder.exe=d",   # no .desktop/menu entries
    }
    if wayland:
        # a sandbox-tagged socket from wlsec.RestrictedSocket, never the raw one
        cmd += ["--dir", "/run/user/cage", "--chmod", "0700", "/run/user/cage",
                "--ro-bind", wayland, "/run/user/cage/wayland-0"]
        env.update(XDG_RUNTIME_DIR="/run/user/cage", WAYLAND_DISPLAY="wayland-0",
                   XDG_SESSION_TYPE="wayland", QT_QPA_PLATFORM="wayland",
                   GDK_BACKEND="wayland", SDL_VIDEODRIVER="wayland")
        # no DISPLAY: Wine picks its Wayland driver when X11 isn't there
    if pulse:
        # a play-only socket from audio.PlayOnly, never the desktop's
        cmd += ["--ro-bind", pulse, "/cage/pulse"]
        env.update(PULSE_SERVER="unix:/cage/pulse", SDL_AUDIODRIVER="pulseaudio")
    if gpu:
        cmd += ["--dev-bind-try", "/dev/dri", "/dev/dri", "--ro-bind-try", "/sys", "/sys"]
        for n in sorted(Path("/dev").glob("nvidia*")):
            cmd += ["--dev-bind", str(n), str(n)]
        for p in SYS_HIDDEN:                   # the GPU needs /sys; serial numbers it doesn't
            if Path(p).is_dir():
                cmd += ["--tmpfs", p]
    for src, dst in binds_ro:
        cmd += ["--ro-bind", src, dst]
    for src, dst in binds_rw:
        cmd += ["--bind", src, dst]
    for k, v in {**env, **(extra_env or {})}.items():
        cmd += ["--setenv", k, v]
    # the cage's own root (a tmpfs holding the mount points) goes read-only last;
    # /tmp, the home tmpfs and the output bind stay writable as separate mounts
    cmd += ["--remount-ro", "/", "--chdir", chdir, "--", *landlock.wrap(argv, exec_app)]
    return cmd


def _limits() -> None:
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_FILE, MAX_FILE))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _clean(text: str) -> str:
    """What the caged program prints reaches your real terminal only as text:
    every C0/C1 control except tab/newline/CR/backspace is dropped, so no escape
    sequence (clipboard writes, title/hyperlink tricks, terminal remote control)
    gets through."""
    return "".join(c for c in text if c in "\t\n\r\b" or not (ord(c) < 0x20 or 0x7f <= ord(c) < 0xa0))


def _relay(cmd: list[str]) -> int:
    """Run `cmd` on a private pty; forward your keys in, sanitised text out.
    Ctrl-C closes the cage (the program never becomes your terminal's foreground job)."""
    import codecs
    import fcntl
    import select
    import signal
    import struct
    import termios
    import tty

    master, slave = os.openpty()
    try:
        if sys.stdout.isatty():
            fcntl.ioctl(slave, termios.TIOCSWINSZ,
                        fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b"\0" * 8))
    except OSError:
        pass
    p = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave, preexec_fn=_limits,
                         start_new_session=True, pass_fds=tuple(_FDS))
    os.close(slave)
    while _FDS:                                # bwrap has its copies now
        os.close(_FDS.pop())
    tin = sys.stdin.fileno() if sys.stdin.isatty() else None
    saved = termios.tcgetattr(tin) if tin is not None else None
    dec = codecs.getincrementaldecoder("utf-8")("replace")
    try:
        if tin is not None:
            tty.setraw(tin)
        while True:
            fds = [master] + ([tin] if tin is not None else [])
            r, _, _ = select.select(fds, [], [], 0.2)
            if master in r:
                try:
                    data = os.read(master, 65536)
                except OSError:            # EIO: the pty's last writer is gone
                    data = b""
                if not data:
                    break
                sys.stdout.write(_clean(dec.decode(data)))
                sys.stdout.flush()
            if tin is not None and tin in r:
                keys = os.read(tin, 1024)
                if b"\x03" in keys:                  # Ctrl-C: close the cage
                    os.killpg(p.pid, signal.SIGTERM)
                    keys = keys.replace(b"\x03", b"")
                if keys:
                    os.write(master, keys)
            if p.poll() is not None and master not in r:
                break
    finally:
        if saved is not None:
            termios.tcsetattr(tin, termios.TCSADRAIN, saved)
        os.close(master)
    try:
        return p.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        return p.wait()


def spawn(cmd: list[str], memory: str = "8G", tasks: int = 2048) -> int:
    """Run the cage, inside a transient systemd scope when we have one, so a fork
    bomb or a memory hog hits a wall instead of the desktop."""
    if have("systemd-run") and (os.environ.get("DBUS_SESSION_BUS_ADDRESS")
                                or Path(f"/run/user/{os.getuid()}/bus").exists()):
        cmd = ["systemd-run", "--user", "--scope", "--quiet", "--collect",
               "-p", f"MemoryMax={memory}", "-p", "MemorySwapMax=0",
               "-p", f"TasksMax={tasks}", *cmd]
    return _relay(cmd)


def stage(src: Path, whole_dir: bool) -> Path:
    """Copy the target out of the noexec folder into an exec-able scratch dir.

    The locked folder is mounted noexec and that flag follows every bind into the
    cage, so an ELF can't start from there even inside it. The copy is private
    (0700) and deleted after the run."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    os.chmod(SCRATCH, 0o700)
    work = Path(tempfile.mkdtemp(prefix="stage-", dir=SCRATCH))
    if whole_dir:
        shutil.copytree(src.parent, work / "app", symlinks=True)
    else:
        (work / "app").mkdir()
        shutil.copy2(src, work / "app" / src.name)
    os.chmod(work / "app" / src.name, 0o700)      # torrents rarely keep the +x bit
    return work


def unstage(work: Path) -> None:
    shutil.rmtree(work, ignore_errors=True)
