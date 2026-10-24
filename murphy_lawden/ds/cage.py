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
    In front of it sits murphy's own filter (wlsec.FilteredSocket): the program
    sees only the window, input and GPU interfaces a game uses — not your
    clipboard (no reading what you copied, no swapping in a wallet address), not
    focus-stealing, not shortcut grabs, not "is the user idle".
  * no new user namespaces, a fresh session (no terminal injection), its own
    PID/IPC/UTS namespaces, and it dies with Murphy.
  * a system-call filter (seccomp.py): the kernel interfaces exploits use and games
    don't — BPF, io_uring, perf, userfaultfd, keyrings, mounts, module loading —
    answer "operation not permitted".
  * nothing starts from a writable place (landlock.py): a dropped Linux program in
    /tmp, the prefix or the output folder can be written but never run.
  * a made-up identity: its own /etc/machine-id (kept per prefix, so a game sees a
    stable one), hostname, and a passwd that knows only "cage"; /etc without SSH
    host keys, disk UUIDs, boot/kernel/firewall settings; /proc without the kernel
    command line, module list or disk partitions.
  * --gpu: one GPU, as a render node — the integrated one on a laptop (--dgpu adds
    the NVIDIA card and its much larger driver) — and a /sys holding only that GPU's
    folder and the CPU topology, with serials, MACs and EDIDs blanked and the list
    of unmitigated CPU bugs gone.
  * one writable place: the output folder, which lives in the locked folder,
    so anything it produces is itself unrunnable outside a cage. A game that
    saves beside itself gets a copy-on-write layer over its folder: it writes,
    the download underneath never changes.

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
# what a GPU needs from /sys; the rest (disks, network cards, firmware, DMI tables,
# loaded modules) simply isn't there
SYS_GPU = ("/sys/dev/char", "/sys/class/drm", "/sys/bus/pci/devices", "/sys/devices/system/cpu")
# inside a GPU's own folder: serial numbers, MAC addresses and monitor EDIDs read as empty
SYS_BLANKED = {"serial", "serial_number", "address", "perm_addr", "edid", "unique_id", "wwid"}
NVIDIA_SKIPPED = ("nvidia-uvm-tools", "nvidia-caps")   # profiling / MIG: games need neither
# /etc stays (libraries, fonts, certificates, time zone) minus what names you or this
# machine, or tells an exploit how the kernel, the boot and the firewall were hardened
ETC_HIDDEN = ("ssh", "fstab", "crypttab", "crypttab.initramfs", "kernel", "default",
              "mkinitcpio.conf", "mkinitcpio.conf.d", "mkinitcpio.d", "dracut.conf", "dracut.conf.d",
              "modprobe.d", "modules-load.d", "sysctl.conf", "sysctl.d", "ufw", "nftables.conf",
              "iptables", "firewalld", "rkhunter.conf", "rkhunter.conf.local", "rkhunter.d", "audit",
              "apparmor.d", "usbguard", "fail2ban", "kernel-harden", "subuid", "subgid",
              "passwd-", "group-", "NetworkManager", "wireguard", "wpa_supplicant", "iwd", "openvpn",
              "mullvad-vpn", "libvirt", "sddm.conf", "sddm.conf.d", "lightdm", "gdm", "greetd",
              "sudoers", "sudoers.d", "sudo.conf", "doas.conf", "security", "pam.d", "polkit-1",
              "cups", "samba", "snapper", "grub.d", "limine.conf", "adjtime", "machine-info",
              "asusd", "supergfxd.conf", "tlp.conf", "tlp.d", "pacman.d")
# /proc files about the kernel build, its modules and your disks rather than the cage
PROC_HIDDEN = ("/proc/modules", "/proc/kallsyms", "/proc/cmdline", "/proc/config.gz",
               "/proc/bootconfig", "/proc/partitions", "/proc/keys", "/proc/key-users")


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


def gpus() -> list[tuple[Path, str, Path]]:
    """(render node, kernel driver, PCI device folder) of every GPU."""
    found = []
    for node in sorted(Path("/dev/dri").glob("renderD*")):
        dev = Path("/sys/class/drm", node.name, "device")
        try:
            found.append((node, Path(os.readlink(dev / "driver")).name, dev.resolve()))
        except OSError:
            continue
    return found


def pick_gpus(dgpu: bool) -> list[tuple[Path, str, Path]]:
    """Every GPU with --dgpu; otherwise only those not on NVIDIA's driver (a laptop's
    integrated GPU) — one driver's worth of kernel code instead of two — unless
    NVIDIA is all there is."""
    have = gpus()
    return have if dgpu else [g for g in have if g[1] != "nvidia"] or have


def _sys_serials(root: Path) -> list[str]:
    """Every serial / MAC / EDID file under `root` (links not followed: sysfs loops)."""
    out = []
    for top, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in ("power", "subsystem", "driver")]
        out += [f"{top}/{f}" for f in files if f in SYS_BLANKED]
    return out


def _gpu_args(dgpu: bool) -> list[str]:
    """Render nodes only (no display-control card nodes), and a /sys holding just the
    picked GPUs' folders and the CPU topology Wine reads."""
    picked = pick_gpus(dgpu)
    args = ["--dir", "/sys"]
    for p in SYS_GPU:
        if Path(p).is_dir():
            args += ["--ro-bind", p, p]
    vuln = "/sys/devices/system/cpu/vulnerabilities"          # which CPU bugs go unmitigated here
    if Path(vuln).is_dir():
        args += ["--tmpfs", vuln, "--remount-ro", vuln]
    for f in sorted(Path("/sys/devices/system/cpu").glob("cpu*/microcode/version")):
        args += ["--ro-bind-data", str(_data_fd(b"")), str(f)]
    for node, _, dev in picked:
        args += ["--dev-bind", str(node), str(node), "--ro-bind", str(dev), str(dev)]
        for f in _sys_serials(dev):
            args += ["--ro-bind-data", str(_data_fd(b"")), f]
    if any(driver == "nvidia" for _, driver, _ in picked):
        for n in sorted(Path("/dev").glob("nvidia*")):
            if n.name not in NVIDIA_SKIPPED and not n.is_dir():
                args += ["--dev-bind", str(n), str(n)]
        for m in sorted(Path("/sys/module").glob("nvidia*")):
            args += ["--ro-bind", str(m), str(m)]
    return args


def etc_args(user: str, home: str, hostname: str) -> list[str]:
    """Over the read-only /etc: a passwd, group and hosts that know only `user`, the
    given hostname, and ETC_HIDDEN emptied. Only over things that exist — /etc is
    read-only in a cage, nothing new can be made there."""
    uid, gid = os.getuid(), os.getgid()
    made = {"passwd": f"root:x:0:0::/root:/usr/bin/nologin\n{user}:x:{uid}:{gid}::{home}:/bin/sh\n"
                      "nobody:x:65534:65534::/:/usr/bin/nologin\n",
            "group": f"root:x:0:\n{user}:x:{gid}:\nnobody:x:65534:\n",
            "hosts": f"127.0.0.1 localhost {hostname}\n::1 localhost {hostname}\n",
            "hostname": hostname + "\n"}
    args = []
    for name, text in made.items():
        if Path("/etc", name).is_file():
            args += ["--ro-bind-data", str(_data_fd(text.encode())), f"/etc/{name}"]
    for name in ETC_HIDDEN:
        p = Path("/etc", name)
        if p.is_symlink():
            continue
        if p.is_dir():
            args += ["--tmpfs", str(p), "--remount-ro", str(p)]
        elif p.is_file():
            args += ["--ro-bind-data", str(_data_fd(b"")), str(p)]
    return args


def proc_args(keep_modules: bool = False) -> list[str]:
    """Blank PROC_HIDDEN over a fresh /proc (NVIDIA's userspace may look for its module)."""
    return [a for p in PROC_HIDDEN if Path(p).exists() and not (keep_modules and p == "/proc/modules")
            for a in ("--ro-bind-data", str(_data_fd(b"")), p)]


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


def overlay_ok() -> bool:
    """Can bwrap stack a private copy-on-write layer here (bwrap 0.8+, overlayfs in a
    user namespace)? Probed once with throwaway folders."""
    global _OVERLAY
    if _OVERLAY is None:
        SCRATCH.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=SCRATCH) as d:
            for sub in ("lower", "upper", "work"):
                os.mkdir(os.path.join(d, sub))
            try:
                _OVERLAY = subprocess.run(
                    ["bwrap", "--unshare-all", "--unshare-user", "--die-with-parent", *_root_fs(),
                     "--overlay-src", f"{d}/lower", "--overlay", f"{d}/upper", f"{d}/work", "/mnt",
                     "--", "/usr/bin/true"], capture_output=True, timeout=20).returncode == 0
            except (OSError, subprocess.SubprocessError):
                _OVERLAY = False
    return _OVERLAY


_OVERLAY: bool | None = None


def build(argv: list[str], binds_ro: list[tuple[str, str]], binds_rw: list[tuple[str, str]],
          wayland: str | None = None, gpu: bool = False, chdir: str = CAGE_HOME,
          extra_env: dict | None = None, pulse: str | None = None,
          machine_id: str | None = None, exec_app: bool = True, dgpu: bool = False,
          sockets: bool = True, overlays: list[tuple[str, str, str, str]] = ()) -> list[str]:
    """`overlays`: (lower, upper, work, dest) — dest shows lower, every write lands in upper."""
    cmd = ["bwrap",
           "--unshare-all", "--unshare-user", "--disable-userns",
           "--die-with-parent", "--new-session",
           "--hostname", "cage",
           "--clearenv",
           *_root_fs(),
           *etc_args("cage", CAGE_HOME, "cage"),
           "--proc", "/proc",
           *proc_args(keep_modules=gpu and dgpu),
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
    if Path("/etc/machine-id").is_file():
        cmd += ["--ro-bind-data", str(_data_fd(mid.encode())), "/etc/machine-id"]
    if seccomp.supported():
        cmd += ["--seccomp", str(_data_fd(seccomp.program(sockets=sockets)))]
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
        # a filtered socket in front of wlsec.RestrictedSocket, never the raw one
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
        cmd += _gpu_args(dgpu)
        if all(driver != "nvidia" for _, driver, _ in pick_gpus(dgpu)):
            # NVIDIA's userspace isn't even loaded when its card isn't there
            env.update(VK_LOADER_DRIVERS_DISABLE="*nvidia*", VK_LOADER_LAYERS_DISABLE="VK_LAYER_NV_*",
                       __EGL_VENDOR_LIBRARY_FILENAMES="/usr/share/glvnd/egl_vendor.d/50_mesa.json")
    for src, dst in binds_ro:
        cmd += ["--ro-bind", src, dst]
    for src, dst in binds_rw:
        cmd += ["--bind", src, dst]
    for lower, upper, work, dst in overlays:
        cmd += ["--overlay-src", lower, "--overlay", upper, work, dst]
    for k, v in {**env, **(extra_env or {})}.items():
        cmd += ["--setenv", k, v]
    # the cage's own root (a tmpfs holding the mount points) goes read-only last;
    # /tmp, the home tmpfs and the output bind stay writable as separate mounts
    cmd += ["--remount-ro", "/", "--chdir", chdir, "--", *landlock.wrap(argv, exec_app)]
    return cmd


def capture(cmd: list[str], timeout: int) -> tuple[int, str]:
    """Run a built cage without a terminal and return (returncode, output) — for the
    scanner, whose output we parse. Never raises; (-1, "") on failure or timeout."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           pass_fds=tuple(_FDS), preexec_fn=_limits, stdin=subprocess.DEVNULL)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return -1, ""
    finally:
        while _FDS:
            os.close(_FDS.pop())


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
