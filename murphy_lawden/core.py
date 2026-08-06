"""Core data model, host detection, and the check registry for Murphy Lawden.

A *check* is a callable that inspects the host and yields zero or more
``Finding`` objects. Checks never mutate the system — Murphy diagnoses and
advises; the operator decides what to apply. Community check-packs are loaded
declaratively (see ``rules.py``) through the same ``Finding`` interface.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Callable, Iterable


# --------------------------------------------------------------------------- #
#  Severity & status
# --------------------------------------------------------------------------- #
class Severity(IntEnum):
    """How much a failed check costs the host's hardening posture."""
    INFO = 0
    LOW = 3
    MEDIUM = 8
    HIGH = 15
    CRITICAL = 25

    @classmethod
    def parse(cls, name: str) -> "Severity":
        return cls[name.strip().upper()]


class Status(IntEnum):
    PASS = 0      # the host is doing the right thing
    WARN = 1      # not wrong, but worth a look
    FAIL = 2      # a real weakness Murphy can pin down
    INFO = 3      # context, not scored
    SKIP = 4      # couldn't determine (missing tool / needs root)


@dataclass
class Finding:
    """A single verdict from a single check."""
    id: str
    title: str
    status: Status
    severity: Severity = Severity.INFO
    detail: str = ""            # what Murphy actually observed
    rationale: str = ""         # why it matters to an attacker/defender
    fix: str = ""               # generic remediation (human text)
    fix_notes: dict = field(default_factory=dict)  # os-specific remediation, keyed by tag
    refs: list[str] = field(default_factory=list)  # CIS / CVE / vendor docs
    remedy: "object | None" = None   # a remedy.Remedy the autopilot can apply (None = manual only)
    dedupe_key: str = ""        # collapse the same underlying issue from >1 source (see cli._dedupe)

    @property
    def weight(self) -> int:
        return int(self.severity) if self.status == Status.FAIL else 0


# --------------------------------------------------------------------------- #
#  Shell helpers — all read-only, all failure-tolerant
# --------------------------------------------------------------------------- #
def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def run(cmd: list[str], timeout: int = 15) -> tuple[int, str]:
    """Run a read-only command; return (returncode, combined-output).

    Never raises — a missing binary or timeout returns (-1, "")."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.SubprocessError):
        return -1, ""


def read(path: str, limit: int = 1_000_000) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def sysctl(key: str) -> str | None:
    """Read a kernel parameter from /proc/sys (no external tool needed)."""
    val = read("/proc/sys/" + key.replace(".", "/"))
    return val.strip() if val is not None else None


# --------------------------------------------------------------------------- #
#  Host profile
# --------------------------------------------------------------------------- #
@dataclass
class Host:
    system: str          # Linux / Windows / Darwin / FreeBSD ...
    family: str          # linux / bsd / windows / macos / unknown
    distro_id: str = ""  # nixos, debian, chimera, alpine, ...
    distro_like: str = ""
    pretty: str = ""
    kernel: str = ""
    init: str = "unknown"      # systemd / openrc / runit / s6 / sysvinit / launchd
    libc: str = "unknown"      # glibc / musl
    pkg: str = "unknown"       # nix / apt / dnf / pacman / apk / xbps / pkg
    is_root: bool = False
    hostname: str = ""
    tags: set[str] = field(default_factory=set)  # e.g. {"nixos", "systemd", "musl"}

    def has(self, tag: str) -> bool:
        return tag in self.tags

    def env_label(self) -> str:
        """One-line 'where is this running' summary for the case file, derived from
        the virtualisation/device tags. Empty string on plain bare metal."""
        specifics = ["kvm", "qemu", "vmware", "virtualbox", "hyperv", "xen", "parallels"]
        detail = next((t for t in specifics if t in self.tags), "")
        if self.has("waydroid"):
            return "Waydroid (Android in a container)"
        if self.has("wsl"):
            return "WSL (Windows Subsystem for Linux)"
        if self.has("android"):
            return "physical device" if not (self.has("vm") or self.has("container")) else "emulated device"
        if self.has("container"):
            kind = next((t for t in ("docker", "podman", "lxc") if t in self.tags), "container")
            return f"container ({kind})"
        if self.has("vm"):
            return f"virtual machine ({detail})" if detail else "virtual machine"
        return ""


# PID-1 command name → init system. Covers the mainstream and the exotic.
_INIT_COMM = {
    "systemd": "systemd",
    "runit": "runit", "runsvdir": "runit", "runsv": "runit",
    "s6-svscan": "s6", "s6-linux-init": "s6", "s6-svc": "s6",
    "openrc-init": "openrc", "openrc": "openrc",
    "dinit": "dinit",                     # Chimera, Artix
    "shepherd": "shepherd",               # GNU Guix
    "finit": "finit",
    "procd": "procd",                     # OpenWrt
    "epoch": "epoch",
    "66": "66", "s6-rc": "66",            # skarnet 66
    "nosh": "nosh",
    "busybox": "busybox-init",
    "launchd": "launchd",                 # macOS
    "init": "sysvinit",
}
# Marker dirs (fast, reliable when present).
_INIT_DIRS = [
    ("/run/systemd/system", "systemd"), ("/run/openrc", "openrc"),
    ("/run/dinit", "dinit"), ("/run/s6", "s6"), ("/run/s6-rc", "66"),
    ("/run/runit", "runit"), ("/run/shepherd", "shepherd"), ("/run/finit", "finit"),
]
# Last resort: a control binary on PATH implies its supervisor.
_INIT_PROBES = [
    ("rc-status", "openrc"), ("dinitctl", "dinit"), ("herd", "shepherd"),
    ("s6-svscan", "s6"), ("sv", "runit"), ("finit", "finit"),
]


def _detect_init() -> str:
    for d, name in _INIT_DIRS:
        if os.path.isdir(d):
            return name
    comm = read("/proc/1/comm")
    if comm:
        c = comm.strip()
        if c in _INIT_COMM:
            return _INIT_COMM[c]
        for key, name in _INIT_COMM.items():
            if key in c:
                return name
    for probe, name in _INIT_PROBES:
        if have(probe):
            return name
    return "unknown"


def _detect_libc() -> str:
    if any(Path("/lib").glob("ld-musl-*")) or any(Path("/lib").glob("libc.musl-*")):
        return "musl"
    rc, out = run(["ldd", "--version"])
    if "musl" in out.lower():
        return "musl"
    if "glibc" in out.lower() or "gnu libc" in out.lower():
        return "glibc"
    return "glibc" if os.path.exists("/lib/x86_64-linux-gnu") or os.path.exists("/lib64") else "unknown"


# Most reliable: os-release ID → the distro's native package manager.
_PKG_BY_ID = {
    "nixos": "nix", "guix": "guix", "guixsd": "guix",
    "gentoo": "portage", "funtoo": "portage", "calculate": "portage",
    "redcore": "portage", "sabayon": "portage", "pentoo": "portage",
    "moccaccino": "portage", "chromeos": "portage", "chromiumos": "portage",
    "exherbo": "paludis", "crux": "pkgutils", "void": "xbps",
    "clear-linux-os": "swupd", "solus": "eopkg", "kiss": "kiss", "carbs": "cpt",
    "slackware": "slackpkg", "slackware64": "slackpkg", "salix": "slackpkg",
    "gobolinux": "gobo", "nutyx": "cards", "dragora": "qi", "frugalware": "pacman-g2",
    "venom": "scratch", "t2": "portage",
    "alpine": "apk", "chimera": "apk", "adelie": "apk", "postmarketos": "apk",
    "arch": "pacman", "archarm": "pacman", "artix": "pacman", "parabola": "pacman",
    "hyperbola": "pacman", "manjaro": "pacman", "endeavouros": "pacman", "garuda": "pacman",
    "cachyos": "pacman", "arcolinux": "pacman", "archcraft": "pacman", "archbang": "pacman",
    "archlabs": "pacman", "obarun": "pacman", "kaos": "pacman", "mabox": "pacman",
    "blendos": "pacman", "biglinux": "pacman", "crystal": "pacman", "snigdha": "pacman",
    "debian": "apt", "ubuntu": "apt", "devuan": "apt", "linuxmint": "apt",
    "pop": "apt", "raspbian": "apt", "kali": "apt", "pureos": "apt", "elementary": "apt",
    "mx": "apt", "antix": "apt", "zorin": "apt", "deepin": "apt", "uos": "apt",
    "kylin": "apt", "openkylin": "apt", "neptune": "apt", "peppermint": "apt",
    "bodhi": "apt", "sparky": "apt", "tails": "apt", "whonix": "apt", "q4os": "apt",
    "trisquel": "apt", "parrot": "apt", "backbox": "apt", "bunsenlabs": "apt",
    "mobian": "apt", "droidian": "apt", "kaisen": "apt", "spiral": "apt",
    "fedora": "dnf", "rhel": "dnf", "centos": "dnf", "rocky": "dnf", "almalinux": "dnf",
    "ol": "dnf", "amzn": "dnf", "openmandriva": "dnf", "mageia": "urpmi", "pclinuxos": "apt-rpm",
    "nobara": "dnf", "openeuler": "dnf", "anolis": "dnf", "opencloudos": "dnf",
    "tencentos": "dnf", "eurolinux": "dnf", "circle": "dnf", "navylinux": "dnf",
    "springdale": "dnf", "rosa": "urpmi", "altlinux": "apt-rpm", "alt": "apt-rpm",
    "opensuse": "zypper", "opensuse-tumbleweed": "zypper", "opensuse-leap": "zypper",
    "opensuse-slowroll": "zypper", "opensuse-microos": "zypper", "opensuse-aeon": "zypper",
    "sled": "zypper", "sles": "zypper", "suse": "zypper",
    "serpent": "moss", "aerynos": "moss", "source-mage": "sorcery", "sourcemage": "sorcery",
    "lunar": "lunar", "pld": "poldek", "slitaz": "tazpkg", "openwrt": "opkg",
    "bedrock": "bedrock", "endless": "flatpak", "endlessos": "flatpak",
    "android": "pkg", "termux": "pkg", "lineageos": "pkg",
    "freebsd": "pkg", "ghostbsd": "pkg", "dragonfly": "pkg", "midnightbsd": "mport",
    "netbsd": "pkgsrc", "openbsd": "pkg_add", "hardenedbsd": "pkg", "truenas": "pkg",
    "opnsense": "pkg", "pfsense": "pkg",
}
# Fallback: probe for a manager binary on PATH. Order = distinctive/exotic first,
# so a source distro with nix/guix layered on isn't mislabelled by a generic hit.
_PKG_PROBES = [
    ("brl", "bedrock"), ("guix", "guix"), ("emerge", "portage"), ("cave", "paludis"),
    ("prt-get", "pkgutils"), ("pkgadd", "pkgutils"), ("swupd", "swupd"),
    ("eopkg", "eopkg"), ("kiss", "kiss"), ("cpt", "cpt"), ("moss", "moss"),
    ("sorcery", "sorcery"), ("cast", "sorcery"), ("lin", "lunar"),
    ("cards", "cards"), ("qi", "qi"), ("scratch", "scratch"), ("gobo", "gobo"),
    ("pacman-g2", "pacman-g2"), ("rpm-ostree", "rpm-ostree"),
    ("slackpkg", "slackpkg"), ("installpkg", "slackpkg"), ("xbps-install", "xbps"),
    ("nix", "nix"), ("apk", "apk"), ("pacman", "pacman"), ("apt", "apt"),
    ("dnf", "dnf"), ("dnf5", "dnf"), ("yum", "yum"), ("urpmi", "urpmi"),
    ("zypper", "zypper"), ("poldek", "poldek"), ("tazpkg", "tazpkg"),
    ("opkg", "opkg"), ("pkgin", "pkgin"), ("pkg_add", "pkgsrc"), ("pkg", "pkg"),
]
# Package managers that build from source (affects install expectations/advice).
_SOURCE_PKG = {"portage", "paludis", "pkgutils", "kiss", "cpt", "sorcery", "lunar",
               "guix", "cards", "qi", "scratch", "gobo"}


def _detect_android() -> bool:
    """True on Android (phones/tablets, Termux, Waydroid, LineageOS, etc.).

    platform.system() is 'Linux' on Android, so the family stays linux and every
    Linux check still runs — this just lets Murphy *also* apply the Android/`su`
    checks and mobile-spyware indicators.

    Detection is layered so it survives odd ROMs and Termux/proot: env markers first
    (cheapest), then the on-disk runtime, then a live getprop that returns a real
    Android build property (the definitive tell when the filesystem is unusual)."""
    if any(os.environ.get(v) for v in ("ANDROID_ROOT", "ANDROID_DATA", "ANDROID_STORAGE")):
        return True
    for marker in ("/system/build.prop", "/system/bin/app_process",
                   "/system/bin/app_process64", "/system/bin/app_process32",
                   "/system/framework/framework.jar", "/init.environ.rc",
                   "/data/data/com.termux/files", "/system/etc/permissions"):
        if os.path.exists(marker):
            return True
    # Termux, proot-distro, or a stripped ROM: trust getprop if it answers with a
    # numeric SDK level (only Android's property service does that).
    if have("getprop"):
        rc, out = run(["getprop", "ro.build.version.sdk"], timeout=5)
        if rc == 0 and out.strip().isdigit():
            return True
    return False


# --------------------------------------------------------------------------- #
#  Virtualisation / device environment (VM · container · WSL · Waydroid)
# --------------------------------------------------------------------------- #
def _detect_virt() -> set[str]:
    """Best-effort tags for *where* this Linux is running. Every probe is read-only
    and failure-tolerant; on bare metal it simply returns an empty set.

    Tags can include a class ({"vm"}, {"container"}) plus a specific technology
    ("kvm", "qemu", "vmware", "virtualbox", "hyperv", "xen", "docker", "podman",
    "lxc", "wsl", "waydroid"). Advice keys off these — e.g. Secure Boot / firmware
    checks are noise inside a container, and Waydroid is Android-in-a-box."""
    tags: set[str] = set()

    # Containers — the fast, reliable markers.
    if os.path.exists("/.dockerenv"):
        tags |= {"container", "docker"}
    if os.path.exists("/run/.containerenv"):
        tags |= {"container", "podman"}
    cenv = os.environ.get("container")
    if cenv:
        tags |= {"container", cenv.lower()}
    cg = read("/proc/1/cgroup") or ""
    if "docker" in cg:
        tags |= {"container", "docker"}
    if "/lxc" in cg or "lxc" in (read("/proc/1/environ") or ""):
        tags |= {"container", "lxc"}

    # WSL (Windows Subsystem for Linux) — a Microsoft kernel string is the tell.
    ver = (read("/proc/version") or "").lower()
    if "microsoft" in ver or "wsl" in ver or os.environ.get("WSL_DISTRO_NAME"):
        tags.add("wsl")

    # Waydroid — Android running in a LXC container on a Linux desktop.
    if os.path.isdir("/var/lib/waydroid") or (os.path.exists("/dev/binderfs") and have("waydroid")):
        tags.add("waydroid")

    # Hypervisor via DMI (world-readable on most systems, no tool needed).
    dmi = " ".join(read(f"/sys/class/dmi/id/{f}") or ""
                   for f in ("product_name", "sys_vendor", "board_vendor")).lower()
    for needle, name in (("kvm", "kvm"), ("qemu", "qemu"), ("bochs", "qemu"),
                         ("virtualbox", "virtualbox"), ("innotek", "virtualbox"),
                         ("vmware", "vmware"), ("microsoft corporation", "hyperv"),
                         ("xen", "xen"), ("parallels", "parallels")):
        if needle in dmi:
            tags |= {"vm", name}

    # systemd-detect-virt is authoritative when it's on the box.
    if have("systemd-detect-virt"):
        rc, out = run(["systemd-detect-virt"], timeout=5)
        v = out.strip().lower()
        if rc == 0 and v and v != "none":
            container_kinds = {"lxc", "lxc-libvirt", "systemd-nspawn", "docker", "podman",
                               "rkt", "openvz", "wsl", "proot", "pouch"}
            tags.add("container" if v in container_kinds else "vm")
            tags.add(v)
    return tags


def _android_pretty() -> str:
    """A human label for an Android host, best-effort via getprop."""
    rc, rel = run(["getprop", "ro.build.version.release"])
    rc2, sdk = run(["getprop", "ro.build.version.sdk"])
    rc3, name = run(["getprop", "ro.product.model"])
    rel, sdk, name = rel.strip(), sdk.strip(), name.strip()
    label = "Android"
    if rel:
        label += f" {rel}"
    if sdk:
        label += f" (API {sdk})"
    if name:
        label += f" — {name}"
    return label


def _detect_pkg(distro_id: str = "", distro_like: str = "") -> str:
    if distro_id in _PKG_BY_ID:
        return _PKG_BY_ID[distro_id]
    for tok in distro_like.split():
        if tok in _PKG_BY_ID:
            return _PKG_BY_ID[tok]
    for tool, name in _PKG_PROBES:
        if have(tool):
            return name
    return "unknown"


def detect_host() -> Host:
    import platform as _p
    system = _p.system() or "Unknown"
    family = {"Linux": "linux", "Windows": "windows", "Darwin": "macos"}.get(system, "")
    if not family:
        family = "bsd" if "BSD" in system.upper() else "unknown"

    host = Host(
        system=system,
        family=family,
        kernel=_p.release(),
        hostname=_p.node(),
        is_root=(hasattr(os, "geteuid") and os.geteuid() == 0),
    )

    osr = read("/etc/os-release") or ""
    fields = {k: (q or bare) for k, q, bare in
              re.findall(r'^([A-Z_]+)=(?:"([^"]*)"|(\S*))', osr, re.M)}
    host.distro_id = fields.get("ID", "")
    host.distro_like = fields.get("ID_LIKE", "")
    host.pretty = fields.get("PRETTY_NAME", "") or system

    if family == "linux":
        host.init = _detect_init()
        host.libc = _detect_libc()
        host.pkg = _detect_pkg(host.distro_id, host.distro_like)
        # Android rides on the Linux kernel: keep family=linux so every Linux
        # check runs, but tag it so the su/root checks and mobile-spyware IOCs fire.
        if _detect_android():
            host.tags.add("android")
            if not host.distro_id:
                host.distro_id = "android"
            host.pretty = _android_pretty()
            # Termux ships apt/pkg; if nothing else was detected, say so.
            if host.pkg == "unknown" and (have("pkg") or have("apt")):
                host.pkg = "pkg"
        if host.distro_id == "nixos" or os.path.exists("/etc/NIXOS"):
            host.tags.add("nixos")
        if os.path.isdir("/bedrock") or host.pkg == "bedrock":
            host.tags.add("bedrock")
        if host.init != "unknown":
            host.tags.add(host.init)
        if host.libc == "musl":
            host.tags.add("musl")
        if host.pkg != "unknown":
            host.tags.add("pkg:" + host.pkg)
        if host.pkg in _SOURCE_PKG:
            host.tags.add("source-based")
        if host.distro_id:
            host.tags.add(host.distro_id)
        for like in host.distro_like.split():
            host.tags.add(like)
        # Where is this Linux actually running? (VM / container / WSL / Waydroid)
        host.tags |= _detect_virt()
    return host


# --------------------------------------------------------------------------- #
#  Check registry
# --------------------------------------------------------------------------- #
CheckFn = Callable[[Host], Iterable[Finding]]
_REGISTRY: list[tuple[str, CheckFn]] = []


def check(family: str = "linux"):
    """Register a check for a given OS family (``"*"`` = all)."""
    def deco(fn: CheckFn) -> CheckFn:
        _REGISTRY.append((family, fn))
        return fn
    return deco


def run_checks(host: Host) -> list[Finding]:
    findings: list[Finding] = []
    for family, fn in _REGISTRY:
        if family not in ("*", host.family):
            continue
        try:
            for f in fn(host) or ():
                findings.append(f)
        except Exception as e:  # a broken check must never sink the whole run
            findings.append(Finding(
                id=getattr(fn, "__name__", "unknown"),
                title=f"check '{getattr(fn, '__name__', '?')}' errored",
                status=Status.SKIP, detail=str(e),
            ))
    return findings
