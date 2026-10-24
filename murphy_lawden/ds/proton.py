"""Proton inside the cage — for a Windows game, where plain Wine falls short.

`ds run --proton` swaps the throwaway Wine prefix for a Proton build Steam already
has (GE-Proton, dwproton, …) and a prefix that *stays*: installed files, saves and
shader caches live in `<output folder>/prefix`, inside the locked folder, so they
survive the run and are themselves unrunnable outside a cage.

The build is mounted read-only and started directly — no Steam, no Steam Linux
Runtime (that container needs user namespaces, which the cage forbids). The cage
around it is the same one: no network, no home, no D-Bus; sound only with --audio.

A kept prefix is also a place to persist. Wine honours the Windows autostarts every
time the prefix boots — Run/RunOnce keys and the Startup folder (wineboot), auto-
start services (services.exe), scheduled tasks, AppInit_DLLs, debugger hijacks — so
`autostarts()` lists them, and `ds run` refuses a prefix that grew one the Proton
build's own template doesn't have, until you accept it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from . import state

TOOL_DIRS = (Path.home() / ".local/share/Steam/compatibilitytools.d",
             Path.home() / ".steam/root/compatibilitytools.d",
             Path("/usr/share/steam/compatibilitytools.d"))
INNER = "/cage/proton"
INNER_PREFIX = "/cage/prefix"


def _natural(name: str) -> list:
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", name)]


def builds() -> list[Path]:
    """Every Proton build Steam knows of, newest first."""
    found: dict[str, Path] = {}
    for d in TOOL_DIRS:
        if not d.is_dir():
            continue
        for b in d.iterdir():
            if (b / "proton").is_file() and (b / "files/bin/wine").exists():
                found.setdefault(b.name, b.resolve())
    return sorted(found.values(), key=lambda b: _natural(b.name), reverse=True)


def pick(want: str | None) -> Path | None:
    """The newest build whose name contains `want`; with no `want`, the newest GE-Proton
    (falling back to the newest of anything)."""
    have = builds()
    if want:
        have = [b for b in have if want.lower() in b.name.lower()]
    else:
        have = [b for b in have if b.name.startswith("GE-Proton")] or have
    return have[0] if have else None


def prefix_of(target: Path) -> Path | None:
    """If `target` sits inside a Proton prefix (…/pfx/drive_c/…), the folder holding `pfx`.
    That's a game an earlier caged installer put there: it runs in the prefix it lives in."""
    parts = target.parts
    for i in range(len(parts) - 2, 0, -1):
        if parts[i] == "pfx" and parts[i + 1] == "drive_c":
            return Path(*parts[:i])
    return None


def argv(inner: str, name: str) -> list[str]:
    """Run it, then wait for the prefix to fall quiet: launchers and installers hand off
    to a child and exit, and the cage would take the child down with them."""
    run = ["msiexec", "/i", inner] if name.lower().endswith(".msi") else [inner]
    return ["sh", "-c", f'{INNER}/proton run "$@"; rc=$?; '
                        f'WINEPREFIX={INNER_PREFIX}/pfx {INNER}/files/bin/wineserver -w; exit $rc',
            "proton", *run]


def env(wayland: bool) -> dict[str, str]:
    e = {
        "STEAM_COMPAT_DATA_PATH": INNER_PREFIX,
        "STEAM_COMPAT_CLIENT_INSTALL_PATH": "/cage/steam",      # not there: no Steam in the cage
        # the cage's home is a tmpfs; without these every run recompiles every shader
        "__GL_SHADER_DISK_CACHE_PATH": INNER_PREFIX + "/shadercache",
        "__GL_SHADER_DISK_CACHE_SKIP_CLEANUP": "1",
        "DXVK_STATE_CACHE_PATH": INNER_PREFIX + "/shadercache",
        "MESA_SHADER_CACHE_DIR": INNER_PREFIX + "/shadercache",
    }
    if wayland:
        e["PROTON_ENABLE_WAYLAND"] = "1"       # there is no X11 in the cage to fall back to
    return e


def prepare(prefix: Path) -> bool:
    """Make the prefix folder; True if it is new."""
    fresh = not (prefix / "pfx").is_dir()
    (prefix / "shadercache").mkdir(parents=True, exist_ok=True)
    os.chmod(prefix, 0o700)
    return fresh


_RUN_KEYS = {r"software\microsoft\windows\currentversion\run",
             r"software\microsoft\windows\currentversion\runonce",
             r"software\microsoft\windows\currentversion\runservices",
             r"software\microsoft\windows\currentversion\runservicesonce",
             r"software\microsoft\windows\currentversion\policies\explorer\run",
             r"software\wow6432node\microsoft\windows\currentversion\run",
             r"software\wow6432node\microsoft\windows\currentversion\runonce"}
_WATCHED = {r"software\microsoft\windows nt\currentversion\winlogon": {"shell", "userinit"},
            r"software\wow6432node\microsoft\windows nt\currentversion\winlogon": {"shell", "userinit"},
            r"software\microsoft\windows nt\currentversion\windows": {"appinit_dlls", "load", "run"}}
_IFEO = "software\\microsoft\\windows nt\\currentversion\\image file execution options\\"
_SERVICE = re.compile(r"^system\\(?:currentcontrolset|controlset\d+)\\services\\([^\\]+)$")


def _unquote(text: str) -> tuple[str, str]:
    """A quoted .reg name at the start of `text` → (name, rest after the quote)."""
    out, i = [], 1
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            out.append(text[i + 1])
            i += 2
            continue
        if c == '"':
            return "".join(out), text[i + 1:]
        out.append(c)
        i += 1
    return "".join(out), ""


def _reg(path: Path, hive: str) -> list[str]:
    """The autostart entries in one Wine .reg file."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    found, services, key, i = [], {}, "", 0
    while i < len(lines):
        line = lines[i]
        while line.endswith("\\") and i + 1 < len(lines):          # hex values continue
            i += 1
            line = line[:-1] + lines[i].strip()
        i += 1
        if line.startswith("["):
            key = line[1:line.rfind("]")].replace("\\\\", "\\").lower()
            continue
        if not line.startswith(('"', "@=")):
            continue
        name, rest = ("", line[1:]) if line.startswith("@") else _unquote(line)
        value = rest.partition("=")[2].strip()
        lname = name.lower()
        svc = _SERVICE.match(key)
        if key in _RUN_KEYS:
            found.append(f"{hive}\\{key}: {name or '(default)'} = {value}")
        elif lname in _WATCHED.get(key, ()):
            found.append(f"{hive}\\{key}: {name} = {value}")
        elif key.startswith(_IFEO) and lname in ("debugger", "verifierdlls"):
            found.append(f"{hive}\\{key}: {name} = {value}")
        elif svc and lname in ("start", "imagepath"):
            services.setdefault(svc.group(1), {})[lname] = value
    for svc, v in services.items():
        if v.get("start", "").lower() in ("dword:00000000", "dword:00000001", "dword:00000002"):
            found.append(f"service {svc} ({v.get('start')}): {v.get('imagepath', '?')}")
    return found


def _ci(base: Path, *parts: str) -> list[Path]:
    """Every base/parts, matching each part case-insensitively — Windows paths, and a
    case-sensitive disk can hold "Startup" and "StartUp" side by side."""
    found = [base]
    for part in parts:
        nxt = []
        for b in found:
            try:
                nxt += [e for e in b.iterdir() if e.name.lower() == part.lower()]
            except OSError:
                pass
        found = nxt
    return found


def autostarts(pfx: Path) -> list[str]:
    """Everything in a Wine prefix (the folder holding system.reg and drive_c) that
    starts by itself when the prefix boots."""
    found = _reg(pfx / "system.reg", "HKLM") + _reg(pfx / "user.reg", "HKCU")
    drive = pfx / "drive_c"
    places = [*(d for users in _ci(drive, "users") for user in users.glob("*")
                for d in _ci(user, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")),
              *_ci(drive, "ProgramData", "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"),
              *_ci(drive, "windows", "system32", "Tasks"), *_ci(drive, "windows", "Tasks")]
    for d in places:
        for top, _, files in os.walk(d):
            found += [f"autostart file: {Path(top, f).relative_to(drive)}"
                      for f in files if f.lower() != "desktop.ini"]
    return sorted(set(found))


def _accepted_file(prefix: Path) -> Path:
    # outside the prefix: the program can write its prefix, not murphy's state
    tag = hashlib.sha256(str(prefix.resolve()).encode()).hexdigest()[:16]
    return state.state_dir() / "autostart" / f"{tag}.json"


def new_autostarts(prefix: Path, build: Path) -> list[str]:
    """Autostarts in `prefix` that neither the build's template prefix nor you put there."""
    known = set(autostarts(build / "files/share/default_pfx"))
    try:
        known |= set(json.loads(_accepted_file(prefix).read_text()))
    except (OSError, ValueError):
        pass
    return [e for e in autostarts(prefix / "pfx") if e not in known]


def accept_autostarts(prefix: Path, entries: list[str]) -> None:
    f = _accepted_file(prefix)
    try:
        have = set(json.loads(f.read_text()))
    except (OSError, ValueError):
        have = set()
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(sorted(have | set(entries)), indent=1))
