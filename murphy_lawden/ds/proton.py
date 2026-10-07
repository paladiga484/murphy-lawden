"""Proton inside the cage — for a Windows game, where plain Wine falls short.

`ds run --proton` swaps the throwaway Wine prefix for a Proton build Steam already
has (GE-Proton, dwproton, …) and a prefix that *stays*: installed files, saves and
shader caches live in `<output folder>/prefix`, inside the locked folder, so they
survive the run and are themselves unrunnable outside a cage.

The build is mounted read-only and started directly — no Steam, no Steam Linux
Runtime (that container needs user namespaces, which the cage forbids). The cage
around it is the same one: no network, no home, no D-Bus; sound only with --audio.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

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
