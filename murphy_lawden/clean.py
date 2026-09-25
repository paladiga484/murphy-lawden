"""clean — one command to sweep the junk, and nothing that isn't junk.

`murphy clean` measures every target and changes nothing. `murphy clean --apply`
sweeps them. It runs as *you*: root-owned targets are cleared through `sudo`
one command at a time, so `~` is always your home, never /root (the trap the
`tweak --su` path falls into).

Deliberately never touched, because each one "regenerates" as a cost you feel:
  * shader caches (nvidia / mesa / radv / dxvk) — they come back as game stutter
  * Wine / Proton prefixes, ~/.cache/wine, protonfixes — re-downloads, re-installs
  * ~/Downloads — reported (largest files) so you can decide; never deleted
"""
from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .core import have, run

HOME = Path.home()


@dataclass
class Target:
    id: str
    desc: str
    size: int                 # bytes reclaimable (best estimate)
    cmds: list                # argv lists; a leading "sudo" marks root work
    note: str = ""


def _du(*paths: Path) -> int:
    total = 0
    for p in paths:
        if not p.exists():
            continue
        rc, out = run(["du", "-sb", str(p)], timeout=60)
        if rc == 0 and out.split():
            total += int(out.split()[0])
    return total


def _human(n: int) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n}"


def _paccache_bytes(flags: list[str]) -> int:
    """paccache dry-run prints '(disk space saved: 3.35 GiB)'."""
    rc, out = run(["paccache", "-d", *flags], timeout=60)
    m = re.search(r"disk space saved:\s*([\d.]+)\s*(\w+)", out)
    if not m:
        return 0
    mult = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}
    return int(float(m.group(1)) * mult.get(m.group(2), 1))


def _targets(deep: bool) -> list[Target]:
    T: list[Target] = []

    if have("paccache"):
        keep = "1" if deep else "2"
        size = _paccache_bytes([f"-k{keep}"]) + _paccache_bytes(["-uk0"])
        if size:
            T.append(Target("pacman-cache", f"pacman package cache (keep last {keep}, drop uninstalled)",
                            size, [["sudo", "paccache", "-r", f"-k{keep}"], ["sudo", "paccache", "-ruk0"]]))
        if not deep and _paccache_bytes(["-k1"]) > size:
            deep_hint = _human(_paccache_bytes(["-k1"]))
            T.append(Target("pacman-deep", f"pacman cache already at 2 versions; --deep frees {deep_hint} "
                            "more but drops the downgrade path", 0, []))

    if have("pacman"):
        orphans = run(["pacman", "-Qtdq"])[1].split()
        if orphans:
            T.append(Target("orphans", f"orphaned packages ({len(orphans)}): {' '.join(orphans[:6])}"
                            + (" …" if len(orphans) > 6 else ""),
                            0, [["sudo", "pacman", "-Rns", "--noconfirm", *orphans]],
                            note="size shown after removal"))

    core = Path("/var/lib/systemd/coredump")
    csize = _du(core)
    if csize:
        T.append(Target("coredumps", "saved crash dumps", csize,
                        [["sudo", "find", str(core), "-type", "f", "-delete"]]))

    rc, out = run(["journalctl", "--disk-usage"])
    m = re.search(r"take up ([\d.]+)([KMGT])", out)
    if m:
        jbytes = int(float(m.group(1)) * {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m.group(2)])
        if jbytes > 200 << 20:
            T.append(Target("journal", "systemd journal (vacuum to 200M)", jbytes - (200 << 20),
                            [["sudo", "journalctl", "--vacuum-size=200M"]]))

    trash = HOME / ".local/share/Trash"
    tsize = _du(trash / "files", trash / "info")
    if tsize:
        T.append(Target("trash", "your Trash", tsize,
                        [["find", str(trash / "files"), str(trash / "info"),
                          "-mindepth", "1", "-delete"]]))

    thumbs = HOME / ".cache/thumbnails"
    thsize = _du(thumbs)
    if thsize:
        T.append(Target("thumbnails", "thumbnail cache", thsize,
                        [["find", str(thumbs), "-mindepth", "1", "-delete"]]))

    if have("flatpak"):
        rc, out = run(["flatpak", "list", "--unused", "--columns=ref"], timeout=60)
        refs = [l for l in out.splitlines() if l.strip() and "/" in l]
        if refs:
            T.append(Target("flatpak", f"unused flatpak runtimes ({len(refs)})", 0,
                            [["flatpak", "uninstall", "--unused", "-y"]],
                            note="size shown after removal"))

    # .desktop handlers left behind by AppImages that ran from a /tmp mount
    apps = HOME / ".local/share/applications"
    stale = []
    for d in apps.glob("*.desktop") if apps.is_dir() else ():
        try:
            for line in d.read_text(errors="replace").splitlines():
                if line.startswith("Exec="):
                    exe = shlex.split(line[5:])[0] if line[5:].strip() else ""
                    if exe.startswith("/tmp/.mount_") and not os.path.exists(exe):
                        stale.append(d)
                    break
        except (OSError, ValueError):
            continue
    if stale:
        T.append(Target("stale-launchers", "launchers pointing at a vanished AppImage mount: "
                        + ", ".join(p.name for p in stale), sum(p.stat().st_size for p in stale),
                        [["rm", "-f", *map(str, stale)]]))
    return T


def _downloads_report(ink, limit: int = 8) -> None:
    dl = HOME / "Downloads"
    if not dl.is_dir():
        return
    rc, out = run(["du", "-sb", *map(str, sorted(dl.iterdir()))], timeout=120)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t", 1)
        if len(parts) == 2 and parts[0].isdigit():
            rows.append((int(parts[0]), parts[1]))
    rows.sort(reverse=True)
    if not rows:
        return
    print("\n  " + ink.blood("— ~/Downloads (report only, never deleted) —"))
    for size, path in rows[:limit]:
        print(f"    {_human(size):>7}  {Path(path).name}")


def run_clean(apply: bool, deep: bool, ink) -> int:
    targets = _targets(deep)
    print(ink.bone("  MURPHY CLEAN — " + ("sweeping" if apply else "survey (nothing changes)")))
    if not any(t.cmds for t in targets):
        print("  " + ink.green("Nothing to sweep. The house is in order."))
    total = 0
    for t in targets:
        if not t.cmds:                      # a hint, not a sweep
            print(f"             {ink.dim(t.desc)}")
            continue
        total += t.size
        who = ink.amber("sudo") if t.cmds and t.cmds[0][0] == "sudo" else ink.dim("user")
        size = _human(t.size) if t.size else "  ?"
        print(f"    {size:>7}  {who}  {t.desc}")
        if t.note:
            print(f"             {ink.dim(t.note)}")
    if any(t.cmds for t in targets):
        print("    " + ink.bold(f"{_human(total):>7}  reclaimable"))
    print("  " + ink.dim("kept on purpose: shader caches, Wine/Proton prefixes & caches."))
    if not apply:
        _downloads_report(ink)

    if not apply:
        if any(t.cmds for t in targets):
            print("\n  " + ink.dim("Sweep with: ") + ink.cyan("murphy clean --apply")
                  + ink.dim("  (asks for your sudo password once)"))
        return 0

    failed = 0
    for t in targets:
        for cmd in t.cmds:
            rc = subprocess.run(cmd).returncode
            mark = ink.green("✓") if rc == 0 else ink.amber(f"✗ {rc}")
            print(f"  {mark} {t.id}: {' '.join(cmd)[:90]}")
            failed += rc != 0
    print("\n  " + (ink.green("Swept.") if not failed else ink.amber(f"Swept with {failed} failure(s).")))
    return 1 if failed else 0
