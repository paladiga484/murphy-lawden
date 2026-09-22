"""``murphy tweak`` — the Library of Ruina. A catalog of system tweaks.

Every tweak is a small, named, *checked* operation: Murphy reads the current
state, tells you the target, and only changes it if you say so. Read-only by
default (a bare ``murphy tweak`` just files the catalog with each entry's live
state); ``--apply`` acts, asking per tweak unless ``-y``. Root-only tweaks are
planned, not forced, when you're unprivileged — pass ``--su`` to elevate.

Categories: **memory · performance · cache · cleanup · gaming · storage**.
Reversible tweaks carry their revert; one-shot reclaims (cache/journal/trim) are
marked so you know they don't "undo."
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .core import have, run, read, detect_host

CATS = ("memory", "performance", "cache", "cleanup", "gaming", "storage")


@dataclass
class Tweak:
    id: str
    cat: str
    desc: str
    apply: list                       # list of argv lists to run
    revert: list = field(default_factory=list)
    root: bool = True
    reversible: bool = True
    risk: str = "low"                 # low | medium | high
    why: str = ""
    state: object = None              # optional: fn() -> str (current live state)
    applies: object = None            # optional: fn() -> bool (is it relevant here?)
    oneshot: bool = False             # a reclaim (no meaningful "undo")


def _sysctl_now_and_persist(key, value):
    return [["sysctl", "-w", f"{key}={value}"],
            ["sh", "-c", f"echo '{key} = {value}' > /etc/sysctl.d/70-murphy-tweak-{key.replace('.', '-')}.conf"]]


def _sysctl_state(key):
    return lambda: (read("/proc/sys/" + key.replace(".", "/")) or "?").strip()


# --------------------------------------------------------------------------- #
#  The catalog
# --------------------------------------------------------------------------- #
def _catalog(host) -> list:
    gov_path = "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
    T = [
        # ---- memory ----------------------------------------------------- #
        Tweak("mem.oomd", "memory", "Enable systemd-oomd (graceful OOM instead of a hard freeze)",
              [["systemctl", "enable", "--now", "systemd-oomd"]],
              revert=[["systemctl", "disable", "--now", "systemd-oomd"]],
              why="On a RAM-tight box, filling memory freezes the desktop; oomd kills the hog first.",
              state=lambda: run(["systemctl", "is-active", "systemd-oomd"])[1].strip() or "inactive"),
        Tweak("mem.swappiness", "memory", "swappiness=180 (favour fast zram over stalling)",
              _sysctl_now_and_persist("vm.swappiness", "180"),
              why="With zram, swapping to compressed RAM is cheap — push harder before reclaim stalls.",
              state=_sysctl_state("vm.swappiness"),
              applies=lambda: (read("/proc/swaps") or "").find("zram") >= 0),
        Tweak("mem.page_cluster", "memory", "page-cluster=0 (no swap read-ahead — best for zram)",
              _sysctl_now_and_persist("vm.page-cluster", "0"),
              why="zram is random-access; reading ahead just wastes cycles.",
              state=_sysctl_state("vm.page-cluster")),
        Tweak("mem.thp_madvise", "memory", "Transparent Huge Pages → madvise (fewer game stalls)",
              [["sh", "-c", "echo madvise > /sys/kernel/mm/transparent_hugepage/enabled"]],
              revert=[["sh", "-c", "echo always > /sys/kernel/mm/transparent_hugepage/enabled"]],
              why="THP=always can cause compaction stall spikes under Wine/Proton; madvise is calmer.",
              state=lambda: (read("/sys/kernel/mm/transparent_hugepage/enabled") or "?")
              .split("[")[-1].split("]")[0] if read("/sys/kernel/mm/transparent_hugepage/enabled") else "?"),
        Tweak("mem.dropcaches", "memory", "Drop page/dentry/inode caches now (one-shot reclaim)",
              [["sh", "-c", "sync; echo 3 > /proc/sys/vm/drop_caches"]],
              reversible=False, oneshot=True,
              why="Frees reclaimable cache immediately — handy right before launching a heavy game."),
        Tweak("mem.compaction", "memory", "Compact memory now (defrag physical RAM for THP)",
              [["sh", "-c", "echo 1 > /proc/sys/vm/compact_memory"]],
              reversible=False, oneshot=True,
              why="Reduces fragmentation so huge-page allocations succeed without stalls."),

        # ---- performance ------------------------------------------------- #
        Tweak("perf.governor", "performance", "CPU governor → performance (max clocks under load)",
              [["sh", "-c", "for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > $c; done"]],
              revert=[["sh", "-c", "for c in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo powersave > $c; done"]],
              why="gamemode does this per-launch; set it globally for a consistent ceiling.",
              state=lambda: (read(gov_path) or "?").strip()),
        Tweak("perf.split_lock", "performance", "split_lock_mitigate=0 (drop the split-lock stall penalty)",
              _sysctl_now_and_persist("kernel.split_lock_mitigate", "0"),
              risk="medium",
              why="Some games trip split-lock detection and get throttled hard; disabling recovers frames.",
              state=_sysctl_state("kernel.split_lock_mitigate")),
        Tweak("perf.sched_child_runs_first", "performance", "sched: parent runs first (snappier spawns)",
              _sysctl_now_and_persist("kernel.sched_child_runs_first", "0"),
              why="Minor scheduler nicety for fork-heavy workloads (Wine).",
              state=_sysctl_state("kernel.sched_child_runs_first")),
        Tweak("perf.platform_profile", "performance", "ASUS platform profile → performance",
              [["sh", "-c", "echo performance > /sys/firmware/acpi/platform_profile"]],
              revert=[["sh", "-c", "echo balanced > /sys/firmware/acpi/platform_profile"]],
              why="Raises the EC power/thermal budget so the CPU/GPU can actually boost.",
              applies=lambda: bool(read("/sys/firmware/acpi/platform_profile")),
              state=lambda: (read("/sys/firmware/acpi/platform_profile") or "?").strip()),

        # ---- cache (reclaim disk / scrub) -------------------------------- #
        Tweak("cache.pacman", "cache", "Trim the pacman package cache (keep 2 versions)",
              [["sh", "-c", "command -v paccache >/dev/null && paccache -rk2 || pacman -Sc --noconfirm"]],
              reversible=False, oneshot=True,
              why="Downloaded packages pile up in /var/cache/pacman; keep the last 2 for rollback.",
              applies=lambda: have("pacman")),
        Tweak("cache.journal", "cache", "Vacuum the systemd journal to 200M",
              [["journalctl", "--vacuum-size=200M"]],
              reversible=False, oneshot=True,
              why="Logs grow unbounded; 200M keeps plenty of history without hoarding disk."),
        Tweak("cache.user", "cache", "Clear your user cache (~/.cache, keeps app state)",
              [["sh", "-c", "rm -rf ~/.cache/thumbnails/* ~/.cache/mesa_shader_cache_db/* 2>/dev/null; true"]],
              root=False, reversible=False, oneshot=True,
              why="Thumbnail and old shader caches regenerate; safe to clear.",
              state=lambda: (run(["sh", "-c", "du -sh ~/.cache 2>/dev/null | cut -f1"])[1].strip() or "?")),
        Tweak("cache.coredumps", "cache", "Purge saved coredumps",
              [["sh", "-c", "rm -f /var/lib/systemd/coredump/* 2>/dev/null; true"]],
              reversible=False, oneshot=True,
              why="Crash dumps (e.g. the vesktop ones) can be large and are rarely needed after triage."),

        # ---- cleanup ----------------------------------------------------- #
        Tweak("clean.orphans", "cleanup", "Remove orphaned packages (unused deps)",
              [["sh", "-c", "o=$(pacman -Qtdq); [ -n \"$o\" ] && pacman -Rns --noconfirm $o || echo 'no orphans'"]],
              reversible=False,
              why="Leftover dependencies nothing needs any more.",
              applies=lambda: have("pacman"),
              state=lambda: (run(["sh", "-c", "pacman -Qtdq 2>/dev/null | wc -l"])[1].strip() + " orphan(s)")),
        Tweak("clean.trim", "storage", "Enable weekly SSD TRIM (fstrim.timer)",
              [["systemctl", "enable", "--now", "fstrim.timer"]],
              revert=[["systemctl", "disable", "--now", "fstrim.timer"]],
              why="Keeps the NVMe fast and healthy by discarding freed blocks.",
              state=lambda: run(["systemctl", "is-enabled", "fstrim.timer"])[1].strip() or "?"),
        Tweak("clean.trim_now", "storage", "Run fstrim on all mounts now (one-shot)",
              [["fstrim", "-av"]], reversible=False, oneshot=True,
              why="Immediate TRIM pass; pairs with the timer above."),

        # ---- gaming ------------------------------------------------------ #
        Tweak("game.oomd_note", "gaming", "Wire ZZZ to gamemode + mangohud (Steam launch options)",
              [["sh", "-c", "echo 'Set in Steam → ZZZ → Properties → Launch Options (see murphy note)'"]],
              root=False, reversible=False, oneshot=True,
              why="gamemoderun pins performance + inhibits the compositor; mangohud shows the FPS truth.",
              applies=lambda: have("gamemoderun")),
    ]
    return T


# --------------------------------------------------------------------------- #
#  Runner
# --------------------------------------------------------------------------- #
def _emit_tweak(t: Tweak, ink, is_root: bool) -> None:
    tags = []
    tags.append(ink.green("reversible") if t.reversible else ink.amber("one-shot"))
    if t.root:
        tags.append(ink.dim("root") if is_root else ink.amber("needs root"))
    if t.risk != "low":
        tags.append(ink.amber(f"risk:{t.risk}"))
    cur = ""
    try:
        if t.state:
            cur = "  " + ink.dim("now: ") + ink.bone(str(t.state()))
    except Exception:
        pass
    print(f"  {ink.cyan(t.id):<28} {ink.bone(t.desc)}")
    print(f"        {' · '.join(tags)}{cur}")
    if t.why:
        print(f"        {ink.dim(t.why)}")


def run_tweaks(args, ink) -> int:
    host = detect_host()
    import os
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    cat = getattr(args, "category", None)
    do_apply = getattr(args, "apply_tweaks", False)
    yes = getattr(args, "yes", False)

    catalog = [t for t in _catalog(host)
               if (not cat or t.cat == cat)
               and (t.applies is None or _safe(t.applies))]

    if not do_apply:
        print(ink.bone("  THE LIBRARY OF RUINA — system tweak catalog"))
        print("  " + ink.dim("read-only; nothing changes. Apply with: ")
              + ink.cyan("murphy tweak --apply-tweaks [--category <c>] [--su] [-y]"))
        for c in CATS:
            group = [t for t in catalog if t.cat == c]
            if not group:
                continue
            print("\n  " + ink.blood(f"— {c.upper()} —"))
            for t in group:
                _emit_tweak(t, ink, is_root)
        print("\n  " + ink.dim(f"{len(catalog)} tweak(s) applicable to this host. "
                               "Categories: " + ", ".join(CATS)))
        return 0

    # apply mode
    print(ink.bone("  Applying tweaks" + (f" · {cat}" if cat else "")))
    applied = 0
    for t in catalog:
        if t.root and not is_root:
            print(f"  {ink.amber('skip (needs root):')} {t.id} — re-run with --su")
            continue
        print()
        _emit_tweak(t, ink, is_root)
        go = yes
        if not go:
            try:
                go = input(f"        apply {t.id}? [y/N] ").strip().lower() in ("y", "yes")
            except EOFError:
                go = False
        if not go:
            print(f"        {ink.dim('skipped.')}")
            continue
        ok = True
        for cmd in t.apply:
            rc, out = run(cmd, timeout=180)
            print(f"        {ink.green('✓') if rc == 0 else ink.amber('✗ ' + str(rc))} {' '.join(cmd)[:80]}")
            if rc != 0:
                ok = False
        if ok:
            applied += 1
            if t.reversible and t.revert:
                print(f"        {ink.dim('revert: ' + ' '.join(t.revert[0]))}")
    print("\n  " + ink.green(f"Applied {applied} tweak(s).")
          + ink.dim("  Re-run `murphy tweak` to see updated state."))
    return 0


def _safe(fn):
    try:
        return bool(fn())
    except Exception:
        return True
