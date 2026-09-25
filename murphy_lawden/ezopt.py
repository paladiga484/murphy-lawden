"""EZ-opt — the easy optimiser. Debloat a Linux box for maximum gameplay.

A companion to Murphy Lawden, built to the same rules: stdlib only, reversible,
dry-run by default, and amnesiac (it registers its scratch with Murphy's wipe).
Where Murphy hardens, EZ-opt *lightens* — it quiets the background so the whole
machine leans into the game you're about to launch.

It works in facets, and every facet backs up what it touches before it touches
it, so ``ezopt restore`` puts the machine back exactly as it was:

  services   stop + runtime-mask the daemons a game doesn't need (printing,
             discovery, indexers, Bluetooth) so nothing wakes mid-match. The mask
             lives in /run, so a reboot undoes it even if you never restore.
  memory     kernel VM tuning that helps games specifically — a big
             ``vm.max_map_count`` (many modern/Proton titles need it) and no
             background compaction. No cache drop: it evicts the game's own files.
  cpu        pin the CPU governor to ``performance`` so it doesn't downclock
             between frames. Backed up per-core; restore returns your governor.
  io         give the disk your game lives on a low-latency I/O scheduler.
  profile    do the sensible gaming set in one shot (services + memory + cpu).

Nothing here is a silver bullet and none of it is destructive; the honest wins on
a small-RAM machine come from *not paging* — so EZ-opt leans on quieting memory
pressure, which is usually where the frames actually go.
"""
from __future__ import annotations

import json
import os
import pwd
from pathlib import Path

from .core import have, run
from .banner import Ink, render_banner, rule, make_ink

def _real_home() -> Path:
    """The invoking user's home even under sudo — so `sudo ezopt --apply` and
    `sudo ezopt restore` agree on one ledger instead of writing it to /root."""
    user = os.environ.get("SUDO_USER")
    if user and user != "root":
        try:
            return Path(pwd.getpwnam(user).pw_dir)
        except KeyError:
            pass
    return Path.home()


BACKUP = _real_home() / ".local/state/murphy/ezopt.backup.json"

# Daemons a game never needs mid-session. Conservative: nothing here breaks a
# desktop's ability to boot or the network you play online over.
# Sockets are listed with their services: masking a socket-activated daemon
# while its socket still listens just means the next connection restarts it.
_BLOAT_SERVICES = [
    "cups.service", "cups.socket", "cups-browsed.service", "bluetooth.service",
    "avahi-daemon.service", "avahi-daemon.socket", "ModemManager.service",
    "packagekit.service", "tracker-miner-fs-3.service", "tracker-extract-3.service",
    "geoclue.service", "smartd.service",
    "libvirtd.service", "libvirtd.socket", "libvirtd-ro.socket", "libvirtd-admin.socket",
    "docker.service", "docker.socket",
]

# VM knobs that actually move frames — and *only* ones with no hidden interaction
# to walk back. We deliberately DON'T touch vm.dirty_ratio: distros like CachyOS
# drive writeback with vm.dirty_bytes instead (ratio reads 0), and writing a ratio
# would silently disable their tuned bytes value in a way a simple backup can't undo.
_MEM_TUNABLES = {
    "vm.max_map_count": "2147483642",   # Proton/DXVK/some anti-cheat need this high
    "vm.compaction_proactiveness": "0", # stop background compaction stalls mid-frame
}


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _load() -> dict:
    try:
        return json.loads(BACKUP.read_text())
    except (OSError, ValueError):
        return {}


def _save(patch: dict) -> None:
    """Merge into the ledger, keeping the FIRST recorded original of every
    individual entry. (It used to setdefault the whole section, so anything a
    second run touched was never recorded and could never be restored.)"""
    BACKUP.parent.mkdir(parents=True, exist_ok=True)
    cur = _load()
    for k, v in patch.items():
        if isinstance(v, dict):
            section = cur.setdefault(k, {})
            for kk, vv in v.items():
                section.setdefault(kk, vv)
        else:
            cur.setdefault(k, v)
    _write(cur)


def _write(ledger: dict) -> None:
    BACKUP.parent.mkdir(parents=True, exist_ok=True)
    BACKUP.write_text(json.dumps(ledger, indent=2))
    user = os.environ.get("SUDO_USER")
    if user and _is_root():                     # keep it the user's file, not root's
        try:
            pw = pwd.getpwnam(user)
            for path in (BACKUP.parent, BACKUP):
                os.chown(path, pw.pw_uid, pw.pw_gid)
        except (KeyError, OSError):
            pass
    # NOTE: do NOT register this with the amnesia sweep. It is the restore ledger,
    # not disposable scratch — it must survive process exit so `ezopt restore` can
    # walk changes back on a later run. (Same reasoning as Murphy's fix backups,
    # which persist so `undo` works.) An earlier version swept it and silently
    # destroyed reversibility: apply tuning, exit, and restore had nothing to undo.


def _line(ink: Ink, execute: bool, ok: bool, text: str) -> None:
    if not execute:
        print("    " + ink.dim("· would ") + text)
    else:
        print("    " + (ink.green("· ✓ ") if ok else ink.amber("· ✗ ")) + text)


# --------------------------------------------------------------------------- #
#  services
# --------------------------------------------------------------------------- #
def opt_services(ink: Ink, execute: bool) -> int:
    print(rule(ink, "SERVICES — quiet the background"))
    if not have("systemctl"):
        print(ink.amber("    no systemd here — skipping."))
        return 0
    if execute and not _is_root():
        print(ink.amber("    masking services needs root — re-run with sudo."))
        return 1
    masked = {}
    for unit in _BLOAT_SERVICES:
        rc, _ = run(["systemctl", "status", unit])
        if rc == 4:      # 4 == no such unit; skip cleanly
            continue
        state = run(["systemctl", "is-enabled", unit])[1].strip()
        if state.startswith("masked"):
            continue     # already masked by someone else — not ours to undo
        was = {"enabled": state == "enabled",
               "active": run(["systemctl", "is-active", "--quiet", unit])[0] == 0}
        if not execute:
            _line(ink, execute, True, f"stop + mask {unit} until reboot")
            continue
        # --runtime: the mask lives in /run and dies with the boot. Forgetting
        # `restore` costs you one session of Bluetooth, not every session after.
        ok = run(["systemctl", "mask", "--runtime", "--now", unit])[0] == 0
        _line(ink, execute, ok, f"stop + mask {unit} until reboot")
        if ok:
            masked[unit] = was   # record every unit we mask, enabled or not
    if execute and masked:
        _save({"masked_units": masked, "boot_id": _boot_id()})
    print(ink.dim("    ↩ restore brings these back; a reboot does too."))
    return 0


# --------------------------------------------------------------------------- #
#  memory
# --------------------------------------------------------------------------- #
def opt_memory(ink: Ink, execute: bool) -> int:
    print(rule(ink, "MEMORY — stop the paging, drop the fat"))
    if execute and not _is_root():
        print(ink.amber("    sysctl tuning needs root — re-run with sudo."))
        return 1
    backup = {}
    for key, val in _MEM_TUNABLES.items():
        path = "/proc/sys/" + key.replace(".", "/")
        cur = ""
        try:
            cur = Path(path).read_text().strip()
        except OSError:
            _line(ink, execute, False, f"{key} (not present on this kernel)")
            continue
        if not execute:
            _line(ink, execute, True, f"set {key} = {val}  (now {cur})")
            continue
        try:
            Path(path).write_text(val)
            backup[key] = cur
            _line(ink, execute, True, f"set {key} = {val}  (was {cur})")
        except OSError as e:
            _line(ink, execute, False, f"{key}: {e}")
    # No drop_caches: it throws away the game's own file and shader cache (which
    # then comes back as stutter) and does nothing for anonymous pages in zram,
    # which is where the pressure on a small-RAM box actually is.
    if execute and backup:
        _save({"sysctl": backup})
    return 0


# --------------------------------------------------------------------------- #
#  cpu
# --------------------------------------------------------------------------- #
def _governors() -> list[Path]:
    base = Path("/sys/devices/system/cpu")
    return sorted(base.glob("cpu[0-9]*/cpufreq/scaling_governor"))


def opt_cpu(ink: Ink, execute: bool) -> int:
    print(rule(ink, "CPU — hold the clocks up"))
    govs = _governors()
    if not govs:
        print(ink.amber("    no cpufreq governors exposed (VM or fixed-clock) — skipping."))
        return 0
    if execute and not _is_root():
        print(ink.amber("    setting the governor needs root — re-run with sudo."))
        return 1
    cur = govs[0].read_text().strip()
    if not execute:
        _line(ink, execute, True, f"set all {len(govs)} cores to 'performance'  (now '{cur}')")
        return 0
    saved = {}
    ok_all = True
    for g in govs:
        saved[str(g)] = g.read_text().strip()
        try:
            g.write_text("performance")
        except OSError:
            ok_all = False
    _line(ink, execute, ok_all, f"set {len(govs)} cores to 'performance' (was '{cur}')")
    _save({"governors": saved})
    return 0


# --------------------------------------------------------------------------- #
#  io
# --------------------------------------------------------------------------- #
def opt_io(ink: Ink, execute: bool) -> int:
    print(rule(ink, "I/O — low-latency scheduler on the game disk"))
    scheds = sorted(Path("/sys/block").glob("*/queue/scheduler"))
    scheds = [s for s in scheds if not s.parts[-3].startswith(("loop", "ram", "zram"))]
    if not scheds:
        print(ink.amber("    no schedulable block devices — skipping."))
        return 0
    if execute and not _is_root():
        print(ink.amber("    changing the I/O scheduler needs root — re-run with sudo."))
        return 1
    saved = {}
    for s in scheds:
        dev = s.parts[-3]
        avail = s.read_text()
        # NVMe/SSD like 'none'; rotational likes 'mq-deadline'. Pick what's offered.
        want = "none" if "none" in avail else "mq-deadline" if "mq-deadline" in avail else None
        if not want:
            continue
        cur = [t.strip("[]") for t in avail.split() if t.startswith("[")]
        cur = cur[0] if cur else "?"
        if not execute:
            _line(ink, execute, True, f"{dev}: scheduler → {want}  (now {cur})")
            continue
        try:
            s.write_text(want)
            saved[str(s)] = cur
            _line(ink, execute, True, f"{dev}: scheduler → {want} (was {cur})")
        except OSError as e:
            _line(ink, execute, False, f"{dev}: {e}")
    if execute and saved:
        _save({"io_sched": saved})
    return 0


# --------------------------------------------------------------------------- #
#  restore
# --------------------------------------------------------------------------- #
def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return ""


def opt_restore(ink: Ink, execute: bool) -> int:
    print(rule(ink, "RESTORE — put the machine back"))
    bk = _load()
    if not bk:
        print(ink.amber("    nothing on record — EZ-opt hasn't changed anything yet."))
        return 0
    if execute and not _is_root():
        # Refuse up front. Running on without root used to fail every step and
        # then delete the ledger anyway, leaving nothing to restore from.
        print(ink.amber("    restore needs root — re-run with sudo. The ledger is untouched."))
        return 1
    left: dict = {}
    fresh_boot = bk.get("boot_id") and bk.get("boot_id") != _boot_id()

    units = dict(bk.get("masked_units", {}))
    for unit in bk.get("masked_services", []):        # ledgers from older versions
        units.setdefault(unit if "." in unit else unit + ".service",
                         {"enabled": True, "active": True, "legacy": True})
    for unit, was in units.items():
        verb = "unmask" + (" + start" if was.get("active") else "")
        if not execute:
            _line(ink, execute, True, f"{verb} {unit}")
            continue
        # a pre-runtime ledger masked in /etc; a runtime mask may already be gone
        cmd = ["systemctl", "unmask", unit] if was.get("legacy") else \
              ["systemctl", "unmask", "--runtime", unit]
        ok = run(cmd)[0] == 0 or fresh_boot
        if ok and was.get("legacy") and was.get("enabled"):
            ok = run(["systemctl", "enable", unit])[0] == 0
        if ok and was.get("active"):
            ok = run(["systemctl", "start", unit])[0] == 0
        _line(ink, execute, ok, f"{verb} {unit}")
        if not ok:
            left.setdefault("masked_units", {})[unit] = was

    for section, label in (("sysctl", None), ("governors", "governors"), ("io_sched", "I/O schedulers")):
        items = bk.get(section, {})
        failed = {}
        for key, val in items.items():
            path = "/proc/sys/" + key.replace(".", "/") if section == "sysctl" else key
            if execute:
                try:
                    Path(path).write_text(val)
                except OSError:
                    failed[key] = val
            if section == "sysctl":
                _line(ink, execute, key not in failed, f"{key} → {val}")
        if items and label:
            _line(ink, execute, not failed, f"{label} → original ({len(items)})")
        if failed:
            left[section] = failed

    if execute:
        if left:
            _write(left)
            print(ink.amber(f"    {sum(len(v) for v in left.values())} item(s) didn't restore; "
                            "they stay on the ledger for the next run."))
            return 1
        BACKUP.unlink(missing_ok=True)
        print(ink.green("    Restored. EZ-opt's slate is clean."))
    return 0


# --------------------------------------------------------------------------- #
#  driver
# --------------------------------------------------------------------------- #
_FACETS = {
    "services": opt_services, "memory": opt_memory, "cpu": opt_cpu,
    "io": opt_io, "restore": opt_restore,
}


def run_ezopt(facet: str, execute: bool, ink: Ink | None = None, banner: bool = True) -> int:
    ink = ink or make_ink(None)
    if banner:
        print(render_banner(ink))
        print(ink.dim("  EZ-opt — the easy optimiser · debloat for max gameplay · reversible\n"))
    if not execute and facet != "restore":
        print(ink.amber("  Plan only — nothing changes. Add --apply (and sudo) to commit.\n"))

    if facet == "profile":
        # the sensible gaming set, in order
        for name in ("services", "memory", "cpu"):
            _FACETS[name](ink, execute)
            print()
        print(ink.dim("  Profile complete. Walk it all back with:  ezopt restore --apply"))
        return 0
    fn = _FACETS.get(facet)
    if not fn:
        print(ink.amber(f"  unknown facet '{facet}'. Try: services memory cpu io profile restore"))
        return 1
    rc = fn(ink, execute)
    if execute and facet != "restore":
        print(ink.dim("\n  Walk it back any time with:  ezopt restore --apply"))
    return rc
