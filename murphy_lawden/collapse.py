"""``murphy collapse`` — the Narrative Collapse. The last page in the book.

This is the corner of Murphy you reach for when you've concluded the machine is
no longer yours to trust — a rootkit you can't clear, an implant you can't name,
a box you'd rather burn down than keep fighting. Four doors, escalating in how
much they take from you:

  1. reinstall   Delete the OS and start clean. IRREVERSIBLE. Murphy does NOT
                 blindly ``rm -rf /`` a running system — that just corrupts the
                 disk under you. It captures a restore manifest, then hands the
                 actual wipe to install media / firmware, exactly the way `panic`
                 hands a factory reset to the OS. You reboot into the installer.

  2. cleanroom   Strip the machine down to a bare TTY you can trust — no display
                 manager, no radios, no listeners — then (gated, separately)
                 wipe user data, reset sudoers, and stand up a fresh user. Good
                 for hunting malware from a floor you've swept yourself. The
                 strip-down is reversible; the data wipe is not.

  3. freeze      Halt the machine's motion without killing it: SIGSTOP every
                 non-essential process so nothing can act, exfiltrate, or phone
                 home while you look. Fully REVERSIBLE — ``--thaw`` sends SIGCONT
                 and everything resumes where it stood.

  4. sever       Cut every trail an attacker rides in or out on — Wi-Fi, BLE,
                 every radio, the network daemons, the open listeners — and
                 compartmentalise: deny-all firewall, sessions locked. REVERSIBLE.

Same three-lock safety model as `duress`, because this can destroy data too:
    (1) an explicit ``--execute`` — default is a briefing that touches nothing;
    (2) the exact typed **consent phrase** for the chosen door, read off a TTY;
    (3) an explicit door — there is no "collapse everything" shortcut.

Nothing here runs on a scan, a fix, autopilot, or a timer. You have to mean it.
"""
from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

from .core import have, run
from .banner import Ink, make_ink, rule

# Where the reversible doors stash the state needed to walk them back.
STATE_DIR = Path.home() / ".local/state/murphy"
FREEZE_LIST = STATE_DIR / "frozen.pids"
SEVER_STATE = STATE_DIR / "severed.state"

# Per-door typed consent. Deliberately unmemorable so it can't be muscle-memory'd.
PHRASES = {
    "reinstall": "ERASE THIS OS AND REINSTALL",
    "cleanroom": "STRIP THIS MACHINE TO A CLEAN TTY",
    "freeze":    "FREEZE EVERYTHING NOW",
    "sever":     "CUT EVERY TRAIL",
}

# Processes we must never SIGSTOP — freezing any of these can wedge the very path
# you'd use to thaw again (journald, dbus, logind, a TTY/login, our own shell).
# /proc/<pid>/comm is truncated to 15 chars, so we match by PREFIX, not equality —
# 'systemd-journald' shows up as 'systemd-journal', 'dbus-broker-launch' as
# 'dbus-broker-lau'. Protect the whole family rather than a spelled-out name.
_FREEZE_NEVER_PREFIX = (
    "systemd", "init", "dbus", "sshd", "murphy", "python",
    "bash", "fish", "zsh", "login", "agetty", "getty", "kthreadd",
    "sudo", "su", "polkitd", "seatd", "elogind", "logind", "udevd",
    "kworker", "ksoftirqd", "migration", "rcu_", "watchdog",
)


def _protected(comm: str) -> bool:
    return any(comm.startswith(p) for p in _FREEZE_NEVER_PREFIX)


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _ask_phrase(ink: Ink, door: str) -> bool:
    want = PHRASES[door]
    print(ink.amber(f"  Type the consent phrase exactly to proceed, or anything else to abort:"))
    print(ink.dim(f"    {want}"))
    try:
        got = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return got == want


def _step(ink: Ink, execute: bool, label: str, cmd: list[str] | None = None,
          done: str | None = None) -> bool:
    """Show a step; run it only when executing. Returns True if it (would have)
    succeeded. Read-through so the dry-run plan reads exactly like the real run."""
    if not execute:
        print("    " + ink.dim("· would ") + label)
        return True
    if cmd is None:
        print("    " + ink.green("· ") + label)
        return True
    rc, out = run(cmd, timeout=30)
    ok = rc == 0
    mark = ink.green("· ✓ ") if ok else ink.amber("· ✗ ")
    print("    " + mark + label + (ink.dim(f"  ({done})") if ok and done else ""))
    if not ok and out.strip():
        print("      " + ink.dim(out.strip().splitlines()[0][:80]))
    return ok


# --------------------------------------------------------------------------- #
#  Door 3 — FREEZE  (reversible)
# --------------------------------------------------------------------------- #
def _freezable_pids() -> list[tuple[int, str]]:
    me = os.getpid()
    mine = {me, os.getppid()}
    out = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid <= 2 or pid in mine:  # 1=init, 2=kthreadd
            continue
        comm = ""
        try:
            comm = (entry / "comm").read_text().strip()
        except OSError:
            continue
        # kernel threads have no cmdline; never touch them
        try:
            if not (entry / "cmdline").read_bytes().strip(b"\x00"):
                continue
        except OSError:
            continue
        if _protected(comm):
            continue
        out.append((pid, comm))
    return out


def door_freeze(ink: Ink, execute: bool, thaw: bool) -> int:
    print(rule(ink, "DOOR 3 · FREEZE"))
    if thaw:
        print(ink.bone("  Thawing — resuming every process Murphy stopped."))
        if not FREEZE_LIST.exists():
            print(ink.amber("  No freeze on record. Nothing to thaw."))
            return 0
        n = 0
        for line in FREEZE_LIST.read_text().splitlines():
            pid = line.split()[0] if line.split() else ""
            if pid.isdigit():
                try:
                    if execute:
                        os.kill(int(pid), signal.SIGCONT)
                    n += 1
                except ProcessLookupError:
                    pass
                except PermissionError:
                    pass
        if execute:
            FREEZE_LIST.unlink(missing_ok=True)
        print(ink.green(f"  {'Thawed' if execute else 'Would thaw'} {n} process(es). The machine moves again."))
        return 0

    targets = _freezable_pids()
    print(ink.bone(f"  {len(targets)} non-essential process(es) can be frozen. "
                   "Core system, your shell, and Murphy stay alive."))
    if not execute:
        for pid, comm in targets[:20]:
            print("    " + ink.dim(f"· would SIGSTOP {comm} (pid {pid})"))
        if len(targets) > 20:
            print(ink.dim(f"    … and {len(targets)-20} more"))
        print(ink.amber("  Plan only. Re-run with --execute (and the consent phrase) to freeze."))
        print(ink.dim("  Walk it back any time with:  murphy collapse --door freeze --thaw --execute"))
        return 0

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    frozen = []
    for pid, comm in targets:
        try:
            os.kill(pid, signal.SIGSTOP)
            frozen.append(f"{pid} {comm}")
        except (ProcessLookupError, PermissionError):
            pass
    FREEZE_LIST.write_text("\n".join(frozen) + "\n")
    print(ink.green(f"  Frozen {len(frozen)} process(es). Nothing non-essential can act now."))
    print(ink.dim("  Resume everything with:  murphy collapse --door freeze --thaw --execute"))
    return 0


# --------------------------------------------------------------------------- #
#  Door 4 — SEVER  (reversible)
# --------------------------------------------------------------------------- #
_SEVER_DAEMONS = ["bluetooth", "NetworkManager", "wpa_supplicant", "ModemManager",
                  "avahi-daemon", "cups", "sshd", "systemd-resolved"]


def door_sever(ink: Ink, execute: bool, restore: bool) -> int:
    print(rule(ink, "DOOR 4 · SEVER"))
    if restore:
        print(ink.bone("  Reconnecting — lifting the radio block and restarting daemons."))
        _step(ink, execute, "unblock all radios", ["rfkill", "unblock", "all"] if have("rfkill") else None)
        if SEVER_STATE.exists():
            for unit in SEVER_STATE.read_text().splitlines():
                unit = unit.strip()
                if unit and have("systemctl"):
                    _step(ink, execute, f"restart {unit}", ["systemctl", "start", unit])
            if execute:
                SEVER_STATE.unlink(missing_ok=True)
        _step(ink, execute, "flush the deny-all firewall", ["nft", "flush", "ruleset"] if have("nft") else None)
        print(ink.green("  Trails reopened." if execute else "  (plan) trails would reopen."))
        return 0

    print(ink.bone("  Cutting every trail in or out — radios, network daemons, listeners — "
                   "and compartmentalising behind a deny-all firewall."))
    if not _is_root() and execute:
        print(ink.amber("  Severing needs root. Re-run under sudo."))
        return 1
    if execute:
        STATE_DIR.mkdir(parents=True, exist_ok=True)

    # 1. radios: Wi-Fi, Bluetooth/BLE, cellular, NFC — one block covers all.
    _step(ink, execute, "block ALL radios (Wi-Fi, BT/BLE, WWAN, NFC)",
          ["rfkill", "block", "all"] if have("rfkill") else None,
          done="radios dark")
    # 2. network + discovery daemons
    stopped = []
    for unit in _SEVER_DAEMONS:
        if have("systemctl"):
            rc, _ = run(["systemctl", "is-active", "--quiet", unit])
            was_active = rc == 0
            if _step(ink, execute, f"stop {unit}",
                     ["systemctl", "stop", unit] if execute else None) and was_active:
                stopped.append(unit)
    # 3. deny-all firewall (nftables preferred, then a plain default-drop)
    if have("nft"):
        _step(ink, execute, "install a deny-all nftables ruleset",
              ["nft", "add", "table", "inet", "murphy_sever"] if execute else None)
        if execute:
            run(["nft", "add", "chain", "inet", "murphy_sever", "input",
                 "{ type filter hook input priority 0 ; policy drop ; }"])
            run(["nft", "add", "chain", "inet", "murphy_sever", "output",
                 "{ type filter hook output priority 0 ; policy drop ; }"])
    # 4. lock every graphical/tty session so a shoulder-surfer is out too
    _step(ink, execute, "lock all sessions",
          ["loginctl", "lock-sessions"] if have("loginctl") else None)

    if execute:
        SEVER_STATE.write_text("\n".join(stopped) + "\n")
        print(ink.green("  Severed. This machine is an island now."))
        print(ink.dim("  Reconnect with:  murphy collapse --door sever --restore --execute"))
    else:
        print(ink.amber("  Plan only. Add --execute and the consent phrase to sever."))
    return 0


# --------------------------------------------------------------------------- #
#  Door 2 — CLEANROOM  (strip is reversible; the data wipe is not)
# --------------------------------------------------------------------------- #
def door_cleanroom(ink: Ink, execute: bool, wipe_data: bool) -> int:
    print(rule(ink, "DOOR 2 · CLEANROOM"))
    print(ink.bone("  Stripping the machine to a bare, trustworthy TTY: no display "
                   "manager, no radios, no listeners. Then, only if you ask, a data "
                   "wipe and a fresh user on swept ground."))
    if not _is_root() and execute:
        print(ink.amber("  Cleanroom needs root. Re-run under sudo."))
        return 1

    # --- reversible strip-down -------------------------------------------- #
    print(ink.dim("  Strip-down (reversible):"))
    _step(ink, execute, "set boot target to multi-user (TTY, no desktop)",
          ["systemctl", "set-default", "multi-user.target"] if have("systemctl") else None,
          done="next boot lands on a TTY")
    _step(ink, execute, "block all radios", ["rfkill", "block", "all"] if have("rfkill") else None)
    for unit in ("bluetooth", "NetworkManager", "cups", "avahi-daemon"):
        if have("systemctl"):
            _step(ink, execute, f"disable {unit}", ["systemctl", "disable", "--now", unit] if execute else None)
    print(ink.dim("    ↩ walk it back:  systemctl set-default graphical.target  &&  rfkill unblock all"))

    # --- the sudoers / fresh-user plan ------------------------------------ #
    print(ink.dim("  Trust reset (the re-visudo + new user plan):"))
    print("    " + ink.dim("· open a locked-down visudo session so you can rewrite who may sudo"))
    print("    " + ink.dim("· create a fresh user on the swept system; migrate nothing automatically"))
    if execute and wipe_data:
        # Genuinely destructive — do NOT invent a user name or wipe silently. We
        # print the exact, reviewable commands and let the operator run them at the
        # TTY. Murphy refuses to be the thing that erases /home behind your back.
        print(ink.blood("  Data wipe requested. Murphy will not erase /home unattended."))
        print(ink.amber("  Run these yourself at the clean TTY, in order, once you've booted it:"))
        print(ink.cyan("    # 1. rewrite sudoers safely"))
        print("    visudo")
        print(ink.cyan("    # 2. make a new trusted user"))
        print("    useradd -m -G wheel <newname> && passwd <newname>")
        print(ink.cyan("    # 3. wipe the old home dirs (IRREVERSIBLE — name them explicitly)"))
        print("    rm -rf /home/<oldname>")
    elif not execute:
        print(ink.amber("  Plan only. --execute performs the reversible strip-down; add "
                        "--wipe-data to also print the (self-run) trust-reset commands."))
    print(ink.green("  Cleanroom prepared." if execute else "  (briefing) nothing changed."))
    print(ink.dim("  Reboot when ready — you'll come up on a TTY you can trust."))
    return 0


# --------------------------------------------------------------------------- #
#  Door 1 — REINSTALL  (hands the wipe to install media, like panic does)
# --------------------------------------------------------------------------- #
def door_reinstall(ink: Ink, execute: bool, manifest_dir: str | None) -> int:
    print(rule(ink, "DOOR 1 · REINSTALL"))
    print(ink.bone("  Delete the OS and start clean. Murphy does NOT rm the running "
                   "system out from under itself — that corrupts the disk mid-wipe. "
                   "It writes a restore manifest, then sends you to install media."))
    dest = Path(manifest_dir or (Path.home() / "murphy-restore")).expanduser()
    print(ink.dim(f"  Restore manifest → {dest}  (copy this to a USB stick BEFORE you wipe)"))

    if execute:
        dest.mkdir(parents=True, exist_ok=True)
        # A manifest is data, not the OS — safe to write. It's what lets you rebuild.
        if have("pacman"):
            rc, out = run(["pacman", "-Qqe"], timeout=20)
            (dest / "packages.pacman.txt").write_text(out)
        if have("flatpak"):
            rc, out = run(["flatpak", "list", "--app", "--columns=application"], timeout=20)
            (dest / "packages.flatpak.txt").write_text(out)
        for name in (".config", ".local/share", ".ssh"):
            src = Path.home() / name
            if src.exists():
                (dest / "dotfiles.manifest.txt").open("a").write(f"{src}\n")
        (dest / "README.txt").write_text(
            "Murphy Lawden restore manifest.\n"
            "Copy this whole folder to external media, then boot your distro's\n"
            "install USB and wipe the disk from the installer. Reinstall, then\n"
            "reinstate packages from packages.*.txt and copy back only the\n"
            "dotfiles you trust.\n")
        print(ink.green(f"  Manifest written to {dest}."))
    else:
        print(ink.amber("  Plan only. --execute writes the manifest (it does not wipe anything)."))

    print(ink.bold("  To actually erase and reinstall — Murphy hands this to the OS/firmware:"))
    print("    1. " + ink.bone("Copy the restore folder to a USB stick you keep."))
    print("    2. " + ink.bone("Boot your distro's install media (the installer wipes the disk)."))
    print("    3. " + ink.bone("Reinstall, then reinstate from the manifest."))
    if execute and have("systemctl"):
        print(ink.dim("  Reboot to the firmware/boot menu now?  systemctl reboot --firmware-setup"))
    return 0


# --------------------------------------------------------------------------- #
#  Front desk
# --------------------------------------------------------------------------- #
def _briefing(ink: Ink) -> None:
    print(rule(ink, "NARRATIVE COLLAPSE"))
    print(ink.bone("  The last page. Four doors, and every one asks you to mean it."))
    print()
    print("  " + ink.amber("1 · reinstall") + ink.dim("  delete the OS and start clean (hands the wipe to install media). IRREVERSIBLE"))
    print("  " + ink.amber("2 · cleanroom") + ink.dim("  strip to a bare trusted TTY; reset sudoers + new user. strip is reversible, data wipe is not"))
    print("  " + ink.amber("3 · freeze") + ink.dim("     SIGSTOP everything non-essential so nothing can act. REVERSIBLE (--thaw)"))
    print("  " + ink.amber("4 · sever") + ink.dim("      cut Wi-Fi/BLE/all radios + daemons + listeners; deny-all firewall. REVERSIBLE (--restore)"))
    print()
    print(ink.dim("  Pick a door:  murphy collapse --door <name>            (plan, touches nothing)"))
    print(ink.dim("  Fire it:      murphy collapse --door <name> --execute  (then type the consent phrase)"))
    print(ink.dim("  Nothing here runs on a scan, a timer, or by autopilot. Ever."))


def run_collapse(args, ink: Ink) -> int:
    door = getattr(args, "door", None)
    execute = getattr(args, "execute", False)
    if not door:
        _briefing(ink)
        return 0

    # Reversal sub-actions don't need the phrase (they only ever make things safer).
    thaw = getattr(args, "thaw", False)
    restore = getattr(args, "restore", False)
    if door == "freeze" and thaw:
        return door_freeze(ink, execute, thaw=True)
    if door == "sever" and restore:
        return door_sever(ink, execute, restore=True)

    # Firing a destructive/large door requires the typed phrase, read off a TTY.
    if execute:
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            print(ink.amber("  murphy: --execute needs an interactive terminal for consent. Aborted."))
            return 1
        print(rule(ink, f"CONSENT · {door.upper()}"))
        if not _ask_phrase(ink, door):
            print(ink.green("  Phrase not matched. Nothing done. Good instinct."))
            return 1

    if door == "reinstall":
        return door_reinstall(ink, execute, getattr(args, "manifest_dir", None))
    if door == "cleanroom":
        return door_cleanroom(ink, execute, getattr(args, "wipe_data", False))
    if door == "freeze":
        return door_freeze(ink, execute, thaw=False)
    if door == "sever":
        return door_sever(ink, execute, restore=False)
    _briefing(ink)
    return 0
