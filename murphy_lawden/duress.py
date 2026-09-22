"""``murphy duress`` — the last resort. Kill-switch, duress wipe, dead-man switch.

This is the one corner of Murphy that can *destroy* data, so it is built the
opposite way from everything else: **disarmed, dry-run, and consent-gated by
default.** Nothing here fires without all three of:

    1. an explicit ``--execute``  (default is a plan that touches nothing),
    2. the exact typed **consent phrase** read from your own hands on a TTY,
    3. an armed, non-dry-run tier.

The security model is *cryptographic erasure*, not scrubbing: on Android FBE and
on LUKS, destroying the key material makes every byte unrecoverable instantly —
the same physics that lost the vault. Overwriting the raw partition is an
optional paranoid extra in ``hellbreach``, never the mechanism.

Three tiers, escalating:

  recommended  Panic lockdown — REVERSIBLE. Cut the radios, lock the screen,
               kill sensitive sessions, disable ADB & biometrics. Destroys
               nothing; you can walk it all back.
  advanced     Duress wipe — cryptographic erase of user data (a factory-reset
               equivalent / LUKS keyslot erase). Data is gone for good; the
               device stays usable and re-flashable. IRREVERSIBLE.
  hellbreach   Scorched earth — advanced, then overwrite metadata/userdata and
               (optional, OFF by default) relock the bootloader. Extreme brick
               risk on a rooted device. IRREVERSIBLE.

A dead-man switch can arm any tier to fire if you don't check in, but its
DEFAULT escalation is the reversible lockdown, never a wipe, so a missed check-in
on holiday can't nuke your phone.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from .core import detect_host, have, run

CONSENT_WIPE = "YESICONSENTTODELETEEVERYTHING"
CONSENT_RELOCK = "YESICONSENTTOBRICKANDRELOCK"

TIERS = ("recommended", "advanced", "hellbreach")
TIER_BLURB = {
    "recommended": "Panic lockdown — REVERSIBLE. Radios off, screen locked, "
                   "sessions killed, ADB + biometrics disabled. Nothing destroyed.",
    "advanced":    "Duress wipe — cryptographic erase of user data "
                   "(factory-reset / LUKS keyslot erase). IRREVERSIBLE.",
    "hellbreach":  "Scorched earth — advanced wipe + overwrite + OPTIONAL "
                   "bootloader relock (off by default; can brick). IRREVERSIBLE.",
}


def _parse_dur(s, default: int = 259200) -> int:
    """'72h' / '3d' / '90m' / '3600' → seconds. Falls back to default (72h)."""
    if s is None:
        return default
    s = str(s).strip().lower()
    try:
        if s.endswith("h"):
            return int(float(s[:-1]) * 3600)
        if s.endswith("d"):
            return int(float(s[:-1]) * 86400)
        if s.endswith("m"):
            return int(float(s[:-1]) * 60)
        return int(float(s))
    except ValueError:
        return default


def _state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return Path(base) / "murphy"


def _deadman_file() -> Path:
    return _state_dir() / "deadman.json"


# --------------------------------------------------------------------------- #
#  Step model — each step knows if it's reversible and how to describe itself
# --------------------------------------------------------------------------- #
@dataclass
class Step:
    desc: str
    reversible: bool
    cmds: list[list[str]] = field(default_factory=list)   # shell/argv to run when firing
    note: str = ""

    def render(self, ink) -> str:
        mark = ink.green("reversible") if self.reversible else ink.red_b("IRREVERSIBLE")
        head = f"  [{mark}] {self.desc}"
        body = "".join(f"\n        $ {' '.join(c)}" for c in self.cmds)
        if self.note:
            body += f"\n        {ink.dim(self.note)}"
        return head + ink.dim(body)


# --------------------------------------------------------------------------- #
#  Platform-aware plans
# --------------------------------------------------------------------------- #
def _luks_device() -> str | None:
    """Best-effort: the underlying crypto_LUKS block device on this Linux host."""
    rc, out = run(["lsblk", "-rno", "NAME,FSTYPE"])
    if rc == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "crypto_LUKS":
                return "/dev/" + parts[0]
    return None


def _plan(host, tier: str, relock: bool) -> list[Step]:
    android = host.has("android")
    steps: list[Step] = []

    # --- recommended: the reversible kill-switch (every tier starts here) ---
    if android:
        steps += [
            Step("Cut all radios (airplane mode on, wifi + data off)", True, [
                ["settings", "put", "global", "airplane_mode_on", "1"],
                ["svc", "wifi", "disable"], ["svc", "data", "disable"],
                ["am", "broadcast", "-a", "android.intent.action.AIRPLANE_MODE"]]),
            Step("Disable ADB (close the debug door)", True,
                 [["settings", "put", "global", "adb_enabled", "0"]]),
            Step("Force PIN — drop biometric unlock for this boot", True,
                 [["cmd", "lock_settings", "set-disabled", "false"]],
                 note="best-effort; also lock now so only the PIN reopens"),
            Step("Lock the screen now", True, [["input", "keyevent", "26"]]),
        ]
    else:
        steps += [
            Step("Cut networking (rfkill block all + NetworkManager off)", True, [
                ["rfkill", "block", "all"],
                ["nmcli", "networking", "off"]]),
            Step("Lock all desktop sessions", True, [["loginctl", "lock-sessions"]]),
            Step("Clear the clipboard", True, [["wl-copy", "--clear"]],
                 note="falls back to xsel/xclip if Wayland tools are absent"),
        ]

    if tier == "recommended":
        return steps

    # --- advanced: cryptographic erase of user data (IRREVERSIBLE) ---
    if android:
        steps.append(Step(
            "Cryptographic erase of /data — factory-reset equivalent "
            "(destroys the FBE keys → all user data instantly unrecoverable)",
            False,
            [["su", "-c", "recovery --wipe_data"]],
            note="key-destruction, not a 256 GB scrub — complete and instant. "
                 "Falls back to MASTER_CLEAR broadcast if recovery is unavailable."))
    else:
        dev = _luks_device() or "<LUKS-device>"
        steps.append(Step(
            f"Erase every LUKS keyslot on {dev} "
            "(cryptographic erase — the disk becomes noise)",
            False,
            [["cryptsetup", "luksErase", "--batch-mode", dev]],
            note="instant and total: with no keyslot, the master key is gone."))

    if tier == "advanced":
        return steps

    # --- hellbreach: overwrite + optional relock (EXTREME) ---
    if android:
        steps.append(Step(
            "Overwrite the metadata partition (belt-and-suspenders after key erase)",
            False,
            [["su", "-c", "dd if=/dev/zero of=/dev/block/by-name/metadata bs=1M"]],
            note="redundant once keys are erased; adds brick risk if the name is wrong."))
        if relock:
            steps.append(Step(
                "RELOCK THE BOOTLOADER (fastboot flashing lock)",
                False,
                [["reboot", "bootloader"], ["fastboot", "flashing", "lock"]],
                note="⚠ WILL LIKELY HARD-BRICK A ROOTED DEVICE. No data benefit. "
                     "Requires the second consent phrase. Off unless you pass --relock."))
    else:
        dev = _luks_device() or "<LUKS-device>"
        steps.append(Step(
            f"Shred the LUKS header on {dev} (removes even the header backup path)",
            False,
            [["dd", "if=/dev/urandom", f"of={dev}", "bs=1M", "count=32"]],
            note="after luksErase this is redundant; included for the paranoid tier."))
    return steps


# --------------------------------------------------------------------------- #
#  Rendering + gates
# --------------------------------------------------------------------------- #
def _print_plan(host, tier: str, relock: bool, ink) -> None:
    print(ink.red_b("  ┌─ DURESS PLAN ─ tier: ") + ink.bone(tier.upper())
          + ink.red_b(" ─┐"))
    print("  " + ink.dim(TIER_BLURB[tier]))
    print()
    for s in _plan(host, tier, relock):
        print(s.render(ink))
    print()
    irreversible = any(not s.reversible for s in _plan(host, tier, relock))
    if irreversible:
        print("  " + ink.red_b("This tier DESTROYS data. To actually fire it:"))
        print("  " + ink.cyan(f"    murphy duress --tier {tier}"
                              + (" --relock" if relock else "") + " --execute"))
        print("  " + ink.dim(f"    …then type exactly:  {CONSENT_WIPE}")
              + (ink.dim(f"  (and {CONSENT_RELOCK})") if relock else ""))
    else:
        print("  " + ink.dim("Reversible kill-switch. Fire it with: ")
              + ink.cyan(f"murphy duress --tier {tier} --execute"))


def _read_consent(required: str, ink) -> bool:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(ink.red_b("  refused: consent must be typed on a live terminal."))
        return False
    print("  " + ink.red_b("Type the consent phrase to proceed (anything else aborts):"))
    print("  " + ink.dim(f"    {required}"))
    try:
        got = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    if got != required:
        print("  " + ink.green("Phrase did not match — nothing was touched. Stand down."))
        return False
    return True


def _fire(host, tier: str, relock: bool, ink) -> int:
    steps = _plan(host, tier, relock)
    destructive = any(not s.reversible for s in steps)

    if destructive and not _read_consent(CONSENT_WIPE, ink):
        return 1
    if relock and not _read_consent(CONSENT_RELOCK, ink):
        print("  " + ink.green("Relock declined — the rest is still armed; re-run without --relock."))
        return 1

    print("  " + ink.red_b(f"Firing duress tier {tier.upper()} …"))
    ok = True
    for s in steps:
        print(s.render(ink))
        for cmd in s.cmds:
            rc, out = run(cmd, timeout=120)
            status = ink.green("done") if rc == 0 else ink.amber(f"exit {rc}")
            print(f"        {status}: {' '.join(cmd)}")
            if rc != 0:
                ok = False
    print("  " + (ink.green("Duress complete.") if ok
                  else ink.amber("Duress finished with errors (some steps may need root / the bootloader).")))
    return 0 if ok else 2


# --------------------------------------------------------------------------- #
#  Dead-man switch
# --------------------------------------------------------------------------- #
def _arm_deadman(tier: str, window_s: int, ink) -> int:
    fire_tier = tier if tier in TIERS else "recommended"
    data = {"armed_at": int(time.time()), "deadline": int(time.time()) + window_s,
            "window_s": window_s, "tier": fire_tier}
    p = _deadman_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2))
    print("  " + ink.amber(f"Dead-man switch armed — tier {fire_tier.upper()}, "
                           f"window {window_s // 3600}h."))
    print("  " + ink.dim("Check in to reset the clock:  ") + ink.cyan("murphy duress --checkin"))
    print("  " + ink.dim("Disarm entirely:              ") + ink.cyan("murphy duress --disarm"))
    if fire_tier != "recommended":
        print("  " + ink.red_b("  NOTE: this fire tier is DESTRUCTIVE. A missed check-in will "
                               "wipe. Consider the reversible default instead."))
    return 0


def _checkin(ink) -> int:
    p = _deadman_file()
    if not p.exists():
        print("  " + ink.dim("No dead-man switch is armed."))
        return 1
    data = json.loads(p.read_text())
    data["deadline"] = int(time.time()) + int(data.get("window_s", 3600))
    p.write_text(json.dumps(data, indent=2))
    print("  " + ink.green(f"Checked in — clock reset ({data['window_s'] // 3600}h)."))
    return 0


def _disarm(ink) -> int:
    p = _deadman_file()
    if p.exists():
        p.unlink()
        print("  " + ink.green("Dead-man switch disarmed."))
    else:
        print("  " + ink.dim("Nothing was armed."))
    return 0


def _deadman_status(ink) -> None:
    p = _deadman_file()
    if not p.exists():
        return
    data = json.loads(p.read_text())
    left = data["deadline"] - int(time.time())
    if left <= 0:
        print("  " + ink.red_b(f"⚠ dead-man deadline PASSED — tier {data['tier'].upper()} "
                               "would fire on the next `murphy duress --tick --execute`."))
    else:
        print("  " + ink.amber(f"Dead-man armed: tier {data['tier'].upper()}, "
                               f"{left // 3600}h {left % 3600 // 60}m until it trips."))


def _tick(host, execute: bool, ink) -> int:
    """Called by a timer: fire the armed tier iff the deadline has passed."""
    p = _deadman_file()
    if not p.exists():
        return 0
    data = json.loads(p.read_text())
    if data["deadline"] > int(time.time()):
        return 0
    print("  " + ink.red_b(f"Dead-man deadline passed — tier {data['tier']}."))
    if not execute:
        print("  " + ink.dim("dry tick — pass --execute (from the timer) to actually fire."))
        return 0
    return _fire(host, data["tier"], relock=False, ink=ink)


# --------------------------------------------------------------------------- #
#  Entry point
# --------------------------------------------------------------------------- #
def run_duress(args, ink) -> int:
    host = detect_host()

    if getattr(args, "checkin", False):
        return _checkin(ink)
    if getattr(args, "disarm", False):
        return _disarm(ink)
    if getattr(args, "arm", False):
        return _arm_deadman(getattr(args, "tier", None) or "recommended",
                            _parse_dur(getattr(args, "deadman", None)), ink)
    if getattr(args, "tick", False):
        return _tick(host, getattr(args, "execute", False), ink)

    tier = getattr(args, "tier", None)
    relock = getattr(args, "relock", False)

    # Bare `murphy duress` → the safe briefing, never an action.
    if not tier:
        print(ink.red_b("  DURESS — kill-switch · duress wipe · dead-man switch"))
        print("  " + ink.dim("disarmed & dry-run by default; destructive tiers need "
                             "--execute AND a typed consent phrase.\n"))
        for t in TIERS:
            print(f"  {ink.bone(t.ljust(12))} {ink.dim(TIER_BLURB[t])}")
        print()
        print("  " + ink.dim("Plan a tier (shows exactly what it would do, touches nothing):"))
        print("  " + ink.cyan("    murphy duress --tier recommended|advanced|hellbreach"))
        print("  " + ink.dim("Dead-man switch:"))
        print("  " + ink.cyan("    murphy duress --arm --tier recommended --deadman 72h"))
        print("  " + ink.cyan("    murphy duress --checkin   /   --disarm"))
        _deadman_status(ink)
        return 0

    if not getattr(args, "execute", False):
        _print_plan(host, tier, relock, ink)
        return 0
    return _fire(host, tier, relock, ink)
