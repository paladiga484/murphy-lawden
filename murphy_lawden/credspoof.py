"""``murphy spoof`` — credential & identity spoofing.

Every machine broadcasts a handful of stable identifiers that let a network, an
app, or a snoop pin "this exact box" across time and places: the NIC's MAC
address, ``/etc/machine-id``, the hostname the DHCP lease leaks, the timezone a
site reads off your clock. Fingerprinting rides on their *stability*. Spoofing
breaks it — a fresh, plausible identity on demand, so today's box doesn't look
like yesterday's.

This is a privacy tool for your own hardware. It rotates *your* identifiers on
*your* machine; it does not clone anyone else's and it can't help you pretend to
be a specific other device. Everything is reversible: the real values are backed
up before the first change and ``--restore`` puts them all back.

Facets:
  mac        randomise the MAC of a chosen interface (or all wired/wireless).
             Locally-administered, unicast — a real-looking address, not a flag.
  machineid  rotate ``/etc/machine-id`` (+ the dbus one) — the per-install UUID
             that ad/telemetry stacks love.
  hostname   swap in a neutral hostname so DHCP/mDNS stop leaking "friends-laptop".
  timezone   set a decoy timezone (default UTC) so clock-based geolocation lies.

Dry-run by default. ``--apply`` makes changes, and only ``mac`` works without
root; the rest say so and no-op cleanly unprivileged.
"""
from __future__ import annotations

import json
import os
import random
import secrets
import time
from pathlib import Path

from .core import have, run
from .banner import Ink, rule

BACKUP = Path.home() / ".local/state/murphy/identity.backup.json"

# A short, deliberately dull pool — a machine called "localhost" or "debian" is
# far less identifying than a name with a person in it.
_NEUTRAL_NAMES = ["localhost", "archlinux", "debian", "fedora", "gateway",
                  "workstation", "desktop", "linux", "computer"]


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _load_backup() -> dict:
    try:
        return json.loads(BACKUP.read_text())
    except (OSError, ValueError):
        return {}


def _save_backup(data: dict) -> None:
    BACKUP.parent.mkdir(parents=True, exist_ok=True)
    merged = _load_backup()
    # Only record an original once — never overwrite a real value with a spoofed one.
    for k, v in data.items():
        merged.setdefault(k, v)
    BACKUP.write_text(json.dumps(merged, indent=2))


# --------------------------------------------------------------------------- #
#  MAC
# --------------------------------------------------------------------------- #
def _interfaces() -> list[str]:
    base = Path("/sys/class/net")
    out = []
    for iface in sorted(base.iterdir()) if base.exists() else []:
        if iface.name == "lo":
            continue
        # skip virtual bridges/veth we didn't make — spoofing those is pointless
        if (iface / "device").exists() or iface.name.startswith(("wl", "en", "eth", "wlan")):
            out.append(iface.name)
    return out


def _current_mac(iface: str) -> str:
    try:
        return (Path("/sys/class/net") / iface / "address").read_text().strip()
    except OSError:
        return "?"


def _random_mac() -> str:
    """A locally-administered, unicast MAC: set bit 1 of the first octet, clear
    bit 0. Looks like any randomised client address — nothing that screams 'fake'."""
    first = (random.randint(0x00, 0xFF) & 0xFE) | 0x02
    rest = [random.randint(0x00, 0xFF) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in [first] + rest)


def spoof_mac(ink: Ink, apply: bool, iface: str | None) -> int:
    targets = [iface] if iface else _interfaces()
    if not targets:
        print(ink.amber("  No spoofable interfaces found."))
        return 1
    print(rule(ink, "MAC ADDRESS"))
    for name in targets:
        cur = _current_mac(name)
        new = _random_mac()
        if not apply:
            print(f"    {ink.cyan(name):<12} {ink.dim(cur)}  →  {ink.bone(new)}  " + ink.dim("(plan)"))
            continue
        if not _is_root():
            print(ink.amber(f"    {name}: changing a MAC needs root — re-run with sudo."))
            continue
        _save_backup({f"mac:{name}": cur})
        ok = True
        for step in (["ip", "link", "set", name, "down"],
                     ["ip", "link", "set", name, "address", new],
                     ["ip", "link", "set", name, "up"]):
            rc, _ = run(step)
            ok = ok and rc == 0
        now = _current_mac(name)
        if ok and now == new:
            print(f"    {ink.cyan(name):<12} {ink.dim(cur)}  →  {ink.green(new)}  ✓")
        else:
            print(ink.amber(f"    {name}: change didn't stick (now {now}). "
                            "NetworkManager may re-assert it — set its cloned-mac-address instead."))
    return 0


# --------------------------------------------------------------------------- #
#  machine-id
# --------------------------------------------------------------------------- #
def spoof_machine_id(ink: Ink, apply: bool) -> int:
    print(rule(ink, "MACHINE-ID"))
    path = Path("/etc/machine-id")
    cur = path.read_text().strip() if path.exists() else "(none)"
    new = secrets.token_hex(16)  # 32 hex chars, the machine-id format
    print(f"    {ink.dim(cur)}  →  {ink.bone(new)}")
    if not apply:
        print(ink.dim("    (plan) also rewrites /var/lib/dbus/machine-id to match"))
        return 0
    if not _is_root():
        print(ink.amber("    rotating machine-id needs root — re-run with sudo."))
        return 1
    _save_backup({"machine-id": cur})
    try:
        path.write_text(new + "\n")
        dbus = Path("/var/lib/dbus/machine-id")
        if dbus.exists() or dbus.parent.exists():
            dbus.write_text(new + "\n")
        print(ink.green("    rotated ✓  (reboot for every daemon to pick it up)"))
    except OSError as e:
        print(ink.amber(f"    refused: {e}"))
        return 1
    return 0


# --------------------------------------------------------------------------- #
#  hostname
# --------------------------------------------------------------------------- #
def spoof_hostname(ink: Ink, apply: bool, name: str | None) -> int:
    print(rule(ink, "HOSTNAME"))
    cur = os.uname().nodename
    new = name or random.choice(_NEUTRAL_NAMES)
    print(f"    {ink.dim(cur)}  →  {ink.bone(new)}")
    if not apply:
        return 0
    if not _is_root():
        print(ink.amber("    setting the hostname needs root — re-run with sudo."))
        return 1
    _save_backup({"hostname": cur})
    if have("hostnamectl"):
        rc, out = run(["hostnamectl", "set-hostname", new])
        if rc == 0:
            print(ink.green("    set ✓"))
        else:
            print(ink.amber(f"    refused: {out.strip()[:80]}"))
            return 1
    else:
        try:
            Path("/etc/hostname").write_text(new + "\n")
            run(["hostname", new])
            print(ink.green("    set ✓ (wrote /etc/hostname)"))
        except OSError as e:
            print(ink.amber(f"    refused: {e}"))
            return 1
    return 0


# --------------------------------------------------------------------------- #
#  timezone
# --------------------------------------------------------------------------- #
def spoof_timezone(ink: Ink, apply: bool, zone: str | None) -> int:
    print(rule(ink, "TIMEZONE"))
    link = Path("/etc/localtime")
    cur = "?"
    try:
        cur = os.readlink(link).split("zoneinfo/", 1)[-1]
    except OSError:
        pass
    new = zone or "UTC"
    print(f"    {ink.dim(cur)}  →  {ink.bone(new)}  " + ink.dim("(clock-based geolocation will read this)"))
    if not apply:
        return 0
    if not _is_root():
        print(ink.amber("    setting the timezone needs root — re-run with sudo."))
        return 1
    _save_backup({"timezone": cur})
    if have("timedatectl"):
        rc, out = run(["timedatectl", "set-timezone", new])
        print((ink.green("    set ✓") if rc == 0 else ink.amber(f"    refused: {out.strip()[:80]}")))
        return 0 if rc == 0 else 1
    print(ink.amber("    no timedatectl — set /etc/localtime by hand."))
    return 1


# --------------------------------------------------------------------------- #
#  restore
# --------------------------------------------------------------------------- #
def restore(ink: Ink, apply: bool) -> int:
    print(rule(ink, "RESTORE IDENTITY"))
    bk = _load_backup()
    if not bk:
        print(ink.amber("  Nothing on record — no spoof has been applied from this machine."))
        return 0
    for key, val in bk.items():
        print(f"    put back {ink.cyan(key)} = {ink.bone(val)}" + ("" if apply else ink.dim("  (plan)")))
        if not apply:
            continue
        if not _is_root() and not key.startswith("mac:"):
            print(ink.amber("      needs root — re-run with sudo."))
            continue
        if key.startswith("mac:"):
            name = key.split(":", 1)[1]
            run(["ip", "link", "set", name, "down"])
            run(["ip", "link", "set", name, "address", val])
            run(["ip", "link", "set", name, "up"])
        elif key == "machine-id":
            try:
                Path("/etc/machine-id").write_text(val + "\n")
            except OSError:
                pass
        elif key == "hostname" and have("hostnamectl"):
            run(["hostnamectl", "set-hostname", val])
        elif key == "timezone" and have("timedatectl") and val != "?":
            run(["timedatectl", "set-timezone", val])
    if apply:
        BACKUP.unlink(missing_ok=True)
        print(ink.green("  Real identity restored."))
    return 0


def run_spoof(args, ink: Ink) -> int:
    facet = getattr(args, "facet", None) or "all"
    apply = getattr(args, "apply", False)
    if facet == "restore":
        return restore(ink, apply)
    if not apply:
        print(ink.dim("  Plan only — nothing changes. Add --apply (and sudo for all but MAC) to commit.\n"))
    rc = 0
    if facet in ("mac", "all"):
        rc |= spoof_mac(ink, apply, getattr(args, "iface", None))
    if facet in ("machineid", "all"):
        rc |= spoof_machine_id(ink, apply)
    if facet in ("hostname", "all"):
        rc |= spoof_hostname(ink, apply, getattr(args, "new_hostname", None))
    if facet in ("timezone", "all"):
        rc |= spoof_timezone(ink, apply, getattr(args, "tz", None))
    if apply:
        print()
        print(ink.dim("  Walk it all back any time with:  murphy spoof restore --apply"))
    return 0
