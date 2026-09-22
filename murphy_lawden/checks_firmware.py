"""checks_firmware — BIOS / UEFI firmware integrity & corruption checks (Linux).

The bootkit question, answered with evidence instead of vibes: *is the firmware's
own tamper protection intact?* A corrupted or backdoored BIOS is exactly what
turns SPI write-protection off, invalidates the measured-boot PCR0
reconstruction, unlocks SMM, or drops an unexpected ``.efi`` loader into the EFI
System Partition. Murphy reads all of that — via fwupd's Host Security ID, the
Secure Boot state, and the ESP — **read-only**, and grades it.

This is the "BIOS corruption checker": if the platform's self-protection is
whole, a persistent firmware implant has nowhere to hide; if a protection has
been dropped, that is the finding.
"""
from __future__ import annotations

import glob
import os
import re

from .core import check, Finding, Status, Severity, have, run, read

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _f(fid, title, status, severity=Severity.INFO, detail="", rationale="", fix="", refs=None):
    return Finding(id=fid, title=title, status=status, severity=severity, detail=detail,
                   rationale=rationale, fix=fix, refs=refs or [])


# HSI attributes that bear directly on firmware corruption / persistent implants.
# name-substring -> (severity if NOT in the secure state, why it matters)
_CRITICAL_HSI = {
    "spi write protection":    (Severity.HIGH, "the SPI flash can be rewritten — a bootkit's front door"),
    "spi replay protection":   (Severity.MEDIUM, "rollback of flash contents isn't prevented"),
    "smm locked":              (Severity.HIGH, "System Management Mode (ring -2) isn't locked down"),
    "tpm pcr0 reconstruction": (Severity.HIGH, "the measured firmware doesn't reconstruct — possible tampering"),
    "bios firmware updates":   (Severity.LOW, "firmware update path state is unexpected"),
    "platform debugging":      (Severity.MEDIUM, "hardware debug interfaces aren't locked"),
}
_BAD_STATES = ("disabled", "invalid", "unlocked", "not found", "not supported")


def _skip_virtual(host) -> bool:
    return host.has("container") or host.has("vm") or host.has("wsl")


@check("linux")
def firmware_hsi(host):
    """Grade the platform's firmware self-protection from fwupd's HSI attributes."""
    if _skip_virtual(host):
        return
    if not have("fwupdmgr"):
        yield _f("fw.hsi", "fwupd absent — firmware security can't be attested", Status.SKIP,
                 Severity.MEDIUM,
                 fix="install fwupd to read the Host Security ID (SPI protection, PCR0, SMM lockdown).")
        return
    rc, out = run(["fwupdmgr", "security"], timeout=45)
    if rc != 0 or "Host Security ID" not in out:
        yield _f("fw.hsi", "couldn't read firmware security (fwupd)", Status.SKIP, Severity.LOW)
        return
    m = re.search(r"Host Security ID:\s*(HSI:\S+)", _ANSI.sub("", out))
    level = m.group(1) if m else "HSI:?"
    tainted = level.endswith("!")

    weak = []
    for raw in out.splitlines():
        s = _ANSI.sub("", raw).strip()
        mm = re.match(r"[✔✘✗×]\s*(.+?):\s+(.+)$", s)
        if not mm:
            continue
        name, state = mm.group(1).strip(), mm.group(2).strip()
        low = name.lower()
        for key, (sev, why) in _CRITICAL_HSI.items():
            if key in low:
                good = s[:1] == "✔" and state.lower() not in _BAD_STATES
                if not good:
                    weak.append((name, state, sev, why))

    if weak:
        worst = max(weak, key=lambda x: int(x[2]))
        yield _f("fw.hsi", f"firmware self-protection is WEAK ({level})", Status.FAIL, worst[2],
                 detail="; ".join(f"{n}: {st}" for n, st, _, _ in weak),
                 rationale="These are the protections that stop a bootkit from rewriting your BIOS. "
                           + worst[3] + ".",
                 fix="check for a signed BIOS update (fwupdmgr get-updates) and enable the missing "
                     "protections in UEFI setup.",
                 refs=["https://fwupd.github.io/libfwupdplugin/hsi.html"])
    else:
        yield _f("fw.hsi", f"firmware self-protection intact ({level})", Status.PASS, Severity.HIGH,
                 detail="SPI write+replay protection, SMM lockdown and PCR0 reconstruction all in the "
                        "secure state" + (" · runtime taint flagged (out-of-tree module / kernel "
                        "lockdown off — expected with the NVIDIA driver)" if tainted else ""),
                 rationale="A firmware implant has nowhere to persist while these hold.")


@check("linux")
def firmware_secureboot(host):
    """Secure Boot: is the OS boot chain verified at power-on?"""
    if _skip_virtual(host):
        return
    state = None
    if have("mokutil"):
        rc, out = run(["mokutil", "--sb-state"])
        if rc == 0 and out.strip():
            state = out.strip().splitlines()[0]
    if state is None:
        vs = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
        if vs:
            try:
                data = open(vs[0], "rb").read()
                state = "SecureBoot enabled" if data and data[-1] == 1 else "SecureBoot disabled"
            except OSError:
                pass
    if state is None:
        if not os.path.exists("/sys/firmware/efi"):
            return  # legacy BIOS boot — Secure Boot doesn't apply
        yield _f("fw.secureboot", "Secure Boot state undetermined", Status.SKIP, Severity.LOW)
        return
    if "enabled" in state.lower():
        yield _f("fw.secureboot", "Secure Boot enabled", Status.PASS, Severity.MEDIUM,
                 rationale="The bootloader and kernel signatures are verified at power-on.")
    else:
        yield _f("fw.secureboot", "Secure Boot is disabled", Status.WARN, Severity.MEDIUM, detail=state,
                 rationale="Nothing verifies the bootloader/kernel signature at power-on — the classic "
                           "evil-maid / bootkit gap. (Your firmware's own SPI write-protection still "
                           "stands; this is about the OS boot chain, not the BIOS chip.)",
                 fix="enable Secure Boot in UEFI; on Arch you can self-sign with sbctl and keep your "
                     "own keys, no vendor lock-in.")


@check("linux")
def firmware_esp(host):
    """Scan the EFI System Partition for unrecognised boot binaries (bootkit persistence)."""
    if _skip_virtual(host):
        return
    esp = next((c for c in ("/boot/efi", "/efi", "/boot")
                if os.path.isdir(os.path.join(c, "EFI"))), None)
    if not esp:
        return
    known = ("systemd", "boot", "grub", "fwupd", "microsoft", "linux", "arch",
             "cachyos", "refind", "shim", "mmx64", "fbx64", "bootx64", "bootia32", "memtest")
    unexpected = []
    for p in glob.glob(os.path.join(esp, "EFI", "**", "*.efi"), recursive=True):
        tag = (os.path.basename(os.path.dirname(p)) + os.path.basename(p)).lower()
        if not any(k in tag for k in known):
            unexpected.append(p)
    if unexpected:
        yield _f("fw.esp", f"{len(unexpected)} unrecognised EFI binary(ies) in the ESP", Status.WARN,
                 Severity.MEDIUM, detail="; ".join(unexpected[:6]),
                 rationale="An unexpected .efi loader in the EFI System Partition is a classic bootkit "
                           "persistence spot. Confirm you put each of these there.",
                 fix="verify every unknown loader against what you installed; remove any you don't recognise.")
    else:
        yield _f("fw.esp", "EFI System Partition holds only known bootloaders", Status.PASS, Severity.LOW)


@check("linux")
def firmware_version(host):
    """Surface the BIOS build so an unexpected reflash is visible across scans."""
    if _skip_virtual(host):
        return
    ver = read("/sys/class/dmi/id/bios_version")
    if not ver:
        return
    date = (read("/sys/class/dmi/id/bios_date") or "").strip()
    vendor = (read("/sys/class/dmi/id/bios_vendor") or "").strip()
    yield _f("fw.version", f"BIOS {ver.strip()}" + (f" ({date})" if date else ""),
             Status.INFO, Severity.INFO, detail=vendor,
             rationale="Note the firmware build; an unexpected change between scans can mean a reflash. "
                       "Run `murphy watch` to be alerted if the firmware self-protection posture ever drops.")
