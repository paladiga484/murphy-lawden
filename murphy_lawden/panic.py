"""`murphy panic` — emergency response for suspected mercenary spyware (Pegasus /
Predator) on an Android device.

Design notes (why this is not a normal Murphy action):
  * A factory reset is destructive and irreversible, so it lives OUTSIDE the
    reversible fix pipeline — panic is never invoked by scan/fix/av/autopilot.
  * Murphy will NEVER silently wipe a device. The most it does is *launch the OS
    factory-reset screen* after a heavy confirmation gate; the operating system
    then asks for its own final confirmation and performs the wipe.
  * Wiping is usually the WRONG first move for mercenary spyware: it destroys the
    forensic evidence needed to confirm the infection and help the target, and
    advanced implants can survive it. So the correct guidance is shown FIRST, and
    the reset is gated behind repeated confirmations and a typed phrase.
"""
from __future__ import annotations

import sys

from .core import detect_host, run
from .checks_android import scan_mercenary_indicators
from .banner import Ink, make_ink

RESET_PHRASE = "YES RESET MY DEVICE"
CONFIRMATIONS = 5

HELPLINE = "Access Now Digital Security Helpline — https://www.accessnow.org/help/  (help@accessnow.org, free, 24/7)"
MVT = "Amnesty International MVT — https://github.com/mvt-project/mvt"


def _ask_yn(ink: Ink, prompt: str) -> bool:
    try:
        return input("  " + ink.amber(prompt + " [y/N] ")).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def _guidance(ink: Ink) -> None:
    print(ink.bold("  What to do BEFORE you consider wiping:"))
    print("    1. " + ink.bone("Don't wipe yet.") + ink.dim(" A reset destroys the evidence needed to confirm this."))
    print("    2. " + ink.bone("Preserve the device") + ink.dim(" — keep it powered, put it in airplane mode if you can."))
    print("    3. " + ink.bone("Contact experts:") + " " + ink.cyan(HELPLINE))
    print("    4. " + ink.bone("Confirm forensically:") + " " + ink.cyan(MVT))
    print(ink.dim("  A factory reset may NOT remove an advanced implant, and re-infection is common."))


def run_panic(ink: Ink | None = None) -> int:
    ink = ink or make_ink(None)
    host = detect_host()

    print(ink.red_b("╺╸ MURPHY PANIC — suspected mercenary spyware response"))
    print("")

    if not host.has("android"):
        print(ink.amber("  This flow targets Android devices (run it on the phone via Termux)."))
        print(ink.dim("  If you suspect a desktop compromise, isolate the machine and seek help:"))
        print("    " + ink.cyan(HELPLINE))
        return 0

    hits = scan_mercenary_indicators(host)
    if not hits:
        print(ink.green("  No mercenary-spyware indicators seen on this device."))
        print(ink.dim("  This is an indicator scan only — it can miss a well-hidden implant."))
        print("  For real assurance, run " + ink.cyan(MVT) + ink.dim(" on a forensic acquisition."))
        return 0

    print(ink.red_b("  ⚠ Indicator(s) matched:"))
    for h in hits:
        print("    " + ink.red_b("• ") + ink.bone(h))
    print("")
    _guidance(ink)
    print("")

    if not sys.stdin.isatty():
        print(ink.amber("  Non-interactive session — refusing to touch the reset flow. "
                        "Re-run in a real terminal."))
        return 0

    # The reset is opt-in, on top of all the guidance above.
    if not _ask_yn(ink, "Ignore the advice above and go to the factory-reset option anyway?"):
        print(ink.green("  Good — nothing changed. Preserve the device and reach out to the helpline."))
        return 0

    print(ink.red_b("\n  A factory reset ERASES ALL DATA on this device and cannot be undone."))
    for n in range(1, CONFIRMATIONS + 1):
        if not _ask_yn(ink, f"Are you absolutely sure you want to reset? ({n} of {CONFIRMATIONS})"):
            print(ink.green("  Aborted — nothing changed."))
            return 0

    try:
        typed = input("\n  Type exactly " + ink.red_b(RESET_PHRASE) + " to proceed: ")
    except (EOFError, KeyboardInterrupt):
        print(ink.green("\n  Aborted — nothing changed."))
        return 0
    if typed.strip() != RESET_PHRASE:
        print(ink.green("  Phrase did not match — aborted, nothing changed."))
        return 0

    # Murphy does not silently wipe. Open the OS factory-reset screen; the OS asks
    # for its own final confirmation and performs the wipe.
    print(ink.amber("\n  Opening the system factory-reset screen "
                    "(Android will ask you to confirm there)…"))
    launched = False
    for cmd in (["am", "start", "-a", "android.settings.FACTORY_RESET"],
                ["am", "start", "-n", "com.android.settings/.MasterClear"],
                ["am", "start", "-a", "android.settings.PRIVACY_SETTINGS"]):
        rc, _ = run(cmd, timeout=10)
        if rc == 0:
            launched = True
            break
    if launched:
        print(ink.dim("  Follow the on-screen prompts to complete (or cancel) the reset."))
    else:
        print(ink.amber("  Could not open it automatically. Do it manually:"))
        print(ink.dim("    Settings → System → Reset options → Erase all data (factory reset)"))
    print(ink.dim("  Murphy did not erase anything itself; the OS performs the wipe."))
    return 0
