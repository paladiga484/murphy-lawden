"""Android (`su`) hardening checks — phones, tablets, Termux, Waydroid, LineageOS.

Android runs on the Linux kernel, so ``platform.system()`` is ``Linux`` and every
Linux check already applies. These checks add the things that are *specific* to
the Android security model: whether the device is rooted (a live ``su``), whether
a root manager (Magisk/SuperSU) is installed, whether ADB is exposed over the
network, whether SELinux is still enforcing, and whether sideloading or on-device
instrumentation tooling (frida) has been left enabled.

They only fire when the host was tagged ``android`` (see ``core._detect_android``);
on a normal Linux box they return nothing. Read-only and failure-tolerant like the
rest — a missing ``getprop`` or an unreadable path SKIPs, it never crashes.
"""
from __future__ import annotations

import os
from typing import Iterable

from .core import Finding, Host, Severity, Status, check, have, run


def _f(id, title, status, sev=Severity.INFO, **kw) -> Finding:
    return Finding(id=id, title=title, status=status, severity=sev, **kw)


def _getprop(key: str) -> str:
    """Read an Android system property. '' if getprop is missing/unreadable."""
    rc, out = run(["getprop", key])
    return out.strip() if rc == 0 else ""


# Common on-disk locations of an `su` binary across ROMs and rooting methods.
_SU_PATHS = [
    "/system/bin/su", "/system/xbin/su", "/system/sbin/su", "/sbin/su",
    "/su/bin/su", "/magisk/.core/bin/su", "/data/adb/magisk/su",
    "/system/app/Superuser.apk", "/vendor/bin/su", "/debug_ramdisk/su",
    "/data/adb/ksu/bin/ksu", "/data/adb/ap/bin/ap", "/data/adb/apd/bin/apd",
]
# Root managers and their data dirs.
_ROOT_MANAGER_PATHS = [
    "/data/adb/magisk", "/data/adb/modules", "/data/adb/ksu", "/data/adb/ap",
    "/data/adb/magisk.db", "/sbin/.magisk", "/data/adb/ksud", "/data/adb/apd",
]
# Root manager apps, keyed by their real package id → human label. The manager app
# often survives even when its `su` binary and data dir have been renamed or hidden
# (Magisk's "hide"/random-package trick can't rename a *user-installed* manager APK),
# so `pm list packages` is a useful second angle on the same question.
_ROOT_MANAGER_PACKAGES = {
    "com.topjohnwu.magisk": "Magisk",
    "me.weishu.kernelsu": "KernelSU",
    "com.rifsxd.ksunext": "KernelSU-Next",
    "me.bmax.apatch": "APatch",
    "eu.chainfire.supersu": "SuperSU (legacy)",
    "com.koushikdutta.superuser": "Superuser (legacy)",
}


def _pm_packages() -> set[str]:
    """Installed package ids via `pm list packages`, or an empty set if unavailable.

    `pm` prints one ``package:<id>`` line per app; we strip the prefix. Short timeout
    because on a bloated device `pm` can be slow, and this must never hang a scan."""
    if not have("pm"):
        return set()
    rc, out = run(["pm", "list", "packages"], timeout=8)
    if rc != 0:
        return set()
    return {ln.partition(":")[2].strip() for ln in out.splitlines()
            if ln.startswith("package:")}
# On-device instrumentation / hooking tooling — legit for researchers, but a
# classic spyware/implant staging spot when you didn't put it there.
_INSTRUMENTATION_PATHS = [
    "/data/local/tmp/frida-server", "/data/local/tmp/re.frida.server",
    "/data/local/tmp/frida-gadget.so", "/data/local/tmp/gdbserver",
    "/data/local/tmp/objection", "/system/lib/libxposed_art.so",
    "/system/framework/XposedBridge.jar", "/data/adb/lspd",
]


# --------------------------------------------------------------------------- #
#  Rooted? — a live `su` on Android
# --------------------------------------------------------------------------- #
@check("linux")
def android_su(host: Host) -> Iterable[Finding]:
    if not host.has("android"):
        return
    found = [p for p in _SU_PATHS if os.path.exists(p)]
    if have("su") and not found:
        found.append("su (on PATH)")
    if found:
        yield _f("android.su", "Device is rooted — a live `su` is present",
                 Status.WARN, Severity.HIGH, detail=", ".join(found[:6]),
                 rationale="Root breaks Android's app-sandbox model: any app you grant su to (or "
                           "any exploit that reaches the su daemon) gets the whole device. On a "
                           "daily driver this is a large, permanent increase in attack surface — "
                           "and much mobile spyware assumes or seeks root.",
                 fix="If you didn't root this device deliberately, treat it as compromised and "
                     "investigate. If you did, keep the root manager locked down (per-app prompts, "
                     "no default-grant), and never grant su to apps you don't fully trust.")
    else:
        yield _f("android.su", "No `su` present — device is not rooted", Status.PASS, Severity.HIGH)


# --------------------------------------------------------------------------- #
#  Root manager (Magisk / KernelSU / APatch / SuperSU)
# --------------------------------------------------------------------------- #
@check("linux")
def android_root_manager(host: Host) -> Iterable[Finding]:
    if not host.has("android"):
        return

    # Two angles on the same question: the manager's data dir on disk (fast, but the
    # dir can be renamed/hidden), and its installed APK via `pm` (survives hiding the
    # binary). Either is enough to report; together they cut false negatives on ROMs
    # that hide root. Detail names *what* we saw so the reader can act on it.
    evidence: list[str] = []
    evidence += [p for p in _ROOT_MANAGER_PATHS if os.path.exists(p)]

    packages = _pm_packages()
    evidence += [f"{label} app ({pkg})"
                 for pkg, label in _ROOT_MANAGER_PACKAGES.items() if pkg in packages]

    if evidence:
        yield _f("android.rootmgr", "A root manager (Magisk/KernelSU/APatch) is installed",
                 Status.WARN, Severity.MEDIUM, detail=", ".join(evidence[:6]),
                 rationale="A root manager mediates su grants. It's the control point for a rooted "
                           "device — if it's misconfigured (default-grant, no prompts) every app can "
                           "escalate; if it's an unofficial fork it may itself be backdoored.",
                 fix="Confirm it's an official build, require a prompt for every su grant, and audit "
                     "the module list (/data/adb/modules) for anything you didn't install.")
    else:
        yield _f("android.rootmgr", "No root manager detected", Status.PASS, Severity.LOW)


# --------------------------------------------------------------------------- #
#  ADB exposed over the network (wireless debugging)
# --------------------------------------------------------------------------- #
@check("linux")
def android_adb_tcp(host: Host) -> Iterable[Finding]:
    if not host.has("android"):
        return
    port = _getprop("service.adb.tcp.port")
    if port and port not in ("", "0", "-1"):
        yield _f("android.adb_tcp", f"ADB is listening over TCP (port {port})",
                 Status.FAIL, Severity.HIGH, detail=f"service.adb.tcp.port={port}",
                 rationale="Network ADB is an unauthenticated remote shell to anyone who can reach "
                           "the port and whose key is trusted (or who can prompt you to trust one). "
                           "It's a common lateral-movement and implant-installation vector on Wi-Fi.",
                 fix="Turn off wireless debugging: `adb tcpip 0`, or Settings → Developer options → "
                     "Wireless debugging → off. Leave ADB to USB only, and revoke stale debug keys.")
    else:
        yield _f("android.adb_tcp", "ADB is not exposed over TCP", Status.PASS, Severity.MEDIUM)


# --------------------------------------------------------------------------- #
#  SELinux must stay Enforcing on Android
# --------------------------------------------------------------------------- #
@check("linux")
def android_selinux(host: Host) -> Iterable[Finding]:
    if not host.has("android"):
        return
    mode = _getprop("ro.boot.selinux")
    enforce = ""
    if have("getenforce"):
        rc, out = run(["getenforce"])
        enforce = out.strip()
    verdict = (enforce or mode).lower()
    if not verdict:
        yield _f("android.selinux", "Could not determine SELinux mode", Status.SKIP,
                 detail="getenforce/getprop unavailable")
        return
    if "permissive" in verdict or "disabled" in verdict:
        yield _f("android.selinux", f"SELinux is {verdict} (should be enforcing)",
                 Status.FAIL, Severity.HIGH, detail=f"mode={verdict}",
                 rationale="Android relies on SELinux in enforcing mode to contain apps and services. "
                           "Permissive/disabled is normal only on a dev build — on a daily device it "
                           "usually means a custom ROM or an exploit dropped the policy.",
                 fix="Boot a ROM that keeps SELinux enforcing. If you didn't set permissive yourself, "
                     "treat it as a strong sign of tampering and investigate.")
    else:
        yield _f("android.selinux", "SELinux is enforcing", Status.PASS, Severity.HIGH)


# --------------------------------------------------------------------------- #
#  Sideloading / install of non-market apps
# --------------------------------------------------------------------------- #
@check("linux")
def android_sideload(host: Host) -> Iterable[Finding]:
    if not host.has("android"):
        return
    if not have("settings"):
        return
    val = ""
    for scope in ("global", "secure"):
        rc, out = run(["settings", "get", scope, "install_non_market_apps"])
        out = out.strip()
        if out and out != "null":
            val = out
            break
    if val == "1":
        yield _f("android.sideload", "Sideloading (install of non-market apps) is enabled",
                 Status.WARN, Severity.MEDIUM, detail="install_non_market_apps=1",
                 rationale="Most Android malware and stalkerware arrives as a sideloaded APK. A global "
                           "'allow unknown sources' removes the main speed-bump against that.",
                 fix="Disable the global setting and grant install permission per-app only when you "
                     "genuinely need it (Settings → Apps → Special access → Install unknown apps).")
    elif val == "0":
        yield _f("android.sideload", "Sideloading of unknown apps is disabled", Status.PASS, Severity.LOW)
    # unknown/null → say nothing (per-app model on modern Android): not a finding.


# --------------------------------------------------------------------------- #
#  On-device instrumentation tooling staged (frida / Xposed / gdbserver)
# --------------------------------------------------------------------------- #
@check("linux")
def android_instrumentation(host: Host) -> Iterable[Finding]:
    if not host.has("android"):
        return
    found = [p for p in _INSTRUMENTATION_PATHS if os.path.exists(p)]
    if found:
        yield _f("mal.android_instrument", "Instrumentation/hooking tooling staged on device",
                 Status.WARN, Severity.HIGH, detail=", ".join(found[:6]),
                 rationale="frida-server, Xposed/LSPosed and gdbserver hook into other apps' memory. "
                           "They're legitimate for a security researcher — and exactly what an implant "
                           "stages to intercept your messages, tokens and keystrokes.",
                 fix="If you're not actively instrumenting apps yourself, remove these and find out "
                     "what put them there. frida-server in /data/local/tmp is a common implant marker.")
    else:
        yield _f("mal.android_instrument", "No instrumentation tooling staged", Status.PASS, Severity.LOW)


# --------------------------------------------------------------------------- #
#  Mercenary spyware indicators (Pegasus / Chrysaor, Predator)
# --------------------------------------------------------------------------- #
# HONEST SCOPE: this is a light, on-device *indicator* scan. It is NOT a forensic
# confirmation. Real detection of mercenary spyware needs a full acquisition
# analysed with Amnesty International's MVT (https://github.com/mvt-project/mvt).
#   • absence here does NOT mean the device is clean, and
#   • a hit is a reason to ESCALATE and preserve the device — not proof by itself.
# The package list is kept deliberately small and sourced from public IOC reports;
# extend it only from documented indicators.
_MERCENARY_PACKAGES = {
    "com.network.android": "Chrysaor / Android Pegasus (NSO) — Lookout & Google, 2017",
}
# Documented on-device staging artifacts. Frida/Xposed are handled separately by
# android_instrumentation; keep this to spyware-specific, publicly-reported paths.
_MERCENARY_PATHS: list[str] = [
    "/data/local/tmp/lspeed",
    "/data/local/tmp/.wl",
]


def scan_mercenary_indicators(host: "Host") -> list[str]:
    """Return a list of human-readable indicator hits (empty = none seen).

    Read-only and failure-tolerant. Shared by the `mal.pegasus` check and the
    `panic` emergency-response flow so both see exactly the same evidence.
    """
    if not host.has("android"):
        return []
    hits: list[str] = []
    packages = _pm_packages()
    for pkg, label in _MERCENARY_PACKAGES.items():
        if pkg in packages:
            hits.append(f"package {pkg} — {label}")
    hits += [f"artifact {p}" for p in _MERCENARY_PATHS if os.path.exists(p)]
    return hits


@check("linux")
def android_mercenary_spyware(host: Host) -> Iterable[Finding]:
    if not host.has("android"):
        return
    hits = scan_mercenary_indicators(host)
    escalate = (
        "This is an INDICATOR scan, not proof. If you have real reason to suspect "
        "targeting: do NOT wipe yet (a reset destroys the evidence). Preserve the "
        "device, contact the Access Now Digital Security Helpline "
        "(https://www.accessnow.org/help/ · help@accessnow.org, free & 24/7), and "
        "run Amnesty's MVT (https://github.com/mvt-project/mvt) on a forensic "
        "acquisition to confirm. `murphy panic` walks you through this."
    )
    if hits:
        yield _f("mal.pegasus", "Mercenary-spyware indicator(s) present on this device",
                 Status.FAIL, Severity.CRITICAL, detail="; ".join(hits[:6]),
                 rationale="These match publicly-documented indicators of mercenary spyware "
                           "(e.g. NSO Pegasus/Chrysaor). Such implants target journalists, "
                           "activists and their contacts and give an operator full device access.",
                 fix=escalate)
    else:
        yield _f("mal.pegasus", "No mercenary-spyware indicators seen (indicator scan only)",
                 Status.PASS, Severity.LOW, detail="not a forensic confirmation",
                 fix="For real assurance against Pegasus/Predator, run Amnesty's MVT "
                     "(https://github.com/mvt-project/mvt). Indicator scans can miss a "
                     "well-hidden implant.")
