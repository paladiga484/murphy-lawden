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
]
# Root managers and their data dirs.
_ROOT_MANAGER_PATHS = [
    "/data/adb/magisk", "/data/adb/modules", "/data/adb/ksu", "/data/adb/ap",
    "/data/adb/magisk.db", "/sbin/.magisk",
]
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
    found = [p for p in _ROOT_MANAGER_PATHS if os.path.exists(p)]
    if found:
        yield _f("android.rootmgr", "A root manager (Magisk/KernelSU/APatch) is installed",
                 Status.WARN, Severity.MEDIUM, detail=", ".join(found[:6]),
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
