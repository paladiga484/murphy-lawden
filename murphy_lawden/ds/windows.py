"""`ds` on Windows — the same idea with Windows' own locks.

  acl        deny Execute to Everyone on everything inside the torrent folder: an .exe,
             .dll or .scr there cannot start (this works on Home edition too)
  defender   Controlled Folder Access (Defender's anti-ransomware), PUA blocking, and
             attack-surface-reduction rules aimed at droppers, ransomware, credential
             theft and vulnerable-driver (bootkit/rootkit) loading
  qbit       downloads land in the folder and carry Mark-of-the-Web
  run        Windows Sandbox with networking, GPU, clipboard, printers, mic and camera
             off — only on Pro/Enterprise/Education; on Home `ds run` refuses, because
             there is no cage and "run it anyway" is the one thing not to do

Written against Microsoft's documentation; it has not been run on a Windows box.
The Defender layers need an elevated (Administrator) terminal.
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape

from ..core import run
from . import qbit, state

EVERYONE = "*S-1-1-0"
SANDBOX = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
STAGE = state.state_dir() / "stage"

# (GUID, action, why) — 1 = Block, 6 = Warn (you can click through for your own builds)
ASR = [
    ("d3e037e1-3eb8-44c8-a917-57927947596d", 1, "scripts launching downloaded executables"),
    ("5beb7efe-fd9a-4556-801d-275e5ffc04cc", 1, "obfuscated scripts"),
    ("c1db55ab-c21a-4637-bb3f-a12568109d35", 1, "advanced ransomware protection"),
    ("e6db77e5-3df2-4cf1-b95a-636979351e5b", 1, "persistence through WMI"),
    ("56a863a9-875e-4185-98a7-b882c64b5ce5", 1, "vulnerable signed drivers (rootkit/bootkit loaders)"),
    ("9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", 1, "credential theft from LSASS"),
    ("33ddedf1-c6e0-47cb-833e-de6133960387", 1, "reboot into Safe Mode (ransomware trick)"),
    ("01443614-cd74-433a-b99e-2ecdc07bfc25", 6, "unknown/rare executables (Warn: your own builds "
                                                "would trip Block)"),
    ("c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", 6, "copied/impersonated system tools"),
]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _ps(script: str, timeout: int = 120) -> tuple[int, str]:
    return run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)


def _acl_locked(folder: Path) -> bool:
    """Is there an inheritable Deny-Execute ACE for Everyone? Matched by SID, not by
    the group's name, which icacls prints translated on non-English Windows."""
    lit = str(folder).replace("'", "''")
    rc, out = _ps(f"(Get-Acl -LiteralPath '{lit}').Access | Where-Object {{ "
                  "$_.AccessControlType -eq 'Deny' -and "
                  "($_.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::"
                  "ExecuteFile) -and "
                  "$_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])"
                  ".Value -eq 'S-1-1-0' } | Measure-Object | Select-Object -ExpandProperty Count")
    return rc == 0 and out.strip().isdigit() and int(out.strip()) > 0


def _mp_pref() -> dict:
    rc, out = _ps("$p=Get-MpPreference; "
                  "'CFA=' + [int]$p.EnableControlledFolderAccess; "
                  "'PUA=' + [int]$p.PUAProtection; "
                  "'MAPS=' + [int]$p.MAPSReporting; "
                  "for($i=0;$i -lt $p.AttackSurfaceReductionRules_Ids.Count;$i++){"
                  "'ASR=' + $p.AttackSurfaceReductionRules_Ids[$i] + ':' + "
                  "[int]$p.AttackSurfaceReductionRules_Actions[$i]}")
    pref: dict = {"asr": {}}
    for line in out.splitlines():
        k, _, v = line.strip().partition("=")
        if k == "ASR":
            gid, _, act = v.partition(":")
            pref["asr"][gid.lower()] = int(act or 0)
        elif k in ("CFA", "PUA", "MAPS") and v.lstrip("-").isdigit():
            pref[k] = int(v)
    return pref


def lock(folder: Path, out) -> int:
    led = state.load()
    if led.get("folder") and Path(led["folder"]) != folder:
        out("!", f"already locked {led['folder']} — `murphy ds unlock` it first")
        return 2
    led["folder"] = str(folder)
    state.save(led)
    fails = 0
    folder.mkdir(parents=True, exist_ok=True)

    if _acl_locked(folder):
        out("=", f"acl: {folder} already denies Execute")
    else:
        rc, msg = run(["icacls", str(folder), "/deny", f"{EVERYONE}:(OI)(CI)(IO)(X)"])
        ok = rc == 0 and _acl_locked(folder)
        if ok:
            state.remember(led, "acl", "folder", str(folder))
        out("+" if ok else "x", f"acl: nothing inside {folder} may execute" + ("" if ok else f" — {msg.strip()}"))
        fails += not ok

    if not is_admin():
        out("!", "defender: skipped — re-run `murphy ds lock` from an Administrator terminal "
                 "for Controlled Folder Access, PUA and the ASR rules")
    else:
        pref = _mp_pref()
        state.remember(led, "defender", "CFA", pref.get("CFA", 0))
        state.remember(led, "defender", "PUA", pref.get("PUA", 0))
        state.remember(led, "defender", "asr", pref["asr"])
        rc1, _ = _ps("Set-MpPreference -EnableControlledFolderAccess Enabled")
        rc2, _ = _ps("Set-MpPreference -PUAProtection Enabled")
        out("+" if rc1 == 0 else "x", "defender: Controlled Folder Access on (ransomware can't "
                                      "rewrite Documents/Pictures/Desktop…)")
        out("+" if rc2 == 0 else "x", "defender: potentially-unwanted-app blocking on")
        fails += (rc1 != 0) + (rc2 != 0)
        for gid, act, why in ASR:
            if pref["asr"].get(gid) == act:
                continue
            rc, _ = _ps(f"Add-MpPreference -AttackSurfaceReductionRules_Ids {gid} "
                        f"-AttackSurfaceReductionRules_Actions {act}")
            out("+" if rc == 0 else "x", f"asr: {'block' if act == 1 else 'warn'} {why}")
            fails += rc != 0
        if not pref.get("MAPS"):
            out("!", "defender: cloud-delivered protection is off — three of the ASR rules "
                     "(ransomware, obfuscated scripts, unknown executables) need it")

    if qbit.running():
        out("x", "qbittorrent: running — close it and re-run `murphy ds lock`")
        fails += 1
    elif qbit.config_path().exists():
        changed = qbit.apply_lock(folder, led, state.remember)
        out("+" if changed else "=", "qbittorrent: " + ("; ".join(changed) if changed
                                                        else "already pointed at the lock"))
    out("!", "7-Zip: set Tools → Options → 7-Zip → 'Propagate Zone.Id stream' = Yes, so files you "
             "extract by hand keep the internet mark (`murphy ds extract` does it for you)")
    return 1 if fails else 0


def unlock(out) -> int:
    led = state.load()
    fails = 0
    if "acl" in led:
        rc, _ = run(["icacls", led["acl"]["folder"], "/remove:d", EVERYONE, "/T", "/C"])
        out("+" if rc == 0 else "x", "acl: execute-deny removed")
        if rc == 0:
            led.pop("acl")
        fails += rc != 0
    if "defender" in led:
        if not is_admin():
            out("x", "defender: needs an Administrator terminal to restore")
            fails += 1
        else:
            d = led["defender"]
            _ps(f"Set-MpPreference -EnableControlledFolderAccess {int(d.get('CFA', 0))}")
            _ps(f"Set-MpPreference -PUAProtection {int(d.get('PUA', 0))}")
            before = {k.lower(): v for k, v in d.get("asr", {}).items()}
            for gid, _, _ in ASR:
                if gid in before:
                    _ps(f"Add-MpPreference -AttackSurfaceReductionRules_Ids {gid} "
                        f"-AttackSurfaceReductionRules_Actions {before[gid]}")
                else:
                    _ps(f"Remove-MpPreference -AttackSurfaceReductionRules_Ids {gid}")
            led.pop("defender")
            out("+", "defender: previous settings restored")
    if "qbit" in led:
        if qbit.running():
            out("x", "qbittorrent: running — close it and re-run unlock")
            fails += 1
        else:
            qbit.restore(led)
            led.pop("qbit")
            out("+", "qbittorrent: original settings restored")
    if set(led) <= {"folder"}:
        state.LEDGER.unlink(missing_ok=True)
    else:
        state.save(led)
    return 1 if fails else 0


def status(folder: Path, out) -> None:
    out("+" if _acl_locked(folder) else "x", f"acl: {folder} "
        + ("denies Execute" if _acl_locked(folder) else "NOT locked — programs can run from it"))
    pref = _mp_pref()
    out("+" if pref.get("CFA") == 1 else "x", "defender: Controlled Folder Access "
        + ("on" if pref.get("CFA") == 1 else "off"))
    missing = [why for gid, act, why in ASR if pref["asr"].get(gid) not in (1, 6)]
    out("+" if not missing else "x", "asr: " + ("all rules active" if not missing
                                               else f"{len(missing)} rule(s) off"))
    out("+" if SANDBOX.exists() else "!", "cage: " + ("Windows Sandbox available" if SANDBOX.exists()
        else "no Windows Sandbox (Home edition, or the feature is off) — `ds run` will refuse"))


# ---- cage ------------------------------------------------------------------ #
def run_caged(target: Path, whole_dir: bool, outdir: Path, out) -> int:
    if not SANDBOX.exists():
        out("x", "Windows Sandbox isn't available (Home edition, or turn on the optional "
                 "feature 'Windows Sandbox'). There is no cage, so Murphy won't run it.")
        return 2
    STAGE.mkdir(parents=True, exist_ok=True)
    for old in STAGE.iterdir():                       # previous runs' copies
        if time.time() - old.stat().st_mtime > 3600:
            shutil.rmtree(old, ignore_errors=True)
    work = Path(tempfile.mkdtemp(prefix="stage-", dir=STAGE))
    if whole_dir:
        shutil.copytree(target.parent, work / "in")
    else:
        (work / "in").mkdir()
        shutil.copy2(target, work / "in" / target.name)
    outdir.mkdir(parents=True, exist_ok=True)
    inner = f"C:\\cage\\in\\{target.name}"
    wsb = work / "cage.wsb"
    wsb.write_text(f"""<Configuration>
  <Networking>Disable</Networking>
  <vGPU>Disable</vGPU>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ProtectedClient>Enable</ProtectedClient>
  <MappedFolders>
    <MappedFolder><HostFolder>{escape(str(work / 'in'))}</HostFolder>
      <SandboxFolder>C:\\cage\\in</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
    <MappedFolder><HostFolder>{escape(str(outdir))}</HostFolder>
      <SandboxFolder>C:\\cage\\out</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
  </MappedFolders>
  <LogonCommand><Command>cmd.exe /c start "" "{escape(inner)}"</Command></LogonCommand>
</Configuration>
""", encoding="utf-8")
    out("+", "Windows Sandbox: no network, no GPU, no clipboard, no mic/camera; "
             f"writes only to {outdir}. Closing the window destroys everything inside.")
    subprocess.Popen([str(SANDBOX), str(wsb)])
    return 0


def extract(archive: Path, outdir: Path, out) -> int:
    sz = shutil.which("7z") or str(Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
                                   / "7-Zip" / "7z.exe")
    if not Path(sz).exists():
        out("x", "7-Zip not found")
        return 2
    out("!", "Windows has no unprivileged cage for the extractor; 7-Zip runs as you, into the "
             "locked folder, with the internet mark copied onto every file (-snz)")
    outdir.mkdir(parents=True, exist_ok=True)
    return subprocess.run([sz, "x", "-snz", f"-o{outdir}", "--", str(archive)]).returncode
