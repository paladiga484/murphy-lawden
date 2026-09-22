"""``murphy module`` — package Murphy as a systemless Magisk module.

A Magisk module is the most *Murphy-shaped* way to harden Android: it is
**systemless** (nothing is written to a real partition) and **reversible** by
design — toggle the module off in the Magisk app and every change is gone on the
next boot. No restore point needed; the OS forgets it entirely.

``build()`` writes a flashable ``murphy-hardening.zip`` that:

  * applies a vetted set of kernel-hardening sysctls **late in boot** (missing
    knobs are skipped, never forced), logging what it set to
    ``/data/adb/murphy/boot.log``;
  * bundles Murphy itself, so if a Python interpreter is present (e.g. Termux)
    ``service.sh`` also drops a boot-time posture scan to
    ``/data/adb/murphy/last-scan.json``.

Everything here is stdlib-only (``zipfile``). Install the result from the Magisk
app, or ``magisk --install-module murphy-hardening.zip``, or just push the
unpacked tree to ``/data/adb/modules/murphy-hardening/`` and reboot.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from . import __version__

MODULE_ID = "murphy-hardening"

# The official Magisk module installer stub. It loads util_functions.sh from the
# live Magisk install and calls install_module (which reads module.prop, runs
# customize.sh, and lays the tree down under /data/adb/modules/<id>).
_UPDATE_BINARY = """\
#!/sbin/sh
umask 022
ui_print() { echo "$1"; }
require_new_magisk() {
  ui_print "*******************************"
  ui_print " Please install Magisk v20.4+! "
  ui_print "*******************************"
  exit 1
}
OUTFD=$2
ZIPFILE=$3
mount /data 2>/dev/null
[ -f /data/adb/magisk/util_functions.sh ] || require_new_magisk
. /data/adb/magisk/util_functions.sh
[ "$MAGISK_VER_CODE" -lt 20400 ] && require_new_magisk
install_module
exit 0
"""

_UPDATER_SCRIPT = "#MAGISK\n"


def _version_code() -> int:
    parts = (__version__.split("+")[0].split("-")[0].split(".") + ["0", "0", "0"])[:3]
    try:
        a, b, c = (int(x) for x in parts)
    except ValueError:
        a, b, c = 0, 0, 0
    return a * 10000 + b * 100 + c


def _module_prop() -> str:
    return (
        f"id={MODULE_ID}\n"
        f"name=Murphy Lawden (systemless hardening)\n"
        f"version=v{__version__}\n"
        f"versionCode={_version_code()}\n"
        f"author=Murphy Lawden\n"
        f"description=Systemless security suite: kernel hardening at boot + a "
        f"GrapheneOS-style BFU auto-reboot sentinel (seals the device to "
        f"Before-First-Unlock on inactivity). Action button shows status. Fully "
        f"reversible by toggling the module. Bundles Murphy for an optional "
        f"boot-time posture scan when a Python interpreter (e.g. Termux) is present.\n"
    )


_CUSTOMIZE_SH = """\
#!/system/bin/sh
ui_print " "
ui_print "  Murphy Lawden — systemless hardening"
ui_print "  ----------------------------------------------------"
ui_print "  · applies vetted kernel-hardening sysctls at boot"
ui_print "  · missing knobs are skipped, nothing is forced"
ui_print "  · REVERSIBLE — disable/remove the module to revert"
ui_print "    (no trace on /system; a reboot restores stock values)"
ui_print "  · optional boot scan runs only if python is present"
ui_print "  · log:  /data/adb/murphy/boot.log"
ui_print " "
set_perm_recursive "$MODPATH" 0 0 0755 0644
for s in service.sh bfu-autoreboot.sh action.sh; do
  [ -f "$MODPATH/$s" ] && set_perm "$MODPATH/$s" 0 0 0755
done
[ -f "$MODPATH/murphy/murphy.py" ] && set_perm "$MODPATH/murphy/murphy.py" 0 0 0755
ui_print "  · BFU auto-reboot: seals to Before-First-Unlock after 6h idle (edit bfu.conf)"
"""

# Late-boot hardening. Every knob is optional: if /proc/sys/... isn't present or
# writable, it's skipped — a big list never breaks a kernel that lacks a knob.
_SERVICE_SH = """\
#!/system/bin/sh
# Murphy Lawden hardening — runs late in boot, as root, systemlessly.
MODDIR=${0%/*}
STATE=/data/adb/murphy
LOG="$STATE/boot.log"
mkdir -p "$STATE" 2>/dev/null

set_sysctl() {
  node="/proc/sys/$(echo "$1" | tr '.' '/')"
  if [ -w "$node" ]; then
    cur=$(cat "$node" 2>/dev/null)
    if [ "$cur" != "$2" ]; then
      echo "$2" > "$node" 2>/dev/null && echo "$(date '+%Y-%m-%d %H:%M:%S') set $1: $cur -> $2" >> "$LOG"
    fi
  fi
}

echo "=== $(date '+%Y-%m-%d %H:%M:%S') murphy-hardening service.sh ===" >> "$LOG"

# --- kernel / memory ---
set_sysctl kernel.kptr_restrict 2
set_sysctl kernel.dmesg_restrict 1
set_sysctl kernel.perf_event_paranoid 3
set_sysctl kernel.kexec_load_disabled 1
set_sysctl kernel.unprivileged_bpf_disabled 2
set_sysctl net.core.bpf_jit_harden 2
set_sysctl kernel.yama.ptrace_scope 1

# --- network ---
set_sysctl net.ipv4.tcp_syncookies 1
# rp_filter 1 (strict) breaks every VPN and proxy on Android: the platform uses
# per-network policy routing, so tunnel return traffic never matches the
# main-table reverse path and is silently dropped (tx climbs, rx stays 0).
# conf.all is max()-ed against each interface, so 1 here overrides them all.
# 2 = loose RPF: keeps the anti-spoofing guarantee, safe when multi-homed.
set_sysctl net.ipv4.conf.all.rp_filter 2
set_sysctl net.ipv4.conf.all.accept_redirects 0
set_sysctl net.ipv6.conf.all.accept_redirects 0
set_sysctl net.ipv4.conf.all.send_redirects 0
set_sysctl net.ipv4.conf.all.accept_source_route 0
set_sysctl net.ipv6.conf.all.accept_source_route 0

# --- optional: a boot-time posture scan, only if an interpreter exists ---
PY=$(command -v python3 2>/dev/null || command -v python 2>/dev/null)
[ -z "$PY" ] && [ -x /data/data/com.termux/files/usr/bin/python ] && PY=/data/data/com.termux/files/usr/bin/python
if [ -n "$PY" ] && [ -f "$MODDIR/murphy/murphy.py" ]; then
  ( "$PY" "$MODDIR/murphy/murphy.py" scan --json --no-banner --no-prompt \
      > "$STATE/last-scan.json" 2>>"$LOG" && \
    echo "$(date '+%Y-%m-%d %H:%M:%S') posture scan -> $STATE/last-scan.json" >> "$LOG" ) &
fi

# BFU auto-reboot watcher — seal the device to Before-First-Unlock on inactivity.
[ -f "$MODDIR/bfu-autoreboot.sh" ] && sh "$MODDIR/bfu-autoreboot.sh" &
"""

# BFU/AFU auto-reboot: a GrapheneOS-style sentinel. After the device is booted and
# unlocked its FBE class keys live in RAM (AFU); a plain reboot evicts them and the
# device comes back sealed (BFU) — safest against a seized-while-idle phone. This
# watches screen state and reboots once the screen has been off long enough.
_BFU_SH = """\
#!/system/bin/sh
MODDIR=${0%/*}
STATE=/data/adb/murphy
LOG="$STATE/bfu.log"
CONF="$MODDIR/bfu.conf"
mkdir -p "$STATE" 2>/dev/null

THRESHOLD_H=6      # hours of screen-off before sealing to BFU
ENABLED=1
[ -f "$CONF" ] && . "$CONF" 2>/dev/null
[ "$ENABLED" = "1" ] || { echo "$(date '+%F %T') BFU disabled" >> "$LOG"; exit 0; }
THRESHOLD=$(( THRESHOLD_H * 3600 ))

screen_on() { dumpsys power 2>/dev/null | grep -qE 'mWakefulness=Awake'; }

off_since=$(date +%s)
echo "$(date '+%F %T') BFU watcher up — seal after ${THRESHOLD_H}h screen-off" >> "$LOG"
while :; do
  sleep 300
  if screen_on; then off_since=$(date +%s); continue; fi
  idle=$(( $(date +%s) - off_since ))
  if [ "$idle" -ge "$THRESHOLD" ]; then
    echo "$(date '+%F %T') idle ${idle}s ≥ ${THRESHOLD}s — rebooting to BFU (keys evicted)" >> "$LOG"
    sync
    reboot
    exit 0
  fi
done
"""

_BFU_CONF = """\
# Murphy BFU auto-reboot — edit and reboot to apply.
# Seal the device to Before-First-Unlock (evict FBE keys from RAM) after this many
# hours with the screen off. Lower = safer if seized; higher = fewer reboots.
THRESHOLD_H=6
# Set ENABLED=0 to turn the watcher off without removing the module.
ENABLED=1
"""

# Full WebUI app (KernelSU / APatch / MMRL / WebUI-X render webroot/index.html when
# you tap the module) — a real, touch-friendly GUI over the module's controls.
_WEBUI_HTML = r"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Murphy Lawden</title>
<style>
:root{--ink:#0d0c0a;--panel:#16130e;--panel2:#1b1712;--line:#3a2f1e;--brass:#c8a24b;--brass-hi:#e9cf8a;--cream:#efe6d0;--dim:#9c8f74;--oxblood:#5a1414;--ok:#5fa06b;--warn:#d9a441;--fail:#d8503a}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}
body{margin:0;background:var(--ink);color:var(--cream);font-family:"Iowan Old Style",Palatino,Georgia,serif;padding:0 0 40px}
header{border-bottom:2px solid var(--brass);background:var(--panel2);padding:18px 16px calc(14px + env(safe-area-inset-top));text-align:center}
.item{font-size:10px;letter-spacing:2px;color:var(--dim);text-transform:uppercase}
h1{margin:4px 0 2px;font-size:30px;letter-spacing:5px;text-transform:uppercase;color:var(--brass-hi)}
.sub{color:var(--dim);font-style:italic;font-size:13px}
.wrap{padding:16px}
.card{border:1px solid var(--line);background:var(--panel);padding:12px 14px;margin:10px 0}
.card h2{margin:0 0 8px;font-size:12px;letter-spacing:2px;text-transform:uppercase;color:var(--brass)}
.row{display:flex;justify-content:space-between;align-items:center;padding:5px 0;font-size:15px}
.row .v{font-family:"Courier New",monospace}
.pill{font-family:"Courier New",monospace;font-size:12px;padding:2px 8px;border:1px solid}
.on{color:var(--ok);border-color:var(--ok)} .off{color:var(--warn);border-color:var(--warn)}
button{width:100%;margin:8px 0;padding:15px;font-family:inherit;font-size:15px;letter-spacing:1px;text-transform:uppercase;
  color:var(--cream);background:#241c12;border:1px solid var(--brass);border-radius:2px}
button:active{transform:translateY(1px)}
button.gold{background:#5f4a1a}
button.danger{background:var(--oxblood);border-color:#a33}
.thr{display:flex;gap:8px;align-items:center;margin:8px 0}
.thr input{flex:1;background:#0a0908;border:1px solid var(--line);color:var(--cream);padding:12px;font-family:"Courier New",monospace;font-size:16px}
.thr button{width:auto;margin:0;padding:12px 16px}
pre{background:#0a0908;border:1px solid var(--line);padding:10px;overflow:auto;font-family:"Courier New",monospace;font-size:11px;color:#cdbf9c;white-space:pre-wrap;max-height:44vh}
.msg{color:var(--brass-hi);font-size:13px;min-height:18px;text-align:center;margin:6px 0}
.foot{color:var(--dim);font-size:10px;text-align:center;margin-top:20px;letter-spacing:1px}
</style></head><body>
<header>
  <div class="item">Item № ML-3143 · Object Class: Safe (reversible)</div>
  <h1>Murphy Lawden</h1>
  <div class="sub">the fixer — on your phone</div>
</header>
<div class="wrap">
  <div class="msg" id="msg">reading module state…</div>

  <div class="card"><h2>BFU sentinel</h2>
    <div class="row"><span>watcher</span><span class="pill" id="bfuRun">…</span></div>
    <div class="row"><span>auto-reboot</span><span class="pill" id="bfuEn">…</span></div>
    <div class="row"><span>seal after</span><span class="v" id="bfuThr">…</span></div>
  </div>

  <div class="card"><h2>Boot hardening</h2>
    <div class="row"><span>sysctls applied</span><span class="v" id="hard">…</span></div>
    <div class="row"><span>last posture</span><span class="v" id="score">—</span></div>
  </div>

  <div class="card"><h2>Controls</h2>
    <button class="gold" onclick="scan()">Run posture scan</button>
    <button onclick="toggleBFU()" id="btnEn">Toggle auto-reboot</button>
    <div class="thr">
      <input id="thrIn" type="number" min="1" max="72" step="1" placeholder="hours">
      <button onclick="setThr()">Set</button>
    </div>
    <button onclick="showLog('bfu')">View BFU log</button>
    <button onclick="showLog('boot')">View boot log</button>
    <button class="danger" onclick="sealNow()">Seal to BFU now (reboot)</button>
  </div>
  <pre id="log" hidden></pre>
  <div class="foot">systemless · reversible · disable the module to undo everything</div>
</div>
<script>
const MOD="/data/adb/modules/murphy-hardening", ST="/data/adb/murphy", CONF=MOD+"/bfu.conf";
function sh(cmd){
  return new Promise(res=>{
    if(!(window.ksu&&ksu.exec)) return res({errno:1,stdout:"",stderr:"no root WebUI API"});
    const id="cb"+Math.random().toString(36).slice(2);
    window[id]=(e,o,s)=>{delete window[id];res({errno:+e,stdout:o||"",stderr:s||""});};
    try{ksu.exec(cmd,JSON.stringify({}),id);}catch(err){res({errno:1,stdout:"",stderr:String(err)});}
  });
}
const $=s=>document.querySelector(s);
function msg(m){$("#msg").textContent=m;}
async function refresh(){
  const conf=(await sh("cat "+CONF+" 2>/dev/null")).stdout;
  const en=/ENABLED=1/.test(conf), thr=(conf.match(/THRESHOLD_H=(\d+)/)||[,"6"])[1];
  const run=(await sh("pgrep -f bfu-autoreboot.sh | head -1")).stdout.trim();
  $("#bfuRun").textContent=run?"running":"stopped"; $("#bfuRun").className="pill "+(run?"on":"off");
  $("#bfuEn").textContent=en?"on":"off"; $("#bfuEn").className="pill "+(en?"on":"off");
  $("#bfuThr").textContent=thr+" h screen-off"; $("#thrIn").value=thr;
  $("#btnEn").textContent=en?"Disable auto-reboot":"Enable auto-reboot";
  const hard=(await sh("grep -c ' set ' "+ST+"/boot.log 2>/dev/null")).stdout.trim()||"0";
  $("#hard").textContent=hard+" this boot";
  const sc=(await sh("grep -oE '\"(score|grade)\":[^,}]*' "+ST+"/last-scan.json 2>/dev/null")).stdout.trim();
  $("#score").textContent=sc?sc.replace(/\n/g," · ").replace(/\"/g,""):"no scan yet";
  msg("ready");
}
async function toggleBFU(){
  const conf=(await sh("cat "+CONF)).stdout, en=/ENABLED=1/.test(conf);
  await sh("sed -i 's/^ENABLED=.*/ENABLED="+(en?0:1)+"/' "+CONF);
  msg("auto-reboot "+(en?"disabled":"enabled")+" — applies next boot"); refresh();
}
async function setThr(){
  const h=parseInt($("#thrIn").value||"6"); if(h<1)return;
  await sh("sed -i 's/^THRESHOLD_H=.*/THRESHOLD_H="+h+"/' "+CONF);
  msg("seal window → "+h+"h (applies next boot)"); refresh();
}
async function scan(){
  msg("scanning… (needs python; may take a moment)");
  const r=await sh('PY=$(command -v python3||command -v python||echo /data/data/com.termux/files/usr/bin/python); [ -x "$PY" ]&&"$PY" '+MOD+'/murphy/murphy.py scan --json --no-banner --no-prompt >'+ST+'/last-scan.json 2>/dev/null&&echo ok||echo nopy');
  msg(r.stdout.includes("ok")?"scan complete":"no python interpreter found (install Termux+python)"); refresh();
}
async function showLog(which){
  const f=which==="bfu"?ST+"/bfu.log":ST+"/boot.log";
  const r=await sh("tail -n 40 "+f+" 2>/dev/null");
  const pre=$("#log"); pre.hidden=false; pre.textContent=r.stdout||"(empty)"; pre.scrollIntoView({behavior:"smooth"});
}
async function sealNow(){
  if(!confirm("Reboot now to seal the device to Before-First-Unlock? Your FBE keys get evicted from RAM."))return;
  msg("sealing… rebooting"); await sh("sync; reboot");
}
refresh();
</script></body></html>
"""

# Magisk action button (Magisk 27+ / KernelSU): a safe status readout, not a wipe.
_ACTION_SH = """\
#!/system/bin/sh
STATE=/data/adb/murphy
echo "════ MURPHY LAWDEN — status ════"
echo "· BFU watcher:"; tail -n 3 "$STATE/bfu.log" 2>/dev/null || echo "  (no BFU log yet)"
echo "· last boot hardening:"; tail -n 6 "$STATE/boot.log" 2>/dev/null || echo "  (no boot log yet)"
if [ -f "$STATE/last-scan.json" ]; then
  echo "· last posture scan:"
  grep -oE '"(score|grade)":[^,}]*' "$STATE/last-scan.json" 2>/dev/null | head -2 | sed 's/^/    /'
fi
echo "· seal NOW (BFU): su -c reboot   ·   config: $(dirname "$0")/bfu.conf"
"""


def _add_tree(zf: zipfile.ZipFile, src: Path, arc_prefix: str) -> None:
    for p in sorted(src.rglob("*")):
        if p.is_dir() or "__pycache__" in p.parts or p.suffix == ".pyc":
            continue
        zf.write(p, f"{arc_prefix}/{p.relative_to(src).as_posix()}")


def build(out_path: str | Path) -> Path:
    """Write a flashable Magisk module zip. Returns the path written."""
    out = Path(out_path)
    if out.is_dir():
        out = out / f"{MODULE_ID}.zip"
    pkg_dir = Path(__file__).resolve().parent          # murphy_lawden/
    repo = pkg_dir.parent                               # repo root
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("META-INF/com/google/android/update-binary", _UPDATE_BINARY)
        zf.writestr("META-INF/com/google/android/updater-script", _UPDATER_SCRIPT)
        zf.writestr("module.prop", _module_prop())
        zf.writestr("customize.sh", _CUSTOMIZE_SH)
        zf.writestr("service.sh", _SERVICE_SH)
        zf.writestr("bfu-autoreboot.sh", _BFU_SH)   # GrapheneOS-style BFU sentinel
        zf.writestr("bfu.conf", _BFU_CONF)
        zf.writestr("action.sh", _ACTION_SH)        # Magisk action button (fallback)
        _webroot = repo / "webroot" / "index.html"       # hand-authored design, if present
        zf.writestr("webroot/index.html",
                    _webroot.read_text(encoding="utf-8") if _webroot.is_file() else _WEBUI_HTML)
        # Bundle Murphy so the optional boot scan works where python exists.
        zf.write(repo / "murphy.py", "murphy/murphy.py")
        _add_tree(zf, pkg_dir, "murphy/murphy_lawden")
        packs = repo / "packs"
        if packs.is_dir():
            _add_tree(zf, packs, "murphy/packs")
    return out
