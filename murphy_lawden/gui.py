"""``murphy gui`` — the parlour. A local, dependency-free manager for Murphy.

LSPosed did a whole app; Murphy does a whole *case room*. This serves a small
art-deco / film-noir manager on 127.0.0.1 — the tool's report, the fixer, the
sentinel, and the Magisk-module press, behind real buttons wired to the real
engine. It is stdlib only (``http.server``), binds to loopback, and gates every
state-changing call behind a per-session token so nothing on the machine can
poke it but the page Murphy served you.

Theme is a wink at SCP-3143 — *Murphy Law, Ne Quinta Decima* — the showman who
turns a disaster into an act. Item plate, brass, and all.
"""
from __future__ import annotations

import json
import os
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .banner import make_ink

_TOKEN = secrets.token_urlsafe(24)


# --------------------------------------------------------------------------- #
#  Engine glue — reuse the exact CLI pipeline so the GUI can't drift from it
# --------------------------------------------------------------------------- #
def _scan_payload() -> dict:
    from types import SimpleNamespace
    from .core import detect_host
    from .cli import assemble_findings, to_json
    host = detect_host()
    args = SimpleNamespace(pack=[], only=None, via="direct")
    findings = assemble_findings(host, args, online=False, ink=make_ink(False))
    data = json.loads(to_json(host, findings))
    from .cli import is_malware_finding
    for d, f in zip(data["findings"], findings):
        d["malware"] = is_malware_finding(f)
        d["remediable"] = bool(f.status.name == "FAIL" and f.remedy is not None)
        d["risk"] = getattr(f.remedy, "risk", None) if f.remedy else None
    counts = {k: 0 for k in ("FAIL", "WARN", "PASS", "INFO", "SKIP")}
    for d in data["findings"]:
        counts[d["status"]] = counts.get(d["status"], 0) + 1
    data["counts"] = counts
    data["is_root"] = hasattr(os, "geteuid") and os.geteuid() == 0
    return data


def _fix_payload(risk: str, dry_run: bool) -> dict:
    from types import SimpleNamespace
    from .core import detect_host, Status
    from .cli import assemble_findings
    from .remedy import Fixer
    host = detect_host()
    args = SimpleNamespace(pack=[], only=None, via="direct")
    findings = assemble_findings(host, args, online=False, ink=make_ink(False))
    remediable = [f for f in findings
                  if f.status == Status.FAIL and f.remedy is not None
                  and f.remedy.within(risk)]
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    fixer = Fixer(dry_run=dry_run)
    results = []
    for f in remediable:
        needs_root = getattr(f.remedy, "requires_root", True)
        if not dry_run and needs_root and not is_root:
            results.append({"title": f.title, "risk": f.remedy.risk,
                            "applied": False, "messages": ["needs root — start the GUI with sudo to apply"]})
            continue
        try:
            res = fixer.apply(f)
            results.append({"title": f.title, "risk": f.remedy.risk,
                            "applied": res.applied, "messages": res.messages})
        except OSError as e:
            results.append({"title": f.title, "risk": f.remedy.risk,
                            "applied": False, "messages": [f"refused: {e}"]})
    return {"dry_run": dry_run, "risk": risk, "is_root": is_root,
            "count": len(remediable), "results": results}


def _undo_payload() -> dict:
    from .remedy import undo_latest
    ok, msg = undo_latest()
    return {"ok": ok, "message": msg}


def _module_payload(out: str | None) -> dict:
    from . import magiskmod
    path = magiskmod.build(out or os.path.expanduser("~/murphy-hardening.zip"))
    return {"ok": True, "path": str(path)}


def _watch_payload() -> dict:
    from .watch import _collect, _snapshot
    _, findings = _collect()
    return _snapshot(findings)


def _overview_payload() -> dict:
    """The Narrative Overview — memory, daemons, processes, thermals — straight
    from the same collector the terminal uses, so the two can't drift."""
    from .overview import collect
    return collect()


def _collapse_payload(door: str) -> dict:
    """A collapse door, rendered as a PLAN only. Firing a door is deliberately not
    reachable from the browser: the destructive tiers demand a typed consent phrase
    read off a real TTY, so the GUI shows the plan and hands you the exact command
    to run in a terminal. Reuses the CLI engine — no second implementation to drift."""
    import contextlib
    import io
    from types import SimpleNamespace
    from .collapse import run_collapse
    args = SimpleNamespace(door=door, execute=False, thaw=False, restore=False,
                           wipe_data=False, manifest_dir=None)
    buf = io.StringIO()
    # Strip ANSI — the browser gets clean text and styles it itself.
    with contextlib.redirect_stdout(buf):
        run_collapse(args, make_ink(False))
    return {"door": door or "briefing", "plan": buf.getvalue(),
            "command": (f"murphy collapse --door {door} --execute" if door else "murphy collapse")}


# --------------------------------------------------------------------------- #
#  HTTP handler
# --------------------------------------------------------------------------- #
class _Handler(BaseHTTPRequestHandler):
    server_version = "MurphyGUI/" + __version__

    def log_message(self, *a):  # keep the terminal quiet
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

    def _authed(self) -> bool:
        return self.headers.get("X-Murphy-Token") == _TOKEN

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, _PAGE.replace("__TOKEN__", _TOKEN).encode("utf-8"),
                       "text/html; charset=utf-8")
        elif self.path == "/api/scan":
            try:
                self._json(_scan_payload())
            except Exception as e:
                self._json({"error": str(e)}, 500)
        elif self.path == "/api/watch":
            try:
                self._json(_watch_payload())
            except Exception as e:
                self._json({"error": str(e)}, 500)
        elif self.path == "/api/overview":
            try:
                self._json(_overview_payload())
            except Exception as e:
                self._json({"error": str(e)}, 500)
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        if not self._authed():
            self._json({"error": "bad or missing session token"}, 403)
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except ValueError:
            body = {}
        try:
            if self.path == "/api/fix":
                self._json(_fix_payload(body.get("risk", "low"), bool(body.get("dry_run", True))))
            elif self.path == "/api/undo":
                self._json(_undo_payload())
            elif self.path == "/api/module":
                self._json(_module_payload(body.get("out")))
            elif self.path == "/api/collapse":
                self._json(_collapse_payload(body.get("door")))
            else:
                self._json({"error": "unknown action"}, 404)
        except Exception as e:
            self._json({"error": str(e)}, 500)


def serve(port: int = 8787, open_browser: bool = True, ink=None) -> int:
    ink = ink or make_ink(None)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    url = f"http://127.0.0.1:{port}/"
    print(ink.green(f"  Murphy's parlour is open at ") + ink.cyan(url))
    print(ink.dim("  loopback only · session-token gated · Ctrl-C to close up shop"))
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print(ink.dim("  (running unprivileged — the Fixer can still plan every job and "
                      "apply the ones in your own space; start with sudo to apply root fixes)"))
    if open_browser:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(ink.dim("\n  Murphy dims the lights. Case closed for now."))
    finally:
        httpd.server_close()
    return 0


# --------------------------------------------------------------------------- #
#  The page — flat film-noir / cosmic-bleak, one self-contained file, no deps,
#  no gradients. Motion is kept: a title flicker, a sweeping sentinel bar, the
#  blink spinner, meter fills, button lift.
# --------------------------------------------------------------------------- #
_PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Murphy Lawden — Case Room</title>
<style>
:root{
  --ink:#0b0a09; --panel:#141210; --panel2:#1c1815; --panel3:#232019; --line:#3a3128;
  --brass:#c8a24b; --brass-hi:#e9cf8a; --cream:#efe6d0; --dim:#9c8f74;
  --oxblood:#611414; --oxblood-hi:#7f1d1d; --teal:#2f6d69;
  --fail:#d8503a; --warn:#d9a441; --pass:#5fa06b; --skip:#7b7263; --info:#7d8fa0;
}
*{box-sizing:border-box}
html,body{margin:0}
/* Flat ground — no gradient. Stark black is the cosmic-bleak we want. */
body{
  background:var(--ink);
  color:var(--cream); font-family:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;
  letter-spacing:.2px; min-height:100vh;
}
.wrap{max-width:1080px;margin:0 auto;padding:22px 20px 60px}
/* --- letterhead --- */
header.bill{
  border:2px solid var(--brass); background:var(--panel2);
  box-shadow:0 0 0 4px var(--ink), 0 0 0 5px var(--line);
  position:relative; padding:20px 22px 16px; text-align:center; overflow:hidden;
}
/* brass corner ticks — flat bars, not a gradient */
header.bill::before,header.bill::after{
  content:"";position:absolute;top:10px;bottom:10px;width:3px;background:var(--brass);opacity:.35}
header.bill::before{left:10px} header.bill::after{right:10px}
.item{font-size:11px;letter-spacing:3px;color:var(--dim);text-transform:uppercase}
.mono{font-family:"Courier New",ui-monospace,monospace}
h1{margin:.15em 0 .05em;font-size:clamp(30px,6vw,54px);color:var(--brass-hi);
  letter-spacing:6px;text-transform:uppercase;font-weight:700;text-shadow:0 2px 0 #000;
  animation:flick 7s infinite steps(1)}
/* cosmic flicker — the sign that never quite holds */
@keyframes flick{0%,17%,19%,55%,57%,100%{opacity:1}18%,56%{opacity:.66}92%{opacity:.85}}
.sub{color:var(--dim);font-style:italic;letter-spacing:1px}
.latin{color:var(--brass);letter-spacing:5px;text-transform:uppercase;font-size:12px;margin-top:6px}
/* a single brass rule with a slow sentinel light sweeping it — motion, flat fill */
.rule{position:relative;height:2px;margin:14px 0;background:var(--line);overflow:hidden}
.rule::after{content:"";position:absolute;top:0;left:-40px;width:40px;height:2px;
  background:var(--brass);animation:sweep 5.5s linear infinite}
@keyframes sweep{0%{left:-40px}100%{left:100%}}
.chev{color:var(--brass);letter-spacing:8px;font-size:12px}
/* --- verdict plate --- */
.verdict{display:flex;gap:18px;align-items:center;justify-content:center;flex-wrap:wrap;margin-top:12px}
.seal{width:104px;height:104px;border-radius:50%;border:3px double var(--brass);
  display:grid;place-items:center;background:var(--panel);box-shadow:inset 0 0 0 2px var(--ink)}
.seal .g{font-size:44px;color:var(--brass-hi);font-weight:700}
.seal .s{font-size:11px;color:var(--dim);letter-spacing:2px}
.tally{display:flex;gap:10px;flex-wrap:wrap;justify-content:center}
.pill{border:1px solid var(--line);padding:6px 12px;background:var(--panel);font-size:13px;
  letter-spacing:1px;min-width:92px;text-align:center}
.pill b{display:block;font-size:20px}
.pill.fail b{color:var(--fail)} .pill.warn b{color:var(--warn)}
.pill.pass b{color:var(--pass)} .pill.skip b{color:var(--skip)}
/* --- action row --- */
.acts{display:flex;gap:12px;flex-wrap:wrap;justify-content:center;margin:20px 0 8px}
button.act{
  cursor:pointer;border:2px solid var(--brass);color:var(--cream);background:var(--oxblood);
  padding:12px 18px 10px;letter-spacing:2px;text-transform:uppercase;font-size:13px;
  font-family:inherit;position:relative;transition:transform .08s ease, box-shadow .2s ease, background .15s;
  box-shadow:0 3px 0 #000}
button.act small{display:block;color:var(--brass-hi);font-size:10px;letter-spacing:1px;
  text-transform:none;font-style:italic;margin-top:2px}
button.act:hover{transform:translateY(-2px);background:var(--oxblood-hi);box-shadow:0 5px 0 #000}
button.act:active{transform:translateY(1px);box-shadow:0 1px 0 #000}
button.act.ghost{background:var(--panel2);border-color:var(--line)}
button.act.ghost:hover{background:var(--panel3)}
button.act.gold{background:var(--panel3);border-color:var(--brass)}
button.act.gold:hover{background:#2c281f}
button.act[disabled]{opacity:.45;cursor:not-allowed}
.controls{display:flex;gap:14px;align-items:center;justify-content:center;flex-wrap:wrap;
  color:var(--dim);font-size:12px;margin-top:6px}
select,label.tog{background:var(--panel);color:var(--cream);border:1px solid var(--line);
  padding:6px 10px;font-family:inherit;letter-spacing:1px}
label.tog{cursor:pointer;user-select:none}
/* --- tabs --- */
.tabs{display:flex;gap:2px;margin-top:22px;border-bottom:2px solid var(--brass);flex-wrap:wrap}
.tab{padding:9px 16px;cursor:pointer;color:var(--dim);letter-spacing:2px;text-transform:uppercase;
  font-size:12px;border:1px solid transparent;border-bottom:none;background:var(--panel);
  transition:color .15s, background .15s}
.tab:hover{color:var(--cream)}
.tab.on{color:var(--brass-hi);background:var(--panel2);border-color:var(--line)}
.tab.danger.on{color:var(--fail)}
.view{display:none;padding:16px 2px;animation:fade .35s ease} .view.on{display:block}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}
/* --- findings --- */
.grouphdr{color:var(--brass);letter-spacing:3px;text-transform:uppercase;font-size:12px;
  margin:18px 0 8px;border-bottom:1px dashed var(--line);padding-bottom:5px}
.card{border:1px solid var(--line);background:var(--panel2);padding:11px 13px;margin:8px 0;position:relative}
.card .top{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.tag{font-family:"Courier New",monospace;font-size:11px;padding:2px 7px;border:1px solid;letter-spacing:1px}
.tag.FAIL{color:var(--fail);border-color:var(--fail)} .tag.WARN{color:var(--warn);border-color:var(--warn)}
.tag.PASS{color:var(--pass);border-color:var(--pass)} .tag.SKIP{color:var(--skip);border-color:var(--skip)}
.tag.INFO{color:var(--info);border-color:var(--info)}
.sev{font-size:10px;color:var(--dim);letter-spacing:2px}
.ttl{color:var(--cream);font-size:15px} .mal{color:var(--brass-hi)}
.det{color:var(--dim);font-size:13px;margin-top:5px} .why{color:#b9ac90;font-size:12.5px;margin-top:3px;font-style:italic}
.fix{color:var(--teal);font-size:12.5px;margin-top:3px}
/* --- overview panels --- */
.subtabs{display:flex;gap:2px;margin:6px 0 14px;flex-wrap:wrap}
.subtab{padding:7px 14px;cursor:pointer;color:var(--dim);letter-spacing:1px;font-size:12px;
  border:1px solid var(--line);background:var(--panel);transition:color .15s,background .15s}
.subtab.on{color:var(--brass-hi);background:var(--panel2)}
.subview{display:none} .subview.on{display:block;animation:fade .3s ease}
.story{color:var(--cream);font-size:15px;line-height:1.5;margin:2px 0 16px;border-left:2px solid var(--brass);padding-left:12px}
.meter{margin:10px 0}
.meter .lab{display:flex;justify-content:space-between;font-size:12px;color:var(--dim);margin-bottom:4px}
.track{height:16px;border:1px solid var(--line);background:var(--panel);position:relative;overflow:hidden}
.bar{height:100%;width:0;background:var(--teal);transition:width .7s cubic-bezier(.2,.7,.2,1)}
.bar.warm{background:var(--warn)} .bar.hot{background:var(--fail)}
table.grid{width:100%;border-collapse:collapse;font-size:13px;margin-top:6px}
table.grid td,table.grid th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left}
table.grid th{color:var(--brass);font-weight:400;letter-spacing:1px;text-transform:uppercase;font-size:11px}
table.grid td.num{text-align:right;font-family:"Courier New",monospace;color:var(--cream)}
.chip{display:inline-block;font-size:10px;color:var(--warn);border:1px solid var(--warn);padding:0 5px;margin-left:6px}
.temp{font-family:"Courier New",monospace} .temp.warm{color:var(--warn)} .temp.hot{color:var(--fail)} .temp.cool{color:var(--pass)}
/* --- collapse (last resort) --- */
.deadhdr{border:2px solid var(--oxblood-hi);background:var(--panel2);padding:14px 16px;margin-bottom:16px}
.deadhdr h2{margin:0 0 4px;color:var(--fail);letter-spacing:3px;text-transform:uppercase;font-size:16px}
.deadhdr p{margin:0;color:var(--dim);font-size:13px;line-height:1.5}
.doors{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}
.door{border:1px solid var(--line);background:var(--panel2);padding:14px;cursor:pointer;
  transition:border-color .15s,transform .08s}
.door:hover{border-color:var(--brass);transform:translateY(-2px)}
.door.sel{border-color:var(--fail)}
.door .n{font-size:11px;color:var(--dim);letter-spacing:2px}
.door h3{margin:4px 0 6px;color:var(--brass-hi);font-size:17px;letter-spacing:1px}
.door p{margin:0;color:var(--dim);font-size:12.5px;line-height:1.5}
.door .rev{margin-top:8px;font-size:11px;letter-spacing:1px}
.door .rev.ok{color:var(--pass)} .door .rev.no{color:var(--fail)}
/* --- log / results --- */
pre.log{background:#080706;border:1px solid var(--line);padding:12px;overflow:auto;
  font-family:"Courier New",monospace;font-size:12.5px;color:#cdbf9c;white-space:pre-wrap;max-height:52vh}
.cmd{background:#080706;border:1px solid var(--brass);padding:10px 12px;margin-top:12px;
  font-family:"Courier New",monospace;font-size:13px;color:var(--brass-hi);white-space:pre-wrap}
.note{color:var(--dim);font-size:12.5px;font-style:italic;margin:8px 0}
.dossier p{color:#c8bb9e;line-height:1.6} .dossier b{color:var(--brass-hi)}
.foot{color:var(--dim);font-size:11px;text-align:center;margin-top:26px;letter-spacing:1px}
.spin{display:inline-block;color:var(--brass);animation:bl 1s steps(2) infinite}
@keyframes bl{50%{opacity:.2}}
</style></head>
<body><div class="wrap">

<header class="bill">
  <div class="item">Item&nbsp;№&nbsp;ML-3143 &nbsp;·&nbsp; Object Class: <span class="mono">Safe (reversible)</span></div>
  <div class="chev">◄ ◆ ►</div>
  <h1>Murphy&nbsp;Lawden</h1>
  <div class="sub">the fixer you call when everything that could’ve gone wrong, went wrong</div>
  <div class="latin">— Ne Quinta Decima —</div>
  <div class="rule"></div>
  <div class="verdict" id="verdict">
    <div class="seal"><div><div class="g" id="grade">—</div><div class="s" id="score">no case yet</div></div></div>
    <div class="tally" id="tally"></div>
  </div>
  <div class="acts">
    <button class="act gold" onclick="scan()"><span>Open the Case</span><small>read-only audit</small></button>
    <button class="act" id="btnfix" onclick="fix()"><span>Call the Fixer</span><small>plan &amp; apply remedies</small></button>
    <button class="act ghost" onclick="undo()"><span>Turn Back the Clock</span><small>undo the last job</small></button>
    <button class="act ghost" onclick="lookout()"><span>Post the Lookout</span><small>posture snapshot</small></button>
    <button class="act ghost" onclick="press()"><span>Press the Reel</span><small>build Magisk module</small></button>
  </div>
  <div class="controls">
    <span>risk budget</span>
    <select id="risk"><option value="low">low</option><option value="medium">medium</option><option value="high">high</option></select>
    <label class="tog"><input type="checkbox" id="dry" checked> dry-run (plan only, touch nothing)</label>
    <span id="whoami"></span>
  </div>
</header>

<div class="tabs">
  <div class="tab on" data-v="case" onclick="tab('case')">Case File</div>
  <div class="tab" data-v="overview" onclick="tab('overview');loadOverview()">Overview</div>
  <div class="tab" data-v="fixer" onclick="tab('fixer')">The Fixer</div>
  <div class="tab" data-v="press" onclick="tab('press')">The Press</div>
  <div class="tab danger" data-v="collapse" onclick="tab('collapse')">Collapse</div>
  <div class="tab" data-v="dossier" onclick="tab('dossier')">Dossier</div>
</div>

<div class="view on" id="v-case">
  <div class="note" id="casenote">Press <b>Open the Case</b> — Murphy profiles the host, works every read-only check, and files the report. Nothing is written on a scan.</div>
  <div id="report"></div>
</div>

<div class="view" id="v-overview">
  <div class="note">The <b>Narrative Overview</b> — what the machine is doing right now, in plain language. Read-only, refreshes on demand.</div>
  <div class="subtabs">
    <div class="subtab on" data-s="mem" onclick="sub('mem')">Memory</div>
    <div class="subtab" data-s="daemons" onclick="sub('daemons')">Daemons</div>
    <div class="subtab" data-s="procs" onclick="sub('procs')">Processes</div>
    <div class="subtab" data-s="temps" onclick="sub('temps')">Thermals</div>
    <div class="subtab" style="border-color:var(--brass)" onclick="loadOverview()">↻ refresh</div>
  </div>
  <div class="subview on" id="s-mem"></div>
  <div class="subview" id="s-daemons"></div>
  <div class="subview" id="s-procs"></div>
  <div class="subview" id="s-temps"></div>
</div>

<div class="view" id="v-fixer">
  <div class="note">The Fixer runs remedies at or below the chosen <b>risk budget</b>. Leave <b>dry-run</b> on to see the exact plan; every real change is backed up and reversible with <i>Turn Back the Clock</i>.</div>
  <pre class="log" id="fixlog">— no job run yet —</pre>
</div>
<div class="view" id="v-press">
  <div class="note">The press cuts a <b>systemless Magisk module</b> (<span class="mono">murphy-hardening.zip</span>) — vetted kernel hardening applied at boot, reversible by toggling the module. Flash it from the Magisk app.</div>
  <pre class="log" id="presslog">— reel not cut yet —</pre>
</div>

<div class="view" id="v-collapse">
  <div class="deadhdr">
    <h2>Narrative Collapse · the last page</h2>
    <p>For when the box is no longer yours to trust. Four doors, escalating. The browser shows you the <b>plan only</b> — firing a door needs a typed consent phrase at a real terminal, on purpose. Pick a door to read exactly what it would do.</p>
  </div>
  <div class="doors" id="doors"></div>
  <div id="collapseout"></div>
</div>

<div class="view dossier" id="v-dossier">
  <p><b>Subject.</b> Murphy Lawden — itinerant fixer, defensive-hardening &amp; antivirus toolkit. Reads by default; acts only when you say the word, and always leaves a way back.</p>
  <p><b>Aliases.</b> Filed alongside <b>Item ML-3143</b>, <i>“Murphy Law, Ne Quinta Decima”</i> — the showman who turns the worst night of your life into the best seat in the house. Amnesiac to the bone: a scan writes nothing, and the tool sweeps its own runtime traces as it exits.</p>
  <p><b>Method.</b> Profile the host → work the checks + the vetted pack library → file a graded verdict → offer the operating modes. The Overview keeps you oriented; the Press cuts the module; Collapse is the door you hope never to open. All of it, no dependencies, on loopback.</p>
</div>

<div class="foot">
  MURPHY LAWDEN v__VER__ · a scan leaves no trace · served on 127.0.0.1, for your eyes only<br>
  <a href="https://github.com/paladiga484" target="_blank" rel="noopener" style="color:var(--brass)">GitHub @paladiga484</a>
  &nbsp;·&nbsp;
  <a href="https://www.tiktok.com/@trafalger.tar.gz" target="_blank" rel="noopener" style="color:var(--brass)">TikTok @trafalger.tar.gz</a>
  &nbsp;·&nbsp; <span style="color:var(--dim)">offline-first · no telemetry · see PRIVACY.md &amp; TERMS.md</span>
</div>
</div>

<script>
const TOKEN="__TOKEN__";
const $=s=>document.querySelector(s);
function tab(v){document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on',t.dataset.v===v));
  document.querySelectorAll('.view').forEach(x=>x.classList.remove('on'));$('#v-'+v).classList.add('on');}
function sub(s){document.querySelectorAll('.subtab').forEach(t=>t.classList.toggle('on',t.dataset&&t.dataset.s===s));
  document.querySelectorAll('.subview').forEach(x=>x.classList.remove('on'));$('#s-'+s).classList.add('on');}
async function api(path,opts){const o=opts||{};o.headers=Object.assign({'X-Murphy-Token':TOKEN,'Content-Type':'application/json'},o.headers||{});
  const r=await fetch(path,o);return r.json();}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
const ORDER=['FAIL','WARN','INFO','SKIP','PASS'];
const GHEAD={FAIL:'Findings — what went wrong',WARN:'Worth a look',INFO:'Notes',SKIP:'Undetermined',PASS:'Holding up'};

async function scan(){
  $('#casenote').innerHTML='<span class="spin">▮</span> Murphy is working the scene…';
  $('#report').innerHTML='';
  let d;try{d=await api('/api/scan');}catch(e){$('#casenote').textContent='scan failed: '+e;return;}
  if(d.error){$('#casenote').textContent='scan failed: '+d.error;return;}
  $('#grade').textContent=d.grade;$('#score').textContent=d.score+' / 100';
  $('#whoami').textContent=(d.is_root?'· access: root':'· access: unprivileged');
  const c=d.counts;$('#tally').innerHTML=
    `<div class="pill fail"><b>${c.FAIL}</b>failed</div><div class="pill warn"><b>${c.WARN}</b>watch</div>`+
    `<div class="pill pass"><b>${c.PASS}</b>holding</div><div class="pill skip"><b>${c.SKIP}</b>n/d</div>`;
  const h=d.host;
  $('#casenote').innerHTML=`Subject <b>${esc(h.hostname||'?')}</b> — ${esc(h.pretty)} · ${esc(h.family)}/${esc(h.init)}/${esc(h.libc)} · pkg ${esc(h.pkg)}${h.env?(' · '+esc(h.env)):''}`;
  const by={};d.findings.forEach(f=>{(by[f.status]=by[f.status]||[]).push(f);});
  let html='';
  ORDER.forEach(st=>{const arr=by[st];if(!arr||!arr.length)return;
    if(st==='PASS'&&arr.length>14){html+=`<div class="grouphdr">${GHEAD[st]} (${arr.length})</div>`;return;}
    html+=`<div class="grouphdr">${GHEAD[st]} (${arr.length})</div>`;
    arr.forEach(f=>{html+=card(f);});});
  $('#report').innerHTML=html;
}
function card(f){
  return `<div class="card"><div class="top"><span class="tag ${f.status}">${f.status}</span>`+
    `<span class="sev">${f.severity}</span><span class="ttl ${f.malware?'mal':''}">${f.malware?'☰ ':''}${esc(f.title)}</span></div>`+
    (f.detail?`<div class="det">${esc(f.detail)}</div>`:'')+
    (f.status==='FAIL'&&f.rationale?`<div class="why">${esc(f.rationale)}</div>`:'')+
    (f.status==='FAIL'&&f.fix?`<div class="fix">▸ ${esc(f.fix)}</div>`:'')+`</div>`;
}
async function fix(){
  tab('fixer');const dry=$('#dry').checked,risk=$('#risk').value;
  $('#fixlog').textContent=(dry?'Planning':'Applying')+' '+risk+'-budget remedies…';
  let d;try{d=await api('/api/fix',{method:'POST',body:JSON.stringify({risk,dry_run:dry})});}
  catch(e){$('#fixlog').textContent='fix failed: '+e;return;}
  if(d.error){$('#fixlog').textContent='fix failed: '+d.error;return;}
  let out=`— ${d.dry_run?'DRY-RUN (nothing changed)':'APPLIED'} · risk ${d.risk} · ${d.count} remedy(ies) · access ${d.is_root?'root':'user'} —\n\n`;
  if(!d.results.length)out+='Nothing to fix in this budget — clean, or the rest is manual/above budget.\n';
  d.results.forEach(r=>{out+=`● ${r.title}  [risk ${r.risk}]${r.applied?'  ✓ applied':''}\n`;
    r.messages.forEach(m=>out+='    · '+m+'\n');out+='\n';});
  if(!d.dry_run)out+='Done. Reverse the whole job anytime with “Turn Back the Clock”.\n';
  $('#fixlog').textContent=out;
}
async function undo(){
  tab('fixer');$('#fixlog').textContent='Turning back the clock…';
  const d=await api('/api/undo',{method:'POST',body:'{}'});
  $('#fixlog').textContent=(d.ok?'✓ ':'✗ ')+d.message;
}
async function lookout(){
  $('#casenote').innerHTML='<span class="spin">▮</span> Posting the lookout…';
  const s=await api('/api/watch');
  if(s.error){$('#casenote').textContent='lookout failed: '+s.error;return;}
  $('#grade').textContent=s.grade;$('#score').textContent=s.score+' / 100';
  const nf=Object.keys(s.fails||{}).length,nm=(s.mal||[]).length;
  $('#casenote').innerHTML=`Lookout posted — score <b>${s.score}/100</b> (grade ${s.grade}) · ${nf} failing · ${nm} malware indicator(s). Run <b>murphy watch</b> to keep a standing sentinel.`;
}
async function press(){
  tab('press');$('#presslog').textContent='Cutting the reel…';
  const d=await api('/api/module',{method:'POST',body:'{}'});
  if(d.error){$('#presslog').textContent='press failed: '+d.error;return;}
  $('#presslog').textContent='✓ module cut:\n  '+d.path+
    '\n\nInstall it:\n  magisk --install-module '+d.path+'\n  (or flash from the Magisk app)\n\n'+
    'Systemless & reversible — disable the module in Magisk to revert. Boot log: /data/adb/murphy/boot.log';
}

/* ---------- Narrative Overview ---------- */
function human(kb){let u=['kB','MB','GB','TB'],v=kb;for(const x of u){if(v<1024||x==='TB')return (x==='kB'?Math.round(v):v.toFixed(1))+' '+x;v/=1024;}}
function meter(label,pct,right,cls){
  return `<div class="meter"><div class="lab"><span>${label}</span><span>${right}</span></div>`+
    `<div class="track"><div class="bar ${cls||''}" style="width:${Math.min(pct,100)}%"></div></div></div>`;}
async function loadOverview(){
  ['mem','daemons','procs','temps'].forEach(k=>{if(!$('#s-'+k).innerHTML)$('#s-'+k).innerHTML='<div class="note"><span class="spin">▮</span> reading…</div>';});
  let d;try{d=await api('/api/overview');}catch(e){$('#s-mem').innerHTML='overview failed: '+e;return;}
  if(d.error){$('#s-mem').innerHTML='overview failed: '+d.error;return;}
  // Memory
  const m=d.memory;let mh=`<div class="story">${esc(m.story)}</div>`;
  mh+=meter('RAM',m.used_pct,`${m.h_used} / ${m.h_total}`,m.used_pct>85?'hot':m.used_pct>65?'warm':'');
  if(m.swap_total_kb)mh+=meter('swap',m.swap_used_pct,`${m.h_swap_used} / ${m.h_swap_total}`,m.swap_used_pct>50?'hot':'warm');
  if(m.zram&&m.zram.length){mh+='<table class="grid"><tr><th>zram</th><th>used</th><th>compression</th></tr>';
    m.zram.forEach(z=>{mh+=`<tr><td>${esc(z.name)}</td><td class="num">${human(z.used_bytes/1024)}</td><td class="num">${z.ratio}×</td></tr>`;});mh+='</table>';}
  if(m.pressure_avg10)mh+=`<div class="note">memory pressure (PSI avg10): ${esc(m.pressure_avg10)}</div>`;
  $('#s-mem').innerHTML=mh;
  // Daemons
  const dm=d.daemons;let dh=`<div class="story">${esc(dm.note)}</div><table class="grid"><tr><th>service</th><th>what it is</th></tr>`;
  (dm.running||[]).forEach(r=>{dh+=`<tr><td>${esc(r.unit)}${r.idle_hint?'<span class="chip">chatty</span>':''}</td><td style="color:var(--dim)">${esc(r.desc||'')}</td></tr>`;});
  dh+='</table>';if(dm.count>(dm.running||[]).length)dh+=`<div class="note">…and ${dm.count-(dm.running||[]).length} more running.</div>`;
  $('#s-daemons').innerHTML=dh;
  // Processes
  const p=d.processes;let ph=`<div class="story">${p.count} processes running. The heavy hitters:</div>`;
  ph+='<table class="grid"><tr><th>heaviest on RAM</th><th>pid</th><th>rss</th></tr>';
  p.by_ram.forEach(x=>{ph+=`<tr><td>${esc(x.name)}</td><td class="num">${x.pid}</td><td class="num">${esc(x.h_rss)}</td></tr>`;});ph+='</table>';
  ph+='<table class="grid" style="margin-top:14px"><tr><th>heaviest on CPU (since boot)</th><th>pid</th><th>cpu</th></tr>';
  p.by_cpu.forEach(x=>{ph+=`<tr><td>${esc(x.name)}</td><td class="num">${x.pid}</td><td class="num">${x.cpu_sec}s</td></tr>`;});ph+='</table>';
  $('#s-procs').innerHTML=ph;
  // Thermals
  const t=d.thermals;let th=`<div class="story">${esc(t.verdict)}</div>`;
  if(t.sensors&&t.sensors.length){th+='<table class="grid"><tr><th>sensor</th><th>reading</th></tr>';
    t.sensors.forEach(s=>{const cls=s.celsius>=90?'hot':s.celsius>=75?'warm':'cool';
      th+=`<tr><td style="color:var(--dim)">${esc(s.chip)} / ${esc(s.label)}</td><td class="num"><span class="temp ${cls}">${s.celsius}°C</span></td></tr>`;});th+='</table>';}
  else th+='<div class="note">no readable sensors on this host.</div>';
  $('#s-temps').innerHTML=th;
}

/* ---------- Narrative Collapse ---------- */
const DOORS=[
  {id:'reinstall',n:'DOOR 1',t:'Reinstall',rev:false,d:'Delete the OS and start clean. Writes a restore manifest, then hands the wipe to your install media — Murphy never rm’s the running system out from under itself.'},
  {id:'cleanroom',n:'DOOR 2',t:'Cleanroom',rev:false,d:'Strip to a bare, trusted TTY — no desktop, no radios, no listeners — then reset sudoers and stand up a fresh user. Good for hunting rootkits from swept ground.'},
  {id:'freeze',n:'DOOR 3',t:'Freeze',rev:true,d:'SIGSTOP every non-essential process so nothing can act, exfiltrate, or phone home while you look. Fully reversible with a thaw.'},
  {id:'sever',n:'DOOR 4',t:'Sever',rev:true,d:'Cut every trail — Wi-Fi, BLE, all radios, the network daemons, the open listeners — behind a deny-all firewall. Reversible.'},
];
function renderDoors(){$('#doors').innerHTML=DOORS.map(x=>
  `<div class="door" id="door-${x.id}" onclick="pickDoor('${x.id}')"><div class="n">${x.n}</div><h3>${x.t}</h3>`+
  `<p>${x.d}</p><div class="rev ${x.rev?'ok':'no'}">${x.rev?'◈ reversible':'✖ irreversible'}</div></div>`).join('');}
async function pickDoor(id){
  document.querySelectorAll('.door').forEach(d=>d.classList.remove('sel'));$('#door-'+id).classList.add('sel');
  $('#collapseout').innerHTML='<pre class="log"><span class="spin">▮</span> reading the plan…</pre>';
  let d;try{d=await api('/api/collapse',{method:'POST',body:JSON.stringify({door:id})});}
  catch(e){$('#collapseout').innerHTML='<pre class="log">plan failed: '+esc(''+e)+'</pre>';return;}
  if(d.error){$('#collapseout').innerHTML='<pre class="log">plan failed: '+esc(d.error)+'</pre>';return;}
  $('#collapseout').innerHTML=`<pre class="log">${esc(d.plan)}</pre>`+
    `<div class="note">This is the plan only. To actually fire it, run this in a terminal — it will ask you to type a consent phrase by hand:</div>`+
    `<div class="cmd">${esc(d.command)}</div>`;
}
renderDoors();

// File the first case automatically on open — zero clicks to a report.
window.addEventListener('DOMContentLoaded',()=>{try{scan();}catch(e){}});
</script>
</body></html>
""".replace("__VER__", __version__)
