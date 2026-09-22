"""``murphy overview`` — the Narrative Overview.

Not an audit, not a fixer — a plain-language read of what the machine is *doing
right now*, told in four panels: **Memory**, **Daemons**, **Processes**, and
**Thermals**. Everything comes straight from ``/proc`` and ``/sys`` (plus
``systemctl`` if it's there), so it works air-gapped, needs no root, and writes
nothing.

The point is legibility. Where ``free -m`` gives you numbers, the overview gives
you the sentence: *"11 of 14 GB spoken for, and 2 GB has spilled to zram — that
spill is why frames stutter."* The GUI renders these panels as tabs; the terminal
prints them as stacked sections. Both read from the one collector below so they
can't drift apart.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from .core import have, run
from .banner import Ink, rule


# --------------------------------------------------------------------------- #
#  small helpers
# --------------------------------------------------------------------------- #
def _read(path: str) -> str:
    try:
        with open(path, "r", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def _human_kb(kb: float) -> str:
    """A kB count as a friendly size. Memory is reported in kB across /proc."""
    units = ["kB", "MB", "GB", "TB"]
    v = float(kb)
    for u in units:
        if v < 1024 or u == units[-1]:
            return f"{v:.1f} {u}" if u != "kB" else f"{v:.0f} kB"
        v /= 1024
    return f"{v:.1f} TB"


def _pct(part: float, whole: float) -> int:
    return int(round(100 * part / whole)) if whole else 0


# --------------------------------------------------------------------------- #
#  Memory
# --------------------------------------------------------------------------- #
def _meminfo() -> dict[str, int]:
    info: dict[str, int] = {}
    for line in _read("/proc/meminfo").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(":"):
            try:
                info[parts[0][:-1]] = int(parts[1])  # value is in kB
            except ValueError:
                pass
    return info


def _zram() -> list[dict]:
    """Per-zram-device stats — Murphy's own notes say zram thrash is the FPS
    killer on this box, so we surface it explicitly instead of hiding it in swap."""
    out = []
    base = Path("/sys/block")
    if not base.exists():
        return out
    for dev in sorted(base.glob("zram*")):
        disksize = _read(str(dev / "disksize")).strip()
        mm = _read(str(dev / "mm_stat")).split()
        # mm_stat: orig_data_size compr_data_size mem_used_total ...
        orig = int(mm[0]) if len(mm) > 0 and mm[0].isdigit() else 0
        used = int(mm[2]) if len(mm) > 2 and mm[2].isdigit() else 0
        out.append({
            "name": dev.name,
            "disksize": int(disksize) if disksize.isdigit() else 0,
            "orig_bytes": orig,
            "used_bytes": used,
            "ratio": round(orig / used, 2) if used else 0.0,
        })
    return out


def _mem_pressure() -> str | None:
    """PSI 'some' memory-stall average over 10s, if the kernel exposes it. A
    non-zero value means something waited on memory — the honest stutter signal."""
    txt = _read("/proc/pressure/memory")
    for line in txt.splitlines():
        if line.startswith("some"):
            for tok in line.split():
                if tok.startswith("avg10="):
                    return tok.split("=", 1)[1]
    return None


def collect_memory() -> dict:
    m = _meminfo()
    total = m.get("MemTotal", 0)
    avail = m.get("MemAvailable", m.get("MemFree", 0))
    used = max(total - avail, 0)
    swap_total = m.get("SwapTotal", 0)
    swap_free = m.get("SwapFree", 0)
    swap_used = max(swap_total - swap_free, 0)
    zram = _zram()
    pressure = _mem_pressure()

    # The one-sentence read, tuned to what actually hurts on a small-RAM box.
    story = f"{_human_kb(used)} of {_human_kb(total)} in use ({_pct(used, total)}%)."
    if swap_used > 0:
        story += f" {_human_kb(swap_used)} has spilled to swap"
        if zram:
            story += " (zram) — that spill is where stutter comes from."
        else:
            story += "."
    else:
        story += " Nothing has spilled to swap — memory is comfortable."
    if pressure and float(pressure) > 5:
        story += f" Memory pressure is high (PSI {pressure})."

    return {
        "total_kb": total, "used_kb": used, "avail_kb": avail,
        "used_pct": _pct(used, total),
        "cached_kb": m.get("Cached", 0), "buffers_kb": m.get("Buffers", 0),
        "shmem_kb": m.get("Shmem", 0),
        "swap_total_kb": swap_total, "swap_used_kb": swap_used,
        "swap_used_pct": _pct(swap_used, swap_total),
        "zram": zram, "pressure_avg10": pressure,
        "story": story,
        # pre-humanised strings so the renderers don't each re-do the math
        "h_total": _human_kb(total), "h_used": _human_kb(used),
        "h_avail": _human_kb(avail), "h_swap_used": _human_kb(swap_used),
        "h_swap_total": _human_kb(swap_total),
    }


# --------------------------------------------------------------------------- #
#  Processes
# --------------------------------------------------------------------------- #
_CLK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
_PAGE = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096


def _proc_list() -> list[dict]:
    procs = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = entry.name
        comm = _read(f"/proc/{pid}/comm").strip()
        statm = _read(f"/proc/{pid}/statm").split()
        rss_pages = int(statm[1]) if len(statm) > 1 and statm[1].isdigit() else 0
        rss_kb = rss_pages * _PAGE // 1024
        # /proc/pid/stat: utime(14) stime(15) — total CPU ticks the proc has used
        stat = _read(f"/proc/{pid}/stat")
        cpu_ticks = 0
        if ")" in stat:
            fields = stat[stat.rindex(")") + 1:].split()
            # after the comm field, index 11=utime, 12=stime (0-based on the tail)
            if len(fields) > 12:
                try:
                    cpu_ticks = int(fields[11]) + int(fields[12])
                except ValueError:
                    cpu_ticks = 0
        if comm:
            procs.append({"pid": int(pid), "name": comm,
                          "rss_kb": rss_kb, "cpu_ticks": cpu_ticks})
    return procs


def collect_processes(top: int = 12) -> dict:
    """Two short leaderboards — heaviest on RAM and heaviest on CPU since boot —
    plus the total count. Deliberately small; this is a glance, not htop."""
    procs = _proc_list()
    by_ram = sorted(procs, key=lambda p: p["rss_kb"], reverse=True)[:top]
    by_cpu = sorted(procs, key=lambda p: p["cpu_ticks"], reverse=True)[:top]
    for p in by_ram:
        p["h_rss"] = _human_kb(p["rss_kb"])
    for p in by_cpu:
        p["cpu_sec"] = round(p["cpu_ticks"] / _CLK, 1)
    return {"count": len(procs), "by_ram": by_ram, "by_cpu": by_cpu}


# --------------------------------------------------------------------------- #
#  Daemons (systemd services)
# --------------------------------------------------------------------------- #
def collect_daemons(top: int = 20) -> dict:
    """Running system services, newest-heaviest first where we can tell. Falls back
    gracefully on non-systemd inits — the panel just says so."""
    if not have("systemctl"):
        return {"init": "non-systemd", "running": [], "count": 0,
                "note": "no systemctl here — daemon panel is systemd-only for now."}
    rc, out = run(["systemctl", "list-units", "--type=service",
                   "--state=running", "--no-legend", "--no-pager", "--plain"], timeout=8)
    running = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 5 and parts[0].endswith(".service"):
            running.append({"unit": parts[0], "desc": parts[4]})
    # A rough "could probably sleep" hint — cosmetic, never an instruction to act.
    chatty = {"bluetooth", "cups", "avahi-daemon", "ModemManager", "smbd", "nmbd"}
    for r in running:
        stem = r["unit"].removesuffix(".service")
        r["idle_hint"] = stem in chatty
    running.sort(key=lambda r: (not r["idle_hint"], r["unit"]))
    return {"init": "systemd", "running": running[:top],
            "count": len(running),
            "note": f"{len(running)} services running." if running else "no running services listed."}


# --------------------------------------------------------------------------- #
#  Thermals
# --------------------------------------------------------------------------- #
def _hwmon_temps() -> list[dict]:
    out = []
    base = Path("/sys/class/hwmon")
    if not base.exists():
        return out
    for mon in sorted(base.glob("hwmon*")):
        chip = _read(str(mon / "name")).strip() or mon.name
        for inp in sorted(mon.glob("temp*_input")):
            raw = _read(str(inp)).strip()
            if not raw.lstrip("-").isdigit():
                continue
            milli = int(raw)
            label_file = str(inp).replace("_input", "_label")
            label = _read(label_file).strip() or inp.name.replace("_input", "")
            out.append({"chip": chip, "label": label, "celsius": round(milli / 1000, 1)})
    return out


def _thermal_zones() -> list[dict]:
    out = []
    base = Path("/sys/class/thermal")
    if not base.exists():
        return out
    for zone in sorted(base.glob("thermal_zone*")):
        raw = _read(str(zone / "temp")).strip()
        if raw.lstrip("-").isdigit():
            out.append({"chip": _read(str(zone / "type")).strip() or zone.name,
                        "label": zone.name, "celsius": round(int(raw) / 1000, 1)})
    return out


def collect_thermals() -> dict:
    temps = _hwmon_temps() or _thermal_zones()
    hottest = max((t["celsius"] for t in temps), default=None)
    verdict = "no sensors readable here."
    if hottest is not None:
        if hottest >= 90:
            verdict = f"hottest sensor at {hottest}°C — that's therm-throttle territory."
        elif hottest >= 75:
            verdict = f"hottest sensor at {hottest}°C — warm but within range."
        else:
            verdict = f"hottest sensor at {hottest}°C — running cool."
    return {"sensors": temps, "hottest": hottest, "verdict": verdict}


# --------------------------------------------------------------------------- #
#  The whole picture
# --------------------------------------------------------------------------- #
def collect() -> dict:
    return {
        "when": time.strftime("%Y-%m-%d %H:%M:%S"),
        "memory": collect_memory(),
        "processes": collect_processes(),
        "daemons": collect_daemons(),
        "thermals": collect_thermals(),
    }


# --------------------------------------------------------------------------- #
#  Terminal renderer — stacked "tabs" for the CLI
# --------------------------------------------------------------------------- #
def _bar(pct: int, width: int = 24) -> str:
    fill = int(round(width * pct / 100))
    return "[" + "█" * fill + "·" * (width - fill) + f"] {pct}%"


def render(ink: Ink, data: dict | None = None) -> str:
    data = data or collect()
    L: list[str] = []
    m = data["memory"]
    L.append(rule(ink, "MEMORY"))
    L.append("  " + ink.bone(m["story"]))
    L.append("  RAM  " + ink.cyan(_bar(m["used_pct"])) +
             ink.dim(f"  {m['h_used']} / {m['h_total']}"))
    if m["swap_total_kb"]:
        L.append("  swap " + ink.amber(_bar(m["swap_used_pct"])) +
                 ink.dim(f"  {m['h_swap_used']} / {m['h_swap_total']}"))
    for z in m["zram"]:
        L.append(ink.dim(f"    {z['name']}: {_human_kb(z['used_bytes']/1024)} used, "
                         f"{z['ratio']}× compression"))

    d = data["daemons"]
    L.append("")
    L.append(rule(ink, "DAEMONS"))
    L.append("  " + ink.bone(d["note"]))
    for r in d["running"][:14]:
        tag = ink.amber("· chatty") if r.get("idle_hint") else ""
        L.append(f"    {ink.cyan(r['unit']):<34} {ink.dim(r['desc'][:40])} {tag}")

    p = data["processes"]
    L.append("")
    L.append(rule(ink, f"PROCESSES ({p['count']} running)"))
    L.append(ink.dim("  heaviest on RAM:"))
    for x in p["by_ram"][:8]:
        L.append(f"    {x['h_rss']:>10}  {ink.bone(x['name'])} {ink.dim('· pid '+str(x['pid']))}")
    L.append(ink.dim("  heaviest on CPU (since boot):"))
    for x in p["by_cpu"][:6]:
        L.append(f"    {str(x['cpu_sec'])+'s':>10}  {ink.bone(x['name'])} {ink.dim('· pid '+str(x['pid']))}")

    t = data["thermals"]
    L.append("")
    L.append(rule(ink, "THERMALS"))
    L.append("  " + ink.bone(t["verdict"]))
    for s in t["sensors"][:10]:
        c = s["celsius"]
        col = ink.blood if c >= 90 else ink.amber if c >= 75 else ink.green
        L.append(f"    {col(str(c)+'°C'):>8}  {ink.dim(s['chip']+' / '+s['label'])}")
    return "\n".join(L)


def run_overview(ink: Ink) -> int:
    print(render(ink))
    return 0
