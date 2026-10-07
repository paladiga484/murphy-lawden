"""`ds ipfilter` — qBittorrent never talks to address ranges that are bad for everyone.

The list is FireHOL level 1: Spamhaus DROP/EDROP (hijacked networks and criminal
hosting), the Feodo/abuse.ch botnet command servers, DShield's top attackers, and
the address space that should never appear on the internet at all. It is built to
have almost no false positives, so no ordinary peer is lost — unlike "infected IP"
lists, which are mostly home connections and would block half a swarm.

It blocks silently instead of alerting: a peer can't infect you by being a peer
(every piece is checked against the torrent's hashes), so there is nothing for you
to act on — the point is only never to hand those networks a connection.

The list is downloaded over your normal connection (through the VPN), checked for
sanity before it replaces the old one, converted to qBittorrent's .p2p format, and
refreshed weekly by a systemd user timer. qBittorrent reads it when it starts.
"""
from __future__ import annotations

import ipaddress
import os
import shlex
import urllib.request
from pathlib import Path

from ..core import have, run
from . import qbit, state

SOURCE = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
FILE = state.state_dir() / "ipfilter.p2p"
UNIT = "murphy-ds-ipfilter"
UNIT_DIR = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd/user"
K_ON = "BitTorrent/Session/IPFilteringEnabled"
K_PATH = "BitTorrent/Session/IPFilter"
K_TRACKERS = "BitTorrent/Session/TrackerFilteringEnabled"
MIN_ENTRIES = 500            # FireHOL level 1 has a few thousand; fewer means a broken download


def fetch() -> list[ipaddress.IPv4Network]:
    req = urllib.request.Request(SOURCE, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        text = r.read(8 << 20).decode("ascii", "replace")
    nets = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        nets.append(ipaddress.IPv4Network(line, strict=False))   # anything else raises: refuse the list
    if len(nets) < MIN_ENTRIES:
        raise ValueError(f"only {len(nets)} entries — looks truncated, keeping the old list")
    return nets


def update(out) -> int:
    try:
        nets = fetch()
    except (OSError, ValueError) as e:
        out("x", f"blocklist not updated: {e}")
        return 1
    lines = [f"FireHOL level1:{n.network_address}-{n.broadcast_address}" for n in nets]
    FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = FILE.with_suffix(".tmp")
    tmp.write_text("\n".join(lines) + "\n")
    os.replace(tmp, FILE)
    total = sum(n.num_addresses for n in nets)
    out("+", f"blocklist: {len(nets)} ranges ({total / 1e6:.0f} million addresses) → {FILE}")
    return 0


def _configure(enable: bool, out) -> bool:
    if qbit.running():
        if enable:
            out("!", "qBittorrent is open, so its settings can't be changed now. Either close it and "
                     "run this again, or set it by hand: Tools → Options → Connection → IP Filtering → "
                     f"tick 'Filter path' and choose {FILE}")
        else:
            out("!", "qBittorrent is open: untick Tools → Options → Connection → IP Filtering yourself")
        return False
    ini = qbit.Ini(qbit.config_path())
    led = state.load()
    for k in (K_ON, K_PATH, K_TRACKERS):
        state.remember(led, "qbit", k, ini.raw(k))
    if enable:
        ini.set(K_ON, "true")
        ini.set(K_PATH, str(FILE))
        ini.set(K_TRACKERS, "false")       # trackers come from your torrents; don't second-guess them
    else:
        ini.set(K_ON, "false")
    ini.save()
    out("+", "qBittorrent: IP filter " + ("on — takes effect next time it starts" if enable else "off"))
    return True


def _murphy_cmd() -> list[str]:
    from .autoscan import _murphy_cmd as mc
    return mc()


def install(out) -> int:
    if update(out) != 0:
        return 1
    _configure(True, out)
    if have("systemctl"):
        cmd = " ".join(shlex.quote(c) for c in _murphy_cmd())
        UNIT_DIR.mkdir(parents=True, exist_ok=True)
        (UNIT_DIR / f"{UNIT}.service").write_text(
            "[Unit]\nDescription=Murphy ds: refresh qBittorrent's blocklist\n"
            "After=network-online.target\n\n"
            f"[Service]\nType=oneshot\nExecStart={cmd} ds ipfilter --update\nNice=10\n")
        (UNIT_DIR / f"{UNIT}.timer").write_text(
            "[Unit]\nDescription=Murphy ds: refresh qBittorrent's blocklist weekly\n\n"
            "[Timer]\nOnCalendar=weekly\nPersistent=true\nRandomizedDelaySec=6h\n"
            f"Unit={UNIT}.service\n\n[Install]\nWantedBy=timers.target\n")
        ok = run(["systemctl", "--user", "daemon-reload"])[0] == 0 and \
            run(["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"])[0] == 0
        out("+" if ok else "x", "blocklist refreshes weekly (systemd user timer)")
    return 0


def uninstall(out) -> int:
    run(["systemctl", "--user", "disable", "--now", f"{UNIT}.timer"])
    for ext in ("timer", "service"):
        (UNIT_DIR / f"{UNIT}.{ext}").unlink(missing_ok=True)
    run(["systemctl", "--user", "daemon-reload"])
    _configure(False, out)
    FILE.unlink(missing_ok=True)
    out("+", "blocklist removed")
    return 0


def status() -> str:
    if not FILE.exists():
        return "not installed (`murphy ds ipfilter --install`)"
    ini = qbit.Ini(qbit.config_path())
    on = ini.get(K_ON) == "true" and ini.get(K_PATH) == str(FILE)
    n = sum(1 for _ in FILE.open())
    return f"{n} ranges" + ("" if on else " — but qBittorrent isn't using it yet")
