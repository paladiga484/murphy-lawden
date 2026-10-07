"""The network side of `ds go` — find whatever VPN this machine has, on whatever OS
it is, see whether a tunnel is up, and bring one up when none is.

Nothing here is configured by hand: the tools are looked for on PATH, under
Program Files (Windows) and in /Applications (macOS); the tunnel is read from the
kernel's interface list (Linux), the adapter list (Windows) or the route a public
address would take (macOS, the BSDs).

One tunnel, not two: VPN clients each rewrite routes and DNS, and two at once break
each other. `go` uses the tunnel that is already up and starts one only when none is.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from ..core import have, run
from .qbit import vpn_interfaces

WINDOWS = sys.platform == "win32"
MAC = sys.platform == "darwin"


@dataclass(frozen=True)
class Tool:
    name: str
    clis: tuple = ()        # (executable, args that connect) — tried in order
    gui: tuple = ()         # executables that open its window (Linux/BSD)
    win_cli: str = ""       # the CLI, relative to Program Files
    win_gui: str = ""       # the window, relative to Program Files
    mac: str = ""           # the app's name in /Applications
    manual: str = ""        # no way to start it for you: what to type instead


TOOLS = (
    Tool("Mullvad", clis=(("mullvad", ("connect", "--wait")),),
         win_cli="Mullvad VPN/resources/mullvad.exe", win_gui="Mullvad VPN/Mullvad VPN.exe",
         mac="Mullvad VPN"),
    Tool("Proton VPN", clis=(("protonvpn", ("connect",)), ("protonvpn-cli", ("connect", "--fastest"))),
         gui=("protonvpn-app",), win_gui="Proton/VPN/ProtonVPN.Launcher.exe", mac="ProtonVPN"),
    Tool("IVPN", clis=(("ivpn", ("connect",)),), win_cli="IVPN Client/ivpn.exe", mac="IVPN"),
    Tool("NordVPN", clis=(("nordvpn", ("connect",)),), win_gui="NordVPN/NordVPN.exe", mac="NordVPN"),
    Tool("Windscribe", clis=(("windscribe-cli", ("connect",)),),
         win_cli="Windscribe/windscribe-cli.exe", mac="Windscribe"),
    Tool("Private Internet Access", clis=(("piactl", ("connect",)),),
         win_cli="Private Internet Access/piactl.exe", mac="Private Internet Access"),
    Tool("ExpressVPN", clis=(("expressvpnctl", ("connect",)), ("expressvpn", ("connect",))),
         mac="ExpressVPN"),
    Tool("AirVPN Eddie", gui=("eddie-ui",), win_gui="AirVPN/Eddie-UI.exe", mac="Eddie"),
    Tool("WireGuard", win_gui="WireGuard/wireguard.exe", mac="WireGuard",
         manual="wg-quick:sudo wg-quick up <your-config>"),
    Tool("OpenVPN", win_gui="OpenVPN/bin/openvpn-gui.exe",
         manual="openvpn:sudo openvpn --config <your-file.ovpn>"),
)

# how a tunnel's interface/adapter name gives away whose it is
_LABELS = (("mullvad", "Mullvad"), ("proton", "Proton VPN"), ("pvpn", "Proton VPN"),
           ("nord", "NordVPN"), ("ivpn", "IVPN"), ("windscribe", "Windscribe"),
           ("pia", "Private Internet Access"), ("private internet", "Private Internet Access"),
           ("express", "ExpressVPN"), ("eddie", "AirVPN Eddie"))
_WIN_VPN = re.compile(r"(?i)wireguard|wintun|tap-windows|tap-protonvpn|mullvad|protonvpn|nordlynx|"
                      r"openvpn|ivpn|windscribe|private internet access|expressvpn")
_TUN = re.compile(r"^(utun|tun|tap|wg|ipsec|ppp)\d+$")


@dataclass(frozen=True)
class Tunnel:
    id: str             # what the torrent client binds to
    name: str           # what a person calls it
    label: str          # whose it is


def _label(text: str) -> str:
    low = text.lower()
    return next((lab for key, lab in _LABELS if key in low), "VPN")


def _program_files(rel: str) -> str | None:
    for var in ("ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
        base = os.environ.get(var)
        if base and rel and (Path(base) / rel).is_file():
            return str(Path(base) / rel)
    return None


def how(tool: Tool) -> tuple[str, list[str]] | None:
    """How to start this tool here — ("cli", argv) connects by itself, ("gui", argv)
    opens its window, ("manual", [hint]) can only be started by you — or None if it
    isn't installed."""
    for exe, args in tool.clis:
        if have(exe):
            return "cli", [exe, *args]
    if WINDOWS:
        cli = _program_files(tool.win_cli)
        if cli:
            return "cli", [cli, *tool.clis[0][1]]
        gui = _program_files(tool.win_gui)
        return ("gui", [gui]) if gui else None
    if MAC and tool.mac and Path("/Applications", tool.mac + ".app").is_dir():
        inner = Path("/Applications", tool.mac + ".app", "Contents/Resources", tool.clis[0][0]) \
            if tool.clis else None
        if inner and inner.is_file():
            return "cli", [str(inner), *tool.clis[0][1]]
        return "gui", ["open", "-a", tool.mac]
    for exe in tool.gui:
        if have(exe):
            return "gui", [exe]
    exe, _, hint = tool.manual.partition(":")
    return ("manual", [hint]) if exe and have(exe) else None


def installed() -> list[tuple[Tool, str, list[str]]]:
    """Every VPN tool found on this machine, the ones Murphy can start by itself first."""
    found = [(t, *h) for t in TOOLS if (h := how(t))]
    return sorted(found, key=lambda f: ("cli", "gui", "manual").index(f[1]))


def _windows_tunnels() -> list[Tunnel]:
    rc, out = run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                   "Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object Name,"
                   "InterfaceDescription,InterfaceName | ConvertTo-Json -Compress"], timeout=30)
    try:
        rows = json.loads(out) if rc == 0 and out.strip() else []
    except ValueError:
        rows = []
    rows = [rows] if isinstance(rows, dict) else rows
    return [Tunnel(r.get("InterfaceName") or r["Name"], r["Name"],
                   _label(f"{r['Name']} {r.get('InterfaceDescription', '')}"))
            for r in rows if _WIN_VPN.search(f"{r.get('Name', '')} {r.get('InterfaceDescription', '')}")]


def _routed_tunnels() -> list[Tunnel]:
    """macOS and the BSDs always have idle utun/tun devices lying around, so the list
    of interfaces says nothing. The route a public address would take does."""
    m = re.search(r"interface:\s*(\S+)", run(["route", "-n", "get", "1.1.1.1"])[1])
    return [Tunnel(m.group(1), m.group(1), "VPN")] if m and _TUN.match(m.group(1)) else []


def tunnels() -> list[Tunnel]:
    """Tunnels that are actually carrying traffic."""
    if WINDOWS:
        up = _windows_tunnels()
    elif Path("/sys/class/net").is_dir():
        up = [Tunnel(i, i, _label(i)) for i in vpn_interfaces()]
    else:
        up = _routed_tunnels()
    # Mullvad keeps its interface around while it is still connecting (or blocking): ask it
    if any(t.label == "Mullvad" for t in up):
        cli = how(TOOLS[0])
        if cli and cli[0] == "cli" and \
                not run([cli[1][0], "status"])[1].lstrip().startswith("Connected"):
            up = [t for t in up if t.label != "Mullvad"]
    return up


def detach(cmd: list[str]) -> None:
    """Start a desktop program that outlives Murphy."""
    kw = {"creationflags": 0x00000008 | 0x00000200} if WINDOWS else {"start_new_session": True}
    subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, **kw)


def wait_for_tunnel(seconds: int) -> Tunnel | None:
    end = time.monotonic() + seconds
    while True:
        up = tunnels()
        if up:
            return up[0]
        if time.monotonic() >= end:
            return None
        time.sleep(1)
