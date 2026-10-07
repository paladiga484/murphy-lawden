"""qBittorrent: audit its settings and point it at the locked folder.

The config is a Qt INI file: the key `BitTorrent/Session/TempPath` lives as
`Session\\TempPath=` under `[BitTorrent]`. We edit it line-by-line so every other
line (Qt's @ByteArray blobs included) comes back byte-identical, and only while
qBittorrent is closed — it rewrites the whole file when it exits.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from ..core import have, run
from .names import CRIT, HIGH, INFO, WARN, Hit, NEVER_LEGIT

WINDOWS = sys.platform == "win32"

K_SAVE = "BitTorrent/Session/DefaultSavePath"
K_TEMP_ON = "BitTorrent/Session/TempPathEnabled"
K_TEMP = "BitTorrent/Session/TempPath"
K_APPEND = "BitTorrent/Session/AddExtensionToIncompleteFiles"
K_ENC = "BitTorrent/Session/Encryption"
K_EXCL_ON = "BitTorrent/ExcludedFileNamesEnabled"
K_EXCL = "BitTorrent/Session/ExcludedFileNames"
K_IFACE = "BitTorrent/Session/Interface"
K_IFACE_NAME = "BitTorrent/Session/InterfaceName"
K_LSD = "BitTorrent/Session/LSDEnabled"
K_ANON = "BitTorrent/Session/AnonymousModeEnabled"
K_UPNP = "Network/PortForwardingEnabled"
K_MOTW = "Preferences/Advanced/markOfTheWeb"
K_RUN_DONE = "AutoRun/enabled"
K_RUN_DONE_PROG = "AutoRun/program"
K_RUN_ADD = "AutoRun/OnTorrentAdded/Enabled"
K_RUN_ADD_PROG = "AutoRun/OnTorrentAdded/Program"
# the Web UI keys moved between versions; read both spellings
K_WEBUI = ("WebUI/Enabled", "Preferences/WebUI/Enabled")
K_WEBUI_ADDR = ("WebUI/Address", "Preferences/WebUI/Address")
K_WEBUI_LOCALAUTH = ("WebUI/LocalHostAuth", "Preferences/WebUI/LocalHostAuth")

EXCLUDE = sorted(f"*.{e}" for e in NEVER_LEGIT)


def config_path() -> Path:
    if WINDOWS:
        return Path(os.environ.get("APPDATA") or Path.home() / "AppData/Roaming") / "qBittorrent" / "qBittorrent.ini"
    xdg = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    flat = Path.home() / ".var/app/org.qbittorrent.qBittorrent/config/qBittorrent/qBittorrent.conf"
    native = xdg / "qBittorrent" / "qBittorrent.conf"
    if sys.platform == "darwin":               # same folder as Linux, Windows' file name
        native = native.with_suffix(".ini")
    # the Flatpak (sandboxed) client wins once it has a config: that's the one in use
    return flat if flat.exists() or not native.exists() else native


FLATPAK_ID = "org.qbittorrent.qBittorrent"


def is_flatpak() -> bool:
    return not WINDOWS and "/.var/app/" in str(config_path())


def running() -> bool:
    if WINDOWS:
        rc, out = run(["tasklist", "/FI", "IMAGENAME eq qbittorrent.exe", "/NH"])
        return "qbittorrent.exe" in out.lower()
    rc, _ = run(["pgrep", "-x", "-i", "qbittorrent(-nox)?"])
    return rc == 0


def _split(key: str) -> tuple[str, str]:
    sec, _, rest = key.partition("/")
    return sec, rest.replace("/", "\\")


def _unquote(v: str) -> str:
    v = v.strip()
    return v[1:-1].replace('\\"', '"').replace("\\\\", "\\") if len(v) >= 2 and v[0] == v[-1] == '"' else v


def _quote(v: str) -> str:
    # Qt reads an unquoted comma as a list separator; quote anything with one
    if any(c in v for c in ',;="') or v != v.strip():
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return v


class Ini:
    def __init__(self, path: Path):
        self.path = path
        self.lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    def _find(self, key: str) -> tuple[int, int]:
        """(index of the section header or -1, index of the key line or -1)."""
        sec, sub = _split(key)
        in_sec, head = False, -1
        for i, line in enumerate(self.lines):
            s = line.strip()
            if s.startswith("[") and s.endswith("]"):
                in_sec = s[1:-1] == sec
                if in_sec:
                    head = i
                continue
            if in_sec and "=" in s and s.split("=", 1)[0].strip() == sub:
                return head, i
        return head, -1

    def get(self, *keys: str) -> str | None:
        for key in keys:
            _, i = self._find(key)
            if i >= 0:
                return _unquote(self.lines[i].split("=", 1)[1])
        return None

    def get_list(self, key: str) -> list[str]:
        _, i = self._find(key)
        if i < 0:
            return []
        raw = self.lines[i].split("=", 1)[1]
        return [_unquote(x) for x in re.split(r",\s*(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", raw) if x.strip()]

    def set(self, key: str, value: str | None, is_list: bool = False) -> None:
        sec, sub = _split(key)
        head, i = self._find(key)
        if value is None:
            if i >= 0:
                del self.lines[i]
            return
        line = f"{sub}={value if is_list else _quote(value)}"
        if i >= 0:
            self.lines[i] = line
        elif head >= 0:
            j = head + 1                       # after the section's last key
            while j < len(self.lines) and not self.lines[j].strip().startswith("["):
                j += 1
            while j > head + 1 and not self.lines[j - 1].strip():
                j -= 1
            self.lines.insert(j, line)
        else:
            if self.lines and self.lines[-1].strip():
                self.lines.append("")
            self.lines += [f"[{sec}]", line]

    def raw(self, key: str) -> str | None:
        _, i = self._find(key)
        return self.lines[i].split("=", 1)[1] if i >= 0 else None

    def set_raw(self, key: str, raw: str | None) -> None:
        self.set(key, raw, is_list=True)

    def drop_empty_sections(self) -> None:
        keep, i = [], 0
        while i < len(self.lines):
            s = self.lines[i].strip()
            if s.startswith("[") and s.endswith("]"):
                j = i + 1
                while j < len(self.lines) and not self.lines[j].strip().startswith("["):
                    j += 1
                if not any(l.strip() for l in self.lines[i + 1:j]):
                    if keep and not keep[-1].strip():
                        keep.pop()                     # the blank line set() put before it
                    i = j
                    continue
            keep.append(self.lines[i])
            i += 1
        self.lines = keep

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".murphy-tmp")
        tmp.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)


def _true(v: str | None, default: bool) -> bool:
    return default if v is None else v.strip().lower() == "true"


def _version() -> tuple[int, ...] | None:
    if WINDOWS:
        return None
    if is_flatpak() and have("flatpak"):
        out = run(["flatpak", "info", FLATPAK_ID])[1]
        m = re.search(r"Version:\s*(\d+)\.(\d+)\.(\d+)", out)
    elif have("qbittorrent"):
        m = re.search(r"v(\d+)\.(\d+)\.(\d+)", run(["qbittorrent", "--version"])[1])
    else:
        m = None
    return tuple(map(int, m.groups())) if m else None


def vpn_interfaces() -> list[str]:
    """Linux network interfaces that look like a VPN tunnel (Mullvad, Proton, Nord, IVPN,
    Windscribe, PIA, plain WireGuard/OpenVPN). Other systems: net.tunnels()."""
    net = Path("/sys/class/net")
    if WINDOWS or not net.is_dir():
        return []
    pat = re.compile(r"^(wg[\w-]*|proton\w*|pvpn\w*|tun\d+|tap\d+|nordlynx|nordtun|ivpn\w*|"
                     r"windscribe\w*|pia\w*|eddie\w*)$")
    return sorted(p.name for p in net.iterdir() if pat.match(p.name))


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expanduser(p.replace("/", os.sep))))


def audit(folder: Path) -> list[Hit]:
    path = config_path()
    if not path.exists():
        return [Hit(INFO, str(path), "qBittorrent config not found — nothing to audit")]
    ini = Ini(path)
    hits: list[Hit] = []
    ver = _version()
    if ver and ver < (5, 0, 1):
        hits.append(Hit(CRIT, "qbittorrent", f"version {'.'.join(map(str, ver))}: CVE-2024-51774 — "
                        "before 5.0.1 it skipped TLS certificate checks (MITM could swap its "
                        "downloads)"))
    save = ini.get(K_SAVE)
    default_save = str(Path.home() / "Downloads")
    if _norm(save or default_save) != _norm(str(folder)) and \
            not _norm(save or default_save).startswith(_norm(str(folder)) + os.sep):
        hits.append(Hit(HIGH, "save path", f"downloads land in {save or default_save}, "
                                           f"not the locked folder {folder}"))
    temp_on = _true(ini.get(K_TEMP_ON), False)
    temp = ini.get(K_TEMP) or ""
    if temp_on and temp and not _norm(temp).startswith(_norm(str(folder))):
        hits.append(Hit(HIGH, "temp path", f"incomplete files sit in {temp}, outside the lock"))
    for key, prog_key, label in ((K_RUN_DONE, K_RUN_DONE_PROG, "on torrent finished"),
                                 (K_RUN_ADD, K_RUN_ADD_PROG, "on torrent added")):
        if _true(ini.get(key), False):
            hits.append(Hit(HIGH, "autorun", f"runs a program {label}: {ini.get(prog_key) or '?'} "
                                             "— a torrent's name/path reaches a shell; turn it off "
                                             "unless you wrote it"))
    if _true(ini.get(*K_WEBUI), False):
        addr = ini.get(*K_WEBUI_ADDR) or "*"
        if addr not in ("127.0.0.1", "::1", "localhost"):
            hits.append(Hit(HIGH, "web ui", f"Web UI listens on '{addr}', not just this machine"))
        if not _true(ini.get(*K_WEBUI_LOCALAUTH), True):
            hits.append(Hit(HIGH, "web ui", "Web UI skips the password for local clients — any "
                                            "local process (or malware) can drive the client"))
    if _true(ini.get(K_UPNP), True):
        hits.append(Hit(WARN, "upnp", "UPnP/NAT-PMP on: the client opens ports on your router"))
    enc = ini.get(K_ENC) or "0"
    if enc not in ("0", "1"):
        hits.append(Hit(WARN, "encryption", "protocol encryption is disabled"))
    elif enc == "0":
        hits.append(Hit(INFO, "encryption", "encryption allowed but not required"))
    bound = ini.get(K_IFACE)
    if bound and not WINDOWS and not Path("/sys/class/net", bound).exists():
        hits.append(Hit(INFO, "interface", f"bound to '{bound}', which is down right now — "
                                           "torrents are paused until the VPN is back (that's the point)"))
    if not ini.get(K_LSD) or _true(ini.get(K_LSD), True):
        hits.append(Hit(WARN, "local discovery", "Local Peer Discovery on: your torrents are "
                                                 "announced to everyone on your Wi-Fi/LAN"))
    if not _true(ini.get(K_ANON), False):
        hits.append(Hit(INFO, "anonymous mode", "off: peers and trackers see which client and "
                                                "version you run"))
    if not bound:
        hits.append(Hit(WARN, "interface", "not bound to a VPN interface — if the VPN drops, "
                                           "torrent traffic leaks onto your real IP "
                                           "(Advanced → Network interface)"))
    excl = {x.lower() for x in ini.get_list(K_EXCL)} if _true(ini.get(K_EXCL_ON), False) else set()
    missing = [x for x in EXCLUDE if x not in excl]
    if missing:
        hits.append(Hit(WARN, "excluded names", f"never-legit types are still downloaded: "
                                                f"{', '.join(missing[:6])}{' …' if len(missing) > 6 else ''}"))
    if not _true(ini.get(K_APPEND), False):
        hits.append(Hit(INFO, "incomplete", "half-downloaded files keep their real extension "
                                            "(no .!qB), so a partial .exe is clickable"))
    if WINDOWS and not _true(ini.get(K_MOTW), True):
        hits.append(Hit(HIGH, "mark-of-the-web", "downloads are not marked as from the internet — "
                                                 "SmartScreen and Office Protected View stay silent"))
    return hits


def apply_lock(folder: Path, ledger: dict, remember) -> list[str]:
    """Rewrite the settings; returns what changed. Caller checks running() first."""
    path = config_path()
    ini = Ini(path)
    fwd = str(folder).replace("\\", "/")
    want = {
        K_SAVE: fwd,
        K_TEMP_ON: "true",
        K_TEMP: fwd + "/.incomplete",
        K_APPEND: "true",
        K_ENC: "1",
        K_UPNP: "false",
        K_EXCL_ON: "true",
    }
    want[K_LSD] = "false"
    want[K_ANON] = "true"
    vpn = vpn_interfaces()
    if len(vpn) == 1:
        want[K_IFACE] = vpn[0]
        want[K_IFACE_NAME] = vpn[0]
    if WINDOWS:
        want[K_MOTW] = "true"
    changed = []
    for key, val in want.items():
        remember(ledger, "qbit", key, ini.raw(key))
        if ini.get(key) != val:
            ini.set(key, val)
            changed.append(f"{key} = {val}")
    old = ini.get_list(K_EXCL)
    remember(ledger, "qbit", K_EXCL, ini.raw(K_EXCL))
    merged = old + [x for x in EXCLUDE if x.lower() not in {o.lower() for o in old}]
    if merged != old:
        ini.set(K_EXCL, ", ".join(merged), is_list=True)
        changed.append(f"{K_EXCL} += {len(merged) - len(old)} never-legit types")
    ini.save()
    (folder / ".incomplete").mkdir(parents=True, exist_ok=True)
    if len(vpn) != 1:
        changed.append("VPN binding skipped — " + (f"several tunnels up ({', '.join(vpn)}); "
                       "pick one in Advanced → Network interface" if vpn else
                       "no VPN tunnel is up right now; connect it and re-run `murphy ds lock`"))
    return changed


def bound_to() -> str:
    path = config_path()
    return (Ini(path).get(K_IFACE) or "") if path.exists() else ""


def bind(iface: str, name: str, ledger: dict, remember) -> None:
    """Tie the client to one interface, so a dropped VPN stops torrents instead of
    leaking them. Caller checks running() first (the client rewrites its config on exit)."""
    ini = Ini(config_path())
    for key, val in ((K_IFACE, iface), (K_IFACE_NAME, name)):
        remember(ledger, "qbit", key, ini.raw(key))
        ini.set(key, val)
    ini.save()


def launch_cmd() -> list[str] | None:
    """How to open the client on this machine, or None if it isn't installed."""
    if WINDOWS:
        for var in ("ProgramFiles", "ProgramFiles(x86)"):
            exe = Path(os.environ.get(var) or "", "qBittorrent", "qbittorrent.exe")
            if exe.is_file():
                return [str(exe)]
        return ["qbittorrent"] if have("qbittorrent") else None
    if sys.platform == "darwin":
        return ["open", "-a", "qBittorrent"] if Path("/Applications/qBittorrent.app").is_dir() else None
    if is_flatpak() and have("flatpak"):
        return ["flatpak", "run", FLATPAK_ID]
    return ["qbittorrent"] if have("qbittorrent") else None


def stop(wait: int = 20) -> bool:
    """Ask the client to close (it saves its state on the way out); True once it is gone."""
    import time
    if WINDOWS:
        run(["taskkill", "/IM", "qbittorrent.exe"])
    else:
        run(["pkill", "-TERM", "-x", "-i", "qbittorrent"])
    end = time.monotonic() + wait
    while running() and time.monotonic() < end:
        time.sleep(0.5)
    return not running()


def restore(ledger: dict) -> list[str]:
    saved = ledger.get("qbit", {})
    if not saved:
        return []
    ini = Ini(config_path())
    for key, raw in saved.items():
        ini.set_raw(key, raw)
    ini.drop_empty_sections()
    ini.save()
    return list(saved)
