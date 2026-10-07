"""The guided side of `ds` — for when you don't want to remember a command.

  murphy ds        a menu: everything is picked by number, nothing is typed by path
  murphy ds go     get ready to torrent in one step: find the VPN this machine has and
                   bring it up, tie the torrent client to it, watch the folder, open the client

Every choice in the menu ends in an ordinary `murphy ds …` command, and that command
is printed before it runs — so the menu teaches the commands instead of hiding them.
"""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path

from ..banner import Ink, rule
from . import names, net, qbit, state

WINDOWS = sys.platform == "win32"
PROGRAMS = {"exe", "msi", "appimage", "sh", "run", "jar"}
# what a fresh Wine/Proton prefix ships with — never the thing you came to run
_PREFIX_NOISE = ("windows", "users", "programdata", "common files", "internet explorer",
                 "windows media player", "windows nt", "steam")
SHOWN = 20


def _short(p: Path | str) -> str:
    s, home = str(p), str(Path.home())
    return "~" + s[len(home):] if s == home or s.startswith(home + os.sep) else s


def _ask(ink: Ink, prompt: str) -> str:
    try:
        return input("  " + ink.cyan(prompt)).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def _yes(ink: Ink, prompt: str, default: bool = True, assume: bool = False) -> bool:
    if assume:
        return True
    if not sys.stdin.isatty():
        return default
    ans = _ask(ink, f"{prompt} [{'Y/n' if default else 'y/N'}] ").lower()
    return default if not ans else ans in ("y", "yes")


def _choose(ink: Ink, count: int, prompt: str = "which one") -> int | None:
    """A 1-based pick; None for 0/empty/anything else."""
    ans = _ask(ink, f"{prompt} [1-{count}, 0 = none]: ")
    return int(ans) if ans.isdigit() and 1 <= int(ans) <= count else None


def _cmdline(argv: list[str]) -> str:
    return "murphy ds " + " ".join(shlex.quote(a) for a in argv)


def _do(ink: Ink, argv: list[str]) -> int:
    """Show the command, then run it — the same path as typing it."""
    from . import run_ds
    print("  " + ink.dim("$ " + _cmdline(argv)))
    return run_ds(argv, ink)


# ---- finding things, so nobody has to type a path --------------------------- #
def torrents() -> list[Path]:
    """.torrent files where a browser leaves them, newest first."""
    home, found = Path.home(), {}
    for d in (home / "Downloads", home / "Desktop", home):
        try:
            for p in d.iterdir():
                if p.suffix.lower() == ".torrent" and p.is_file():
                    found[p] = p.stat().st_mtime
        except OSError:
            continue
    return sorted(found, key=found.get, reverse=True)


def downloads(folder: Path) -> tuple[list[Path], list[Path], list[Path]]:
    """(installed in a kept prefix, programs, archives) under the torrent folder."""
    installed, programs, archives = [], [], []
    for root, dirs, files in os.walk(folder):
        rel = Path(root).relative_to(folder).parts
        in_prefix = "drive_c" in rel
        top = in_prefix and (rel[-1] == "drive_c" or rel[-1].lower().startswith("program files"))
        dirs[:] = sorted(d for d in dirs if d != ".incomplete" and len(rel) < 12
                         and not (top and d.lower() in _PREFIX_NOISE)
                         and not (rel[-1:] == ("pfx",) and d != "drive_c"))
        for f in sorted(files):
            e = names.ext(f)
            if f.lower().endswith(".!qb"):
                continue
            p = Path(root, f)
            if in_prefix:
                if e == "exe" and not f.lower().startswith(("unins", "uninstall")):
                    installed.append(p)
            elif e in PROGRAMS:
                programs.append(p)
            elif e in names.ARCHIVES or e == "iso":
                archives.append(p)
    return installed, programs, archives


def run_argv(target: Path, folder: Path, game: bool, window: bool, saves: bool = False) -> list[str]:
    argv = ["run", str(target)]
    if target.parent != folder and "drive_c" not in target.parts:
        argv.append("--with-dir")           # an installer wants its data files beside it
        if saves:
            argv.append("--writable")
    if game:
        argv += ["--proton", "--gui", "--gpu", "--audio"]
    elif window:
        argv.append("--gui")
    return argv


def _is_windows_program(p: Path) -> bool:
    return names.ext(p.name) in ("exe", "msi")


# ---- errors that say what to do next ---------------------------------------- #
def explain_run(target: Path, folder: Path, ink: Ink) -> None:
    """`ds run` was pointed at something that isn't a program."""
    what = "is a folder, not a program" if target.is_dir() else "does not exist"
    print("  " + ink.blood(f"{_short(target)} {what}"))
    inst, progs, _ = downloads(target if target.is_dir() else folder) if folder.is_dir() else ([], [], [])
    found = inst + progs
    if not found:
        print("  " + ink.dim(f"Nothing runnable is in {_short(folder)} yet. Download something first — "
                             "`murphy ds go` gets you ready, `murphy ds` is the menu."))
        return
    print("  " + ink.dim("What is there — copy a line, or run `murphy ds` and pick by number:"))
    for p in found[:8]:
        win = _is_windows_program(p)
        print("    " + ink.cyan(_cmdline(run_argv(p, folder, game=win, window=False))))
    if len(found) > 8:
        print("  " + ink.dim(f"  … and {len(found) - 8} more"))


def explain_check(src: str, ink: Ink) -> None:
    """`ds check` was pointed at a .torrent that isn't there."""
    print("  " + ink.blood(f"{_short(Path(src).expanduser())} does not exist"))
    found = torrents()
    if not found:
        print("  " + ink.dim("No .torrent files in ~/Downloads, ~/Desktop or your home folder. Save one "
                             "from the site first, or paste the magnet link in quotes: "
                             "murphy ds check \"magnet:?xt=…\""))
        return
    print("  " + ink.dim("The .torrent files you do have:"))
    for p in found[:8]:
        print("    " + ink.cyan(_cmdline(["check", str(p)])))


# ---- go: everything a download needs, in one step --------------------------- #
def _pick_tunnel(up: list, ink: Ink, out, assume: bool):
    if len(up) == 1:
        return up[0]
    out("!", "more than one VPN tunnel is up: " + ", ".join(f"{t.label} ({t.name})" for t in up)
        + " — two VPNs at once fight over routes; turn one off")
    if assume or not sys.stdin.isatty():
        return None
    for i, t in enumerate(up, 1):
        print(f"   {ink.green(str(i))}  {t.label} ({t.name})")
    n = _choose(ink, len(up), "tie the torrent client to which")
    return up[n - 1] if n else None


def _bring_up(ink: Ink, out, assume: bool, want: str | None):
    tools = net.installed()
    if want:
        tools = [t for t in tools if want.lower() in t[0].name.lower()] or tools
    if not tools:
        out("x", "no VPN found on this machine. Without one every peer in the swarm sees your "
                 "real IP address. Install one (Mullvad, Proton VPN, IVPN …) and run this again.")
        return None
    tool, kind, argv = tools[0]
    if len(tools) > 1 and not want and not assume and sys.stdin.isatty():
        out("=", "no VPN is connected. Found on this machine:")
        for i, (t, k, _) in enumerate(tools, 1):
            note = {"cli": "Murphy connects it", "gui": "opens its window; you press Connect",
                    "manual": "you start it yourself"}[k]
            print(f"   {ink.green(str(i))}  {ink.bone(t.name)}  {ink.dim(note)}")
        n = _choose(ink, len(tools), "start which")
        if not n:
            return None
        tool, kind, argv = tools[n - 1]
    if kind == "manual":
        out("!", f"{tool.name} is installed but has no switch Murphy can press. Bring it up "
                 f"yourself — {argv[0]} — then run this again.")
        return None
    if kind == "cli":
        out("=", f"{tool.name}: connecting …")
        from ..core import run
        run(argv, timeout=60)
        up = net.wait_for_tunnel(30)
    else:
        out("!", f"{tool.name} has no command line here, so its window is opening — press "
                 "Connect in it. Waiting up to 2 minutes for the tunnel …")
        net.detach(argv)
        up = net.wait_for_tunnel(120)
    if up is None:
        out("x", f"{tool.name} did not come up. Check that you are online and signed in to it.")
    return up


def go(folder: Path, ink: Ink, out, assume: bool = False, open_client: bool = True,
       want: str | None = None) -> int:
    print(ink.bone("  DS GO — getting this machine ready to torrent"))
    rc = 0
    # 1. the VPN
    up = net.tunnels()
    tunnel = _pick_tunnel(up, ink, out, assume) if up else _bring_up(ink, out, assume, want)
    if tunnel:
        out("+", f"VPN: {tunnel.label} is connected ({tunnel.name})")
    else:
        rc = 1

    # 2. the torrent client, tied to that tunnel
    launch = qbit.launch_cmd()
    safe = False                                # safe to open the client?
    if launch is None:
        out("!", "qBittorrent is not installed — it is the client Murphy knows how to harden. "
                 "With any other client, bind it to the VPN interface by hand.")
    else:
        bound = qbit.bound_to()
        if tunnel and bound == tunnel.id:
            safe = True
            out("+", f"qBittorrent: tied to {tunnel.name} — if the VPN drops, torrents stop "
                     "instead of leaking your real IP")
        elif tunnel:
            closed = True
            if qbit.running():
                # never closed unasked: unattended and without -y the answer is no
                closed = _yes(ink, "qBittorrent is open and must be closed to change its settings. "
                                   "Close it now?", default=sys.stdin.isatty(), assume=assume) \
                    and qbit.stop()
            if closed:
                qbit.bind(tunnel.id, tunnel.name, state.load(), state.remember)
                safe = True
                out("+", f"qBittorrent: now tied to {tunnel.name} — if the VPN drops, torrents "
                         "stop instead of leaking your real IP (`murphy ds unlock` undoes it)")
            else:
                rc = 1
                out("!", "qBittorrent: left as it was — NOT tied to the VPN. Close it and run "
                         "`murphy ds go` again.")
        elif bound:
            safe = True
            out("=", f"qBittorrent: tied to '{bound}', which is down — it will sit idle until "
                     "the VPN is back (that is the point)")
        else:
            out("x", "qBittorrent: not tied to a VPN and no VPN is up — not opening it; it "
                     "would announce your real IP")

    # 3. the folder and the watcher
    if not WINDOWS and Path("/sys/class/net").is_dir():
        from . import autoscan, lock_linux
        if lock_linux.locked(folder):
            out("+", f"folder: {_short(folder)} is locked — nothing in it runs outside the cage")
        else:
            rc = 1
            out("!", f"folder: {_short(folder)} is not locked yet — run `murphy ds lock` once "
                     "(asks for your password)")
        if folder.is_dir():
            if autoscan.status()[0]:
                out("+", "autoscan: every finished download is scanned and you get a notification")
            elif autoscan.install(folder, lambda *_: None) == 0:
                out("+", "autoscan: switched on — every finished download is scanned and you get "
                         "a notification (`murphy ds autoscan --uninstall` undoes it)")
            else:
                out("!", "autoscan: could not be switched on (`murphy ds autoscan --install`)")
    else:
        out("=", "folder: `murphy ds status` shows whether it is locked on this system")

    # 4. open the client
    if launch and safe and open_client:
        if qbit.running():
            out("+", "qBittorrent: already open")
        else:
            net.detach(launch)
            out("+", "qBittorrent: opened")
    print()
    if launch and safe:
        print("  " + ink.bone("Next:") + ink.dim(" add your torrent or magnet in qBittorrent. It saves into "
                                               f"{_short(folder)}. When it is done, run ")
              + ink.cyan("murphy ds") + ink.dim(" and choose Run."))
    else:
        print("  " + ink.amber("Not ready yet — fix the lines marked ✗ or ! above, then `murphy ds go` again."))
    return rc


# ---- the menu --------------------------------------------------------------- #
def _menu_check(ink: Ink) -> None:
    found = torrents()
    for i, p in enumerate(found[:SHOWN], 1):
        print(f"   {ink.green(f'{i:>2}')}  {names.safe(p.name)}  {ink.dim(_short(p.parent))}")
    if not found:
        print("  " + ink.dim("no .torrent files in ~/Downloads, ~/Desktop or your home folder"))
    ans = _ask(ink, ("number, or " if found else "") + "paste a magnet link / path (empty = back): ")
    if ans.isdigit() and 1 <= int(ans) <= min(len(found), SHOWN):
        _do(ink, ["check", str(found[int(ans) - 1])])
    elif ans:
        _do(ink, ["check", ans.strip("'\"")])


def _menu_run(folder: Path, ink: Ink) -> None:
    inst, progs, archives = downloads(folder) if folder.is_dir() else ([], [], [])
    rows = [(p, "installed") for p in inst] + [(p, "program") for p in progs] \
        + [(p, "archive") for p in archives]
    if not rows:
        print("  " + ink.dim(f"Nothing to run in {_short(folder)} yet. Choose 1 (Get ready), add a "
                             "torrent in qBittorrent, and come back when it has finished."))
        return
    tint = {"installed": ink.green, "program": ink.bone, "archive": ink.dim}
    for i, (p, kind) in enumerate(rows[:SHOWN], 1):
        print(f"   {ink.green(f'{i:>2}')}  {tint[kind](f'{kind:<9}')}  "
              f"{names.safe(str(p.relative_to(folder)))}")
    if len(rows) > SHOWN:
        print("  " + ink.dim(f"… and {len(rows) - SHOWN} more (run `murphy ds run <path>` for those)"))
    n = _choose(ink, min(len(rows), SHOWN))
    if not n:
        return
    target, kind = rows[n - 1]
    if kind == "archive":
        print("  " + ink.dim("An archive is unpacked in the cage first, then scanned."))
        _do(ink, ["extract", str(target)])
        return
    if _is_windows_program(target):
        game = _yes(ink, "Is it a game or an installer that needs a window and the graphics card?")
        window = False
        saves = game and kind == "program" and target.parent != folder and _yes(
            ink, "Does it keep its saves in its own folder (RPG Maker and many old games do)?",
            default=False)
    else:
        game, saves, window = False, False, _yes(ink, "Does it need a window?", default=False)
    argv = run_argv(target, folder, game, window, saves)
    print("  " + ink.dim("It runs in the cage: no network, no view of your home."
                         + (" Installs and saves are kept in its own folder." if game else "")))
    if _yes(ink, "Run it now?"):
        _do(ink, argv + ["-y"])


def _headline(folder: Path, ink: Ink) -> str:
    up = net.tunnels()
    vpn = ink.green(f"✓ {up[0].label} connected") if up else ink.amber("! no VPN connected")
    bound = qbit.bound_to()
    tied = ink.green("✓ qBittorrent tied to the VPN") if bound and any(t.id == bound for t in up) \
        else ink.amber("! qBittorrent not tied to the VPN") if qbit.launch_cmd() else ink.dim("no qBittorrent")
    return f"  {vpn}   {tied}"


def menu(folder: Path, ink: Ink, out) -> int:
    items = (("Get ready", "VPN up, qBittorrent tied to it, folder watched, qBittorrent opened"),
             ("Check", "judge a .torrent or magnet before a byte downloads"),
             ("Scan", "virus-scan and judge what has been downloaded"),
             ("Run", "pick a download and run it in the cage (games too)"),
             ("Status", "every layer of protection, and what is missing"))
    while True:
        print()
        print(rule(ink, f"TORRENTS — {_short(folder)}"))
        print(_headline(folder, ink))
        for i, (name, what) in enumerate(items, 1):
            print(f"   {ink.green(str(i))}  {ink.bone(f'{name:<10}')} {ink.dim(what)}")
        print(f"   {ink.dim('0')}  {ink.dim('Leave')}")
        ans = _ask(ink, f"choose [0-{len(items)}]: ")
        print()
        if ans == "1":
            _do(ink, ["go"])
        elif ans == "2":
            _menu_check(ink)
        elif ans == "3":
            _do(ink, ["scan"])
        elif ans == "4":
            _menu_run(folder, ink)
        elif ans == "5":
            _do(ink, ["status"])
        else:
            return 0
