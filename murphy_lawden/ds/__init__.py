"""`murphy ds` — download security for torrents and magnets (Linux + Windows).

  murphy ds                                   the menu: pick everything by number
  murphy ds go                                get ready: VPN up, client tied to it, folder watched
  murphy ds check <file.torrent | magnet:…>   judge it before a byte downloads
  murphy ds scan [PATH] [--apply]             judge + AV-scan what arrived; --apply quarantines
  murphy ds extract <archive>                 unpack inside the cage (no net, no home)
  murphy ds run <file> [--with-dir] [--gui]   run it inside the cage
  murphy ds run <game.exe> --proton --gui --gpu   a Windows game: Proton, and a prefix that is kept
  murphy ds lock | unlock | status            the locked folder and everything around it
  murphy ds quarantine                        list what scan --apply moved away

What it promises, stated plainly: nothing from the torrent folder runs except in a
cage with no network, no view of your home, and one writable output folder.
What it can't stop: a script you hand to an interpreter yourself, anything you run
with sudo/as admin, a file you copy out of the folder and start, and a game you add
to Steam/Lutris by hand (Proton launches its own Wine, outside the shim).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from ..banner import Ink
from . import names, state
from .names import CRIT, HIGH, INFO, RANK, WARN, Hit

WINDOWS = sys.platform == "win32"


def _out(ink: Ink):
    marks = {"+": ink.green("✓"), "x": ink.blood("✗"), "!": ink.amber("!"), "=": ink.dim("·")}

    def out(mark: str, text: str) -> None:
        print(f"  {marks.get(mark, mark)} {names.safe(text)}", flush=True)
    return out


def _paint(ink: Ink, level: str) -> str:
    return {CRIT: ink.red_b, HIGH: ink.blood, WARN: ink.amber, INFO: ink.dim}[level](f"{level:<4}")


def _print_hits(ink: Ink, hits: list[Hit], limit: int = 60, base: Path | None = None) -> None:
    seen, rows = set(), []
    for h in sorted(hits, key=lambda h: -RANK[h.level]):
        if (h.path, h.reason) not in seen:
            seen.add((h.path, h.reason))
            rows.append(h)
    for h in rows[:limit]:
        path = h.path
        if base and os.path.isabs(path) and (base == Path(path) or base in Path(path).parents):
            path = os.path.relpath(path, base.parent)
        path = names.safe(path)
        path = path if len(path) <= 70 else "…" + path[-69:]
        print(f"    {_paint(ink, h.level)}  {path}\n          {ink.dim(names.safe(h.reason))}")
    if len(rows) > limit:
        print(ink.dim(f"    … and {len(rows) - limit} more"))


def _verdict(ink: Ink, hits: list[Hit], complete: bool = True) -> int:
    w = names.worst(hits)
    if w == CRIT:
        print("\n  " + ink.red_b("VERDICT: do not open this. It carries the marks of malware."))
        return 3
    if w == HIGH:
        print("\n  " + ink.blood("VERDICT: dangerous. Only ever through `murphy ds run`, if at all."))
        return 2
    if w == WARN:
        print("\n  " + ink.amber("VERDICT: caution — nothing damning, some things to watch."))
        return 1
    if complete:
        print("\n  " + ink.green("VERDICT: no red flags.") + ink.dim(" Names and headers can't prove "
                                                                   "a file clean — scan after download."))
    return 0


def _platform():
    if WINDOWS:
        from . import windows
        return windows
    from . import lock_linux
    return lock_linux


def _folder(args) -> Path:
    if getattr(args, "folder", None):
        return Path(args.folder).expanduser().resolve()
    led = state.load()
    return Path(led["folder"]) if led.get("folder") else state.default_folder()


# ---- commands --------------------------------------------------------------- #
def cmd_check(args, ink: Ink) -> int:
    from . import torrent
    # an unquoted magnet gets split by the shell, and people paste the bare hash: rejoin both
    src = "".join(args.target) if len(args.target) > 1 and not Path(args.target[0]).expanduser().exists() \
        else " ".join(args.target)
    import re
    bare = [t for t in args.target if re.fullmatch(r"[0-9A-Fa-f]{40}|[A-Za-z2-7]{32}", t.strip())]
    if bare and not src.startswith("magnet:"):
        src = "magnet:?xt=urn:btih:" + bare[0].strip()
    try:
        if src.startswith("magnet:"):
            r = torrent.check_magnet(src)
        else:
            r = torrent.check_torrent(Path(src).expanduser())
    except FileNotFoundError:
        from . import guide
        guide.explain_check(src, ink)
        return 2
    except (OSError, torrent.BencodeError) as e:
        print("  " + ink.blood(f"can't read it: {e}"))
        return 2
    print(ink.bone(f"  DS CHECK — {names.safe(r.title)}"))
    if r.infohash:
        print(ink.dim(f"  info-hash {r.infohash}"))
    if r.files:
        total = sum(s for _, s in r.files)
        print(ink.dim(f"  {len(r.files)} file(s), {total / (1 << 30):.2f} GiB"))
        if args.verbose:
            for p, s in r.files:
                print(ink.dim(f"      {s / (1 << 20):>10.1f} MiB  {names.safe(p)}"))
    for n in r.notes:
        print("  " + ink.dim("· " + names.safe(n)))
    if r.hits:
        print()
        _print_hits(ink, r.hits)
    if not r.complete:
        print("\n  " + ink.amber("A magnet link has no file list until metadata arrives from the swarm, "
                                 "and Murphy won't join the swarm for you (it announces your IP)."))
        print("  " + ink.dim("In qBittorrent's add dialog, wait for the file list, press "
                             "'Save as .torrent file…', then: ") + ink.cyan("murphy ds check that.torrent"))
    return _verdict(ink, r.hits, r.complete)


def cmd_scan(args, ink: Ink) -> int:
    from . import scan
    root = Path(args.target).expanduser() if args.target else _folder(args)
    if not root.exists():
        print("  " + ink.blood(f"{root} does not exist"))
        return 2
    print(ink.bone(f"  DS SCAN — {root}") + ink.dim("  (read-only)" if not args.apply else "  (--apply: quarantine)"))
    hits = scan.judge_tree(root)
    if not args.no_av:
        from ..spinner import working
        with working("signature scan", ink):
            av_hits, notes = scan.engines(root)
        hits += av_hits
        for n in notes:
            print("  " + ink.amber("! " + names.safe(n)))
    if hits:
        _print_hits(ink, hits, base=root)
    rc = _verdict(ink, hits)
    bad: dict[str, list[str]] = {}
    for h in hits:
        if RANK[h.level] >= RANK[HIGH] and os.path.lexists(h.path) \
                and not (root.is_dir() and Path(h.path) == root):
            bad.setdefault(h.path, []).append(f"{h.level}: {h.reason}")
    if bad and not args.apply:
        print("  " + ink.dim(f"{len(bad)} file(s) would be quarantined — ") + ink.cyan("murphy ds scan --apply"))
    if bad and args.apply:
        for p, reasons in bad.items():
            try:
                e = scan.quarantine(Path(p), reasons)
                print(f"  {ink.green('✓')} quarantined {names.safe(p)}"
                      + (f"  sha256 {e['sha256']}" if "sha256" in e else ""))
            except OSError as ex:
                print(f"  {ink.blood('✗')} {names.safe(p)}: {ex}")
    return rc


def cmd_quarantine(args, ink: Ink) -> int:
    from . import scan
    items = scan.listing()
    if not items:
        print("  " + ink.dim("quarantine is empty"))
        return 0
    for e in items:
        print(f"  {ink.bone(e['id'])}  {names.safe(e['original'])}")
        print(ink.dim(f"      {e.get('sha256') or 'symlink → ' + names.safe(e.get('symlink_to', '?'))}"))
        for r in e["reasons"][:3]:
            print(ink.dim(f"      {names.safe(r)}"))
    print("  " + ink.dim(f"stored in {state.QUARANTINE} (no permissions; move back by hand if you "
                         "are certain)"))
    return 0


def _outdir(args, target: Path, suffix: str) -> Path:
    if args.out:
        return Path(args.out).expanduser().resolve()
    folder = _folder(args)
    base = target.parent if folder in target.resolve().parents else folder
    return base / f"{target.stem}{suffix}"


def _warn_unlocked(ink: Ink, folder: Path, outdir: Path) -> None:
    if WINDOWS:
        return
    from .lock_linux import locked
    if not locked(folder) or folder not in outdir.resolve().parents:
        print("  " + ink.amber(f"! output {outdir} is not inside a locked folder — what the cage "
                               "writes there could be run later. `murphy ds lock` first."))


def cmd_extract(args, ink: Ink) -> int:
    from . import scan
    archive = Path(args.target).expanduser().resolve()
    if not archive.is_file():
        print("  " + ink.blood(f"{archive} is not a file"))
        return 2
    outdir = _outdir(args, archive, "_x")
    if outdir.exists() and any(outdir.iterdir()):
        print("  " + ink.blood(f"{outdir} exists and isn't empty — pick another with --out"))
        return 2
    out = _out(ink)
    if WINDOWS:
        from . import windows
        rc = windows.extract(archive, outdir, out)
    else:
        from . import cage
        ok, why = cage.available()
        if not ok:
            print("  " + ink.blood(why))
            return 2
        _warn_unlocked(ink, _folder(args), outdir)
        outdir.mkdir(parents=True, exist_ok=True)
        out("+", f"extracting in the cage (no network, no home) → {outdir}")
        cmd = cage.build(["7z", "x", "-o/cage/out", "--", f"/cage/in/{archive.name}"],
                         binds_ro=[(str(archive), f"/cage/in/{archive.name}")],
                         binds_rw=[(str(outdir), "/cage/out")], chdir="/cage/out")
        rc = cage.spawn(cmd)
    print()
    if rc != 0:
        print("  " + ink.amber(f"! extractor exited {rc}"))
    args.target = str(outdir)
    return max(cmd_scan(args, ink), 1 if rc else 0)


def _run_argv(staged: str, kind: str, name: str) -> list[str] | None:
    e = names.ext(name)
    if kind.startswith("Windows executable") or e in ("exe", "msi", "bat", "cmd", "com", "lnk"):
        if e == "msi":
            return ["wine", "msiexec", "/i", staged]
        return ["wine", staged]
    if kind.startswith("Linux executable") or kind.startswith("script"):
        return [staged]
    if e == "jar":
        return ["java", "-jar", staged]
    if e in ("py", "pyw"):
        return ["python3", staged]
    if e in ("sh", "bash"):
        return ["bash", staged]
    return None


# folders that hold unrelated files: never hand one of these to the cage whole
_CATCH_ALL = ("", "Downloads", "Desktop", "Documents", "Pictures", "Videos", "Music")


def _auto_flags(args, target: Path, out) -> None:
    """--auto: choose the flags a person would. Used by the Wine shim, the double-click
    launcher and the Steam compatibility tool, where nobody is there to pick them."""
    folder = _folder(args).resolve()
    in_torrents = folder in target.parents
    in_prefix = "drive_c" in target.parts
    home_dir = target.parent == Path.home() or (target.parent.parent == Path.home()
                                                and target.parent.name in _CATCH_ALL)
    own_dir = not in_prefix and target.parent != folder and not home_dir \
        and target.parent != Path(tempfile_dir())
    args.gui = True
    args.with_dir = args.with_dir or own_dir
    if names.ext(target.name) in ("exe", "msi"):
        args.proton = args.gpu = args.audio = True
        # saves beside the .exe — only for a game in its own folder inside the locked folder
        args.writable = args.writable or (own_dir and in_torrents)
    picked = [f for f, on in (("--with-dir", args.with_dir), ("--writable", args.writable),
                              ("--proton", args.proton), ("--gui", True), ("--gpu", args.gpu),
                              ("--audio", args.audio)) if on]
    out("=", "auto: " + " ".join(picked))


def tempfile_dir() -> str:
    import tempfile
    return tempfile.gettempdir()


def cmd_run(args, ink: Ink) -> int:
    from . import scan
    target = Path(args.target).expanduser().resolve()
    if not target.is_file():
        from . import guide
        guide.explain_run(target, _folder(args), ink)
        return 2
    print(ink.bone(f"  DS RUN — {names.safe(target.name)}"))
    if args.auto:
        _auto_flags(args, target, _out(ink))
    if args.with_dir and target.parent == _folder(args).resolve():
        print("  " + ink.blood("--with-dir on a file sitting directly in the torrent folder would hand "
                               "the cage every download you have. Put it in its own subfolder."))
        return 2
    hits = scan.judge_tree(target.parent if args.with_dir else target)
    if hits:
        _print_hits(ink, hits, limit=15)
    if names.worst(hits) == CRIT and not args.force:
        print("\n  " + ink.red_b("Refused: this carries the marks of malware. ")
              + ink.dim("(--force runs it in the cage anyway)"))
        return 3
    outdir = _outdir(args, target, "_cage-out")
    build = prefix = None
    if args.proton or args.proton_build:
        from . import proton
        if WINDOWS:
            print("  " + ink.blood("--proton is Linux-only"))
            return 2
        build = proton.pick(args.proton_build)
        if build is None:
            have = ", ".join(b.name for b in proton.builds()) or "none"
            print("  " + ink.blood(f"no Proton build matches (found: {have})"))
            return 2
        prefix = proton.prefix_of(target)          # already installed by an earlier caged run
        if prefix and not args.out:
            outdir = prefix.parent
        prefix = prefix or outdir / "prefix"
    if not args.yes and sys.stdin.isatty():
        try:
            ans = input("  " + ink.cyan(f"run it in the cage (no network, no home, writes only to "
                                        f"{outdir})? [y/N] ")).strip().lower()
        except EOFError:
            ans = ""
        if ans not in ("y", "yes"):
            print("  " + ink.dim("Left alone."))
            return 0
    out = _out(ink)
    if WINDOWS:
        from . import windows
        return windows.run_caged(target, args.with_dir, outdir, out)

    from . import cage
    ok, why = cage.available()
    if not ok:
        print("  " + ink.blood(why))
        return 2
    _warn_unlocked(ink, _folder(args), outdir)
    try:
        with open(target, "rb") as fh:
            kind = names.sniff(fh.read(16))
    except OSError as e:
        print("  " + ink.blood(str(e)))
        return 2
    needs_exec = kind.startswith(("Linux executable", "script"))
    work = None
    if needs_exec:                       # the lock's noexec follows binds; run a private copy
        work = cage.stage(target, args.with_dir)
        src_dir = work / "app"
    else:
        src_dir = target.parent if args.with_dir else None
    inner = f"/cage/app/{target.name}"
    argv = _run_argv(inner, kind, target.name)
    if build and (argv is None or argv[0] != "wine"):
        print("  " + ink.blood("--proton is for Windows programs; this is "
                               f"a '{kind or names.ext(target.name) or 'plain'}' file"))
        if work:
            cage.unstage(work)
        return 2
    if argv is None:
        print("  " + ink.blood(f"don't know how to run a '{kind or names.ext(target.name) or 'plain'}' file"))
        if work:
            cage.unstage(work)
        return 2
    outdir.mkdir(parents=True, exist_ok=True)
    binds = [(str(src_dir), "/cage/app")] if src_dir else [(str(target), inner)]
    binds_rw, extra_env = [(str(outdir), "/cage/out")], None
    if args.writable and not (prefix and prefix in target.parents):   # a prefix already is
        if not args.with_dir or work:
            out("x", "--writable needs --with-dir, and can't apply to a Linux program (it runs "
                     "from a private copy that is thrown away)")
            if work:
                cage.unstage(work)
            return 2
        binds, binds_rw = [], binds_rw + [(str(src_dir), "/cage/app")]
        out("!", f"its own folder is writable: it can save there — and change or delete "
                 f"anything in {src_dir}")
    chdir = "/cage/app" if src_dir else "/cage/out"
    if build:
        from . import proton
        fresh = proton.prepare(prefix)
        if prefix in target.parents:               # it lives in the prefix; nothing else to mount
            inner, binds = f"{proton.INNER_PREFIX}/{target.relative_to(prefix)}", []
            chdir = os.path.dirname(inner)
        argv = proton.argv(inner, target.name)
        binds.append((str(build), proton.INNER))
        binds_rw.append((str(prefix), proton.INNER_PREFIX))
        extra_env = proton.env(wayland=args.gui)
        out("+", f"{build.name} · " + ("new prefix" if fresh else "its prefix from last time")
            + f" (kept): {prefix}")
        if not (args.gui and args.gpu):
            out("!", "a game wants a window and the GPU: add --gui --gpu")
    from contextlib import ExitStack
    from . import wlsec
    with ExitStack() as stack:
        if work:
            stack.callback(cage.unstage, work)
        wl = None
        if args.gui:
            try:
                wl = stack.enter_context(wlsec.RestrictedSocket())
                leaked = set(wlsec.PRIVILEGED) & wlsec.offered(wl)
            except (OSError, wlsec.WaylandError) as e:
                print("  " + ink.blood(f"--gui refused: {e}. A raw Wayland socket would let the "
                                       "program type into your terminal and read your screen."))
                return 2
            if leaked:
                print("  " + ink.blood("--gui refused: the compositor still offers "
                                       + ", ".join(sorted(leaked)) + " to sandboxed clients."))
                return 2
        snd = None
        if args.audio:
            from . import audio
            try:
                snd = stack.enter_context(audio.PlayOnly())
            except (OSError, audio.AudioError) as e:
                if not args.auto:
                    print("  " + ink.blood(f"--audio refused: {e}. The desktop's own sound socket would "
                                           "let the program record your microphone."))
                    return 2
                out("!", f"no sound this time: {e}")
        mid = None
        if build:                                  # a kept prefix keeps one made-up machine id
            idf = prefix / "machine-id"
            if not idf.is_file():
                import uuid
                idf.write_text(uuid.uuid4().hex + "\n")
            mid = idf.read_text().strip()
        cmd = cage.build(argv, binds_ro=binds, binds_rw=binds_rw, extra_env=extra_env,
                         wayland=wl, gpu=args.gpu, chdir=chdir, pulse=snd, machine_id=mid,
                         exec_app=not args.writable)
        out("+", "cage up: no network · empty home · read-only OS · writes only to " + str(outdir)
            + (" · restricted Wayland window" if wl else " · no display")
            + (" · GPU" if args.gpu else "") + (" · play-only sound" if snd else "")
            + (" · syscall filter" if cage.seccomp.supported() else "")
            + " · Ctrl-C closes it")
        rc = cage.spawn(cmd, memory=args.memory)
    if build:
        out("=", f"cage closed (exit {rc}); its home and /tmp are gone, the prefix stays — "
                 f"delete {prefix} to forget the game")
    else:
        out("=", f"cage closed (exit {rc}); its home, /tmp and Wine prefix are gone")
    return rc


def cmd_go(args, ink: Ink) -> int:
    from . import guide
    return guide.go(_folder(args), ink, _out(ink), assume=args.yes, open_client=not args.no_open,
                    want=args.vpn)


def cmd_snapshot(args, ink: Ink) -> int:
    from . import snapshot
    out = _out(ink)
    if args.drop:
        return snapshot.drop_all(out)
    if args.list:
        snaps = snapshot.listing()
        for m in snaps:
            print(f"  {ink.bone(m['id'])}  " + ink.dim(" · ".join(
                x for x in ("manifest", "home" if m.get("home") else "",
                            f"snapper #{m['snapper']}" if m.get("snapper") is not None else "") if x)))
        if not snaps:
            print("  " + ink.dim("no pre-torrent snapshots yet — `murphy ds snapshot`"))
        return 0
    if args.check or args.restore:
        meta = snapshot.latest()
        if meta is None:
            print("  " + ink.blood("no snapshot to compare against — take one with `murphy ds snapshot`"))
            return 2
        d = snapshot.compare(meta)
        if "error" in d:
            print("  " + ink.blood(d["error"]))
            return 2
        print(ink.bone(f"  DS SNAPSHOT CHECK — since {d['taken']}") + ink.dim(f"  (against the {d['source']})"))
        for label, mark in (("new", "x"), ("changed", "!"), ("removed", "!")):
            for rel in d[label]:
                out(mark, f"{label}: ~/{rel}")
        if d["crontab"]:
            out("x", "your crontab changed")
        for k in d["run_keys"]:
            out("x", f"new Windows autostart entry: {k}")
        clean = not (d["new"] or d["changed"] or d["removed"] or d["crontab"] or d["run_keys"])
        if args.notify:
            from . import sentinel
            sentinel.notify(d)
        if clean:
            out("+", "nothing in the startup places changed")
        if args.restore and not clean:
            for rel in d["changed"] + d["removed"]:
                out("+" if snapshot.restore_file(meta, rel) else "x", f"restored ~/{rel}")
            from . import scan
            for rel in d["new"]:
                p = Path.home() / rel
                if p.exists() or p.is_symlink():
                    scan.quarantine(p, ["appeared in a startup place after the pre-torrent snapshot"])
                    out("+", f"quarantined ~/{rel}")
        return 0 if clean or args.notify else 1    # under the sentinel a finding is a notification, not a failed unit
    print(ink.bone("  DS SNAPSHOT — a known-good point before you torrent"))
    return snapshot.take(out, layers=not args.no_system)


def cmd_jail(args, ink: Ink) -> int:
    from . import jail
    out = _out(ink)
    if WINDOWS:
        print("  " + ink.amber("the jail is Linux-only"))
        return 2
    if args.install:
        return jail.install(out)
    if args.uninstall:
        return jail.uninstall(out)
    if args.status:
        out("=", "jail: " + jail.status())
        return 0
    return jail.launch(args.qbit_args, out)


def cmd_ipfilter(args, ink: Ink) -> int:
    from . import ipfilter
    out = _out(ink)
    if args.install:
        return ipfilter.install(out)
    if args.update:
        return ipfilter.update(out)
    if args.uninstall:
        return ipfilter.uninstall(out)
    out("=", "ip filter: " + ipfilter.status())
    return 0


def cmd_sentinel(args, ink: Ink) -> int:
    from . import sentinel
    if WINDOWS:
        print("  " + ink.amber("the sentinel is Linux-only for now (it rides on systemd user units)"))
        return 2
    out = _out(ink)
    if args.install:
        return sentinel.install(out)
    if args.uninstall:
        return sentinel.uninstall(out)
    on, how = sentinel.status()
    out("+" if on else "!", "sentinel: " + ("watching the startup places" if on else
                                            f"{how} (`murphy ds sentinel --install`)"))
    return 0


def cmd_lock(args, ink: Ink) -> int:
    folder = _folder(args)
    print(ink.bone(f"  DS LOCK — {folder}"))
    mod = _platform()
    rc = mod.lock(folder, _out(ink))
    print()
    cmd_status(args, ink)
    return rc


def cmd_unlock(args, ink: Ink) -> int:
    print(ink.bone("  DS UNLOCK"))
    mod = _platform()
    return mod.unlock(_out(ink))


def cmd_autoscan(args, ink: Ink) -> int:
    from . import autoscan
    if WINDOWS:
        print("  " + ink.amber("autoscan is Linux-only for now (it rides on a systemd path unit)"))
        return 2
    if args.install:
        return autoscan.install(_folder(args), _out(ink))
    if args.uninstall:
        return autoscan.uninstall(_out(ink))
    return autoscan.run_autoscan(_folder(args), ink)


def cmd_status(args, ink: Ink) -> int:
    from . import qbit
    folder = _folder(args)
    print(ink.bone(f"  DS STATUS — {folder}"))
    mod = _platform()
    mod.status(folder, _out(ink))
    if not WINDOWS:
        from . import autoscan
        from ..core import run
        on, how = autoscan.status()
        _out(ink)("+" if on else "!", "autoscan: " + ("watching for finished downloads" if on
                                                      else f"{how} (`murphy ds autoscan --install`)"))
        from . import sentinel
        on, how = sentinel.status()
        _out(ink)("+" if on else "!", "sentinel: " + ("notifies you if anything makes itself start again"
                                                      if on else f"{how} (`murphy ds sentinel --install`)"))
        fresh = run(["systemctl", "is-enabled", "clamav-freshclam-once.timer"])[1].strip()
        daemon = run(["systemctl", "is-active", "clamav-freshclam.service"])[1].strip()
        ok = fresh == "enabled" or daemon == "active"
        _out(ink)("+" if ok else "!", "virus signatures: " + ("updated daily" if ok else
                  "not auto-updated (`sudo systemctl enable --now clamav-freshclam-once.timer`)"))
        if qbit.is_flatpak():
            _out(ink)("+", "qbittorrent: sandboxed Flatpak build")
    hits = qbit.audit(folder)
    if hits:
        print("\n  " + ink.bone("qBittorrent"))
        _print_hits(ink, hits)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="murphy ds", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--folder", help="the locked torrent folder (default: ~/Torrents, or the one "
                                    "`ds lock` recorded)")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check", help="judge a .torrent or magnet before downloading")
    c.add_argument("target", nargs="+", help="a .torrent file, a magnet link, or a bare info-hash")
    c.add_argument("-v", "--verbose", action="store_true", help="list every file")
    s = sub.add_parser("scan", help="judge + AV-scan downloaded files")
    s.add_argument("target", nargs="?")
    s.add_argument("--apply", action="store_true", help="quarantine HIGH/CRIT files")
    s.add_argument("--no-av", action="store_true", help="skip ClamAV/Defender")
    x = sub.add_parser("extract", help="unpack an archive inside the cage")
    x.add_argument("target")
    x.add_argument("--out")
    x.add_argument("--apply", action="store_true", help="quarantine what the post-scan flags")
    x.add_argument("--no-av", action="store_true")
    r = sub.add_parser("run", help="run a program inside the cage")
    r.add_argument("target")
    r.add_argument("--with-dir", action="store_true",
                   help="give it its whole folder (installers with data files), read-only")
    r.add_argument("--out")
    r.add_argument("--gui", action="store_true",
                   help="allow a window on a restricted Wayland socket (never X11; refused if "
                        "the compositor can't withhold virtual input/screen capture)")
    r.add_argument("--gpu", action="store_true", help="allow the GPU (more kernel attack surface)")
    r.add_argument("--audio", action="store_true",
                   help="allow sound through a private play-only server: no microphone, no "
                        "capture (refused if that can't be verified)")
    r.add_argument("--writable", action="store_true",
                   help="with --with-dir: let it write into its own folder (games that keep "
                        "their saves beside the .exe)")
    r.add_argument("--proton", action="store_true",
                   help="Windows game: run it under Proton (newest GE-Proton) with a prefix "
                        "that is kept in the output folder — installs and saves survive")
    r.add_argument("--proton-build", metavar="NAME",
                   help="which Proton build, by part of its name (e.g. dwproton); implies --proton")
    r.add_argument("--memory", default="8G", help="memory ceiling (default 8G)")
    r.add_argument("--force", action="store_true", help="run even with a CRIT verdict")
    r.add_argument("-y", "--yes", action="store_true", help="don't ask")
    r.add_argument("--auto", action="store_true",
                   help="pick the flags yourself: a Windows .exe gets Proton, a window, the GPU and "
                        "play-only sound; its own folder (writable inside the torrent folder)")
    g = sub.add_parser("go", help="get ready to torrent: bring the VPN up, tie qBittorrent to "
                                  "it, watch the folder, open qBittorrent")
    g.add_argument("--vpn", metavar="NAME", help="which VPN to start if none is connected "
                                                 "(part of its name; default: asks, or the first found)")
    g.add_argument("--no-open", action="store_true", help="don't open qBittorrent at the end")
    g.add_argument("-y", "--yes", action="store_true", help="don't ask (closes qBittorrent if it must)")
    sn = sub.add_parser("snapshot", help="take a pre-torrent snapshot; --check shows what changed since")
    sn.add_argument("--check", action="store_true", help="what changed in the startup places since the last one")
    sn.add_argument("--restore", action="store_true", help="--check, then put changed files back and quarantine new ones")
    sn.add_argument("--list", action="store_true", help="list the snapshots")
    sn.add_argument("--drop", action="store_true", help="remove every pre-torrent snapshot")
    sn.add_argument("--no-system", action="store_true", help="manifest only: no sudo, no btrfs/snapper/restore point")
    sn.add_argument("--notify", action="store_true", help="with --check: a desktop notification if anything changed")
    jl = sub.add_parser("jail", help="run qBittorrent sandboxed: it can only write into the torrent folder")
    jg = jl.add_mutually_exclusive_group()
    jg.add_argument("--install", action="store_true", help="make every way of starting qBittorrent jailed")
    jg.add_argument("--uninstall", action="store_true", help="stop jailing it")
    jg.add_argument("--status", action="store_true")
    jl.add_argument("qbit_args", nargs="*", help="passed to qBittorrent (after --)")
    ip = sub.add_parser("ipfilter", help="qBittorrent never connects to hijacked/criminal/botnet networks")
    ig = ip.add_mutually_exclusive_group()
    ig.add_argument("--install", action="store_true", help="download the list, point qBittorrent at it, refresh weekly")
    ig.add_argument("--update", action="store_true", help="refresh the list now")
    ig.add_argument("--uninstall", action="store_true", help="stop filtering")
    se = sub.add_parser("sentinel", help="notify you when something tries to make itself start again")
    sg = se.add_mutually_exclusive_group()
    sg.add_argument("--install", action="store_true", help="start watching (systemd --user)")
    sg.add_argument("--uninstall", action="store_true", help="stop watching")
    sub.add_parser("lock", help="lock the torrent folder and close the routes around it")
    sub.add_parser("unlock", help="undo everything `lock` did (files are kept)")
    sub.add_parser("status", help="show every layer and audit qBittorrent")
    sub.add_parser("quarantine", help="list quarantined files")
    a = sub.add_parser("autoscan", help="scan finished downloads as they land and notify you")
    g = a.add_mutually_exclusive_group()
    g.add_argument("--install", action="store_true", help="watch the torrent folder (systemd --user)")
    g.add_argument("--uninstall", action="store_true", help="stop watching")
    return p


def run_ds(argv: list[str], ink: Ink) -> int:
    if not argv:
        if sys.stdin.isatty() and sys.stdout.isatty():      # bare `murphy ds`: the menu
            from . import guide
            return guide.menu(_folder(None), ink, _out(ink))
        build_parser().print_help()
        return 2
    args = build_parser().parse_args(argv)
    return {"go": cmd_go, "snapshot": cmd_snapshot, "sentinel": cmd_sentinel, "ipfilter": cmd_ipfilter, "jail": cmd_jail, "check": cmd_check, "scan": cmd_scan, "extract": cmd_extract, "run": cmd_run,
            "lock": cmd_lock, "unlock": cmd_unlock, "status": cmd_status,
            "quarantine": cmd_quarantine, "autoscan": cmd_autoscan}[args.cmd](args, ink)
