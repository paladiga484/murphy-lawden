#!/usr/bin/env python3
"""Murphy Lawden — the install job.

Stylish, and amnesiac to the bone: this writes exactly ONE file (a launcher in
~/.local/bin) and touches nothing else — no state dir, no cache, no config, no
history. Murphy still writes nothing on a scan; only `fix` ever touches disk, and
only with a backup you can `murphy undo`. Installing him doesn't change that.

    python3 install.py            put `murphy` on PATH (asks first)
    python3 install.py --yes      no prompt
    python3 install.py --uninstall remove the launcher this put down
"""
from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from murphy_lawden.banner import Ink, WATERMARK, make_ink, render_banner, rule  # noqa: E402

ENTRY = os.path.join(HERE, "murphy.py")
NAME = "murphy"
BIN = os.environ.get("XDG_BIN_HOME") or os.path.expanduser("~/.local/bin")
LAUNCHER = os.path.join(BIN, NAME)
MARKER = "# installed by murphy-lawden/install.py — safe to delete"


def _launcher_text() -> str:
    return f'#!/usr/bin/env bash\n{MARKER}\nexec python3 {ENTRY!r} "$@"\n'


def _panel(ink: Ink, title: str, lines: list[str]) -> None:
    print(rule(ink, title))
    for ln in lines:
        print("  " + ln)
    print()


def do_install(ink: Ink, assume_yes: bool) -> int:
    print(render_banner(ink))
    print()

    _panel(ink, "THE JOB", [
        f"{ink.bone('one')} launcher goes down: {ink.cyan(LAUNCHER)}",
        ink.dim(f"→ exec python3 {ENTRY}"),
        "",
        ink.dim("nothing else is touched — no state, no cache, no config, no logs."),
    ])

    on_path = BIN in os.environ.get("PATH", "").split(os.pathsep)
    if not on_path:
        _panel(ink, "ONE THING FIRST", [
            ink.amber(f"{BIN} isn't on your PATH — the command won't resolve until it is:"),
            ink.cyan(f"fish:    fish_add_path {BIN}"),
            ink.cyan(f"bash/zsh: echo 'export PATH=\"{BIN}:$PATH\"' >> ~/.profile"),
        ])

    if not assume_yes and sys.stdin.isatty():
        try:
            ans = input(f"  {ink.cyan('Put Murphy on PATH?')} [Y/n] ").strip().lower()
        except EOFError:
            ans = ""
        if ans in ("n", "no"):
            print("  " + ink.dim("Left it. Murphy shows himself out."))
            return 0

    os.makedirs(BIN, exist_ok=True)
    with open(LAUNCHER, "w", encoding="utf-8") as f:
        f.write(_launcher_text())
    os.chmod(LAUNCHER, 0o755)

    _panel(ink, "DONE", [ink.green("✓ ") + f"{ink.bone(NAME)} is on the job — {ink.dim(LAUNCHER)}"])

    _panel(ink, "AMNESIA — INTACT", [
        ink.green("✓ ") + ink.dim("a ") + ink.bone("scan") + ink.dim(" writes nothing to disk. Ever."),
        ink.green("✓ ") + ink.dim("only ") + ink.bone("murphy fix") + ink.dim(" touches files — backed up, and ") + ink.cyan("murphy undo") + ink.dim(" reverses it."),
        ink.green("✓ ") + ink.dim("this installer added ") + ink.bone("one file") + ink.dim(" and left no trace of its own."),
    ])

    print("  " + ink.dim("try:  ") + ink.cyan("murphy scan") + ink.dim("   ·   ") + ink.cyan("murphy --help"))
    print("  " + ink.dim(f"undo this install:  python3 {os.path.join(HERE, 'install.py')} --uninstall"))
    print("  " + ink.dim(WATERMARK))
    return 0


def do_uninstall(ink: Ink) -> int:
    print(render_banner(ink))
    print()
    if os.path.exists(LAUNCHER):
        with open(LAUNCHER, encoding="utf-8", errors="replace") as f:
            mine = MARKER in f.read()
        if mine:
            os.remove(LAUNCHER)
            _panel(ink, "CLEARED OUT", [ink.green("✓ ") + f"removed {ink.dim(LAUNCHER)}"])
        else:
            _panel(ink, "LEFT ALONE", [
                ink.amber(f"{LAUNCHER} wasn't put here by this installer — not touching it.")])
    else:
        _panel(ink, "NOTHING TO DO", [ink.dim("no launcher here. Murphy was never on PATH.")])
    print("  " + ink.dim("Like he was never here. " + WATERMARK))
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    ink = make_ink(True if "--color" in argv else False if "--no-color" in argv else None)
    if "--uninstall" in argv:
        return do_uninstall(ink)
    return do_install(ink, assume_yes=("--yes" in argv or "-y" in argv or not sys.stdin.isatty()))


if __name__ == "__main__":
    raise SystemExit(main())
