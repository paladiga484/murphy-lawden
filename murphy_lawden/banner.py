"""Terminal presentation: a block wordmark with rising smoke, and case-file chrome.

Colour is opt-out (NO_COLOR env, non-tty, or --no-color). Palette is restrained:
bone-white wordmark, grey smoke, a single red accent — a report, not a demo.
"""
from __future__ import annotations

import os
import sys

from . import __version__

SLOGAN = "im just a guy you call when everything that couldve went wrong went wrong"

# Grey smoke drifting up off the title (rendered dim).
_SMOKE = r"""
                            ( )
                          )  ~  (
                         ~  ( )  ~
"""

# Block wordmark (ANSI-shadow style). Two halves, deliberately lit differently:
# MURPHY reads bone-white (the name you call), LAWDEN sits back in a greyer
# shade — the surname half recedes like it's half-lost in the smoke.
_MURPHY = r"""
███╗   ███╗██╗   ██╗██████╗ ██████╗ ██╗  ██╗██╗   ██╗
████╗ ████║██║   ██║██╔══██╗██╔══██╗██║  ██║╚██╗ ██╔╝
██╔████╔██║██║   ██║██████╔╝██████╔╝███████║ ╚████╔╝
██║╚██╔╝██║██║   ██║██╔══██╗██╔═══╝ ██╔══██║  ╚██╔╝
██║ ╚═╝ ██║╚██████╔╝██║  ██║██║     ██║  ██║   ██║
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝   ╚═╝
"""
_LAWDEN = r"""
██╗      █████╗ ██╗    ██╗██████╗ ███████╗███╗   ██╗
██║     ██╔══██╗██║    ██║██╔══██╗██╔════╝████╗  ██║
██║     ███████║██║ █╗ ██║██║  ██║█████╗  ██╔██╗ ██║
██║     ██╔══██║██║███╗██║██║  ██║██╔══╝  ██║╚██╗██║
███████╗██║  ██║╚███╔███╔╝██████╔╝███████╗██║ ╚████║
╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝
"""


class Ink:
    def __init__(self, enabled: bool):
        self.on = enabled

    def _w(self, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if self.on else s

    def bone(self, s):   return self._w("97", s)         # bright white
    def ash(self, s):    return self._w("38;5;244", s)   # mid grey (the LAWDEN half)
    def dim(self, s):    return self._w("90", s)         # grey (smoke)
    def amber(self, s):  return self._w("33", s)      # warning
    def blood(self, s):  return self._w("31", s)      # red
    def red_b(self, s):  return self._w("1;91", s)    # bright red, bold
    def green(self, s):  return self._w("32", s)
    def cyan(self, s):   return self._w("36", s)
    def bold(self, s):   return self._w("1", s)


def make_ink(force: bool | None = None) -> Ink:
    if force is not None:
        return Ink(force)
    enabled = (
        sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
        and os.environ.get("TERM") not in (None, "dumb")
    )
    return Ink(enabled)


WATERMARK = "made by paladiga484"


def render_banner(ink: Ink) -> str:
    lines = [ink.dim(row) for row in _SMOKE.strip("\n").splitlines()]
    lines += [ink.bone(row) for row in _MURPHY.strip("\n").splitlines()]
    lines += [ink.ash(row) for row in _LAWDEN.strip("\n").splitlines()]
    lines.append("")
    lines.append(ink.blood("“") + ink.dim(SLOGAN) + ink.blood("”"))
    lines.append(ink.dim(f"defensive hardening toolkit · v{__version__} · the fixer"))
    # Amnesiac: Murphy leaves no trace on disk. Watermark stays with the work.
    lines.append(ink.dim("amnesiac — nothing written to disk · ") + ink.dim(WATERMARK))
    return "\n".join(lines)


def rule(ink: Ink, label: str = "", width: int = 64) -> str:
    if label:
        return ink.dim("── ") + ink.bold(label) + " " + ink.dim("─" * max(0, width - len(label) - 4))
    return ink.dim("─" * width)
