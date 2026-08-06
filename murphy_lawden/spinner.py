"""Animated 'working' indicator: the fixer, wreathed in drifting smoke, shown
while a long operation runs.

Rules that keep it from ever corrupting output:
  * stderr only, and only when stderr is a real TTY (never in pipes / --json).
  * animation runs on a daemon thread; the operation runs normally on the main
    thread inside a `with working(...)` block.
  * on exit it erases itself, restoring the cursor — it leaves no trace, same as
    the rest of Murphy.
  * on a terminal too short for the full figure it degrades to a one-line smoke
    spinner instead of fighting the scroll region.
"""
from __future__ import annotations

import os
import shutil
import sys
import threading
import time

from .banner import Ink, make_ink

# The fixer, mid-drag — downscaled 2× from assets_working.txt so the spinner
# stays compact (9 rows) instead of swallowing the screen.
_FIGURE = r"""⠀⠀⠀⣠⡿⢷⣶⠶⢤⡀
⠀⢠⠞⣿⢁⢀⠹⣧⠠⠙⢦⡀
⠀⡏⠆⣿⡐⠁⣀⣹⣦⡴⠾⠷⣄⡀
⠈⣧⣴⢾⣷⣿⡏⠁⠉⠛⠶⣶⠶⠛⠁
⢰⣇⣰⣿⡇⠀⠀⠀⠀⠀⠀⢸⡄
⠙⠉⡽⣿⣿⠂⠀⠀⠀⠀⠀⡖⠃
⢀⡾⠡⡐⢈⢙⠲⢤⣀⡀⠀⡟⢳⡀⢀⣤⣄
⠻⠶⢤⣬⣄⣂⡈⠒⠝⢯⡉⠀⠀⠻⣾⣿⠏
⠀⠀⠀⠀⠀⠉⠉⠛⠳⠷⣽⡆"""

_FIG_LINES = _FIGURE.splitlines()
_FIG_W = max(len(l) for l in _FIG_LINES)

# Smoke rises above the figure's head (roughly columns 3–7). Four hand-cut
# frames cycled to read as a curling, drifting plume.
_SMOKE_FRAMES = [
    ["    ( )   ",
     "   )   (  ",
     "    ~ ‘   "],
    ["   ~  °   ",
     "    ( )   ",
     "   )   (  "],
    ["  )   (   ",
     "   ‘ (    ",
     "    ) ~   "],
    ["    °     ",
     "   ( ~ )  ",
     "    ) (   "],
]
_SMOKE_H = 3
_SPIN = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

_HIDE, _SHOW = "\033[?25l", "\033[?25h"


def _use(stream, enabled: bool | None) -> bool:
    if enabled is False:
        return False
    return bool(getattr(stream, "isatty", lambda: False)()) \
        and os.environ.get("NO_COLOR") is None \
        and os.environ.get("TERM") not in (None, "dumb")


class Working:
    """Context manager. `with Working('scanning host', ink): long_call()`."""

    def __init__(self, label: str, ink: Ink | None = None,
                 stream=None, enabled: bool | None = None, interval: float = 0.12):
        self.label = label
        self.ink = ink or make_ink(None)
        self.stream = stream if stream is not None else sys.stderr
        self.enabled = _use(self.stream, enabled)
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._full = False  # figure mode vs. one-line fallback
        self._height = 0

    # -- lifecycle --------------------------------------------------------- #
    def __enter__(self) -> "Working":
        if not self.enabled:
            return self
        rows = shutil.get_terminal_size((80, 24)).lines
        self._full = rows >= len(_FIG_LINES) + _SMOKE_H + 2
        self._height = (len(_FIG_LINES) + _SMOKE_H + 1) if self._full else 1
        self.stream.write(_HIDE)
        self.stream.flush()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> bool:
        self._stop.set()
        if self._thread:
            self._thread.join()
        return False  # never swallow the operation's exception

    # -- rendering --------------------------------------------------------- #
    def _frame_full(self, i: int) -> str:
        ink = self.ink
        smoke = _SMOKE_FRAMES[i % len(_SMOKE_FRAMES)]
        out = [ink.dim(l.ljust(_FIG_W)) for l in smoke]
        out += [ink.ash(l.ljust(_FIG_W)) for l in _FIG_LINES]
        spin = ink.red_b(_SPIN[i % len(_SPIN)])
        out.append(f"{spin} {ink.bone(self.label)}{ink.dim(' …')}".ljust(_FIG_W))
        return "\n".join(out)

    def _frame_line(self, i: int) -> str:
        ink = self.ink
        puff = ["· ˚", "˚ ·", ": °", "° :"][i % 4]
        spin = ink.red_b(_SPIN[i % len(_SPIN)])
        return f"\r{spin} {ink.dim(puff)} {ink.bone(self.label)}{ink.dim(' …')}\033[K"

    def _run(self) -> None:
        i, first = 0, True
        try:
            while not self._stop.is_set():
                if self._full:
                    if not first:
                        self.stream.write(f"\033[{self._height - 1}A\r")
                    self.stream.write(self._frame_full(i))
                else:
                    self.stream.write(self._frame_line(i))
                self.stream.flush()
                first = False
                i += 1
                self._stop.wait(self.interval)
        finally:
            # Erase the whole block and restore the cursor — leave no trace.
            if self._full and not first:
                self.stream.write(f"\033[{self._height - 1}A\r\033[J")
            else:
                self.stream.write("\r\033[K")
            self.stream.write(_SHOW)
            self.stream.flush()


def working(label: str, ink: Ink | None = None,
            enabled: bool | None = None, stream=None) -> Working:
    """Convenience factory so callers read `with working('…', ink):`."""
    return Working(label, ink=ink, enabled=enabled, stream=stream)
