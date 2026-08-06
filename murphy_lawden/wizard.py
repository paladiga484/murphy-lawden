"""A full-screen setup wizard for the scan → review → harden flow.

This is a *front-end*, not a second engine: it profiles the host (already done by
the caller), lets you read the case file, browse the findings grouped by severity,
and pick one of the same four operating modes the text menu offers. The choice is
handed straight back to the existing fix pipeline in ``cli`` — the wizard never
applies anything itself, so every safety guarantee (dry-run default, restore point,
risk budget, ``murphy undo``) still holds exactly as before.

Opt-in with ``--tui``. It needs a real terminal of a reasonable size; if curses
can't run (piped output, tiny window, no TERM) the caller falls back to the plain
text menu, so nothing is ever lost by trying.

Keys, everywhere: ↑/↓ move · Enter select · Tab/→ next screen · q or Esc back/quit.
"""
from __future__ import annotations

import curses

from .core import Finding, Severity, Status


class WizardUnavailable(RuntimeError):
    """Raised when the terminal can't host the wizard — caller should fall back."""


# Severity → (label, color-pair id). CRITICAL/HIGH fails read red, WARN amber.
_SEV_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "INFO",
}

# Color-pair slots (initialised against the terminal's own default background).
_C_RED = 1
_C_AMBER = 2
_C_GREEN = 3
_C_CYAN = 4
_C_GREY = 5


def _init_colors() -> None:
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:  # pragma: no cover — very old terminals
        bg = curses.COLOR_BLACK
    curses.init_pair(_C_RED, curses.COLOR_RED, bg)
    curses.init_pair(_C_AMBER, curses.COLOR_YELLOW, bg)
    curses.init_pair(_C_GREEN, curses.COLOR_GREEN, bg)
    curses.init_pair(_C_CYAN, curses.COLOR_CYAN, bg)
    curses.init_pair(_C_GREY, curses.COLOR_WHITE, bg)


def _put(win, y: int, x: int, text: str, attr: int = 0) -> None:
    """addstr that clips to the window and never raises on the bottom-right cell."""
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    text = text[: max(0, w - x - 1)]
    try:
        win.addstr(y, x, text, attr)
    except curses.error:
        pass


def _footer(win, keys: str) -> None:
    h, w = win.getmaxyx()
    _put(win, h - 1, 2, keys, curses.color_pair(_C_GREY) | curses.A_DIM)


def _rule(win, y: int, label: str = "") -> None:
    h, w = win.getmaxyx()
    grey = curses.color_pair(_C_GREY) | curses.A_DIM
    if label:
        _put(win, y, 2, "── ", grey)
        _put(win, y, 5, label, curses.A_BOLD)
        start = 5 + len(label) + 1
        _put(win, y, start, "─" * max(0, w - start - 2), grey)
    else:
        _put(win, y, 2, "─" * max(0, w - 4), grey)


def _grade(findings: list[Finding]) -> tuple[int, str, int]:
    """(score, grade, color-pair) — reuses the CLI's scorer so the number matches."""
    from .cli import score as _score, grade as _grade_fn
    s = _score(findings)
    g = _grade_fn(s)
    color = _C_GREEN if g in ("A", "B") else _C_AMBER if g == "C" else _C_RED
    return s, g, color


# --------------------------------------------------------------------------- #
#  Screen 1 — the case file
# --------------------------------------------------------------------------- #
def _case_screen(win, host, findings: list[Finding]) -> str:
    while True:
        win.erase()
        _rule(win, 0, "CASE FILE")

        fails = sum(1 for f in findings if f.status == Status.FAIL)
        warns = sum(1 for f in findings if f.status == Status.WARN)
        passes = sum(1 for f in findings if f.status == Status.PASS)
        s, g, gcolor = _grade(findings)

        rows = [
            ("subject", host.hostname or "(unknown host)"),
            ("system", f"{host.pretty}  ·  kernel {host.kernel}"),
            ("family", f"{host.family} · init={host.init} · libc={host.libc} · pkg={host.pkg}"),
        ]
        env = host.env_label()
        if env:
            rows.append(("running on", env))
        rows.append(("access", "root — full visibility" if host.is_root
                     else "unprivileged — some checks limited"))

        y = 2
        for k, v in rows:
            _put(win, y, 4, f"{k:>11}", curses.color_pair(_C_GREY) | curses.A_DIM)
            _put(win, y, 16, v, curses.A_BOLD if k == "subject" else 0)
            y += 1

        y += 1
        _put(win, y, 4, "grade", curses.color_pair(_C_GREY) | curses.A_DIM)
        _put(win, y, 16, f" {g} ", curses.color_pair(gcolor) | curses.A_REVERSE | curses.A_BOLD)
        _put(win, y, 21, f"{s}/100", curses.color_pair(gcolor) | curses.A_BOLD)
        y += 2

        _put(win, y, 4, f"{fails}", curses.color_pair(_C_RED) | curses.A_BOLD)
        _put(win, y, 6, "failing", curses.color_pair(_C_GREY))
        _put(win, y, 16, f"{warns}", curses.color_pair(_C_AMBER) | curses.A_BOLD)
        _put(win, y, 18, "worth a look", curses.color_pair(_C_GREY))
        _put(win, y, 34, f"{passes}", curses.color_pair(_C_GREEN) | curses.A_BOLD)
        _put(win, y, 36, "passing", curses.color_pair(_C_GREY))

        _footer(win, "Enter/→ review findings   ·   q quit")
        win.refresh()

        key = win.getch()
        if key in (ord("q"), 27):
            return "quit"
        if key in (curses.KEY_ENTER, 10, 13, curses.KEY_RIGHT, ord("\t")):
            return "next"


# --------------------------------------------------------------------------- #
#  Screen 2 — findings browser
# --------------------------------------------------------------------------- #
def _severity_color(f: Finding) -> int:
    if f.status == Status.WARN:
        return _C_AMBER
    return _C_RED if f.severity >= Severity.HIGH else _C_CYAN


def _build_rows(findings: list[Finding]) -> list[tuple[str, object]]:
    """Flat display list: ('head', label) and ('item', Finding), fails then warns."""
    fails = sorted((f for f in findings if f.status == Status.FAIL),
                   key=lambda f: -int(f.severity))
    warns = [f for f in findings if f.status == Status.WARN]
    rows: list[tuple[str, object]] = []
    if fails:
        rows.append(("head", f"FAILURES ({len(fails)})"))
        rows += [("item", f) for f in fails]
    if warns:
        rows.append(("head", f"WORTH A LOOK ({len(warns)})"))
        rows += [("item", f) for f in warns]
    if not rows:
        rows.append(("head", "No failures or warnings — the doors Murphy checks are locked."))
    return rows


def _detail_popup(win, f: Finding) -> None:
    import textwrap
    h, w = win.getmaxyx()
    while True:
        win.erase()
        _rule(win, 0, "FINDING")
        color = _severity_color(f)
        _put(win, 2, 2, f.title, curses.color_pair(color) | curses.A_BOLD)
        _put(win, 3, 2, f"{f.id}  ·  {_SEV_LABEL[f.severity]}",
             curses.color_pair(_C_GREY) | curses.A_DIM)
        y = 5
        wrapw = max(20, w - 6)
        for label, text in (("observed", f.detail), ("why", f.rationale), ("fix", f.fix)):
            if not text:
                continue
            _put(win, y, 2, label, curses.color_pair(_C_CYAN) | curses.A_BOLD)
            y += 1
            for line in textwrap.wrap(text, wrapw):
                if y >= h - 2:
                    break
                _put(win, y, 4, line)
                y += 1
            y += 1
        _footer(win, "any key — back to the list")
        win.refresh()
        win.getch()
        return


def _findings_screen(win, findings: list[Finding]) -> str:
    rows = _build_rows(findings)
    selectable = [i for i, (kind, _) in enumerate(rows) if kind == "item"]
    sel = 0            # index into `selectable`
    top = 0            # first visible row
    while True:
        win.erase()
        _rule(win, 0, "FINDINGS")
        h, w = win.getmaxyx()
        view_h = h - 4  # leave header + footer

        cur_row = selectable[sel] if selectable else -1
        if cur_row >= 0:
            if cur_row < top:
                top = cur_row
            elif cur_row >= top + view_h:
                top = cur_row - view_h + 1

        y = 2
        for ri in range(top, min(len(rows), top + view_h)):
            kind, payload = rows[ri]
            if kind == "head":
                _put(win, y, 2, payload, curses.color_pair(_C_GREY) | curses.A_BOLD)
            else:
                f: Finding = payload
                color = _severity_color(f)
                selected = ri == cur_row
                tag = "FAIL" if f.status == Status.FAIL else "WARN"
                attr = curses.color_pair(color) | (curses.A_REVERSE if selected else 0)
                marker = "›" if selected else " "
                _put(win, y, 2, f"{marker} ", curses.A_BOLD)
                _put(win, y, 4, f"[{tag}] ", attr | curses.A_BOLD)
                _put(win, y, 11, f.title, curses.A_BOLD if selected else 0)
            y += 1

        _footer(win, "↑/↓ move · Enter detail · h harden now · ← back · q quit")
        win.refresh()

        key = win.getch()
        if key in (ord("q"), 27):
            return "quit"
        if key in (curses.KEY_LEFT,):
            return "back"
        if key in (ord("h"), ord("H")):
            return "harden"
        if not selectable:
            continue
        if key == curses.KEY_UP:
            sel = (sel - 1) % len(selectable)
        elif key == curses.KEY_DOWN:
            sel = (sel + 1) % len(selectable)
        elif key in (curses.KEY_ENTER, 10, 13):
            _detail_popup(win, rows[selectable[sel]][1])


# --------------------------------------------------------------------------- #
#  Screen 3 — pick an operating mode
# --------------------------------------------------------------------------- #
_MODES = [
    ("1", "offline", "no network, no sudo — apply only fixes in your own space"),
    ("2", "offline · su", "no network, sudo — apply root-level fixes too, undoable"),
    ("3", "online", "no sudo — pull extra packs, offer to install missing tools"),
    ("4", "online · su", "the full treatment: online + sudo"),
    ("5", "antivirus", "malware sweep: heuristics + ClamAV signature scan"),
    ("0", "no thanks", "leave everything exactly as it is"),
]


def _menu_screen(win) -> str:
    sel = 0
    while True:
        win.erase()
        _rule(win, 0, "HARDEN NOW?")
        _put(win, 2, 2, "Would you like Murphy to harden your system for you?",
             curses.A_BOLD)
        _put(win, 3, 2, "· su = may touch the whole system   ·   no-su = only files you own",
             curses.color_pair(_C_GREY) | curses.A_DIM)
        y = 5
        for i, (num, name, desc) in enumerate(_MODES):
            selected = i == sel
            numcolor = _C_GREEN if num != "0" else _C_GREY
            _put(win, y, 2, "› " if selected else "  ", curses.A_BOLD)
            _put(win, y, 4, f"{num}  ", curses.color_pair(numcolor) | curses.A_BOLD)
            _put(win, y, 7, f"{name:<13}",
                 curses.A_BOLD | (curses.A_REVERSE if selected else 0))
            _put(win, y, 21, desc, curses.color_pair(_C_GREY))
            y += 1
        _footer(win, "↑/↓ move · Enter choose · ← back · q quit")
        win.refresh()

        key = win.getch()
        if key in (ord("q"), 27):
            return "0"
        if key == curses.KEY_LEFT:
            return "back"
        if key == curses.KEY_UP:
            sel = (sel - 1) % len(_MODES)
        elif key == curses.KEY_DOWN:
            sel = (sel + 1) % len(_MODES)
        elif key in (curses.KEY_ENTER, 10, 13):
            return _MODES[sel][0]
        elif chr(key & 0xFF) in {"0", "1", "2", "3", "4", "5"}:
            return chr(key & 0xFF)


# --------------------------------------------------------------------------- #
#  Driver
# --------------------------------------------------------------------------- #
def run_setup(host, findings: list[Finding]) -> str | None:
    """Run the wizard. Returns the chosen mode ("1".."5") or None to leave as-is.

    Raises ``WizardUnavailable`` if the terminal can't host it — the caller should
    then fall back to the plain text menu."""

    def _inner(stdscr) -> str | None:
        _init_colors()
        curses.curs_set(0)
        h, w = stdscr.getmaxyx()
        if h < 18 or w < 62:
            raise WizardUnavailable(f"terminal too small ({w}×{h}; need ≥62×18)")

        state = "case"
        while True:
            if state == "case":
                if _case_screen(stdscr, host, findings) == "quit":
                    return None
                state = "findings"
            elif state == "findings":
                r = _findings_screen(stdscr, findings)
                if r == "quit":
                    return None
                if r == "back":
                    state = "case"
                else:  # "harden"
                    state = "menu"
            elif state == "menu":
                r = _menu_screen(stdscr)
                if r == "back":
                    state = "findings"
                    continue
                return r if r in {"1", "2", "3", "4", "5"} else None

    try:
        curses.curs_set(0)
    except curses.error:
        pass
    try:
        return curses.wrapper(_inner)
    except curses.error as e:
        raise WizardUnavailable(str(e)) from e
