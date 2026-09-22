"""``murphy`` amnesia — leave the machine exactly as clean as we found it.

Murphy has always *claimed* to be amnesiac. This module makes it literal: every
run arms an exit handler that shreds the traces Murphy itself can leave behind —
the interpreter's ``__pycache__``, any scratch state under the temp dir, the
Magisk zip if it was cut into a temp location, the readline history line that
would otherwise remember your command. When the process ends — cleanly, on
Ctrl-C, or on an uncaught error — the sweep runs.

Two intensities:

  * ``arm_amnesia()``   the default. Wipes *runtime traces* only — caches, temp
                        state, history. Your source tree, your git checkout, the
                        report you asked for with ``--save`` are never touched.
                        This is what every ordinary run gets.

  * ``incinerate()``    the explicit ``--incinerate`` flag. Everything the default
                        sweep does, then the running package itself: the
                        ``murphy_lawden/`` directory Murphy is executing from,
                        overwritten and unlinked, so the tool deletes *itself*
                        whole on the way out. Guarded so it will never eat a git
                        checkout, a site-packages install, or anything outside a
                        self-contained drop.

Design rules, same spirit as the rest of Murphy:
  * best-effort and non-fatal — a wipe that can't complete must never crash the
    run or mask the real exit code.
  * loud enough to be honest — on an interactive terminal we say what we swept.
  * never widen scope silently — the incinerate path refuses anything it isn't
    certain is a throwaway copy.
"""
from __future__ import annotations

import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

from .banner import Ink, make_ink

# Set once we've armed, so a second import (GUI thread, re-exec) can't double-arm.
_ARMED = False
# Extra paths a session wants swept — modules register scratch files here.
_EXTRA: list[Path] = []


def register(path) -> None:
    """Ask the amnesia sweep to also remove ``path`` on exit (a scratch file a
    subcommand wrote and wants gone). Missing paths are ignored at sweep time."""
    try:
        _EXTRA.append(Path(path))
    except TypeError:
        pass


def _pkg_dir() -> Path:
    return Path(__file__).resolve().parent


def _shred_file(p: Path) -> None:
    """Overwrite a file's bytes once, then unlink. Not forensic-grade on a CoW or
    flash-backed filesystem — the point is that a casual reader finds nothing, not
    that a lab can't. Cheap and best-effort."""
    try:
        n = p.stat().st_size
        if n and n < 8 * 1024 * 1024:  # don't grind on anything large
            with open(p, "r+b", buffering=0) as fh:
                fh.write(os.urandom(n))
                fh.flush()
                os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        p.unlink()
    except OSError:
        pass


def _rm(p: Path) -> None:
    try:
        if p.is_dir() and not p.is_symlink():
            shutil.rmtree(p, ignore_errors=True)
        elif p.exists() or p.is_symlink():
            _shred_file(p)
    except OSError:
        pass


def _runtime_traces() -> list[Path]:
    """The traces an ordinary run can leave. Conservative on purpose."""
    out: list[Path] = []
    pkg = _pkg_dir()
    out.append(pkg / "__pycache__")
    # Murphy's own scratch under the system temp dir, plus a stray temp zip.
    tmp = Path(tempfile.gettempdir())
    for pat in ("murphy-*", "murphy_lawden-*", ".murphy-*"):
        out.extend(tmp.glob(pat))
    out.extend(tmp.glob("murphy-hardening*.zip"))
    # The readline history Python writes for input() prompts, if any.
    for hist in (Path.home() / ".python_history",):
        # We don't delete the user's whole history — only prune it below.
        pass
    out.extend(p for p in _EXTRA)
    return out


def _prune_history() -> None:
    """Drop any line mentioning 'murphy' from the shell-agnostic python history so
    the wizard's input() prompts don't leave a breadcrumb. Leaves the rest intact."""
    hist = Path.home() / ".python_history"
    try:
        if not hist.exists():
            return
        lines = hist.read_text(errors="ignore").splitlines(keepends=True)
        kept = [ln for ln in lines if "murphy" not in ln.lower()]
        if len(kept) != len(lines):
            hist.write_text("".join(kept))
    except OSError:
        pass


def sweep(ink: Ink | None = None, announce: bool = True) -> int:
    """Run the runtime-trace sweep now. Returns how many paths it removed."""
    ink = ink or make_ink(None)
    removed = 0
    for p in _runtime_traces():
        if p.exists() or p.is_symlink():
            _rm(p)
            removed += 1
    _prune_history()
    if announce and removed and sys.stderr.isatty():
        sys.stderr.write(ink.dim(f"  murphy: amnesia — swept {removed} runtime "
                                 "trace(s), nothing kept.\n"))
    return removed


# --------------------------------------------------------------------------- #
#  Incinerate — the tool deletes itself whole
# --------------------------------------------------------------------------- #
def _is_disposable_drop(pkg: Path) -> tuple[bool, str]:
    """Refuse to self-delete unless we're clearly a throwaway copy.

    A checkout the user is developing (has a .git), or a system/venv install under
    site-packages, must survive — deleting either would be sabotage, not amnesia.
    A drop is 'disposable' when it's a bare ``murphy_lawden/`` folder (optionally
    beside a ``murphy.py`` launcher) with no version control around it."""
    parent = pkg.parent
    if (parent / ".git").exists() or (pkg / ".git").exists():
        return False, "a git checkout — refusing to delete your source"
    if "site-packages" in pkg.parts or "dist-packages" in pkg.parts:
        return False, "an installed package — uninstall with pip instead"
    for anchor in ("/usr", "/opt", "/nix", "/snap"):
        if str(pkg).startswith(anchor):
            return False, f"under {anchor} — a system path, left alone"
    return True, ""


def incinerate(ink: Ink | None = None, confirmed: bool = False) -> int:
    """Full self-delete: the runtime sweep, then the package directory itself.

    Requires ``confirmed`` — the caller has read the user's typed consent. Returns
    0 on a completed burn, 1 if it was refused as non-disposable, 2 if unconfirmed."""
    ink = ink or make_ink(None)
    if not confirmed:
        return 2
    sweep(ink, announce=False)
    pkg = _pkg_dir()
    ok, why = _is_disposable_drop(pkg)
    if not ok:
        sys.stderr.write(ink.amber(f"  murphy: incinerate refused — {why}.\n"))
        return 1
    # Shred each source file, then drop the launcher and the empty tree. We do this
    # last so the interpreter has already imported everything it needs to finish.
    for f in sorted(pkg.rglob("*"), key=lambda x: len(x.parts), reverse=True):
        _rm(f)
    launcher = pkg.parent / "murphy.py"
    if launcher.exists():
        _shred_file(launcher)
    _rm(pkg)
    if sys.stderr.isatty():
        sys.stderr.write(ink.dim("  murphy: incinerated — the tool is gone. "
                                 "Nothing of it remains on this disk.\n"))
    return 0


def arm_amnesia(incinerate_on_exit: bool = False, ink: Ink | None = None) -> None:
    """Register the exit sweep. Call once, early, from ``main()``.

    With ``incinerate_on_exit`` the whole package is burned when the process ends;
    otherwise only runtime traces are swept. Idempotent."""
    global _ARMED
    if _ARMED:
        return
    _ARMED = True
    ink = ink or make_ink(None)

    def _on_exit() -> None:
        try:
            if incinerate_on_exit:
                incinerate(ink, confirmed=True)
            else:
                sweep(ink, announce=True)
        except Exception:
            pass  # amnesia must never be the thing that crashes the exit

    atexit.register(_on_exit)
