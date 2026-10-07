"""Where `ds` keeps its undo ledger and quarantine — per OS, always the real user's.

The ledger is the only thing `ds unlock` trusts, so it records the ORIGINAL value
of everything the first time it is changed, and a later `lock` never overwrites
an original it already holds.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

WINDOWS = sys.platform == "win32"


def state_dir() -> Path:
    if WINDOWS:
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local") / "murphy"
    return Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state") / "murphy"


LEDGER = state_dir() / "ds.ledger.json"
QUARANTINE = state_dir() / "quarantine"


def default_folder() -> Path:
    return Path.home() / "Torrents"


def load() -> dict:
    try:
        return json.loads(LEDGER.read_text())
    except (OSError, ValueError):
        return {}


def save(ledger: dict) -> None:
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    tmp = LEDGER.with_suffix(".tmp")
    tmp.write_text(json.dumps(ledger, indent=2))
    os.replace(tmp, LEDGER)


def remember(ledger: dict, section: str, key: str, original) -> None:
    """Record `original` for section/key unless an original is already on file."""
    ledger.setdefault(section, {}).setdefault(key, original)
    save(ledger)
