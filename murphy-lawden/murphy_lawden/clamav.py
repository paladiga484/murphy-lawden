"""ClamAV bridge — the signature-scanning half of ``murphy av``.

Murphy doesn't reimplement an AV engine; when ClamAV is present it drives it and
folds the results into the same Finding/report model as everything else. All of it
is opt-in and prompted (a recursive scan is slow), and read-only — clamscan reports,
it doesn't quarantine unless you tell Murphy to act.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

from .core import have, run

DB_DIR = "/var/lib/clamav"
DEFAULT_TARGETS = ["~", "/tmp", "/var/tmp", "/dev/shm"]


def available() -> bool:
    return have("clamscan")


def can_update() -> bool:
    return have("freshclam")


@dataclass
class DbStatus:
    present: bool
    age_days: float | None
    detail: str


def db_status() -> DbStatus:
    newest = 0.0
    try:
        for fn in os.listdir(DB_DIR):
            if fn.endswith((".cvd", ".cld")):
                newest = max(newest, os.stat(os.path.join(DB_DIR, fn)).st_mtime)
    except OSError:
        return DbStatus(False, None, f"{DB_DIR} not readable")
    if newest == 0.0:
        return DbStatus(False, None, f"no signature DB in {DB_DIR}")
    age = (time.time() - newest) / 86400
    return DbStatus(True, age, f"signatures {age:.0f} day(s) old")


def update(use_sudo: bool = False, timeout: int = 600) -> tuple[bool, str]:
    """Refresh signatures via freshclam (online). Needs write access to the DB dir."""
    if not can_update():
        return False, "freshclam not installed"
    cmd = ["freshclam"]
    if use_sudo and not (hasattr(os, "geteuid") and os.geteuid() == 0):
        cmd = ["sudo"] + cmd
    rc, out = run(cmd, timeout=timeout)
    return rc == 0, out


def _expand(targets: list[str]) -> list[str]:
    seen, out = set(), []
    for t in targets:
        p = os.path.expanduser(t)
        if p not in seen and os.path.exists(p):
            seen.add(p)
            out.append(p)
    return out


@dataclass
class ScanResult:
    scanned_paths: list[str]
    infected: list[tuple[str, str]]   # (path, signature)
    rc: int
    raw: str


def scan(targets: list[str] | None = None, timeout: int = 1800) -> ScanResult:
    """Recursively scan `targets` (default: home + scratch dirs) for known malware.

    clamscan exit codes: 0 = clean, 1 = virus found, 2 = error. We parse the
    `path: Signature FOUND` lines regardless."""
    paths = _expand(targets or DEFAULT_TARGETS)
    if not paths:
        return ScanResult([], [], 0, "no existing targets to scan")
    rc, out = run(["clamscan", "-r", "-i", "--no-summary", "--stdout", *paths], timeout=timeout)
    infected = []
    for line in out.splitlines():
        if line.rstrip().endswith("FOUND"):
            path, _, sig = line.rpartition(":")
            infected.append((path.strip(), sig.replace("FOUND", "").strip()))
    return ScanResult(paths, infected, rc, out)
