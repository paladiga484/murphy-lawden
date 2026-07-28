"""Declarative community check-packs — the extensible half of the 'library'.

A pack is JSON: a list of rule objects, each describing one read-only check.
Packs are evaluated in-memory and never written to disk (amnesiac), so a pack
can be shipped as a file or streamed from a URL and it leaves no trace.

Rule schema (all fields but id/title/kind/severity optional)::

    {
      "id": "ssh.maxauthtries",
      "title": "SSH MaxAuthTries is capped",
      "severity": "MEDIUM",          # INFO|LOW|MEDIUM|HIGH|CRITICAL
      "family": "linux",             # default: linux
      "kind": "cmd",                 # sysctl | file_mode | path_exists | cmd
      "rationale": "why an attacker cares",
      "fix": "how to remediate",
      "refs": ["CIS ..."],
      ...kind-specific fields...
    }

Kinds & their fields:
  sysctl        key, expect (str or list)                → FAIL if current not in expect
  file_mode     path, max_mode ("640")                   → FAIL if more permissive than max
  path_exists   path, should_exist (bool, default true)  → FAIL if presence != expectation
  cmd           cmd (list[str]), must_match / must_not_match (regex on output)
"""
from __future__ import annotations

import json
import os
import re
from typing import Iterable

from .core import Finding, Host, Severity, Status, read, run, sysctl
from .remedy import chmod_remedy, sysctl_remedy
from .transport import fetch


def _is_remote(source: str) -> bool:
    return source.startswith("dns:") or bool(re.match(r"^https?://", source))


def _remedy_for(rule: dict):
    """Build an autopilot remedy from a rule, so pack findings are fixable too.

    Rules can steer this:
      "no_autofix": true   → advisory only (e.g. a change that could break the host)
      "set": "<value>"     → the exact value to write (else derived from `expect`)
      "risk": "low|medium|high"  → gate it behind a risk budget (default low)
    Only sysctl and file_mode kinds are mechanically safe to auto-apply; path_exists
    (removing a package) and cmd stay advisory."""
    if rule.get("no_autofix"):
        return None
    kind = rule.get("kind")
    if kind == "sysctl":
        val = rule.get("set")
        if val is None:
            expect = rule.get("expect")
            # A list means "any of these pass"; the FIRST entry is the recommended
            # target to write, so order packs with the safe/preferred value first.
            val = (expect[0] if isinstance(expect, list) and expect
                   else None if isinstance(expect, list) else expect)
        if val is None:
            return None
        r = sysctl_remedy(rule["key"], str(val))
        r.risk = rule.get("risk", r.risk)
        return r
    if kind == "file_mode":
        r = chmod_remedy(rule["path"], str(rule.get("max_mode", "644")))
        r.risk = rule.get("risk", r.risk)
        return r
    return None


def load_pack(source: str, transport: str = "direct") -> list[dict]:
    """Read a pack from a local path or a remote source. Never writes to disk.

    Remote sources (http(s):// or dns:) are fetched via the chosen transport
    (direct / tor / dns); local paths ignore transport entirely."""
    if _is_remote(source):
        raw = fetch(source, transport=transport)
    else:
        with open(os.path.expanduser(source), encoding="utf-8") as f:
            raw = f.read()
    data = json.loads(raw)
    if isinstance(data, dict) and "rules" in data:
        data = data["rules"]
    if not isinstance(data, list):
        raise ValueError("pack must be a JSON list of rules (or {\"rules\": [...]})")
    return data


def _finding(rule: dict, status: Status, detail: str = "") -> Finding:
    return Finding(
        id=rule.get("id", "pack.unknown"),
        title=rule.get("title", rule.get("id", "unnamed rule")),
        status=status, severity=Severity.parse(rule.get("severity", "MEDIUM")),
        detail=detail,
        rationale=rule.get("rationale", ""),
        fix=rule.get("fix", ""),
        refs=list(rule.get("refs", [])),
        # Only a real failure gets an autopilot remedy; PASS/SKIP don't need one.
        remedy=_remedy_for(rule) if status == Status.FAIL else None,
    )


def _eval(rule: dict) -> Finding:
    kind = rule.get("kind")

    if kind == "sysctl":
        cur = sysctl(rule["key"])
        if cur is None:
            return _finding(rule, Status.SKIP, "sysctl not present")
        expect = rule["expect"]
        want = set(expect) if isinstance(expect, list) else {str(expect)}
        cur0 = cur.split()[0] if cur else cur
        return _finding(rule, Status.PASS if cur0 in want else Status.FAIL,
                        f"current={cur0} expect={'/'.join(sorted(want))}")

    if kind == "file_mode":
        path = rule["path"]
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            return _finding(rule, Status.SKIP, f"{path} absent/unreadable")
        maxmode = int(str(rule.get("max_mode", "644")), 8)
        too_open = bool(mode & ~maxmode & 0o777)
        return _finding(rule, Status.FAIL if too_open else Status.PASS,
                        f"mode {oct(mode)[2:]} (max {oct(maxmode)[2:]})")

    if kind == "path_exists":
        should = rule.get("should_exist", True)
        exists = os.path.exists(rule["path"])
        return _finding(rule, Status.PASS if exists == should else Status.FAIL,
                        f"exists={exists} expected={should}")

    if kind == "cmd":
        rc, out = run(list(rule["cmd"]))
        if rc == -1:
            return _finding(rule, Status.SKIP, "command unavailable")
        # e.g. a mount check where the path isn't a separate mountpoint: the command
        # exits non-zero with nothing to judge — that's "not applicable", not a fail.
        if rc != 0 and rule.get("skip_if_rc_nonzero"):
            return _finding(rule, Status.SKIP, "not applicable (command returned non-zero)")
        if "must_match" in rule:
            ok = re.search(rule["must_match"], out) is not None
        elif "must_not_match" in rule:
            ok = re.search(rule["must_not_match"], out) is None
        else:
            return _finding(rule, Status.SKIP, "cmd rule missing must_match/must_not_match")
        return _finding(rule, Status.PASS if ok else Status.FAIL, "")

    return _finding(rule, Status.SKIP, f"unknown rule kind: {kind!r}")


def run_pack(rules: list[dict], host: Host, pack_name: str = "pack") -> Iterable[Finding]:
    for rule in rules:
        fam = rule.get("family", "linux")
        # A rule runs when its family is the host family, "*", or a host tag
        # (so family:"android" rules fire on Android — which reports family=linux
        # with an "android" tag — but stay out of the way on a normal Linux box).
        if fam not in ("*", host.family) and fam not in host.tags:
            continue
        try:
            yield _eval(rule)
        except Exception as e:
            yield Finding(id=rule.get("id", f"{pack_name}.error"),
                          title=f"rule '{rule.get('id', '?')}' errored",
                          status=Status.SKIP, detail=str(e))
