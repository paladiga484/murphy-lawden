# Areas, Plain Verbs and Short/Long Flags — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `murphy -f ssh` / `murphy --fix ssh` / `murphy fix ssh` all work; every area explains what it does, needs, changes and how to undo it, and Murphy asks for exactly that before running anything — while every existing command keeps working.

**Architecture:** A new front layer (`argv.py` → `runner.py`) parses verb-first commands into a `Command`, looks up `Area`s and their `Manifest`s (`areas/`), renders one ask from the manifests, elevates once if needed, then calls the existing implementations in `cli.py`, `ds/`, `ezopt.py`, `credspoof.py`, `collapse.py`, `duress.py`, `panic.py`, `magiskmod.py`. Anything that looks like a legacy invocation goes to the untouched `cli.main` path. Restore points gain tags so `murphy -u ssh` undoes the latest ssh fix only.

**Tech Stack:** Python 3 stdlib only (argparse not used for the new layer — the grammar is hand-parsed so short flags stack and verbs can be words), `unittest`.

**Spec:** `docs/superpowers/specs/2026-10-07-areas-and-flags-design.md`

## Global Constraints

- Stdlib only. No new dependencies (README badge: "dependencies: stdlib only").
- Tests: `python3 -m unittest discover -s tests -v`, run from the repo root.
- A check never writes to disk ("amnesiac"); a `check` manifest has empty `changes` and empty `writes`.
- Exit codes: 0 ok, 1 FAIL findings (check) / action failed, 2 usage error, 3 declined at the ask.
- `-y` never skips the ask for a dangerous action; it prints why.
- Exactly one action per run; two actions is a usage error naming both.
- Old subcommands and old flags keep working unchanged.
- Identity for commits: repo-local git config is already paladiga484 — don't change it.
- `fw.*` finding ids are **firmware** (fwupd/Secure Boot/ESP), not firewall. The firewall check is `net.firewall`. (The spec's area table lists `fw.*` under net — that is wrong; route `fw.` → firmware.)

## Review Focus

1. **`murphy` with stdin not a TTY (cron, pipe) and an ask needed** — must not hang on `input()`; treat as declined (exit 3) unless `-y` and calm. Test in Task 6.
2. **`sudo` re-exec loop** — after elevation the child must not ask again and must not try to elevate again. Test in Task 6 (hidden `--consented` flag, `os.geteuid` patched).
3. **Area word that is also a legacy subcommand** (`murphy clean`, `murphy fix`, `murphy undo`, `murphy panic`) — goes to the new layer; `murphy fix --su --risk medium` (legacy flags) still goes to legacy. Test in Task 4.
4. **`murphy -x file -- --gpu`** style passthrough and file names that start with `-`** — everything after `--` is passthrough, a lone target after `-x` is taken verbatim. Test in Task 4.
5. **`murphy -u ssh` when the only restore points are untagged (made before this change)** — must say "no ssh restore point" and change nothing, never fall back to undoing an unrelated job. Test in Task 3.

---

## File Structure

| File | Responsibility |
|---|---|
| `murphy_lawden/manifest.py` (create) | `Needs`, `Manifest`, merging, help/explain rendering, ask rendering |
| `murphy_lawden/areas/__init__.py` (create) | `Area`, the registry, `resolve()` with aliases + did-you-mean |
| `murphy_lawden/areas/catalog.py` (create) | the 12 areas' data: aliases, covers, manifests |
| `murphy_lawden/areas/routing.py` (create) | `area_for(finding_id)` prefix rules |
| `murphy_lawden/argv.py` (create) | `Command`, `parse(argv)`, `is_legacy(argv)`, `UsageError` |
| `murphy_lawden/situations.py` (create) | `SITUATIONS` table + `expand(name)` |
| `murphy_lawden/runner.py` (create) | `run(cmd, ink)`: ask, elevate, dispatch to existing code |
| `murphy_lawden/helptext.py` (create) | top-level `murphy -h`, per-area help, `-l` list |
| `murphy_lawden/remedy.py` (modify) | restore-point tags; `undo_latest(tag=None)` |
| `murphy_lawden/cli.py` (modify `main`, `do_fix`) | route new vs legacy; legacy tip line; pass tags to `Fixer` |
| `tests/__init__.py`, `tests/test_*.py` (create) | unittest suites |
| `README.md` (modify) | new usage block |

---

### Task 1: Routing — every finding id belongs to an area

**Files:**
- Create: `murphy_lawden/areas/__init__.py` (empty for now, one docstring line), `murphy_lawden/areas/routing.py`
- Create: `tests/__init__.py` (empty), `tests/test_routing.py`

**Interfaces:**
- Produces: `routing.area_for(finding_id: str) -> str` returning one of `"cage","net","ssh","users","kernel","disk","apps","privacy","virus","firmware","phone","emergency","misc"`; `routing.AREA_NAMES: tuple[str, ...]` (the 12 real areas, no `misc`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_routing.py
import unittest
from murphy_lawden.areas.routing import area_for, AREA_NAMES

CASES = {
    "ssh.root_login": "ssh",
    "pack.perm/etc/ssh/ssh_config": "ssh",
    "net.firewall": "net", "net.listen": "net", "pack.net.ipv4_forward": "net",
    "fw.secureboot": "firmware", "fw.hsi": "firmware", "fw.esp": "firmware",
    "acct.empty_password": "users", "sudo.nopasswd": "users",
    "perm/etc/shadow": "users", "perm/etc/passwd": "users",
    "pack.perm/etc/sudoers": "users", "pack.perm/etc/security/opasswd": "users",
    "pack.perm/etc/login.defs": "users",
    "kernel.lockdown": "kernel", "sysctl.kernel.kptr_restrict": "kernel",
    "pack.kernel.dmesg": "kernel", "pack.sysrq": "kernel", "pack.kexec_disabled": "kernel",
    "pack.perf_paranoid": "kernel", "pack.ftrace_restrict": "kernel",
    "pack.userns_clone": "kernel", "pack.vm.mmap_min": "kernel",
    "disk.luks": "disk", "pack.mount/tmp": "disk", "pack.fs.suid_dumpable": "disk",
    "pack.perm/etc/cron.d": "disk", "pack.tmp_sticky": "disk", "pack.cron_perm": "disk",
    "pack.dev.shm": "disk", "perm/etc/group-": "users",
    "systemd.exposure": "apps", "pack.absent/usr/sbin/telnetd": "apps", "pack.no_rsh": "apps",
    "mal.ld_preload": "virus", "pack.ioc/tmp/xmrig": "virus",
    "android.selinux": "phone",
    "something.unknown": "misc",
}


class RoutingTest(unittest.TestCase):
    def test_known_prefixes(self):
        for fid, area in CASES.items():
            with self.subTest(fid=fid):
                self.assertEqual(area_for(fid), area)

    def test_area_names(self):
        self.assertEqual(len(AREA_NAMES), 12)
        self.assertNotIn("misc", AREA_NAMES)

    def test_every_registered_check_routes(self):
        # Run the real checks on this host; none may land in misc. Slow (~a minute).
        from murphy_lawden import cli
        from murphy_lawden.banner import make_ink
        from murphy_lawden.core import detect_host
        args = cli.build_parser().parse_args(["scan", "--no-prompt"])
        findings = cli.assemble_findings(detect_host(), args, False, make_ink(False))
        stray = sorted({f.id for f in findings if area_for(f.id) == "misc"})
        self.assertEqual(stray, [], f"unrouted finding ids: {stray}")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_routing -v`
Expected: FAIL / ERROR — `ModuleNotFoundError: No module named 'murphy_lawden.areas'`

- [ ] **Step 3: Write minimal implementation**

```python
# murphy_lawden/areas/__init__.py
"""Murphy's areas: what each part of hardening covers, needs and changes."""
```

```python
# murphy_lawden/areas/routing.py
"""Which area a finding belongs to, by its id prefix.

Order matters: the first matching prefix wins, so specific paths
(``pack.perm/etc/ssh``) come before the general family (``pack.perm``).
"""
from __future__ import annotations

AREA_NAMES: tuple[str, ...] = (
    "cage", "net", "ssh", "users", "kernel", "disk",
    "apps", "privacy", "virus", "firmware", "phone", "emergency",
)

_RULES: tuple[tuple[str, str], ...] = (
    # virus first: IOC paths can look like anything else
    ("mal.", "virus"), ("pack.ioc", "virus"),
    ("ssh.", "ssh"), ("pack.perm/etc/ssh", "ssh"),
    ("acct.", "users"), ("sudo.", "users"),
    ("pack.perm/etc/sudoers", "users"), ("pack.perm/etc/security", "users"),
    ("pack.perm/etc/login", "users"),
    ("perm/etc/passwd", "users"), ("perm/etc/shadow", "users"),
    ("perm/etc/group", "users"), ("perm/etc/gshadow", "users"),
    ("net.", "net"), ("pack.net", "net"),
    ("fw.", "firmware"),
    ("kernel.", "kernel"), ("sysctl.", "kernel"), ("pack.kernel", "kernel"),
    ("pack.sysrq", "kernel"), ("pack.kexec", "kernel"), ("pack.perf", "kernel"),
    ("pack.ftrace", "kernel"), ("pack.userns", "kernel"), ("pack.vm", "kernel"),
    ("disk.", "disk"), ("perm/", "disk"), ("pack.mount", "disk"), ("pack.fs", "disk"),
    ("pack.perm", "disk"), ("pack.tmp_sticky", "disk"), ("pack.cron_perm", "disk"),
    ("pack.dev", "disk"),
    ("systemd.", "apps"), ("pack.absent", "apps"), ("pack.no_", "apps"),
    ("android.", "phone"),
)


def area_for(finding_id: str) -> str:
    for prefix, area in _RULES:
        if finding_id.startswith(prefix):
            return area
    return "misc"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_routing -v`
Expected: PASS (3 tests). If `test_every_registered_check_routes` lists stray ids, add a rule for each to `_RULES` (pick the area by what the check inspects) and add the id to `CASES`; do not widen a prefix to catch everything.

- [ ] **Step 5: Commit**

```bash
git add murphy_lawden/areas tests
git commit -m "areas: route every finding id to an area"
```

---

### Task 2: Manifests — does / needs / changes / undo, rendered

**Files:**
- Create: `murphy_lawden/manifest.py`
- Test: `tests/test_manifest.py`

**Interfaces:**
- Produces:
  - `Needs(root: bool = False, network: bool = False, devices: tuple[str, ...] = (), reads: tuple[str, ...] = (), writes: tuple[str, ...] = ())`, frozen dataclass.
  - `Manifest(area: str, action: str, does: str, needs: Needs, changes: tuple[str, ...], undo: str, platforms: frozenset[str], danger: str = "calm")`, frozen dataclass. `action` ∈ `{"check","fix","undo"}`; `danger` ∈ `{"calm","dangerous"}`.
  - `merge_needs(ms: list[Manifest]) -> Needs` — OR of booleans, de-duplicated tuples in first-seen order.
  - `is_dangerous(ms: list[Manifest]) -> bool`
  - `render_manifest(m: Manifest) -> list[str]` — plain lines (no colour) for `--help`/`--explain`.
  - `render_ask(ms: list[Manifest]) -> list[str]` — the ask block lines, without the final question.
  - `needs_line(n: Needs) -> str` — e.g. `"root (sudo, asked once) · no network · no devices"`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_manifest.py
import unittest
from murphy_lawden.manifest import (Manifest, Needs, merge_needs, is_dangerous,
                                    render_manifest, render_ask, needs_line)

SSH_FIX = Manifest(
    area="ssh", action="fix",
    does="Turns off password and root login for sshd.",
    needs=Needs(root=True, reads=("/etc/ssh/sshd_config",),
                writes=("/etc/ssh/sshd_config.d/10-murphy-*.conf",)),
    changes=("PasswordAuthentication no", "PermitRootLogin no"),
    undo="murphy -u ssh", platforms=frozenset({"linux"}))
KERNEL_FIX = Manifest(
    area="kernel", action="fix", does="Tightens kernel sysctls.",
    needs=Needs(root=True, writes=("/etc/sysctl.d/60-murphy.conf",)),
    changes=("kernel.kptr_restrict=2",), undo="murphy -u kernel",
    platforms=frozenset({"linux"}))
WIPE = Manifest(
    area="emergency", action="fix", does="Opens the emergency menu.",
    needs=Needs(root=True), changes=("depends on the door you pick",),
    undo="each door prints its own undo", platforms=frozenset({"linux"}),
    danger="dangerous")


class ManifestTest(unittest.TestCase):
    def test_merge_needs(self):
        n = merge_needs([SSH_FIX, KERNEL_FIX])
        self.assertTrue(n.root)
        self.assertFalse(n.network)
        self.assertEqual(n.writes, ("/etc/ssh/sshd_config.d/10-murphy-*.conf",
                                    "/etc/sysctl.d/60-murphy.conf"))

    def test_merge_dedupes(self):
        self.assertEqual(merge_needs([SSH_FIX, SSH_FIX]).writes, SSH_FIX.needs.writes)

    def test_dangerous(self):
        self.assertFalse(is_dangerous([SSH_FIX, KERNEL_FIX]))
        self.assertTrue(is_dangerous([SSH_FIX, WIPE]))

    def test_needs_line(self):
        self.assertEqual(needs_line(Needs()), "nothing special · no network · no devices")
        self.assertEqual(needs_line(Needs(root=True, network=True, devices=("wlan0",))),
                         "root (sudo, asked once) · network · devices: wlan0")

    def test_render_manifest_has_every_part(self):
        text = "\n".join(render_manifest(SSH_FIX))
        for part in ("does", "needs", "changes", "undo", "runs on",
                     "PasswordAuthentication no", "murphy -u ssh", "linux"):
            self.assertIn(part, text)

    def test_render_ask(self):
        text = "\n".join(render_ask([SSH_FIX, KERNEL_FIX]))
        self.assertIn("murphy will: fix ssh, fix kernel", text)
        self.assertIn("root (sudo, asked once)", text)
        self.assertIn("/etc/sysctl.d/60-murphy.conf", text)
        self.assertIn("murphy -u ssh", text)
        self.assertNotIn("DANGEROUS", text)
        self.assertIn("DANGEROUS", "\n".join(render_ask([WIPE])))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_manifest -v`
Expected: ERROR — `No module named 'murphy_lawden.manifest'`

- [ ] **Step 3: Write minimal implementation**

```python
# murphy_lawden/manifest.py
"""What an area action does, needs, changes, and how to undo it.

The same data drives ``murphy -h <area>``, ``murphy -e <area>`` and the ask
shown before anything runs, so the help can never drift from what happens.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Needs:
    root: bool = False
    network: bool = False
    devices: tuple[str, ...] = ()
    reads: tuple[str, ...] = ()
    writes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Manifest:
    area: str
    action: str                 # check | fix | undo
    does: str
    needs: Needs
    changes: tuple[str, ...]
    undo: str
    platforms: frozenset[str]
    danger: str = "calm"        # calm | dangerous


def _uniq(items) -> tuple[str, ...]:
    seen: list[str] = []
    for i in items:
        if i not in seen:
            seen.append(i)
    return tuple(seen)


def merge_needs(ms: list[Manifest]) -> Needs:
    return Needs(
        root=any(m.needs.root for m in ms),
        network=any(m.needs.network for m in ms),
        devices=_uniq(d for m in ms for d in m.needs.devices),
        reads=_uniq(r for m in ms for r in m.needs.reads),
        writes=_uniq(w for m in ms for w in m.needs.writes),
    )


def is_dangerous(ms: list[Manifest]) -> bool:
    return any(m.danger == "dangerous" for m in ms)


def needs_line(n: Needs) -> str:
    parts = ["root (sudo, asked once)" if n.root else "nothing special",
             "network" if n.network else "no network",
             ("devices: " + ", ".join(n.devices)) if n.devices else "no devices"]
    return " · ".join(parts)


def render_manifest(m: Manifest) -> list[str]:
    lines = [f"{m.action} {m.area}" + ("   [DANGEROUS — asks at every step]" if m.danger == "dangerous" else ""),
             f"  does     {m.does}",
             f"  needs    {needs_line(m.needs)}"]
    if m.needs.reads:
        lines.append(f"  reads    {', '.join(m.needs.reads)}")
    lines.append(f"  writes   {', '.join(m.needs.writes) if m.needs.writes else 'nothing'}")
    lines.append(f"  changes  {'; '.join(m.changes) if m.changes else 'nothing — look only'}")
    lines.append(f"  undo     {m.undo}")
    lines.append(f"  runs on  {', '.join(sorted(m.platforms))}")
    return lines


def render_ask(ms: list[Manifest]) -> list[str]:
    n = merge_needs(ms)
    head = "murphy will: " + ", ".join(f"{m.action} {m.area}" for m in ms)
    lines = [head]
    if is_dangerous(ms):
        lines.append("  DANGEROUS — you will be asked to type a confirmation at every step")
    for m in ms:
        lines.append(f"  does     {m.area}: {m.does}")
    lines.append(f"  needs    {needs_line(n)}")
    lines.append(f"  writes   {', '.join(n.writes) if n.writes else 'nothing'}")
    undos = _uniq(m.undo for m in ms if m.action != "undo")
    if undos:
        lines.append(f"  undo     {' · '.join(undos)}")
    return lines
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_manifest -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add murphy_lawden/manifest.py tests/test_manifest.py
git commit -m "manifest: does/needs/changes/undo model, help and ask rendering"
```

---

### Task 3: Tagged restore points — `undo` per area

**Files:**
- Modify: `murphy_lawden/remedy.py` (`RestorePoint.__init__`, `commit`, `latest`; `Fixer.__init__`; `undo_latest`)
- Test: `tests/test_undo_tags.py`

**Interfaces:**
- Produces: `RestorePoint(tags: tuple[str, ...] = ())`; journal JSON gains `"tags": [...]`; `RestorePoint.latest(tag: str | None = None) -> Path | None` (with a tag, only points whose journal lists it; untagged legacy points never match a tag); `Fixer(dry_run: bool = True, tags: tuple[str, ...] = ())`; `undo_latest(tag: str | None = None) -> tuple[bool, str]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_undo_tags.py
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from murphy_lawden import remedy


class UndoTagsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "restore"
        self.p = mock.patch.object(remedy, "_state_dir", return_value=self.state)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.tmp.cleanup()

    def _point(self, name, tags, target):
        d = self.state / name
        d.mkdir(parents=True)
        body = {"id": name, "actions": [{"type": "remove_file", "path": str(target)}]}
        if tags is not None:
            body["tags"] = tags
        (d / "journal.json").write_text(json.dumps(body))

    def test_tagged_undo_only_touches_that_area(self):
        a, b = Path(self.tmp.name) / "a", Path(self.tmp.name) / "b"
        a.write_text("x"); b.write_text("x")
        self._point("20261007-100000", ["ssh"], a)
        self._point("20261007-110000", ["kernel"], b)
        ok, msg = remedy.undo_latest("ssh")
        self.assertTrue(ok, msg)
        self.assertFalse(a.exists())
        self.assertTrue(b.exists())

    def test_untagged_legacy_point_never_matches_a_tag(self):
        a = Path(self.tmp.name) / "a"
        a.write_text("x")
        self._point("20261001-100000", None, a)
        ok, msg = remedy.undo_latest("ssh")
        self.assertFalse(ok)
        self.assertIn("no ssh restore point", msg)
        self.assertTrue(a.exists())

    def test_untagged_undo_still_takes_latest(self):
        a = Path(self.tmp.name) / "a"
        a.write_text("x")
        self._point("20261001-100000", None, a)
        ok, _ = remedy.undo_latest()
        self.assertTrue(ok)
        self.assertFalse(a.exists())

    def test_commit_writes_tags(self):
        rp = remedy.RestorePoint(tags=("ssh",))
        rp.journal.append({"type": "remove_file", "path": "/nonexistent"})
        rp.commit()
        data = json.loads((rp.dir / "journal.json").read_text())
        self.assertEqual(data["tags"], ["ssh"])

    def test_fixer_passes_tags(self):
        f = remedy.Fixer(dry_run=False, tags=("net",))
        self.assertEqual(f.rp.tags, ("net",))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_undo_tags -v`
Expected: FAIL — `TypeError: undo_latest() takes 0 positional arguments but 1 was given` (and similar for `tags=`).

- [ ] **Step 3: Write minimal implementation**

In `murphy_lawden/remedy.py`:

```python
class RestorePoint:
    """A timestamped backup + undo journal for one ``fix`` run."""

    def __init__(self, tags: tuple[str, ...] = ()):
        self.id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.dir = _state_dir() / self.id
        self.journal: list[dict] = []
        self._backed_up: set[str] = set()
        self.tags = tuple(tags)
```

`commit` body becomes:

```python
    def commit(self):
        if not self.journal:
            return
        self._ensure()
        (self.dir / "journal.json").write_text(
            json.dumps({"id": self.id, "tags": list(self.tags), "actions": self.journal}, indent=2))
```

`latest` becomes:

```python
    @staticmethod
    def latest(tag: str | None = None) -> Path | None:
        d = _state_dir()
        if not d.exists():
            return None
        points = []
        for p in sorted(d.glob("*"), key=lambda p: p.name):
            j = p / "journal.json"
            if not j.exists():
                continue
            if tag is not None:
                try:
                    tags = json.loads(j.read_text()).get("tags") or []
                except (OSError, ValueError):
                    continue
                if tag not in tags:
                    continue
            points.append(p)
        return points[-1] if points else None
```

`Fixer.__init__`:

```python
    def __init__(self, dry_run: bool = True, tags: tuple[str, ...] = ()):
        self.dry_run = dry_run
        self.rp = None if dry_run else RestorePoint(tags=tags)
```

`undo_latest` signature and first lines:

```python
def undo_latest(tag: str | None = None) -> tuple[bool, str]:
    point = RestorePoint.latest(tag)
    if point is None:
        if tag:
            return False, f"no {tag} restore point — nothing of {tag} to undo."
        return False, "no restore point found — nothing to undo."
```

(rest of `undo_latest` unchanged).

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_undo_tags -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add murphy_lawden/remedy.py tests/test_undo_tags.py
git commit -m "remedy: tag restore points by area so undo can be per area"
```

---

### Task 4: The grammar — `Command`, stacked flags, verbs, legacy detection

**Files:**
- Create: `murphy_lawden/argv.py`
- Test: `tests/test_argv.py`

**Interfaces:**
- Produces:
  - `class UsageError(Exception)` (message is user-facing).
  - `@dataclass Command: action: str; targets: list[str]; yes: bool = False; dry: bool = False; verbose: bool = False; quiet: bool = False; json: bool = False; consented: bool = False; passthrough: list[str] = []`. `action` ∈ `{"check","fix","undo","explain","cage","game","clean","for","panic","list","menu","help","version"}`.
  - `parse(argv: list[str]) -> Command` (raises `UsageError`).
  - `is_legacy(argv: list[str]) -> bool`.
  - `ACTIONS: dict[str, str]` short-letter → action; `LONG: dict[str, str]` long → action; `WORDS: dict[str, str]` word → action.

Grammar rules (from the spec):
- Short actions: `-c check, -f fix, -u undo, -e explain, -x cage, -g game, -k clean, -s for, -P panic, -l list`. Long: `--check --fix --undo --explain --cage --game --clean --for --panic --list`.
- Modifiers: `-y/--yes, -n/--dry, -v/--verbose, -q/--quiet, -j/--json, -h/--help, -V/--version`; hidden `--consented`.
- Words: `check fix undo explain cage game clean for panic emergency list help version` (`emergency` → panic).
- Short flags stack: `-fy`, `-cv`. Unknown letter → `UsageError("unknown flag -z")`.
- Two different actions → `UsageError("pick one: fix or check")` (names in the order given).
- `-h` with targets → action `help` with those targets; `-h` alone → `help`. `-V` → `version`.
- No action and no args → `menu`. No action but targets (`murphy ssh`) → `UsageError("say what to do with ssh: murphy -c ssh (check) or murphy -f ssh (fix)")`.
- `--` ends parsing; the rest is `passthrough` (only meaningful for `cage`).
- For `cage`, the first non-flag word after the action is the target verbatim even if it starts with `-` only when it follows `--`; otherwise normal parsing.
- Targets are lower-cased for every action except `cage` (a file path).

`is_legacy(argv)` is True when:
- the first word is one of `scan av watch gui module kill duress tweak overview collapse spoof ezopt ds incinerate`, or
- any token is a legacy-only flag: `--su --risk --mode --online --via --nix-config --nix-host --target --dry-run --pack --only --no-banner --no-prompt --tui --no-color --color --save --interval --once --notify --state --install-service --uninstall-service --out --port --no-open --tier --execute --relock --arm --deadman --checkin --disarm --tick --category --apply-tweaks --door --thaw --restore --wipe-data --manifest-dir --facet --apply --deep --iface --new-hostname --tz --incinerate` (match the token or `token=` prefix).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_argv.py
import unittest
from murphy_lawden.argv import parse, is_legacy, UsageError


class ParseTest(unittest.TestCase):
    def test_three_forms_are_equal(self):
        a, b, c = parse(["fix", "ssh"]), parse(["-f", "ssh"]), parse(["--fix", "ssh"])
        for cmd in (a, b, c):
            self.assertEqual((cmd.action, cmd.targets), ("fix", ["ssh"]))

    def test_every_action_letter(self):
        table = {"-c": "check", "-f": "fix", "-u": "undo", "-e": "explain", "-x": "cage",
                 "-g": "game", "-k": "clean", "-s": "for", "-P": "panic", "-l": "list"}
        for flag, action in table.items():
            with self.subTest(flag=flag):
                self.assertEqual(parse([flag]).action, action)

    def test_stacking(self):
        cmd = parse(["-fy", "ssh"])
        self.assertEqual((cmd.action, cmd.yes, cmd.targets), ("fix", True, ["ssh"]))
        cmd = parse(["-cvj", "wifi"])
        self.assertTrue(cmd.verbose and cmd.json)

    def test_many_areas(self):
        self.assertEqual(parse(["-c", "ssh", "wifi", "kernel"]).targets, ["ssh", "wifi", "kernel"])

    def test_two_actions_is_an_error(self):
        with self.assertRaises(UsageError) as e:
            parse(["-cf"])
        self.assertIn("check", str(e.exception))
        self.assertIn("fix", str(e.exception))

    def test_unknown_letter(self):
        with self.assertRaises(UsageError):
            parse(["-z"])

    def test_bare_is_menu(self):
        self.assertEqual(parse([]).action, "menu")

    def test_area_without_verb(self):
        with self.assertRaises(UsageError) as e:
            parse(["ssh"])
        self.assertIn("murphy -c ssh", str(e.exception))

    def test_help_and_version(self):
        self.assertEqual(parse(["-h"]).action, "help")
        cmd = parse(["-h", "ssh"])
        self.assertEqual((cmd.action, cmd.targets), ("help", ["ssh"]))
        self.assertEqual(parse(["-V"]).action, "version")
        self.assertEqual(parse(["--version"]).action, "version")

    def test_emergency_word(self):
        self.assertEqual(parse(["emergency"]).action, "panic")

    def test_cage_passthrough_and_dash_names(self):
        cmd = parse(["-x", "game.exe", "--", "--gpu", "--audio"])
        self.assertEqual((cmd.targets, cmd.passthrough), (["game.exe"], ["--gpu", "--audio"]))
        cmd = parse(["-x", "--", "-weird.exe"])
        self.assertEqual(cmd.passthrough, ["-weird.exe"])

    def test_cage_target_case_kept(self):
        self.assertEqual(parse(["-x", "Setup.EXE"]).targets, ["Setup.EXE"])

    def test_targets_lowercased(self):
        self.assertEqual(parse(["-c", "SSH"]).targets, ["ssh"])

    def test_dry_and_consented(self):
        cmd = parse(["--fix", "--dry", "--consented"])
        self.assertTrue(cmd.dry and cmd.consented)


class LegacyTest(unittest.TestCase):
    def test_legacy_words(self):
        for argv in (["scan"], ["av"], ["ds", "lock"], ["ezopt"], ["spoof"], ["overview"]):
            with self.subTest(argv=argv):
                self.assertTrue(is_legacy(argv))

    def test_legacy_flags(self):
        self.assertTrue(is_legacy(["fix", "--su", "--risk", "medium"]))
        self.assertTrue(is_legacy(["--mode=su"]))
        self.assertTrue(is_legacy(["clean", "--apply"]))

    def test_new_forms_are_not_legacy(self):
        for argv in (["fix", "ssh"], ["-f"], ["clean"], ["undo"], ["panic"], ["-c", "-v"], []):
            with self.subTest(argv=argv):
                self.assertFalse(is_legacy(argv))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_argv -v`
Expected: ERROR — `No module named 'murphy_lawden.argv'`

- [ ] **Step 3: Write minimal implementation**

```python
# murphy_lawden/argv.py
"""Murphy's command grammar: verb first, every verb with -x and --word forms.

    murphy fix ssh  ==  murphy -f ssh  ==  murphy --fix ssh

Hand-parsed (not argparse) so short flags stack (-fy) and verbs can be words.
Legacy invocations are detected and left to the old parser untouched.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class UsageError(Exception):
    pass


ACTIONS = {"c": "check", "f": "fix", "u": "undo", "e": "explain", "x": "cage",
           "g": "game", "k": "clean", "s": "for", "P": "panic", "l": "list"}
LONG = {"--" + a: a for a in ("check", "fix", "undo", "explain", "cage",
                              "game", "clean", "for", "panic", "list")}
WORDS = {w: w for w in ("check", "fix", "undo", "explain", "cage", "game",
                        "clean", "for", "panic", "list", "help", "version")}
WORDS["emergency"] = "panic"
_MODS_SHORT = {"y": "yes", "n": "dry", "v": "verbose", "q": "quiet", "j": "json"}
_MODS_LONG = {"--yes": "yes", "--dry": "dry", "--verbose": "verbose", "--quiet": "quiet",
              "--json": "json", "--consented": "consented"}

_LEGACY_WORDS = {"scan", "av", "watch", "gui", "module", "kill", "duress", "tweak",
                 "overview", "collapse", "spoof", "ezopt", "ds", "incinerate"}
_LEGACY_FLAGS = {
    "--su", "--risk", "--mode", "--online", "--via", "--nix-config", "--nix-host", "--target",
    "--dry-run", "--pack", "--only", "--no-banner", "--no-prompt", "--tui", "--no-color",
    "--color", "--save", "--interval", "--once", "--notify", "--state", "--install-service",
    "--uninstall-service", "--out", "--port", "--no-open", "--tier", "--execute", "--relock",
    "--arm", "--deadman", "--checkin", "--disarm", "--tick", "--category", "--apply-tweaks",
    "--door", "--thaw", "--restore", "--wipe-data", "--manifest-dir", "--facet", "--apply",
    "--deep", "--iface", "--new-hostname", "--tz", "--incinerate",
}


@dataclass
class Command:
    action: str
    targets: list[str] = field(default_factory=list)
    yes: bool = False
    dry: bool = False
    verbose: bool = False
    quiet: bool = False
    json: bool = False
    consented: bool = False
    passthrough: list[str] = field(default_factory=list)


def is_legacy(argv: list[str]) -> bool:
    if argv and argv[0] in _LEGACY_WORDS:
        return True
    for tok in argv:
        if tok == "--":
            break
        if tok.split("=", 1)[0] in _LEGACY_FLAGS:
            return True
    return False


def parse(argv: list[str]) -> Command:
    actions: list[str] = []
    mods: dict[str, bool] = {}
    targets: list[str] = []
    passthrough: list[str] = []
    want_help = want_version = False

    def set_action(a: str) -> None:
        if actions and actions[0] != a:
            raise UsageError(f"pick one: {actions[0]} or {a}")
        if not actions:
            actions.append(a)

    i = 0
    while i < len(argv):
        tok = argv[i]
        i += 1
        if tok == "--":
            passthrough = argv[i:]
            break
        if tok in ("-h", "--help"):
            want_help = True
        elif tok in ("-V", "--version"):
            want_version = True
        elif tok in LONG:
            set_action(LONG[tok])
        elif tok in _MODS_LONG:
            mods[_MODS_LONG[tok]] = True
        elif tok.startswith("--"):
            raise UsageError(f"unknown flag {tok}")
        elif tok.startswith("-") and len(tok) > 1:
            for ch in tok[1:]:
                if ch in ACTIONS:
                    set_action(ACTIONS[ch])
                elif ch in _MODS_SHORT:
                    mods[_MODS_SHORT[ch]] = True
                elif ch == "h":
                    want_help = True
                elif ch == "V":
                    want_version = True
                else:
                    raise UsageError(f"unknown flag -{ch}")
        elif not actions and not targets and tok in WORDS:
            set_action(WORDS[tok])
        else:
            targets.append(tok)

    if want_version:
        action = "version"
    elif want_help:
        action = "help"
    elif actions:
        action = actions[0]
    elif targets:
        t = targets[0]
        raise UsageError(f"say what to do with {t}: murphy -c {t} (check) or murphy -f {t} (fix)")
    else:
        action = "menu"

    if action not in ("cage",):
        targets = [t.lower() for t in targets]
    return Command(action=action, targets=targets, passthrough=list(passthrough), **mods)
```

Note `help`/`version` words: `WORDS` maps them, so `murphy help ssh` → action `help`, targets `["ssh"]`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_argv -v`
Expected: PASS (all)

- [ ] **Step 5: Commit**

```bash
git add murphy_lawden/argv.py tests/test_argv.py
git commit -m "argv: verb-first grammar with stacked -x and --word flags"
```

---

### Task 5: The area catalog — 12 areas with real manifests

**Files:**
- Create: `murphy_lawden/areas/catalog.py`
- Modify: `murphy_lawden/areas/__init__.py`
- Test: `tests/test_areas.py`

**Interfaces:**
- Consumes: `Manifest`, `Needs` (Task 2); `AREA_NAMES` (Task 1).
- Produces (in `murphy_lawden/areas/__init__.py`):
  - `@dataclass(frozen=True) Area: name: str; aliases: tuple[str, ...]; covers: str; manifests: dict[str, Manifest]` (keys are actions present for that area).
  - `class UnknownArea(Exception)` with `.word: str`, `.suggestion: str | None`; `str(e)` is `"no area 'shh' — did you mean ssh?"` or `"no area 'zzz' — murphy -l lists them"`.
  - `AREAS: dict[str, Area]` keyed by canonical name, in `AREA_NAMES` order.
  - `resolve(word: str) -> Area` — canonical name or alias, case-insensitive; raises `UnknownArea` (suggestion via `difflib.get_close_matches` over names + aliases, cutoff 0.6, mapped back to the canonical name).
  - `resolve_many(words: list[str]) -> list[Area]` — de-duplicated, order kept; empty list → every area.
  - `manifests_for(action: str, areas: list[Area]) -> tuple[list[Manifest], list[str]]` → (manifests found, names of areas lacking that action).

Area data (canonical, aliases, actions). Every manifest's `does` is one plain sentence; `check` manifests have `changes=()` and `writes=()`.

| area | aliases | check needs | fix (needs / danger) | undo |
|---|---|---|---|---|
| cage | isolate, sandbox, torrents, ds | none | `murphy ds lock`: root, writes `/etc/systemd/system/home-*-Torrents.mount`, `/etc/binfmt.d/wine.conf`, `~/.local/bin/wine`, `~/.config/mimeapps.list`, qBittorrent config; calm | `murphy ds unlock` |
| net | wifi, firewall, vpn, dns, network | none | net findings' remedies: root, writes `/etc/sysctl.d/60-murphy.conf`; calm | restore point tag `net` |
| ssh | sshd | reads `/etc/ssh/` | root, writes `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/`; calm | tag `ssh` |
| users | accounts, sudo, login, passwords | reads `/etc/passwd`, `/etc/shadow` (root for shadow), `/etc/sudoers` | root, writes file modes on `/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers`; calm | tag `users` |
| kernel | sysctl, boot | reads `/proc/sys` | root, writes `/etc/sysctl.d/60-murphy.conf`; calm | tag `kernel` |
| disk | fs, mounts, files, permissions | reads `/etc/fstab`, `/proc/mounts` | root, writes file modes, `/etc/fstab` (backed up); calm | tag `disk` |
| apps | debloat, services, legacy | reads systemd units | root, writes systemd unit state; calm | tag `apps` |
| privacy | identity, spoof, mac, hostname | reads interfaces, `/etc/machine-id`, hostname, timezone | `murphy spoof --facet all --apply`: root, devices `network interfaces`, writes `/etc/machine-id`, `/etc/hostname`, `/etc/localtime`; calm | `murphy spoof --facet restore --apply` |
| virus | av, malware, antivirus | reads home, `/tmp`, `/var/tmp`, `/dev/shm` | — (no fix: Murphy never deletes files on a guess) | — |
| firmware | uefi, bios, secureboot | reads `fwupdmgr`, `mokutil`, ESP | — (no fix: never touches firmware keys) | — |
| phone | android, magisk | none (runs on Android) | builds `murphy-hardening.zip` (writes it in cwd); calm | "disable or remove the module in Magisk, reboot" |
| emergency | panic, duress, collapse | reads only (briefing) | the emergency menu: root; **dangerous** | "each door prints its own undo" |

Platforms: cage `{linux, windows}`; net/ssh/users/kernel/disk/apps `{linux}`; ssh also `bsd, macos`; privacy `{linux}`; virus `{linux, bsd, macos}`; firmware `{linux}`; phone `{android}`; emergency `{linux, android}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_areas.py
import unittest
from murphy_lawden.areas import AREAS, resolve, resolve_many, manifests_for, UnknownArea
from murphy_lawden.areas.routing import AREA_NAMES


class AreasTest(unittest.TestCase):
    def test_all_twelve_in_order(self):
        self.assertEqual(tuple(AREAS), AREA_NAMES)

    def test_every_area_has_a_check(self):
        for a in AREAS.values():
            with self.subTest(area=a.name):
                self.assertIn("check", a.manifests)

    def test_checks_change_nothing(self):
        for a in AREAS.values():
            m = a.manifests["check"]
            with self.subTest(area=a.name):
                self.assertEqual(m.changes, ())
                self.assertEqual(m.needs.writes, ())

    def test_manifests_are_complete(self):
        for a in AREAS.values():
            for action, m in a.manifests.items():
                with self.subTest(area=a.name, action=action):
                    self.assertEqual((m.area, m.action), (a.name, action))
                    self.assertTrue(m.does.strip())
                    self.assertTrue(m.undo.strip())
                    self.assertTrue(m.platforms)
                    self.assertIn(m.danger, ("calm", "dangerous"))

    def test_fix_has_undo_unless_none(self):
        for a in AREAS.values():
            if "fix" in a.manifests and a.name not in ("phone", "emergency"):
                with self.subTest(area=a.name):
                    self.assertIn("undo", a.manifests)

    def test_only_emergency_is_dangerous(self):
        for a in AREAS.values():
            for m in a.manifests.values():
                with self.subTest(area=a.name, action=m.action):
                    self.assertEqual(m.danger == "dangerous", a.name == "emergency" and m.action == "fix")

    def test_aliases(self):
        self.assertEqual(resolve("wifi").name, "net")
        self.assertEqual(resolve("AV").name, "virus")
        self.assertEqual(resolve("torrents").name, "cage")

    def test_typo(self):
        with self.assertRaises(UnknownArea) as e:
            resolve("shh")
        self.assertEqual(str(e.exception), "no area 'shh' — did you mean ssh?")
        with self.assertRaises(UnknownArea) as e:
            resolve("zzzzzz")
        self.assertIn("murphy -l", str(e.exception))

    def test_resolve_many(self):
        self.assertEqual([a.name for a in resolve_many(["wifi", "net", "ssh"])], ["net", "ssh"])
        self.assertEqual(len(resolve_many([])), 12)

    def test_manifests_for_reports_missing(self):
        ms, missing = manifests_for("fix", resolve_many(["ssh", "virus"]))
        self.assertEqual([m.area for m in ms], ["ssh"])
        self.assertEqual(missing, ["virus"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_areas -v`
Expected: ERROR — `cannot import name 'AREAS'`

- [ ] **Step 3: Write minimal implementation**

`murphy_lawden/areas/catalog.py` — build the table above with a small helper so each manifest is one call:

```python
# murphy_lawden/areas/catalog.py
"""The areas Murphy covers, and exactly what each action does, needs and changes."""
from __future__ import annotations

from ..manifest import Manifest, Needs

LINUX = frozenset({"linux"})


def _m(area, action, does, needs=Needs(), changes=(), undo="nothing to undo — look only",
       platforms=LINUX, danger="calm"):
    return Manifest(area=area, action=action, does=does, needs=needs, changes=tuple(changes),
                    undo=undo, platforms=frozenset(platforms), danger=danger)


def _finding_area(name, covers, aliases, check_does, check_reads, fix_does, fix_writes,
                  fix_changes, platforms=LINUX, check_root=False):
    """An area whose check/fix are Murphy's scan findings routed to it."""
    undo = f"murphy -u {name} rolls back the last {name} fix from its restore point"
    return (name, tuple(aliases), covers, {
        "check": _m(name, "check", check_does,
                    Needs(root=check_root, reads=tuple(check_reads)), platforms=platforms),
        "fix": _m(name, "fix", fix_does, Needs(root=True, writes=tuple(fix_writes)),
                  fix_changes, undo, platforms),
        "undo": _m(name, "undo", f"Puts back what the last {name} fix changed.",
                   Needs(root=True, writes=tuple(fix_writes)),
                   (f"restores the files backed up by the last {name} fix",), undo, platforms),
    })


_DATA = [
    ("cage", ("isolate", "sandbox", "torrents", "ds"),
     "compartmentalization: run downloads, apps and games in a sandbox",
     {
         "check": _m("cage", "check", "Shows whether the torrent folder is locked down and the cage is ready.",
                     platforms={"linux", "windows"}),
         "fix": _m("cage", "fix",
                   "Locks the torrent folder: nothing in it can run except inside the cage.",
                   Needs(root=True, writes=("/etc/systemd/system/home-*-Torrents.mount",
                                            "/etc/binfmt.d/wine.conf", "~/.local/bin/wine",
                                            "~/.config/mimeapps.list", "qBittorrent config")),
                   ("~/Torrents mounted noexec,nosuid,nodev", "Wine binfmt off",
                    "Windows files in ~/Torrents open in the cage"),
                   "murphy -u cage (= murphy ds unlock), every change is in the ds ledger",
                   {"linux", "windows"}),
         "undo": _m("cage", "undo", "Unlocks the torrent folder and removes everything the lock installed.",
                    Needs(root=True), ("reverses each entry in ~/.local/state/murphy/ds.ledger.json",),
                    "murphy -f cage locks it again", {"linux", "windows"}),
     }),
    _finding_area("net", "wifi, firewall, DNS, VPN and network kernel settings",
                  ("wifi", "firewall", "vpn", "dns", "network"),
                  "Checks the firewall, listening ports and network kernel settings.",
                  ("/proc/sys/net", "ufw/nft state", "listening sockets"),
                  "Tightens network kernel settings (redirects, source routing, rp_filter, syncookies).",
                  ("/etc/sysctl.d/60-murphy.conf",),
                  ("net.ipv4.conf.all.accept_redirects=0", "net.ipv4.tcp_syncookies=1")),
    _finding_area("ssh", "sshd and ssh client configuration",
                  ("sshd",),
                  "Checks how sshd is configured: root login, passwords, ciphers.",
                  ("/etc/ssh/",),
                  "Turns off root and password login for sshd and drops weak settings.",
                  ("/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/"),
                  ("PermitRootLogin no", "PasswordAuthentication no"),
                  platforms={"linux", "bsd", "macos"}),
    _finding_area("users", "users, sudo, passwords and login",
                  ("accounts", "sudo", "login", "passwords"),
                  "Checks accounts, sudo rules and the permissions on the password files.",
                  ("/etc/passwd", "/etc/shadow", "/etc/sudoers"),
                  "Fixes ownership and modes of the account and sudo files.",
                  ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers"),
                  ("file modes only — no account is added, removed or locked",)),
    _finding_area("kernel", "kernel settings, lockdown and boot options",
                  ("sysctl", "boot"),
                  "Checks kernel hardening settings and lockdown.",
                  ("/proc/sys", "/sys/kernel/security/lockdown"),
                  "Tightens kernel sysctls (pointer leaks, dmesg, ptrace, BPF).",
                  ("/etc/sysctl.d/60-murphy.conf",),
                  ("kernel.kptr_restrict=2", "kernel.dmesg_restrict=1")),
    _finding_area("disk", "mounts, file permissions, SUID files and encryption",
                  ("fs", "mounts", "files", "permissions"),
                  "Checks mount options, sensitive file permissions and disk encryption.",
                  ("/etc/fstab", "/proc/mounts"),
                  "Tightens file modes and mount options.",
                  ("file modes", "/etc/fstab (backed up first)"),
                  ("chmod on world-writable or over-permissive files", "nodev/nosuid mount options")),
    _finding_area("apps", "services, autostart and legacy network daemons",
                  ("debloat", "services", "legacy"),
                  "Checks for exposed services and legacy daemons (telnet, rsh, ftp...).",
                  ("systemd units",),
                  "Stops and disables exposed or legacy services.",
                  ("systemd unit state",),
                  ("systemctl disable --now on flagged units",)),
    ("privacy", ("identity", "spoof", "mac", "hostname"),
     "machine-id, hostname, timezone and MAC address",
     {
         "check": _m("privacy", "check", "Shows the identifiers this box gives away: MAC, machine-id, hostname, timezone.",
                     Needs(reads=("network interfaces", "/etc/machine-id", "/etc/hostname"))),
         "fix": _m("privacy", "fix", "Rotates the MAC, machine-id, hostname and timezone to neutral values.",
                   Needs(root=True, devices=("network interfaces",),
                         writes=("/etc/machine-id", "/etc/hostname", "/etc/localtime")),
                   ("new MAC on each interface", "new machine-id", "neutral hostname", "decoy timezone"),
                   "murphy -u privacy puts the originals back"),
         "undo": _m("privacy", "undo", "Puts the original MAC, machine-id, hostname and timezone back.",
                    Needs(root=True, devices=("network interfaces",),
                          writes=("/etc/machine-id", "/etc/hostname", "/etc/localtime")),
                    ("originals restored from murphy's spoof state",), "murphy -f privacy rotates them again"),
     }),
    ("virus", ("av", "malware", "antivirus"),
     "malware heuristics, ClamAV and known-bad indicators",
     {
         "check": _m("virus", "check", "Looks for malware: rootkit traces, known-bad files, then a ClamAV sweep.",
                     Needs(reads=("home", "/tmp", "/var/tmp", "/dev/shm")),
                     platforms={"linux", "bsd", "macos"}),
     }),
    ("firmware", ("uefi", "bios", "secureboot"),
     "Secure Boot, firmware security level and the EFI partition",
     {
         "check": _m("firmware", "check", "Reads Secure Boot state, the firmware security level and the EFI partition.",
                     Needs(reads=("fwupdmgr", "mokutil", "EFI system partition"))),
     }),
    ("phone", ("android", "magisk"),
     "Android hardening through a Magisk module",
     {
         "check": _m("phone", "check", "Checks Android hardening: SELinux, debugging, root exposure.",
                     platforms={"android"}),
         "fix": _m("phone", "fix", "Builds the systemless Magisk hardening module.",
                   Needs(writes=("./murphy-hardening.zip",)),
                   ("a zip file in the current folder — the phone changes only when you install it",),
                   "disable or remove the module in Magisk, then reboot", {"android", "linux"}),
     }),
    ("emergency", ("panic", "duress", "collapse"),
     "panic, duress, collapse and self-wipe — last resorts",
     {
         "check": _m("emergency", "check", "Shows which emergency doors this box has, without opening any.",
                     platforms={"linux", "android"}),
         "fix": _m("emergency", "fix", "Opens the emergency menu: lockdown, duress, collapse doors, phone spyware response.",
                   Needs(root=True), ("depends on the door you pick — each one shows its own plan first",),
                   "each door prints its own undo", {"linux", "android"}, danger="dangerous"),
     }),
]
```

`murphy_lawden/areas/__init__.py`:

```python
"""Murphy's areas: what each part of hardening covers, needs and changes."""
from __future__ import annotations

import difflib
from dataclasses import dataclass

from ..manifest import Manifest
from .catalog import _DATA
from .routing import AREA_NAMES


@dataclass(frozen=True)
class Area:
    name: str
    aliases: tuple[str, ...]
    covers: str
    manifests: dict[str, Manifest]


class UnknownArea(Exception):
    def __init__(self, word: str, suggestion: str | None):
        self.word, self.suggestion = word, suggestion
        tail = f"did you mean {suggestion}?" if suggestion else "murphy -l lists them"
        super().__init__(f"no area '{word}' — {tail}")


AREAS: dict[str, Area] = {}
for _name, _aliases, _covers, _manifests in _DATA:
    AREAS[_name] = Area(_name, _aliases, _covers, _manifests)
AREAS = {n: AREAS[n] for n in AREA_NAMES}

_LOOKUP: dict[str, str] = {}
for _a in AREAS.values():
    _LOOKUP[_a.name] = _a.name
    for _al in _a.aliases:
        _LOOKUP[_al] = _a.name


def resolve(word: str) -> Area:
    w = word.lower()
    if w in _LOOKUP:
        return AREAS[_LOOKUP[w]]
    close = difflib.get_close_matches(w, list(_LOOKUP), n=1, cutoff=0.6)
    raise UnknownArea(word, _LOOKUP[close[0]] if close else None)


def resolve_many(words: list[str]) -> list[Area]:
    if not words:
        return list(AREAS.values())
    out: list[Area] = []
    for w in words:
        a = resolve(w)
        if a not in out:
            out.append(a)
    return out


def manifests_for(action: str, areas: list[Area]) -> tuple[list[Manifest], list[str]]:
    found = [a.manifests[action] for a in areas if action in a.manifests]
    missing = [a.name for a in areas if action not in a.manifests]
    return found, missing
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_areas -v`
Expected: PASS. Then run the whole suite: `python3 -m unittest discover -s tests -v` — all PASS.

- [ ] **Step 5: Commit**

```bash
git add murphy_lawden/areas tests/test_areas.py
git commit -m "areas: the 12 areas with what each action does, needs, changes, undoes"
```

---

### Task 6: The ask and elevation

**Files:**
- Create: `murphy_lawden/runner.py` (ask + elevate parts only in this task)
- Test: `tests/test_ask.py`

**Interfaces:**
- Consumes: `Command` (Task 4), `Manifest`, `render_ask`, `is_dangerous`, `merge_needs` (Task 2).
- Produces:
  - `DECLINED = 3`
  - `ask(cmd: Command, ms: list[Manifest], ink, *, out=print, read=input, isatty=sys.stdin.isatty) -> bool` — prints the block; returns True to proceed. Rules: `cmd.consented` → True without printing; `cmd.dry` → prints block + `"dry run — nothing will change"` and returns False; dangerous → `-y` prints `"-y doesn't skip a dangerous action — answer it yourself"` and still asks, and the answer must be the word `yes` typed in full; calm + `cmd.yes` → True after printing; not a TTY → prints `"not a terminal and nothing said yes — stopping (add -y for calm actions)"`, returns False; otherwise `go ahead? [y/N]` accepting `y`/`yes`.
  - `elevate(argv: list[str], ink, *, geteuid=os.geteuid, execvp=os.execvp, which=shutil.which) -> None` — if already root, return; if no sudo, raise `SystemExit(2)` after a message; else exec `sudo <python> <murphy.py> <argv> --consented`. Never adds `--consented` twice.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ask.py
import sys
import unittest
from murphy_lawden.argv import Command
from murphy_lawden.banner import make_ink
from murphy_lawden.manifest import Manifest, Needs
from murphy_lawden import runner

INK = make_ink(False)
CALM = Manifest("ssh", "fix", "Turns off root login.", Needs(root=True), ("PermitRootLogin no",),
                "murphy -u ssh", frozenset({"linux"}))
DANGER = Manifest("emergency", "fix", "Opens the emergency menu.", Needs(root=True), ("door",),
                  "each door", frozenset({"linux"}), "dangerous")


def run_ask(cmd, ms, answers=(), tty=True):
    lines, it = [], iter(answers)
    ok = runner.ask(cmd, ms, INK, out=lines.append, read=lambda _p: next(it), isatty=lambda: tty)
    return ok, "\n".join(lines)


class AskTest(unittest.TestCase):
    def test_calm_yes_answer(self):
        ok, text = run_ask(Command("fix"), [CALM], ["y"])
        self.assertTrue(ok)
        self.assertIn("murphy will: fix ssh", text)

    def test_calm_no_answer(self):
        self.assertFalse(run_ask(Command("fix"), [CALM], [""])[0])

    def test_calm_dash_y(self):
        self.assertTrue(run_ask(Command("fix", yes=True), [CALM])[0])

    def test_dangerous_ignores_dash_y_and_wants_full_yes(self):
        ok, text = run_ask(Command("panic", yes=True), [DANGER], ["y"])
        self.assertFalse(ok)
        self.assertIn("-y doesn't skip", text)
        self.assertTrue(run_ask(Command("panic"), [DANGER], ["yes"])[0])

    def test_dry_never_proceeds(self):
        ok, text = run_ask(Command("fix", dry=True), [CALM], ["y"])
        self.assertFalse(ok)
        self.assertIn("dry run", text)

    def test_not_a_tty_stops(self):
        ok, text = run_ask(Command("fix"), [CALM], tty=False)
        self.assertFalse(ok)
        self.assertIn("not a terminal", text)

    def test_consented_skips(self):
        ok, text = run_ask(Command("fix", consented=True), [CALM])
        self.assertTrue(ok)
        self.assertEqual(text, "")


class ElevateTest(unittest.TestCase):
    def test_root_does_nothing(self):
        called = []
        runner.elevate(["-f", "ssh"], INK, geteuid=lambda: 0, execvp=lambda *a: called.append(a))
        self.assertEqual(called, [])

    def test_reexec_adds_consented_once(self):
        called = []
        runner.elevate(["-f", "ssh", "--consented"], INK, geteuid=lambda: 1000,
                       execvp=lambda f, a: called.append(a), which=lambda _: "/usr/bin/sudo")
        argv = called[0]
        self.assertEqual(argv[0], "sudo")
        self.assertEqual(argv.count("--consented"), 1)
        self.assertEqual(argv[-3:], ["-f", "ssh", "--consented"])

    def test_no_sudo(self):
        with self.assertRaises(SystemExit) as e:
            runner.elevate(["-f"], INK, geteuid=lambda: 1000, execvp=lambda *a: None,
                           which=lambda _: None)
        self.assertEqual(e.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_ask -v`
Expected: ERROR — `No module named 'murphy_lawden.runner'`

- [ ] **Step 3: Write minimal implementation**

```python
# murphy_lawden/runner.py
"""Run a parsed Command: show the ask, elevate once, call the existing code."""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .argv import Command
from .manifest import Manifest, is_dangerous, render_ask

DECLINED = 3
_MURPHY_PY = Path(__file__).resolve().parent.parent / "murphy.py"


def ask(cmd: Command, ms: list[Manifest], ink, *, out=print, read=input,
        isatty=sys.stdin.isatty) -> bool:
    if cmd.consented:
        return True
    for line in render_ask(ms):
        out(ink.bone(line) if line.startswith("murphy will") else ink.dim(line)
            if not line.lstrip().startswith("DANGEROUS") else ink.red_b(line))
    if cmd.dry:
        out(ink.cyan("dry run — nothing will change"))
        return False
    danger = is_dangerous(ms)
    if danger and cmd.yes:
        out(ink.amber("-y doesn't skip a dangerous action — answer it yourself"))
    if cmd.yes and not danger:
        return True
    if not isatty():
        out(ink.amber("not a terminal and nothing said yes — stopping (add -y for calm actions)"))
        return False
    try:
        if danger:
            ans = read("type yes to go ahead: ").strip().lower()
            return ans == "yes"
        ans = read("go ahead? [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def elevate(argv: list[str], ink, *, geteuid=getattr(os, "geteuid", lambda: 0),
            execvp=os.execvp, which=shutil.which) -> None:
    if geteuid() == 0:
        return
    if not which("sudo"):
        sys.stderr.write(ink.red_b("murphy: this needs root and sudo isn't installed.\n"))
        raise SystemExit(2)
    args = [a for a in argv if a != "--consented"] + ["--consented"]
    sys.stderr.write(ink.dim("murphy: asking sudo for root (once)…\n"))
    execvp("sudo", ["sudo", sys.executable, str(_MURPHY_PY), *args])
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_ask -v`
Expected: PASS (10 tests)

- [ ] **Step 5: Commit**

```bash
git add murphy_lawden/runner.py tests/test_ask.py
git commit -m "runner: the explicit ask (calm/dangerous/dry/no-tty) and one-time sudo"
```

---

### Task 7: Dispatch — check / fix / undo / explain / list / help per area

**Files:**
- Modify: `murphy_lawden/runner.py` (add `run`)
- Create: `murphy_lawden/helptext.py`
- Modify: `murphy_lawden/cli.py` — `do_fix` gets an optional `tags` parameter passed to `Fixer`.
- Test: `tests/test_runner.py`

**Interfaces:**
- Consumes: everything above; `cli.assemble_findings`, `cli.render_report`, `cli.to_json`, `cli.do_fix`, `cli.do_av`, `cli.build_parser`, `core.detect_host`, `remedy.undo_latest`, `ds.run_ds`, `credspoof.run_spoof`, `collapse.run_collapse`, `magiskmod.build`.
- Produces:
  - `helptext.top_help() -> str`, `helptext.area_help(area: Area) -> str`, `helptext.list_text() -> str`.
  - `runner.run(cmd: Command, ink, argv: list[str]) -> int`.
  - `cli.do_fix(host, findings, args, ink, tags: tuple[str, ...] = ()) -> int` (creates `Fixer(dry_run=args.dry_run, tags=tags)`).

Dispatch rules for `run`:
- `version` → print `Murphy Lawden v{__version__}`; 0.
- `help` → no targets: `top_help()`; with targets: `area_help` for each (`UnknownArea` → message to stderr, 2).
- `explain` → requires exactly one target (else `UsageError` message, 2); prints `area_help`.
- `list` → `list_text()`; 0.
- `menu` → `cli._wizard(ink)`.
- `check`, `fix`, `undo`:
  1. `areas = resolve_many(cmd.targets)` (`UnknownArea` → stderr, 2).
  2. `ms, missing = manifests_for(action, areas)`. If targets were given explicitly and `missing` is non-empty, print one line per missing area: `"<area> has no <action>: <reason>"` where reason is `"Murphy never deletes files on a guess — murphy -c virus shows what to remove"` for virus fix, `"Murphy never touches firmware keys"` for firmware fix/undo, else `"nothing to <action>"`. If `ms` is empty → return 1.
  3. Filter `ms` to those whose `platforms` contains `detect_host().family` (or `android` when `host.has("android")` if that attribute exists; otherwise family). Areas skipped print `"<area>: not on <family> — skipped"`.
  4. For `check`: if `merge_needs(ms).root` and not root, run unprivileged anyway and say `"some checks need root — murphy -c -y ... --consented under sudo shows them"`? **No** — keep it simple: checks run as the user, and checks that need root already SKIP themselves. No ask for check.
  5. For `fix`/`undo`: `if not ask(cmd, ms, ink): return DECLINED if not cmd.dry else 0`; then if `merge_needs(ms).root`: `elevate(argv, ink)`.
  6. Execute per area (in order) with the table below; overall exit = max of per-area codes.

| area | check | fix | undo |
|---|---|---|---|
| finding areas (net ssh users kernel disk apps firmware phone) | findings filtered by `area_for(f.id) == area`, rendered with `render_report` (or JSON) | `do_fix(host, filtered, args, ink, tags=(area,))` with `args` from `build_parser().parse_args(["fix", "--no-banner"] + (["-y"] if yes) + (["--dry-run"] if dry) + (["--json"] if json))` and `args.risk = "low"` | `remedy.undo_latest(area)` printed green/amber; 0/1 |
| virus | `do_av(host, all_findings, args, ink, False)` | — | — |
| cage | `run_ds(["status"], ink)` | `run_ds(["lock"], ink)` | `run_ds(["unlock"], ink)` |
| privacy | `run_spoof(ns(facet="all", apply=False), ink)` | `run_spoof(ns(facet="all", apply=True), ink)` | `run_spoof(ns(facet="restore", apply=True), ink)` |
| phone fix | — | `magiskmod.build("murphy-hardening.zip")` + the four lines `cli.main` prints today | — |
| emergency | `run_collapse(ns(door=None, execute=False, thaw=False, restore=False, manifest_dir=None, wipe_data=False), ink)` | emergency menu (Task 8) | — |

`ns(**kw)` is `argparse.Namespace(iface=None, new_hostname=None, tz=None, **kw)`.

Findings are assembled once per run (only if any finding-based area or virus is involved), with `args = build_parser().parse_args(["scan", "--no-prompt"])`.

`helptext.top_help()` content:

```
murphy — hardening for every situation

  murphy                 menu: pick what you want, it explains as you go
  -c, --check   [area]   look only, change nothing
  -f, --fix     [area]   harden it — shows what it will do and asks first
  -u, --undo    [area]   put it back
  -e, --explain  area    what it does, needs, changes, and how to undo it
  -x, --cage     file    run something in the sandbox
  -g, --game   [on|off]  debloat for gaming
  -k, --clean            sweep junk
  -s, --for  situation   a preset: daily, gaming, torrents, travel, compromised, fresh, throwaway
  -P, --panic            emergency menu (asks at every step)
  -l, --list             list areas and situations

  -y, --yes      don't ask (calm actions only)     -n, --dry      show, change nothing
  -v, --verbose  more detail                       -q, --quiet    less
  -j, --json     machine-readable                  -h, --help     this, or: murphy -h <area>
  -V, --version

  areas: cage net ssh users kernel disk apps privacy virus firmware phone emergency
  no area = all of them · short flags stack: murphy -fy ssh · old commands still work
```

`area_help(area)` = `"<name> — <covers>"`, `"aliases: ..."`, blank, then `render_manifest` lines for each action in `("check","fix","undo")` present, separated by blank lines.

In this task `-l` prints the areas only, via `helptext.areas_text()`. Task 8 adds `helptext.list_text()` (areas + situations) and switches the `list` branch to it.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_runner.py
import io
import json
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest import mock

from murphy_lawden import runner, helptext
from murphy_lawden.argv import parse
from murphy_lawden.areas import AREAS
from murphy_lawden.banner import make_ink

INK = make_ink(False)


def go(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = runner.run(parse(argv), INK, argv)
    return code, out.getvalue(), err.getvalue()


class HelpTest(unittest.TestCase):
    def test_top_help_lists_every_flag(self):
        text = helptext.top_help()
        for flag in ("-c, --check", "-f, --fix", "-u, --undo", "-e, --explain", "-x, --cage",
                     "-g, --game", "-k, --clean", "-s, --for", "-P, --panic", "-l, --list",
                     "-y, --yes", "-n, --dry", "-j, --json", "-V, --version"):
            self.assertIn(flag, text)

    def test_area_help_renders_for_every_area(self):
        for a in AREAS.values():
            with self.subTest(area=a.name):
                text = helptext.area_help(a)
                self.assertIn("does", text)
                self.assertIn("undo", text)

    def test_help_ssh_and_explain_match(self):
        self.assertEqual(go(["-h", "ssh"])[1], go(["-e", "ssh"])[1])

    def test_unknown_area_is_usage_error(self):
        code, _, err = go(["-c", "shh"])
        self.assertEqual(code, 2)
        self.assertIn("did you mean ssh", err)

    def test_version(self):
        code, out, _ = go(["-V"])
        self.assertEqual(code, 0)
        self.assertIn("Murphy Lawden v", out)


class CheckTest(unittest.TestCase):
    def test_check_ssh_json_only_ssh_findings(self):
        code, out, _ = go(["-cj", "ssh"])
        data = json.loads(out)
        ids = [f["id"] for f in data["findings"]]
        self.assertTrue(all(i.startswith(("ssh.", "pack.perm/etc/ssh")) for i in ids), ids)


class NoFixTest(unittest.TestCase):
    def test_virus_has_no_fix(self):
        code, out, _ = go(["-f", "virus"])
        self.assertEqual(code, 1)
        self.assertIn("never deletes files on a guess", out)


class FixAskTest(unittest.TestCase):
    def test_fix_declined_changes_nothing(self):
        with mock.patch.object(runner, "elevate") as el, \
             mock.patch("murphy_lawden.cli.do_fix") as df, \
             mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("builtins.input", return_value="n"):
            code, out, _ = go(["-f", "ssh"])
        self.assertEqual(code, runner.DECLINED)
        el.assert_not_called()
        df.assert_not_called()
        self.assertIn("murphy will: fix ssh", out)

    def test_fix_yes_elevates_then_fixes_with_tag(self):
        with mock.patch.object(runner, "elevate") as el, \
             mock.patch("murphy_lawden.cli.do_fix", return_value=0) as df:
            code, _, _ = go(["-fy", "ssh"])
        self.assertEqual(code, 0)
        el.assert_called_once()
        self.assertEqual(df.call_args.kwargs["tags"], ("ssh",))

    def test_undo_ssh_uses_tag(self):
        with mock.patch.object(runner, "elevate"), \
             mock.patch("murphy_lawden.remedy.undo_latest", return_value=(False, "no ssh restore point")) as ul:
            code, out, _ = go(["-uy", "ssh"])
        ul.assert_called_once_with("ssh")
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
```

Note: `to_json` output must contain a top-level `"findings"` list of objects with `"id"`. Before writing the test, run `python3 murphy.py scan --json --no-prompt | python3 -c "import json,sys; print(list(json.load(sys.stdin)))"` and adjust the key in `test_check_ssh_json_only_ssh_findings` to the real one if it differs.

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_runner -v`
Expected: ERROR — `cannot import name 'helptext'`

- [ ] **Step 3: Write minimal implementation**

`murphy_lawden/helptext.py`:

```python
"""The words Murphy prints for -h, -e and -l. Generated from the manifests."""
from __future__ import annotations

from .areas import AREAS, Area
from .manifest import render_manifest

_TOP = """\
murphy — hardening for every situation

  murphy                 menu: pick what you want, it explains as you go
  -c, --check   [area]   look only, change nothing
  -f, --fix     [area]   harden it — shows what it will do and asks first
  -u, --undo    [area]   put it back
  -e, --explain  area    what it does, needs, changes, and how to undo it
  -x, --cage     file    run something in the sandbox
  -g, --game   [on|off]  debloat for gaming
  -k, --clean            sweep junk
  -s, --for  situation   a preset: daily, gaming, torrents, travel, compromised, fresh, throwaway
  -P, --panic            emergency menu (asks at every step)
  -l, --list             list areas and situations

  -y, --yes      don't ask (calm actions only)     -n, --dry      show, change nothing
  -v, --verbose  more detail                       -q, --quiet    less
  -j, --json     machine-readable                  -h, --help     this, or: murphy -h <area>
  -V, --version

  areas: {areas}
  no area = all of them · short flags stack: murphy -fy ssh · old commands still work
"""


def top_help() -> str:
    return _TOP.format(areas=" ".join(AREAS))


def area_help(area: Area) -> str:
    lines = [f"{area.name} — {area.covers}"]
    if area.aliases:
        lines.append(f"aliases: {', '.join(area.aliases)}")
    for action in ("check", "fix", "undo"):
        if action in area.manifests:
            lines.append("")
            lines.extend(render_manifest(area.manifests[action]))
    return "\n".join(lines) + "\n"


def areas_text() -> str:
    width = max(len(n) for n in AREAS)
    return "areas\n" + "\n".join(f"  {a.name:<{width}}  {a.covers}" for a in AREAS.values()) + "\n"
```

`murphy_lawden/runner.py` — append:

```python
import argparse

from . import __version__
from .areas import AREAS, UnknownArea, manifests_for, resolve, resolve_many
from .areas.routing import area_for
from .argv import UsageError
from .manifest import merge_needs

_FINDING_AREAS = {"net", "ssh", "users", "kernel", "disk", "apps", "firmware", "phone"}
_NO_ACTION = {
    ("virus", "fix"): "Murphy never deletes files on a guess — murphy -c virus shows what to remove",
    ("firmware", "fix"): "Murphy never touches firmware keys",
    ("firmware", "undo"): "Murphy never touches firmware keys",
}


def _ns(**kw):
    base = dict(iface=None, new_hostname=None, tz=None)
    base.update(kw)
    return argparse.Namespace(**base)


def _legacy_args(cmd: Command, verb: str):
    from .cli import build_parser
    argv = [verb, "--no-banner", "--no-prompt"]
    if cmd.yes:
        argv.append("-y")
    if cmd.dry:
        argv.append("--dry-run")
    if cmd.json:
        argv.append("--json")
    if cmd.verbose:
        argv.append("-v")
    return build_parser().parse_args(argv)


def _platform_of(host) -> str:
    has = getattr(host, "has", None)
    if callable(has) and has("android"):
        return "android"
    return host.family


def run(cmd: Command, ink, argv: list[str]) -> int:
    from . import helptext
    try:
        if cmd.action == "version":
            print(f"Murphy Lawden v{__version__}")
            return 0
        if cmd.action == "help":
            if not cmd.targets:
                print(helptext.top_help(), end="")
            for t in cmd.targets:
                print(helptext.area_help(resolve(t)), end="")
            return 0
        if cmd.action == "explain":
            if len(cmd.targets) != 1:
                raise UsageError("explain takes one area: murphy -e ssh")
            print(helptext.area_help(resolve(cmd.targets[0])), end="")
            return 0
        if cmd.action == "list":
            print(helptext.areas_text(), end="")
            return 0
        if cmd.action == "menu":
            from .cli import _wizard
            return _wizard(ink)
        if cmd.action in ("check", "fix", "undo"):
            return _run_area_action(cmd, ink, argv)
        raise UsageError(f"{cmd.action} is not wired yet")
    except (UnknownArea, UsageError) as e:
        sys.stderr.write(f"murphy: {e}\n")
        return 2


def _run_area_action(cmd: Command, ink, argv: list[str]) -> int:
    from .core import detect_host
    action = cmd.action
    areas = resolve_many(cmd.targets)
    ms, missing = manifests_for(action, areas)
    if cmd.targets:
        for name in missing:
            print(ink.amber(f"{name} has no {action}: "
                            + _NO_ACTION.get((name, action), f"nothing to {action}")))
    host = detect_host()
    plat = _platform_of(host)
    usable = []
    for m in ms:
        if plat in m.platforms:
            usable.append(m)
        elif cmd.targets:
            print(ink.dim(f"{m.area}: not on {plat} — skipped"))
    if not usable:
        return 1
    if action != "check":
        if not ask(cmd, usable, ink):
            return 0 if cmd.dry else DECLINED
        if merge_needs(usable).root:
            elevate(argv, ink)

    findings = None
    if any(m.area in _FINDING_AREAS or m.area == "virus" for m in usable) and action != "undo":
        from .cli import assemble_findings, build_parser
        from .spinner import working
        scan_args = build_parser().parse_args(["scan", "--no-prompt"])
        with working("scanning host", ink, enabled=not cmd.json):
            findings = assemble_findings(host, scan_args, False, ink)

    worst = 0
    for m in usable:
        worst = max(worst, _do(m.area, action, cmd, ink, host, findings))
    return worst


def _do(area: str, action: str, cmd: Command, ink, host, findings) -> int:
    from . import cli
    if area in _FINDING_AREAS:
        if action == "undo":
            from . import remedy
            ok, msg = remedy.undo_latest(area)
            print((ink.green if ok else ink.amber)("murphy: " + msg))
            return 0 if ok else 1
        mine = [f for f in findings if area_for(f.id) == area]
        if action == "check":
            if cmd.json:
                print(cli.to_json(host, mine))
            else:
                print(cli.render_report(host, mine, ink, cmd.verbose, banner=False,
                                        mode_label=f"check {area}"))
            from .core import Status
            return 1 if any(f.status == Status.FAIL for f in mine) else 0
        if area == "phone":
            from . import magiskmod
            out = magiskmod.build("murphy-hardening.zip")
            print(ink.green(f"✓ built {out}"))
            print(ink.dim("  systemless + reversible — install it, reboot, done:"))
            print(ink.cyan("    magisk --install-module ") + str(out))
            return 0
        args = _legacy_args(cmd, "fix")
        args.risk = "low"
        return cli.do_fix(host, mine, args, ink, tags=(area,))
    if area == "virus":
        return cli.do_av(host, findings, _legacy_args(cmd, "av"), ink, False)
    if area == "cage":
        from .ds import run_ds
        return run_ds([{"check": "status", "fix": "lock", "undo": "unlock"}[action]], ink)
    if area == "privacy":
        from .credspoof import run_spoof
        if action == "check":
            return run_spoof(_ns(facet="all", apply=False), ink)
        if action == "fix":
            return run_spoof(_ns(facet="all", apply=True), ink)
        return run_spoof(_ns(facet="restore", apply=True), ink)
    if area == "emergency":
        if action == "check":
            from .collapse import run_collapse
            return run_collapse(_ns(door=None, execute=False, thaw=False, restore=False,
                                    manifest_dir=None, wipe_data=False), ink)
        return run_emergency_menu(cmd, ink)
    raise UsageError(f"{action} {area} is not wired")


def run_emergency_menu(cmd: Command, ink) -> int:
    """Filled in by Task 8."""
    raise UsageError("the emergency menu arrives in Task 8")
```

**Do not leave the `run_emergency_menu` stub past Task 8** — Task 8 replaces it.

In `murphy_lawden/cli.py`, `do_fix` signature and Fixer line:

```python
def do_fix(host, findings: list[Finding], args, ink: Ink, tags: tuple[str, ...] = ()) -> int:
    ...
    fixer = Fixer(dry_run=args.dry_run, tags=tags)
```

Note: `privacy` check (`run_spoof(... apply=False)`) — verify by reading `credspoof.run_spoof` that `apply=False` with `facet="all"` only prints a plan. If it needs other attributes, add them to `_ns`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_runner -v` then `python3 -m unittest discover -s tests -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add murphy_lawden/runner.py murphy_lawden/helptext.py murphy_lawden/cli.py tests/test_runner.py
git commit -m "runner: check/fix/undo/explain/help per area through the manifests"
```

---

### Task 8: Cage, game, clean, panic and situations

**Files:**
- Create: `murphy_lawden/situations.py`
- Modify: `murphy_lawden/runner.py` (cage/game/clean/for/panic/list branches; real `run_emergency_menu`)
- Modify: `murphy_lawden/helptext.py` (add `list_text`)
- Test: `tests/test_situations.py`

**Interfaces:**
- Produces:
  - `situations.SITUATIONS: dict[str, tuple[str, ...]]` — steps like `"check:*"`, `"fix:ssh"`, `"game:on"`, `"clean"`.
  - `situations.DOES: dict[str, str]` — one sentence each.
  - `situations.expand(name: str) -> list[tuple[str, str | None]]` — `[("check", None), ("fix", "ssh"), ("game", "on"), ("clean", None)]`; unknown name → `UsageError` with did-you-mean.
  - `situations.describe_all() -> list[str]` — `"  <name>  <does>"` lines.
  - `helptext.list_text() -> str` = `areas_text()` + `"\nsituations\n"` + lines.
  - New manifests in `runner` (module-level constants): `GAME_ON`, `GAME_OFF`, `CLEAN`, `CAGE_RUN` (all calm; `GAME_*` need root; `CLEAN` needs root; `CAGE_RUN` needs nothing — the cage drops everything).

```python
# murphy_lawden/situations.py
"""Situations: named presets of area actions, asked as one."""
from __future__ import annotations

import difflib

from .argv import UsageError

SITUATIONS: dict[str, tuple[str, ...]] = {
    "daily":       ("check:*", "fix:ssh", "fix:kernel", "fix:net"),
    "gaming":      ("game:on",),
    "torrents":    ("fix:cage", "check:net"),
    "travel":      ("fix:net", "fix:privacy"),
    "compromised": ("check:virus", "check:*", "panic"),
    "fresh":       ("check:*", "fix:*"),
    "throwaway":   ("fix:privacy", "clean"),
}
DOES: dict[str, str] = {
    "daily":       "Checks everything, then hardens ssh, the kernel and the network.",
    "gaming":      "Debloats the box for a gaming session (murphy -g off puts it back).",
    "torrents":    "Locks the torrent folder into the cage and checks the network.",
    "travel":      "Hardens the network and rotates the identifiers this box gives away.",
    "compromised": "Malware sweep, full check, then the emergency menu.",
    "fresh":       "Checks everything and hardens everything in the calm tier.",
    "throwaway":   "Rotates identifiers and sweeps junk.",
}


def expand(name: str) -> list[tuple[str, str | None]]:
    if name not in SITUATIONS:
        close = difflib.get_close_matches(name, list(SITUATIONS), n=1, cutoff=0.6)
        tail = f"did you mean {close[0]}?" if close else "murphy -l lists them"
        raise UsageError(f"no situation '{name}' — {tail}")
    out = []
    for step in SITUATIONS[name]:
        verb, _, target = step.partition(":")
        out.append((verb, None if target in ("", "*") else target))
    return out


def describe_all() -> list[str]:
    width = max(len(n) for n in SITUATIONS)
    return [f"  {n:<{width}}  {DOES[n]}" for n in SITUATIONS]
```

Runner branches:
- `cage`: needs exactly one target → `run_ds(["run", "--auto", *cmd.passthrough, "--", target], ink)` after `ask(cmd, [CAGE_RUN], ink)`. (Read `ds/__init__.py` around line 631 to confirm `run` accepts flags before the target; if `--` is not accepted there, pass `[ "run", "--auto", *passthrough, target ]`.)
- `game`: target `on` (default) or `off`; anything else → `UsageError("game takes on or off")`. Ask with `GAME_ON`/`GAME_OFF`, elevate, then `run_ezopt("profile", True, ink=ink)` / `run_ezopt("restore", True, ink=ink)`.
- `clean`: ask with `CLEAN`; `cmd.dry` → `run_clean(False, False, ink)` (the survey) and return; else elevate if root needed → `run_clean(True, False, ink)`.
- `for`: one target; `steps = expand(target)`; collect manifests for every step (area actions via `manifests_for`, `game`/`clean`/`panic` via the constants and `AREAS["emergency"].manifests["fix"]`), one combined `ask`, one `elevate` if any needs root, then run the steps in order through the same functions with `cmd.consented=True` so nothing asks twice (dangerous steps — the emergency menu — still ask their own typed confirmations inside). Return the worst code.
- `panic` → `run_emergency_menu(cmd, ink)`.
- `list` → `list_text()`.

`run_emergency_menu`:

```python
def run_emergency_menu(cmd: Command, ink) -> int:
    m = AREAS["emergency"].manifests["fix"]
    if not ask(cmd, [m], ink):
        return 0 if cmd.dry else DECLINED
    doors = [
        ("1", "lockdown", "instant reversible lockdown (murphy kill)", ["kill"]),
        ("2", "duress", "duress tiers, dead-man switch", ["duress"]),
        ("3", "collapse", "the four last-resort doors", ["collapse"]),
        ("4", "phone", "Android spyware (Pegasus) response", ["panic"]),
    ]
    for key, name, what, _ in doors:
        print(f"   {ink.green(key)}  {ink.bone(name):<10} {ink.dim(what)}")
    print(f"   {ink.dim('0')}  {ink.dim('leave')}")
    try:
        choice = input("  choose [0-4]: ").strip()
    except EOFError:
        return 0
    route = {k: argv for k, _, _, argv in doors}.get(choice)
    if not route:
        print(ink.dim("  left as-is."))
        return 0
    from .cli import main as legacy_main
    return legacy_main(route)
```

The menu passes through `cli.main` with a legacy argv, so each door keeps its existing typed-consent gating. `legacy_main(["panic"])` must reach the legacy Pegasus flow, not the new layer — Task 9 makes `cli.main` take the legacy path when called with an explicit argv list that `is_legacy` accepts **or** when the first word is `panic`/`kill` and `MURPHY_LEGACY=1` is set; implement by calling an internal `cli._legacy_main(route)` instead (Task 9 creates it by renaming the current `main` body). Until Task 9 lands, call `cli.main(route)` and accept that `panic` routes to the old flow (the new layer is not wired into `main` yet).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_situations.py
import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

from murphy_lawden import situations, runner, helptext
from murphy_lawden.argv import parse, UsageError
from murphy_lawden.areas import AREAS
from murphy_lawden.banner import make_ink

INK = make_ink(False)


class SituationsTest(unittest.TestCase):
    def test_expand(self):
        self.assertEqual(situations.expand("daily"),
                         [("check", None), ("fix", "ssh"), ("fix", "kernel"), ("fix", "net")])

    def test_every_step_is_known(self):
        verbs = {"check", "fix", "undo", "game", "clean", "panic"}
        for name in situations.SITUATIONS:
            for verb, target in situations.expand(name):
                with self.subTest(situation=name, step=(verb, target)):
                    self.assertIn(verb, verbs)
                    if verb in ("check", "fix", "undo") and target:
                        self.assertIn(target, AREAS)
            self.assertIn(name, situations.DOES)

    def test_typo(self):
        with self.assertRaises(UsageError) as e:
            situations.expand("travl")
        self.assertIn("did you mean travel", str(e.exception))

    def test_list_has_both_sections(self):
        text = helptext.list_text()
        self.assertIn("areas", text)
        self.assertIn("situations", text)
        self.assertIn("compromised", text)


class GameCleanTest(unittest.TestCase):
    def _run(self, argv, answers=("y",)):
        it = iter(answers)
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(runner, "elevate"), \
             mock.patch("sys.stdin.isatty", return_value=True), \
             mock.patch("builtins.input", lambda _p: next(it)):
            code = runner.run(parse(argv), INK, argv)
        return code, out.getvalue()

    def test_game_on_calls_ezopt_profile(self):
        with mock.patch("murphy_lawden.ezopt.run_ezopt", return_value=0) as ez:
            code, _ = self._run(["-g"])
        ez.assert_called_once()
        self.assertEqual(ez.call_args.args[:2], ("profile", True))

    def test_game_off_restores(self):
        with mock.patch("murphy_lawden.ezopt.run_ezopt", return_value=0) as ez:
            self._run(["-g", "off"])
        self.assertEqual(ez.call_args.args[:2], ("restore", True))

    def test_game_bad_arg(self):
        code, _ = self._run(["-g", "sideways"])
        self.assertEqual(code, 2)

    def test_clean_dry_is_survey(self):
        with mock.patch("murphy_lawden.clean.run_clean", return_value=0) as rc:
            self._run(["-kn"])
        rc.assert_called_once_with(False, False, INK)

    def test_situation_asks_once(self):
        with mock.patch.object(runner, "_do", return_value=0) as do, \
             mock.patch("murphy_lawden.ezopt.run_ezopt", return_value=0):
            code, out = self._run(["-s", "daily"])
        self.assertEqual(out.count("murphy will:"), 1)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_situations -v`
Expected: ERROR — `No module named 'murphy_lawden.situations'`

- [ ] **Step 3: Write minimal implementation**

Create `situations.py` (above). In `helptext.py` add:

```python
def list_text() -> str:
    from .situations import describe_all
    return areas_text() + "\nsituations\n" + "\n".join(describe_all()) + "\n"
```

In `runner.py` add the manifest constants:

```python
from .manifest import Manifest, Needs

GAME_ON = Manifest("game", "on", "Debloats for gaming: pauses background services, frees memory, pins the CPU to performance.",
                   Needs(root=True, writes=("runtime systemd masks (gone at reboot)", "~/.local/state/murphy/ezopt.backup.json")),
                   ("services masked --runtime", "memory and CPU tuning"), "murphy -g off",
                   frozenset({"linux"}))
GAME_OFF = Manifest("game", "off", "Puts back everything murphy -g changed.",
                    Needs(root=True), ("restores from the ezopt ledger",), "murphy -g on",
                    frozenset({"linux"}))
CLEAN = Manifest("clean", "fix", "Sweeps junk: package caches, old logs, trash, temp files. Never shader caches or Downloads.",
                 Needs(root=True, writes=("package cache", "journal", "~/.cache (not shader caches)", "trash")),
                 ("deletes junk files",), "nothing to undo — junk is gone; murphy -kn shows it first",
                 frozenset({"linux"}))
CAGE_RUN = Manifest("cage", "run", "Runs the file in the sandbox: no network, no view of your home, one writable output folder.",
                    Needs(), ("nothing outside the cage's output folder",),
                    "delete the cage's output folder", frozenset({"linux", "windows"}))
```

Add branches in `run` before the final `raise`:

```python
        if cmd.action == "cage":
            return _run_cage(cmd, ink)
        if cmd.action == "game":
            return _run_game(cmd, ink, argv)
        if cmd.action == "clean":
            return _run_clean(cmd, ink, argv)
        if cmd.action == "for":
            return _run_situation(cmd, ink, argv)
        if cmd.action == "panic":
            return run_emergency_menu(cmd, ink)
```

and change the `list` branch to `print(helptext.list_text(), end="")`.

Helpers:

```python
def _run_cage(cmd, ink) -> int:
    if len(cmd.targets) != 1 and not cmd.passthrough:
        raise UsageError("cage takes one file: murphy -x setup.exe")
    if not ask(cmd, [CAGE_RUN], ink):
        return 0 if cmd.dry else DECLINED
    from .ds import run_ds
    target = cmd.targets[0] if cmd.targets else cmd.passthrough[-1]
    extra = cmd.passthrough if cmd.targets else cmd.passthrough[:-1]
    return run_ds(["run", "--auto", "-y", *extra, target], ink)


def _game_manifest(cmd) -> tuple[Manifest, str]:
    mode = (cmd.targets or ["on"])[0]
    if mode not in ("on", "off"):
        raise UsageError("game takes on or off: murphy -g / murphy -g off")
    return (GAME_ON, "profile") if mode == "on" else (GAME_OFF, "restore")


def _run_game(cmd, ink, argv) -> int:
    m, facet = _game_manifest(cmd)
    if not ask(cmd, [m], ink):
        return 0 if cmd.dry else DECLINED
    elevate(argv, ink)
    from . import ezopt
    return ezopt.run_ezopt(facet, True, ink=ink)


def _run_clean(cmd, ink, argv) -> int:
    from . import clean
    if cmd.dry:
        return clean.run_clean(False, False, ink)
    if not ask(cmd, [CLEAN], ink):
        return DECLINED
    elevate(argv, ink)
    return clean.run_clean(True, False, ink)


def _run_situation(cmd, ink, argv) -> int:
    from .situations import expand
    if len(cmd.targets) != 1:
        raise UsageError("pick one situation: murphy -l lists them")
    steps = expand(cmd.targets[0])
    ms: list[Manifest] = []
    for verb, target in steps:
        if verb in ("check", "fix", "undo"):
            found, _ = manifests_for(verb, resolve_many([target] if target else []))
            ms.extend(m for m in found if not (verb == "check" and target is None and m.area == "emergency"))
        elif verb == "game":
            ms.append(GAME_ON if target in (None, "on") else GAME_OFF)
        elif verb == "clean":
            ms.append(CLEAN)
        elif verb == "panic":
            ms.append(AREAS["emergency"].manifests["fix"])
    changing = [m for m in ms if m.action != "check"]
    if changing:
        if not ask(cmd, changing, ink):
            return 0 if cmd.dry else DECLINED
        if merge_needs(changing).root:
            elevate(argv, ink)
    from dataclasses import replace
    sub = replace(cmd, consented=True, targets=[])
    worst = 0
    for verb, target in steps:
        step_cmd = replace(sub, action=verb, targets=[target] if target else [])
        if verb in ("check", "fix", "undo"):
            worst = max(worst, _run_area_action(step_cmd, ink, argv))
        elif verb == "game":
            worst = max(worst, _run_game(step_cmd, ink, argv))
        elif verb == "clean":
            worst = max(worst, _run_clean(step_cmd, ink, argv))
        elif verb == "panic":
            worst = max(worst, run_emergency_menu(replace(cmd, consented=False), ink))
    return worst
```

Replace the `run_emergency_menu` stub with the version given in this task's Interfaces section.

Note on `test_situation_asks_once`: `_run_area_action` for `check` does not ask and for `fix` with `consented=True` skips the ask, so `"murphy will:"` appears once. `_do` is patched so no real scan or fix runs, but `_run_area_action` still calls `assemble_findings`; also patch `murphy_lawden.cli.assemble_findings` to return `[]` in that test if the scan makes it slow (> 10 s).

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_situations -v`, then the full suite.
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add murphy_lawden/situations.py murphy_lawden/runner.py murphy_lawden/helptext.py tests/test_situations.py
git commit -m "runner: cage, game, clean, emergency menu and situation presets"
```

---

### Task 9: Wire it into `murphy` — new first, legacy untouched, tip line

**Files:**
- Modify: `murphy_lawden/cli.py` (`main`: split into `main` + `_legacy_main`)
- Modify: `murphy_lawden/runner.py` (`run_emergency_menu` calls `cli._legacy_main`)
- Test: `tests/test_main.py`

**Interfaces:**
- Produces: `cli.main(argv=None) -> int` — new entry; `cli._legacy_main(argv=None) -> int` — the current `main` body, unchanged except its name.
- `main` logic:
  1. `raw = sys.argv[1:] if argv is None else argv`.
  2. If `is_legacy(raw)`: print the tip (unless `-q` in raw or stdout is not a TTY) for the mapped forms below, then `return _legacy_main(raw)`.
  3. Else `cmd = parse(raw)` (`UsageError` → stderr `murphy: <msg>` + `"murphy -h for help"`, return 2); arm amnesia (`selfwipe.arm_amnesia(ink=ink)`, same as legacy); `return runner.run(cmd, ink, raw)`.
  4. Bare interactive `murphy` (no args, both TTYs) still opens the wizard — `parse([])` gives `menu`, which calls `_wizard`.
- Tips (first word → new form): `scan` → `murphy -c`, `av` → `murphy -c virus`, `ezopt` → `murphy -g`, `spoof` → `murphy -f privacy`, `ds` → `murphy -x <file> / murphy -f cage`, `collapse`/`duress`/`kill` → `murphy -P`; flags `--su`/`--risk` with `fix` → `murphy -f [area]`. Format: `ink.dim("tip: this is now " + new)` to stderr.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_main.py
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

from murphy_lawden import cli

ROOT = Path(__file__).resolve().parent.parent


def murphy(*args, home=None):
    env = dict(os.environ)
    if home:
        env.update(HOME=home, XDG_STATE_HOME=f"{home}/.local/state",
                   XDG_CACHE_HOME=f"{home}/.cache", XDG_CONFIG_HOME=f"{home}/.config")
    return subprocess.run([sys.executable, str(ROOT / "murphy.py"), *args],
                          capture_output=True, text=True, env=env, timeout=600)


class MainTest(unittest.TestCase):
    def test_short_long_word_help_identical(self):
        a, b, c = murphy("-h", "ssh"), murphy("--help", "ssh"), murphy("help", "ssh")
        self.assertEqual(a.stdout, b.stdout)
        self.assertEqual(a.stdout, c.stdout)
        self.assertIn("does", a.stdout)

    def test_usage_error_exit_2(self):
        r = murphy("-cf")
        self.assertEqual(r.returncode, 2)
        self.assertIn("pick one", r.stderr)

    def test_legacy_goes_to_legacy(self):
        with mock.patch.object(cli, "_legacy_main", return_value=0) as lm:
            cli.main(["scan", "--json", "--no-prompt"])
        lm.assert_called_once_with(["scan", "--json", "--no-prompt"])

    def test_legacy_fix_with_su_is_legacy(self):
        with mock.patch.object(cli, "_legacy_main", return_value=0) as lm:
            cli.main(["fix", "--su", "--risk", "medium"])
        lm.assert_called_once()

    def test_new_fix_is_not_legacy(self):
        with mock.patch.object(cli, "_legacy_main") as lm, \
             mock.patch("murphy_lawden.runner.run", return_value=0) as rn:
            cli.main(["fix", "ssh"])
        lm.assert_not_called()
        rn.assert_called_once()

    def test_check_json_writes_nothing(self):
        with tempfile.TemporaryDirectory() as home:
            before = sorted(p for p in Path(home).rglob("*"))
            r = murphy("-cj", "ssh", "kernel", home=home)
            after = sorted(p for p in Path(home).rglob("*"))
        self.assertIn(r.returncode, (0, 1), r.stderr)
        self.assertEqual(before, after, "a check wrote to disk")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_main -v`
Expected: FAIL — `AttributeError: module 'murphy_lawden.cli' has no attribute '_legacy_main'`

- [ ] **Step 3: Write minimal implementation**

In `cli.py`, rename `def main(argv: list[str] | None = None) -> int:` to `def _legacy_main(argv: list[str] | None = None) -> int:` and inside it replace the two self-calls in `_wizard` (`return main(["ds"])`, `return main(route + ...)`) with `_legacy_main(...)` so the wizard's routes keep legacy behaviour. Remove the bare-TTY wizard branch from `_legacy_main` (the new `main` handles it). Then add:

```python
_TIPS = {"scan": "murphy -c", "av": "murphy -c virus", "ezopt": "murphy -g",
         "spoof": "murphy -f privacy", "ds": "murphy -x <file>  ·  murphy -f cage",
         "collapse": "murphy -P", "duress": "murphy -P", "kill": "murphy -P"}


def main(argv: list[str] | None = None) -> int:
    from .argv import UsageError, is_legacy, parse
    raw = list(sys.argv[1:] if argv is None else argv)
    ink = make_ink(None)
    if is_legacy(raw):
        tip = _TIPS.get(raw[0]) if raw else None
        if tip is None and raw[:1] == ["fix"]:
            tip = "murphy -f [area]"
        if tip and "-q" not in raw and sys.stderr.isatty():
            sys.stderr.write(ink.dim(f"tip: this is now {tip}\n"))
        return _legacy_main(raw)
    try:
        cmd = parse(raw)
    except UsageError as e:
        sys.stderr.write(f"murphy: {e}\nmurphy -h for help\n")
        return 2
    from .selfwipe import arm_amnesia
    arm_amnesia(ink=ink)
    from . import runner
    return runner.run(cmd, ink, raw)
```

Note: `raw[0] == "fix"` with legacy flags → legacy (tip printed); plain `murphy fix` → new layer (fix everything in the calm tier, with the ask). `murphy undo` (no flags) → new layer: no target means every area; for undo with no target, `_run_area_action` must call `remedy.undo_latest()` once (untagged, same as today) instead of once per area — add that special case at the top of `_run_area_action`: `if action == "undo" and not cmd.targets:` → ask with a single `Manifest("everything","undo","Rolls back the most recent fix, whatever area it was.", Needs(root=True), ("restores the last restore point",), "murphy -f again", frozenset({"linux","bsd","macos"}))`, elevate, `undo_latest()`.

In `runner.run_emergency_menu` change the last two lines to:

```python
    from .cli import _legacy_main
    return _legacy_main(route)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS (all suites). Then by hand, in a terminal:
- `python3 murphy.py -h` — the new top help.
- `python3 murphy.py -e cage` — the cage manifest.
- `python3 murphy.py -fn ssh` — the ask block plus "dry run — nothing will change", exit 0.
- `python3 murphy.py scan --no-prompt | head` — the old report, with the dim tip on stderr.
- `python3 murphy.py` — the wizard.

- [ ] **Step 5: Commit**

```bash
git add murphy_lawden/cli.py murphy_lawden/runner.py tests/test_main.py
git commit -m "cli: new verb-first front door; old commands go to the old parser with a tip"
```

---

### Task 10: README and push

**Files:**
- Modify: `README.md` (replace the `## Usage` code block)

- [ ] **Step 1: Replace the Usage block** with the exact text of `helptext.top_help()` (run `python3 murphy.py -h` and paste its output inside the fenced block), followed by:

```markdown
Every area explains itself before it does anything: `murphy -e ssh` prints what
`check`, `fix` and `undo` do, what they need (root, network, devices, files) and
how to put things back. `fix`/`undo` show that summary and ask first; dangerous
actions (the emergency menu) ask you to type `yes` at every step, and `-y` never
skips that. Every old command (`scan`, `fix --su`, `ds`, `ezopt`, ...) still works.
```

- [ ] **Step 2: Run the whole suite one last time**

Run: `python3 -m unittest discover -s tests -v`
Expected: all PASS.

- [ ] **Step 3: Commit and push**

```bash
git add README.md
git commit -m "README: the new commands"
git push origin main
```

If the push returns `remote: Internal Server Error`, wait a few minutes and retry; it was GitHub-side on 2026-10-07.
