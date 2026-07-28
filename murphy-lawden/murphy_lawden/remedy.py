"""The autopilot: Murphy doesn't just name what went wrong, he fixes it.

A ``Remedy`` is a small, ordered list of concrete operations attached to a
finding. The ``Fixer`` executes them behind two guarantees a serious operator
expects:

  * **Reversible** — every file Murphy touches is backed up to a restore point
    before the first change, and every action records how to undo it. ``murphy
    undo`` rolls the last job back.
  * **Deliberate** — dry-run is the default (he shows the plan, changes nothing).
    Applying needs root and a risk budget: only fixes at or below the chosen risk
    level run, so autopilot never quietly makes a lockout-class change.

Taking action necessarily writes to disk — that is the one place Murphy steps
out of pure-recon amnesia, and he says so, and he leaves you the way back.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Remedy:
    """What the autopilot can do about a finding."""
    summary: str                       # one line: what applying this changes
    steps: list[dict]                  # ordered operations (see _apply_step)
    risk: str = "low"                  # low | medium | high (lockout-class = high)
    requires_root: bool = True
    nixos_note: str = ""               # how to make it permanent on a declarative host
    nix: tuple | None = None           # (lhs, nix-value) for the NixOS declarative path

    def within(self, budget: str) -> bool:
        return RISK_ORDER.get(self.risk, 2) <= RISK_ORDER.get(budget, 0)


def _nix_scalar(value: str) -> str:
    """Format a plain value as a Nix literal: bare int if numeric, else a string."""
    return value if re.fullmatch(r"-?\d+", value or "") else f'"{value}"'


# --------------------------------------------------------------------------- #
#  Restore points
# --------------------------------------------------------------------------- #
def _state_dir() -> Path:
    base = "/var/lib/murphy" if os.geteuid() == 0 else os.path.expanduser("~/.local/state/murphy")
    return Path(base) / "restore"


class RestorePoint:
    """A timestamped backup + undo journal for one ``fix`` run."""

    def __init__(self):
        self.id = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.dir = _state_dir() / self.id
        self.journal: list[dict] = []
        self._backed_up: set[str] = set()

    def _ensure(self):
        (self.dir / "files").mkdir(parents=True, exist_ok=True)

    def backup(self, path: str):
        """Copy a file into the restore point once, before it's modified."""
        if path in self._backed_up:
            return
        self._ensure()
        self._backed_up.add(path)
        if os.path.exists(path):
            dest = self.dir / "files" / path.strip("/").replace("/", "%")
            shutil.copy2(path, dest)
            self.journal.append({"type": "restore_file", "path": path, "backup": str(dest)})
        else:
            # File didn't exist — undo means delete whatever we create.
            self.journal.append({"type": "remove_file", "path": path})

    def record_cmd(self, undo_cmd: list[str] | None):
        if undo_cmd:
            self.journal.append({"type": "run", "cmd": undo_cmd})

    def commit(self):
        if not self.journal:
            return
        self._ensure()
        (self.dir / "journal.json").write_text(
            json.dumps({"id": self.id, "actions": self.journal}, indent=2))

    @staticmethod
    def latest() -> Path | None:
        d = _state_dir()
        points = sorted((p for p in d.glob("*") if (p / "journal.json").exists()),
                        key=lambda p: p.name) if d.exists() else []
        return points[-1] if points else None


# --------------------------------------------------------------------------- #
#  The Fixer
# --------------------------------------------------------------------------- #
@dataclass
class StepResult:
    ok: bool
    message: str


@dataclass
class FixResult:
    finding_id: str
    title: str
    applied: bool
    dry_run: bool
    messages: list[str] = field(default_factory=list)


def _set_directive(text: str, key: str, value: str) -> str:
    """Set/replace a `Key Value` directive (sshd_config style), idempotently."""
    pat = re.compile(rf"(?im)^\s*#?\s*{re.escape(key)}\b.*$")
    line = f"{key} {value}"
    if pat.search(text):
        return pat.sub(line, text, count=1)
    return (text.rstrip("\n") + "\n" + line + "\n") if text else line + "\n"


def _ensure_line(text: str, line: str) -> str:
    if any(l.strip() == line.strip() for l in text.splitlines()):
        return text
    return (text.rstrip("\n") + "\n" + line + "\n") if text else line + "\n"


class Fixer:
    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self.rp = None if dry_run else RestorePoint()

    def _apply_step(self, step: dict, out: list[str]) -> bool:
        op = step.get("op")

        if op == "run":
            cmd = step["cmd"]
            if self.dry_run:
                out.append("would run: " + " ".join(cmd))
                return True
            if self.rp:
                self.rp.record_cmd(step.get("undo_cmd"))
            p = subprocess.run(cmd, capture_output=True, text=True)
            out.append(("ran: " if p.returncode == 0 else "FAILED: ") + " ".join(cmd)
                       + (f" ({p.stderr.strip()})" if p.returncode else ""))
            return p.returncode == 0

        if op == "chmod":
            path, mode = step["path"], int(str(step["mode"]), 8)
            if self.dry_run:
                out.append(f"would chmod {oct(mode)[2:]} {path}")
                return True
            if not os.path.exists(path):
                out.append(f"skip chmod (absent): {path}")
                return True
            self.rp.backup(path)
            self.rp.journal.append({"type": "chmod", "path": path,
                                    "mode": oct(os.stat(path).st_mode & 0o777)})
            os.chmod(path, mode)
            out.append(f"chmod {oct(mode)[2:]} {path}")
            return True

        if op in ("set_directive", "ensure_line", "write_file"):
            path = step["path"]
            if self.dry_run:
                what = {"set_directive": f"set '{step.get('key')} {step.get('value')}' in",
                        "ensure_line": f"ensure line {step.get('line')!r} in",
                        "write_file": "write"}[op]
                out.append(f"would {what} {path}")
                return True
            self.rp.backup(path)
            cur = ""
            if os.path.exists(path):
                cur = Path(path).read_text(encoding="utf-8", errors="replace")
            if op == "set_directive":
                new = _set_directive(cur, step["key"], step["value"])
            elif op == "ensure_line":
                new = _ensure_line(cur, step["line"])
            else:
                new = step["content"]
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            Path(path).write_text(new, encoding="utf-8")
            out.append(f"updated {path}")
            return True

        out.append(f"unknown op: {op!r}")
        return False

    def apply(self, finding) -> FixResult:
        r: Remedy = finding.remedy
        out: list[str] = []
        ok = True
        for step in r.steps:
            if not self._apply_step(step, out):
                ok = False
                break
        if self.rp:
            self.rp.commit()
        return FixResult(finding.id, finding.title, applied=(ok and not self.dry_run),
                         dry_run=self.dry_run, messages=out)


# --------------------------------------------------------------------------- #
#  Undo
# --------------------------------------------------------------------------- #
def undo_latest() -> tuple[bool, str]:
    point = RestorePoint.latest()
    if point is None:
        return False, "no restore point found — nothing to undo."
    data = json.loads((point / "journal.json").read_text())
    # Reverse order: last change undone first.
    for action in reversed(data["actions"]):
        t = action["type"]
        try:
            if t == "restore_file":
                shutil.copy2(action["backup"], action["path"])
            elif t == "remove_file":
                if os.path.exists(action["path"]):
                    os.remove(action["path"])
            elif t == "chmod":
                os.chmod(action["path"], int(action["mode"], 8))
            elif t == "run":
                subprocess.run(action["cmd"], capture_output=True)
        except OSError as e:
            return False, f"undo hit an error on {action.get('path', action)}: {e}"
    return True, f"rolled back restore point {data['id']} ({len(data['actions'])} actions)."


# --------------------------------------------------------------------------- #
#  Remedy builders (used by the checks)
# --------------------------------------------------------------------------- #
def sysctl_remedy(key: str, value: str) -> Remedy:
    return Remedy(
        summary=f"set {key}={value} now and persist it",
        risk="low",
        steps=[
            {"op": "run", "cmd": ["sysctl", "-w", f"{key}={value}"]},
            {"op": "ensure_line", "path": "/etc/sysctl.d/60-murphy.conf",
             "line": f"{key} = {value}"},
        ],
        nixos_note=f'boot.kernel.sysctl."{key}" = "{value}";',
        nix=(f'boot.kernel.sysctl."{key}"', _nix_scalar(value)),
    )


def chmod_remedy(path: str, mode: str) -> Remedy:
    return Remedy(summary=f"chmod {mode} {path}", risk="low",
                  steps=[{"op": "chmod", "path": path, "mode": mode}])


def sshd_remedy(key: str, value: str, risk: str = "medium") -> Remedy:
    return Remedy(
        summary=f"set '{key} {value}' in sshd_config and reload sshd",
        risk=risk,
        steps=[
            {"op": "set_directive", "path": "/etc/ssh/sshd_config", "key": key, "value": value},
            {"op": "run", "cmd": ["systemctl", "reload", "sshd"],
             "undo_cmd": ["systemctl", "reload", "sshd"]},
        ],
        nixos_note=f'services.openssh.settings.{key} = '
                   f'{"false" if value == "no" else f"\"{value}\""};',
        nix=(f"services.openssh.settings.{key}",
             "false" if value == "no" else f'"{value}"'),
    )
