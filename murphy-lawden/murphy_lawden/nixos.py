"""Make Murphy's fixes *stick* on NixOS — the declarative half of the autopilot.

On NixOS an imperative `sysctl -w` is undone by the next rebuild. So instead of
poking the running kernel, Murphy writes the hardening into the config and asks
you to rebuild. The reliable way to do that (rather than fragile in-place surgery
on your hand-written configuration.nix) is:

  * Murphy owns ONE generated module — ``murphy-hardening.nix`` — that it can
    rewrite deterministically. Every option is ``lib.mkDefault``, so it fills gaps
    and NEVER overrides a value you set yourself (no duplicate-attribute errors).
  * The only edit to your own file is a single, idempotent ``import`` line, added
    with ``sed`` — the "would you like Murphy to use sed?" moment.
  * Before anything is activated, ``nixos-rebuild dry-build`` proves the config
    still evaluates; if it doesn't, Murphy rolls the change back.

Everything here is opt-in and reversible (backups + ``murphy undo``); the rebuild
itself is never run without an explicit yes.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .core import have, read, run

MODULE_NAME = "murphy-hardening.nix"
_HEADER = (
    "# Managed by murphy-lawden — do not hand-edit; regenerated on each apply.\n"
    "# To fully revert: delete this file and its import from configuration.nix\n"
    "# (or run `murphy undo`).  Every option is mkDefault, so your own settings win.\n"
    "{ lib, ... }:\n{\n"
)


@dataclass
class NixTarget:
    config_path: str          # the .nix file we add the import to
    is_flake: bool
    flake_dir: str            # dir holding flake.nix (for --flake DIR#host)
    host: str                 # nixosConfigurations.<host>

    @property
    def module_path(self) -> str:
        return os.path.join(os.path.dirname(self.config_path), MODULE_NAME)


# --------------------------------------------------------------------------- #
#  Detection
# --------------------------------------------------------------------------- #
def detect_nix_config(config_override: str | None = None,
                      host_override: str | None = None) -> NixTarget | None:
    nixdir = "/etc/nixos"
    flake = os.path.join(nixdir, "flake.nix")
    is_flake = os.path.exists(flake)
    host = host_override or ""
    config = config_override or ""

    if is_flake and (not host or not config):
        ftext = read(flake) or ""
        if not host:
            m = re.search(r"nixosConfigurations\.([A-Za-z0-9_-]+)", ftext)
            host = m.group(1) if m else ""
        if not config:
            # first ./<file>.nix referenced in a modules = [ ... ] list
            m = re.search(r"modules\s*=\s*\[(.*?)\]", ftext, re.S)
            region = m.group(1) if m else ftext
            fm = re.search(r"\./([A-Za-z0-9_./-]+\.nix)", region)
            config = os.path.join(nixdir, fm.group(1)) if fm else ""

    if not config:
        config = os.path.join(nixdir, "configuration.nix")
    if not host:
        import platform
        host = platform.node() or "nixos"

    if not os.path.exists(config):
        return None
    return NixTarget(config_path=config, is_flake=is_flake, flake_dir=nixdir, host=host)


# --------------------------------------------------------------------------- #
#  The generated module (Murphy owns it entirely)
# --------------------------------------------------------------------------- #
def render_module(options: dict[str, str]) -> str:
    body = "".join(f"  {lhs} = lib.mkDefault {val};\n"
                   for lhs, val in sorted(options.items()))
    return _HEADER + body + "}\n"


def write_module(target: NixTarget, options: dict[str, str], rp=None) -> str:
    """(Re)write murphy-hardening.nix. Backs up any prior version via rp."""
    path = target.module_path
    if rp is not None:
        rp.backup(path)  # records restore (or remove-if-new) for `murphy undo`
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_module(options))
    return path


# --------------------------------------------------------------------------- #
#  The one sed touch to the user's file: ensure the import
# --------------------------------------------------------------------------- #
def _sed(script: str, path: str) -> bool:
    rc, _ = run(["sed", "-i", script, path])
    return rc == 0


def ensure_import(target: NixTarget, rp=None) -> bool:
    """Idempotently add ./murphy-hardening.nix to the config's imports, via sed.

    Returns True if the file was changed. Handles the single-line and multi-line
    `imports = [ ... ]` forms; if there's no imports attr, adds one before the
    closing brace."""
    if not have("sed"):
        raise RuntimeError("sed not found — can't wire the import in.")
    text = read(target.config_path)
    if text is None:
        raise RuntimeError(f"can't read {target.config_path}")
    if MODULE_NAME in text:
        return False  # already imported

    if rp is not None:
        rp.backup(target.config_path)

    lines = text.splitlines()
    ref = f"./{MODULE_NAME}"
    for i, line in enumerate(lines):
        if re.search(r"\bimports\s*=\s*\[", line):
            after = line.split("[", 1)[1]
            if "]" in after:
                # single-line list: slip the ref in before its closing bracket
                return _sed(f"{i+1}s|\\]|{ref} ]|", target.config_path)
            # multi-line list: append the ref right after `imports = [`
            return _sed(f"{i+1}a\\  {ref}", target.config_path)

    # No imports attr at all — add one just before the final closing brace.
    return _sed(f"$ i\\  imports = [ {ref} ];", target.config_path)


def remove_import(target: NixTarget) -> None:
    """Best-effort undo helper: strip the import ref back out (used on rollback)."""
    ref = re.escape(f"./{MODULE_NAME}")
    _sed(f"s| *{ref}||", target.config_path)


# --------------------------------------------------------------------------- #
#  Validate & activate
# --------------------------------------------------------------------------- #
def _rebuild_cmd(target: NixTarget, action: str) -> list[str]:
    if target.is_flake:
        return ["nixos-rebuild", action, "--flake", f"{target.flake_dir}#{target.host}"]
    return ["nixos-rebuild", action]


def dry_build(target: NixTarget) -> tuple[bool, str]:
    """Evaluate + build the new config WITHOUT activating it. The safety gate."""
    if not have("nixos-rebuild"):
        return False, "nixos-rebuild not found"
    rc, out = run(_rebuild_cmd(target, "dry-build"), timeout=900)
    return rc == 0, out


def switch(target: NixTarget, use_sudo: bool) -> tuple[bool, str]:
    """Activate the new config (needs root). Only ever called after a yes."""
    cmd = _rebuild_cmd(target, "switch")
    if use_sudo and not (hasattr(os, "geteuid") and os.geteuid() == 0):
        cmd = ["sudo"] + cmd
    rc, out = run(cmd, timeout=1800)
    return rc == 0, out
