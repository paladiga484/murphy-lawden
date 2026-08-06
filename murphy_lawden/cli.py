"""Command line: detect the host, work the case, file the report.

Amnesiac by design — output goes to stdout and nothing touches disk unless the
operator explicitly passes --save (which prints a warning, because it breaks the
one promise Murphy makes to a Tails/Qubes user).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from . import checks_linux  # noqa: F401  (import registers the linux checks)
from . import checks_malware  # noqa: F401  (import registers the malware/AV checks)
from . import checks_android  # noqa: F401  (import registers the Android/su checks)
from .banner import Ink, WATERMARK, make_ink, render_banner, rule
from .core import Finding, Severity, Status, detect_host, have, run_checks
from .rules import load_pack, run_pack

_STATUS_TAG = {
    Status.FAIL: "FAIL", Status.WARN: "WARN", Status.PASS: " OK ",
    Status.INFO: "INFO", Status.SKIP: "SKIP",
}
_SEV_NAME = {Severity.CRITICAL: "CRIT", Severity.HIGH: "HIGH", Severity.MEDIUM: "MED",
             Severity.LOW: "LOW", Severity.INFO: "—"}


# --------------------------------------------------------------------------- #
#  Scoring & verdict
# --------------------------------------------------------------------------- #
def is_malware_finding(f: Finding) -> bool:
    """The 'antivirus' view: built-in integrity heuristics (``mal.*``) plus the
    known-bad / RAT / spyware IOC packs (``pack.ioc*``). Kept separate from the
    hardening findings so the two concerns read cleanly and both feed ``murphy av``."""
    return f.id.startswith("mal.") or f.id.startswith("pack.ioc")


def score(findings: list[Finding]) -> int:
    exposure = sum(f.weight for f in findings if f.status == Status.FAIL)
    exposure += 2 * sum(1 for f in findings if f.status == Status.WARN)
    return max(0, 100 - exposure)


def grade(s: int) -> str:
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


_VERDICTS = {
    "A": "Clean scene. Murphy tips his hat and shows himself out.",
    "B": "A couple loose ends. Nothing the fixer can't tie off before dawn.",
    "C": "This place has been turned over. Roll up your sleeves.",
    "D": "Somebody's been in here — doors unlocked, windows wide open.",
    "F": "It's a crime scene. Everything that could go wrong, went wrong.",
}


# --------------------------------------------------------------------------- #
#  Rendering
# --------------------------------------------------------------------------- #
def _tag(ink: Ink, f: Finding) -> str:
    color = {
        Status.FAIL: ink.red_b, Status.WARN: ink.amber, Status.PASS: ink.green,
        Status.INFO: ink.dim, Status.SKIP: ink.dim,
    }[f.status]
    return color(f"[{_STATUS_TAG[f.status]}]")


def _sev(ink: Ink, f: Finding) -> str:
    color = {
        Severity.CRITICAL: ink.red_b, Severity.HIGH: ink.blood, Severity.MEDIUM: ink.amber,
        Severity.LOW: ink.cyan, Severity.INFO: ink.dim,
    }[f.severity]
    return color(f"{_SEV_NAME[f.severity]:>4}")


def render_report(host, findings: list[Finding], ink: Ink, verbose: bool, banner: bool,
                  mode_label: str = "offline · user") -> str:
    out: list[str] = []
    if banner:
        out.append(render_banner(ink))
        out.append("")

    # Case header — who we're looking at.
    out.append(rule(ink, "CASE FILE"))
    profile = [
        ("subject", host.hostname or "(unknown host)"),
        ("system", f"{host.pretty}  ·  kernel {host.kernel}"),
        ("family", f"{host.family}  ·  init={host.init}  ·  libc={host.libc}  ·  pkg={host.pkg}"),
    ]
    env = host.env_label()
    if env:
        profile.append(("running on", env))
    profile += [
        ("mode", mode_label),
        ("access", "root (full visibility)" if host.is_root
                   else "unprivileged (some checks limited — re-run as root for the full sweep)"),
    ]
    for k, v in profile:
        out.append(f"  {ink.dim(k+':'):<18} {v}")
    out.append("")

    order = {Status.FAIL: 0, Status.WARN: 1, Status.INFO: 2, Status.SKIP: 3, Status.PASS: 4}
    findings = sorted(findings, key=lambda f: (order[f.status], -int(f.severity)))

    def emit(f: Finding):
        out.append(f"  {_tag(ink, f)} {_sev(ink, f)}  {ink.bone(f.title)}")
        if f.detail:
            out.append(f"        {ink.dim(f.detail)}")
        if verbose or f.status in (Status.FAIL,):
            if f.rationale:
                out.append(f"        {ink.dim('why: ')}{f.rationale}")
            if f.fix:
                out.append(f"        {ink.cyan('fix: ')}{f.fix}")
            for tag, note in f.fix_notes.items():
                out.append(f"        {ink.cyan(f'fix ({tag}): ')}{note}")
            if f.refs and verbose:
                out.append(f"        {ink.dim('ref: ' + '; '.join(f.refs))}")

    fails = [f for f in findings if f.status == Status.FAIL]
    warns = [f for f in findings if f.status == Status.WARN]
    infos = [f for f in findings if f.status == Status.INFO]
    skips = [f for f in findings if f.status == Status.SKIP]
    passes = [f for f in findings if f.status == Status.PASS]

    # Malware/integrity findings get their own heading (the "antivirus" view);
    # keep them out of the hardening sections so the two concerns read cleanly.
    _is_mal = is_malware_finding

    def _hard(bucket):
        return [f for f in bucket if not _is_mal(f)]

    if _hard(fails):
        out.append(rule(ink, "FINDINGS — WHAT WENT WRONG"))
        for f in _hard(fails):
            emit(f)
        out.append("")
    if _hard(warns):
        out.append(rule(ink, "WORTH A LOOK"))
        for f in _hard(warns):
            emit(f)
        out.append("")
    if verbose and _hard(infos):
        out.append(rule(ink, "NOTES"))
        for f in _hard(infos):
            emit(f)
        out.append("")

    # MALWARE / INTEGRITY — the antivirus view. Non-PASS always; PASS with -v.
    mal = [f for f in findings if _is_mal(f) and (verbose or f.status != Status.PASS)]
    if mal:
        out.append(rule(ink, "MALWARE / INTEGRITY"))
        for f in sorted(mal, key=lambda f: (order[f.status], -int(f.severity))):
            emit(f)
        out.append(f"  {ink.dim('deeper signature scan (ClamAV) + full walk: ')}{ink.cyan('murphy av')}")
        out.append("")

    if verbose and passes:
        out.append(rule(ink, "HOLDING UP"))
        for f in passes:
            emit(f)
        out.append("")

    # Verdict.
    s = score(findings)
    g = grade(s)
    gcolor = ink.green if g in ("A", "B") else ink.amber if g == "C" else ink.red_b
    out.append(rule(ink, "VERDICT"))
    out.append(f"  hardening score: {gcolor(f'{s}/100  (grade {g})')}")
    out.append(f"  {ink.dim(_VERDICTS[g])}")
    counts = (f"{len(fails)} failed · {len(warns)} to watch · {len(passes)} holding · "
              f"{len(skips)} not determined")
    out.append(f"  {ink.dim(counts)}")

    # Plain-language read on the results: what actually hurts, and the next move.
    out.append("")
    out.append(f"  {ink.bone('what this means')}")
    if fails:
        crit = [f for f in fails if f.severity >= Severity.HIGH]
        lead = crit or fails
        worst = max(lead, key=lambda f: int(f.severity))
        out.append(f"    {ink.dim('·')} Biggest exposure: {ink.bone(worst.title)} "
                   f"{ink.dim('(' + _SEV_NAME[worst.severity].strip() + ')')}.")
        if worst.rationale:
            out.append(f"      {ink.dim(worst.rationale)}")
        top = sorted(fails, key=lambda f: -int(f.severity))[:3]
        if len(fails) > 1:
            out.append(f"    {ink.dim('·')} Also failing: "
                       + ", ".join(f.title for f in top[1:] or top) + ".")
        auto = [f for f in fails if f.remedy is not None]
        if auto:
            out.append(f"    {ink.dim('·')} {ink.green(str(len(auto)))} of these Murphy can fix "
                       f"for you — say yes to the menu below, or run "
                       f"{ink.cyan('murphy fix --su')}.")
        manual = [f for f in fails if f.remedy is None]
        if manual:
            out.append(f"    {ink.dim('·')} {len(manual)} need a human call "
                       f"(no safe auto-fix): {ink.dim(', '.join(f.title for f in manual[:3]))}"
                       + (" …" if len(manual) > 3 else "") + ".")
    else:
        out.append(f"    {ink.dim('·')} No hard failures. "
                   + ("Tighten the WORTH-A-LOOK items to push the grade up." if warns
                      else "The doors Murphy checks are locked.") )
    if not host.is_root and skips:
        out.append(f"    {ink.dim('·')} {len(skips)} check(s) couldn't be determined without root — "
                   f"re-run as {ink.cyan('sudo murphy scan')} for the full picture.")
    out.append("")
    out.append(ink.dim(f"amnesiac run — nothing written to disk · {WATERMARK}"))
    return "\n".join(out)


def to_json(host, findings: list[Finding]) -> str:
    return json.dumps({
        "tool": "murphy-lawden", "version": __version__,
        "watermark": WATERMARK, "amnesiac": True,
        "host": {
            "hostname": host.hostname, "system": host.system, "family": host.family,
            "distro": host.distro_id, "pretty": host.pretty, "kernel": host.kernel,
            "init": host.init, "libc": host.libc, "pkg": host.pkg,
            "env": host.env_label(), "is_root": host.is_root, "tags": sorted(host.tags),
        },
        "score": score(findings), "grade": grade(score(findings)),
        "findings": [{
            "id": f.id, "title": f.title, "status": f.status.name,
            "severity": f.severity.name, "detail": f.detail,
            "rationale": f.rationale, "fix": f.fix, "fix_notes": f.fix_notes, "refs": f.refs,
        } for f in findings],
    }, indent=2)


# --------------------------------------------------------------------------- #
#  Entry point
# --------------------------------------------------------------------------- #
_HELP_DESCRIPTION = """\
Murphy Lawden — the fixer you call when everything that could've gone wrong, went wrong.

A defensive system-hardening toolkit. By default it only *looks*: it profiles the
host, runs a battery of read-only checks (SSH, firewall, kernel sysctls, accounts,
file permissions, listening ports, disk/boot, systemd exposure) plus a vetted
library of community check-packs, and files a graded report. Nothing is written to
disk on a scan — Murphy is amnesiac. Taking action is always a separate, consented
step ('fix'), every change is backed up, and 'undo' rolls the last job back.
"""

_HELP_EPILOG = """\
the four modes (network × privilege)
  Two independent axes decide how Murphy works:
    · network   — offline (nothing leaves the box) vs online (fetch packs / tools)
    · privilege — no-sudo (touch only what your user owns) vs · su (elevate for root)
  They combine into four modes. After a scan Murphy offers them as a menu (1–4);
  you can also pick one up front with the flags below.

    1  offline        NO network, NO sudo — the safe default.
                      Uses only the tools already installed, sends nothing out, and
                      applies just the fixes that live in *your* space: files you own
                      (chmod on your dotfiles/keys), your user crontab, per-user
                      config. Anything needing root — firewall, kernel sysctls, the
                      sshd config, system file modes — is DIAGNOSED and left for you
                      with the exact command, not applied. Good for a locked-down or
                      air-gapped box, or a first look before you trust it with sudo.

    2  offline · su   Still NO network, but elevates with sudo so it can actually
                      APPLY the root-level fixes it could only report in mode 1
                      (firewall rules, sysctl, sshd hardening, system file modes).
                      Every change is backed up; 'murphy undo' rolls the job back.

    3  online         Network YES, sudo NO.
                      Everything mode 1 does, plus it reaches out (direct / tor / dns)
                      to pull extra vetted check-packs and OFFERS to install the
                      hardening tools you're missing. Installs and root fixes that
                      need privilege are still only proposed, never forced — you stay
                      unprivileged the whole time.

    4  online · su    The full treatment: online + sudo. Fetch packs, install tools,
                      apply every in-budget fix. Backed up and undoable like mode 2.

  Flags map onto the same axes:  --online / --su / --mode {offline,online,su,online-su}
  Mnemonic: · su means "may touch the whole system"; no-su means "only my own stuff".

examples
  murphy                      scan this host, print a graded report, offer to harden
  murphy scan -v              verbose scan (show passing checks + references)
  murphy scan --json          machine-readable report (still stdout only)
  murphy fix --su             elevate and apply low-risk fixes, asking before each
  murphy fix --su -y          autopilot: apply everything in the risk budget
  murphy fix --dry-run        show exactly what would change, touch nothing
  murphy --online --via tor   scan + pull extra packs anonymised over Tor
  murphy undo                 roll back the most recent fix

  risk budget: --risk low|medium|high  (fixes above the budget are left untouched)
  amnesia:     scans write nothing; only 'fix' (with backups) and --save touch disk.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="murphy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=_HELP_DESCRIPTION,
        epilog=_HELP_EPILOG)
    p.add_argument("command", nargs="?", default="scan",
                   choices=["scan", "fix", "av", "undo", "panic", "version"],
                   help="scan (default) audits; fix takes action (asks first); "
                        "av runs the antivirus (heuristics + ClamAV); "
                        "undo rolls back the last fix; panic runs the Android "
                        "mercenary-spyware (Pegasus) emergency-response flow; "
                        "version prints the build.")
    # Two axes — network and privilege — compose into the four operating modes.
    p.add_argument("--mode", choices=["offline", "online", "su", "online-su"],
                   help="shorthand for the four modes. offline+unprivileged is the default.")
    p.add_argument("--online", action="store_true",
                   help="online mode: fetch check-packs over the network. Default is offline, "
                        "which uses only the pre-staged bundled library (air-gapped).")
    p.add_argument("--via", choices=["direct", "tor", "dns"], default="direct",
                   help="online transport: direct HTTP, anonymised over tor, or covert over dns.")
    p.add_argument("--su", action="store_true",
                   help="elevate to root (re-execs via sudo if needed). Required to apply fixes.")
    p.add_argument("--risk", choices=["low", "medium", "high"], default="low",
                   help="fix: only apply remedies at or below this risk (default: low).")
    p.add_argument("--nix-config", metavar="PATH",
                   help="NixOS: the .nix file to add the hardening import to "
                        "(default: auto-detected from the flake, else /etc/nixos/configuration.nix).")
    p.add_argument("--nix-host", metavar="NAME",
                   help="NixOS: the nixosConfigurations.<NAME> to dry-build/switch (default: auto).")
    p.add_argument("--target", action="append", default=[], metavar="PATH",
                   help="av: a path to signature-scan (repeatable). Default: home + /tmp + scratch dirs.")
    p.add_argument("-y", "--yes", action="store_true",
                   help="fix: don't ask per action — apply everything in the risk budget (autopilot).")
    p.add_argument("--dry-run", action="store_true",
                   help="fix: show exactly what Murphy would do, change nothing.")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show passing checks, notes, and references too.")
    p.add_argument("--json", action="store_true", help="machine-readable output (still stdout only).")
    p.add_argument("--pack", action="append", default=[], metavar="PATH|URL",
                   help="load a community check-pack (file or http[s] URL). Repeatable. "
                        "Loaded in-memory; never cached to disk.")
    p.add_argument("--only", metavar="TEXT", help="only show findings whose id/title contains TEXT.")
    p.add_argument("--no-banner", action="store_true", help="skip the header art.")
    p.add_argument("--no-prompt", action="store_true",
                   help="scan: don't offer the interactive 'harden now?' menu at the end.")
    p.add_argument("--tui", action="store_true",
                   help="scan: review the report and pick a mode in a full-screen wizard "
                        "(falls back to the text menu if the terminal can't host it).")
    color = p.add_mutually_exclusive_group()
    color.add_argument("--no-color", action="store_true", help="disable ANSI colour.")
    color.add_argument("--color", action="store_true", help="force ANSI colour.")
    p.add_argument("--save", metavar="FILE",
                   help="write the report to FILE — WARNING: breaks amnesia (leaves a trace on disk).")
    return p


def _resolve_mode(args) -> tuple[bool, bool]:
    """Fold --mode and the --online/--su flags into (online, su)."""
    online, su = args.online, args.su
    if args.mode == "online":
        online = True
    elif args.mode == "su":
        su = True
    elif args.mode == "online-su":
        online = su = True
    return online, su


def _elevate(argv0_args: list[str], ink: Ink) -> None:
    """su mode: re-exec the whole invocation under sudo, then never return."""
    import os
    import shutil
    if not shutil.which("sudo"):
        sys.stderr.write(ink.red_b("murphy: su mode needs sudo, which isn't installed.\n"))
        raise SystemExit(2)
    sys.stderr.write(ink.dim("murphy: su mode — re-executing under sudo…\n"))
    cmd = ["sudo", os.path.abspath(sys.argv[0]), *argv0_args]
    os.execvp("sudo", cmd)  # replaces this process


_BUNDLED_PACKS = Path(__file__).resolve().parent.parent / "packs"


def _is_remote(src: str) -> bool:
    return src.lower().startswith(("http://", "https://", "dns:"))


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that describe the *same* underlying issue from more than one
    source. The builtin checks run first and carry richer remediation (a Remedy, refs,
    a NixOS note), so the first occurrence of a dedupe_key wins and later duplicates
    (typically a community pack re-checking the same sysctl) are dropped — this also
    stops the score double-counting a single weakness. Findings without a key (the
    common case) are never touched."""
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        if f.dedupe_key:
            if f.dedupe_key in seen:
                continue
            seen.add(f.dedupe_key)
        out.append(f)
    return out


def assemble_findings(host, args, online: bool, ink: Ink) -> list[Finding]:
    """Host checks + the pre-staged bundled library + any requested packs."""
    findings = list(run_checks(host))

    # Offline still has a full library: the bundled packs are pre-staged on disk.
    if _BUNDLED_PACKS.is_dir():
        for pack in sorted(_BUNDLED_PACKS.glob("*.json")):
            try:
                findings += list(run_pack(load_pack(str(pack)), host, pack_name=pack.name))
            except Exception as e:
                sys.stderr.write(ink.amber(f"murphy: bundled pack {pack.name} failed: {e}\n"))

    for src in args.pack:
        if _is_remote(src) and not online:
            sys.stderr.write(ink.amber(
                f"murphy: offline mode — refusing to fetch remote pack {src!r}. "
                f"Re-run with --online (add --via tor|dns to choose the channel).\n"))
            continue
        try:
            findings += list(run_pack(load_pack(src, transport=args.via), host, pack_name=src))
        except Exception as e:
            sys.stderr.write(ink.amber(f"murphy: could not load pack {src!r}: {e}\n"))

    findings = _dedupe(findings)

    if args.only:
        needle = args.only.lower()
        findings = [f for f in findings if needle in f.id.lower() or needle in f.title.lower()]
    return findings


def do_fix(host, findings: list[Finding], args, ink: Ink) -> int:
    from .remedy import Fixer

    import os
    remediable = [f for f in findings if f.status == Status.FAIL and f.remedy is not None]
    in_budget = [f for f in remediable if f.remedy.within(args.risk)]
    deferred = [f for f in remediable if not f.remedy.within(args.risk)]

    print(rule(ink, "AUTOPILOT"))
    if not remediable:
        print("  " + ink.green("Nothing to fix — either it's clean or the rest is manual-only."))
        return 0

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0

    # On NixOS the durable fix is declarative: write it into the config with sed
    # rather than poke the running kernel (which a rebuild would undo). That path
    # usually needs no root — the config file is the operator's, not root's.
    nix_target = None
    if host.has("nixos"):
        from . import nixos as nixmod
        nix_target = nixmod.detect_nix_config(getattr(args, "nix_config", None),
                                              getattr(args, "nix_host", None))

    nix_fixes = [f for f in in_budget if nix_target and f.remedy.nix] if nix_target else []
    imperative = [f for f in in_budget if f not in nix_fixes]

    # Offline-user mode: without sudo, apply only imperative remedies that don't
    # need root; hold the rest for su mode. (NixOS declarative fixes are exempt —
    # they write a user-owned config file, no root required.)
    if not is_root and not args.dry_run:
        root_only = [f for f in imperative if getattr(f.remedy, "requires_root", True)]
        imperative = [f for f in imperative if not getattr(f.remedy, "requires_root", True)]
        if root_only:
            print("  " + ink.amber(f"{len(root_only)} imperative fix(es) need root — held for su "
                                    "mode ('offline · su' / 'murphy fix --su'):"))
            for f in root_only:
                print(f"    {ink.dim('·')} {f.title}")
            print()
        if not imperative and not nix_fixes:
            print("  " + ink.dim("Nothing left that a non-root user can safely apply. "
                                 "Pick a 'su' mode to let Murphy do the rest."))
            return 0

    fixer = Fixer(dry_run=args.dry_run)
    done = 0
    for f in imperative:
        r = f.remedy
        print()
        print(f"  {ink.red_b('[FIX]')} {ink.bone(f.title)}  {ink.dim('· risk ' + r.risk)}")
        print(f"        {ink.dim(r.summary)}")

        if args.dry_run:
            for line in fixer.apply(f).messages:
                print(f"        {ink.cyan('· ')}{line}")
            continue

        go = args.yes
        if not go:
            try:
                ans = input(f"        Would you like Murphy to {r.summary}? [y/N] ").strip().lower()
            except EOFError:
                ans = ""
            go = ans in ("y", "yes")
        if not go:
            print(f"        {ink.dim('skipped.')}")
            continue

        try:
            res = fixer.apply(f)
        except OSError as e:
            print(f"        {ink.red_b('✗ refused: ')}couldn't create a restore point "
                  f"({e}). Murphy won't change anything he can't undo.")
            return 2
        for line in res.messages:
            mark = ink.green("✓") if "FAILED" not in line else ink.red_b("✗")
            print(f"        {mark} {line}")
        if res.applied:
            done += 1
        if host.has("nixos") and r.nixos_note:
            print(f"        {ink.amber('note (nixos): ')}"
                  f"imperative change won't survive a rebuild — make it permanent:")
            print(f"          {ink.cyan(r.nixos_note)}")

    # NixOS declarative batch: collect the accepted options, write the module,
    # sed the import in, validate with dry-build, then offer to rebuild.
    if nix_fixes:
        done += _apply_nixos(nix_target, nix_fixes, args, ink, fixer, is_root)

    if deferred:
        print()
        print("  " + ink.amber(f"{len(deferred)} fix(es) above your risk budget "
                               f"(--risk {args.risk}) — left untouched:"))
        for f in deferred:
            print(f"    {ink.dim('·')} {f.title}  {ink.dim('(risk ' + f.remedy.risk + ')')}")
        print("  " + ink.dim("Raise the budget to include them, e.g. --risk medium."))

    if not args.dry_run and fixer.rp and fixer.rp.journal:
        print()
        print("  " + ink.green(f"Applied {done} fix(es). ")
              + ink.dim(f"Restore point saved — roll back anytime with: murphy undo"))
    return 0


def _apply_nixos(target, fixes: list[Finding], args, ink: Ink, fixer, is_root: bool) -> int:
    """Write the accepted fixes into a Murphy-owned NixOS module and offer to rebuild.

    Reliability: Murphy owns murphy-hardening.nix outright and writes every option
    as lib.mkDefault (so it can never clash with the operator's own settings); the
    only edit to the hand-written config is one idempotent `import` line, via sed.
    A dry-build gates activation, and a failure rolls the whole thing back."""
    from . import nixos as nixmod

    print()
    print("  " + rule(ink, "NIXOS — MAKE IT STICK"))
    print(f"  {ink.dim('target:')} {target.config_path}  {ink.dim('(+ ' + nixmod.MODULE_NAME + ')')}")
    print("  " + ink.dim(f"Murphy writes {nixmod.MODULE_NAME} (every option mkDefault — your own "
                         "settings always win) and sed-imports it."))

    writable = os.access(target.config_path, os.W_OK)
    if not writable and not is_root and not args.dry_run:
        print("  " + ink.amber(f"{target.config_path} isn't writable by you — re-run in a 'su' mode "
                               "so Murphy can edit it."))
        return 0

    queued: dict[str, str] = {}
    for f in fixes:
        lhs, val = f.remedy.nix
        print()
        print(f"  {ink.red_b('[NIX]')} {ink.bone(f.title)}  {ink.dim('· risk ' + f.remedy.risk)}")
        print(f"        {ink.dim(lhs + ' = ' + val + ';')}")
        if args.dry_run:
            print(f"        {ink.cyan('· ')}would add: {lhs} = lib.mkDefault {val};")
            queued[lhs] = val
            continue
        go = args.yes
        if not go:
            try:
                ans = input("        Would you like Murphy to use sed to make this permanent? "
                            "[y/N] ").strip().lower()
            except EOFError:
                ans = ""
            go = ans in ("y", "yes")
        if not go:
            print(f"        {ink.dim('skipped.')}")
            continue
        queued[lhs] = val

    if not queued:
        return 0
    if args.dry_run:
        print()
        print("  " + ink.cyan(f"dry-run — would write {len(queued)} option(s), sed the import in, "
                              "then `nixos-rebuild dry-build`."))
        return 0

    rp = fixer.rp  # share the restore point so `murphy undo` reverts these too
    try:
        nixmod.write_module(target, queued, rp=rp)
        nixmod.ensure_import(target, rp=rp)
    except Exception as e:
        print("  " + ink.red_b(f"✗ couldn't write the config ({e}) — nothing changed."))
        return 0
    print()
    print("  " + ink.green(f"✓ wrote {nixmod.MODULE_NAME} ({len(queued)} option(s)) and sed'd the import."))

    print("  " + ink.dim("→ validating with `nixos-rebuild dry-build` (can take a moment)…"))
    ok, out = nixmod.dry_build(target)
    if not ok:
        print("  " + ink.red_b("✗ dry-build failed — rolling the change back so your system still builds:"))
        try:
            os.remove(target.module_path)
        except OSError:
            pass
        nixmod.remove_import(target)
        for line in out.strip().splitlines()[-6:]:
            print("      " + ink.dim(line))
        return 0
    print("  " + ink.green("✓ dry-build OK — the config still evaluates cleanly."))

    do_switch = args.yes
    if not do_switch:
        try:
            ans = input("  Run `nixos-rebuild switch` now to make it live? (needs sudo) [y/N] ").strip().lower()
        except EOFError:
            ans = ""
        do_switch = ans in ("y", "yes")
    if do_switch:
        print("  " + ink.dim("→ nixos-rebuild switch…"))
        sok, sout = nixmod.switch(target, use_sudo=not is_root)
        if sok:
            print("  " + ink.green("✓ rebuilt — the hardening is now live and survives every future rebuild."))
        else:
            print("  " + ink.red_b("✗ switch failed (staged config is fine; fix and rebuild yourself):"))
            for line in sout.strip().splitlines()[-6:]:
                print("      " + ink.dim(line))
    else:
        flake = f" --flake {target.flake_dir}#{target.host}" if target.is_flake else ""
        print("  " + ink.dim(f"Left staged & validated. Apply when ready: sudo nixos-rebuild switch{flake}"))
    return len(queued)


# --------------------------------------------------------------------------- #
#  Antivirus — heuristics (from the scan) + ClamAV signature scan
# --------------------------------------------------------------------------- #
def _emit_mal(f: Finding, ink: Ink) -> None:
    print(f"  {_tag(ink, f)} {_sev(ink, f)}  {ink.bone(f.title)}")
    if f.detail:
        print(f"        {ink.dim(f.detail)}")
    if f.status in (Status.FAIL, Status.WARN):
        if f.rationale:
            print(f"        {ink.dim('why: ')}{f.rationale}")
        if f.fix:
            print(f"        {ink.cyan('do: ')}{f.fix}")


def do_av(host, findings: list[Finding], args, ink: Ink, online: bool) -> int:
    from . import clamav

    mal = sorted((f for f in findings if is_malware_finding(f)),
                 key=lambda f: ({Status.FAIL: 0, Status.WARN: 1, Status.INFO: 2,
                                 Status.SKIP: 3, Status.PASS: 4}[f.status], -int(f.severity)))
    bad = [f for f in mal if f.status in (Status.FAIL, Status.WARN)]

    print(rule(ink, "ANTIVIRUS — HOST HEURISTICS"))
    if not mal:
        print("  " + ink.dim("no malware checks registered."))
    for f in mal:
        if args.verbose or f.status != Status.PASS:
            _emit_mal(f, ink)
    if not bad:
        print("  " + ink.green("Built-in heuristics: nothing suspicious."))
    print("")

    print(rule(ink, "ANTIVIRUS — CLAMAV SIGNATURE SCAN"))
    infected: list = []
    if not clamav.available():
        print("  " + ink.amber("ClamAV not installed — running heuristics only."))
        print("  " + ink.dim("Install it for signature scanning (nixos: services.clamav.daemon.enable = true;)."))
    else:
        st = clamav.db_status()
        print("  " + ink.dim("engine: clamscan · ") + (ink.green(st.detail) if st.present
              and (st.age_days or 0) <= 7 else ink.amber(st.detail)))

        if online and clamav.can_update():
            if _ask(ink, "  Update signatures first (freshclam)?"):
                print("  " + ink.dim("→ freshclam…"))
                ok, out = clamav.update(use_sudo=not (hasattr(os, "geteuid") and os.geteuid() == 0))
                print("  " + (ink.green("✓ signatures updated") if ok
                              else ink.amber("✗ freshclam failed (may need the clamav user/root): "
                                             + out.strip().splitlines()[-1] if out.strip() else "✗ freshclam failed")))

        targets = args.target or clamav.DEFAULT_TARGETS
        pretty = ", ".join(targets)
        if _ask(ink, f"  Run a recursive ClamAV scan of [{pretty}]? (can be slow)"):
            print("  " + ink.dim("→ clamscan… (this can take a while)"))
            from .spinner import working
            with working("clamav scan", ink):
                res = clamav.scan(args.target or None)
            infected = res.infected
            if res.rc == 2:
                print("  " + ink.amber("clamscan reported errors (some paths unreadable) — partial results."))
            if infected:
                print("  " + ink.red_b(f"⚠ {len(infected)} infected file(s):"))
                for path, sig in infected[:20]:
                    print(f"    {ink.red_b('✗')} {ink.bone(path)}  {ink.dim(sig)}")
                print("  " + ink.dim("Murphy does not auto-delete. Quarantine/remove after you confirm."))
            else:
                print("  " + ink.green(f"✓ clean — no signatures matched in [{pretty}]."))
        else:
            print("  " + ink.dim("scan skipped."))

    # Rootkit scanners, if the operator has them.
    extra = [t for t in ("rkhunter", "chkrootkit") if have(t)]
    if extra:
        print("")
        print(rule(ink, "ANTIVIRUS — ROOTKIT SCANNERS"))
        for tool in extra:
            if _ask(ink, f"  Run {tool}?"):
                print("  " + ink.dim(f"→ {tool}…"))
                cmd = [tool] if tool == "chkrootkit" else [tool, "--check", "--sk"]
                import subprocess
                subprocess.run(cmd)

    print("")
    print(ink.dim(f"amnesiac run — nothing written to disk · {WATERMARK}"))
    return 1 if (infected or any(f.status == Status.FAIL for f in mal)) else 0


def _ask(ink: Ink, prompt: str) -> bool:
    try:
        return input(prompt + " [y/N] ").strip().lower() in ("y", "yes")
    except EOFError:
        return False


# --------------------------------------------------------------------------- #
#  Online mode: install the hardening tools the host is missing
# --------------------------------------------------------------------------- #
# Package-manager install verbs. nix installs into the *user* profile (no sudo);
# everyone else needs root, so we prefix sudo in su mode.
_PKG_CMD = {
    # mainstream
    "apt": ["apt-get", "install", "-y"], "dnf": ["dnf", "install", "-y"],
    "yum": ["yum", "install", "-y"], "pacman": ["pacman", "-S", "--noconfirm"],
    "apk": ["apk", "add"], "xbps": ["xbps-install", "-y"],
    "zypper": ["zypper", "-n", "install"], "urpmi": ["urpmi", "--auto"],
    # functional / per-user (no sudo)
    "nix": ["nix", "profile", "install"], "guix": ["guix", "install"],
    # source-based
    "portage": ["emerge", "--noreplace"], "paludis": ["cave", "resolve", "-x"],
    "pkgutils": ["prt-get", "install"], "kiss": ["kiss", "install"], "cpt": ["cpt", "install"],
    "sorcery": ["cast"], "lunar": ["lunar", "install"],
    # other binary managers
    "swupd": ["swupd", "bundle-add"], "eopkg": ["eopkg", "-y", "install"],
    "slackpkg": ["slackpkg", "install"], "moss": ["moss", "install", "-y"],
    "poldek": ["poldek", "-i"], "tazpkg": ["tazpkg", "get-install"], "opkg": ["opkg", "install"],
    # BSD
    "pkg": ["pkg", "install", "-y"], "pkgin": ["pkgin", "-y", "install"], "pkgsrc": ["pkg_add"],
}
# Managers that install into a per-user profile — no sudo needed.
_PKG_ROOTLESS = {"nix", "guix"}
# tool -> package name per manager. Bare tool name is the fallback (works on most
# managers: `xbps-install nftables`, `eopkg install nftables`, `guix install tor`…);
# only the managers whose atom differs are spelled out here.
_PKG_NAME = {
    "nft":     {"apt": "nftables", "dnf": "nftables", "yum": "nftables", "pacman": "nftables",
                "apk": "nftables", "xbps": "nftables", "zypper": "nftables", "urpmi": "nftables",
                "nix": "nixpkgs#nftables", "guix": "nftables", "portage": "net-firewall/nftables",
                "eopkg": "nftables", "swupd": "network-basic", "opkg": "nftables", "pkgin": "nftables"},
    "mokutil": {"apt": "mokutil", "dnf": "mokutil", "yum": "mokutil", "pacman": "mokutil",
                "zypper": "mokutil", "urpmi": "mokutil", "nix": "nixpkgs#mokutil",
                "portage": "sys-boot/mokutil", "xbps": "mokutil"},
    "curl":    {"apt": "curl", "dnf": "curl", "yum": "curl", "pacman": "curl", "apk": "curl",
                "xbps": "curl", "zypper": "curl", "urpmi": "curl", "nix": "nixpkgs#curl",
                "guix": "curl", "portage": "net-misc/curl", "eopkg": "curl", "swupd": "c-basic",
                "opkg": "curl", "pkg": "curl", "pkgin": "curl"},
    "dig":     {"apt": "dnsutils", "dnf": "bind-utils", "yum": "bind-utils", "pacman": "bind",
                "apk": "bind-tools", "xbps": "bind-utils", "zypper": "bind-utils", "urpmi": "bind-utils",
                "nix": "nixpkgs#dnsutils", "guix": "isc-bind", "portage": "net-dns/bind-tools",
                "eopkg": "bind-utils", "pkg": "bind-tools", "pkgin": "bind"},
    "tor":     {"apt": "tor", "dnf": "tor", "yum": "tor", "pacman": "tor", "apk": "tor",
                "xbps": "tor", "zypper": "tor", "urpmi": "tor", "nix": "nixpkgs#tor", "guix": "tor",
                "portage": "net-vpn/tor", "eopkg": "tor", "opkg": "tor", "pkg": "tor", "pkgin": "tor"},
}


def _recommend_tools(host, args, findings: list[Finding]) -> list[tuple[str, str]]:
    """Which hardening tools is this host missing that would strengthen the sweep?

    Returns (tool, why) pairs. Conservative — only names a tool when it's both
    genuinely useful here and absent."""
    want: list[tuple[str, str]] = []
    fw_present = have("nft") or have("ufw") or have("firewall-cmd") or have("nftables")
    fw_failed = any(f.id == "net.firewall" and f.status == Status.FAIL for f in findings)
    if not fw_present and fw_failed:
        want.append(("nft", "so Murphy can raise a default-deny host firewall"))
    if os.path.exists("/sys/firmware/efi") and not have("mokutil"):
        want.append(("mokutil", "to read Secure Boot state instead of skipping it"))
    if args.via == "tor" and not have("curl"):
        want.append(("curl", "required for the Tor transport"))
    if args.via == "dns" and not have("dig"):
        want.append(("dig", "required for the DNS transport"))
    return want


def _install_tools(host, tools: list[tuple[str, str]], use_sudo: bool, ink: Ink) -> None:
    print()
    print("  " + ink.bone("Online — closing tool gaps:"))
    pkg = host.pkg
    if pkg not in _PKG_CMD:
        print("  " + ink.amber(f"unknown package manager ({pkg!r}); install these yourself: "
                               + ", ".join(t for t, _ in tools)))
        return
    # NixOS is declarative — imperatively installing daemons doesn't wire them in.
    if host.has("nixos"):
        print("  " + ink.amber("NixOS is declarative — don't install these imperatively. "
                               "Add to configuration.nix and rebuild:"))
        for tool, why in tools:
            hint = {"nft": "networking.nftables.enable = true;  # or networking.firewall.enable = true;",
                    "mokutil": "environment.systemPackages = [ pkgs.mokutil ];",
                    "curl": "environment.systemPackages = [ pkgs.curl ];",
                    "dig": "environment.systemPackages = [ pkgs.dnsutils ];",
                    "tor": "services.tor.enable = true;"}.get(tool, f"# add {tool}")
            print(f"    {ink.dim('·')} {tool} — {ink.dim(why)}")
            print(f"        {ink.cyan(hint)}")
        return
    # Guix System is likewise declarative for services; installs still work per-user.
    if host.pkg == "guix":
        print("  " + ink.dim("note (Guix): `guix install` goes to your profile; for system daemons "
                             "prefer services in your operating-system config + `guix system reconfigure`."))
    if host.has("source-based"):
        print("  " + ink.dim(f"note ({pkg}): source-based — the first build of a package can take a while."))
    for tool, why in tools:
        name = _PKG_NAME.get(tool, {}).get(pkg, tool)
        cmd = _PKG_CMD[pkg] + [name]
        if pkg not in _PKG_ROOTLESS and use_sudo:
            cmd = ["sudo"] + cmd
        print(f"    {ink.dim('·')} {tool} ({name}) — {ink.dim(why)}")
        print(f"      {ink.dim('→ ' + ' '.join(cmd))}")
        import subprocess
        rc = subprocess.run(cmd).returncode
        print("      " + (ink.green("✓ installed") if rc == 0
                          else ink.amber(f"✗ install exited {rc} — do it manually if needed")))


def _interactive_harden(host, findings: list[Finding], args, ink: Ink) -> None:
    """After a scan, offer the four operating modes (plus a full AV run)."""
    remediable = [f for f in findings if f.status == Status.FAIL and f.remedy is not None]
    missing = _recommend_tools(host, args, findings)
    mal_flagged = any(is_malware_finding(f) and f.status in (Status.FAIL, Status.WARN)
                      for f in findings)
    if not remediable and not missing and not mal_flagged:
        return
    print()
    print(rule(ink, "HARDEN NOW?"))
    print("  " + ink.bone("Would you like Murphy to harden your system for you?"))
    print("  " + ink.dim("(· su = may touch the whole system · no-su = only files your user owns)"))
    print(f"    {ink.green('1')}  offline       {ink.dim('— no network, no sudo: apply only the fixes in your')}")
    print(f"    {'':13} {ink.dim('  own space; root-level ones are reported, not applied')}")
    print(f"    {ink.green('2')}  offline · su  {ink.dim('— no network, but sudo to APPLY the root fixes too')}")
    print(f"    {'':13} {ink.dim('  (firewall, sysctl, sshd, system file modes) — undoable')}")
    print(f"    {ink.green('3')}  online        {ink.dim('— no sudo: pull extra vetted packs + offer to install')}")
    print(f"    {'':13} {ink.dim('  the tools you are missing; nothing forced')}")
    print(f"    {ink.green('4')}  online · su   {ink.dim('— the full treatment: online + sudo')}")
    print(f"    {ink.green('5')}  antivirus     {ink.dim('— full malware sweep: heuristics + ClamAV scan')}")
    print(f"    {ink.dim('0')}  no thanks     {ink.dim('— leave everything exactly as it is')}")
    try:
        choice = input("  " + ink.dim("choose [0-5]: ")).strip()
    except EOFError:
        return
    if choice not in {"1", "2", "3", "4", "5"}:
        print("  " + ink.dim("Left as-is — Murphy didn't touch a thing."))
        return
    _run_harden_choice(choice, host, findings, args, ink, missing)


def _run_harden_choice(choice: str, host, findings: list[Finding], args, ink: Ink,
                       missing: list[tuple[str, str]] | None = None) -> None:
    """Act on a chosen mode (1–5). Shared by the text menu and the --tui wizard so
    both drive the exact same fix pipeline — the wizard picks nothing itself."""
    if choice not in {"1", "2", "3", "4", "5"}:
        print("  " + ink.dim("Left as-is — Murphy didn't touch a thing."))
        return
    if missing is None:
        missing = _recommend_tools(host, args, findings)

    online = choice in {"3", "4"}
    su = choice in {"2", "4"}

    if choice == "5":
        print()
        do_av(host, findings, args, ink, online=_resolve_mode(args)[0])
        return

    if online and missing:
        _install_tools(host, missing, use_sudo=su, ink=ink)

    new_argv = ["fix", "--risk", args.risk, "--no-prompt"]
    if su:
        new_argv.append("--su")
    if online:
        new_argv += ["--online", "--via", args.via]
    label = {"1": "offline", "2": "offline · su", "3": "online", "4": "online · su"}[choice]
    print()
    print("  " + ink.dim(f"→ {label}:  murphy " + " ".join(new_argv)))
    print()
    main(new_argv)  # su modes re-exec under sudo and never return here


def _wizard_harden(host, findings: list[Finding], args, ink: Ink) -> bool:
    """--tui: drive the review-and-choose flow in the full-screen wizard.

    Returns True if the wizard ran (whatever the operator chose), False if the
    terminal couldn't host it so the caller should fall back to the text menu."""
    try:
        from .wizard import run_setup, WizardUnavailable
    except Exception:
        return False
    try:
        choice = run_setup(host, findings)
    except WizardUnavailable as e:
        sys.stderr.write(ink.dim(f"murphy: wizard unavailable ({e}); using the text menu.\n"))
        return False
    if choice is None:
        print(ink.dim("Left as-is — Murphy didn't touch a thing."))
    else:
        _run_harden_choice(choice, host, findings, args, ink)
    return True


def _wizard(ink: Ink) -> int:
    """Bare, interactive run: ask what the operator wants before doing anything.
    Read-only until they pick a fix — a scan stays amnesiac. Each choice just
    re-enters `main` with the right argv, so every path behaves identically to
    running the command directly (`--no-banner` because the wizard already drew it)."""
    print(render_banner(ink))
    print()
    print(rule(ink, "WHERE TO START?"))
    print(f"   {ink.green('1')}  {ink.bone('Scan')}       {ink.dim('read-only audit, graded report, then offer to harden')}")
    print(f"   {ink.green('2')}  {ink.bone('Review')}     {ink.dim('the same scan in a full-screen wizard (--tui)')}")
    print(f"   {ink.green('3')}  {ink.bone('Antivirus')}  {ink.dim('malware heuristics + a ClamAV signature sweep')}")
    print(f"   {ink.green('4')}  {ink.bone('Undo')}       {ink.dim('roll back the most recent fix')}")
    print(f"   {ink.dim('0')}  {ink.dim('Leave')}")
    print("  " + ink.dim("nothing is written until you choose to fix — a scan leaves no trace."))
    try:
        choice = input("  " + ink.cyan("choose [0-4]: ")).strip().lower()
    except EOFError:
        print()
        return 0
    route = {"1": ["scan"], "2": ["scan", "--tui"], "3": ["av"], "4": ["undo"]}.get(choice)
    if route is None:
        print("  " + ink.dim("Left as-is — Murphy didn't touch a thing."))
        return 0
    print()
    return main(route + (["--no-banner"] if choice != "4" else []))


def main(argv: list[str] | None = None) -> int:
    import os
    # Bare, interactive invocation → the wizard. Any explicit argv (`murphy scan`,
    # `murphy fix --su`, …) skips it and behaves exactly as before.
    if argv is None and not sys.argv[1:] and sys.stdin.isatty() and sys.stdout.isatty():
        return _wizard(make_ink(None))
    args = build_parser().parse_args(argv)
    force_color = True if args.color else False if args.no_color else None
    ink = make_ink(force_color)

    if args.command == "version":
        print(f"Murphy Lawden v{__version__} — {WATERMARK}")
        return 0

    if args.command == "undo":
        from .remedy import undo_latest
        ok, msg = undo_latest()
        print((ink.green if ok else ink.amber)("murphy: " + msg))
        return 0 if ok else 1

    if args.command == "panic":
        from .panic import run_panic
        return run_panic(ink)

    online, su = _resolve_mode(args)

    # su mode: if asked to elevate and we're not root yet, hand off to sudo.
    if su and not (hasattr(os, "geteuid") and os.geteuid() == 0):
        _elevate(argv if argv is not None else sys.argv[1:], ink)

    mode_label = ("online/" + args.via if online else "offline") + " · " + ("su" if su else "user")

    host = detect_host()
    from .spinner import working
    with working("scanning host", ink, enabled=not args.json):
        findings = assemble_findings(host, args, online, ink)

    if args.command == "fix":
        if not args.no_banner and not args.json:
            print(render_banner(ink) + "\n")
        return do_fix(host, findings, args, ink)

    if args.command == "av":
        if not args.no_banner and not args.json:
            print(render_banner(ink) + "\n")
        return do_av(host, findings, args, ink, online)

    report = to_json(host, findings) if args.json \
        else render_report(host, findings, ink, args.verbose, banner=not args.no_banner,
                           mode_label=mode_label)
    print(report)

    if args.save:
        sys.stderr.write(ink.amber(
            f"murphy: --save breaks amnesia — writing a trace to {args.save}\n"))
        with open(args.save, "w", encoding="utf-8") as f:
            f.write((to_json(host, findings) if args.json else report) + "\n")

    # After a scan on an interactive terminal, offer to actually harden. With --tui
    # this happens in the full-screen wizard; if that can't run we fall through to
    # the plain text menu so the offer is never silently lost.
    if (args.command == "scan" and not args.json and not args.no_prompt
            and sys.stdin.isatty() and sys.stdout.isatty()):
        if args.tui and _wizard_harden(host, findings, args, ink):
            pass
        else:
            _interactive_harden(host, findings, args, ink)

    # Exit non-zero if there are real failures — useful in CI / cron blue-team gates.
    return 1 if any(f.status == Status.FAIL for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
