# Murphy: areas, plain verbs, short/long flags, explicit asks

Status: approved in conversation 2026-10-07. Piece 1 of 6 (see "Later pieces").

## Why

Murphy is hardening for every situation: compartmentalization, wifi, ssh, debloating, and the
rest. Today it is 19 commands sharing ~50 global flags in one argparse parser, so `--help`
cannot say what any one command does or needs, and the commands read backwards from how a person
says them. This piece gives Murphy one shape that every later piece (tests/CI, Windows, daemon +
dashboard, eBPF, packaging) builds on.

## Goals

1. Easy commands: verb first, plain area names, every verb with a `-x` and a `--word` form.
2. Every action declares what it **does**, **needs**, **changes**, how to **undo** it, which
   **platforms** it runs on, and whether it is **calm** or **dangerous**.
3. Murphy shows that summary and asks for exactly what it needs before running anything. It
   never takes root, network or a device it did not ask for.
4. Nothing that works today breaks.

Non-goals for this piece: new hardening content, Windows work, daemon, eBPF, packaging.

## Command line

The positional word, the short flag and the long flag are the same command:

    murphy fix ssh  =  murphy -f ssh  =  murphy --fix ssh

### Actions

| short | long        | argument      | meaning                                         |
|-------|-------------|---------------|-------------------------------------------------|
| `-c`  | `--check`   | [area ...]    | look only, change nothing                       |
| `-f`  | `--fix`     | [area ...]    | harden; asks first                              |
| `-u`  | `--undo`    | [area ...]    | put it back                                     |
| `-e`  | `--explain` | area          | print the manifest: does / needs / changes / undo |
| `-x`  | `--cage`    | file          | run something in the sandbox (today's `ds run`) |
| `-g`  | `--game`    | [on\|off]     | debloat for gaming (today's `ezopt`)            |
| `-k`  | `--clean`   |               | sweep junk (today's `clean`)                    |
| `-s`  | `--for`     | situation     | run a situation preset                          |
| `-P`  | `--panic`   |               | emergency menu; asks at every step              |
| `-l`  | `--list`    |               | list areas and situations                       |

### Modifiers

| short | long        | meaning                                              |
|-------|-------------|------------------------------------------------------|
| `-y`  | `--yes`     | don't ask — calm actions only; dangerous ones still ask |
| `-n`  | `--dry`     | show what would change, touch nothing                |
| `-v`  | `--verbose` | more detail                                          |
| `-q`  | `--quiet`   | less                                                 |
| `-j`  | `--json`    | machine-readable output                              |
| `-h`  | `--help`    | help; `murphy -h ssh` is help for one area           |
| `-V`  | `--version` |                                                      |

### Rules

- Short flags stack: `murphy -fy ssh`, `murphy -cv wifi`.
- Several areas at once: `murphy -c ssh wifi kernel`.
- No area = every area: `murphy -c` checks the whole box; `murphy -f` fixes within the calm tier.
- Exactly one action per run. Two actions (`-cf`) is an error that names both.
- Bare `murphy` opens the numbered menu (`wizard.py`), which explains each choice as it goes.
- Unknown area: "no area 'shh' — did you mean ssh?" (difflib), exit 2.
- Exit codes: 0 ok, 1 findings at FAIL (check) / an action failed (fix, undo), 2 usage error,
  3 declined at the ask.

## Areas

| area        | aliases                     | covers                                               | today's code |
|-------------|-----------------------------|------------------------------------------------------|--------------|
| `cage`      | isolate, sandbox, torrents  | compartmentalization: app/download/game sandboxes    | `ds/`        |
| `net`       | wifi, firewall, vpn, dns    | wifi, firewall, DNS, VPN kill switch, MAC            | `net.*` checks (incl. `net.firewall`), `ds/net.py`, spoof MAC |
| `ssh`       |                             | sshd + client config, keys                           | `ssh.*` checks |
| `users`     | accounts, sudo, login       | users, sudo, PAM, passwords                          | `acct.*`, `sudo.*` |
| `kernel`    | sysctl, boot                | sysctls, lockdown, modules, cmdline                  | `kernel.*`, sysctl fixes |
| `disk`      | fs, mounts                  | mounts, permissions, SUID, encryption                | `disk.*`, fstab triage |
| `apps`      | debloat, services           | services, autostart, telemetry                       | `ezopt`, `tweak` |
| `privacy`   | identity, spoof             | machine-id, hostname, timezone, fingerprint          | `credspoof.py` |
| `virus`     | av, malware                 | heuristics, ClamAV, IOC packs                        | `mal.*`, `pack.ioc*`, `clamav.py` |
| `firmware`  | uefi, bios                  | Secure Boot state, firmware checks                   | `fw.*` checks, `checks_firmware.py` |
| `phone`     | android, magisk             | Android / Magisk                                     | `android.*`, `magiskmod.py` |
| `emergency` | panic, duress, collapse     | panic, duress, collapse, self-wipe                   | as is |

Existing checks are routed to areas by their finding-id prefix (`ssh.` → ssh, `net.` → net, `fw.` → firmware,
`acct.`/`sudo.` → users, `mal.`/`pack.ioc` → virus, `android.` → phone, ...). A check with no
mapped prefix lands in a `misc` area and a unit test fails, so nothing is silently unrouted.

## Manifests

Every area action carries a manifest, defined next to the code that does the work:

```python
Manifest(
    area="ssh", action="fix",
    does="Turns off password and root login for sshd and drops weak ciphers.",
    needs=Needs(root=True, network=False, devices=[],
                reads=["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/"],
                writes=["/etc/ssh/sshd_config.d/10-murphy-*.conf"]),
    changes=["PasswordAuthentication no", "PermitRootLogin no", "..."],
    undo="murphy -u ssh removes the drop-ins (backed up in the job ledger).",
    platforms={"linux", "bsd", "macos"},
    danger="calm",   # or "dangerous"
)
```

- `does` is one sentence, plain words, no jargon the reader has to look up.
- `needs` is the complete list. The runner enforces it: an action that did not declare `root`
  is never run under sudo; one that did not declare `network` runs with Murphy's existing
  offline guard. Undeclared writes are caught by the test suite (piece 2), not at runtime.
- `changes` for `check` is always the empty list — that is what "look only" means, and a test
  asserts it for every area.
- Area-level `--help` / `--explain` is generated from the manifests; there is no second copy of
  the text to drift.

## The ask

Before any action runs, Murphy prints one block built from the manifests involved:

    murphy will: fix ssh, fix kernel
      does     turns off password/root ssh login; tightens 6 kernel sysctls
      needs    root (sudo, asked once) · no network · no devices
      writes   /etc/ssh/sshd_config.d/10-murphy-*.conf, /etc/sysctl.d/60-murphy.conf
      undo     murphy -u ssh kernel
    go ahead? [y/N]

- **Calm** actions: that one block, one yes. `fix` keeps its existing per-change confirmation
  inside the run unless `-y`.
- **Dangerous** actions (`emergency`, collapse doors, wipe, anything flagged dangerous): the block,
  then a typed confirmation at every step (the existing duress/collapse gating). `-y` does not
  skip these; passing it prints why.
- `-n` prints the block and the planned changes and stops — no ask, no changes.
- `check` asks only if it needs something (root for some checks); otherwise it just runs.
- Declining exits 3 with nothing changed.

## Situations

`murphy -s <situation>` = a named list of area actions plus one combined ask. Data, not code:

```python
SITUATIONS = {
  "daily":       ["check:*", "fix:ssh", "fix:kernel", "fix:net"],
  "gaming":      ["game:on"],
  "torrents":    ["fix:cage", "fix:net"],          # today's `ds lock` + `ds go`
  "travel":      ["fix:net", "fix:privacy"],
  "compromised": ["check:virus", "check:*", "emergency:menu"],
  "fresh":       ["check:*", "fix:*"],
  "throwaway":   ["fix:privacy", "clean"],
}
```

`murphy -l` lists them with their combined `does` line. The exact lists are refined during
implementation; adding one is a dict entry.

## Compatibility

- Old subcommands (`scan`, `fix`, `av`, `ds`, `ezopt`, `clean`, `spoof`, `overview`, `collapse`,
  `duress`, `panic`, `undo`, `watch`, `gui`, `tweak`, `module`, `kill`, `version`, `incinerate`)
  and old flags (`--su`, `--risk`, `--apply`, `--mode`, ...) keep working unchanged.
- When an old form is used, Murphy prints one dim line with the new form
  (`tip: this is now murphy -f ssh`), suppressed by `-q`.
- `murphy ds ...` keeps its full sub-tree (lock/unlock/run/go/jail/...); `-x/--cage` covers the
  common case `ds run --auto`.
- `--json` output for `scan` keeps its current schema.

## Structure

- `murphy_lawden/areas/` — one module per area: its manifests and thin `check/fix/undo/status`
  functions that call the existing code. No hardening logic moves in this piece.
- `murphy_lawden/manifest.py` — `Manifest`, `Needs`, the ask renderer, the runner that enforces
  `needs`.
- `murphy_lawden/argv.py` — the new parser (stacked short flags, verb words, area aliases) and
  the legacy fallback: if the first word is a legacy subcommand or a legacy flag is present,
  hand argv to the current `cli.py` parser untouched.
- `murphy_lawden/situations.py` — the table above.
- `cli.py` keeps today's implementations; the new layer calls into it. Its 1210 lines are not
  restructured beyond what routing needs.

## Testing

Unit tests (stdlib `unittest`, no new deps), run with `python -m unittest`:
- parser: every short/long/word form maps to the same parsed command; stacking; multiple areas;
  two-action error; alias and typo handling; legacy argv goes to the legacy parser.
- manifests: every area has check/fix/undo manifests with non-empty `does` and `undo`; every
  `check` manifest has empty `changes` and no `writes`; `--help` text for every area renders.
- routing: every registered check's id maps to an area (no `misc`).
- ask: calm vs dangerous rendering; `-y` refused for dangerous; `-n` changes nothing.
- end-to-end smoke: `murphy -c -j` on this host produces valid JSON and writes nothing to disk
  (temp HOME, snapshot of the tree before/after).

## Later pieces (own spec each)

2. Tests + CI (GitHub Actions, Linux + Windows runners).
3. Windows for real (check/fix/undo + cage), verified in a VM.
4. Daemon + terminal dashboard.
5. eBPF exec/network monitor feeding live verdicts.
6. Packaging: AUR, signed releases, man pages (generated from manifests).
