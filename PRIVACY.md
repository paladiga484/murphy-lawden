# Privacy Policy — Murphy Lawden

_Last updated: 2026-08-28_

Murphy Lawden is a **local, offline-first** defensive-hardening and antivirus
toolkit. The short version: **it does not collect anything, it does not phone
home, and by default it does not write to disk or touch the network at all.**
This document is specific about the two things a security tool must never be
vague about — **what it writes** and **what it puts on the network / which
ports it opens**.

## 1. No data collection, no telemetry

- There is **no analytics, no telemetry, no crash reporting, no "usage
  statistics," and no account.**
- Murphy has **no server**. Nothing you scan, fix, or report is ever transmitted
  to the author or any third party.
- Scan results exist only in your terminal (or your own browser, for the GUI)
  and are discarded when the process exits.

## 2. What Murphy writes to disk

Murphy is **amnesiac**: a `scan` / `av` run writes **nothing** to disk. The only
operations that ever touch disk are explicit and opt-in:

| Action | What it writes | Reversible? |
|---|---|---|
| `fix` | backs up each changed file to a restore point under `~/.local/state/murphy` (or `/var/lib/murphy` as root), then applies the change | yes — `murphy undo` |
| `watch --state DIR` | a posture-baseline JSON in `DIR` | yes — delete it |
| `watch --install-service` | an optional systemd **user** unit | yes — `--uninstall-service` |
| `--save FILE` | writes the report to `FILE` (and prints a warning that this breaks amnesia) | yes — delete it |
| `module` | a `murphy-hardening.zip` you choose the path for | yes — delete it |
| `duress` | destroys data **only** after `--execute` + a typed consent phrase | **no — that is the point** |

Nothing is written silently. `duress` is the sole destructive capability and is
disarmed and dry-run by default; see the Terms.

## 3. Networking and ports — exactly what opens a socket

By default Murphy is **fully offline** and opens **no ports** and makes **no
network connections.** The complete list of exceptions, each of which you
trigger explicitly:

- **`gui`** starts a local web server bound to **`127.0.0.1` (loopback only),
  default TCP port `8787`** (change with `--port`). It is reachable only from
  your own machine, never the network, and every state-changing request must
  carry a random per-session token embedded in the page. It serves only your own
  scan/fix data. No external requests are made by the page.
- **`--online`** (never the default) fetches community **check-packs** over the
  transport you pick — `--via direct|tor|dns`. This is the only outbound traffic
  Murphy makes, it goes to the pack source you specify, and it sends no
  information about your host beyond a normal HTTP request.
- **ClamAV `freshclam`** may run during `av` **only** if you are `--online` and
  approve it; that contacts ClamAV's own mirrors, not us.
- **`module`** and **`watch`** open no sockets. `duress` opens no sockets (it
  *closes* them — cutting radios is part of the kill-switch).

If you never pass `--online` and never run `gui`, Murphy makes zero network
activity and listens on zero ports.

## 4. The rest of the suite

Murphy ships alongside two sibling tools with the same offline-first ethos:
**Lupin** (OSINT analyser — offline unless you pass `--online`, no telemetry) and
**Lone Ronin** (authorized-only tester — contacts only targets you place in a
scope file, and logs every run to a local audit log). Neither collects or
transmits anything about you.

## 5. Your data is yours

Everything Murphy touches stays on your device under your control. There is no
cloud, no sync, and no operator with access to it. Removing the tool and its
`~/.local/state/murphy` directory removes every trace it ever wrote.

## 6. Contact

- GitHub: **[@paladiga484](https://github.com/paladiga484)**
- TikTok: **[@trafalger.tar.gz](https://www.tiktok.com/@trafalger.tar.gz)**
