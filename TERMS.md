# Terms of Service — Murphy Lawden

_Last updated: 2026-08-28_

Murphy Lawden ("the Software") is free, open-source software provided under the
MIT License. By using it you agree to the following.

## 1. As-is, no warranty

The Software is provided **"as is", without warranty of any kind**, express or
implied. The authors are **not liable** for any damage, data loss, downtime, or
bricked hardware arising from its use. You run it at your own risk.

## 2. Authorized use only

Use the Software **only on systems you own or are explicitly authorized to
administer.** You are responsible for complying with all applicable laws and
policies. The sibling tool **Lone Ronin** additionally refuses any target not in
your scope file — do not attempt to defeat that.

## 3. The `fix` autopilot

`fix` changes system configuration. Although every change is backed up and
reversible with `murphy undo`, **you are responsible for reviewing the plan**
(use `--dry-run`) and for the outcome on your system. Apply within a risk budget
you understand.

## 4. The `duress` capability — read this

`duress` can **permanently destroy data** and, in its `hellbreach` tier, can
**relock the bootloader**. Specifically, you acknowledge:

- Duress wipes perform **cryptographic erasure** — the data is **unrecoverable.
  There is no undo.**
- It is **disarmed and dry-run by default**; it fires only with `--execute`
  **and** a consent phrase you type by hand on a live terminal.
- **Bootloader relock (`--relock`) can permanently hard-brick a rooted or
  modified device.** It is off by default, requires its own separate consent
  phrase, and provides **no additional data security** over cryptographic
  erasure. The authors strongly recommend leaving it off.
- The **dead-man switch** can fire a tier automatically if you do not check in.
  You are responsible for choosing its window and tier; the safe default fire
  tier is the reversible lockdown, not a wipe.

By using `duress` you accept **sole responsibility** for the destruction of your
own data or hardware.

## 5. No collection

The Software collects nothing and transmits nothing about you. See the
[Privacy Policy](PRIVACY.md) for exactly what it writes and which ports it opens.

## 6. Author & contact

Maintained by **[@paladiga484](https://github.com/paladiga484)** (GitHub) ·
**[@trafalger.tar.gz](https://www.tiktok.com/@trafalger.tar.gz)** (TikTok).

MIT License — see [LICENSE](LICENSE).
