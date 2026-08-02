- murphy lawden:
- "The guy you call when everything that could've gone wrong, went wrong. A cross-OS defensive hardening toolkit + antivirus."
## Why Murphy Lawden exists

A lot of tools that call themselves "security toolkits" aren't. They promise hardening and auditing, then quietly ship a RAT, a token grabber, or worse in the installer. You run them to protect yourself and end up compromised. Murphy Lawden is built to be the opposite of that.

- **Read-only by default.** A scan writes *nothing* to disk. It looks, it reports, it leaves.
- **Fixes are separate and consented.** Nothing changes unless you explicitly run `fix`, every change is backed up, and `undo` rolls back the last job in full.
- **Standard library only.** No third-party dependencies to vet. Python 3, stdlib, that's it — anyone can read the whole thing top to bottom.
- **Genuinely cross-platform.** Any Linux distro, the BSDs, independent GNU systems, Windows, and Android — with checks tuned to each, not a Linux tool with token gestures elsewhere.
