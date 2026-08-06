"""Linux / GNU / systemd / NixOS hardening checks.

Every check is read-only and failure-tolerant: a missing tool or a file it
can't read yields a SKIP (with a note on how to get a real answer, e.g. run as
root), never a crash and never a false PASS. Remediation is concrete, and where
the host is NixOS the fix is given as declarative ``configuration.nix`` options.
"""
from __future__ import annotations

import glob
import os
import re
from pathlib import Path
from typing import Iterable

from .core import Finding, Host, Severity, Status, check, have, read, run, sysctl
from .remedy import chmod_remedy, sshd_remedy, sysctl_remedy


def _f(id, title, status, sev=Severity.INFO, **kw) -> Finding:
    return Finding(id=id, title=title, status=status, severity=sev, **kw)


# --------------------------------------------------------------------------- #
#  SSH server
# --------------------------------------------------------------------------- #
@check("linux")
def ssh_server(host: Host) -> Iterable[Finding]:
    cfg = read("/etc/ssh/sshd_config")
    if cfg is None:
        if not (have("sshd") or os.path.exists("/etc/ssh")):
            return
        yield _f("ssh.config", "SSH server configuration", Status.SKIP,
                 detail="/etc/ssh/sshd_config not readable (run as root).")
        return

    # Effective value = last matching directive wins.
    def directive(name, default):
        vals = re.findall(rf"^\s*{name}\s+(\S+)", cfg, re.I | re.M)
        return vals[-1].lower() if vals else default

    nix = {"nixos": "services.openssh.settings.PermitRootLogin = \"no\";\n"
                     "services.openssh.settings.PasswordAuthentication = false;"}

    root_login = directive("PermitRootLogin", "prohibit-password")
    if root_login in ("yes",):
        yield _f("ssh.rootlogin", "SSH permits direct root login", Status.FAIL, Severity.HIGH,
                 detail=f"PermitRootLogin {root_login}",
                 rationale="Direct root over SSH hands an attacker the whole box on one "
                           "cracked/leaked credential and erases the audit trail of who acted.",
                 fix="Set 'PermitRootLogin no' (or 'prohibit-password') in sshd_config and reload sshd.",
                 fix_notes=nix, refs=["CIS Linux 5.2", "cisecurity.org"],
                 remedy=sshd_remedy("PermitRootLogin", "no"))
    else:
        yield _f("ssh.rootlogin", "SSH root login restricted", Status.PASS, Severity.HIGH,
                 detail=f"PermitRootLogin {root_login}")

    pw = directive("PasswordAuthentication", "yes")
    if pw == "yes":
        yield _f("ssh.password", "SSH allows password authentication", Status.WARN, Severity.MEDIUM,
                 detail="PasswordAuthentication yes",
                 rationale="Passwords are brute-forceable and phishable; keys are not.",
                 fix="Move to key-based auth, then set 'PasswordAuthentication no'.",
                 fix_notes=nix, refs=["CIS Linux 5.2"])

    if directive("PermitEmptyPasswords", "no") == "yes":
        yield _f("ssh.emptypw", "SSH permits empty passwords", Status.FAIL, Severity.CRITICAL,
                 detail="PermitEmptyPasswords yes",
                 rationale="An account with no password becomes a remote, unauthenticated door.",
                 fix="Set 'PermitEmptyPasswords no' in sshd_config.",
                 remedy=sshd_remedy("PermitEmptyPasswords", "no", risk="low"))


# --------------------------------------------------------------------------- #
#  Host firewall
# --------------------------------------------------------------------------- #
@check("linux")
def firewall(host: Host) -> Iterable[Finding]:
    active, how = False, ""
    rc, out = run(["nft", "list", "ruleset"])
    if rc == 0 and re.search(r"\b(chain|table)\b", out):
        active, how = True, "nftables"
    if not active:
        rc, out = run(["iptables", "-S"])
        if rc == 0 and out.count("\n") > 3:
            active, how = True, "iptables"
    if not active and have("ufw"):
        rc, out = run(["ufw", "status"])
        if "Status: active" in out:
            active, how = True, "ufw"
    if not active and have("firewall-cmd"):
        rc, out = run(["firewall-cmd", "--state"])
        if out.strip() == "running":
            active, how = True, "firewalld"

    if active:
        yield _f("net.firewall", f"Host firewall active ({how})", Status.PASS, Severity.HIGH,
                 detail=how)
    else:
        yield _f("net.firewall", "No active host firewall detected", Status.FAIL, Severity.HIGH,
                 rationale="Without a default-deny firewall, every listening service is exposed to "
                           "whatever network the host is on — the classic 'I didn't know that port "
                           "was open' incident.",
                 fix="Enable a default-deny firewall (nftables/ufw/firewalld) allowing only needed ports.",
                 fix_notes={"nixos": "networking.firewall.enable = true;\n"
                                     "networking.firewall.allowedTCPPorts = [ 22 ];"},
                 refs=["CIS Linux 3.5"])


# --------------------------------------------------------------------------- #
#  Kernel parameters
# --------------------------------------------------------------------------- #
_SYSCTLS = [
    # key, expected, severity, rationale
    ("kernel.randomize_va_space", "2", Severity.HIGH,
     "Full ASLR makes memory-corruption exploits far less reliable."),
    ("kernel.kptr_restrict", {"1", "2"}, Severity.MEDIUM,
     "Leaked kernel pointers hand exploit writers the addresses they need."),
    ("kernel.dmesg_restrict", "1", Severity.LOW,
     "The kernel log leaks addresses and hardware detail useful to attackers."),
    ("kernel.yama.ptrace_scope", {"1", "2", "3"}, Severity.MEDIUM,
     "Unrestricted ptrace lets a compromised process read secrets from its siblings."),
    ("net.ipv4.tcp_syncookies", "1", Severity.LOW,
     "SYN cookies keep the host answering during a SYN flood."),
    ("net.ipv4.conf.all.rp_filter", "1", Severity.LOW,
     "Reverse-path filtering drops spoofed source addresses."),
    ("net.ipv4.conf.all.accept_redirects", "0", Severity.MEDIUM,
     "Accepting ICMP redirects lets an attacker reroute your traffic."),
    ("net.ipv4.conf.all.accept_source_route", "0", Severity.MEDIUM,
     "Source routing lets a packet dictate its own return path — spoofing aid."),
    ("kernel.unprivileged_bpf_disabled", {"1", "2"}, Severity.MEDIUM,
     "Unprivileged eBPF has been a rich source of local privilege-escalation bugs."),
]


@check("linux")
def kernel_sysctls(host: Host) -> Iterable[Finding]:
    for key, want, sev, why in _SYSCTLS:
        cur = sysctl(key)
        if cur is None:
            yield _f(f"sysctl.{key}", f"{key} unavailable", Status.SKIP,
                     detail="not exposed by this kernel")
            continue
        cur0 = cur.split()[0] if cur else cur
        ok = (cur0 in want) if isinstance(want, set) else (cur0 == want)
        pretty = "/".join(sorted(want)) if isinstance(want, set) else want
        if ok:
            yield _f(f"sysctl.{key}", f"{key} = {cur0}", Status.PASS, sev,
                     dedupe_key=f"sysctl:{key}")
        else:
            yield _f(f"sysctl.{key}", f"{key} is {cur0}, want {pretty}", Status.FAIL, sev,
                     detail=f"current={cur0} expected={pretty}", rationale=why,
                     fix=f"sysctl -w {key}={pretty.split('/')[-1]}  "
                         f"(persist in /etc/sysctl.d/60-hardening.conf)",
                     fix_notes={"nixos": f'boot.kernel.sysctl."{key}" = "{pretty.split("/")[-1]}";'},
                     remedy=sysctl_remedy(key, pretty.split("/")[-1]),
                     dedupe_key=f"sysctl:{key}")


# --------------------------------------------------------------------------- #
#  Accounts & authentication
# --------------------------------------------------------------------------- #
@check("linux")
def uid0_accounts(host: Host) -> Iterable[Finding]:
    passwd = read("/etc/passwd")
    if passwd is None:
        return
    roots = [ln.split(":")[0] for ln in passwd.splitlines()
             if len(ln.split(":")) > 3 and ln.split(":")[2] == "0"]
    extra = [u for u in roots if u != "root"]
    if extra:
        yield _f("acct.uid0", "Extra UID-0 (root-equivalent) accounts", Status.FAIL, Severity.CRITICAL,
                 detail="uid 0: " + ", ".join(roots),
                 rationale="Any account with UID 0 IS root. A hidden second root is a classic "
                           "persistence backdoor.",
                 fix=f"Investigate and remove/repair: {', '.join(extra)}. Only 'root' should be UID 0.")
    else:
        yield _f("acct.uid0", "Only 'root' holds UID 0", Status.PASS, Severity.CRITICAL)


@check("linux")
def empty_passwords(host: Host) -> Iterable[Finding]:
    shadow = read("/etc/shadow")
    if shadow is None:
        yield _f("acct.emptypw", "Empty-password check", Status.SKIP,
                 detail="/etc/shadow not readable (run as root).")
        return
    empties = [ln.split(":")[0] for ln in shadow.splitlines()
               if len(ln.split(":")) > 1 and ln.split(":")[1] == ""]
    if empties:
        yield _f("acct.emptypw", "Accounts with no password set", Status.FAIL, Severity.CRITICAL,
                 detail="empty: " + ", ".join(empties),
                 rationale="A blank password is instant login for anyone who reaches the prompt.",
                 fix="Lock or set passwords: passwd -l <user>  (or assign a strong password).")
    else:
        yield _f("acct.emptypw", "No empty-password accounts", Status.PASS, Severity.CRITICAL)


@check("linux")
def sensitive_perms(host: Host) -> Iterable[Finding]:
    targets = [("/etc/shadow", 0o640), ("/etc/gshadow", 0o640),
               ("/etc/passwd", 0o644), ("/etc/group", 0o644)]
    for path, maxmode in targets:
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            continue
        if mode & ~maxmode & 0o777:
            yield _f(f"perm{path}", f"{path} is {oct(mode)[2:]}, too permissive", Status.FAIL,
                     Severity.HIGH, detail=f"mode {oct(mode)} > {oct(maxmode)}",
                     rationale="World/group access to credential files leaks hashes for offline cracking.",
                     fix=f"chmod {oct(maxmode)[2:]} {path}",
                     remedy=chmod_remedy(path, oct(maxmode)[2:]),
                     dedupe_key=f"mode:{path}")
        else:
            yield _f(f"perm{path}", f"{path} permissions ok ({oct(mode)[2:]})", Status.PASS, Severity.HIGH,
                     dedupe_key=f"mode:{path}")


@check("linux")
def sudo_nopasswd(host: Host) -> Iterable[Finding]:
    files = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*")
    text, readable = "", False
    for fp in files:
        c = read(fp)
        if c is not None:
            readable, text = True, text + "\n" + c
    if not readable:
        yield _f("sudo.nopasswd", "sudo NOPASSWD check", Status.SKIP,
                 detail="sudoers not readable (run as root).")
        return
    hits = [ln.strip() for ln in text.splitlines()
            if "NOPASSWD" in ln and not ln.strip().startswith("#")]
    if hits:
        yield _f("sudo.nopasswd", "Passwordless sudo rules present", Status.WARN, Severity.MEDIUM,
                 detail="; ".join(hits[:4]) + (" …" if len(hits) > 4 else ""),
                 rationale="NOPASSWD means a stolen session escalates to root with no second gate.",
                 fix="Remove NOPASSWD where possible, or scope it to a single audited command.")
    else:
        yield _f("sudo.nopasswd", "No passwordless sudo rules", Status.PASS, Severity.MEDIUM)


# --------------------------------------------------------------------------- #
#  Exposure surface
# --------------------------------------------------------------------------- #
@check("linux")
def listening_services(host: Host) -> Iterable[Finding]:
    rc, out = run(["ss", "-tulnpH"])
    if rc != 0:
        rc, out = run(["ss", "-tulnp"])
    if rc != 0:
        yield _f("net.listen", "Listening-services check", Status.SKIP, detail="'ss' unavailable")
        return
    external = []
    for ln in out.splitlines():
        m = re.search(r"\s(\S+):(\d+)\s+\S+\s", " " + ln + " ")
        if not m:
            continue
        addr = m.group(1)
        if addr in ("127.0.0.1", "::1", "[::1]") or addr.startswith("127."):
            continue
        external.append(f"{addr}:{m.group(2)}")
    external = sorted(set(external))
    if external:
        yield _f("net.listen", f"{len(external)} service(s) listening on non-loopback",
                 Status.WARN, Severity.MEDIUM,
                 detail=", ".join(external[:8]) + (" …" if len(external) > 8 else ""),
                 rationale="Every externally-bound port is attack surface. Confirm each one is "
                           "meant to be reachable and is behind the firewall.",
                 fix="Bind internal services to 127.0.0.1, or firewall the port. Verify with: ss -tulnp")
    else:
        yield _f("net.listen", "No services listening on external interfaces", Status.PASS,
                 Severity.MEDIUM)


# --------------------------------------------------------------------------- #
#  Disk & boot integrity
# --------------------------------------------------------------------------- #
@check("linux")
def disk_encryption(host: Host) -> Iterable[Finding]:
    rc, out = run(["lsblk", "-o", "TYPE,MOUNTPOINT", "-nr"])
    if rc != 0:
        yield _f("disk.luks", "Disk-encryption check", Status.SKIP, detail="'lsblk' unavailable")
        return
    has_crypt = "crypt" in out
    if has_crypt:
        yield _f("disk.luks", "Encrypted volume present (LUKS/dm-crypt)", Status.PASS, Severity.MEDIUM)
    else:
        yield _f("disk.luks", "No encrypted volume detected", Status.WARN, Severity.MEDIUM,
                 rationale="Without full-disk encryption, physical access = data access "
                           "(the stolen-laptop / seized-server scenario).",
                 fix="Use LUKS full-disk encryption. (Retrofitting requires reinstall/migration.)")


@check("linux")
def secure_boot(host: Host) -> Iterable[Finding]:
    if not os.path.exists("/sys/firmware/efi"):
        yield _f("boot.secureboot", "Secure Boot check", Status.SKIP, detail="legacy BIOS boot (no EFI)")
        return
    state = None
    if have("mokutil"):
        rc, out = run(["mokutil", "--sb-state"])
        if rc == 0:
            state = "enabled" if "enabled" in out.lower() else "disabled"
    if state is None:
        var = glob.glob("/sys/firmware/efi/efivars/SecureBoot-*")
        if var:
            data = Path(var[0]).read_bytes() if os.access(var[0], os.R_OK) else b""
            state = "enabled" if data[-1:] == b"\x01" else "disabled" if data else None
    if state == "enabled":
        yield _f("boot.secureboot", "Secure Boot enabled", Status.PASS, Severity.LOW)
    elif state == "disabled":
        yield _f("boot.secureboot", "Secure Boot is disabled", Status.WARN, Severity.LOW,
                 rationale="Secure Boot blocks unsigned bootloaders/kernels — a bootkit defence.",
                 fix="Enable Secure Boot in firmware (may require signing your kernel/shim).")
    else:
        yield _f("boot.secureboot", "Secure Boot state undetermined", Status.SKIP)


# --------------------------------------------------------------------------- #
#  systemd exposure ("the slop tax")
# --------------------------------------------------------------------------- #
@check("linux")
def systemd_exposure(host: Host) -> Iterable[Finding]:
    if not host.has("systemd") or not have("systemd-analyze"):
        return
    rc, out = run(["systemd-analyze", "security", "--no-pager"], timeout=30)
    if rc != 0 or not out.strip():
        yield _f("systemd.exposure", "systemd unit exposure", Status.SKIP,
                 detail="systemd-analyze returned nothing")
        return
    exposed = []
    for ln in out.splitlines():
        m = re.search(r"(\S+\.service)\s+([\d.]+)\s+(.*?)\s{2,}", ln)
        if m and re.search(r"EXPOSED|UNSAFE", ln, re.I):
            exposed.append((m.group(1), m.group(2)))
    if exposed:
        exposed.sort(key=lambda x: float(x[1]), reverse=True)
        names = ", ".join(f"{n} ({s})" for n, s in exposed[:5])
        yield _f("systemd.exposure", f"{len(exposed)} systemd unit(s) rated EXPOSED/UNSAFE",
                 Status.WARN, Severity.MEDIUM,
                 detail=names + (" …" if len(exposed) > 5 else ""),
                 rationale="A service with a high exposure score runs with far more privilege and "
                           "kernel surface than it needs; if it's popped, so is the box.",
                 fix="Sandbox units via drop-ins: NoNewPrivileges, ProtectSystem=strict, "
                     "PrivateTmp, CapabilityBoundingSet=. Re-check with: systemd-analyze security <unit>",
                 fix_notes={"nixos": "systemd.services.<name>.serviceConfig = { "
                                     "NoNewPrivileges = true; ProtectSystem = \"strict\"; PrivateTmp = true; };"})
    else:
        yield _f("systemd.exposure", "No systemd units flagged EXPOSED/UNSAFE", Status.PASS, Severity.LOW)


# --------------------------------------------------------------------------- #
#  NixOS advisory
# --------------------------------------------------------------------------- #
@check("linux")
def nixos_notes(host: Host) -> Iterable[Finding]:
    if not host.has("nixos"):
        return
    yield _f("nixos.hardened", "NixOS hardening profile", Status.INFO,
             detail="Config is declarative — remediation below is configuration.nix-ready.",
             rationale="On NixOS, harden once in config and it's reproducible on every rebuild.",
             fix="Consider: imports = [ <nixpkgs/nixos/modules/profiles/hardened.nix> ]; "
                 "plus networking.firewall.enable, and per-service serviceConfig sandboxing.",
             refs=["nixos.org/manual", "wiki.nixos.org/wiki/Hardening"])
