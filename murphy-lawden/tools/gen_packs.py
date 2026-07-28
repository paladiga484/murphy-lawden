#!/usr/bin/env python3
"""Generate Murphy Lawden's large vetted check-pack library.

Every entry here is a *real*, well-established hardening item (CIS Linux
Benchmark, the kernel-hardening guides, Lynis) — not invented noise. The engine
SKIPs when a sysctl/path is absent, so a big library never false-fails a host
that simply doesn't have a given knob.

This deliberately does NOT duplicate the built-in checks or the four curated
packs (baseline / kernel-extra / network-extra / filesystem-extra). Run it from
the repo root:  python3 tools/gen_packs.py   → writes packs/*.generated.json
"""
from __future__ import annotations

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PACKS = os.path.join(os.path.dirname(HERE), "packs")

# Anything already covered by the built-in checks or the curated packs — never
# emit these again (keeps findings de-duplicated).
_ALREADY = {
    # built-in sysctls (checks_linux._SYSCTLS)
    "kernel.randomize_va_space", "kernel.kptr_restrict", "kernel.dmesg_restrict",
    "kernel.yama.ptrace_scope", "net.ipv4.tcp_syncookies",
    "net.ipv4.conf.all.rp_filter", "net.ipv4.conf.all.accept_redirects",
    "net.ipv4.conf.all.accept_source_route", "kernel.unprivileged_bpf_disabled",
    # baseline + kernel-extra + network-extra
    "kernel.perf_event_paranoid", "fs.suid_dumpable", "fs.protected_hardlinks",
    "fs.protected_symlinks", "fs.protected_fifos", "fs.protected_regular",
    "kernel.kexec_load_disabled", "kernel.sysrq", "kernel.unprivileged_userns_clone",
    "kernel.ftrace_enabled", "net.ipv4.conf.all.send_redirects",
    "net.ipv4.conf.default.send_redirects", "net.ipv4.conf.default.accept_redirects",
    "net.ipv4.conf.default.accept_source_route", "net.ipv4.conf.all.log_martians",
    "net.ipv4.icmp_echo_ignore_broadcasts", "net.ipv4.icmp_ignore_bogus_error_responses",
    "net.ipv4.conf.default.rp_filter", "net.ipv6.conf.all.accept_ra",
    "net.ipv6.conf.all.accept_redirects",
}
_ALREADY_PATHS = {
    "/tmp", "/etc/crontab", "/usr/bin/telnet", "/usr/bin/rsh", "/etc/shadow-",
    "/etc/gshadow-", "/etc/passwd-", "/etc/group-", "/etc/ssh/sshd_config",
    "/boot/grub/grub.cfg", "/etc/cron.d", "/usr/bin/rlogin", "/usr/bin/rcp",
    "/usr/sbin/ypbind", "/usr/bin/tftp",
    # /etc/{shadow,gshadow,passwd,group} handled by built-in sensitive_perms
    "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group",
}


def sysctl(key, expect, sev, why, fix=None, **opts):
    assert key not in _ALREADY, f"duplicate sysctl {key}"
    want = expect[0] if isinstance(expect, list) else expect
    r = {"id": f"pack.{key}", "title": f"{key} (want {want})", "kind": "sysctl",
         "key": key, "expect": expect, "severity": sev,
         "rationale": why, "fix": fix or f"sysctl -w {key}={expect if not isinstance(expect, list) else expect[0]}"}
    r.update(opts)
    return r


def perm(path, mode, sev, why, **opts):
    assert path not in _ALREADY_PATHS, f"duplicate path {path}"
    r = {"id": f"pack.perm{path}", "title": f"{path} not overly permissive",
         "kind": "file_mode", "path": path, "max_mode": mode, "severity": sev,
         "rationale": why, "fix": f"chmod {mode} {path}", "refs": ["CIS Linux Benchmark 6.1"]}
    r.update(opts)
    return r


def absent(path, sev, why, **opts):
    assert path not in _ALREADY_PATHS, f"duplicate path {path}"
    name = os.path.basename(path)
    r = {"id": f"pack.absent{path}", "title": f"{name} not installed",
         "kind": "path_exists", "path": path, "should_exist": False, "severity": sev,
         "rationale": why, "fix": f"Remove {name} (legacy/insecure).",
         "refs": ["CIS Linux Benchmark 2.3"]}
    r.update(opts)
    return r


def ioc(path, sev, why, note="", **opts):
    """Known-bad file indicator. Present == FAIL. Framed as an indicator to
    investigate, not a verdict — many have a legitimate twin."""
    name = os.path.basename(path)
    fixtext = f"If you didn't put {name} there deliberately, treat the host as possibly "
    fixtext += "compromised: isolate it, capture the file for analysis, and hunt for persistence."
    r = {"id": f"pack.ioc{path}", "title": f"IOC: {name} present ({path})",
         "kind": "path_exists", "path": path, "should_exist": False, "severity": sev,
         "rationale": why + (f"  {note}" if note else ""), "fix": fixtext,
         "refs": ["known-malware IOC", "rkhunter/Lynis"]}
    r.update(opts)
    return r


def ioc_cmd(slug, title, cmd, must_not_match, sev, why, note="",
            skip_if_rc_nonzero=True, **opts):
    """A command-based indicator (lsmod, pm list, find …). FAIL when the bad
    pattern turns up in the command's output. Framed as investigate-not-verdict."""
    fixtext = ("If this indicator is unexpected, treat the host as possibly compromised: "
               "isolate it, capture the artifacts for analysis, and hunt for persistence.")
    r = {"id": f"pack.ioc/{slug}", "title": title, "kind": "cmd", "cmd": cmd,
         "must_not_match": must_not_match, "severity": sev,
         "rationale": why + (f"  {note}" if note else ""), "fix": fixtext,
         "refs": ["known-malware IOC", "rkhunter/Lynis"]}
    if skip_if_rc_nonzero:
        r["skip_if_rc_nonzero"] = True
    r.update(opts)
    return r


def mount(point, option, sev):
    return {"id": f"pack.mount{point}.{option}",
            "title": f"{point} mounted with {option}", "kind": "cmd",
            "cmd": ["findmnt", "-nro", "OPTIONS", point], "must_match": rf"\b{option}\b",
            "skip_if_rc_nonzero": True,  # not a separate mountpoint → N/A, not a failure
            "severity": sev,
            "rationale": f"Mounting {point} with {option} shrinks what an attacker "
                         f"who can write there can do (run code / device nodes / setuid).",
            "fix": f"Add {option} to the {point} mount options in /etc/fstab and remount.",
            "refs": ["CIS Linux Benchmark 1.1"]}


# --------------------------------------------------------------------------- #
#  1) Extended network sysctls (IPv6 parity + secure redirects + TCP)
# --------------------------------------------------------------------------- #
NETWORK = [
    sysctl("net.ipv4.conf.all.secure_redirects", "0", "MEDIUM",
           "Even 'secure' ICMP redirects let a gateway reshape your routing — only accept from none."),
    sysctl("net.ipv4.conf.default.secure_redirects", "0", "MEDIUM",
           "Same as above for interfaces brought up later."),
    sysctl("net.ipv4.conf.default.log_martians", "1", "LOW",
           "Log impossible source addresses on new interfaces too — early spoofing warning."),
    sysctl("net.ipv4.tcp_rfc1337", "1", "LOW",
           "RFC1337 protection drops the TIME-WAIT assassination hazard."),
    sysctl("net.ipv6.conf.default.accept_redirects", "0", "MEDIUM",
           "IPv6 redirect-reroute protection on interfaces brought up later."),
    sysctl("net.ipv6.conf.all.accept_source_route", "0", "MEDIUM",
           "Source-routed IPv6 packets can dictate their own return path — spoofing aid."),
    sysctl("net.ipv6.conf.default.accept_source_route", "0", "MEDIUM",
           "Same, for interfaces brought up later."),
    sysctl("net.ipv6.conf.default.accept_ra", ["0", "1"], "LOW",
           "A rogue router advertisement can hijack your default gateway; disable RA on non-routers.",
           fix="On non-routers set net.ipv6.conf.default.accept_ra=0.", no_autofix=True),
    sysctl("net.ipv4.ip_forward", "0", "LOW",
           "IP forwarding turns a host into a router; leave it off unless it genuinely routes.",
           fix="sysctl -w net.ipv4.ip_forward=0 (skip if this box is a router/VM host/VPN gateway).",
           no_autofix=True),
    sysctl("net.ipv6.conf.all.forwarding", "0", "LOW",
           "IPv6 forwarding equivalent — off unless this host really routes IPv6.",
           no_autofix=True),
    sysctl("net.ipv4.conf.all.arp_ignore", ["1", "2"], "LOW",
           "Restricting ARP replies reduces ARP-cache-poisoning surface on multi-homed hosts.",
           no_autofix=True),
    sysctl("net.ipv4.conf.all.arp_announce", ["1", "2"], "LOW",
           "Conservative ARP announcements avoid leaking addresses across interfaces.",
           no_autofix=True),
]

# --------------------------------------------------------------------------- #
#  2) Extended kernel / memory / BPF sysctls
# --------------------------------------------------------------------------- #
KERNEL = [
    sysctl("net.core.bpf_jit_harden", ["1", "2"], "MEDIUM",
           "Hardening the BPF JIT blunts JIT-spray exploitation of the packet filter."),
    sysctl("dev.tty.ldisc_autoload", "0", "LOW",
           "Auto-loading TTY line disciplines has been a local-privesc path; pin it off."),
    sysctl("kernel.core_uses_pid", "1", "LOW",
           "Tagging core dumps with the PID avoids one process clobbering another's core."),
    sysctl("vm.unprivileged_userfaultfd", "0", "MEDIUM",
           "Unprivileged userfaultfd has repeatedly aided use-after-free exploitation.",
           risk="medium"),
    sysctl("kernel.panic_on_oops", "1", "LOW",
           "Panicking on an oops fails closed instead of running on in a corrupted state.",
           fix="sysctl -w kernel.panic_on_oops=1 (note: turns an oops into a reboot).",
           no_autofix=True),
    sysctl("kernel.modules_disabled", "1", "HIGH",
           "Once your modules are loaded, locking further loading blocks a whole class of rootkits.",
           fix="Set kernel.modules_disabled=1 late in boot (one-way until reboot; breaks hot-plug).",
           no_autofix=True),
    sysctl("kernel.io_uring_disabled", ["1", "2"], "MEDIUM",
           "io_uring is a large, exploit-prone surface; disable it where nothing needs it.",
           fix="sysctl -w kernel.io_uring_disabled=2 (breaks apps that use io_uring).",
           no_autofix=True),
    sysctl("net.ipv4.tcp_sack", ["0", "1"], "INFO",
           "Context only — selective ACK has had DoS CVEs (SACK panic); note the state.",
           no_autofix=True),
]

# --------------------------------------------------------------------------- #
#  3) Legacy / cleartext services & clients that shouldn't be present
# --------------------------------------------------------------------------- #
LEGACY = [
    absent("/usr/sbin/telnetd", "MEDIUM", "A telnet server accepts cleartext logins over the network."),
    absent("/usr/sbin/in.telnetd", "MEDIUM", "inetd-style telnet server — cleartext logins."),
    absent("/usr/sbin/rshd", "MEDIUM", "rsh server: host-based trust + cleartext, a lateral-movement classic."),
    absent("/usr/sbin/in.rshd", "MEDIUM", "inetd rsh server — same risk."),
    absent("/usr/sbin/rlogind", "MEDIUM", "rlogin server: trusts .rhosts, speaks cleartext."),
    absent("/usr/sbin/in.rlogind", "MEDIUM", "inetd rlogin server — same risk."),
    absent("/usr/bin/rexec", "MEDIUM", "rexec sends credentials in the clear."),
    absent("/usr/sbin/rexecd", "MEDIUM", "rexec server — cleartext remote execution."),
    absent("/usr/sbin/in.rexecd", "MEDIUM", "inetd rexec server — same risk."),
    absent("/usr/sbin/ypserv", "MEDIUM", "NIS server: obsolete, unauthenticated directory service."),
    absent("/usr/bin/ypwhich", "LOW", "NIS client tooling — presence hints NIS is in use."),
    absent("/usr/sbin/in.tftpd", "LOW", "TFTP server: no authentication; a common staging/exfil channel."),
    absent("/usr/sbin/tftpd", "LOW", "TFTP server — same risk."),
    absent("/usr/bin/talk", "LOW", "talk client is legacy, cleartext, rarely wanted."),
    absent("/usr/sbin/in.talkd", "LOW", "talk server — legacy, cleartext."),
    absent("/usr/bin/finger", "LOW", "The finger client leaks/queries user info over a legacy protocol."),
    absent("/usr/sbin/in.fingerd", "MEDIUM", "finger server discloses account details to the network."),
    absent("/usr/sbin/vsftpd", "LOW", "An FTP server usually means cleartext credentials; prefer sftp.",
           refs=["CIS Linux Benchmark 2.2"]),
    absent("/usr/sbin/proftpd", "LOW", "FTP server — cleartext credentials; prefer sftp."),
    absent("/usr/sbin/pure-ftpd", "LOW", "FTP server — cleartext credentials; prefer sftp."),
    absent("/usr/bin/ftp", "LOW", "The cleartext ftp client invites cleartext credential use; prefer sftp."),
    absent("/usr/bin/tnftp", "LOW", "tnftp is another cleartext ftp client."),
    absent("/usr/sbin/xinetd", "LOW", "A running (x)inetd super-server multiplies exposed legacy services."),
    absent("/usr/sbin/inetd", "LOW", "Classic inetd super-server — same concern."),
    absent("/usr/bin/nis", "LOW", "NIS tooling present — obsolete directory service."),
]

# --------------------------------------------------------------------------- #
#  4) File & directory permissions (credential, cron, auth, banner files)
# --------------------------------------------------------------------------- #
PERMS = [
    perm("/etc/security/opasswd", "600", "HIGH",
         "opasswd stores old password hashes for reuse checks — same offline-cracking risk as shadow."),
    perm("/etc/login.defs", "644", "LOW",
         "login.defs sets password/UID policy; a writable copy lets a user relax it."),
    perm("/etc/ssh/ssh_config", "644", "LOW",
         "A writable client config can be used to weaken outbound SSH (e.g. disable host-key checks)."),
    perm("/etc/sudoers", "440", "HIGH",
         "A writable sudoers file is a direct, unaudited path to root."),
    perm("/etc/sudoers.d", "750", "HIGH",
         "A writable sudoers.d drop-in directory is the same root path by another door."),
    perm("/etc/cron.hourly", "700", "MEDIUM", "Writable cron dir = scheduled root code execution."),
    perm("/etc/cron.daily", "700", "MEDIUM", "Writable cron dir = scheduled root code execution."),
    perm("/etc/cron.weekly", "700", "MEDIUM", "Writable cron dir = scheduled root code execution."),
    perm("/etc/cron.monthly", "700", "MEDIUM", "Writable cron dir = scheduled root code execution."),
    perm("/etc/cron.allow", "640", "LOW", "cron.allow controls who may schedule jobs; keep it tight."),
    perm("/etc/cron.deny", "640", "LOW", "cron.deny is part of the same access decision."),
    perm("/etc/at.allow", "640", "LOW", "at.allow controls who may schedule 'at' jobs."),
    perm("/etc/at.deny", "640", "LOW", "at.deny is part of the same access decision."),
    perm("/etc/hosts.allow", "644", "LOW", "tcpwrappers policy file — shouldn't be world-writable."),
    perm("/etc/hosts.deny", "644", "LOW", "tcpwrappers deny file — shouldn't be world-writable."),
    perm("/etc/motd", "644", "LOW", "A writable login banner can be abused for social-engineering."),
    perm("/etc/issue", "644", "LOW", "A writable console banner can be abused likewise."),
    perm("/etc/issue.net", "644", "LOW", "A writable network banner can be abused likewise."),
    perm("/boot/grub2/grub.cfg", "600", "MEDIUM",
         "GRUB2 config leaks boot parameters and can hide a boot password; keep it root-only."),
]

# --------------------------------------------------------------------------- #
#  5) Mount options (nodev / nosuid / noexec on sensitive mountpoints)
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
#  6) Known-bad file indicators (conservative, well-documented Linux malware)
# --------------------------------------------------------------------------- #
IOC = [
    ioc("/tmp/kdevtmpfsi", "HIGH",
        "kdevtmpfsi is the payload of the Kinsing cryptomining malware — one of the most common "
        "Linux server infections."),
    ioc("/tmp/kinsing", "HIGH", "The Kinsing malware dropper itself."),
    ioc("/var/tmp/kinsing", "HIGH", "The Kinsing dropper in its other common location."),
    ioc("/dev/shm/kdevtmpfsi", "HIGH", "Kinsing miner staged in shared memory."),
    ioc("/usr/bin/kthrotlds", "HIGH",
        "kthrotlds masquerades as a kernel thread; it's a well-known cryptominer."),
    ioc("/usr/lib/libprocesshider.so", "CRITICAL",
        "libprocesshider is a userland rootkit that hides malicious processes via ld.so.preload.",
        note="Its presence usually accompanies an active compromise."),
    ioc("/usr/local/lib/libprocesshider.so", "CRITICAL",
        "libprocesshider rootkit (alternate path)."),
    ioc("/var/tmp/.diicot", "HIGH", "Artifact of the Diicot (formerly 'Mexals') Linux botnet/miner."),
    ioc("/var/tmp/.update-logs", "MEDIUM", "A hidden staging dir used by several Linux miners/botnets."),
    ioc("/tmp/.diicot", "HIGH", "Diicot botnet artifact in /tmp."),
    ioc("/usr/bin/.sshd", "CRITICAL",
        "A dot-hidden 'sshd' is a classic backdoor named to blend in with the real daemon."),
    ioc("/usr/sbin/.sshd", "CRITICAL", "Hidden 'sshd' backdoor (alternate path)."),
    ioc("/bin/.sshd", "CRITICAL", "Hidden 'sshd' backdoor (alternate path)."),
    ioc("/tmp/.X25-unix/.rsync", "HIGH", "Path used by the outlaw/'rsync' Linux mining botnet."),
    ioc("/tmp/xmrig", "MEDIUM",
        "XMRig is a Monero miner — legitimate if YOU run it, but a top sign of a cryptojacked box.",
        note="Only benign if you mine on purpose."),
    ioc("/usr/local/bin/xmrig", "MEDIUM", "XMRig cryptominer in a system path (see above)."),
    ioc("/opt/xmrig", "MEDIUM", "XMRig cryptominer install (see above)."),
    ioc("/etc/ld.so.preload.bak", "MEDIUM",
        "A backup of ld.so.preload often left behind by preload-based rootkit installers."),
]

# --------------------------------------------------------------------------- #
#  7) RATs, backdoors & rootkits (Linux) — file & kernel-module indicators
# --------------------------------------------------------------------------- #
# Well-documented Linux implants beyond the cryptominer set. Fixed system paths
# and kernel-module names only (home-dir artifacts are handled with find-rules in
# the spyware pack). Present == investigate; each has a public write-up.
RATS = [
    # --- LKM (loadable kernel module) rootkits: hide files/procs/ports ---
    ioc_cmd("lkm/known-rootkit-module", "IOC: known LKM-rootkit module loaded",
            ["lsmod"],
            r"(?im)\b(diamorphine|reptile|adore[-_]?ng|adore|knark|modhide|phalanx|"
            r"sutekh|nuk3gh0st|rooty|enyelkm|kbeast|suterusu|wnps|snd_floppy)\b",
            "CRITICAL",
            "These are the module names of public Linux kernel-mode rootkits (Diamorphine, "
            "Reptile, Adore-ng, KBeast, Suterusu, Cloud Snooper's snd_floppy…). A loaded one "
            "hides its own processes, files and network ports from you.",
            note="Cross-check with a trusted `lsmod` from rescue media — a good rootkit hides "
                 "itself from the running kernel too."),
    ioc("/reptile", "CRITICAL",
        "The Reptile LKM rootkit installs into /reptile (reptile_cmd, reptile_shell). "
        "Its presence means an active kernel-mode compromise."),
    ioc("/etc/rc.modules", "HIGH",
        "Reptile and several LKM rootkits persist by loading their module from /etc/rc.modules.",
        note="Legitimate on a few old setups — confirm what it loads."),

    # --- BPFDoor: passive magic-packet backdoor (Red Menshen) ---
    ioc("/dev/shm/kdmtmpflush", "CRITICAL",
        "kdmtmpflush is a dropper/loader used by the BPFDoor passive backdoor, staged in "
        "shared memory to survive on disk-less."),
    ioc("/var/run/haldrund.pid", "HIGH",
        "haldrund.pid is a lock file BPFDoor writes to ensure a single instance — a strong "
        "indicator of the BPFDoor implant."),

    # --- XorDDoS: DDoS bot + rootkit ---
    ioc("/etc/cron.hourly/gcc.sh", "HIGH",
        "gcc.sh in cron.hourly is XorDDoS's persistence stub — it re-drops the bot every hour."),
    ioc("/lib/libudev.so", "HIGH",
        "XorDDoS ships a fake /lib/libudev.so (the real library is libudev.so.1 under the "
        "arch triplet dir). A bare /lib/libudev.so is a classic XorDDoS marker.",
        note="Confirm it isn't a legitimate dev symlink before acting."),

    # --- RotaJakiro: stealthy Linux backdoor (360 Netlab) ---
    ioc("/lib/systemd/systemd-daemon", "HIGH",
        "RotaJakiro masquerades as a systemd binary; there is no real 'systemd-daemon'. "
        "One of its documented persistence paths."),
    ioc("/usr/lib/mozillae/mozillat", "HIGH",
        "A RotaJakiro payload path that impersonates Mozilla files."),

    # --- Skidmap: kernel-module cryptominer/rootkit ---
    ioc("/usr/bin/kaudited", "HIGH",
        "kaudited is a Skidmap component that installs malicious kernel modules and a fake "
        "'pam' to backdoor authentication."),
    ioc("/usr/bin/pamdicks", "HIGH",
        "pamdicks is a Skidmap payload used for persistence/credential theft."),

    # --- Winnti / RedXOR / PWNLNX family ---
    ioc("/bin/iptabler", "HIGH",
        "iptabler is a RedXOR (Winnti-linked) backdoor component that mimics the iptables name."),

    # --- HiddenWasp: trojan + rootkit ---
    ioc("/sbin/.ifup-local", "HIGH",
        "A dot-hidden network hook script is HiddenWasp-style persistence — legit ifup-local "
        "is never hidden.",
        note="A visible /sbin/ifup-local can be a normal admin hook; the hidden dot-file is not."),
]

# --------------------------------------------------------------------------- #
#  8) Spyware / stalkerware / commercial surveillance
#     (Linux desktop file indicators + Android package indicators)
# --------------------------------------------------------------------------- #
# Mobile spyware (Pegasus & co.) is best triaged forensically — this pack ships
# the cheap, offline indicators; for a real mobile investigation use Amnesty's
# MVT. Android rules use `pm list packages` and SKIP on a normal Linux box.
SPYWARE = [
    # --- Linux desktop spyware / keyloggers ---
    ioc_cmd("evilgnome", "IOC: EvilGnome spyware artifacts in a home dir",
            ["find", "/home", "/root", "-maxdepth", "5", "-name", "gnome-shell-ext.sh"],
            r"gnome-shell-ext\.sh", "CRITICAL",
            "EvilGnome is Linux desktop spyware (screenshots, audio capture, file exfil) that "
            "disguises itself as a GNOME Shell extension and persists via ~/.config/autostart.",
            skip_if_rc_nonzero=False),
    ioc_cmd("evilgnome/autostart", "IOC: EvilGnome autostart entry",
            ["find", "/home", "/root", "-maxdepth", "5", "-name", "gnome-shell-ext.desktop"],
            r"gnome-shell-ext\.desktop", "CRITICAL",
            "The autostart .desktop file EvilGnome drops so its agent relaunches at login.",
            skip_if_rc_nonzero=False),
    ioc("/var/log/logkeys.log", "MEDIUM",
        "logkeys is a userspace keylogger; its default logfile here means keystrokes are being "
        "recorded.",
        note="Dual-use — only benign if you set it up yourself."),
    ioc("/usr/bin/logkeys", "MEDIUM",
        "The logkeys keylogger binary. Legitimate only if you installed it deliberately."),

    # --- Android: Pegasus / Chrysaor & commercial/stalkerware packages ---
    # family="android" so these fire on Android (family=linux + 'android' tag) but
    # don't clutter a normal Linux scan, where `pm` doesn't exist anyway.
    ioc_cmd("android/pegasus-chrysaor", "IOC: Pegasus (Chrysaor) package installed",
            ["pm", "list", "packages"], r"(?im)\bcom\.network\.android\b", "CRITICAL",
            "com.network.android is the documented package name of Chrysaor, the Android build "
            "of NSO Group's Pegasus spyware.",
            note="For a real mobile-spyware investigation use Amnesty International's MVT.",
            family="android"),
    ioc_cmd("android/thetruthspy", "IOC: TheTruthSpy stalkerware package installed",
            ["pm", "list", "packages"], r"(?im)\bcom\.systemservice\b", "HIGH",
            "com.systemservice is the package used by the TheTruthSpy stalkerware family, which "
            "hides as a fake 'System Service' app.", family="android"),
    ioc_cmd("android/cerberus", "IOC: Cerberus (abusable tracker) package installed",
            ["pm", "list", "packages"], r"(?im)\bcom\.lsdroid\.cerberus\b", "MEDIUM",
            "Cerberus is an anti-theft app routinely abused as covert stalkerware (remote mic, "
            "location, photos).",
            note="Legitimate if YOU installed it as anti-theft; a red flag if you didn't.",
            family="android"),
    ioc_cmd("android/spymax-rat", "IOC: SpyMax/SpyNote-style RAT service present",
            ["pm", "list", "packages"], r"(?im)\b(com\.mrraven|com\.spymax|com\.example\.spynote)\b",
            "HIGH",
            "Package names associated with the SpyMax / SpyNote Android RAT builders, common in "
            "targeted mobile surveillance.", family="android"),
    ioc_cmd("android/frida-package", "IOC: on-device frida app installed",
            ["pm", "list", "packages"], r"(?im)\bre\.frida\.server\b", "MEDIUM",
            "The frida instrumentation app can hook other apps' memory — legit for researchers, "
            "a hooking implant otherwise.",
            note="Pairs with the frida-server staging check in Murphy's Android module.",
            family="android"),
]

MOUNTS = []
for pt, opts in [
    ("/tmp", ["nodev", "nosuid", "noexec"]),
    ("/dev/shm", ["nodev", "nosuid", "noexec"]),
    ("/var/tmp", ["nodev", "nosuid", "noexec"]),
    ("/home", ["nodev", "nosuid"]),
    ("/var", ["nodev", "nosuid"]),
    ("/var/log", ["nodev", "nosuid", "noexec"]),
    ("/boot", ["nodev", "nosuid"]),
]:
    for opt in opts:
        MOUNTS.append(mount(pt, opt, "LOW"))


PACK_FILES = {
    "sysctl-network-extended.generated.json": (
        "Extended IPv4/IPv6 network-stack sysctls (CIS 3.x, IPv6 parity).", NETWORK),
    "sysctl-kernel-extended.generated.json": (
        "Extended kernel / memory / BPF hardening sysctls (kernel-hardening guides).", KERNEL),
    "legacy-services.generated.json": (
        "Legacy/cleartext servers & clients that should not be installed (CIS 2.x).", LEGACY),
    "file-permissions.generated.json": (
        "Credential, cron, auth and banner file/dir permissions (CIS 6.1 / 5.1).", PERMS),
    "mount-options.generated.json": (
        "nodev/nosuid/noexec on sensitive mountpoints (CIS 1.1).", MOUNTS),
    "ioc-known-bad.generated.json": (
        "Known-bad file indicators for common Linux malware (Kinsing, XMRig, libprocesshider, "
        "Diicot, hidden-sshd backdoors). Conservative — present == investigate.", IOC),
    "ioc-rats-rootkits.generated.json": (
        "RAT / backdoor / rootkit indicators (Reptile, Diamorphine & other LKM rootkits, "
        "BPFDoor, XorDDoS, RotaJakiro, Skidmap, RedXOR/Winnti, HiddenWasp). Present == investigate.",
        RATS),
    "ioc-spyware.generated.json": (
        "Spyware / stalkerware / commercial-surveillance indicators — Linux desktop (EvilGnome, "
        "logkeys) and Android packages (Pegasus/Chrysaor, TheTruthSpy, Cerberus, SpyMax/SpyNote). "
        "For real mobile triage use Amnesty's MVT.", SPYWARE),
}


def main():
    total = 0
    for fname, (desc, rules) in PACK_FILES.items():
        doc = {"name": fname.replace(".generated.json", ""),
               "description": desc + "  Absent keys/paths SKIP, never false-fail.",
               "rules": rules}
        path = os.path.join(PACKS, fname)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, ensure_ascii=False)
            f.write("\n")
        print(f"wrote {len(rules):3d} rules → packs/{fname}")
        total += len(rules)
    print(f"total generated: {total} rules")


if __name__ == "__main__":
    main()
