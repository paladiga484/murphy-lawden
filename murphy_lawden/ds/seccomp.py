"""A system-call filter for the cage (seccomp-BPF), built by hand — no libseccomp needed.

The cage's walls are kernel walls, so the realistic way out of it is a kernel bug.
This filter makes the kernel refuse, with "operation not permitted", the calls a
game or a Windows program under Wine never needs but kernel exploits love: BPF,
io_uring, perf counters, userfaultfd, the key store, module and kexec loading,
every mount and namespace call, raw I/O ports, grabbing another process's file
handles, and SysV message queues (the favourite kernel-heap spray).

Sockets are let through only for the families a program actually uses — local
(unix), IPv4/IPv6 and route/uevent netlink. Every other family (packet, AF_ALG,
vsock, TIPC, RDS, CAN, Bluetooth…) answers "family not supported": no exotic,
rarely audited protocol code is reachable, and none gets auto-loaded as a module.
`sockets=False` (the scanner and the extractor) refuses socket() altogether, so a
compromised parser can't even knock on a unix socket it finds lying around.

ptrace and process_vm_readv stay allowed: Wine uses them between its own
processes, and inside the cage's PID namespace there is nothing else to reach.

Both x86-64 and 32-bit x86 calls are filtered — Proton still runs old 32-bit games
as real 32-bit processes, and an unfiltered 32-bit table would be a way around.
32-bit socketcall() is refused (its arguments sit behind a pointer the filter
can't read; 32-bit glibc uses the direct calls instead), and 32-bit ipc() is
filtered by operation. The x32 ABI is refused outright. On other CPUs the filter
is skipped, and `ds run` says so.
"""
from __future__ import annotations

import platform
import struct

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_I386 = 0x40000003
X32_BIT = 0x40000000
RET_ALLOW = 0x7FFF0000
RET_ERRNO = 0x00050000
EPERM, EPROTONOSUPPORT, EAFNOSUPPORT = 1, 93, 97
LD_ABS_W, ALU_AND_K, JEQ_K, JGT_K, JGE_K, RET_K = 0x20, 0x54, 0x15, 0x25, 0x35, 0x06
NR, ARG0, ARG2 = 0, 16, 32        # offsets in struct seccomp_data (low 32 bits of each arg)

AF_UNIX, AF_INET, AF_INET6, AF_NETLINK = 1, 2, 10, 16
NETLINK_ROUTE, NETLINK_KOBJECT_UEVENT = 0, 15
IPC_MSGSND, IPC_MSGCTL = 11, 14    # 32-bit ipc(): msgsnd, msgrcv, msgget, msgctl

# name: (x86-64 number, i386 number or None)
BLOCKED = {
    "bpf": (321, 357), "perf_event_open": (298, 336), "userfaultfd": (323, 374),
    "io_uring_setup": (425, 425), "io_uring_enter": (426, 426), "io_uring_register": (427, 427),
    "keyctl": (250, 288), "add_key": (248, 286), "request_key": (249, 287),
    "init_module": (175, 128), "finit_module": (313, 350), "delete_module": (176, 129),
    "kexec_load": (246, 283), "kexec_file_load": (320, None),
    "mount": (165, 21), "umount2": (166, 52), "pivot_root": (155, 217), "setns": (308, 346),
    "open_tree": (428, 428), "move_mount": (429, 429), "fsopen": (430, 430),
    "fsconfig": (431, 431), "fsmount": (432, 432), "fspick": (433, 433), "mount_setattr": (442, 442),
    "open_tree_attr": (467, 467), "statmount": (457, 457), "listmount": (458, 458), "chroot": (161, 61),
    "open_by_handle_at": (304, 342), "name_to_handle_at": (303, 341),
    "swapon": (167, 87), "swapoff": (168, 115), "reboot": (169, 88), "acct": (163, 51),
    "syslog": (103, 103), "quotactl": (179, 131), "quotactl_fd": (443, 443),
    "iopl": (172, 110), "ioperm": (173, 101), "vhangup": (153, 111),
    "pidfd_getfd": (438, 438), "process_madvise": (440, 440), "fanotify_init": (300, 338),
    "msgget": (68, 399), "msgsnd": (69, 400), "msgrcv": (70, 401), "msgctl": (71, 402),
    "uselib": (134, 86), "ustat": (136, 62), "sysfs": (139, 135), "_sysctl": (156, 149),
    "nfsservctl": (180, 169), "lookup_dcookie": (212, 253), "remap_file_pages": (216, 257),
    "socketcall": (None, 102),
    "umount": (None, 22), "vm86": (None, 166), "vm86old": (None, 113),
}
SOCKET, SOCKETPAIR, IPC = (41, 359), (53, 360), (None, 117)


def supported() -> bool:
    return platform.machine() in ("x86_64", "AMD64")


def _ins(code: int, k: int, jt: int = 0, jf: int = 0) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


def _arch(arch: int, tag: str, sockets: bool) -> list[tuple]:
    """The checks for one syscall table; every jump lands on a label of this table."""
    deny, sock, pair, ipc, ok = (f"{tag}-{x}" for x in ("deny", "sock", "pair", "ipc", "ok"))
    prog: list[tuple] = [("label", tag), ("ld", NR)]
    if arch == 0:
        prog.append(("jge", X32_BIT, deny))                         # x32 numbers: refused
    prog += [("jeq", SOCKET[arch], sock), ("jeq", SOCKETPAIR[arch], pair)]
    if IPC[arch] is not None:
        prog.append(("jeq", IPC[arch], ipc))
    prog += [("jeq", n, deny) for n in sorted({v[arch] for v in BLOCKED.values() if v[arch] is not None})]
    prog += [("ret", RET_ALLOW), ("label", deny), ("ret", RET_ERRNO | EPERM), ("label", sock)]
    if sockets:
        prog += [("ld", ARG0), ("jeq", AF_UNIX, ok), ("jeq", AF_INET, ok), ("jeq", AF_INET6, ok),
                 ("jeq", AF_NETLINK, f"{tag}-netlink"), ("ret", RET_ERRNO | EAFNOSUPPORT),
                 ("label", f"{tag}-netlink"), ("ld", ARG2), ("jeq", NETLINK_ROUTE, ok),
                 ("jeq", NETLINK_KOBJECT_UEVENT, ok), ("ret", RET_ERRNO | EPROTONOSUPPORT)]
    else:
        prog.append(("ret", RET_ERRNO | EPERM))
    prog += [("label", pair), ("ld", ARG0), ("jeq", AF_UNIX, ok), ("ret", RET_ERRNO | EAFNOSUPPORT)]
    if IPC[arch] is not None:                                       # ipc(call): op in the low 16 bits
        prog += [("label", ipc), ("ld", ARG0), ("and", 0xFFFF), ("jge", IPC_MSGSND, f"{tag}-ipc-msg"),
                 ("ret", RET_ALLOW), ("label", f"{tag}-ipc-msg"), ("jgt", IPC_MSGCTL, ok),
                 ("ret", RET_ERRNO | EPERM)]
    return prog + [("label", ok), ("ret", RET_ALLOW)]


def _assemble(prog: list[tuple]) -> bytes:
    labels, idx = {}, 0
    for op in prog:
        if op[0] == "label":
            labels[op[1]] = idx
        else:
            idx += 1
    out, pc = [], 0
    for op in prog:
        kind = op[0]
        if kind == "label":
            continue
        if kind == "ld":
            out.append(_ins(LD_ABS_W, op[1]))
        elif kind == "and":
            out.append(_ins(ALU_AND_K, op[1]))
        elif kind == "ret":
            out.append(_ins(RET_K, op[1]))
        else:                                       # jeq/jgt/jge k, label-if-true; else fall through
            jump = labels[op[2]] - pc - 1
            if not 0 <= jump <= 255:                # BPF conditional jumps are 8-bit, forward only
                raise ValueError(f"filter jump to {op[2]} out of range ({jump})")
            out.append(_ins({"jeq": JEQ_K, "jgt": JGT_K, "jge": JGE_K}[kind], op[1], jt=jump))
        pc += 1
    return b"".join(out)


def program(sockets: bool = True) -> bytes:
    """The compiled filter, as bwrap --seccomp wants it (raw struct sock_filter[])."""
    prog: list[tuple] = [
        ("ld", 4),                                   # seccomp_data.arch
        ("jeq", AUDIT_ARCH_X86_64, "x64"),
        ("jeq", AUDIT_ARCH_I386, "x86"),
        ("ret", RET_ERRNO | EPERM),                  # any other ABI: refused
        *_arch(0, "x64", sockets),
        *_arch(1, "x86", sockets),
    ]
    return _assemble(prog)
