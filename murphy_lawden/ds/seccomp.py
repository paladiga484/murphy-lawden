"""A system-call filter for the cage (seccomp-BPF), built by hand — no libseccomp needed.

The cage's walls are kernel walls, so the realistic way out of it is a kernel bug.
This filter makes the kernel refuse, with "operation not permitted", the calls a
game or a Windows program under Wine never needs but kernel exploits love: BPF,
io_uring, perf counters, userfaultfd, the key store, module and kexec loading,
every mount and namespace call, raw I/O ports, and grabbing another process's
file handles.

ptrace and process_vm_readv stay allowed: Wine uses them between its own
processes, and inside the cage's PID namespace there is nothing else to reach.

Both x86-64 and 32-bit x86 calls are filtered — Proton still runs old 32-bit games
as real 32-bit processes, and an unfiltered 32-bit table would be a way around.
The x32 ABI is refused outright. On other CPUs the filter is skipped, and `ds run`
says so.
"""
from __future__ import annotations

import platform
import struct

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_I386 = 0x40000003
X32_BIT = 0x40000000
RET_ALLOW = 0x7FFF0000
RET_EPERM = 0x00050000 | 1
LD_ABS_W, JEQ_K, JGE_K, RET_K = 0x20, 0x15, 0x35, 0x06

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
    "open_by_handle_at": (304, 342), "name_to_handle_at": (303, 341),
    "swapon": (167, 87), "swapoff": (168, 115), "reboot": (169, 88), "acct": (163, 51),
    "syslog": (103, 103), "quotactl": (179, 131), "iopl": (172, 110), "ioperm": (173, 101),
    "pidfd_getfd": (438, 438), "process_madvise": (440, 440),
    "umount": (None, 22), "vm86": (None, 166), "vm86old": (None, 113),
}


def supported() -> bool:
    return platform.machine() in ("x86_64", "AMD64")


def _ins(code: int, k: int, jt: int = 0, jf: int = 0) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


def _table(nrs: list[int], prog: list[tuple]) -> None:
    """Append: for each number, 'equal → deny'; then allow. Jumps are patched later."""
    for nr in nrs:
        prog.append(("jeq_deny", nr))
    prog.append(("ret", RET_ALLOW))


def program() -> bytes:
    """The compiled filter, as bwrap --seccomp wants it (raw struct sock_filter[])."""
    x64 = sorted({v[0] for v in BLOCKED.values() if v[0] is not None})
    x86 = sorted({v[1] for v in BLOCKED.values() if v[1] is not None})
    prog: list[tuple] = [
        ("ld", 4),                                   # seccomp_data.arch
        ("jeq_label", AUDIT_ARCH_X86_64, "x64"),
        ("jeq_label", AUDIT_ARCH_I386, "x86"),
        ("ret", RET_EPERM),                          # any other ABI: refused
        ("label", "x64"), ("ld", 0),                 # seccomp_data.nr
        ("jge_deny", X32_BIT),
    ]
    _table(x64, prog)
    prog += [("label", "x86"), ("ld", 0)]
    _table(x86, prog)
    prog += [("label", "deny"), ("ret", RET_EPERM)]

    # resolve labels to instruction indexes
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
        elif kind == "ret":
            out.append(_ins(RET_K, op[1]))
        elif kind == "jeq_label":
            out.append(_ins(JEQ_K, op[1], jt=labels[op[2]] - pc - 1, jf=0))
        elif kind == "jeq_deny":
            out.append(_ins(JEQ_K, op[1], jt=labels["deny"] - pc - 1, jf=0))
        elif kind == "jge_deny":
            out.append(_ins(JGE_K, op[1], jt=labels["deny"] - pc - 1, jf=0))
        pc += 1
    if labels["deny"] > 255:                     # BPF conditional jumps are 8-bit
        raise ValueError("filter too long for 8-bit jumps")
    return b"".join(out)
