"""Landlock for the cage: nothing new may be *started* from a writable place.

A Windows .exe under Wine is still a Linux process, and Wine-aware malware knows
it: the common move is to write a native Linux program somewhere (/tmp, its
prefix, the output folder) and start it, stepping out of Windows into Linux. The
cage already gives such a program no network and no home; this takes away the
step itself.

Inside the cage, a small launcher asks the kernel (Landlock, an LSM in every
kernel since 5.13) to allow execve() only from the read-only system and the
program's own read-only copy — /usr, /opt, the Proton build, /cage/app. Writable
places (/tmp, the cage's home, the prefix, the output folder) can hold files but
can never run them. Windows code itself is loaded by Wine with mmap, not execve,
so games are unaffected.

The restriction is permanent for the process and everything it starts. On a
kernel without Landlock the launcher says so and carries on — the rest of the
cage still stands.
"""
from __future__ import annotations

# Runs inside the cage as `python3 -I -c CODE dir... -- argv...`; stdlib only.
CODE = r'''
import ctypes, os, struct, sys
i = sys.argv.index("--")
dirs, argv = sys.argv[1:i], sys.argv[i + 1:]
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
EXECUTE = 1                                            # LANDLOCK_ACCESS_FS_EXECUTE
def fail(why):
    sys.stderr.write("cage: landlock unavailable (%s) - starting without the exec lock\n" % why)
attr = ctypes.create_string_buffer(struct.pack("<Q", EXECUTE))
fd = libc.syscall(444, attr, ctypes.c_size_t(8), ctypes.c_uint32(0))   # landlock_create_ruleset
if fd < 0:
    fail(os.strerror(ctypes.get_errno()))
else:
    for d in dirs:
        try:
            pfd = os.open(d, os.O_PATH | os.O_CLOEXEC)
        except OSError:
            continue
        rule = ctypes.create_string_buffer(struct.pack("<Qi", EXECUTE, pfd))  # packed: 12 bytes
        libc.syscall(445, ctypes.c_int(fd), ctypes.c_int(1), rule, ctypes.c_uint32(0))
        os.close(pfd)
    libc.prctl(38, 1, 0, 0, 0)                         # PR_SET_NO_NEW_PRIVS
    if libc.syscall(446, ctypes.c_int(fd), ctypes.c_uint32(0)) != 0:   # landlock_restrict_self
        fail(os.strerror(ctypes.get_errno()))
    os.close(fd)
os.execvp(argv[0], argv)
'''

EXEC_DIRS = ("/usr", "/opt", "/cage/proton", "/cage/app")


def wrap(argv: list[str], exec_app: bool = True) -> list[str]:
    """exec_app=False when the program's folder is writable (--writable): a folder it can
    write to must not also be one it can start programs from."""
    dirs = [d for d in EXEC_DIRS if exec_app or d != "/cage/app"]
    return ["/usr/bin/python3", "-I", "-c", CODE, *dirs, "--", *argv]
