"""A restricted Wayland socket for the cage (wp-security-context-v1).

Handing a program the raw compositor socket hands it the privileged protocols
too — on Hyprland that includes a virtual keyboard (it could type into your
terminal), screen capture and clipboard snooping. The security-context protocol
lets us open a *second* listening socket whose clients the compositor knows are
sandboxed, and it withholds the privileged globals from them.

Minimal Wayland wire protocol, stdlib only: connect, find the manager, create a
listener on our own socket, tag it, commit. The listener lives until the
`close` pipe is hung up (when the cage exits).
"""
from __future__ import annotations

import array
import os
import socket
import struct
import tempfile
from pathlib import Path

# the globals that turn a window into an escape; if any of these is still offered
# on the restricted socket, the compositor isn't filtering and --gui must refuse
PRIVILEGED = ("zwp_virtual_keyboard_manager_v1", "zwlr_virtual_pointer_manager_v1",
              "zwlr_data_control_manager_v1", "ext_data_control_manager_v1",
              "zwlr_screencopy_manager_v1", "ext_image_copy_capture_manager_v1",
              "hyprland_toplevel_export_manager_v1", "zwp_input_method_manager_v2",
              "hyprland_input_capture_manager_v1", "zwlr_foreign_toplevel_manager_v1",
              "ext_foreign_toplevel_list_v1", "hyprland_global_shortcuts_manager_v1")


class WaylandError(RuntimeError):
    pass


def _str(s: str) -> bytes:
    b = s.encode() + b"\0"
    return struct.pack("<I", len(b)) + b + b"\0" * (-len(b) % 4)


class _Conn:
    def __init__(self, path: str):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(path)
        self.buf = b""
        self.next_id = 2

    def new_id(self) -> int:
        i, self.next_id = self.next_id, self.next_id + 1
        return i

    def send(self, obj: int, op: int, payload: bytes = b"", fds: list[int] | None = None) -> None:
        msg = struct.pack("<II", obj, ((8 + len(payload)) << 16) | op) + payload
        anc = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds).tobytes())] if fds else []
        self.s.sendmsg([msg], anc)

    def events(self):
        while True:
            while len(self.buf) >= 8:
                obj, word = struct.unpack_from("<II", self.buf)
                size, op = word >> 16, word & 0xFFFF
                if size < 8:
                    raise WaylandError("malformed message")
                if len(self.buf) < size:
                    break
                body, self.buf = self.buf[8:size], self.buf[size:]
                yield obj, op, body
            chunk = self.s.recv(65536)
            if not chunk:
                raise WaylandError("compositor closed the connection")
            self.buf += chunk

    def roundtrip_globals(self, registry: int) -> dict[str, tuple[int, int]]:
        """{interface: (name, version)} — everything the registry announces."""
        cb = self.new_id()
        self.send(1, 0, struct.pack("<I", cb))                  # wl_display.sync
        found = {}
        for obj, op, body in self.events():
            if obj == registry and op == 0:                     # wl_registry.global
                name, = struct.unpack_from("<I", body)
                n, = struct.unpack_from("<I", body, 4)
                iface = body[8:8 + n - 1].decode()
                ver, = struct.unpack_from("<I", body, 8 + n + (-n % 4))
                found[iface] = (name, ver)
            elif obj == cb and op == 0:                         # wl_callback.done
                return found
            elif obj == 1 and op == 0:                          # wl_display.error
                raise WaylandError("protocol error from compositor")

    def globals(self) -> dict[str, tuple[int, int]]:
        reg = self.new_id()
        self.send(1, 1, struct.pack("<I", reg))                 # wl_display.get_registry
        return reg, self.roundtrip_globals(reg)


def _display_path() -> str:
    wl = os.environ.get("WAYLAND_DISPLAY", "")
    rt = os.environ.get("XDG_RUNTIME_DIR", "")
    if not wl:
        raise WaylandError("not a Wayland session (WAYLAND_DISPLAY unset)")
    return wl if wl.startswith("/") else os.path.join(rt, wl)


class RestrictedSocket:
    """Context manager: yields the path of a sandbox-tagged Wayland socket."""

    def __init__(self, app_id: str = "murphy.ds.cage"):
        self.app_id = app_id

    def __enter__(self) -> str:
        self.conn = _Conn(_display_path())
        reg, g = self.conn.globals()
        if "wp_security_context_manager_v1" not in g:
            raise WaylandError("the compositor has no security-context support")
        name, ver = g["wp_security_context_manager_v1"]
        mgr = self.conn.new_id()
        self.conn.send(reg, 0, struct.pack("<I", name) + _str("wp_security_context_manager_v1")
                       + struct.pack("<II", 1, mgr))          # wl_registry.bind
        self.dir = tempfile.mkdtemp(prefix="wl-", dir=os.environ.get("XDG_RUNTIME_DIR") or None)
        self.path = os.path.join(self.dir, "wayland-cage")
        self.listen = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listen.bind(self.path)
        self.listen.listen(16)
        self.close_r, self.close_w = os.pipe()
        ctx = self.conn.new_id()
        self.conn.send(mgr, 1, struct.pack("<I", ctx),
                       fds=[self.listen.fileno(), self.close_r])   # create_listener
        self.conn.send(ctx, 1, _str("murphy-ds"))              # set_sandbox_engine
        self.conn.send(ctx, 2, _str(self.app_id))              # set_app_id
        self.conn.send(ctx, 4)                                 # commit
        # a roundtrip surfaces any protocol error before we trust the socket
        self.conn.roundtrip_globals(reg)
        os.close(self.close_r)
        self.listen.close()                                    # the compositor holds its copy
        return self.path

    def __exit__(self, *exc) -> None:
        os.close(self.close_w)                                 # hang up: listener stops
        self.conn.s.close()
        Path(self.path).unlink(missing_ok=True)
        os.rmdir(self.dir)


def offered(path: str) -> set[str]:
    c = _Conn(path)
    _, g = c.globals()
    c.s.close()
    return set(g)
