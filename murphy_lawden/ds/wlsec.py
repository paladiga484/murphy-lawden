"""A restricted Wayland socket for the cage (wp-security-context-v1).

Handing a program the raw compositor socket hands it the privileged protocols
too — on Hyprland that includes a virtual keyboard (it could type into your
terminal), screen capture and clipboard snooping. The security-context protocol
lets us open a *second* listening socket whose clients the compositor knows are
sandboxed, and it withholds the privileged globals from them.

Minimal Wayland wire protocol, stdlib only: connect, find the manager, create a
listener on our own socket, tag it, commit. The listener lives until the
`close` pipe is hung up (when the cage exits).

The compositor's idea of "sandboxed" still leaves a lot: your clipboard (read it,
or swap a wallet address into it — the classic Windows clipper), focus stealing,
keyboard-shortcut grabs, "is the user idle?". FilteredSocket sits in front and
shows a client only an allowlist of interfaces; a client that tries to bind one
it wasn't shown is cut off and named.
"""
from __future__ import annotations

import array
import os
import selectors
import socket
import struct
import tempfile
import threading
from pathlib import Path

# the globals that turn a window into an escape; if any of these is still offered
# on the restricted socket, the compositor isn't filtering and --gui must refuse
PRIVILEGED = ("zwp_virtual_keyboard_manager_v1", "zwlr_virtual_pointer_manager_v1",
              "zwlr_data_control_manager_v1", "ext_data_control_manager_v1",
              "zwlr_screencopy_manager_v1", "ext_image_copy_capture_manager_v1",
              "hyprland_toplevel_export_manager_v1", "zwp_input_method_manager_v2",
              "hyprland_input_capture_manager_v1", "zwlr_foreign_toplevel_manager_v1",
              "ext_foreign_toplevel_list_v1", "hyprland_global_shortcuts_manager_v1")


# what a game's window needs: surfaces, input, GPU buffers, pacing, scaling, colour
WINDOW_GLOBALS = frozenset({
    "wl_compositor", "wl_subcompositor", "wl_shm", "wl_seat", "wl_output", "wl_drm",
    "xdg_wm_base", "xdg_wm_dialog_v1", "xdg_toplevel_tag_manager_v1", "xdg_system_bell_v1",
    "zxdg_decoration_manager_v1", "org_kde_kwin_server_decoration_manager", "zxdg_output_manager_v1",
    "zwp_linux_dmabuf_v1", "wp_linux_drm_syncobj_manager_v1", "wp_viewporter",
    "wp_fractional_scale_manager_v1", "wp_presentation", "wp_commit_timing_manager_v1",
    "wp_fifo_manager_v1", "wp_tearing_control_manager_v1", "wp_single_pixel_buffer_manager_v1",
    "wp_alpha_modifier_v1", "wp_color_manager_v1", "wp_content_type_manager_v1",
    "wp_cursor_shape_manager_v1", "zwp_relative_pointer_manager_v1", "zwp_pointer_constraints_v1",
    "zwp_pointer_gestures_v1", "wp_pointer_warp_v1", "zwp_text_input_manager_v3",
    "zwp_tablet_manager_v2", "zwp_idle_inhibit_manager_v1",
})
# an app you hand links to (qBittorrent: pasting a magnet) keeps the clipboard
APP_GLOBALS = WINDOW_GLOBALS | {"wl_data_device_manager", "zwp_primary_selection_device_manager_v1",
                                "xdg_activation_v1"}


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


class _Closed(Exception):
    pass


class _End:
    """One socket of a relayed connection: bytes still being assembled into whole
    messages (and the fds that came with them), and what we still owe it."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.inbuf = b""
        self.infds: list[int] = []
        self.out = bytearray()
        self.outfds: list[int] = []


def _iface(msg: bytes, off: int) -> str:
    """The string argument at `off` (length-prefixed, NUL-terminated)."""
    n, = struct.unpack_from("<I", msg, off)
    return msg[off + 4:off + 4 + max(n - 1, 0)].decode("ascii", "replace")


class _Link:
    """A client and the compositor, relayed whole message by whole message. Only the
    registry is read: globals outside `allow` are never announced, and binding a name
    that wasn't announced ends the connection."""

    BACKLOG = 4 << 20               # bytes owed to one side before we stop reading the other

    def __init__(self, client: socket.socket, server: socket.socket, allow, refused: list):
        self.c, self.s = _End(client), _End(server)
        self.allow, self.refused = allow, refused
        self.registries: set[int] = set()
        self.shown: dict[int, str] = {}          # global name -> interface, as announced
        self.hidden: set[int] = set()

    def peer(self, end: _End) -> _End:
        return self.s if end is self.c else self.c

    def pump(self, end: _End) -> None:
        try:
            data, fds, _, _ = socket.recv_fds(end.sock, 65536, 64)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            raise _Closed
        end.infds += fds
        if not data:
            raise _Closed
        end.inbuf += data
        keep = []
        while len(end.inbuf) >= 8:
            obj, word = struct.unpack_from("<II", end.inbuf)
            size, op = word >> 16, word & 0xFFFF
            if size < 8 or size % 4:
                raise _Closed                    # not Wayland, or out of step
            if len(end.inbuf) < size:
                break
            msg, end.inbuf = end.inbuf[:size], end.inbuf[size:]
            try:
                if (self._from_client if end is self.c else self._from_server)(obj, op, msg):
                    keep.append(msg)
            except struct.error:
                raise _Closed                    # a registry message too short to be one
        # fds travel with the bytes that follow them, never after: a message never
        # arrives before the descriptors it carries
        other = self.peer(end)
        other.out += b"".join(keep)
        other.outfds += end.infds
        end.infds = []

    def flush(self, end: _End) -> None:
        while end.out:
            chunk = bytes(end.out[:4 if len(end.outfds) > 200 else 65536])
            fds = end.outfds[:200]
            try:
                n = socket.send_fds(end.sock, [chunk], fds) if fds else end.sock.send(chunk)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                raise _Closed
            for fd in fds:
                os.close(fd)
            del end.outfds[:len(fds)]
            del end.out[:n]

    def _from_client(self, obj: int, op: int, msg: bytes) -> bool:
        if obj == 1 and op == 1 and len(msg) >= 12:            # wl_display.get_registry
            self.registries.add(struct.unpack_from("<I", msg, 8)[0])
        elif obj in self.registries and op == 0:               # wl_registry.bind(name, iface, ver, id)
            name, = struct.unpack_from("<I", msg, 8)
            iface = _iface(msg, 12) if len(msg) >= 16 else ""
            if self.shown.get(name) != iface:
                self.refused.append(iface or f"global #{name}")
                raise _Closed
        return True

    def _from_server(self, obj: int, op: int, msg: bytes) -> bool:
        if obj in self.registries and op == 0:                 # wl_registry.global(name, iface, ver)
            name, = struct.unpack_from("<I", msg, 8)
            iface = _iface(msg, 12)
            if iface in self.allow:
                self.shown[name] = iface
                return True
            self.hidden.add(name)
            return False
        if obj in self.registries and op == 1:                 # wl_registry.global_remove(name)
            name, = struct.unpack_from("<I", msg, 8)
            self.shown.pop(name, None)
            if name in self.hidden:
                self.hidden.discard(name)
                return False
        elif obj == 1 and op == 1:                             # wl_display.delete_id(id)
            self.registries.discard(struct.unpack_from("<I", msg, 8)[0])
        return True

    def close(self) -> None:
        for end in (self.c, self.s):
            for fd in end.infds + end.outfds:
                os.close(fd)
            end.infds, end.outfds = [], []
            end.sock.close()


class FilteredSocket:
    """Context manager: yields the path of a socket that relays to `upstream` (a
    RestrictedSocket, ideally) and shows clients only the globals in `allow`.
    `refused` lists every hidden interface a client tried to bind anyway."""

    MAX_CLIENTS = 32

    def __init__(self, upstream: str, allow: frozenset[str]):
        self.upstream, self.allow = upstream, allow
        self.refused: list[str] = []

    def __enter__(self) -> str:
        self.dir = tempfile.mkdtemp(prefix="wlf-", dir=os.environ.get("XDG_RUNTIME_DIR") or None)
        self.path = os.path.join(self.dir, "wayland-filtered")
        self.listen = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listen.bind(self.path)
        self.listen.listen(16)
        self.listen.setblocking(False)
        self.stop_r, self.stop_w = os.pipe()
        self.thread = threading.Thread(target=self._serve, name="wayland-filter", daemon=True)
        self.thread.start()
        return self.path

    def __exit__(self, *exc) -> None:
        os.write(self.stop_w, b"x")
        self.thread.join(timeout=5)
        os.close(self.stop_w)
        os.close(self.stop_r)
        self.listen.close()
        Path(self.path).unlink(missing_ok=True)
        os.rmdir(self.dir)

    def _serve(self) -> None:
        sel = selectors.DefaultSelector()
        sel.register(self.listen, selectors.EVENT_READ, None)
        sel.register(self.stop_r, selectors.EVENT_READ, None)
        links: set[_Link] = set()

        def arm(link: _Link) -> None:
            """Read a side only while the other isn't owed too much; watch for room to
            write only while we owe it something. Neither: off the selector until the
            other side drains."""
            for end in (link.c, link.s):
                ev = (0 if len(link.peer(end).out) > _Link.BACKLOG else selectors.EVENT_READ) \
                    | (selectors.EVENT_WRITE if end.out else 0)
                try:
                    have = sel.get_key(end.sock).events
                except KeyError:
                    have = 0
                if ev == have:
                    continue
                if not ev:
                    sel.unregister(end.sock)
                elif have:
                    sel.modify(end.sock, ev, (link, end))
                else:
                    sel.register(end.sock, ev, (link, end))

        def drop(link: _Link) -> None:
            for end in (link.c, link.s):
                try:
                    sel.unregister(end.sock)
                except (KeyError, ValueError):
                    pass
            link.close()
            links.discard(link)

        try:
            while True:
                for key, mask in sel.select():
                    if key.fileobj == self.stop_r:
                        return
                    if key.fileobj is self.listen:
                        try:
                            client, _ = self.listen.accept()
                        except OSError:
                            continue
                        if len(links) >= self.MAX_CLIENTS:
                            client.close()
                            continue
                        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                        try:
                            server.connect(self.upstream)
                        except OSError:
                            client.close()
                            server.close()
                            continue
                        client.setblocking(False)
                        server.setblocking(False)
                        link = _Link(client, server, self.allow, self.refused)
                        links.add(link)
                        sel.register(client, selectors.EVENT_READ, (link, link.c))
                        sel.register(server, selectors.EVENT_READ, (link, link.s))
                        continue
                    link, end = key.data
                    if link not in links:
                        continue
                    try:
                        if mask & selectors.EVENT_READ:
                            link.pump(end)
                        for e in (link.c, link.s):
                            link.flush(e)
                        arm(link)
                    except Exception:                  # one bad connection never stalls the others
                        drop(link)
        finally:
            for link in list(links):
                drop(link)
            sel.close()
