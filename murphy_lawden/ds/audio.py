"""Play-only sound for the cage.

The desktop's own audio socket is a door: through it a program can record the
microphone, capture what other programs play, and load server modules — one of
which streams audio to the network, from *outside* the cage. So the cage never
gets that socket.

`--audio` starts a second, private pipewire-pulse for the length of the run. It
listens on its own socket, refuses module loading, and blocks every client from
recording and from touching volumes. What is left is the one thing a game needs:
it can play. Before the socket is handed over it is probed — if a module still
loads or a recording still opens, `--audio` is refused rather than trusted.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from ..core import have, run

_CONF = """\
context.properties = {{ }}
context.spa-libs = {{
    audio.convert.* = audioconvert/libspa-audioconvert
    support.*       = support/libspa-support
}}
context.modules = [
    {{ name = libpipewire-module-rt args = {{ nice.level = -11 rtportal.enabled = false }}
       flags = [ ifexists nofail ] }}
    {{ name = libpipewire-module-protocol-native }}
    {{ name = libpipewire-module-client-node }}
    {{ name = libpipewire-module-adapter }}
    {{ name = libpipewire-module-metadata }}
    {{ name = libpipewire-module-protocol-pulse args = {{ }} }}
]
pulse.properties = {{
    server.address = [ "unix:{sock}" ]
    server.dbus-name = "org.murphy.ds.cage{pid}"
    pulse.allow-module-loading = false
}}
pulse.rules = [
    # pulse.server.type is set by the server on every connection: no client can dodge this
    {{ matches = [ {{ pulse.server.type = "unix" }} ]
       actions = {{ quirks = [ block-record-stream block-source-volume block-sink-volume ] }} }}
]
"""


class AudioError(RuntimeError):
    pass


def _probe(sock: str) -> str:
    """What the socket still allows that it must not; empty when it is play-only."""
    env = {**os.environ, "PULSE_SERVER": "unix:" + sock}
    try:
        info = subprocess.run(["pactl", "info"], env=env, capture_output=True, timeout=10)
        if info.returncode != 0:
            return "the private sound server doesn't answer"
        mod = subprocess.run(["pactl", "load-module", "module-null-sink", "sink_name=murphy-probe"],
                             env=env, capture_output=True, text=True, timeout=10)
        if mod.returncode == 0:
            subprocess.run(["pactl", "unload-module", mod.stdout.strip()], env=env,
                           capture_output=True, timeout=10)
            return "it still lets clients load modules"
        rec = subprocess.run(["parec", "--raw"], env=env, capture_output=True, timeout=3)
        if rec.returncode == 0 or rec.stdout:
            return "it still lets clients record"
    except subprocess.TimeoutExpired:
        return "it still lets clients record"        # parec kept running: a stream opened
    except OSError as e:
        return str(e)
    return ""


class PlayOnly:
    """Context manager: yields the path of a play-only PulseAudio socket."""

    def __enter__(self) -> str:
        for exe in ("pipewire-pulse", "pactl", "parec"):
            if not have(exe):
                raise AudioError(f"{exe} is not installed (needs PipeWire with pipewire-pulse)")
        if run(["pactl", "info"])[0] != 0:
            raise AudioError("no sound server is running in this session")
        self.dir = tempfile.mkdtemp(prefix="snd-", dir=os.environ.get("XDG_RUNTIME_DIR") or None)
        sock = os.path.join(self.dir, "pulse")
        conf = Path(self.dir, "pulse.conf")
        conf.write_text(_CONF.format(sock=sock, pid=os.getpid()))
        self.proc = subprocess.Popen(["pipewire-pulse", "-c", str(conf)], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        end = time.monotonic() + 5
        while not os.path.exists(sock) and self.proc.poll() is None and time.monotonic() < end:
            time.sleep(0.05)
        why = "the private sound server didn't start" if not os.path.exists(sock) else _probe(sock)
        if why:
            self.__exit__()
            raise AudioError(why)
        return sock

    def __exit__(self, *exc) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        shutil.rmtree(self.dir, ignore_errors=True)
