"""How Murphy reaches the network in online mode — and how quietly.

Three transports, chosen with --via:

  direct   plain HTTP(S) over the default route (fastest, least private).
  tor      HTTP(S) routed through the local Tor SOCKS proxy (127.0.0.1:9050),
           with DNS resolved Tor-side too — the fetch is anonymised and the
           request never touches your ISP's resolver.
  dns      the pack is pulled out of DNS TXT records — a covert, censorship-
           resistant channel that works where outbound HTTP is filtered.

Offline mode never calls any of these; it uses only the bundled library.

Nothing here is cached to disk — the fetched bytes live in memory and are
handed straight to the rules engine (amnesiac).
"""
from __future__ import annotations

import base64
import re
import shutil
import subprocess
import urllib.request

TOR_PROXY = "127.0.0.1:9050"


class TransportError(RuntimeError):
    pass


def _direct(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "murphy-lawden"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")


def _tor(url: str, timeout: int) -> str:
    if not shutil.which("curl"):
        raise TransportError("Tor transport needs 'curl'.")
    # --socks5-hostname resolves the hostname through Tor too (no DNS leak).
    p = subprocess.run(
        ["curl", "-fsS", "--socks5-hostname", TOR_PROXY, "--max-time", str(timeout), url],
        capture_output=True, text=True)
    if p.returncode != 0:
        raise TransportError(
            f"Tor fetch failed (is tor running on {TOR_PROXY}?): {p.stderr.strip() or p.returncode}")
    return p.stdout


def _dns(name: str, timeout: int) -> str:
    """Reassemble a pack from DNS TXT records.

    Wire format: each TXT record is  "<index>:<base64-chunk>" . Murphy sorts by
    index, concatenates the chunks, and base64-decodes the result to the pack
    JSON. Publish a pack with, e.g.:  packs.example.com  IN TXT "0:eyJ..." ...
    """
    if not shutil.which("dig"):
        raise TransportError("DNS transport needs 'dig' (bind-tools/dnsutils).")
    p = subprocess.run(["dig", "+short", "+time=" + str(timeout), "TXT", name],
                       capture_output=True, text=True)
    if p.returncode != 0 or not p.stdout.strip():
        raise TransportError(f"no TXT records for {name!r}")
    chunks: list[tuple[int, str]] = []
    for raw in p.stdout.splitlines():
        val = "".join(re.findall(r'"([^"]*)"', raw)) or raw.strip()
        m = re.match(r"(\d+):(.*)", val)
        if m:
            chunks.append((int(m.group(1)), m.group(2)))
    if not chunks:
        raise TransportError(f"{name} TXT records aren't in '<index>:<base64>' format")
    chunks.sort(key=lambda c: c[0])
    blob = "".join(c[1] for c in chunks)
    try:
        return base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8", "replace")
    except Exception as e:
        raise TransportError(f"could not decode DNS payload: {e}")


def fetch(source: str, transport: str = "direct", timeout: int = 20) -> str:
    """Return the raw pack text for a remote source using the chosen transport."""
    if transport == "dns" or source.startswith("dns:"):
        return _dns(source[4:] if source.startswith("dns:") else source, timeout)
    if transport == "tor":
        return _tor(source, timeout)
    return _direct(source, timeout)
