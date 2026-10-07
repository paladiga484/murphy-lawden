"""Read a .torrent or a magnet link without fetching a single payload byte.

A .torrent carries the whole file list, so it can be judged completely before the
download starts. A magnet link carries a hash and maybe a name — the file list
only exists once the client has pulled metadata from the swarm. We never do that
ourselves (joining the DHT announces your IP); if qBittorrent already has it,
we read qBittorrent's cached copy instead.
"""
from __future__ import annotations

import base64
import hashlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import names
from .names import CRIT, HIGH, WARN, Hit

MAX_TORRENT = 64 << 20           # a real .torrent is KBs–a few MB; refuse anything absurd
MAX_DEPTH = 64


class BencodeError(ValueError):
    pass


def _decode(buf: bytes, i: int, depth: int, spans: dict):
    if depth > MAX_DEPTH:
        raise BencodeError("nesting too deep")
    if i >= len(buf):
        raise BencodeError("truncated")
    c = buf[i:i + 1]
    if c == b"i":
        end = buf.index(b"e", i)
        return int(buf[i + 1:end]), end + 1
    if c == b"l":
        i += 1
        out = []
        while buf[i:i + 1] != b"e":
            v, i = _decode(buf, i, depth + 1, spans)
            out.append(v)
        return out, i + 1
    if c == b"d":
        i += 1
        out = {}
        while buf[i:i + 1] != b"e":
            k, i = _decode(buf, i, depth + 1, spans)
            if not isinstance(k, bytes):
                raise BencodeError("non-string key")
            start = i
            v, i = _decode(buf, i, depth + 1, spans)
            if depth == 0 and k == b"info":
                spans["info"] = (start, i)
            out[k] = v
        return out, i + 1
    if c.isdigit():
        colon = buf.index(b":", i)
        n = int(buf[i:colon])
        if n < 0 or colon + 1 + n > len(buf):
            raise BencodeError("string runs past the end")
        return buf[colon + 1:colon + 1 + n], colon + 1 + n
    raise BencodeError(f"bad token {c!r} at {i}")


def bdecode(buf: bytes) -> tuple[dict, bytes]:
    """Decode; also return the raw `info` bytes (the infohash is their SHA-1/256)."""
    spans: dict = {}
    try:
        v, end = _decode(buf, 0, 0, spans)
    except (ValueError, IndexError) as e:
        raise BencodeError(str(e)) from None
    if not isinstance(v, dict) or "info" not in spans:
        raise BencodeError("not a torrent (no info dictionary)")
    a, b = spans["info"]
    return v, buf[a:b]


def _s(b) -> str:
    return b.decode("utf-8", "replace") if isinstance(b, bytes) else str(b)


@dataclass
class Report:
    title: str
    infohash: str = ""
    files: list[tuple[str, int]] = field(default_factory=list)
    hits: list[Hit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    complete: bool = True            # False = magnet without metadata: file list unknown


def _files_v1(info: dict) -> list[tuple[str, int]]:
    name = _s(info.get(b"name.utf-8", info.get(b"name", b"")))
    if b"files" not in info:
        return [(name, int(info.get(b"length", 0)))]
    out = []
    for f in info[b"files"]:
        parts = f.get(b"path.utf-8", f.get(b"path", []))
        if f.get(b"attr", b"") and b"p" in f.get(b"attr", b""):
            continue                                   # BEP 47 padding file
        out.append(("/".join([name] + [_s(p) for p in parts]), int(f.get(b"length", 0))))
    return out


def _files_v2(tree: dict, prefix: str) -> list[tuple[str, int]]:
    out = []
    for k, v in tree.items():
        if k == b"":
            out.append((prefix, int(v.get(b"length", 0))))
        elif isinstance(v, dict):
            out.extend(_files_v2(v, f"{prefix}/{_s(k)}" if prefix else _s(k)))
    return out


def _judge_trackers(urls: list[str], r: Report) -> None:
    for u in urls:
        scheme = urlparse(u).scheme.lower()
        if scheme == "http":
            r.notes.append(f"tracker over plain HTTP (your ISP sees the hash): {u}")
        elif scheme not in ("https", "udp", "wss", "ws"):
            r.hits.append(Hit(WARN, u, f"unusual tracker scheme '{scheme}'"))


def _judge_files(r: Report) -> None:
    media = names.media_context(r.files, r.title)
    total = sum(s for _, s in r.files)
    for path, size in r.files:
        r.hits.extend(names.judge_name(path, media))
        e = names.ext(path)
        if e in names.MEDIA and 0 < size < (2 << 20) and e not in ("mp3", "flac", "m4a", "ogg",
                                                                   "opus", "wav", "aac"):
            r.hits.append(Hit(HIGH, path, f"a 'video' of {size // 1024} KB: too small to be the film"))
    exes = [p for p, _ in r.files if names.ext(p) in names.EXEC]
    arcs = [p for p, _ in r.files if names.ext(p) in names.ARCHIVES]
    pw = [p for p, _ in r.files if names.ext(p) in ("txt", "nfo", "")
          and any(w in p.lower() for w in ("pass", "pwd"))]
    if arcs and pw:
        r.hits.append(Hit(HIGH, arcs[0], "archive shipped with a password file — the classic way "
                                         "to smuggle a payload past antivirus"))
    if media and exes:
        r.hits.append(Hit(CRIT, r.title, f"media download that also carries {len(exes)} "
                                         "executable(s) — the textbook fake-movie dropper"))
    if total and len(r.files) == 1 and names.ext(r.files[0][0]) in names.ARCHIVES and media:
        r.hits.append(Hit(HIGH, r.title, "a single archive posing as media"))


def check_torrent(path: Path) -> Report:
    size = path.stat().st_size
    if size > MAX_TORRENT:
        raise BencodeError(f"{size} bytes — no real .torrent is that large")
    meta, raw_info = bdecode(path.read_bytes())
    info = meta.get(b"info", {})
    name = _s(info.get(b"name.utf-8", info.get(b"name", path.stem.encode())))
    r = Report(title=name)
    v2 = b"file tree" in info
    # qBittorrent's id: the v1 hash, or the v2 hash cut to 40 hex for v2-only torrents
    r.infohash = hashlib.sha1(raw_info).hexdigest() if (b"pieces" in info or not v2) \
        else hashlib.sha256(raw_info).hexdigest()[:40]
    r.files = _files_v1(info) if b"pieces" in info or not v2 else _files_v2(info[b"file tree"], name)
    if info.get(b"private") == 1:
        r.notes.append("private torrent (DHT/PEX off by design)")
    trackers = [_s(meta[b"announce"])] if b"announce" in meta else []
    for tier in meta.get(b"announce-list", []) or []:
        trackers += [_s(t) for t in tier if isinstance(t, bytes)]
    _judge_trackers(sorted(set(trackers)), r)
    seeds = meta.get(b"url-list", [])
    for u in ([seeds] if isinstance(seeds, bytes) else seeds):
        r.notes.append(f"web seed (your client will fetch from this server directly): {_s(u)}")
    _judge_files(r)
    return r


# ---- magnets --------------------------------------------------------------- #
def _btih(xt: str) -> str:
    h = xt.split(":")[-1]
    if len(h) == 40 and all(c in "0123456789abcdefABCDEF" for c in h):
        return h.lower()
    if len(h) == 32:
        try:
            return base64.b32decode(h.upper()).hex()
        except ValueError:
            return ""
    return ""


def qbit_cache_dirs() -> list[Path]:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA", "")
        return [Path(base) / "qBittorrent" / "BT_backup"] if base else []
    home = Path.home()
    return [home / ".local/share/qBittorrent/BT_backup",
            home / ".var/app/org.qbittorrent.qBittorrent/data/qBittorrent/BT_backup"]


def check_magnet(uri: str) -> Report:
    q = parse_qs(urlparse(uri).query)
    xts = q.get("xt", [])
    hashes = [_btih(x) for x in xts if x.startswith("urn:btih:")]
    v2 = [x.split(":")[-1].lower().removeprefix("1220")[:40]      # sha2-256 multihash
          for x in xts if x.startswith("urn:btmh:")]
    dn = unquote(q.get("dn", [""])[0])
    r = Report(title=dn or "(no name in link)")
    if not hashes and not v2:
        raise BencodeError("no info-hash in it — not a real magnet link")
    r.infohash = hashes[0] if hashes and hashes[0] else (v2[0] if v2 else "")
    if hashes and not hashes[0]:
        r.hits.append(Hit(WARN, "xt", "malformed btih hash"))

    # Already fetched by qBittorrent? Its cached .torrent has the full file list.
    for d in qbit_cache_dirs():
        cached = d / f"{r.infohash}.torrent"
        if r.infohash and cached.is_file():
            full = check_torrent(cached)
            full.notes.insert(0, f"file list read from qBittorrent's metadata cache ({cached})")
            _judge_trackers(q.get("tr", []), full)
            return full

    r.complete = False
    if dn:
        r.hits.extend(names.judge_name(dn, names.ext(dn) in names.MEDIA))
    _judge_trackers(q.get("tr", []), r)
    for key in ("xs", "as", "ws"):
        for u in q.get(key, []):
            r.notes.append(f"{key}= source: your client may fetch from {u} directly")
    return r
