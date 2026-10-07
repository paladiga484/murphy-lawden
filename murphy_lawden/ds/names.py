"""File-name and file-header heuristics shared by every `ds` check.

The same rules judge a name listed inside a .torrent (before a byte is fetched)
and a real file on disk (after). On disk we also read the first bytes, because a
renamed executable is the oldest trick there is: `movie.mp4` that starts `MZ`.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath

CRIT, HIGH, WARN, INFO = "CRIT", "HIGH", "WARN", "INFO"
RANK = {CRIT: 3, HIGH: 2, WARN: 1, INFO: 0}


@dataclass
class Hit:
    level: str
    path: str
    reason: str


# Windows runs these on a double-click (or through a shell association).
WIN_EXEC = {
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "hta", "msi", "msp", "msc", "lnk", "url", "cpl", "dll", "sys", "ocx", "jar",
    "reg", "inf", "scf", "chm", "application", "appref-ms", "gadget", "xll", "wll", "iqy",
    "settingcontent-ms", "library-ms", "search-ms", "appx", "msix", "appxbundle", "msixbundle",
}
# Linux / cross-platform runnables.
# (.bin/.elf/.so are left to the header sniff: .bin is usually a CD image or game data.)
NIX_EXEC = {"sh", "bash", "zsh", "fish", "run", "appimage", "desktop",
            "py", "pyw", "pl", "rb", "deb", "rpm", "flatpakref", "flatpak"}
# Never legitimate inside a media/game download; there is no innocent reason for them.
NEVER_LEGIT = {"scr", "pif", "lnk", "hta", "vbs", "vbe", "jse", "wsf", "wsh", "cpl", "msc",
               "scf", "url", "settingcontent-ms", "library-ms", "search-ms", "iqy", "desktop"}
# Office formats that carry macros.
MACRO_DOCS = {"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"}
# Disk images: they mount and strip Mark-of-the-Web from what's inside (Windows).
MOTW_BYPASS = {"iso", "img", "vhd", "vhdx"}
MEDIA = {"mkv", "mp4", "m4v", "avi", "mov", "wmv", "webm", "mpg", "mpeg", "ts", "m2ts", "flv",
         "mp3", "flac", "m4a", "aac", "ogg", "opus", "wav", "ape", "alac"}
DOCS = {"pdf", "epub", "mobi", "azw3", "cbz", "cbr", "txt", "nfo", "srt", "ass", "sub", "idx",
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "gif", "webp"}
ARCHIVES = {"zip", "rar", "7z", "tar", "gz", "bz2", "xz", "tgz", "cab", "arj", "lzh", "ace"}
# Legacy formats whose players have a history of being the delivery vehicle.
RISKY_MEDIA = {"wmv", "asf", "wma"}   # DRM licence URLs → "download this codec"

EXEC = WIN_EXEC | NIX_EXEC

# Bidi overrides make `photo_gpj.exe` render as `photo_exe.jpg`; zero-widths hide things.
_BIDI = re.compile("[‪-‮⁦-⁩‎‏؜]")
_INVISIBLE = re.compile("[​-‍⁠﻿᠎]")
# The lure names malware ships under. (setup/install/patch are ordinary in a game
# repack; they get the plain "executable" verdict, not this one.)
_BAIT = re.compile(r"(?i)(^|[\W_])(codec|player|keygen|keymaker|crack(ed)?|activat(or|ion)|"
                   r"kms\w*|loader|unlock(er)?|serial|license|password|passwd|pwd)([\W_]|$)")


def ext(name: str) -> str:
    base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return base.rsplit(".", 1)[-1].lower().strip() if "." in base else ""


def _prev_ext(name: str) -> str:
    base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    parts = base.split(".")
    return parts[-2].lower().strip() if len(parts) >= 3 else ""


def judge_name(path: str, media_context: bool) -> list[Hit]:
    """Rules that need only the name. `media_context` = the download is mostly media/docs,
    so an executable in it has no business being there."""
    hits: list[Hit] = []
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    e, pe = ext(base), _prev_ext(base)

    if _BIDI.search(path):
        hits.append(Hit(CRIT, path, "hidden right-to-left/bidi character: the name you see is "
                                    "not the real extension"))
    if any(unicodedata.category(c) == "Cc" for c in path):
        hits.append(Hit(CRIT, path, "control characters in the name (newlines/escapes that "
                                    "forge or hide terminal output)"))
    if _INVISIBLE.search(path):
        hits.append(Hit(HIGH, path, "invisible zero-width character in the name"))
    parts = PurePosixPath(path.replace("\\", "/")).parts
    if ".." in parts or path.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", path):
        hits.append(Hit(CRIT, path, "path escapes the download folder (../, absolute or drive path)"))
    if e in EXEC and (pe in MEDIA or pe in DOCS or pe in ARCHIVES):
        hits.append(Hit(CRIT, path, f"double extension .{pe}.{e}: an executable dressed as {pe}"))
    elif e in EXEC and re.search(r"\s{3,}\.?\w+$", base):
        hits.append(Hit(CRIT, path, "runs of spaces before the extension (hides it in narrow columns)"))
    damned = any(h.level == CRIT for h in hits)
    if e in NEVER_LEGIT:
        hits.append(Hit(CRIT, path, f".{e} has no innocent use in a download"))
    elif e in EXEC and not damned:
        hits.append(Hit(HIGH if media_context else WARN, path,
                        f"executable (.{e})" + (" inside a media/document download" if media_context
                                                else ": run it only through `murphy ds run`")))
    if e in MACRO_DOCS:
        hits.append(Hit(HIGH, path, f"macro-enabled Office file (.{e})"))
    if e in MOTW_BYPASS and media_context:
        hits.append(Hit(HIGH, path, f".{e} disk image: mounting it strips the internet mark from "
                                    "everything inside"))
    if e in RISKY_MEDIA:
        hits.append(Hit(WARN, path, f".{e}: classic 'download this codec/licence' lure format"))
    if e in WIN_EXEC and _BAIT.search(base):          # the lures are Windows payloads
        hits.append(Hit(HIGH, path, "executable with a bait name (codec/crack/keygen/setup/…)"))
    if e in ("txt", "nfo", "") and re.search(r"(?i)pass(word)?|pwd", base):
        hits.append(Hit(WARN, path, "password file: an encrypted archive + its password is how "
                                    "droppers hide from antivirus"))
    return hits


# ---- header sniffing ------------------------------------------------------ #
_MAGIC = [
    (b"MZ", "Windows executable (PE)"),
    (b"\x7fELF", "Linux executable (ELF)"),
    (b"#!", "script with a shebang"),
    (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
    (b"\xcf\xfa\xed\xfe", "Mach-O executable"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (.lnk)"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file (old Office/MSI)"),
]


def sniff(head: bytes) -> str:
    for magic, label in _MAGIC:
        if head.startswith(magic):
            return label
    return ""


def judge_header(path: str, head: bytes) -> list[Hit]:
    """A file whose bytes say "program" while its name says anything else."""
    kind = sniff(head)
    if not kind or kind.startswith("OLE"):
        return []
    e = ext(path)
    if e in EXEC:
        return []
    if not e:
        # extension-less ELF/scripts are how Linux ships programs; a bare PE is odd
        return [Hit(HIGH, path, f"no extension, but the bytes are a {kind}")] \
            if kind.startswith(("Windows", "Mach-O")) else []
    if kind.startswith("script") and e not in MEDIA | DOCS | ARCHIVES:
        return []
    return [Hit(CRIT, path, f"named .{e} but the bytes are a {kind}")]


_RELEASE = re.compile(r"(?i)\b(\d{3,4}p|[xh]\.?26[45]|hevc|av1|blu-?ray|bdrip|brrip|web-?dl|"
                      r"web-?rip|hdtv|dvdrip|remux|s\d{1,2}e\d{1,3}|flac|mp3|320kbps|aac|"
                      r"epub|audiobook)\b")


def safe(s: str) -> str:
    """Printable form of an untrusted string: every control/format character
    (C0, C1, bidi overrides, zero-widths — Unicode categories Cc and Cf) shown
    as <U+XXXX>, so a name can't reorder, hide or forge the line it's printed on."""
    return "".join(f"<U+{ord(c):04X}>" if unicodedata.category(c) in ("Cc", "Cf") else c
                   for c in s)


def media_context(names_sizes: list[tuple[str, int]], title: str = "") -> bool:
    """True when the release name says film/series/music/book, or most of the
    payload (by size) is media or documents."""
    if title and _RELEASE.search(title):
        return True
    total = sum(s for _, s in names_sizes) or 1
    media = sum(s for n, s in names_sizes if ext(n) in MEDIA | DOCS)
    return media / total >= 0.6


def worst(hits: list[Hit]) -> str:
    return max((h.level for h in hits), key=RANK.get, default="")
