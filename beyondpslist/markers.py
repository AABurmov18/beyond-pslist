"""Shared pattern library: IOC regexes and antivirus-signature marker patterns.

The core idea of this toolkit lives here. Two families of pattern:

1. IOC_PATTERNS   -- what an analyst greps a dump for (IPs, URLs, wallets, tokens...).
2. AV_MARKERS     -- what an antivirus *signature database* looks like in memory.

If an IOC-looking string sits next to an AV_MARKER (or is stored as an ASCII string
immediately followed by its UTF-16LE copy), it is almost certainly a detection
signature -- the AV's *name* for a threat -- not a resident payload. That single test
is what separates residue from evidence.

All patterns are byte patterns so they can run directly over a memory image.
"""

from __future__ import annotations

import re

# --- Indicators an analyst typically hunts for -------------------------------------
IOC_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "ipv4": re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "url": re.compile(rb"https?://[^\s\"'<>)\x00]{4,}"),
    "btc": re.compile(rb"\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "telegram_token": re.compile(rb"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"),
    "discord_webhook": re.compile(rb"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_.-]+"),
    "onion": re.compile(rb"\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b"),
    "email": re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
}

# --- What an AV signature database / AMSI scan buffer looks like in memory ----------
# These are generic, public Microsoft Defender naming conventions, not case data.
AV_MARKERS: list[re.Pattern[bytes]] = [
    re.compile(rb"![A-Za-z][A-Za-z0-9]{1,6}!(?:MTB|MSR|rfn|dha|dam|bit|ibt)"),  # ...Family.AB!MTB
    re.compile(rb"!(?:MTB|MSR|rfn|dha|dam)\b"),
    re.compile(rb"#ATTR_[0-9A-Fa-f]{6,}"),                 # VDM record attribute marker
    re.compile(rb"MHSTR:"),                                # "match HSTR" signature prefix
    re.compile(rb"!#(?:SCRIPT|ALF|SCPT):"),                # AMSI script-scan signature ids
    re.compile(rb"!MainPS\b"),
    re.compile(rb"\.[A-Z]{2,4}!(?:MTB|MSR|rfn)"),          # ...NWO!MTB style
    re.compile(
        rb"(?:Ransom|Trojan|TrojanDownloader|TrojanSpy|Backdoor|Worm|VirTool|HackTool|"
        rb"PWS|Behavior|Exploit|DDoS|Spammer):"
        rb"(?:Win32|Win64|MSIL|O97M|HTML|JS|VBS|PowerShell|Script|AndroidOS|Linux|MacOS|BAT|Python)/"
    ),
]

# Compact set of substrings handy for quick human eyeballing / grep.
AV_MARKER_HINTS: tuple[bytes, ...] = (
    b"!MTB", b"!MSR", b"!rfn", b"#ATTR_", b"MHSTR:", b"!#SCRIPT:", b"!#ALF:",
    b"!#SCPT:", b"!MainPS", b"Ransom:Win", b"Trojan:Win", b"TrojanDownloader:",
    b"Behavior:", b"VirTool:", b"HackTool:",
)


def find_av_markers(window: bytes) -> list[str]:
    """Return the distinct antivirus-signature markers present in a byte window."""
    hits: list[str] = []
    for pat in AV_MARKERS:
        for m in pat.finditer(window):
            tok = m.group(0).decode("latin-1", "replace")
            if tok not in hits:
                hits.append(tok)
    return hits


def is_utf16_paired(data: bytes, start: int, text: bytes) -> bool:
    """True if the ASCII string `text` at `start` is immediately followed (or preceded)
    by its UTF-16LE copy -- the dual-encoding fingerprint of a Defender .vdm record."""
    utf16 = text.decode("latin-1").encode("utf-16-le")
    after = data[start + len(text): start + len(text) + len(utf16) + 1]
    if utf16 in after:
        return True
    before = data[max(0, start - len(utf16) - 1): start]
    return utf16 in before


def classify(data: bytes, start: int, text: bytes, window: int = 400) -> tuple[str, list[str]]:
    """Classify a hit as RESIDUE / CANDIDATE given its neighbourhood.

    Returns (verdict, reasons). RESIDUE means it looks like AV signature content;
    CANDIDATE means nothing here marks it as a signature -- it warrants a closer look
    (which is NOT the same as 'confirmed malicious').
    """
    lo = max(0, start - window)
    hi = min(len(data), start + len(text) + window)
    neigh = data[lo:hi]
    reasons: list[str] = []
    markers = find_av_markers(neigh)
    if markers:
        reasons.append("av-markers: " + ", ".join(markers[:6]))
    if is_utf16_paired(data, start, text):
        reasons.append("ascii+utf16-le pairing (vdm encoding)")
    verdict = "RESIDUE" if reasons else "CANDIDATE"
    return verdict, reasons
