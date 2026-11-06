#!/usr/bin/env python3
"""Generate small SYNTHETIC dumps for the quickstart and tests.

Every byte written here is fabricated for teaching. None of it corresponds to any real
case, host, sample, or indicator. The point is to reproduce the *shape* of the problem:
a 'target' dump whose scary strings are mostly antivirus-signature residue, a 'clean'
baseline that shares some of them, and a carved region that is empty.

Run:  python examples/make_synthetic.py   ->  writes examples/out/{target,baseline,carved_region}.bin
"""

from __future__ import annotations

import os

OUT = os.path.join(os.path.dirname(__file__), "out")

# --- fabricated, defanged placeholders (NOT real indicators) -----------------------
FAMILY = b"Ransom:Win64/Demoware.A!MTB"
WALLET = b"bc1qsyntheticexampleaddressnotrealxxxxxxyyyy"
TOKEN = b"1111111111:AAFakeSyntheticTokenDoNotUseThisXXyy"
RESIDUE_URL = b"http://198.51.100.77/relay/"          # RFC5737 doc IP, next to AV markers
CANDIDATE_IP = b"10.20.30.9"                           # bare IP, away from any marker

# Synthetic scenario the fuller walkthrough uses (a USB-delivered reverse shell that is
# then driven interactively). The listener is the SAME host as the surviving candidate IP
# above, so the one string that passes scoring ties back to the one live socket.
HOST = "DESK-SYNTH-02"
SAMPLE = "freebonus.exe"
USB_SERIAL = "USB-SN-0000SYNTH1234"
VICTIM_IP = "10.20.30.40"
LISTENER = "10.20.30.9:9001"                           # == CANDIDATE_IP, deliberately


def _pair(s: bytes) -> bytes:
    """ASCII string immediately followed by its UTF-16LE copy (the .vdm fingerprint)."""
    return s + b" " + s.decode("latin-1").encode("utf-16-le") + b" "


def build_target() -> bytes:
    b = bytearray()
    b += b"\x00" * 64
    # A CANDIDATE: a bare IP in benign text, deliberately >400 bytes from any AV marker.
    b += b"session log: client connected from " + CANDIDATE_IP + b" during lab setup\n"
    b += b" " * 600
    # A Defender .vdm-style signature record: labels + dual-encoded strings + record markers.
    b += b"VirTool:MSIL/Filler "
    b += FAMILY + b" "
    b += _pair(b"All of your files are encrypted")
    b += _pair(b"README_RECOVER.txt")
    b += b"#ATTR_0003a1b2 MHSTR:Demoware.A!MTB "
    b += b"TrojanDownloader:O97M/Example.B!MTB "
    b += RESIDUE_URL + b" "
    b += WALLET + b" "
    b += TOKEN + b" "
    b += b"!MTB trailing filler "
    b += b"\x00" * 64
    return bytes(b)


def build_baseline() -> bytes:
    # A 'clean' process (think dwm.exe) that still carries shared signature residue.
    b = bytearray()
    b += b"synthetic clean baseline (dwm-like)\n"
    b += FAMILY + b" "
    b += WALLET + b" "
    b += TOKEN + b" "
    b += b" filler " * 20
    return bytes(b)


def build_carved() -> bytes:
    # A carved 'private RWX' region that is paged out / empty: all zero, no payload.
    return b"\x00" * 4096


def build_timeline_csv() -> str:
    # columns: timestamp,source,detail. Note the ~7 minute gap between the parent
    # starting (09:12:31) and its children appearing (09:19:xx) -> interactive use.
    rows = [
        ("timestamp", "source", "detail"),
        ("2025-01-01 09:12:03", "SymlinkScan",
         f"USB mass storage {USB_SERIAL} mounted as HarddiskVolume7 (D:)"),
        ("2025-01-01 09:12:31", "PsList",
         f"{SAMPLE} (pid 4821) started by explorer.exe (pid 1320)"),
        ("2025-01-01 09:12:31", "NetScan",
         f"TCP {VICTIM_IP}:50122 -> {LISTENER} ESTABLISHED (pid 4821)"),
        ("2025-01-01 09:19:47", "PsList",
         f"cmd.exe (pid 5133) started by {SAMPLE} (pid 4821)"),
        ("2025-01-01 09:19:52", "PsList",
         f"notepad.exe (pid 5160) started by {SAMPLE} (pid 4821)"),
        ("2025-01-01 09:22:10", "Acquisition", "memory capture started"),
    ]
    return "\n".join(",".join(f'"{c}"' for c in r) for r in rows) + "\n"


def build_netscan_txt() -> str:
    # A tiny synthetic netscan-like listing: exactly one live malicious socket.
    return (
        "Proto  LocalAddr           ForeignAddr          State        PID   Owner\n"
        f"TCPv4  {VICTIM_IP}:50122   {LISTENER}   ESTABLISHED  4821  {SAMPLE}\n"
        f"TCPv4  {VICTIM_IP}:139     0.0.0.0:0            LISTENING    4     System\n"
    )


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    for name, data in (
        ("target.bin", build_target()),
        ("baseline.bin", build_baseline()),
        ("carved_region.bin", build_carved()),
    ):
        with open(os.path.join(OUT, name), "wb") as fh:
            fh.write(data)
        print(f"wrote {os.path.join(OUT, name)} ({len(data)} bytes)")

    for name, text in (
        ("timeline_events.csv", build_timeline_csv()),
        ("netscan.txt", build_netscan_txt()),
    ):
        with open(os.path.join(OUT, name), "w", encoding="ascii", newline="\n") as fh:
            fh.write(text)
        print(f"wrote {os.path.join(OUT, name)} ({len(text)} bytes)")


if __name__ == "__main__":
    main()
