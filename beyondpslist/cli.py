"""Command-line entry point: `bps <subcommand>`.

Subcommands:
    strings   offline ASCII + UTF-16LE extraction (with offsets)
    context   print the bytes around a hit (surfaces AV signature labels)
    zcheck    is a carved region a real payload?
    sift      baseline-subtract two dumps and score survivors residue vs candidate
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from . import context as _context
from . import zcheck as _zcheck
from .sift import sift
from .strings import iter_strings


def _cmd_strings(a: argparse.Namespace) -> int:
    for s in iter_strings(a.file, min_len=a.min, mode=a.mode):
        print(s)
    return 0


def _cmd_context(a: argparse.Namespace) -> int:
    needle = a.needle.encode("latin-1")
    hits = _context.find_in_file(a.file, needle, before=a.before, after=a.after, max_hits=a.max)
    if not hits:
        print(f"'{a.needle}' not found in {a.file}")
        return 1
    for h in hits:
        flags = []
        if h.av_markers:
            flags.append("AV-MARKERS: " + ", ".join(h.av_markers[:6]))
        if h.utf16_paired:
            flags.append("ASCII+UTF-16 pairing")
        tag = "  [RESIDUE: " + "; ".join(flags) + "]" if flags else "  [no signature markers nearby]"
        print(f"@0x{h.offset:x}{tag}\n  {h.rendered}\n")
    return 0


def _cmd_zcheck(a: argparse.Namespace) -> int:
    print(_zcheck.check_file(a.file).summary())
    return 0


def _cmd_sift(a: argparse.Namespace) -> int:
    kws = [k for k in (a.keywords.split(",") if a.keywords else []) if k]
    res = sift(a.target, a.baseline, min_len=a.min, window=a.window, keywords=kws)
    print(res.summary())
    print("-" * 72)
    for f in res.findings:
        mark = "!" if f.verdict == "CANDIDATE" else " "
        print(f"[{f.verdict:9}]{mark} {f.ioc_type:16} {f.text}")
        for r in f.reasons:
            print(f"              - {r}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bps",
        description="beyond-pslist: tell antivirus-signature residue from a real payload.",
    )
    p.add_argument("--version", action="version", version=f"beyond-pslist {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("strings", help="offline ASCII + UTF-16LE extraction with offsets")
    s.add_argument("file")
    s.add_argument("--min", type=int, default=6, help="minimum string length (default 6)")
    s.add_argument("--mode", choices=["ascii", "utf16", "both"], default="both")
    s.set_defaults(func=_cmd_strings)

    c = sub.add_parser("context", help="print the bytes around a hit")
    c.add_argument("file")
    c.add_argument("needle")
    c.add_argument("--before", type=int, default=160)
    c.add_argument("--after", type=int, default=160)
    c.add_argument("--max", type=int, default=5)
    c.set_defaults(func=_cmd_context)

    z = sub.add_parser("zcheck", help="is a carved region a real payload?")
    z.add_argument("file")
    z.set_defaults(func=_cmd_zcheck)

    v = sub.add_parser("sift", help="baseline-subtract two dumps and score survivors")
    v.add_argument("target", help="the dump under examination")
    v.add_argument("baseline", help="a clean dump (e.g. dwm.exe) that cannot be infected")
    v.add_argument("--min", type=int, default=6)
    v.add_argument("--window", type=int, default=400, help="bytes of context to scan for markers")
    v.add_argument("--keywords", default="", help="extra comma-separated strings to test")
    v.set_defaults(func=_cmd_sift)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
