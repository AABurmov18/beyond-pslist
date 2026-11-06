"""Print the bytes around a hit.

The single most useful habit in this toolkit: never attribute a string without reading
what it sits next to. A ransom note bracketed by `Ransom:Win64/...!MTB` is a signature,
not a payload. `context` renders a neighbourhood with non-printables dotted so those
labels jump out.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .markers import find_av_markers, is_utf16_paired


@dataclass(frozen=True)
class Hit:
    offset: int
    rendered: str
    av_markers: list[str]
    utf16_paired: bool


def _render(chunk: bytes) -> str:
    text = re.sub(rb"[^\x20-\x7e]", b".", chunk).decode("ascii", "replace")
    return re.sub(r"\.{4,}", " ... ", text)  # collapse long runs of non-printables


def find(data: bytes, needle: bytes, before: int = 160, after: int = 160,
         max_hits: int = 5) -> list[Hit]:
    """Return up to `max_hits` neighbourhoods around `needle` in `data`."""
    out: list[Hit] = []
    i = data.find(needle)
    while i != -1 and len(out) < max_hits:
        lo, hi = max(0, i - before), min(len(data), i + len(needle) + after)
        out.append(Hit(
            offset=i,
            rendered=_render(data[lo:hi]),
            av_markers=find_av_markers(data[lo:hi]),
            utf16_paired=is_utf16_paired(data, i, needle),
        ))
        i = data.find(needle, i + 1)
    return out


def find_in_file(path: str, needle: bytes, before: int = 160, after: int = 160,
                 max_hits: int = 5) -> list[Hit]:
    import mmap
    with open(path, "rb") as fh:
        try:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            return find(fh.read(), needle, before, after, max_hits)
        try:
            return find(mm[:], needle, before, after, max_hits)
        finally:
            mm.close()
