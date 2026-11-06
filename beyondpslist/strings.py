"""Offline ASCII + UTF-16LE string extraction.

A deterministic, dependency-free stand-in for GNU `strings -a -n N [-e l]` that also
reports the byte offset of every hit (handy for feeding `context`/`sift`). Uses mmap so
it streams a multi-gigabyte image without loading it into RAM.
"""

from __future__ import annotations

import mmap
import re
from dataclasses import dataclass
from typing import Iterator

_ASCII = lambda n: re.compile(rb"[\x20-\x7e\t]{%d,}" % n)
_UTF16 = lambda n: re.compile(rb"(?:[\x20-\x7e\t]\x00){%d,}" % n)


@dataclass(frozen=True)
class Str:
    offset: int
    encoding: str  # "ascii" | "utf16"
    text: str

    def __str__(self) -> str:  # GNU-strings-ish, with offset
        return f"0x{self.offset:x}\t{self.encoding}\t{self.text}"


def _decode_utf16(raw: bytes) -> str:
    return raw.decode("utf-16-le", "replace")


def iter_strings(path: str, min_len: int = 6, mode: str = "both") -> Iterator[Str]:
    """Yield Str(offset, encoding, text) for a file on disk."""
    with open(path, "rb") as fh:
        try:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            data = fh.read()
            yield from iter_strings_bytes(data, min_len=min_len, mode=mode)
            return
        try:
            yield from iter_strings_bytes(mm, min_len=min_len, mode=mode)
        finally:
            mm.close()


def iter_strings_bytes(data, min_len: int = 6, mode: str = "both") -> Iterator[Str]:
    """Yield Str(...) from an in-memory buffer or mmap. Used by the tests and tools."""
    if mode in ("ascii", "both"):
        for m in _ASCII(min_len).finditer(data):
            yield Str(m.start(), "ascii", m.group(0).decode("latin-1"))
    if mode in ("utf16", "both"):
        for m in _UTF16(min_len).finditer(data):
            yield Str(m.start(), "utf16", _decode_utf16(m.group(0)))


def string_set(path: str, min_len: int = 6, mode: str = "both") -> set[str]:
    """Deduplicated set of string *texts* (for baseline subtraction)."""
    return {s.text for s in iter_strings(path, min_len=min_len, mode=mode)}
