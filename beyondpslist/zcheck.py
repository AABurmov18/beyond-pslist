"""Is a carved region actually a payload?

When a private RWX allocation or a 'suspicious' region turns up, the first questions are
dull but decisive: how much of it is even resident, and does it contain the markers of a
real executable or script? A region that is 99% zero, with no PE header and no toolchain
strings, cannot be the payload someone claims it is -- it is paged out or never written.
"""

from __future__ import annotations

from dataclasses import dataclass

# Toolchain / format markers that a genuine payload region tends to carry.
_MARKERS: dict[str, bytes] = {
    "mz_header": b"MZ",
    "pe_header": b"PE\x00\x00",
    "dos_stub": b"This program cannot be run in DOS mode",
    "go_buildid": b"Go build ID",
    "go_runtime": b"runtime.",
    "go_path": b"/usr/local/go",
    "rich_header": b"Rich",
    "upx": b"UPX!",
    "dotnet": b"_CorExeMain",
    "text_section": b".text",
    "rdata_section": b".rdata",
}


@dataclass(frozen=True)
class ZReport:
    size: int
    nonzero_ratio: float
    mz_at_start: bool
    markers: dict[str, int]

    @property
    def looks_like_payload(self) -> bool:
        return self.mz_at_start or any(
            self.markers[k] for k in ("pe_header", "dos_stub", "go_buildid", "go_runtime")
        )

    def summary(self) -> str:
        found = ", ".join(f"{k}={v}" for k, v in self.markers.items() if v) or "none"
        return (
            f"size={self.size}  nonzero={self.nonzero_ratio:.2%}  MZ@0={self.mz_at_start}\n"
            f"markers: {found}\n"
            f"verdict: {'POSSIBLE payload region' if self.looks_like_payload else 'NO payload evidence (paged/zeroed or data-only)'}"
        )


def check(data: bytes) -> ZReport:
    size = len(data)
    nonzero = sum(1 for b in data if b) if size else 0
    markers = {name: data.count(sig) for name, sig in _MARKERS.items()}
    return ZReport(
        size=size,
        nonzero_ratio=(nonzero / size) if size else 0.0,
        mz_at_start=data[:2] == b"MZ",
        markers=markers,
    )


def check_file(path: str) -> ZReport:
    with open(path, "rb") as fh:
        return check(fh.read())
