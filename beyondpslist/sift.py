"""vdm-sift: the two-part discipline, automated.

Given a TARGET dump and a CLEAN BASELINE dump (e.g. a process that cannot be infected,
such as dwm.exe), sift:

  1. finds IOC-looking strings in the target (IPs, URLs, wallets, tokens, webhooks);
  2. SUBTRACTS the baseline -- anything also present in a clean process is shared residue
     (this is a valid POSITIVE residue test);
  3. for each survivor, reads the surrounding bytes and scores it RESIDUE vs CANDIDATE by
     antivirus-signature-marker adjacency and ASCII+UTF-16 pairing.

Why both steps: a signature database is compressed and only partly resident, so a string
being unique to the target and absent from one baseline does NOT make it genuine. The
baseline subtraction finds residue; it must never *promote* a survivor to 'real'. Only
the bytes around a hit can do that. Step 3 is that guardrail.

A CANDIDATE verdict means 'nothing here marks it as a signature' -- a prompt to look
closer, not a confirmation of malice.
"""

from __future__ import annotations

import mmap
from dataclasses import dataclass, field

from .markers import IOC_PATTERNS, classify


@dataclass
class Finding:
    ioc_type: str
    text: str
    offset: int
    in_baseline: bool
    verdict: str                 # RESIDUE | CANDIDATE
    reasons: list[str] = field(default_factory=list)


@dataclass
class SiftResult:
    findings: list[Finding]

    @property
    def residue(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict == "RESIDUE"]

    @property
    def candidates(self) -> list[Finding]:
        return [f for f in self.findings if f.verdict == "CANDIDATE"]

    def summary(self) -> str:
        n = len(self.findings)
        return (f"{n} IOC-looking strings examined | "
                f"{len(self.residue)} RESIDUE | {len(self.candidates)} CANDIDATE "
                f"(candidate != confirmed malicious -- verify by hand)")


def _collect_iocs(data: bytes, keywords: list[bytes]) -> list[tuple[str, bytes, int]]:
    out: list[tuple[str, bytes, int]] = []
    for name, pat in IOC_PATTERNS.items():
        for m in pat.finditer(data):
            out.append((name, m.group(0), m.start()))
    for kw in keywords:
        start = data.find(kw)
        while start != -1:
            out.append(("keyword", kw, start))
            start = data.find(kw, start + 1)
    return out


def _read(path: str) -> bytes:
    with open(path, "rb") as fh:
        try:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            return fh.read()
        try:
            return mm[:]
        finally:
            mm.close()


def sift(target_path: str, baseline_path: str, min_len: int = 6,
         window: int = 400, keywords: list[str] | None = None) -> SiftResult:
    baseline = _read(baseline_path)      # substring test: does the indicator appear at all?
    data = _read(target_path)
    kw_bytes = [k.encode("latin-1") for k in (keywords or [])]

    seen: set[tuple[str, str]] = set()
    findings: list[Finding] = []
    for ioc_type, raw, off in _collect_iocs(data, kw_bytes):
        text = raw.decode("latin-1", "replace")
        key = (ioc_type, text)
        if key in seen:
            continue
        seen.add(key)
        in_base = raw in baseline
        verdict, reasons = classify(data, off, raw, window=window)
        if in_base:
            verdict = "RESIDUE"
            reasons = ["present in clean baseline"] + reasons
        findings.append(Finding(ioc_type, text, off, in_base, verdict, reasons))

    findings.sort(key=lambda f: (f.verdict != "CANDIDATE", f.ioc_type, f.text))
    return SiftResult(findings)
