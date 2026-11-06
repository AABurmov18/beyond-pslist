"""Merge normalized event rows into one chronological timeline.

Memory forensics is only half done when you have found the artifacts; the other half is putting
them in order. Process create times, network connections, file MACB timestamps, registry
LastWrite times and the supertimeline all carry time, in different plugins and different formats.
This module ingests a simple ``timestamp,source,detail`` feed (CSV or TSV, with a header or
without, and tolerant of Volatility ``timeliner`` style lines), sorts it, de-duplicates it, and
flags quiet gaps that often mark interactive, hands-on-keyboard activity.

Work in UTC. Sanity-check absurd dates: a load time in the year 1601 is timestomping, not history.
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Optional

_TS_TOKEN = re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?")
_EMPTY = {"", "-", "n/a", "none", "null"}
_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M",
)


@dataclass(frozen=True)
class Event:
    ts: Optional[datetime]
    raw_ts: str
    source: str
    detail: str


def parse_timestamp(value: str) -> Optional[datetime]:
    """Parse an ISO-ish timestamp, tolerating a trailing ' UTC'/'Z' and surrounding text.

    Returns None for blank, '-', 'N/A', or anything without a recognisable date-time token.
    """
    if value is None:
        return None
    s = value.strip()
    if s.lower() in _EMPTY:
        return None
    m = _TS_TOKEN.search(s)
    if not m:
        return None
    token = m.group(0)
    for fmt in _FORMATS:
        try:
            return datetime.strptime(token, fmt)
        except ValueError:
            continue
    return None


def _split(line: str) -> list[str]:
    line = line.rstrip("\r\n")
    if "\t" in line:
        return line.split("\t")
    return next(csv.reader([line]))


def _find_ts_index(fields: list[str]) -> Optional[int]:
    for i, f in enumerate(fields):
        if parse_timestamp(f) is not None:
            return i
    return None


def _join(parts: Iterable[str]) -> str:
    return " ".join(p.strip() for p in parts if p and p.strip())


def _row_to_event(fields: list[str], header: Optional[dict[str, int]]) -> Event:
    if header:
        def get(name: str) -> str:
            idx = header.get(name)
            return fields[idx] if idx is not None and idx < len(fields) else ""
        raw_ts = get("timestamp")
        source = get("source") or "event"
        detail = get("detail")
        if not detail:
            used = set(header.values())
            detail = _join(f for i, f in enumerate(fields) if i not in used)
    elif fields and parse_timestamp(fields[0]) is not None:
        # default shape: timestamp, source, detail...
        raw_ts = fields[0]
        source = fields[1] if len(fields) > 1 else "event"
        detail = _join(fields[2:]) if len(fields) > 2 else ""
    else:
        # timeliner style: the timestamp sits somewhere other than column 0
        idx = _find_ts_index(fields)
        if idx is None:
            raw_ts = ""
            source = fields[0] if fields else "event"
            detail = _join(fields[1:])
        else:
            raw_ts = fields[idx]
            rest = [f for i, f in enumerate(fields) if i != idx]
            source = rest[0] if rest else "event"
            detail = _join(rest[1:])
    return Event(parse_timestamp(raw_ts), raw_ts.strip(), source.strip() or "event", detail.strip())


def parse_rows(lines: Iterable[str]) -> list[Event]:
    """Parse a CSV/TSV feed into Events. A header row naming 'timestamp' is honoured."""
    events: list[Event] = []
    header: Optional[dict[str, int]] = None
    for raw in lines:
        if not raw or not raw.strip():
            continue
        fields = _split(raw)
        low = [f.strip().lower() for f in fields]
        if header is None and "timestamp" in low:
            header = {name: low.index(name) for name in ("timestamp", "source", "detail") if name in low}
            continue
        events.append(_row_to_event(fields, header))
    return events


def build_timeline(events: Iterable[Event]) -> list[Event]:
    """De-duplicate and sort: dated events chronologically, undated events last."""
    seen: set[tuple] = set()
    unique: list[Event] = []
    for e in events:
        key = (e.ts.isoformat() if e.ts else None, e.source, e.detail)
        if key in seen:
            continue
        seen.add(key)
        unique.append(e)
    dated = sorted((e for e in unique if e.ts), key=lambda e: e.ts)
    undated = [e for e in unique if not e.ts]
    return dated + undated


def from_lines(lines: Iterable[str]) -> list[Event]:
    return build_timeline(parse_rows(lines))


def interactive_gaps(events: list[Event], gap_minutes: float) -> list[tuple[Event, Event, float]]:
    """Return (earlier, later, delta_minutes) for consecutive dated events at least gap_minutes apart.

    A quiet stretch followed by fresh process activity (a child spawned minutes after its parent)
    is the classic fingerprint of a human driving a shell rather than an automated dropper.
    """
    dated = [e for e in events if e.ts]
    out: list[tuple[Event, Event, float]] = []
    for a, b in zip(dated, dated[1:]):
        delta = (b.ts - a.ts).total_seconds() / 60.0
        if delta >= gap_minutes:
            out.append((a, b, delta))
    return out


def _fmt_delta(minutes: float) -> str:
    total = int(round(minutes * 60))
    if total >= 86400:
        return f"+{total // 86400}d"
    m, s = divmod(total, 60)
    if m >= 60:
        h, m = divmod(m, 60)
        return f"+{h}h{m}m"
    return f"+{m}m{s}s"


def render_table(events: list[Event], gap_minutes: float = 0.0) -> str:
    """Render an aligned timeline table.

    If gap_minutes > 0, any dated event that follows a quiet stretch of at least gap_minutes
    is annotated inline with the gap (for example ``[+7m16s]``), the hands-on-keyboard hint.
    """
    gap_tag: dict[int, str] = {}
    if gap_minutes > 0:
        for a, b, delta in interactive_gaps(events, gap_minutes):
            gap_tag[id(b)] = _fmt_delta(delta)

    rows = [("TIME (UTC)", "SOURCE", "DETAIL")]
    tags = [None]
    for e in events:
        t = e.ts.strftime("%Y-%m-%d %H:%M:%S") if e.ts else "N/A"
        rows.append((t, e.source, e.detail))
        tags.append(gap_tag.get(id(e)))
    w0 = max(len(r[0]) for r in rows)
    w1 = max(len(r[1]) for r in rows)
    lines = []
    for r, tag in zip(rows, tags):
        line = f"{r[0]:<{w0}}  {r[1]:<{w1}}  {r[2]}"
        if tag:
            line += f"   [{tag}]"
        lines.append(line)
    return "\n".join(lines)
