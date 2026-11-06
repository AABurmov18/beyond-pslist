from datetime import datetime

from beyondpslist.timeline import (
    build_timeline,
    from_lines,
    interactive_gaps,
    parse_rows,
    parse_timestamp,
    render_table,
)


def test_parse_timestamp_formats():
    assert parse_timestamp("2025-09-26 11:41:39.000000 UTC") == datetime(2025, 9, 26, 11, 41, 39)
    assert parse_timestamp("2025-09-26T11:41:39") == datetime(2025, 9, 26, 11, 41, 39)
    assert parse_timestamp("2025-09-26 11:41") == datetime(2025, 9, 26, 11, 41)
    assert parse_timestamp("N/A") is None
    assert parse_timestamp("") is None
    assert parse_timestamp("-") is None


def test_sort_and_dedup_with_header():
    lines = [
        "timestamp,source,detail",
        "2025-01-01 09:27:19 UTC,PsList,cmd created",
        "2025-01-01 09:20:11 UTC,PsList,sample created",
        "2025-01-01 09:20:11 UTC,PsList,sample created",   # duplicate
        "N/A,MftScan,note with no time",
    ]
    tl = build_timeline(parse_rows(lines))
    dated = [e for e in tl if e.ts]
    assert [e.detail for e in dated] == ["sample created", "cmd created"]   # chronological
    assert sum(1 for e in tl if e.detail == "sample created") == 1          # de-duplicated
    assert tl[-1].ts is None                                                # undated last


def test_interactive_gap_flagged():
    lines = [
        "2025-01-01 09:12:31 UTC,PsList,sample started",
        "2025-01-01 09:19:47 UTC,PsList,cmd started",
    ]
    tl = build_timeline(parse_rows(lines))
    gaps = interactive_gaps(tl, 5.0)
    assert len(gaps) == 1
    _, later, delta = gaps[0]
    assert later.detail == "cmd started"
    assert 7.0 <= delta <= 7.5          # 7m16s

    # small gaps are not flagged
    assert interactive_gaps(tl, 30.0) == []


def test_timeliner_style_tsv_row():
    # timestamp is not the first field (Volatility timeliner shape)
    line = "PsList\tProcess: 4821 freebonus.exe\t2025-01-01 09:12:31.000000 UTC"
    tl = from_lines([line])
    assert tl[0].ts == datetime(2025, 1, 1, 9, 12, 31)
    assert "freebonus" in tl[0].detail
    assert tl[0].source == "PsList"


def test_render_inline_gap_tag():
    lines = [
        "2025-01-01 09:12:31 UTC,PsList,sample started",
        "2025-01-01 09:19:47 UTC,PsList,cmd started",
    ]
    out = render_table(build_timeline(parse_rows(lines)), gap_minutes=5.0)
    assert "[+7m16s]" in out
    # disabling the flag removes the annotation
    assert "[+7m16s]" not in render_table(build_timeline(parse_rows(lines)), gap_minutes=0.0)
