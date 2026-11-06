from beyondpslist.strings import iter_strings_bytes


def test_ascii_and_utf16_extraction():
    # separate the regions with 0xff so the UTF-16 run can't swallow a trailing ASCII char
    data = b"\x00\x00HELLOASCII\xff" + b"W\x00I\x00D\x00E\x001\x006\x00" + b"\xff"
    found = {(s.encoding, s.text) for s in iter_strings_bytes(data, min_len=6, mode="both")}
    assert ("ascii", "HELLOASCII") in found
    assert ("utf16", "WIDE16") in found


def test_min_length_filters_short_runs():
    data = b"ab\x00cd\x00LONGENOUGH"
    texts = {s.text for s in iter_strings_bytes(data, min_len=6, mode="ascii")}
    assert "LONGENOUGH" in texts
    assert "ab" not in texts


def test_offsets_are_reported():
    data = b"####TARGETSTRING####"
    hit = next(s for s in iter_strings_bytes(data, min_len=6, mode="ascii")
               if "TARGETSTRING" in s.text)
    assert data[hit.offset:hit.offset + len("####TARGETSTRING####")].startswith(b"####")
