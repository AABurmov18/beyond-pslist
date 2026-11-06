from beyondpslist.markers import (
    IOC_PATTERNS,
    classify,
    find_av_markers,
    is_utf16_paired,
)

FAMILY = b"Ransom:Win64/Demoware.A!MTB"
WALLET = b"bc1qsyntheticexampleaddressnotrealxxxxxxyyyy"
TOKEN = b"1111111111:AAFakeSyntheticTokenDoNotUseThisXXyy"


def test_av_markers_detected():
    assert find_av_markers(b"xx " + FAMILY + b" yy")
    assert find_av_markers(b"....#ATTR_0003a1b2 MHSTR:Demoware.A!MTB....")
    assert find_av_markers(b"!#SCRIPT:PowerShell/Example!MainPS")
    assert find_av_markers(b"nothing to see here") == []


def test_utf16_pairing():
    s = b"README_RECOVER.txt"
    paired = s + s.decode("latin-1").encode("utf-16-le")
    assert is_utf16_paired(paired, 0, s) is True
    not_paired = s + b" just more ascii text follows here"
    assert is_utf16_paired(not_paired, 0, s) is False


def test_classify_residue_vs_candidate():
    residue = b"pad " + FAMILY + b" README_RECOVER.txt !MTB pad"
    off = residue.find(b"README_RECOVER.txt")
    verdict, reasons = classify(residue, off, b"README_RECOVER.txt", window=120)
    assert verdict == "RESIDUE" and reasons

    clean = b"a" * 500 + b"UNIQUE_LOOKALIKE_IOC" + b"b" * 500
    off2 = clean.find(b"UNIQUE_LOOKALIKE_IOC")
    verdict2, reasons2 = classify(clean, off2, b"UNIQUE_LOOKALIKE_IOC", window=400)
    assert verdict2 == "CANDIDATE" and not reasons2


def test_ioc_patterns_match_synthetic_values():
    assert IOC_PATTERNS["btc"].search(WALLET)
    assert IOC_PATTERNS["telegram_token"].search(TOKEN)
    assert IOC_PATTERNS["ipv4"].search(b"10.20.30.9")
    assert IOC_PATTERNS["url"].search(b"http://198.51.100.77/relay/")
    assert IOC_PATTERNS["discord_webhook"].search(b"discord.com/api/webhooks/123/abcDEF_-")
