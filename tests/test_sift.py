from beyondpslist.sift import sift

FAMILY = b"Ransom:Win64/Demoware.A!MTB"
WALLET = b"bc1qsyntheticexampleaddressnotrealxxxxxxyyyy"


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_sift_classifies_residue_and_candidate(tmp_path):
    target = (
        b"\x00" * 32
        + b"benign note: peer 10.20.30.9 seen during setup\n"
        + b" " * 600                      # keep the candidate IP far from any AV marker
        + FAMILY + b" " + WALLET + b" !MTB trailing"
        + b"\x00" * 16
    )
    baseline = b"clean dwm-like baseline " + WALLET + b" filler filler filler"

    t = _write(tmp_path, "target.bin", target)
    b = _write(tmp_path, "baseline.bin", baseline)
    res = sift(t, b)

    by_text = {f.text: f for f in res.findings}

    # wallet appears in the clean baseline -> residue by subtraction
    assert by_text[WALLET.decode()].verdict == "RESIDUE"

    # the bare operator IP is far from any marker and not in the baseline -> candidate
    assert by_text["10.20.30.9"].verdict == "CANDIDATE"

    assert res.residue and res.candidates
