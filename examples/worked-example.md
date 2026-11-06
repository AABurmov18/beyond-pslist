# Worked example (fully synthetic)

> **Everything here is fabricated for teaching.** The sample name, host, IPs, wallet, token, domains
> and family labels below are invented and defanged. They do **not** correspond to any real case,
> host, or indicator. No forensic data is included in this repository.

This walks the exact shape of a real investigation without any real data. Build the synthetic dumps
first:

```bash
python examples/make_synthetic.py      # -> examples/out/{target,baseline,carved_region}.bin
```

## 1. The naïve read (what fools people)

A grep over `target.bin` turns up a ransom note, a crypto wallet, a Telegram token, a C2 URL and a
`Ransom:Win64/...` family name. The tempting story: *"this host has ransomware with crypto and
Telegram C2."* That story is wrong — and here is how the tools show it.

## 2. Read what the hits sit next to

```bash
bps context examples/out/target.bin "README_RECOVER"
```
Expected: the ransom-note string is rendered **next to `Ransom:Win64/Demoware.A!MTB`** and flagged
`ASCII+UTF-16 pairing`. That's a Defender definition record — the antivirus's *name* for a threat —
not a payload. Verdict: **RESIDUE**.

## 3. Is the "payload region" even real?

```bash
bps zcheck examples/out/carved_region.bin
```
Expected: `nonzero=0.00%  MZ@0=False  markers: none  verdict: NO payload evidence`. A region that is
entirely zero cannot be the payload anyone claims it is.

## 4. Subtract a clean baseline and score everything

```bash
bps sift examples/out/target.bin examples/out/baseline.bin
```
Expected (abridged):

```
... IOC-looking strings examined | N RESIDUE | 1 CANDIDATE (candidate != confirmed malicious)
------------------------------------------------------------------------
[RESIDUE  ]  btc              bc1qsyntheticexampleaddressnotrealxxxxxxyyyy
              - present in clean baseline
[RESIDUE  ]  telegram_token   1111111111:AAFakeSyntheticTokenDoNotUseThisXXyy
              - present in clean baseline
[RESIDUE  ]  url              http://198.51.100.77/relay/
              - av-markers: TrojanDownloader:O97M/, !MTB
[RESIDUE  ]  ipv4             198.51.100.77
              - av-markers: !MTB
[CANDIDATE]! ipv4             10.20.30.9
```

- The wallet and token are **RESIDUE** because they also appear in a process that can't be infected
  (the baseline) — the positive subtraction test.
- The C2 URL / IP are **RESIDUE** because they sit next to Defender signature labels.
- The bare `10.20.30.9` is **CANDIDATE**: nothing marks it as a signature, so it earns a closer look
  — which is *not* the same as "confirmed malicious". In a real case this is where you'd pivot
  (netscan, VAD privacy, who it talks to) before writing anything down.

## 5. The lesson

Eleven scary strings collapsed to signature residue; one survived as "look closer". That ratio is
the whole point. Had we trusted the naïve grep, we'd have reported a ransomware/crypto/Telegram
infection that the image never actually contained.
