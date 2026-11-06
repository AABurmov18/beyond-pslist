# Worked example (fully synthetic)

> **Everything here is fabricated for teaching.** The sample name, host, IPs, wallet, token, domains
> and family labels below are invented and defanged. They do **not** correspond to any real case,
> host, or indicator. No forensic data is included in this repository.

This is a full pass of the method on a synthetic scenario that has the same shape as a real one:
a USB-delivered reverse shell that is then driven interactively, sitting inside a large amount of
antivirus-signature noise. The job is not just to clear noise. It is to run the method end to end
and come out with real results and a timeline.

Build the synthetic inputs first:

```bash
python examples/make_synthetic.py
# writes examples/out/{target,baseline,carved_region}.bin, timeline_events.csv, netscan.txt
```

The scenario in one line: host `DESK-SYNTH-02`, a sample `freebonus.exe` (pid 4821) run from a USB
stick, one live connection to `10.20.30.9:9001`, and two child processes that appear about seven
minutes later.

## 1. Triage and backbone

Start where everyone starts, then distrust it. The process tree shows `freebonus.exe` (pid 4821)
launched by `explorer.exe`, later spawning `cmd.exe` and `notepad.exe`. One connection is live:

```bash
cat examples/out/netscan.txt
```
```
TCPv4  10.20.30.40:50122   10.20.30.9:9001   ESTABLISHED  4821  freebonus.exe
```

That single ESTABLISHED socket is a real artifact: a kernel structure, not a string someone could
have scanned into memory. Mark it **LIVE** and keep going. The process list named the anomaly; it
has not told you how bad things are, or how benign.

## 2. The climb

Each deeper plugin shows something the process list cannot (see `docs/CHEATSHEET.md`). The trap at
every step is reading a benign artifact as an attack. For carved regions, the question is blunt:

```bash
bps zcheck examples/out/carved_region.bin
```
```
size=4096  nonzero=0.00%  MZ@0=False
markers: none
verdict: NO payload evidence (paged/zeroed or data-only)
```

A region that is entirely zero, with no PE or toolchain markers, is not the payload anyone claims
it is. It is paged out or empty. No amount of scary VAD flags changes that.

## 3. Remove the noise

A grep over `target.bin` turns up a ransom note, a crypto wallet, a Telegram token, a C2 URL and a
`Ransom:Win64/...` family name. The tempting story is "ransomware with crypto and Telegram C2". It
is wrong. Read what each hit sits next to:

```bash
bps context examples/out/target.bin "README_RECOVER"
```
The ransom note renders next to `Ransom:Win64/Demoware.A!MTB` and is flagged `ASCII+UTF-16 pairing`.
That is a Defender definition record, the antivirus's name for a threat, not a payload. Now score
everything against a process that cannot be infected:

```bash
bps sift examples/out/target.bin examples/out/baseline.bin
```
```
5 IOC-looking strings examined | 4 RESIDUE | 1 CANDIDATE (candidate != confirmed malicious -- verify by hand)
------------------------------------------------------------------------
[CANDIDATE]! ipv4             10.20.30.9
[RESIDUE  ]  btc              bc1qsyntheticexampleaddressnotrealxxxxxxyyyy
              - present in clean baseline
[RESIDUE  ]  ipv4             198.51.100.77
              - av-markers: !MTB, #ATTR_0003a1b2, MHSTR:, Ransom:Win64/, TrojanDownloader:O97M/
[RESIDUE  ]  telegram_token   1111111111:AAFakeSyntheticTokenDoNotUseThisXXyy
              - present in clean baseline
[RESIDUE  ]  url              http://198.51.100.77/relay/
              - av-markers: !MTB, Ransom:Win64/, TrojanDownloader:O97M/
```

The wallet and token are **RESIDUE** because they also appear in a process that cannot be infected
(the positive subtraction test). The URL and its IP are **RESIDUE** because they sit inside a
Defender signature record. Four scary indicators, zero evidence of a resident payload.

## 4. Confirm the real evidence

One indicator survives: `10.20.30.9`. Nothing marks it as a signature, and it is not in the clean
baseline. That is a **CANDIDATE**, which means look closer, not "confirmed bad". So look closer, and
it lines up with the one thing from Station 1 that was never in doubt:

```
netscan:  10.20.30.40:50122 -> 10.20.30.9:9001  ESTABLISHED  (freebonus.exe)
sift:     10.20.30.9  CANDIDATE
```

The surviving string is the same host as the only live socket. That convergence, a real kernel
connection plus a string that passes the provenance test, is your signal. Everything else was noise.

## 5. Build the timeline

Results are not findings until they sit on a clock. Feed the collected events in:

```bash
bps timeline examples/out/timeline_events.csv
```
Expected shape:
```
2025-01-01 09:12:03  SymlinkScan  USB mass storage USB-SN-0000SYNTH1234 mounted as HarddiskVolume7 (D:)
2025-01-01 09:12:31  PsList       freebonus.exe (pid 4821) started by explorer.exe (pid 1320)
2025-01-01 09:12:31  NetScan      TCP 10.20.30.40:50122 -> 10.20.30.9:9001 ESTABLISHED (pid 4821)
2025-01-01 09:19:47  PsList       cmd.exe (pid 5133) started by freebonus.exe (pid 4821)   [+7m16s]
2025-01-01 09:19:52  PsList       notepad.exe (pid 5160) started by freebonus.exe (pid 4821)
2025-01-01 09:22:10  Acquisition  memory capture started
```

The shape tells the story. The USB mounts, the sample runs and connects out in the same second
(automated start), and then nothing for about seven minutes, until `cmd.exe` and `notepad.exe`
appear. An automated dropper spawns its children immediately. A seven minute gap is the fingerprint
of a human on the other end of the shell, typing. That gap is a finding on its own.

## 6. The report in one paragraph

On `DESK-SYNTH-02`, `freebonus.exe` (pid 4821) was launched from USB `USB-SN-0000SYNTH1234` and
opened a reverse shell to `10.20.30.9:9001`, the single **LIVE** channel in the image. About seven
minutes later the shell was used interactively to spawn `cmd.exe` and `notepad.exe`, which is
hands-on-keyboard activity rather than an automated payload. The ransomware family name, crypto
wallet, Telegram token and C2 URL are **RESIDUE** (antivirus signature content and shared noise)
and are not treated as indicators. No resident payload was recoverable. The image cannot show who
operated `10.20.30.9` or what was typed through the shell, so those stay open questions rather than
claims. See `docs/REPORTING.md` for the template this follows.

## What people take away

The point is not "strings are noise". It is a repeatable method: triage, climb, strip noise by
provenance, confirm the artifacts that survive, and put them on a timeline. In this synthetic image
eleven scary strings collapsed to residue and one survived, and that one lined up with a real socket
and a seven minute interactive gap. That is the difference between a grep and an investigation.
