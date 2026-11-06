# beyond-pslist

**Most of what looks like malware in a memory image is noise. The skill is separating it from the real evidence.**

[![CI](https://github.com/AABurmov18/beyond-pslist/actions/workflows/ci.yml/badge.svg)](https://github.com/AABurmov18/beyond-pslist/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![os](https://img.shields.io/badge/os-Windows%20%7C%20macOS%20%7C%20Linux-brightgreen)](https://github.com/AABurmov18/beyond-pslist)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

![beyond-pslist demo](https://raw.githubusercontent.com/AABurmov18/beyond-pslist/main/docs/demo.gif)

Most memory forensics stops at the process list: run `pslist`, spot the odd process, check its
connections, write it up. That is the right first move, and it is where a lot of analysis stops.
beyond-pslist is a small toolkit and a repeatable method for going the rest of the way, from "spot
the bad process" to a defensible timeline and report.

The method is six stations:

1. **Gate and triage** - verify the image, then build the process/network backbone.
2. **The climb** - go past the process list into injection, drivers, registry, files.
3. **Remove the noise** - strip out what only looks like malware (this is the standout station).
4. **Confirm the real evidence** - keep only what survives a provenance test.
5. **Build the timeline** - order the surviving facts in UTC and read the gaps.
6. **Report** - classify live vs noise vs tooling, and state what the image cannot prove.

The hook, and the station most people get wrong, is #3:

> A Windows image is full of malware indicators (family names, C2 domains, crypto wallets, Telegram
> and Discord tokens, ransom notes) that are not resident malware. On a Defender-enabled endpoint
> they are typically the antivirus engine's own signature database and AMSI scan buffers, mapped
> through process memory. Read as evidence, they invent infections that were never there.

Assume that noise is present and test for it. It is not universal: it is absent or thinner if
Defender is disabled or replaced, on stripped or server builds, or in analysis VMs, and how far it
spreads across processes depends on recent scan activity. The point is the discipline, not the
assumption.

### Sources of memory noise

- antivirus signature databases and AMSI scan buffers
- browsed threat content (web pages, documents, chat, email)
- security tooling (EDR agents, scanners, sandboxes, SIEM agents)
- the examiner's own acquisition and analysis tools
- threat-intel feeds and malware sample zoos
- shared and mapped pages, and pagefile content attributed to many processes
- deliberate decoys

> **Use responsibly.** Only run these tools against images you are authorised to analyse. No
> forensic data ships in this repo; every value under `examples/` is synthetic and defanged.

## Install

Not on PyPI yet, so install from a clone:

```bash
git clone https://github.com/AABurmov18/beyond-pslist
cd beyond-pslist
pip install -e .
```

After a PyPI release, `pip install beyond-pslist` will also work. Pure standard library, with no
third-party runtime dependencies, so it runs on a locked-down analysis box.

## Quickstart (fully synthetic, no real data)

```bash
# 1. build the synthetic inputs (two tiny dumps, a carved region, a timeline CSV)
python examples/make_synthetic.py

# 2. extract strings with offsets (ASCII + UTF-16LE)
bps strings examples/out/target.bin --min 6

# 3. read what a hit sits NEXT TO. this is the whole game.
bps context examples/out/target.bin "README_RECOVER"
#   shows the ransom note bracketed by a 'Ransom:Win64/...!MTB' label  => RESIDUE

# 4. is a carved region a real payload?
bps zcheck examples/out/carved_region.bin
#   0.00% non-zero, no MZ, no toolchain markers => NO payload evidence

# 5. the headline: subtract a clean baseline, then score each survivor
bps sift examples/out/target.bin examples/out/baseline.bin
#   fake wallet / token / family strings => RESIDUE (next to AV markers, or in the baseline)
#   the one planted non-signature IOC    => CANDIDATE (look closer, not 'confirmed bad')

# 6. put the surviving facts on a clock and read the gaps
bps timeline examples/out/timeline_events.csv
#   a child process spawned ~7 min after the shell connected => interactive, hands-on-keyboard
```

For the full method on this synthetic scenario end to end, see [`examples/worked-example.md`](examples/worked-example.md).

## What's in here

| Path | What it is |
|---|---|
| `beyondpslist/` | the tools: `strings`, `context`, `zcheck`, `sift`, plus the shared `markers` library |
| `docs/METHODOLOGY.md` | the full end-to-end method, stations A to F |
| `docs/CHEATSHEET.md` | a Volatility 3 plugin runbook: which plugin surfaces which artifact, in order |
| `docs/TIMELINE.md` | building the timeline: ordering surviving facts in UTC and reading the gaps |
| `docs/REPORTING.md` | classifying findings and stating the boundaries the image cannot cross |
| `regex/ioc-regex.md` | copy-paste IOC regexes (IPv4, URL, BTC, Telegram, Discord, onion, email) |
| `regex/defender-vdm-markers.md` | the antivirus-signature marker patterns that flag residue |
| `yara/defender-residue.yar` | YARA rules that match signature-database content so you can exclude it |
| `examples/` | a synthetic dump generator and a fully defanged worked example |

## The one rule (station 3)

The clean-baseline subtraction (`sift`) is a residue detector, not a residue excluder:

- **Valid (positive):** a string present in a process that cannot be infected (for example
  `dwm.exe`) is shared residue.
- **Invalid (negative):** a string being absent from that baseline does not make it genuine. A
  signature database is compressed and only partly resident, so a lone signature page easily looks
  "unique". The only thing that promotes a survivor is reading the bytes around it. If it sits next
  to `!MTB`, `Ransom:`, `#ATTR_`, `MHSTR:`, `!#SCRIPT:`, or is stored as ASCII immediately followed
  by its UTF-16LE copy, it is the antivirus's name for a threat, not the threat.

A `CANDIDATE` verdict means "nothing here marks it as a signature". It is a prompt to look closer,
not a confirmation that something is malicious.

## Volatility plugins this pairs with

`windows.info`, `pslist`, `pstree`, `netscan`, `malfind`, `vadinfo`, `svcscan`, `modules`,
`registry.hivelist/printkey`, `mftscan`, `consoles`, `timeliner`, `vadyarascan`,
`malware.hollowprocesses`, `malware.ldrmodules`. See `docs/CHEATSHEET.md`.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT, see [LICENSE](LICENSE).
