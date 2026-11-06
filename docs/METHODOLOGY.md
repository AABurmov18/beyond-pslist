# Methodology — going past the process list without fooling yourself

A repeatable workflow for Windows memory triage, and the provenance discipline that stops you
reporting your antivirus's dictionary as a crime scene. Tool-agnostic; pairs with Volatility 3 and
the helpers in this repo.

## Part A — the fundamentals (get these right first)

1. **Gate the image.** `windows.info` for OS/build/time; hash the image and record it. If the hash
   isn't what you expect, stop.
2. **Backbone.** `pslist` + `pstree` for lineage; `netscan` for live connections; `cmdline` for how
   things were launched. Note parent/child relationships and **process create-time gaps** — a child
   spawned minutes after its parent is a sign of interactive, hands-on-keyboard activity, not an
   automated dropper.
3. **Name the anomaly, then distrust it.** The suspicious process is the start of the investigation,
   not the end. The process list is often the least honest thing in the dump.

## Part B — the climb (each step shows something the process list can't)

| Step | Tool | What it surfaces | Trap to avoid |
|---|---|---|---|
| Injection | `malfind`, `vadinfo` | private RWX regions | RWX inside the AV engine (MsMpEng) is **normal** — its own JIT/scan buffers, not injected shellcode |
| Hollowing | `malware.hollowprocesses`, `malware.ldrmodules` | image replacement, unlinked modules | a paged-out PEB makes *every* module look "unlinked" — don't read paging as reflective injection |
| Carved regions | `vadinfo --dump` + `zcheck` | is this region a real payload? | a region that's ~100% zero with no PE/toolchain markers is paged/empty — not a payload, however scary the VAD flags look |
| Services / drivers | `svcscan`, `modules` | kernel drivers, persistence | a driver in `\Temp` may be **your own acquisition tool** (e.g. FTK/AccessData) — check the service display name before shouting BYOVD |
| Registry | `registry.hivelist`, `printkey` | Run keys, autoruns | if the **user hive isn't in the image**, "Run keys are empty" is absence of evidence, not evidence of absence |
| Files / impact | `mftscan`, `filescan` | ransom notes, dropped files, timestamps | no note / no ciphertext on disk = no realised encryption, whatever strings are in RAM |
| The archive | `strings` + `context` + `vadyarascan` | C2 domains, keys, tokens, notes | **this is where almost everything goes wrong — see Part C** |

## Part C — the provenance discipline (the point of this repo)

A memory image contains the antivirus engine's **signature database** (Defender's `.vdm`) and AMSI
scan buffers. Those literally contain known-bad indicators — ransom notes, family names, wallets,
C2 domains, exfil-code snippets — because that's how detection works. Mapped through process memory,
they look exactly like resident malware to `strings | grep`.

**Three independent tests. A finding should pass all three before you call it a payload.**

1. **Clean-baseline subtraction (positive test only).** Dump a process that cannot be infected
   (e.g. `dwm.exe`, Desktop Window Manager). Any indicator that also appears there is shared residue.
   - *Valid:* present in the clean baseline ⇒ residue.
   - *Invalid:* **absent** from the baseline ⇒ "genuine". It does not follow. The signature database
     is compressed and only ~1% resident, so any single signature page easily looks unique. This is
     the exact trap that produces imaginary infections.
2. **Read the bytes around the hit (the decisive test).** Signature content wears labels. If the
   indicator sits within a few hundred bytes of `!MTB`, `!MSR`, `#ATTR_`, `MHSTR:`, `!#SCRIPT:`,
   `Ransom:`, `Trojan:`, `TrojanDownloader:`, or is stored as an **ASCII string immediately followed
   by its UTF-16LE copy**, it is a detection definition — not a payload. `bps context` renders this.
3. **Is it your own tooling?** Acquisition and lab software (FTK Imager / AccessData, CodeMeter,
   PostgreSQL consoles) leave drivers, services and console buffers that read as "suspicious" until
   you check the vendor name. Rule them out before attribution.

### A worked cognitive failure (why this matters)
It is possible to debunk eleven indicators as signature residue and still promote the twelfth to
"genuine payload" — because it happened to be absent from one baseline and *looked* coherent. Only
widening the byte window revealed it bracketed by `Ransom:Win64/<family>!MTB` and dual-encoded. The
fix is mechanical: **apply test 2 to every indicator, with no exceptions, before it goes in the
report.** Independent review catches what confirmation bias doesn't — get a second analyst, ideally
reproducing blind from the image before reading your conclusions.

## Part D — reporting

- Separate **live** (a socket in `netscan`), **residue** (fails tests 1–2), and **host/tooling**
  (your own software). Never let a residue string become an IOC.
- External reputation (e.g. VirusTotal) answers "is this indicator known-bad in the world?" — not
  "did it run on this host?" A residue string being genuinely malicious in the wild is *why* the AV
  catalogues it; it is not evidence of local execution.
- State boundaries plainly. "Staged, not fired" is a fact; "intentionally not detonated" is intent
  the dump cannot prove. "A human spawned processes" is provable; *what they typed* may be paged out
  and unrecoverable — say so.
