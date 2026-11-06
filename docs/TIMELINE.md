# Building a timeline from a memory image

Finding the artifacts is half the job. The other half is putting them in order, because a sequence
tells a story that a pile of facts cannot. A child process that appears seven minutes after its
parent is not visible in any single plugin; it is visible in the timeline.

## Where the time lives

Different plugins carry time in different columns. Collect them, then merge.

| Time source | Plugin | What you get |
|---|---|---|
| Process create times | `windows.pslist`, `windows.psscan` | when each process started |
| Supertimeline (+ USB mount symlinks) | `timeliner` | a broad, pre-merged set incl. device mounts |
| File MACB timestamps | `windows.mftscan.MFTScan` | created / modified / accessed / MFT-changed per file |
| Live connections | `windows.netscan` | the moment a socket was seen, with owning PID |
| Registry key LastWrite | `windows.registry.printkey --key ...` | when a key last changed |
| Console / command history | `windows.consoles` | interactive command context (when resident) |

## Merge them with `bps timeline`

Normalise whatever you collect into a `timestamp,source,detail` feed (CSV or TSV, header optional),
then:

```bash
bps timeline examples/sample_events.csv
```

`bps timeline` sorts chronologically, de-duplicates, keeps undated rows at the end, and annotates a
row inline when it follows a quiet stretch (default: 5 minutes, set with `--gap-minutes`). It also
reads `timeliner`-style lines where the timestamp is not the first field, and accepts stdin:

```bash
cat events.tsv | bps timeline - --gap-minutes 3
```

Expected shape for the sample:

```
TIME (UTC)           SOURCE       DETAIL
1601-01-01 00:00:00  PeHeader     synthdrv.sys PE compile time (timestomped - ignore)
2025-01-01 09:12:03  SymlinkScan  USB mass storage USB-SN-0000SYNTH1234 mounted as HarddiskVolume7 (D:)   [+154863d]
2025-01-01 09:12:31  PsList       freebonus.exe (pid 4821) started by explorer.exe (pid 1320)
2025-01-01 09:12:31  NetScan      TCP 10.20.30.40:50122 -> 10.20.30.9:9001 ESTABLISHED (pid 4821)
2025-01-01 09:13:04  PsList       conhost.exe (pid 4990) started
2025-01-01 09:19:47  PsList       cmd.exe (pid 5133) started by freebonus.exe (pid 4821)   [+6m43s]
2025-01-01 09:19:52  PsList       notepad.exe (pid 5160) started by freebonus.exe (pid 4821)
2025-01-01 09:22:10  Acquisition  memory capture started
N/A                  MftScan      README_RECOVER.txt present (no MACB timestamp resident)
```

The gap is measured against the immediately preceding event, so the `[+6m43s]` sits on `cmd.exe`
(quiet since `conhost` at 09:13:04). The year-1601 timestomp sorts to the top and pushes an absurd
`[+154863d]` tag onto the next real row; that absurdity is the tell, not a real gap.

## Reading an interactive gap

The USB mounts, the sample runs and connects out in the same second (an automated start), then
nothing happens for about seven minutes, and then `cmd.exe` and `notepad.exe` appear. An automated
dropper spawns its children immediately. A multi-minute gap before new process activity is the
classic fingerprint of a human on the other end of a shell, typing. That gap is a finding on its
own, and `bps timeline` tags it (`[+6m43s]` here) so you do not have to eyeball the deltas.

What the gap does NOT tell you: who was at the keyboard, or what they typed. Note it as interactive
activity and keep those as open questions.

## Pitfalls

- **Timestamps can be forged.** A PE compile time or file time in the year 1601 (or 2099) is
  timestomping, not history. In the sample, the `synthdrv.sys` row sorts to the very top and
  produces an absurd gap tag; that absurdity is the tell. Do not anchor a narrative on a single
  stamp you cannot corroborate.
- **Paged-out data leaves holes.** Missing rows are missing evidence, not evidence of absence. A
  console buffer that is paged out means you cannot recover what was typed, full stop.
- **Work in UTC.** Mixing local time and UTC invents or hides gaps. Keep everything in UTC and say
  so on the slide and in the report.
- **Correlate, do not assume.** A create time and a socket time that line up are two artifacts
  agreeing. One stamp on its own is a lead, not a conclusion.
