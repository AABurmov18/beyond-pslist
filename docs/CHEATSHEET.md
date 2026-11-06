# Volatility 3 runbook - which plugin surfaces what

A fast reference for the climb in `METHODOLOGY.md`. Invocation pattern (set UTF-8 first - a stray
CJK byte in a process field will otherwise crash a cp1252 console):

```bash
export PYTHONUTF8=1
VOL="python vol.py -q -f image.mem"
```

## Triage backbone
| Goal | Command |
|---|---|
| OS / build / capture time | `$VOL windows.info` |
| Process list | `$VOL windows.pslist` |
| Process tree / lineage | `$VOL windows.pstree` |
| Hidden / exited processes | `$VOL windows.psscan` |
| How a process launched | `$VOL windows.cmdline --pid <PID>` |
| Live connections | `$VOL windows.netscan` |
| Timeline (incl. USB mount symlinks) | `$VOL timeliner` |

## Injection / hollowing
| Goal | Command | Note |
|---|---|---|
| RWX private memory | `$VOL windows.malfind --pid <PID>` | RWX in MsMpEng/AV is its own engine |
| VAD map + protections | `$VOL windows.vadinfo --pid <PID>` | `PrivateMemory`, `PAGE_EXECUTE_READWRITE`, mapped file names |
| Carve a region | `$VOL windows.vadinfo --pid <PID> --address <VA> --dump` | then `bps zcheck` the output |
| Process hollowing | `$VOL windows.malware.hollowprocesses` | empty => nothing hollowed |
| Unlinked modules | `$VOL windows.malware.ldrmodules --pid <PID>` | a paged PEB makes everything look unlinked |

## Drivers / services / persistence
| Goal | Command | Note |
|---|---|---|
| Services (+ driver display names) | `$VOL windows.svcscan` | check names: "AccessData Driver" = FTK Imager |
| Loaded kernel modules | `$VOL windows.modules` | note the load path |
| Hives present | `$VOL windows.registry.hivelist` | is the *user* hive even in the image? |
| Autoruns | `$VOL windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"` | paged-out key != empty key |
| Program execution | `$VOL windows.registry.userassist` | may error if hive absent |

## Files / impact / tokens
| Goal | Command |
|---|---|
| MFT (file timestamps, drops) | `$VOL windows.mftscan.MFTScan` |
| Alternate data streams | `$VOL windows.mftscan.ADS` |
| File objects | `$VOL windows.filescan` |
| Console history | `$VOL windows.consoles` |
| Token integrity / groups | `$VOL windows.getsids --pid <PID>` |
| Privileges (read the Attributes column!) | `$VOL windows.privileges --pid <PID>` |

> `windows.privileges` lists every privilege *slot*; the **Attributes** column
> (`Present,Enabled,Default`) says which are actually held. An empty Attributes column means the
> privilege is **not** held. Don't read slot enumeration as an elevated token.

## Strings & provenance (pair with this repo)
| Goal | Command |
|---|---|
| Per-process strings | `$VOL -o out windows.memmap --pid <PID> --dump` then `bps strings out/pid.<PID>.dmp` |
| Read a hit's neighbourhood | `bps context <dump> "<indicator>"` |
| YARA across process VADs | `$VOL windows.vadyarascan --yara-file rules.yar` |
| Residue vs candidate | `bps sift <target.dmp> <clean_dwm.dmp>` |

> `vadyarascan` under-reports in the negative direction (it can miss hits a targeted `--pid` run
> finds). Treat a hit as meaningful; treat a miss as inconclusive.

## Timeline (pair with this repo)

Memory carries time in several plugins; merge them into one ordered view with `bps timeline`.

| Time source | Command |
|---|---|
| Process create times | `$VOL windows.pslist` / `$VOL windows.psscan` |
| Supertimeline (+ USB mount symlinks) | `$VOL timeliner` |
| File MACB timestamps | `$VOL windows.mftscan.MFTScan` |
| Live connection owners | `$VOL windows.netscan` |
| Registry key LastWrite | `$VOL windows.registry.printkey --key ...` |

Normalise any of these into a `timestamp,source,detail` CSV/TSV, then:

```bash
bps timeline events.csv --gap-minutes 5
```

A child process created minutes after its parent (a quiet gap then a burst of activity) is a classic
hands-on-keyboard signal; `bps timeline` tags it inline (`[+7m16s]`). Watch for timestomped dates
(year 1601, far-future), and always work in UTC. See `docs/TIMELINE.md`.
