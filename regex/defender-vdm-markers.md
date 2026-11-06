# Antivirus-signature markers — how to recognise residue

These are the patterns that tell you an indicator is **antivirus signature content**, not a resident
payload. They mirror `beyondpslist/markers.py` (`AV_MARKERS`). They describe Microsoft Defender's
public threat-naming grammar and its `.vdm` definition records — generic conventions, not data from
any case.

If an IOC sits within a few hundred bytes of any of these, treat it as residue.

| Marker | Meaning |
|---|---|
| `...<Family>.<Var>!MTB` | ML/heuristic detection suffix (e.g. `Ransom:Win64/Demoware.A!MTB`) |
| `!MSR`, `!rfn`, `!dha`, `!dam` | other Defender detection-type suffixes |
| `#ATTR_<hex>` | VDM definition-record attribute marker |
| `MHSTR:` | "match HSTR" signature-string prefix |
| `!#SCRIPT:`, `!#ALF:`, `!#SCPT:` | AMSI script-scan signature identifiers |
| `!MainPS` | PowerShell AMSI signature tail (e.g. `!#SCRIPT:PowerShell/<Family>!MainPS`) |
| `Ransom:`, `Trojan:`, `TrojanDownloader:`, `Backdoor:`, `VirTool:`, `HackTool:`, `Behavior:` | Defender `Type:Platform/Family` threat names |

## The strongest single tell: ASCII + UTF-16LE pairing

Defender `.vdm` records store a string as **ASCII immediately followed by its UTF-16LE copy**:

```
README_RECOVER.txt R.E.A.D.M.E._.R.E.C.O.V.E.R...t.x.t.
```

A payload rarely carries both encodings back-to-back; a signature database does it everywhere.
`beyondpslist.markers.is_utf16_paired()` detects it, and `bps context` / `bps sift` flag it.

## Other residue tells
- The **same bytes repeated at several virtual addresses** (the VDM mapped more than once).
- IOC lists mixed with **unrelated** IOCs and family labels (a signature bundling many samples).
- **Cross-platform** content in one block (macOS `system_profiler`, Android `Trojan:AndroidOS/...`)
  next to your "Windows payload" — a database, not a process.

## Grep hints

```bash
grep -aoE "!MTB|!MSR|#ATTR_[0-9A-Fa-f]+|MHSTR:|!#SCRIPT:|(Ransom|Trojan|TrojanDownloader):(Win32|Win64|MSIL|O97M)/" image.mem | sort | uniq -c
```
