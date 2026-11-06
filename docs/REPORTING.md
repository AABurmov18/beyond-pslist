# Reporting - turning results into findings

A short, practical template for writing up a memory investigation so that noise never leaks into the
conclusions. It pairs with `METHODOLOGY.md` (how you get the results) and the walkthrough in
`examples/worked-example.md` (the method on a synthetic case).

## Classify every indicator before it reaches the report

Give each indicator exactly one label. If you cannot justify LIVE or HOST/TOOLING, it is RESIDUE
until proven otherwise.

| Class | Meaning | How you decide |
|---|---|---|
| **LIVE** | A real artifact of activity on this host | A kernel socket in `netscan`, a process in the tree, a file object, a registry value. Something that exists as structure, not just as a string. |
| **RESIDUE** | A string that fails the provenance test | Present in a clean baseline, sitting next to antivirus signature markers (`!MTB`, `Ransom:`, `#ATTR_`, `MHSTR:`, `!#SCRIPT:`), stored ASCII+UTF-16, repeated across mapped pages, or clearly rendered content (a browsed page, a document, an intel feed). |
| **HOST/TOOLING** | Benign software that looks suspicious | The examiner's own acquisition tools (check driver and service display names), security agents, backup software, developer tools. |

## Rules

1. **A RESIDUE string is never an IOC.** Do not put it in the indicators table, the detection
   content, or the attribution. It describes what the antivirus knows about the world, not what ran
   here.
2. **External reputation answers the wrong question.** A lookup (for example VirusTotal) tells you
   an indicator is known-bad in the world. It does not tell you it executed on this host. A residue
   string being genuinely malicious in the wild is exactly why an antivirus catalogues it.
3. **State the boundaries the image cannot cross.** Memory forensics proves actions, not intent or
   identity. Spell out what is unknown:
   - **Who** operated a remote endpoint (an image cannot bind a person to a listener).
   - **Why** something did or did not happen (staged is a fact; "intentionally not detonated" is
     intent you cannot prove).
   - **What** was typed or run, when the relevant buffer is paged out and unrecoverable.
4. **Separate a result from a finding.** A plugin output is a result. A finding is a result you have
   classified, corroborated, and placed on the timeline.

## Report template

```
# <case id> - memory investigation

## Summary
<2-4 sentences: what ran, the one or few LIVE channels, and the single most important boundary.>

## Scope and image
- Image: <name>, <size>, SHA-256 <hash>
- OS / build / capture time: <...>
- Host / user: <...>

## Timeline (UTC)
<oldest first; call out interactive gaps, e.g. a child spawned minutes after its parent.>

## Findings
| Indicator | Class | Evidence |
|---|---|---|
| <socket / process / file> | LIVE | <plugin + offset/pid> |
| <ip that survived scoring> | LIVE or CANDIDATE | <netscan match + sift verdict> |
| <family name / wallet / token / C2 string> | RESIDUE | <baseline hit or signature-marker adjacency> |
| <driver or console from own tooling> | HOST/TOOLING | <svcscan display name / vendor> |

## What this image cannot prove
- <who operated the remote endpoint>
- <why X did or did not happen>
- <what was run through the shell, if the console buffer is paged out>

## Indicators of compromise (LIVE only)
<defang everything. Only indicators that passed the provenance test belong here.>
```

## A filled synthetic row (from the worked example)

- `10.20.30[.]9:9001` - **LIVE** - ESTABLISHED socket owned by `freebonus.exe` (pid 4821), and the
  bare IP `10.20.30[.]9` was the single CANDIDATE that survived `bps sift`.
- `Ransom:Win64/Demoware.A!MTB`, `bc1qsynthetic...`, `1111111111:AAFake...`, `http://198.51.100[.]77/relay/`
  - **RESIDUE** - antivirus signature content; excluded from the IOC list.
- 7-minute gap between `freebonus.exe` starting and `cmd.exe`/`notepad.exe` spawning - **LIVE** -
  evidence of interactive, hands-on-keyboard use; operator identity and typed commands are out of
  scope for what the image can prove.
