# IOC regexes

Copy-paste patterns for hunting indicators in a memory image or string dump. These mirror
`beyondpslist/markers.py` (`IOC_PATTERNS`). Run them over raw bytes.

> Finding one of these does **not** mean the host is infected. Signature databases contain known-bad
> indicators too. Always pair with `regex/defender-vdm-markers.md` and `bps context`.

| Indicator | Regex |
|---|---|
| IPv4 | `\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b` |
| URL | `https?://[^\s"'<>)\x00]{4,}` |
| Bitcoin (legacy + bech32) | `\b(?:bc1[a-z0-9]{20,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b` |
| Telegram bot token | `\b\d{6,12}:[A-Za-z0-9_-]{30,}\b` |
| Discord webhook | `discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_.-]+` |
| Tor onion | `\b[a-z2-7]{16}(?:[a-z2-7]{40})?\.onion\b` |
| Email | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b` |

## Usage

```bash
# with this toolkit
bps strings image.mem | grep -EoP "<regex>"

# or let sift do the hunting + the residue scoring in one pass
bps sift target.dmp clean_dwm.dmp
```

## Defang on slides / in writeups

All example indicators below are **synthetic**. Still, defang anything you present:

```
http://198.51.100[.]77/relay/            (URL)
198.51.100[.]77                          (IP)
bc1qsynthetic...example                  (wallet, truncated)
1111111111:AAFake...Synthetic            (token, truncated)
```
