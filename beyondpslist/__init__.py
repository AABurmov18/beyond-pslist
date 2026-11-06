"""beyond-pslist: tell antivirus-signature residue from a real payload in a memory dump.

A small, dependency-free toolkit for going past the process list in Windows memory
forensics. The headline problem it solves: a memory image is full of malware strings
(family names, C2 domains, wallets, tokens, ransom notes) that are NOT resident malware
at all -- they are the antivirus engine's own signature database and scan buffers mapped
through process memory. Treating that residue as evidence manufactures infections.

Modules:
    strings  -- offline ASCII + UTF-16LE string extraction (no binutils required)
    context  -- print the bytes around a hit so you can read what it sits next to
    zcheck   -- is a carved region a real payload? (non-zero ratio + PE/script markers)
    sift     -- baseline-subtract two dumps, then score survivors residue vs candidate
    timeline -- merge event rows into one chronological timeline, flag interactive gaps
    markers  -- shared IOC regexes and antivirus-signature marker patterns
"""

__version__ = "0.1.0"
