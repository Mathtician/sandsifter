#!/usr/bin/env python3
"""Step 7: dump demangled forms for the small groups."""
from collections import Counter

PREFIX_BYTES = (0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf0,0xf2,0xf3)

def strip(b):
    i = 0
    while i < len(b) and (b[i] in PREFIX_BYTES or 0x40 <= b[i] <= 0x4f):
        i += 1
    return b[i:]

TARGETS = ["0fae", "0f82", "0f83", "0f84", "0f85", "0f86", "0f87", "0f88",
           "0f89", "0f8a", "0f8b", "0f8c", "0f8d", "0f8e", "0f8f",
           "dcd0", "ddc8", "ded0", "dfc8", "c403", "c423", "c443", "c463",
           "c483", "c4a3", "c4c3", "c4e3", "0f00", "0f01", "0f18", "0f1d", "0f1e"]

log = open("../data_orig/log", "rb")
out = {t: Counter() for t in TARGETS}
for line in log:
    if line.startswith(b"#"):
        continue
    v = line.split()
    enc_raw = bytes.fromhex(v[5][1:-1].decode())
    raw = enc_raw.decode("utf-8").encode("latin-1")
    length = int(v[2]); signum = int(v[3])
    insn = raw[:length]
    s = strip(insn)
    key2 = s[:2].hex()
    if key2 in out:
        out[key2][(insn.hex(), length, signum)] += 1

for t in TARGETS:
    if out[t]:
        print(f"===== {t}: {sum(out[t].values())} artifacts, {len(out[t])} distinct =====")
        for (insn, ln, sg), c in sorted(out[t].items())[:8]:
            print(f"    {insn}  len={ln} sig={sg}  x{c}")
