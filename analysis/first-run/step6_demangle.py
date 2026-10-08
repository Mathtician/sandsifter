#!/usr/bin/env python3
"""Step 6: demangle the log (undo the sifter's cstr2py UTF-8 bug) and regroup."""
import pickle
from collections import Counter

PREFIXES = set("26 2e 36 3e 64 65 66 67 f0 f2 f3".split())

def strip(b):
    i = 0
    while i < len(b):
        x = b[i]
        if x in (0x26,0x2e,0x36,0x3e,0x64,0x65,0x66,0x67,0xf0,0xf2,0xf3) or 0x40 <= x <= 0x4f:
            i += 1
        else:
            break
    return b[i:]

log = open("../data_orig/log", "rb")

by_grp = Counter()
examples = {}
n = 0
bad = 0
for line in log:
    if line.startswith(b"#"):
        continue
    v = line.split()
    try:
        enc_raw = bytes.fromhex(v[5][1:-1].decode())
        raw = enc_raw.decode("utf-8").encode("latin-1")   # undo cstr2py().encode()
    except Exception:
        bad += 1
        continue
    length = int(v[2]); signum = int(v[3])
    insn = raw[:length]
    s = strip(insn)
    key2 = s[:2].hex() if len(s) >= 2 else s.hex()
    by_grp[(key2, signum)] += 1
    if (key2, signum) not in examples:
        examples[(key2, signum)] = insn.hex()
    n += 1

pickle.dump({"by_grp": by_grp, "examples": examples}, open("groups_demangled.pkl", "wb"))
print("total:", n, "undecodable:", bad, "groups:", len(by_grp))
for (g, s), c in sorted(by_grp.items(), key=lambda kv: -kv[1])[:40]:
    print(f"{c:>10}  sig{s}  {g:<6}  e.g. {examples[(g,s)]}")
