#!/usr/bin/env python3
"""Step 2: strip legacy prefixes, group by (stripped 2-byte opcode prefix, signum)."""
import pickle
from collections import Counter

PREFIXES = set("26 2e 36 3e 64 65 66 67 f0 f2 f3".split())

def strip(insn):
    """strip legacy+REX prefixes; return (stripped_hex, prefix_set)"""
    pre = []
    i = 0
    while i < len(insn):
        b = insn[i:i+2]
        if b in PREFIXES or (len(b) == 2 and 0x40 <= int(b, 16) <= 0x4f):
            pre.append(b)
            i += 2
        else:
            break
    return insn[i:], tuple(pre)

log = open("../data/log", "rb")

by_grp = Counter()    # (stripped_2bytes, signum) -> count
examples = {}
n = 0
for line in log:
    if line.startswith(b"#"):
        continue
    v = line.split()
    insn = v[0].decode()
    signum = int(v[3])
    s, p = strip(insn)
    key2 = s[:4] if len(s) >= 4 else s
    by_grp[(key2, signum)] += 1
    if (key2, signum) not in examples:
        examples[(key2, signum)] = (insn, line.decode().strip())
    n += 1

pickle.dump({"by_grp": by_grp, "examples": examples}, open("groups.pkl", "wb"))
print("total:", n, "groups:", len(by_grp))

print("\n== top 120 groups by count ==")
for (g, s), c in sorted(by_grp.items(), key=lambda kv: -kv[1])[:120]:
    ex = examples[(g, s)][0]
    print(f"{c:>10}  sig{s}  {g:<6}  e.g. {ex}")
