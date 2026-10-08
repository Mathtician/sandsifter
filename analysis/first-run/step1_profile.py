#!/usr/bin/env python3
"""Step 1: parse data/log, profile artifact space by (first bytes, signum)."""
import pickle
from collections import Counter

log = open("../data/log", "rb")

by_pre1 = Counter()   # (first_byte, signum) -> count
by_pre2 = Counter()   # (first2, signum) -> count
examples = {}         # (prefix, signum) -> first example line
n = 0
for line in log:
    if line.startswith(b"#"):
        continue
    v = line.split()
    insn = v[0].decode()
    signum = int(v[3])
    pre1 = insn[:2]
    pre2 = insn[:4] if len(insn) >= 4 else insn
    by_pre1[(pre1, signum)] += 1
    by_pre2[(pre2, signum)] += 1
    examples.setdefault((pre2, signum), line.decode().strip())
    n += 1

print("total artifacts:", n)
pickle.dump({"by_pre1": by_pre1, "by_pre2": by_pre2, "examples": examples},
            open("profile.pkl", "wb"))

print("\n== (byte0, signum) with >= 1000 artifacts ==")
for (p, s), c in sorted(by_pre1.items(), key=lambda kv: -kv[1]):
    if c >= 1000:
        print(f"{c:>10}  sig{s}  {p}")
