#!/usr/bin/env python3
"""Tabulate the 0fc2 group: stripped bytes -> count, with lengths."""
from collections import Counter

PREFIXES = set("26 2e 36 3e 64 65 66 67 f0 f2 f3".split())

def strip(insn):
    pre = []
    i = 0
    while i < len(insn):
        b = insn[i:i+2]
        if b in PREFIXES or (len(b) == 2 and 0x40 <= int(b, 16) <= 0x4f):
            pre.append(b); i += 2
        else:
            break
    return insn[i:], tuple(pre)

log = open("../data/log", "rb")
forms = Counter()
lens = Counter()
for line in log:
    if line.startswith(b"#"):
        continue
    v = line.split()
    insn = v[0].decode()
    s, p = strip(insn)
    if s[:4] == "0fc2":
        forms[s] += 1
        lens[(s, int(v[2]))] += 1

print("distinct stripped forms:", len(forms))
# organize: second byte (modrm) -> list of suffixes
bymodrm = {}
for s, c in forms.items():
    modrm = s[4:6]
    bymodrm.setdefault(modrm, []).append(s)
for m in sorted(bymodrm):
    ss = sorted(bymodrm[m])
    print(f"modrm={m}: {len(ss)} forms, e.g. {[x for x in ss[:4]]}")
