#!/usr/bin/env python3
"""Analyze the 0f78 group (10M artifacts, all sig4/SIGILL)."""
from collections import Counter

PREFIXES = set("26 2e 36 3e 64 65 66 67 f0 f2 f3".split())

def strip(insn):
    i = 0
    while i < len(insn):
        b = insn[i:i+2]
        if b in PREFIXES or (len(b) == 2 and 0x40 <= int(b, 16) <= 0x4f):
            i += 2
        else:
            break
    return insn[i:]

log = open("../data/log", "rb")
modrm_len = Counter()     # (modrm, recorded_length) -> count   [unprefixed only]
forms = Counter()
n = 0
for line in log:
    if line.startswith(b"#"):
        continue
    v = line.split()
    insn = v[0].decode()
    s = strip(insn)
    if s[:4] != "0f78":
        continue
    n += 1
    if n > 2000000:
        break
    ln = int(v[2])
    modrm = s[4:6] if len(s) >= 6 else ""
    modrm_len[(modrm, ln)] += 1
    forms[s] += 1

print("scanned:", n)
print("distinct stripped forms:", len(forms))
print("\nsample forms:", [f for f in list(forms)[:10]])

# hypothesis: recorded length == bytes needed by extrq-style decode:
# opcode(2) + modrm(1) + [sib] + [disp] + imm8 + imm8
def extrq_len(modrm):
    m = int(modrm, 16)
    mod, rm = m >> 6, m & 7
    L = 3  # 0f 78 modrm
    if mod != 3:
        if rm == 4:
            L += 1  # sib
        if mod == 1:
            L += 1
        elif mod == 2 or (mod == 0 and rm == 5):
            L += 4
        if mod == 0 and rm == 4:
            pass  # sib counted; base/index normal, no disp unless sib base=5
    L += 2  # imm8 imm8
    return L

# check match rate
ok = bad = 0
badex = []
for (modrm, ln), c in modrm_len.items():
    if not modrm:
        continue
    if extrq_len(modrm) == ln:
        ok += c
    else:
        bad += c
        if len(badex) < 20:
            badex.append((modrm, ln, c, extrq_len(modrm)))
print(f"\nentries where length == extrq-format length: {ok}; mismatch: {bad}")
for b in badex:
    print("  mismatch: modrm", b)
