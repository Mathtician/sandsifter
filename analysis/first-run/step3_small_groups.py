#!/usr/bin/env python3
"""Step 3: dump the small groups (stripped-prefix first-two-bytes in target set)."""
PREFIXES = set("26 2e 36 3e 64 65 66 67 f0 f2 f3".split())

def strip(insn):
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

TARGETS = {"0f00", "0f01", "0fc2", "c384", "c39c", "c39d", "c39e", "c39f",
           "0f18", "0f1d", "0f1e"}

log = open("../data/log", "rb")
out = {t: [] for t in TARGETS}
for line in log:
    if line.startswith(b"#"):
        continue
    v = line.split()
    insn = v[0].decode()
    s, p = strip(insn)
    key2 = s[:4] if len(s) >= 4 else s
    if key2 in TARGETS:
        out[key2].append(line.decode().strip())

for t in sorted(TARGETS):
    print(f"===== group {t}: {len(out[t])} artifacts =====")
    for l in out[t][:200]:
        print("   ", l)
