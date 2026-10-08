# sandsifter log analysis — AMD Ryzen 5 7640U (Zen 4)

## Target and scan metadata

From the `data/log` header:

| field | value |
|---|---|
| CPU | AMD Ryzen 5 7640U w/ Radeon 760M (Zen 4, "Phoenix") |
| family/model/stepping | 25 / 116 / 1 |
| microcode | 0xa70410a |
| arch | 64-bit, kernel 6.18.40 (NixOS) |
| scan | `sifter.py --unk --dis --len --sync --tick -- -P1 -t` (tunnel, max 1 prefix byte) |
| seed | 1587131472 |
| instructions tested | 822,308,128 in 06:21:29 |
| anomalies found | 19,301,762 (all distinct instructions) |

Reference: Intel SDM, Order Number 325462-092US, June 2026 (not included in
this repo; download it from Intel).

## How to read the log

Each line: `%30s %2d %2d %2d %2d (%s)` = executed bytes, valid, length, signum,
si_code, raw 16 bytes. Mechanism (from `injector.c`):

* the instruction is placed at the end of an RWX page; the next page is
  RW-but-not-executable. `inject(i)` for i=1..15 places i bytes; if the CPU
  decoder needs more than i bytes, instruction fetch crosses the boundary →
  SIGSEGV at the boundary address and the loop continues. The loop stops at
  the first i where the instruction is *complete*, so **`length` = minimal
  byte count the CPU needs to fully decode the instruction**.
* TF (single-step) is set by a `pushfq/orq/popfq` preamble in the packet, so
  a cleanly executing instruction reports **SIGTRAP / si_code 2 (TRAP_TRACE)**.
  #UD reports **SIGILL / si_code 2 (ILL_ILLOPN)**.
* All GPRs are 0, page at address 0 is mapped RW (root `-0`), rsp points at a
  dummy stack. There are **no SIGSEGV/SIGFPE/SIGBUS anomalies at all** — with
  this setup almost every memory operand accesses succeed.

The log contains only two signal classes:

| signum | count | meaning here |
|---|---|---|
| 4 (SIGILL) | 12,684,232 | CPU raises #UD, but capstone's decode length ≠ CPU's |
| 5 (SIGTRAP) | 6,617,530 | instruction executed, but capstone didn't know it or disagreed on length |

## Complete census — every line accounted for

The log is fully explained by a small set of "root" anomalies, each
replicated under the one-byte prefixes {26, 2e, 36, 3e, 65} (segment), {66}
(operand-size), and {40–4f} (REX), which the CPU ignores for these
instructions but capstone does not:

```
14 groups × 832,411   = 11,653,754   unprefixed + {26,2e,36,3e,65} + REX.{R=0}
 8 groups × 934,603   =  7,476,824   REX with REX.R set (44-47, 4c-4f):
                                      same + 102,192 extra (0f 1a/1b reg ≤3,
                                      where REX.R extends bnd reg to bnd8-11)
 1 group  × 169,968   =    169,968   66-prefixed set (different semantics)
      small groups    =      1,216   x87 aliases and seg-prefix+VEX (below)
                      ----------
                        19,301,762   ✓ matches the header count exactly
```

Base anomaly set (832,411 per prefix group):

| opcode | count | class |
|---|---|---|
| `0f 78` | 576,556 | AMD decode-length quirk (SIGILL) — **all** SIGILL lines are this: 576,556 × 22 prefixes = 12,684,232 = exact SIGILL total |
| `0f 1c` | 89,482 | CLDEMOTE space, reserved reg forms execute as NOP |
| `0f 0d` | 63,870 | PREFETCH space, reserved reg forms /3–/7 execute as NOP |
| `0f 1a` | 51,160 | BNDLDX space (no MPX) executes as NOP |
| `0f 1b` | 51,160 | BNDSTX space (no MPX) executes as NOP |
| `0f 1d` | 64 | mod=3 forms execute as NOP |
| `0f 1e` | 64 | mod=3 forms execute as NOP |
| `0f 18` | 32 | mod=3, reg /0–/3 execute as NOP |
| `0f ae` | 21 | fences with rm≠0 (see below) |
| `0f 00` | 1 | SLDT — measurement artifact (UMIP, see below) |
| `0f 01` | 1 | SGDT — measurement artifact (UMIP, see below) |

The 66-prefixed group (169,968) additionally contains `66 0f 82..8f` ×256
(3,584): the Jcc-rel16 capstone bug, and omits `0f 78` (66 0f 78 = EXTRQ,
CPU and capstone agree) — see findings.

The 1,216 small-group lines: x87 alias opcodes (dc d0–df, dd c8–cf,
de d0–d7, df c8–df) under {26,2e,36,3e,65,40–4f} prefixes, and
segment-prefix + VEX (`26 c4 …` etc., 8 per prefix = all ~R~X~B combos of
`c4 ?3 7d 00 00 00`).

---

## Findings

### F1. AMD decoder expects two immediate bytes for bare `0F 78` before raising #UD — 12.68M lines (65.7% of the log)

`0F 78 /r` is VMREAD on Intel (VMX). This CPU has no VMX, so it #UDs — but
it does so only after decoding **modrm(+SIB+disp) plus two extra immediate
bytes**. Measured consumed length = normal modrm length + 2, uniformly:

| bytes | normal len | CPU len | |
|---|---|---|---|
| `0f 78 00` ([rax]) | 3 | 5 | +2 |
| `0f 78 45 xx` (disp8) | 4 | 6 | +2 |
| `0f 78 05 disp32` ([rip+disp32]) | 7 | 9 | +2 |
| `0f 78 04 05 disp32` (SIB+disp32) | 8 | 10 | +2 |
| `0f 78 c0` (mod=3) | 3 | 5 | +2 |

This exactly mirrors the SSE4a EXTRQ encoding `66 0F 78 /r ib ib` (this CPU
still has `sse4a` in CPUID): the AMD decoder apparently decides the *length*
of the `0F 78` family from the SSE4a decode path, regardless of the
mandatory 66/F2 prefix, then faults. Contrast: bare `0F 79` (VMWRITE on
Intel, register-form in the SSE4a family) #UDs at the normal 3 bytes — no
extra immediates — consistent with the SSE4a `0F 79` forms having no
immediates.

Consequences:

* if a bare `0F 78 …` sequence straddles a page boundary, you get **#PF
  instead of #UD** (the CPU tries to fetch the "immediates" first) —
  exception-type divergence observable from userspace;
* on Intel the same bytes decode as a complete 3-byte VMREAD-then-#UD —
  a genuine AMD/Intel decoder divergence for illegal instructions;
* every emulator/disassembler that models #UD for `0F 78` at the VMREAD
  length gets the boundary-fault behavior wrong.

Verified with `tools/probe 0f7800` (page-boundary harness) on the live
machine: matches the log exactly.

### F2. `VEX.66.0F3A.W0 00 /r ib` executes as VPERMQ (W must be 1 per spec)

`c4 03 7d 00 00 ib` — the SDM defines `0F3A 00` only as
`VPERMQ ymm, ymm/m256, imm8` with **VEX.W=1**. With W=0 both capstone 5.0.9
and objdump 2.46 reject the encoding, but the CPU executes it.
Semantics verified (`tools/vexsem.c`): with input qwords
[1000 1001 1002 1003] and imm=0x1b it produced [1003 1002 1001 1000] —
exactly VPERMQ with W ignored.

Found only via the segment-prefix exploration paths (`26 c4 ?3 7d …`,
8 ~R~X~B combinations × 5 segment prefixes; the bare form was never tested
by the tunnel — coverage gap, see recommendations). This is the known
"AMD does not enforce VEX.W" leniency class; it is a portability trap
(code that runs on AMD #UDs on Intel) and an emulator-fidelity gap.

### F3. `0F 0D /3–/7` execute as NOPs (reserved prefetch hints) — 63,870 lines

SDM documents `0F 0D /0` PREFETCH, `/1` PREFETCHW, `/2` PREFETCHWT1
(Knights Landing). Reg values /3–/7 are reserved. On this CPU every
mod≠3 form executes as a NOP-equivalent prefetch hint (mod=3 forms #UD,
consistent with a memory-only hint). capstone knows /0–/2 but reports
/3–/7 as unknown; objdump accepts all of them as `prefetch`.
Counts: 12,774 addressing variants per reg × 5 regs = 63,870.

### F4. Fences with rm ≠ 0 execute — documented in the SDM, capstone bug — 21 lines

`0f ae e9–ef` (LFENCE), `0f ae f1–f7` (MFENCE), `0f ae f9–ff` (SFENCE).
The SDM says explicitly (Vol. 2A, LFENCE/MFENCE/SFENCE pages): "the
processor ignores the r/m field of the ModR/M byte. Thus, LFENCE is
encoded by any opcode of the form 0F AE Ex, where x is in the range 8-F"
(same text for MFENCE Fx 0-7, SFENCE Fx 8-F). capstone 5.0.9 knows only
E8/F0/F8 → **capstone bug**; objdump decodes all forms correctly.

### F5. `66 0F 8x` = Jcc rel16 in 64-bit mode; capstone decodes it as 7-byte rel32 — 3,584 lines

`66 0f 82 00 00`: CPU consumes 5 bytes (objdump agrees: `jb rel16`).
capstone 5.0.9 reports **7 bytes** (`jb rel32` with the 66 treated as
inert) — wrong length *and* wrong semantics: hardware verification
(`tools/jcc.c`) shows the CPU additionally **truncates RIP to 16 bits**
((RIP+dest) ∧ 0xFFFF — jumped to 0x6106 in the test), exactly the legacy
rel16 behavior the SDM marks "N.S." (not supported) in 64-bit mode.

So: the encoding is alive and dangerous on real hardware (a 5-byte
instruction that jumps to RIP∧0xFFFF+rel16), while capstone silently
mis-disassembles it. Worth an upstream capstone report.

### F6. Undocumented x87 alias opcodes execute — 1,152 lines (prefixed forms)

Executed on hardware (SIGTRAP, correct lengths):

| encoding | alias of | SDM status |
|---|---|---|
| `DC D0+i` | FCOM st(i) | SDM documents FCOM = D8 D0+i only |
| `DC D8+i` | FCOMP st(i) | SDM documents FCOMP = D8 D8+i only |
| `DD C8+i` | FFREEP st(i) | FFREEP was removed from documentation long ago |
| `DE D0+i` | FCOMP-alias | DE D9 = FCOMPP documented; D0–D7 not |
| `DF C8+i` … `DF DF+i` | FFREEP/FSTP-family aliases | undocumented |

Semantic spot check (`tools/x87sem2.c`): with st0=2.0, st1=1.0,
`dc d0` sets C3C2C0=100 (st0==st0 — fcom semantics) exactly like
`d8 d0`; `dc d1` gives 000 (2.0 > 1.0). These are the classic
undocumented x87 aliases already catalogued in the sandsifter
whitepaper; here they are confirmed alive on Zen 4. **Both** capstone
and objdump reject them — disassembler coverage gaps.

The log only contains them under segment/REX prefixes (e.g. `26 dc d0`);
the bare forms execute too (verified with `tools/step`) but were never
visited by the tunnel — a coverage artifact, not a CPU property.

### F7. Hint-NOP space (`0F 18–1F`) executes broadly as NOP — 192,858 lines

On this CPU (no MPX, no CLDEMOTE, no CET per CPUID flags):

* `0F 18` mod=3 reg /0–/3: execute (capstone: unknown; objdump: `nop %eax`).
  /4–/7 mod=3 are already `nop r32` to capstone.
* `0F 1A`/`0F 1B` (BNDLDX/BNDSTX): **all** modrm forms execute as NOPs.
  SDM documents "the reg-reg form of this instruction will remain a NOP";
  the CPU NOPs the memory forms too (no MPX). capstone accepts only
  bnd0–bnd3 in reg → /4–/7 (and, with REX.R, /0–/3 as bnd8–bnd11) are
  "unknown but execute" — that's 51,160 per opcode plus the 102,192
  REX.R extras. objdump prints `bndldx (%rax),(bad)` — partial decode.
* `0F 1C` (CLDEMOTE space): /0 mod≠3 is CLDEMOTE to capstone (executes
  as NOP-equivalent here — no `cldemote` CPUID flag; whether it demotes
  anything is unobservable from here), /1–/7 and all mod=3 forms execute
  as NOPs, unknown to capstone. objdump prints `nopl`.
* `0F 1D`, `0F 1E` mod=3: execute as NOPs, unknown to capstone
  (objdump: `nop`). Note `F3 0F 1E /1 mod=3` is RDSSP — documented NOP
  when CET is disabled — and we verified even reg /0 (`f3 0f 1e c0`)
  NOPs.

None of these are CPU bugs; they are the standard hint-NOP behavior of
the `0F 18–1F` range, which the SDM only partially documents. The
actionable items are disassembler gaps (capstone missing the reserved
forms; both tools' output disagreeing with hardware length = a bug for
anyone using them to decode hint-NOP-padded code).

### F8. Prefix leniency is what multiplies everything ×22

The CPU ignores redundant segment (26/2e/36/3e/65) and REX (40–4f)
prefixes in front of all of the above; capstone either rejects the
combination or computes a different length → each root anomaly appears
once per prefix. Additionally `26/2e/36/3e/65 c4 …` (segment prefix +
3-byte VEX) **executes** (VEX decoded normally, prefix ignored) while
both disassemblers reject a VEX prefix after a legacy prefix — SDM
considers non-VEX-first encodings reserved, but the CPU is lenient.
40 lines total; harmless, but another disassembler/emulator trap.

### F9. The `0f 00`/`0f 01` "length anomalies" are Linux UMIP emulation, not hardware — and they break single-stepping

The two singletons `0f00000000` (l=5, executed) and `0f01000000` (l=5)
look like "SLDT [rax]/SGDT [rax] consume 5 bytes instead of 3". The real
mechanism (`tools/step.c`, `tools/umip2.c`):

1. This kernel has `CONFIG_X86_UMIP=y` and CR4.UMIP set. SGDT, SIDT,
   SLDT, STR, SMSW at CPL=3 → #GP, which the kernel's UMIP handler
   **emulates silently** (no signal) with *dummy* descriptor-table
   values: we read gdtr.base=0xfffffffffffe0000 limit=0,
   idtr.base=0xffffffffffff0000 limit=0 — not the real GDT/IDT.
2. Because the instruction never completes architecturally, the
   TF single-step #DB is delivered only after the instruction
   *following* the emulated one (IRET-restored TF semantics) —
   an effective one-instruction debug-trap shadow, like `mov ss`.
3. The injector's length loop then measures SLDT=5 (sldt + the
   following `00 00` = `add [rax],al`) → bogus "length mismatch" entry.

Real-world impact, demonstrated with `tools/sldtdemo2.c` under gdb:
`stepi` on `sldt %ax` executes **two** instructions — any
TF-based single-stepper (gdb, rr, DBI frameworks, sandsifter itself)
silently steps over the instruction after an emulated
SGDT/SIDT/SLDT/STR/SMSW. A full-opcode-map scan for #DB deferral
(`tools/shadow_scan.txt`) found the deferral set is *exactly* the UMIP
instruction set — no other instruction on this CPU defers #DB
(VERR/VERW, FPU ops, fences, CPUID, RDTSC, … all trap normally;
the raw scan's apparent hits on imm8-form instructions are artifacts
of feeding truncated encodings, re-verified individually).

Worth noting: with `clearcpuid=umip` on the boot line these two log
entries (and the gdb behavior) should disappear — a good cross-check.

### F10. Negative results (space covered, nothing found)

* No SIGSEGV/SIGFPE/SIGBUS anomalies anywhere — no instruction in the
  explored space faults in a way capstone didn't predict a length for.
* XOP (`8f …`) is gone on Zen 4: `#UD`, matching CPUID (no `xop` flag).
* Invalid EVEX (`62 01 7d 00`) #UDs consistently with disassemblers.
* `0F 79` bare #UDs at the normal 3-byte length (asymmetric with F1).
* mod=3 forms of `0F 0D /3–/7` #UD (memory-only hint opcodes).
* `f3 0f ae 28` (INCSSP-shaped) #UDs as reserved (CET disabled), as
  documented.

---

## Tools built for this analysis (all in `tools/`)

Build each with `cc -O0 -o NAME NAME.c` (`cdis` also needs `-lcapstone`; the
flake's dev shell provides gcc and capstone).

| tool | purpose |
|---|---|
| `cdis.c` | disassemble hex with the *same* libcapstone 5.0.9 the injector used |
| `probe.c` | page-boundary length/signal probe (replicates injector semantics; GPRs→scratch page instead of NULL page, so no root needed) |
| `step.c` | direct TF single-step position test — detects #DB deferral |
| `scan_shadow.sh` + `shadow_scan.txt` | full 1-byte + 0F-map scan for #DB deferral |
| `vexsem.c` | proved `c4 03 7d 00 00 ib` ≡ VPERMQ |
| `x87sem2.c` | proved `dc d0+i` ≡ FCOM st(i) semantics |
| `jcc.c` | proved `66 0f 8x rel16` executes with RIP truncated to 16 bits |
| `umip2.c` | proved SGDT/SIDT return dummy values (kernel UMIP emulation) |
| `sldtdemo2.c` | gdb `stepi` over `sldt` skips an instruction |
| `cmp.sh` | capstone-vs-objdump comparison helper |

## Recommendations for further work (where to look for bugs)

Highest value first:

1. **Report the capstone bugs.** Concrete, hardware-verified cases:
   (a) `66 0F 8x` decoded as 7-byte rel32 (should be 5-byte rel16, RIP
   truncation!); (b) LFENCE/MFENCE/SFENCE accepted only for the canonical
   rm (SDM explicitly documents E8-EF/F0-F7/F8-FF); (c) hint-NOP range
   reserved forms (`0F 18` mod=3 /0–/3, `0F 1A/1B` reg≥4, `0F 1C /1–/7`,
   `0F 1D/1E` mod=3) all rejected although they execute at the
   capstone-consistent lengths; (d) x87 aliases rejected (also objdump);
   (e) `0F 0D /3–/7` rejected. (a) is the only one that is a *length* bug
   in valid code; the rest are existence bugs.
2. **Systematic VEX.W leniency sweep on AMD.** F2 was found by accident.
   For every VEX instruction the SDM marks W1, generate the W0 variant and
   probe. Likely a whole family; each is a portability/emulation trap.
   Directed run: `./injector -i c4 -e c5 -P0 -t` plus filtering, or a
   small generator over the 0F3A map + `tools/probe`.
3. **EVEX and F2/F3-prefixed space are essentially unexplored.** This
   scan used `-P1` and the tunnel never visited F2/F3-prefixed or bare
   VEX (`c4`/`c5`) / EVEX (`62`) spaces except accidentally. Zen 4 has
   AVX-512: `62` space is the richest unexplored region (EVEX has
   broadcast/rounding/mask bits with many reserved combinations — prime
   territory for decoder quirks like F1/F2). Also run a 32-bit build
   (`make CFLAGS=-m32`): `c4`/`c5` mean LES/LDS there, and decode
   generally differs.
4. **Map the AMD #UD decoder systematically.** F1 shows AMD computes
   lengths for illegal instructions from the "nearest" decode path, and
   gets #PF-vs-#UD boundary behavior wrong relative to Intel. Sweep all
   illegal opcodes (e.g. remaining `0F 38`/`0F 3A` holes, reserved VEX
   pp/map combos) through `tools/probe` to build the #UD-length table;
   compare against an Intel machine. Useful for fingerprinting and for
   emulator validation.
5. **UMIP emulation follow-ups.** (a) Cross-check the scan with
   `clearcpuid=umip` (the F9 artifacts should vanish; also validates the
   mechanism end-to-end). (b) Decide whether the gdb stepi skip is worth
   a kernel report: the emulation path inherently defers #DB via IRET;
   userspace debuggers are misled. (c) Check KVM guests: if the host
   emulates UMIP for a guest, a guest agent sees the same fake tables —
   interesting for VM detection/sandboxing assumptions.
6. **Fix the sifter's blind spots before the next run.** (a) TF+UMIP
   corrupts length measurement for the 5 emulated instructions — either
   blacklist `0f 00`/`0f 01` reg ≤1, /4 (and sidt/sgdt forms) or detect
   and annotate them. (b) The tunnel shows strong exploration bias
   (found prefixed x87 aliases but never the bare ones; never entered
   F2/F3/VEX/EVEX space): consider seeding ranges manually with `-i`/`-e`,
   or a longer random phase. (c) `--ill` was not enabled — running it
   would catch "capstone knows it, CPU #UDs" cases (e.g. verify
   `66 0f 78` mod≠3 and VEX-with-illegal-vvvv behavior).
7. **Re-run under a hypervisor comparison.** If this box can boot the
   same kernel under KVM, a guest run would show whether the hypervisor
   intercepts/abotches any of F1–F9 (sandsifter's original use case:
   hypervisor bugs).

## Notes / caveats

* Results are specific to microcode 0xa70410a on family 25 model 116;
  re-run after a microcode update.
* `length` in the log is the *minimal decode length*, not "bytes at
  fault"; all interpretations above rely on that (see injector loop).
* The scan exited cleanly (log = sync + summary header), runtime 6h21m.
* `data/tick` shows the last-tested instruction `66 69 3c f5 8c 00`
  (66 imul …, imm16) — deep in the 66-prefix phase, consistent with a
  completed -P1 tunnel pass.
