> **Superseded.** This is the write-up of the *first* scan, whose log was
> corrupted by the `cstr2py()` UTF-8 bug described in section 0 (fixed in this
> fork's `sifter.py`). The scripts `step*.py` here are the ad-hoc passes used on
> that log (they expect `../data/log` and write intermediate `.pkl` files).
> The complete analysis of the clean rerun is [`../README.md`](../README.md).
> Two corrections from that rerun: the counts below are for the mangled log, and
> the delayed #DB on SLDT/STR/SGDT/SIDT/SMSW (section 8) is *not* a hardware
> quirk but Linux's UMIP emulation (finding F9 there).

# Analysis of the sandsifter run (Ryzen 5 7640U, Zen 4, family 25 model 116, microcode 0xa70410a)

## 0. Caveat: the log itself is corrupted by a sifter.py bug

`sifter.py`'s `cstr2py()` builds a `str` via `chr(byte)` and then calls `.encode()`,
which is **UTF-8**: every instruction byte >= 0x80 becomes two bytes
(`80`->`c2 80`, ..., `bf`->`c2 bf`, `c0`->`c3 80`, ...). Both `data/log` and
`data/sync` have their `insn` field (and the parenthesized raw dump) mangled this
way, and `insn = encoded[:length]` truncates the *expanded* byte stream, so the
recorded instruction often shares only a prefix with what was actually executed.

Example: the honest record `0f 78 80 00 ...` (length 9, SIGILL) appears in the
log as `0f78c2800000000000` — looking like an impossible 9-byte `vmread` in
register form.  Any artifact containing a byte >= 0x80 is affected (~most of the
interesting ones).  To demangle: `bytes.fromhex(field).decode('utf-8').encode('latin-1')`.

**Fixed** in sifter.py: `cstr2py()` now returns `bytes(s)` directly, and the six
call sites no longer `.encode()` the result.  Verified end-to-end: a rerun over
the `0f78` range now logs the honest forms (`0f7880...` length 9, `0f78c2...`
length 5) instead of the phantoms, and `insn == raw[:length]` holds for all
577,596 artifacts of the verification run.  (The pre-existing `data/log` and
`data/sync` are still mangled, of course - the analysis below used demangled
data; demangle with `bytes.fromhex(field).decode('utf-8').encode('latin-1')`.)

All analysis below is on the demangled data.  After demangling, all
16,116,556 artifacts fall into a small number of fully explained categories.

## 1. `0f 78` — 10,023,112 artifacts (SIGILL) — disassembler modeling gap

Capstone (and objdump) decode `0F 78 /r` as Intel `vmread`.  Zen 4 has no VMX,
so it `#UD`s — correctly.  This is only an "artifact" because capstone cannot
model feature-dependent `#UD`.

Cute detail confirmed by the minimal-length measurements: AMD's length decoder
treats `0F 78` using the SSE4a `extrq` format (modrm + imm8 + imm8), e.g.
`0f 78 00` needs 5 bytes before `#UD`, SIB/disp forms extend accordingly
(`0f 78 04 05 ...` needs 10).  SSE4a itself is alive: `66 0f 78 c0 00 00`
(extrq) executes.  The famous "undocumented AMD `0f 0f` 3DNow!" range `#UD`s
(correctly — 3DNow! was removed), and its length decoder still requires the
full modrm+imm8 before raising `#UD`.

## 2. `0f 0d /r` — 1,354,930 artifacts (SIGTRAP) — capstone gap

`0F 0D /r` = AMD's PREFETCH (`/0`) / PREFETCHW (`/1`), documented in the AMD
APM since forever, still executed by Zen 4, fault-suppressing (verified: no
fault on unmapped operand).  Reg fields /2–/7 also execute as NOPs.
capstone 5.0.7 doesn't decode any of it; objdump does.

## 3. `0f 18`–`0f 1f` hint-NOP space — ~4.75M artifacts (SIGTRAP) — capstone gaps

`0F 1A`/`0F 1B` (MPX `bnd*` slots) and `0F 1C`–`0F 1F` execute as multi-byte
NOPs on Zen 4, exactly as the Intel SDM specifies for the reserved-NOP space.
capstone fails to decode many forms (e.g. `0f 1c 08`, `0f 1a 20`, `0f 18 c0`);
objdump decodes them as `nop`/`bnd*`.  Expected CPU behavior, disassembler gap.

## 4. `66 0f 8x cw` — 1,820 artifacts (SIGTRAP) — capstone gap

16-bit conditional jumps (`66 0f 82 00 00` = `jb +0`, etc.).  The CPU executes
them in 64-bit mode; capstone refuses to decode them; objdump is fine.

## 5. `0f ae e9` — 22 artifacts (SIGTRAP) — lfence alias

`0F AE E9` (LFENCE with r/m != 0) executes.  Known class (Domas' whitepaper
documents `0f ae e9-ef` aliases).  capstone only knows `e8`; objdump decodes
`e9` as `lfence`.

## 6. `dc d0`, `dd c8`, `de d0`, `df c8` — 84 artifacts (SIGTRAP) — x87 reserved-encoding aliases

Reserved x87 mod=11 encodings (e.g. `DD C8` = DD /1, which no manual assigns)
execute without faulting.  Classic x87 decoder leniency (cf. Domas' `dbe0`,
`dbe1`, `df c0-c7` finds on other CPUs).  capstone and objdump both reject
them.

## 7. `c4 .. 7d 00 00 00` (VEX) — 40 artifacts (SIGTRAP) — AMD W-bit leniency

`C4 03 7D 00 /r ib` = VEX.256.66.0F3A.**W0** opcode 00.  Documented form is
VPERMQ with **W1**; W=0 is reserved (#UD on Intel per spec).  Zen 4 executes it
and computes exactly VPERMQ (verified the qword-select semantics against
imm8).  Opcode 01 (VPERMPD W=0) likewise executes.  All 8 R/X/B variants work.
L=0 (128-bit) still `#UD`s, so only the W bit is ignored.  Disassemblers reject
the W=0 encodings.  Category: "undocumented tolerance" — AMD/Intel decode
divergence, benign (almost certainly just WIG-style decode on AMD).

## 8. `0f 00 00` / `0f 01 00` — 46 artifacts (SIGTRAP) — real microarchitectural quirk

`SLDT`/`STR`/`SGDT`/`SIDT`/`SMSW` with memory operands execute fine (3 bytes),
but **the TF (#DB) single-step trap is delivered only after the *following*
instruction retires** — e.g. `0f 00 00; 00 00` traps at offset 5, not 3
(reproduced with an independent harness; register forms show the #DB being
similarly late).  The fuzz recorded these as length-5 instructions vs
capstone's 3.  This is a genuine hardware/microcode quirk (imprecise #DB for
the microcoded system-register stores), though benign and only observable
under single-stepping.

## Summary

No evidence of secret instructions, no exploitable hardware bugs.  The run is
dominated by (a) capstone 5.0.7 decode gaps (`0f 0d`, hint-NOP space, 16-bit
Jcc, `0f ae e9`, x87 aliases) and (b) correct-but-unmodelable behavior (VMREAD
`#UD`).  The two mildly interesting CPU findings: VPERMQ/VPERMPD W=0 leniency
and the delayed `#DB` on SLDT/STR/SGDT/SIDT/SMSW.  And the most actionable
finding is the sifter.py UTF-8 mangling bug, which corrupts the recorded form
of most artifacts in this very log.

Note: the injector's recorded "length" for faulting instructions is actually
"minimum bytes the CPU needs to see before it decides to #UD" (a page-boundary
probe), which is itself a nice side-channel into the decoder tables.
