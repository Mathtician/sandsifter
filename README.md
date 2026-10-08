## About this fork

This is a fork of [laura240406/sandsifter](https://github.com/laura240406/sandsifter)
(itself a Python 3 update of [xoreaxeaxeax/sandsifter](https://github.com/xoreaxeaxeax/sandsifter))
with a working Python 3 port and a full analysis of one scan of an
**AMD Ryzen 5 7640U (Zen 4, "Phoenix")**.

Changes to the tool:

- **Fixed a logging bug that corrupted most results.** `cstr2py()` built a
  `str` and callers `.encode()`d it as UTF-8, so every instruction byte ≥ 0x80
  was logged as two bytes (and truncated to the wrong length). It now returns
  the raw bytes.
- The injector must be built with `-O0 -fno-pie` (the injection trick depends on
  `-O0` code generation and on a fixed-address immediate); the Makefile now
  forces both, since some toolchains (e.g. nixpkgs' hardened gcc) default to
  `-O2`/PIE and silently break injection.
- A Nix flake dev shell (gcc, capstone, objdump, ndisasm, uv, ...) and a `uv`
  project for the Python side.

To build and run:

```
nix develop
make
sudo uv run python sifter.py --unk --dis --len --sync --tick -- -P1 -t
uv run python summarize.py data/log
```

### Findings on Zen 4

822,308,128 instructions were tested in about 6h20m (`-P1` tunnel mode),
producing 19,301,762 anomalies. Every one of them is accounted for by about ten
root causes, each repeated under the ~22 redundant segment/REX/66 prefixes the
CPU ignores. The full write-up, with hardware-verification programs, is in
[`analysis/README.md`](analysis/README.md). In brief:

- **AMD decodes bare `0F 78` with two phantom immediate bytes before raising
  #UD** (65.7% of the log). The length comes from the SSE4a `EXTRQ` path, so
  near a page boundary you get #PF instead of #UD, which differs from Intel.
- **`VEX.W0` VPERMQ (`c4 03 7d 00 /r ib`) executes as VPERMQ** although the
  spec requires W1 (AMD ignores VEX.W), so this code runs on AMD and #UDs on Intel.
- **`66 0F 8x` (Jcc rel16) is live in 64-bit mode and truncates RIP to 16 bits.**
  Capstone mis-decodes it as a 7-byte rel32 jump.
- **SGDT/SIDT/SLDT/STR/SMSW "length anomalies" come from Linux UMIP emulation**,
  which defers the single-step #DB by one instruction. As a result, `stepi` in gdb (or
  any TF-based tracer) silently skips the following instruction.
- Undocumented x87 alias opcodes (`dc d0+i`, `dd c8+i`, `de d0+i`, `df c8+i`)
  are confirmed alive on Zen 4. Capstone and objdump both reject them.
- Capstone 5.0.9 coverage gaps, none of them CPU bugs: reserved `0F 0D` prefetch
  hints, the whole `0F 18–1F` hint-NOP space (MPX/CLDEMOTE slots), and fences
  with r/m ≠ 0 (which the SDM explicitly allows).
- Negative results: no SIGSEGV/SIGFPE/SIGBUS anomalies, XOP is gone, and
  invalid EVEX #UDs as expected.

[`analysis/first-run/`](analysis/first-run/) holds the superseded write-up of
the first scan, whose log was mangled by the bug fixed above.

### Not yet done

- Report the Capstone bugs upstream (Jcc rel16 length, fence aliases,
  hint-NOP and prefetch reserved forms, x87 aliases).
- Compare with an Intel CPU and with a run under a hypervisor (KVM guest).
- Explore the EVEX (`62`) space, along with F2/F3-prefixed and bare VEX space, which this
  tunnel-mode scan barely visited. Also sweep for VEX.W leniency
  and rerun with `--ill` and with `clearcpuid=umip`.

---

## s a n d s i f t e r 
: the x86 processor fuzzer

### Overview

The sandsifter audits x86 processors for hidden instructions and hardware bugs,
by systematically generating machine code to search through a processor's
instruction set, and monitoring execution for anomalies. Sandsifter has
uncovered secret processor instructions from every major vendor; ubiquitous
software bugs in disassemblers, assemblers, and emulators; flaws in enterprise
hypervisors; and both benign and security-critical hardware bugs in x86 chips.

With the multitude of x86 processors in existence, the goal of the tool is to
enable users to check their own systems for hidden instructions and bugs.

To run a basic audit against your processor:

```
sudo uv run python sifter.py --unk --dis --len --sync --tick -- -P1 -t
```

![demo_sandsifter](references/sandsifter.gif)

The computer is systematically scanned for anomalous instructions.  In the upper
half, you can view the instructions that the sandsifter is currently testing on
the processor.  In the bottom half, the sandsifter reports anomalies it finds.

The search will take from a few hours to a few days, depending on the speed of
and complexity of your processor.  When it is complete, summarize the results:

```
uv run python summarize.py data/log
```

![demo_summarizer](references/summarizer.png)

Typically, several million undocumented instructions on your processor will be
found, but these generally fall into a small number of different groups.  After
binning the anomalies, the summarize tool attempts to assign each instruction to
an issue category:

* Software bug (for example, a bug in your hypervisor or disassembler),
* Hardware bug (a bug in your CPU), or
* Undocumented instruction (an instruction that exists in the processor, but is
  not acknowledged by the manufacturer)

Press 'Q' to quit and obtain a text based summary of the system scan:

The results of a scan can sometimes be difficult for the tools to automatically
classify, and may require manual analysis. For help analyzing your results, feel
free to send the ./data/log file to xoreaxeaxeax@gmail.com.  No personal
information, other than the processor make, model, and revision (from
/proc/cpuinfo) are included in this log.


### Results

Scanning with the sandsifter has uncovered undocumented processor features
across dozens of opcode categories, flaws in enterprise hypervisors, bugs in
nearly every major disassembly and emulation tool, and critical hardware bugs
opening security vulnerabilities in the processor itself.

Details of the results can be found in the project 
[whitepaper](./references/domas_breaking_the_x86_isa_wp.pdf).

(TODO: detailed results enumeration here)


### Building

Sandsifter requires first installing the Capstone disassembler:
http://www.capstone-engine.org/.  Capstone can typically be installed with:

```
sudo apt-get install libcapstone3 libcapstone-dev
sudo pip install capstone
```

Sandsifter can be built with:

```
make
```

and is then run with 

```
sudo ./sifter.py --unk --dis --len --sync --tick -- -P1 -t
```

### Flags

Flags are passed to the sifter with --flag, and to the injector with -- -f.

Example:

```
sudo ./sifter.py --unk --dis --len --sync --tick -- -P1 -t
```

Sifter flags:

```
--len
	search for length differences in all instructions (instructions that
	executed differently than the disassembler expected, or did not
	exist when the disassembler expected them to

--dis
	search for length differences in valid instructions (instructions that
	executed differently than the disassembler expected)

--unk
	search for unknown instructions (instructions that the disassembler doesn't
	know about but successfully execute)

--ill
	the inverse of --unk, search for invalid disassemblies (instructions that do
	not successfully execute but that the disassembler acknowledges)

--tick
	periodically write the current instruction to disk

--save
	save search progress on exit

--resume
	resume search from last saved state

--sync
	write search results to disk as they are found

--low-mem
	do not store results in memory
```

Injector flags:

```
-b
	mode: brute force

-r
	mode: randomized fuzzing

-t
	mode: tunneled fuzzing

-d
	mode: externally directed fuzzing

-R
	raw output mode

-T
	text output mode

-x
	write periodic progress to stderr

-0
	allow null dereference (requires sudo)

-D
	allow duplicate prefixes

-N
	no nx bit support

-s seed
	in random search, seed value

-B brute_depth
	in brute search, maximum search depth

-P max_prefix
	maximum number of prefixes to search

-i instruction
	instruction at which to start search (inclusive)

-e instruction
	instruction at which to end search (exclusive)

-c core
	core on which to perform search

-X blacklist
	blacklist the specified instruction

-j jobs
	number of simultaneous jobs to run

-l range_bytes
	number of base instruction bytes in each sub range
```


### Keys

m: Mode - change the search mode (brute force, random, or tunnel) for the sifter

q: Quit - exit the sifter

p: Pause - pause or unpause the search


### Algorithms

The scanning supports four different search algorithms, which can be set at the
command line, or cycled via hotkeys.

* Random searching generates random instructions to test; it generally produces
  results quickly, but is unable to find complex hidden instructions and bugs.
* Brute force searching tries instructions incrementally, up to a user-specified
  length; in almost all situations, it performs worse than random searching.
* Driven or mutation driven searching is designed to create new, increasingly
  complex instructions through genetic algorithms; while promising, this
  approach was never fully realized, and is left as a stub for future research.
* Tunneling is the approach described in the presentation and white paper, and
  in almost all cases provides the best trade-off between thoroughness and
  speed.


### Tips

* sudo

	For best results, the tool should be run as the root user.  This is necessary so
	that the process can map into memory a page at address 0, which requires root
	permissions.  This page prevents many instructions from seg-faulting on memory
	accesses, which allows a more accurate fault analysis.

* Prefixes

	The primary limitation for the depth of an instruction search is the number
	of prefix bytes to explore, with each additional prefix byte increasing the
	search space by around a factor of 10.  Limit prefix bytes with the -P flag.

* Colors

	The interface for the sifter is designed for a 256 color terminal.  While
	the details vary greatly depending on your terminal, this can roughly be
	accomplished with:

	```
	export TERM='xterm-256color'
	```

* GUI

	The interface assumes the terminal is of at least a certain size; if the
	interface is not rendering properly, try increasing the terminal size; this
	can often be accomplished by decreasing the terminal font size.

	In some cases, it may be desirable or necessary to run the tool without the
	graphical front end.  This can be done by running the injector directly:

	```
	sudo ./injector -P1 -t -0
	```

	To filter the results of a direct injector invocation, grep can be used.
	For example,

	```
	sudo ./injector -P1 -r -0 | grep '\.r' | grep -v sigill
	```

	searches for instructions for which the processor and disassembler disagreed
	on the instruction length (grep '\.r'), but the instruction successfully
	executed (grep -v sigill).

* Targeted fuzzing

	In many cases, it is valuable to direct the fuzzer to a specific target.
	For example, if you suspect that an emulator has flaws around repeated 'lock'
	prefixes (0xf0), you could direct the fuzzer to search this region of the
	instruction space with the -i and -e flags:

	```
	sudo ./sifter.py --unk --dis --len --sync --tick -- -t -i f0f0 -e f0f1 -D -P15
	```

* Legacy systems

	For scanning much older systems (i586 class processors, low memory systems),
	pass the --low-mem flag to the sifter and the -N flag to the injector:

	```
	sudo ./sifter.py --unk --dis --len --sync --tick --low-mem -- -P1 -t -N
	```

	If you observe your scans completing too quickly (for example, a scan
	completes in seconds), it is typically because these flags are required for
	the processor you are scanning.

* 32 vs. 64 bit

	By default, sandsifter is built to target the bitness of the host operating
	system.  However, some instructions have different behaviors when run in a
	32 bit process compared to when run in a 64 bit process.  To explore these
	scenarios, it is sometimes valuable to run a 32 bit sandsifter on a 64 bit
	system.

	To build a 32 bit sandsifter on a 64 bit system, Capstone must be installed
	as 32 bit; the instructions for this can be found at http://www.capstone-engine.org/.

	Then sandsifter must be built for a 32 bit architecture:

	```
	make CFLAGS=-m32
	```

	With this, the 32 bit instruction space can be explored on a 64 bit system.


### References

* A discussion of the techniques and results can be found in the Black Hat
  [presentation](https://www.youtube.com/watch?v=KrksBdWcZgQ).
* Technical details are described in the
  [whitepaper](./references/domas_breaking_the_x86_isa_wp.pdf).
* Slides from the Black Hat presentation are
  [here](./references/domas_breaking_the_x86_isa.pdf).


### Author

sandsifter is a research effort from Christopher Domas
([@xoreaxeaxeax](https://twitter.com/xoreaxeaxeax)).

