/* probe: measure, for a given instruction byte sequence, the minimum number of
 * bytes the CPU needs before the instruction is complete ("consumed length"),
 * and what signal (if any) its execution raises.
 *
 * Faithfully replicates the sandsifter injector's method:
 *   - one RWX page; the instruction is placed so it ENDS at the page boundary
 *   - the following page is RW-but-not-executable (like the injector's
 *     nx_support path), so instruction fetch across the boundary faults
 *     while data accesses (e.g. rip-relative) succeed
 *   - the packet contains the TF-setting preamble (pushfq; orq $TF,(%rsp);
 *     popfq) immediately before the instruction under test, so that a cleanly
 *     executed instruction raises SIGTRAP with RIP just past the instruction
 *   - for i = 1..15, place i bytes at the page end and jump in; stop at the
 *     first i that does not produce an instruction-fetch fault at the boundary
 *
 * Difference vs. the injector: general purpose registers point at a RW
 * scratch page (the injector uses 0 and maps the null page, which needs root;
 * for the modrm.memory cases we probe here, a mapped scratch page behaves the
 * same). rsp points at a dummy stack, like the injector.
 *
 * usage: ./probe 0f00000000
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <assert.h>

#define PAGE 4096
#define TF 0x100

static uint8_t *packet_page;   /* RWX */
static uint8_t *next_page;     /* RW, no-exec */
static uint8_t *scratch;       /* RW data page for register values */
static uint8_t *dstack;        /* RW dummy stack */
static uint8_t insn[15];
static int insn_len;

static volatile sig_atomic_t got_sig;
static volatile sig_atomic_t got_code;
static volatile uintptr_t got_ip;
static volatile uintptr_t got_addr;
static volatile uintptr_t base_ip; /* address of instruction start */

static sigjmp_buf jmpbuf;

static void handler(int sig, siginfo_t *si, void *p)
{
	ucontext_t *uc = p;
	got_sig = sig;
	got_code = si->si_code;
	got_ip = uc->uc_mcontext.gregs[REG_RIP];
	got_addr = (uintptr_t)si->si_addr;
	uc->uc_mcontext.gregs[REG_EFL] &= ~TF;
	siglongjmp(jmpbuf, 1);
}

static void install_handlers(void)
{
	struct sigaction s;
	memset(&s, 0, sizeof s);
	s.sa_sigaction = handler;
	s.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigfillset(&s.sa_mask);
	sigaction(SIGILL, &s, NULL);
	sigaction(SIGSEGV, &s, NULL);
	sigaction(SIGFPE, &s, NULL);
	sigaction(SIGBUS, &s, NULL);
	sigaction(SIGTRAP, &s, NULL);
	stack_t ss;
	ss.ss_sp = malloc(64 * 1024);
	ss.ss_flags = 0;
	ss.ss_size = 64 * 1024;
	sigaltstack(&ss, 0);
}

/* runner(pkt, scratch, stack): load all GPRs from scratch, rsp from stack,
 * jump to pkt. */
__asm__ (
	".globl runner\n"
	"runner:\n"
	"	mov %rsi, %rax\n"
	"	mov %rsi, %rbx\n"
	"	mov %rsi, %rcx\n"
	"	mov %rsi, %rdx\n"
	"	mov %rsi, %rbp\n"
	"	mov %rsi, %r8\n"
	"	mov %rsi, %r9\n"
	"	mov %rsi, %r10\n"
	"	mov %rsi, %r11\n"
	"	mov %rsi, %r12\n"
	"	mov %rsi, %r13\n"
	"	mov %rsi, %r14\n"
	"	mov %rsi, %r15\n"
	"	mov %rdx, %rsp\n"
	"	mov %rsi, %rsi\n"
	"	jmp *%rdi\n"
);

extern void runner(void *pkt, void *scratch, void *stack);

/* pushfq; orq $0x100,(%rsp); popfq */
static const uint8_t preamble[] = { 0x9c, 0x48, 0x81, 0x0c, 0x24,
                                    0x00, 0x01, 0x00, 0x00, 0x9d };
#define PREAMBLE_LEN 10

/* run i bytes of insn at the end of packet_page. fills got_*. */
static void run_len(int i)
{
	uint8_t *pkt = packet_page + PAGE - i - PREAMBLE_LEN;
	memset(packet_page, 0, PAGE);
	memcpy(pkt, preamble, PREAMBLE_LEN);
	memcpy(pkt + PREAMBLE_LEN, insn, i);
	got_sig = 0;
	base_ip = (uintptr_t)pkt + PREAMBLE_LEN;
	if (sigsetjmp(jmpbuf, 1)) return;  /* handler jumped back here */
	runner(pkt, scratch, dstack + PAGE / 2);
	fprintf(stderr, "[dbg] runner returned?!\n");
}

static const char *signame(int s)
{
	switch (s) {
	case SIGILL: return "ILL ";
	case SIGSEGV: return "SEGV";
	case SIGFPE: return "FPE ";
	case SIGBUS: return "BUS ";
	case SIGTRAP: return "TRAP";
	}
	return "?";
}

int main(int argc, char **argv)
{
	if (argc != 2) { fprintf(stderr, "usage: %s <hex>\n", argv[0]); return 2; }
	const char *h = argv[1];
	insn_len = strlen(h) / 2;
	if (insn_len < 1 || insn_len > 15 || strlen(h) % 2) {
		fprintf(stderr, "bad hex\n"); return 2;
	}
	for (int i = 0; i < insn_len; i++)
		insn[i] = strtol((char[]){h[2*i], h[2*i+1], 0}, NULL, 16);

	uint8_t *buf = malloc(PAGE * 2);
	packet_page = (uint8_t *)(((uintptr_t)buf + PAGE - 1) & ~(uintptr_t)(PAGE - 1));
	next_page = packet_page + PAGE;
	assert(!mprotect(packet_page, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC));
	assert(!mprotect(next_page, PAGE, PROT_READ | PROT_WRITE));
	scratch = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
	               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	dstack = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
	              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(scratch != MAP_FAILED && dstack != MAP_FAILED);

	install_handlers();

	uintptr_t boundary = (uintptr_t)packet_page + PAGE;
	int final = -1;
	for (int i = 1; i <= insn_len && i <= 15; i++) {
		run_len(i);
		long consumed = (long)(got_ip - base_ip);
		if (consumed < 0 || consumed > 15) consumed = 0; /* faulting insn */
		int is_fetch_fault = (got_sig == SIGSEGV) &&
		                     (got_addr == boundary);
		printf("i=%2d sig=%s code=%2d consumed=%ld addr=%p %s\n",
		       i, signame(got_sig), got_code, consumed,
		       (void *)got_addr,
		       is_fetch_fault ? "(fetch crossed boundary)" :
		       (got_sig == SIGTRAP ? "(executed)" : "(faulted)"));
		final = i;
		if (!is_fetch_fault) break;
	}
	printf("=> consumed length %d, final sig %s code %d\n",
	       final, signame(got_sig), got_code);
	return 0;
}
