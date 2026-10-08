/* step: directly test trap-flag (#DB) delivery position for a given
 * instruction. Executes, in an RWX buffer:
 *
 *   pushfq; orq $TF,(%rsp); popfq; <INSN>; nop x8
 *
 * With TF set, #DB should be delivered immediately after <INSN>, with
 * RIP = insn_start + insn_len. If the instruction defers the trap (like
 * mov ss / pop ss / sti do), RIP will be further along.
 *
 * All GPRs point at a RW scratch page, rsp at a dummy stack.
 * Prints: insn, signal, si_code, and trap_offset = RIP - insn_start.
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

static uint8_t *codebuf;
static uint8_t *scratch;
static uint8_t *dstack;

static volatile sig_atomic_t got_sig;
static volatile sig_atomic_t got_code;
static volatile uintptr_t got_ip;

static sigjmp_buf jmpbuf;

static void handler(int sig, siginfo_t *si, void *p)
{
	ucontext_t *uc = p;
	got_sig = sig;
	got_code = si->si_code;
	got_ip = uc->uc_mcontext.gregs[REG_RIP];
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
	stack_t ss = { .ss_sp = malloc(64 * 1024), .ss_flags = 0,
	               .ss_size = 64 * 1024 };
	sigaltstack(&ss, 0);
}

__asm__ (
	".globl runner2\n"
	"runner2:\n"
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
extern void runner2(void *pkt, void *scratch, void *stack);

/* pushfq; orq $0x100,(%rsp); popfq */
static const uint8_t preamble[] = { 0x9c, 0x48, 0x81, 0x0c, 0x24,
                                    0x00, 0x01, 0x00, 0x00, 0x9d };
#define PREAMBLE_LEN 10

int main(int argc, char **argv)
{
	if (argc != 2) { fprintf(stderr, "usage: %s <hex>\n", argv[0]); return 2; }
	const char *h = argv[1];
	int n = strlen(h) / 2;
	if (n < 1 || n > 15 || strlen(h) % 2) { fprintf(stderr, "bad hex\n"); return 2; }
	uint8_t insn[15];
	for (int i = 0; i < n; i++)
		insn[i] = strtol((char[]){h[2*i], h[2*i+1], 0}, NULL, 16);

	codebuf = mmap(NULL, PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
	               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	scratch = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
	               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	dstack = mmap(NULL, PAGE, PROT_READ | PROT_WRITE,
	              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(codebuf != MAP_FAILED && scratch != MAP_FAILED && dstack != MAP_FAILED);

	uint8_t *p = codebuf;
	memcpy(p, preamble, PREAMBLE_LEN);
	p += PREAMBLE_LEN;
	uint8_t *insn_start = p;
	memcpy(p, insn, n);
	p += n;
	memset(p, 0x90, 8); /* nop x8 */

	install_handlers();

	if (!sigsetjmp(jmpbuf, 1))
		runner2(codebuf, scratch, dstack + PAGE / 2);

	long off = (long)(got_ip - (uintptr_t)insn_start);
	printf("insn=%s sig=%d code=%d trap_offset=%ld insn_len=%d %s\n",
	       h, got_sig, got_code, off, n,
	       (got_sig == SIGTRAP && off == n) ? "normal" :
	       (got_sig == SIGTRAP && off > n) ? "DEFERRED (#DB shadow)" :
	       "fault/other");
	return 0;
}
