/* check if UMIP is actually enforced: sgdt at CPL3 should #GP if so */
#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
static sigjmp_buf jb;
static void h(int s, siginfo_t *si, void *p) {
	printf("fault: sig=%d code=%d (%s)\n", s, si->si_code,
	       si->si_code == 128 ? "SI_KERNEL/#GP" : "other");
	siglongjmp(jb, 1);
}
int main(void) {
	struct sigaction sa = {0};
	sa.sa_sigaction = h; sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	sigaction(SIGSEGV, &sa, 0); sigaction(SIGILL, &sa, 0);
	uint8_t buf[16] = {0};
	if (!sigsetjmp(jb, 1)) {
		__asm__ volatile("sgdt %0" : "=m"(buf));
		printf("sgdt executed at CPL3, gdtr: base=%02x%02x%02x%02x%02x%02x limit=%02x%02x\n",
		       buf[9], buf[8], buf[7], buf[6], buf[5], buf[4], buf[1], buf[0]);
	}
	if (!sigsetjmp(jb, 1)) {
		__asm__ volatile("sldt %0" : "=m"(buf));
		printf("sldt executed at CPL3\n");
	}
	if (!sigsetjmp(jb, 1)) {
		__asm__ volatile("str %0" : "=m"(buf));
		printf("str executed at CPL3\n");
	}
	if (!sigsetjmp(jb, 1)) {
		__asm__ volatile("smsw %0" : "=m"(buf));
		printf("smsw executed at CPL3\n");
	}
	return 0;
}
