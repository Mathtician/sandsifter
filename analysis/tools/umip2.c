#include <stdio.h>
#include <stdint.h>
int main(void) {
	uint8_t g[16] = {0}, i[16] = {0};
	uint16_t l = 0, tr = 0, msw = 0;
	__asm__ volatile("sgdt %0" : "=m"(g));
	__asm__ volatile("sidt %0" : "=m"(i));
	__asm__ volatile("sldt %0" : "=m"(l));
	__asm__ volatile("str %0" : "=m"(tr));
	__asm__ volatile("smsw %0" : "=m"(msw));
	uint64_t gb = *(uint64_t*)(g+2); uint16_t gl = *(uint16_t*)g;
	uint64_t ib = *(uint64_t*)(i+2); uint16_t il = *(uint16_t*)i;
	printf("gdtr base=%016lx limit=%04x\n", gb, gl);
	printf("idtr base=%016lx limit=%04x\n", ib, il);
	printf("ldtr=%04x tr=%04x msw=%04x\n", l, tr, msw);
	printf("sgdt again: ");
	__asm__ volatile("sgdt %0" : "=m"(g));
	gb = *(uint64_t*)(g+2); gl = *(uint16_t*)g;
	printf("base=%016lx limit=%04x\n", gb, gl);
	return 0;
}
