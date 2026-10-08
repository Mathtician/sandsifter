/* vexsem: determine the semantics of c4 03 7d 00 00 ib
 * (VEX.66.0F3A.W0 opcode 00 - documented form is VPERMQ with W=1 only).
 * Executes it on a known memory operand, stores ymm0, prints qwords.
 * Compare against vpermq (W=1 form, c4 03 fd 00 00 ib): qword q[imm&3]
 * broadcast pattern etc. (vpermq selects 4 qwords by 2-bit fields).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <assert.h>

int main(void)
{
	uint8_t *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
	                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	uint64_t *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
	                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(code != MAP_FAILED && mem != MAP_FAILED);
	uint64_t out[4] = {0, 0, 0, 0};
	for (int i = 0; i < 4; i++) mem[i] = 0x1000 + i;

	/* code: <test insn with modrm [r8] + imm8>; vmovdqu [r9], ymm0; ret
	 * test insn: c4 03 7d 00 00 ib   (modrm 00 -> [r8], B=1 -> r8)
	 * vmovdqu [r9],ymm0: c4 01 7e 7f 01  (VEX.66.0F.W0 7F /r, modrm 01 -> [r9])
	 */
	uint8_t *p = code;
	uint8_t t[] = { 0xc4, 0x03, 0x7d, 0x00, 0x00, 0x1b };
	memcpy(p, t, sizeof t); p += sizeof t;
	uint8_t s[] = { 0xc4, 0x01, 0x7e, 0x7f, 0x01, 0xc3 };
	memcpy(p, s, sizeof s); p += sizeof s;

	__asm__ __volatile__ (
		"mov %1, %%r8\n"
		"mov %2, %%r9\n"
		"call *%0\n"
		:
		: "r"(code), "r"(mem), "r"(out)
		: "r8", "r9", "ymm0", "memory", "cc");

	printf("input : %lx %lx %lx %lx\n", mem[0], mem[1], mem[2], mem[3]);
	printf("output: %lx %lx %lx %lx\n", out[0], out[1], out[2], out[3]);
	printf("(vpermq imm=0x1b would give: q0,q2,q3,q0 = 1000 1002 1003 1000)\n");
	return 0;
}
