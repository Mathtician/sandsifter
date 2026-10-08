/* does 66 0F 8x take a rel16 (5 bytes) or rel32 (7 bytes) in 64-bit mode?
 * layout: jb16=66 0F 82 <rel16>; if rel16 -> lands at "good", if rel32 ->
 * misdecodes, different target. We set CF=1 so jb is taken. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
int main(void) {
	uint8_t *c = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
	                  MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	assert(c != MAP_FAILED);
	uint8_t *p = c;
	/* stc; 66 0f 82 rel16 -> skip 0x0100 bytes forward to "good" marker.
	 * If CPU used rel32 (imm bytes 00 01 41 xx), target would differ. */
	*p++ = 0xf9; /* stc */
	uint8_t jb[] = { 0x66, 0x0f, 0x82, 0x00, 0x01 }; /* jb +0x100 */
	memcpy(p, jb, 5); p += 5;
	/* fill with int3-ish garbage so wrong-length jumps crash */
	memset(p, 0xcc, 0x100); p += 0x100;
	/* good: mov eax, 0x1234; ret */
	*p++ = 0xb8; *(uint32_t*)p = 0x1234; p += 4; *p++ = 0xc3;
	uint32_t r;
	__asm__ __volatile__ ("call *%1" : "=a"(r) : "r"(c) : "memory", "cc");
	printf("result: %#x (%s)\n", r, r == 0x1234 ? "rel16 confirmed" : "WRONG");
	return 0;
}
