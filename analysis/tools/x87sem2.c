/* semantics of undocumented x87 alias opcodes, using plain asm blocks.
 * For each candidate pair B0 B1: fld st1=1.0, fld st0=2.0, exec, fnstsw.
 * fcom st(0),st(0) => equal => c3c2c0 = 100. */
#include <stdio.h>
#include <stdint.h>

static double one = 1.0, two = 2.0;

#define TEST(name, b0, b1)                                     \
static void test_##name(void) {                                \
	uint16_t sw = 0;                                       \
	__asm__ volatile (                                     \
		"fldl %1\n"     /* st0 = 1.0 */                \
		"fldl %2\n"     /* st0 = 2.0, st1 = 1.0 */     \
		".byte " #b0 ", " #b1 "\n"                     \
		"fnstsw %0\n"                                  \
		"fstp %%st(0)\n"                               \
		"fstp %%st(0)\n"                               \
		: "=m"(sw)                                     \
		: "m"(one), "m"(two)                           \
		: "rax", "cc", "st", "st(1)");                 \
	printf("%-24s c3c2c0=%d%d%d\n", #name,                 \
	       (sw >> 14) & 1, (sw >> 10) & 1, (sw >> 8) & 1); \
}

TEST(d8d0_fcom_st0, 0xd8, 0xd0)
TEST(dcd0, 0xdc, 0xd0)
TEST(dcd1, 0xdc, 0xd1)
TEST(dcd8, 0xdc, 0xd8)
TEST(ddc0_ffree_st0, 0xdd, 0xc0)
TEST(ddc8, 0xdd, 0xc8)
TEST(ded9_fcompp, 0xde, 0xd9)
TEST(ded0, 0xde, 0xd0)
TEST(dfc8, 0xdf, 0xc8)
TEST(dfd0, 0xdf, 0xd0)

int main(void)
{
	test_d8d0_fcom_st0();
	test_dcd0();
	test_dcd1();
	test_dcd8();
	test_ddc0_ffree_st0();
	test_ddc8();
	test_ded9_fcompp();
	test_ded0();
	test_dfc8();
	test_dfd0();
	return 0;
}
