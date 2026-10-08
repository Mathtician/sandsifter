/* marker labels as globals so we can see addresses in gdb */
#include <stdio.h>
__asm__ (
	".globl m1,m2,m3,m4\n"
	".text\n"
	"m1: nop\n"
	"    sldt %ax\n"
	"m2: nop\n"
	"m3: ret\n"
);
extern char m1[], m2[], m3[];
int main(void) {
	void f(void);
	__asm__ (
		".globl target_fn\n"
		"target_fn:\n"
		"   nop\n"
		"   sldt %ax\n"
		"   nop\n"
		"   ret\n");
	extern void target_fn(void);
	printf("&m1=%p &m2=%p &m3=%p target_fn=%p\n", m1, m2, m3, target_fn);
	target_fn();
	printf("done\n");
	return 0;
}
