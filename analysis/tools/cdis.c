/* cdis: disassemble hex bytes from stdin (one per line) with capstone 5.0.9,
 * 64-bit mode, exactly as the sandsifter injector does.
 * usage: echo 0f0d18 | ./cdis        -> "3 prefetch [rax]" style output
 *        ./cdis < hexlines           -> one output line per input line
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>

int main(void) {
    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) != CS_ERR_OK) return 1;
    cs_insn *insn = cs_malloc(h);
    char line[4096];
    while (fgets(line, sizeof line, stdin)) {
        /* strip whitespace/newline; allow optional trailing text after space */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        char hex[64]; int hi = 0;
        while (((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) && hi < 62)
            hex[hi++] = *p++;
        hex[hi] = 0;
        if (hi == 0 || hi % 2) { printf(".\t(invalid)\n"); continue; }
        unsigned char buf[31];
        for (int i = 0; i < hi/2; i++)
            buf[i] = (unsigned char)strtol((char[]){hex[2*i], hex[2*i+1], 0}, NULL, 16);
        /* pad with zeros to 16 bytes like the injector does */
        for (int i = hi/2; i < 16; i++) buf[i] = 0;
        const uint8_t *code = buf;
        size_t size = 16;
        uint64_t addr = 0x1000;
        if (cs_disasm_iter(h, &code, &size, &addr, insn)) {
            printf("%d\t%s %s\n", insn[0].size, insn[0].mnemonic, insn[0].op_str);
        } else {
            printf("0\t(unk)\n");
        }
    }
    cs_free(insn, 1);
    cs_close(&h);
    return 0;
}
