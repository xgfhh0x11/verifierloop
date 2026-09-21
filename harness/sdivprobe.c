// sdivprobe — hand-written probe for the round-215 REG INVARIANTS VIOLATION (alu).
// Standalone (own macros, own bpf() wrapper) so it never touches diffharness.c, which a
// hunt round rebuilds. The round-215 finding: `w7 s/= w9` with both operands full-range u32
// (divisor including 0 and negative) made reg_bounds_sanity_check WARN at verifier.c:2211 —
// the reg-invariants class (F2), but via check_alu_op (signed division), NOT sync_linked_regs.
// Each arm isolates one signed ALU op; udiv32 is the control that must NOT warn.
// The WARN is a kernel printk -> serial console; this only prints the load verdict.
// Build: cc -O2 -static -o harness/sdivprobe harness/sdivprobe.c
#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#define BPF_MOV64_IMM(DST, IMM) ((struct bpf_insn){.code=BPF_ALU64|BPF_MOV|BPF_K,.dst_reg=DST,.src_reg=0,.off=0,.imm=IMM})
#define BPF_MOV32_REG(DST, SRC) ((struct bpf_insn){.code=BPF_ALU|BPF_MOV|BPF_X,.dst_reg=DST,.src_reg=SRC,.off=0,.imm=0})
#define BPF_EMIT_CALL(F)        ((struct bpf_insn){.code=BPF_JMP|BPF_CALL,.dst_reg=0,.src_reg=0,.off=0,.imm=(F)})
#define BPF_EXIT_INSN()         ((struct bpf_insn){.code=BPF_JMP|BPF_EXIT,.dst_reg=0,.src_reg=0,.off=0,.imm=0})
/* signed div/mod carry off=1; 32-bit uses BPF_ALU, 64-bit BPF_ALU64. */
#define ALU_REG(CLASS,OP,DST,SRC,OFF) ((struct bpf_insn){.code=(CLASS)|BPF_OP(OP)|BPF_X,.dst_reg=DST,.src_reg=SRC,.off=OFF,.imm=0})

static int bpf(int cmd, union bpf_attr *a, unsigned int s){ return syscall(__NR_bpf, cmd, a, s); }
static char g_log[1<<20];

struct arm { const char *name; int class_; int op; int off; };

int main(void){
    struct arm arms[] = {
        {"sdiv32", BPF_ALU,   BPF_DIV, 1},   /* w7 s/= w9  — the round-215 shape */
        {"smod32", BPF_ALU,   BPF_MOD, 1},   /* w7 s%= w9 */
        {"sdiv64", BPF_ALU64, BPF_DIV, 1},   /* r7 s/= r9 (operands still u32-range) */
        {"smod64", BPF_ALU64, BPF_MOD, 1},
        {"udiv32", BPF_ALU,   BPF_DIV, 0},   /* CONTROL: unsigned, must not warn */
    };
    for (unsigned i=0;i<sizeof(arms)/sizeof(arms[0]);i++){
        struct arm *A=&arms[i];
        struct bpf_insn ins[16]; int n=0;
        ins[n++]=BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32); /* r0 = full u32 */
        ins[n++]=BPF_MOV32_REG(7,0);                      /* r7 = full u32 (dividend) */
        ins[n++]=BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32);
        ins[n++]=BPF_MOV32_REG(9,0);                      /* r9 = full u32 (divisor, incl 0/neg) */
        ins[n++]=ALU_REG(A->class_, A->op, 7, 9, A->off); /* w7 (s)/(s%)= w9 */
        ins[n++]=BPF_MOV64_IMM(0,0);
        ins[n++]=BPF_EXIT_INSN();

        g_log[0]='\0';
        union bpf_attr attr; memset(&attr,0,sizeof(attr));
        attr.prog_type=BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt=n; attr.insns=(uint64_t)(unsigned long)ins;
        attr.license=(uint64_t)(unsigned long)"GPL";
        attr.log_level=2; attr.log_size=sizeof(g_log); attr.log_buf=(uint64_t)(unsigned long)g_log;
        printf("===SDIVPROBE arm=%s (expect warn unless udiv) ===\n", A->name);
        fflush(stdout);
        int fd=bpf(BPF_PROG_LOAD,&attr,sizeof(attr)); int err=errno;
        if(fd>=0) close(fd);
        /* print the tail of the verifier log where the offending insn's state prints */
        char *last=g_log; for(char *p=g_log;*p;p++) if(*p=='\n' && p[1]) last=p+1;
        printf("SDIVRESULT arm=%s decision=%s errno=%d\n", A->name, fd>=0?"accept":"reject", fd>=0?0:err);
        fflush(stdout);
    }
    return 0;
}
