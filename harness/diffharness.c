// verifierloop differential/verifier-log harness (v0) — GUEST-SIDE.
//
// Purpose: produce the verifier-SEMANTIC CORE signal that syzkaller does NOT emit
// on its own — the verifier's accept/reject decision plus its register-state
// evolution — by loading small BPF programs with log_level=2 and capturing the
// kernel verifier log buffer VERBATIM. This is the real raw input the normalize
// stage's verifier-log parser will interpret into CoreMetrics.
//
// Why C (not Rust): raw bpf() syscall, zero deps, statically buildable, trivially
// runs both on the host and inside the disposable Debian VM. Matches the project's
// "collect DEFAULT native output UNCHANGED" principle — the verifier log is emitted
// byte-for-byte; only a minimal per-program frame is added around it.
//
// NOTE on JIT<->interpreter: the primary hunt kernel is built with
// CONFIG_BPF_JIT_ALWAYS_ON=y, so the interpreter is compiled OUT and a
// single-kernel JIT/interp retval differential is IMPOSSIBLE. That signal needs a
// separate interpreter-only kernel (bpf_jit_enable=0) and is deferred to a later
// cross-kernel harness mode. v0 produces decision + register-state only.
//
// Output: a simple line-framed native format on stdout (one block per program):
//   ===PROG <name> type=<t> ===
//   RESULT decision=<accept|reject> fd=<n|-1> errno=<e> load_ns=<n>
//   ---LOG---
//   <raw verifier log, verbatim>
//   ---END---
//
// Build:  cc -O2 -static -o diffharness diffharness.c   (or without -static)
// Run:    ./diffharness            (needs CAP_SYS_ADMIN / root for BPF_PROG_LOAD)

#define _GNU_SOURCE
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

// --- minimal BPF insn encoding (classic macros from the kernel samples) ------
#define BPF_ALU64_IMM(OP, DST, IMM)                                            \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_K,                 \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
#define BPF_MOV64_IMM(DST, IMM)                                                \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_K,                    \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
#define BPF_MOV64_REG(DST, SRC)                                                \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_X,                    \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_JMP_IMM(OP, DST, IMM, OFF)                                         \
    ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_K,                   \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                                       \
    ((struct bpf_insn){.code = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,             \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
#define BPF_ST_MEM(SIZE, DST, OFF, IMM)                                        \
    ((struct bpf_insn){.code = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,              \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
#define BPF_STX_MEM(SIZE, DST, SRC, OFF)                                       \
    ((struct bpf_insn){.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,             \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
// Pseudo LD_IMM64 loading a map fd. Occupies TWO insn slots — the macro expands
// to both, exactly as the kernel's own bpf_insn.h spells it (and as
// Documentation/bpf/verifier.rst writes it in its examples).
#define BPF_LD_MAP_FD(DST, FD)                                                 \
    ((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = DST,      \
                       .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = (FD)}),  \
    ((struct bpf_insn){0})
#define BPF_EMIT_CALL(FUNC)                                                    \
    ((struct bpf_insn){.code = BPF_JMP | BPF_CALL,                             \
                       .dst_reg = 0, .src_reg = 0, .off = 0, .imm = (FUNC)})
#define BPF_EXIT_INSN()                                                        \
    ((struct bpf_insn){.code = BPF_JMP | BPF_EXIT,                             \
                       .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0})

static int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static char g_log[256 * 1024];

// Load one program with log_level=2 and print its native frame.
//
// `prog_type`/`type_name` and `prog_flags` are explicit because a few documented
// cases are only reachable under a specific program type (the socket helpers are
// not callable from a socket filter) or a specific load flag (strict alignment).
// The header line stays byte-identical for the default socket_filter/no-flag
// programs — the extra `flags=` field is printed only when a flag is actually set.
static void run_one_ex(const char *name, const struct bpf_insn *insns, int n,
                       int prog_type, const char *type_name, uint32_t prog_flags) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = prog_type;
    attr.prog_flags = prog_flags;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;                            // full register-state evolution
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=%s%s ===\n", name, type_name,
           prog_flags & BPF_F_STRICT_ALIGNMENT ? " flags=strict_alignment" : "");
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);
    printf("---LOG---\n%s\n---END---\n", g_log);
    if (fd >= 0)
        close(fd);
}

// Default program shape: socket filter, no load flags (loadable as root, no attach).
static void run_one(const char *name, const struct bpf_insn *insns, int n) {
    run_one_ex(name, insns, n, BPF_PROG_TYPE_SOCKET_FILTER, "socket_filter", 0);
}

// Create a small ARRAY map and run a CORRECT bpf_map_lookup_elem(&map, &key) call
// so the verifier log shows a real helper-call site (arg register types at the
// call). This is what the verifier-log parser extracts as the OBSERVED arg type.
static void run_map_lookup(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 8;
    m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG map_lookup type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n"
               "---LOG---\n---END---\n", errno);
        return;
    }
    struct bpf_insn insns[] = {
        BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),   // *(u32*)(r10-4) = 0  (key on stack)
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),   // r2 = r10
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),  // r2 = &key (PTR_TO_STACK) = arg1
        // r1 = map (pseudo LD_MAP_FD, 2 slots) = arg0
        ((struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                           .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd}),
        ((struct bpf_insn){0}),
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    run_one("map_lookup", insns, (int)(sizeof(insns) / sizeof(insns[0])));
    close(map_fd);
}

// ---------------------------------------------------------------------------
// DOCUMENTED-BEHAVIOUR CASES (ground-truth source 2).
//
// Each program below is the pseudo-asm example printed in
// Documentation/bpf/verifier.rst, translated to real insns. The label matches a
// `DocumentedCase::id` in pipeline::groundtruth::verifier_rst, where the
// document's own sentence is quoted and anchor-checked. The EXPECTED outcome
// lives there (from the doc); this file only supplies the program.
//
// The pseudo-asm -> insn translation is a reviewable judgement, kept literal:
// register numbers and instruction kinds follow the document exactly.
// ---------------------------------------------------------------------------
static void run_documented_cases(void) {
    // verifier.rst:25-30 — "If register was never written to, it's not readable"
    //   bpf_mov R0 = R2
    //   bpf_exit
    struct bpf_insn doc_unreadable_reg[] = {
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_2),
        BPF_EXIT_INSN(),
    };

    // verifier.rst:37-45 — "Since R6-R9 are callee saved, their state is preserved
    // across the call" ... "is a correct program".
    //   bpf_mov R6 = 1 ; bpf_call foo ; bpf_mov R0 = R6 ; bpf_exit
    // `foo` is instantiated as a helper callable from a socket filter.
    struct bpf_insn doc_callee_saved_r6[] = {
        BPF_MOV64_IMM(BPF_REG_6, 1),
        BPF_EMIT_CALL(BPF_FUNC_get_prandom_u32),
        BPF_MOV64_REG(BPF_REG_0, BPF_REG_6),
        BPF_EXIT_INSN(),
    };

    // verifier.rst:49-56 — load/store only with valid pointer types; the example
    //   bpf_mov R1 = 1 ; bpf_mov R2 = 2 ; bpf_xadd *(u32 *)(R1 + 3) += R2 ; bpf_exit
    // "will be rejected, since R1 doesn't have a valid pointer type".
    struct bpf_insn doc_bad_ptr_xadd[] = {
        BPF_MOV64_IMM(BPF_REG_1, 1),
        BPF_MOV64_IMM(BPF_REG_2, 2),
        ((struct bpf_insn){.code = BPF_STX | BPF_W | BPF_ATOMIC,
                           .dst_reg = BPF_REG_1, .src_reg = BPF_REG_2,
                           .off = 3, .imm = BPF_ADD}),
        BPF_EXIT_INSN(),
    };

    run_one("doc_unreadable_reg", doc_unreadable_reg,
            (int)(sizeof(doc_unreadable_reg) / sizeof(doc_unreadable_reg[0])));
    run_one("doc_callee_saved_r6", doc_callee_saved_r6,
            (int)(sizeof(doc_callee_saved_r6) / sizeof(doc_callee_saved_r6[0])));
    run_one("doc_bad_ptr_xadd", doc_bad_ptr_xadd,
            (int)(sizeof(doc_bad_ptr_xadd) / sizeof(doc_bad_ptr_xadd[0])));
}

// ---------------------------------------------------------------------------
// DOCUMENTED-BEHAVIOUR CASES, part 2 — the "Understanding eBPF verifier
// messages" section (verifier.rst:353-560).
//
// These 11 programs differ from the prose examples above in a way that matters:
// the document prints them ALREADY in `BPF_*` macro form — the same macros this
// harness uses — so getting them in here is transcription, not translation
// judgement. Each also carries its exact expected error string, anchored by
// `DocumentedCase::expected_error` on the Rust side. All 11 are programs the
// verifier MUST reject, so they test the verifier's SOUNDNESS: an accept here is
// a real finding, not a documentation quibble.
//
// Three places where the document leaves something implicit and a choice had to
// be made. Each is a reviewable judgement, marked JUDGEMENT at its case:
//  (a) The document writes `BPF_LD_MAP_FD(BPF_REG_1, 0)` even in examples whose
//      OWN log shows `r1 = 1` (i.e. captured with a real map). fd 0 fails at
//      pseudo-ldimm64 resolution — before the condition the case is about — so
//      those cases get a real map. The one case that IS about fd 0 keeps 0.
//  (b) The document never states the map's value_size. 16 is used so the
//      documented offsets (`off 4 size 8`) are in bounds and the case reaches the
//      condition it is about instead of failing the bounds check first.
//  (c) Two cases call socket helpers, which a socket filter cannot call at all,
//      and one is about alignment, which x86 skips unless strict alignment is
//      requested. Both are stated per case.
// ---------------------------------------------------------------------------

// An ARRAY map big enough for every documented offset in the section (b).
static int make_doc_map(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 16;
    m.max_entries = 1;
    return bpf(BPF_MAP_CREATE, &m, sizeof(m));
}

static void run_documented_message_cases(void) {
    // verifier.rst:356 — "Program with unreachable instructions" -> `unreachable insn 1`
    struct bpf_insn doc_msg_unreachable_insn[] = {
        BPF_EXIT_INSN(),
        BPF_EXIT_INSN(),
    };
    run_one("doc_msg_unreachable_insn", doc_msg_unreachable_insn,
            (int)(sizeof(doc_msg_unreachable_insn) / sizeof(doc_msg_unreachable_insn[0])));

    // verifier.rst:367 — "Program that reads uninitialized register" -> `R2 !read_ok`.
    // This is the SAME program as the prose example above (doc_unreadable_reg);
    // it is not duplicated here — the prose case carries the error string instead.

    // verifier.rst:377 — "Program that doesn't initialize R0 before exiting"
    //   -> `R0 !read_ok`
    struct bpf_insn doc_msg_uninit_r0_exit[] = {
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_1),
        BPF_EXIT_INSN(),
    };
    run_one("doc_msg_uninit_r0_exit", doc_msg_uninit_r0_exit,
            (int)(sizeof(doc_msg_uninit_r0_exit) / sizeof(doc_msg_uninit_r0_exit[0])));

    // verifier.rst:388 — "Program that accesses stack out of bounds"
    //   -> `invalid stack off=8 size=8`
    struct bpf_insn doc_msg_stack_oob[] = {
        BPF_ST_MEM(BPF_DW, BPF_REG_10, 8, 0),
        BPF_EXIT_INSN(),
    };
    run_one("doc_msg_stack_oob", doc_msg_stack_oob,
            (int)(sizeof(doc_msg_stack_oob) / sizeof(doc_msg_stack_oob[0])));

    int map_fd = make_doc_map();
    if (map_fd < 0) {
        // Say so instead of silently skipping: a missing denominator must be
        // visible, not look like a clean run.
        printf("===PROG doc_msg_map_cases type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n"
               "---LOG---\n---END---\n", errno);
    } else {
        // verifier.rst:398 — "Program that doesn't initialize stack before passing
        //   its address into function" -> `invalid indirect read from stack off -8+0 size 8`
        // JUDGEMENT (a): real map fd; with the document's literal fd 0 the load
        // would fail at map resolution and never reach the uninitialized-stack check.
        struct bpf_insn doc_msg_uninit_stack_arg[] = {
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
            BPF_LD_MAP_FD(BPF_REG_1, map_fd),
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_EXIT_INSN(),
        };
        run_one("doc_msg_uninit_stack_arg", doc_msg_uninit_stack_arg,
                (int)(sizeof(doc_msg_uninit_stack_arg) / sizeof(doc_msg_uninit_stack_arg[0])));

        // verifier.rst:432 — "Program that doesn't check return value of
        //   map_lookup_elem() before accessing map element"
        //   -> `R0 invalid mem access 'map_value_or_null'`
        struct bpf_insn doc_msg_unchecked_map_value[] = {
            BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
            BPF_LD_MAP_FD(BPF_REG_1, map_fd),
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0),
            BPF_EXIT_INSN(),
        };
        run_one("doc_msg_unchecked_map_value", doc_msg_unchecked_map_value,
                (int)(sizeof(doc_msg_unchecked_map_value) / sizeof(doc_msg_unchecked_map_value[0])));

        // verifier.rst:453 — "checks for NULL, but accesses the memory with
        //   incorrect alignment" -> `misaligned access off 4 size 8`
        // JUDGEMENT (c): x86_64 has efficient unaligned access, so the verifier
        // skips this check unless the load asks for it. BPF_F_STRICT_ALIGNMENT is
        // what makes the documented condition reachable at all on this arch;
        // without it the program is legitimately accepted here and the document's
        // claim simply does not apply.
        struct bpf_insn doc_msg_misaligned_value[] = {
            BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
            BPF_LD_MAP_FD(BPF_REG_1, map_fd),
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 1),
            BPF_ST_MEM(BPF_DW, BPF_REG_0, 4, 0),
            BPF_EXIT_INSN(),
        };
        run_one_ex("doc_msg_misaligned_value", doc_msg_misaligned_value,
                   (int)(sizeof(doc_msg_misaligned_value) / sizeof(doc_msg_misaligned_value[0])),
                   BPF_PROG_TYPE_SOCKET_FILTER, "socket_filter", BPF_F_STRICT_ALIGNMENT);

        // verifier.rst:477 — "accesses memory with correct alignment in one side of
        //   'if' branch, but fails to do so in the other" -> `R0 invalid mem access 'imm'`
        struct bpf_insn doc_msg_branch_imm_deref[] = {
            BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
            BPF_LD_MAP_FD(BPF_REG_1, map_fd),
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 2),
            BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 0),
            BPF_EXIT_INSN(),
            BPF_ST_MEM(BPF_DW, BPF_REG_0, 0, 1),
            BPF_EXIT_INSN(),
        };
        run_one("doc_msg_branch_imm_deref", doc_msg_branch_imm_deref,
                (int)(sizeof(doc_msg_branch_imm_deref) / sizeof(doc_msg_branch_imm_deref[0])));

        close(map_fd);
    }

    // verifier.rst:414 — "Program that uses invalid map_fd=0 while calling to
    //   map_lookup_elem()" -> `fd 0 is not pointing to valid bpf_map`
    // fd 0 is kept deliberately: here the invalid fd IS the documented condition.
    struct bpf_insn doc_msg_invalid_map_fd[] = {
        BPF_ST_MEM(BPF_DW, BPF_REG_10, -8, 0),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
        BPF_LD_MAP_FD(BPF_REG_1, 0),
        BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
        BPF_EXIT_INSN(),
    };
    run_one("doc_msg_invalid_map_fd", doc_msg_invalid_map_fd,
            (int)(sizeof(doc_msg_invalid_map_fd) / sizeof(doc_msg_invalid_map_fd[0])));

    // verifier.rst:508 / :536 — the two socket-lookup cases
    //   -> `Unreleased reference id=1, alloc_insn=7` (both)
    // JUDGEMENT (c): bpf_sk_lookup_tcp is not callable from a socket filter, so
    // these run as BPF_PROG_TYPE_SCHED_CLS — the classic tc program type these
    // examples come from. The program text itself is the document's, unchanged.
    struct bpf_insn doc_msg_unreleased_ref_null[] = {
        BPF_MOV64_IMM(BPF_REG_2, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -8),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
        BPF_MOV64_IMM(BPF_REG_3, 4),
        BPF_MOV64_IMM(BPF_REG_4, 0),
        BPF_MOV64_IMM(BPF_REG_5, 0),
        BPF_EMIT_CALL(BPF_FUNC_sk_lookup_tcp),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    run_one_ex("doc_msg_unreleased_ref_null", doc_msg_unreleased_ref_null,
               (int)(sizeof(doc_msg_unreleased_ref_null) / sizeof(doc_msg_unreleased_ref_null[0])),
               BPF_PROG_TYPE_SCHED_CLS, "sched_cls", 0);

    struct bpf_insn doc_msg_unreleased_ref_nocheck[] = {
        BPF_MOV64_IMM(BPF_REG_2, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -8),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -8),
        BPF_MOV64_IMM(BPF_REG_3, 4),
        BPF_MOV64_IMM(BPF_REG_4, 0),
        BPF_MOV64_IMM(BPF_REG_5, 0),
        BPF_EMIT_CALL(BPF_FUNC_sk_lookup_tcp),
        BPF_EXIT_INSN(),
    };
    run_one_ex("doc_msg_unreleased_ref_nocheck", doc_msg_unreleased_ref_nocheck,
               (int)(sizeof(doc_msg_unreleased_ref_nocheck) / sizeof(doc_msg_unreleased_ref_nocheck[0])),
               BPF_PROG_TYPE_SCHED_CLS, "sched_cls", 0);
}

int main(void) {
    // Program A: clean, minimal accepted prog — `return 0`.
    struct bpf_insn prog_return0[] = {
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };

    // Program B: some ALU to create richer register state, then return.
    //   r0 = 1; r0 <<= 3; r0 &= 0xff; r0 += 5; exit
    struct bpf_insn prog_alu[] = {
        BPF_MOV64_IMM(BPF_REG_0, 1),
        BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 3),
        BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xff),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 5),
        BPF_EXIT_INSN(),
    };

    // Program C: deliberately invalid — exit with R0 uninitialized (reject).
    struct bpf_insn prog_uninit[] = {
        BPF_EXIT_INSN(),
    };

    // Program D: bounded unknown scalar — read a ctx u32 (skb->len, unknown),
    // mask to 0..255. Produces the FULL scalar form: var_off=(0x0; 0xff).
    struct bpf_insn prog_ranged_and[] = {
        BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0),
        BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xff),
        BPF_EXIT_INSN(),
    };

    // Program E: unknown high bits — read a ctx u32, shift left 8 (low 8 bits
    // known-zero, the rest unknown). Exercises var_off mask with known-zero bits.
    struct bpf_insn prog_shift[] = {
        BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0),
        BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 8),
        BPF_EXIT_INSN(),
    };

    // Program F: comparison-narrowed bound — read a ctx u32, cap it at 10 via a
    // conditional. Exercises verifier bound narrowing (umax) on one path.
    struct bpf_insn prog_bounded[] = {
        BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0),
        BPF_JMP_IMM(BPF_JLE, BPF_REG_0, 10, 1),
        BPF_MOV64_IMM(BPF_REG_0, 10),
        BPF_EXIT_INSN(),
    };

    run_one("return0", prog_return0,
            (int)(sizeof(prog_return0) / sizeof(prog_return0[0])));
    run_one("alu_state", prog_alu,
            (int)(sizeof(prog_alu) / sizeof(prog_alu[0])));
    run_one("uninit_r0", prog_uninit,
            (int)(sizeof(prog_uninit) / sizeof(prog_uninit[0])));
    run_one("ranged_and", prog_ranged_and,
            (int)(sizeof(prog_ranged_and) / sizeof(prog_ranged_and[0])));
    run_one("shift_unknown", prog_shift,
            (int)(sizeof(prog_shift) / sizeof(prog_shift[0])));
    run_one("bounded_cmp", prog_bounded,
            (int)(sizeof(prog_bounded) / sizeof(prog_bounded[0])));
    run_map_lookup();
    run_documented_cases();
    run_documented_message_cases();
    return 0;
}
