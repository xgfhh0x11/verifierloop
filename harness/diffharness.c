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
#include <stdlib.h>
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
// 32-bit (subregister) forms. The verifier tracks u32_min/u32_max separately from
// the 64-bit bounds and must keep the two views in sync; these are the insns that
// force that sync to happen.
#define BPF_ALU32_IMM(OP, DST, IMM)                                            \
    ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_K,                   \
                       .dst_reg = DST, .src_reg = 0, .off = 0, .imm = IMM})
#define BPF_JMP32_IMM(OP, DST, IMM, OFF)                                       \
    ((struct bpf_insn){.code = BPF_JMP32 | BPF_OP(OP) | BPF_K,                 \
                       .dst_reg = DST, .src_reg = 0, .off = OFF, .imm = IMM})
// Register-to-register (BPF_X) forms — the classic macros above are all immediate
// (BPF_K). OI-9's next increment needs these: two registers, each carrying its own
// abstract state, meeting in one op (a different verifier path from the imm forms).
#define BPF_ALU64_REG(OP, DST, SRC)                                            \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_OP(OP) | BPF_X,                 \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_ALU32_REG(OP, DST, SRC)                                            \
    ((struct bpf_insn){.code = BPF_ALU | BPF_OP(OP) | BPF_X,                   \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
#define BPF_JMP_REG(OP, DST, SRC, OFF)                                         \
    ((struct bpf_insn){.code = BPF_JMP | BPF_OP(OP) | BPF_X,                   \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
#define BPF_JMP32_REG(OP, DST, SRC, OFF)                                       \
    ((struct bpf_insn){.code = BPF_JMP32 | BPF_OP(OP) | BPF_X,                 \
                       .dst_reg = DST, .src_reg = SRC, .off = OFF, .imm = 0})
#define BPF_JMP_A(OFF)                                                         \
    ((struct bpf_insn){.code = BPF_JMP | BPF_JA,                               \
                       .dst_reg = 0, .src_reg = 0, .off = OFF, .imm = 0})
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

// ===========================================================================
// TARGETED GENERATION (devlog 0025) — aim the input budget, do not sprinkle it.
//
// Reviewer's diagnosis (2026-09-01): bug hunting = oracle x input. The oracle side
// has three calibrated legs; the input side is ~241 programs total because KVM is
// blocked and everything runs on TCG. Random volume cannot fix that at this scale —
// 279 blocks of syzkaller corpus never produced six of the error classes eleven
// hand-written programs produced in one run. So the input budget gets AIMED.
//
// WHAT IT IS AIMED AT, and why exactly this: the ONE detector leg that needs no
// external ground truth is the intrinsic-invariant leg — it checks the verifier
// against ITSELF (tnum well-formedness, bound ordering, and tnum-vs-bounds
// agreement). That leg can only fire on registers whose abstract state is actually
// interesting: partially-known bits AND narrowed bounds at the same time. Programs
// like that do not appear by accident in a syscall fuzzer's corpus; they have to be
// constructed. This generator constructs them, and nothing else.
//
// NOT RANDOM, ENUMERATIVE. With a few hundred executions to spend, sampling a space
// wastes the budget. Every (alu op x compare x width) combination is emitted exactly
// once, so the cross-product is COVERED rather than sampled, and program N is the
// same program on every run — a finding is reproducible from its label alone.
//
// The skeleton is fixed and every part of it is load-bearing:
//
//   0: r0 = *(u32 *)(r1 + 0)   unknown scalar from ctx -> full 32-bit range
//   1: <alu op1>               shapes the tnum (and/or/xor/shifts) or the bounds
//                              (add/sub/mul/div/mod) -- the two are tracked by
//                              DIFFERENT verifier code paths
//   2: if r0 <cmp> imm goto 5  narrows bounds on both branches; back-propagating a
//                              comparison into the tnum is where the two trackers
//                              must agree
//   3: <alu op2>               arithmetic on the narrowed value (not-taken path)
//   4: goto 6
//   5: <alu op2'>              arithmetic on the OTHER narrowing (taken path)
//   6: r0 &= 0xffff            bound the return value
//   7: exit                    -> insn 6 is a MERGE point: two different abstract
//                              states join, which is where a range desync would show
//
// A 32-bit variant of each program uses BPF_ALU32/BPF_JMP32, because the verifier
// keeps u32_min/u32_max separately from the 64-bit bounds and has to reconcile them.
// That reconciliation is historically the densest source of verifier range bugs.
// ===========================================================================

struct gen_alu {
    const char *name;
    int op;
    int imm1;   // shaping immediate
    int imm2;   // not-taken path immediate
    int imm3;   // taken path immediate
};

// Mixed on purpose: bitwise ops move the tnum and leave the bounds to be deduced;
// arithmetic ops move the bounds and leave the tnum to be deduced. The interesting
// states come from chaining one kind after the other.
static const struct gen_alu GEN_ALU[] = {
    {"and",  BPF_AND,  0x0f0f, 0x00ff, 0xff00},
    {"or",   BPF_OR,   0x00f0, 0x0003, 0x1000},
    {"xor",  BPF_XOR,  0xff00, 0x0f0f, 0x00f0},
    {"lsh",  BPF_LSH,       5,      3,      9},
    {"rsh",  BPF_RSH,       3,      7,      2},
    {"arsh", BPF_ARSH,      7,      2,     11},
    {"add",  BPF_ADD,   0x100,   0x40,   -17},
    {"sub",  BPF_SUB,    0x40,     23,   -64},
    {"mul",  BPF_MUL,      12,      3,      7},
    {"div",  BPF_DIV,       7,      3,      5},
    {"mod",  BPF_MOD,       9,     16,      6},
};

// Every compare form, signed and unsigned, plus JSET (the only one that narrows
// BITS rather than a range — so it is the compare most likely to disagree with the
// bounds tracker).
struct gen_cmp {
    const char *name;
    int op;
    int imm;
};
static const struct gen_cmp GEN_CMP[] = {
    {"jeq",  BPF_JEQ,   64},
    {"jne",  BPF_JNE,   64},
    {"jgt",  BPF_JGT,  100},
    {"jge",  BPF_JGE,  100},
    {"jlt",  BPF_JLT,  100},
    {"jle",  BPF_JLE,  100},
    {"jsgt", BPF_JSGT,  -5},
    {"jsge", BPF_JSGE,  -5},
    {"jslt", BPF_JSLT,  -5},
    {"jsle", BPF_JSLE,  -5},
    {"jset", BPF_JSET, 0x10},
};

#define GEN_ALU_N ((int)(sizeof(GEN_ALU) / sizeof(GEN_ALU[0])))
#define GEN_CMP_N ((int)(sizeof(GEN_CMP) / sizeof(GEN_CMP[0])))

// Emit one program of the family. `w32` selects the subregister variant.
static void run_generated(int alu_i, int cmp_i, int w32, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[8];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    if (w32) {
        insns[1] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_JMP32_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[3] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
        insns[5] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm3);
    } else {
        insns[1] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_JMP_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[3] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
        insns[5] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
    }
    insns[4] = BPF_JMP_A(1);
    insns[6] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[7] = BPF_EXIT_INSN();

    // The label IS the recipe: it names the exact program, so any finding can be
    // rebuilt from the report without consulting a seed or a corpus file.
    char name[64];
    snprintf(name, sizeof(name), "gen#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one(name, insns, 8);
}

// The whole enumerated family: every alu x compare x width, once each.
static void run_generated_family(void) {
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated(alu_i, cmp_i, w32, index++);
}

// ===========================================================================
// MIXED-WIDTH FAMILY (devlog 0026) — aimed at the 32<->64 reconciliation.
//
// OI-9 named the blind spot the first family had by construction: every program in
// it was purely 64-bit or purely 32-bit, so the verifier's two views of a scalar
// always agreed and it printed them as ONE shared token (`umax=umax32=255`). Two
// views that are literally the same token cannot be caught disagreeing — measured:
// the 242-program family scored 0 on the 32<->64 denominator.
//
// The verifier keeps u32_min/u32_max/s32_min/s32_max separately from the 64-bit
// bounds and reconciles them in reg_bounds_sync() (__reg32_deduce_bounds /
// __reg64_deduce_bounds). Historically that reconciliation is the densest source of
// verifier range bugs. To reach it, the two views have to be forced APART inside one
// program, which needs a width CHANGE mid-program:
//
//   * a 32-bit ALU op writes the low half and ZEROES the upper half, so whatever
//     64-bit knowledge existed is discarded and must be rebuilt from the 32-bit view
//   * a 32-bit compare narrows only the 32-bit view, and the 64-bit view has to be
//     re-derived from it (and vice versa for a 64-bit compare after a 32-bit op)
//   * a sign-extending move (movsx) propagates the low half's sign into the upper
//     half, which is the one operation that ties the two views together arithmetically
//
// Three sub-families, each enumerated in full:
//   64->32  : shape 64-bit, then 32-bit op, then 32-bit compare   (121 programs)
//   32->64  : shape 32-bit, then 64-bit op, then 64-bit compare   (121 programs)
//   movsx   : shape 32-bit, sign-extend from 8/16/32, then signed
//             64-bit compare                                       (33 programs)
// ===========================================================================

// Sign-extending move, `r0 = (sN)r0`. Not in the classic macro set because it
// postdates it: BPF_MOV with a non-zero off is movsx (N = 8, 16 or 32).
#define BPF_MOVSX64_REG(DST, SRC, SZ)                                          \
    ((struct bpf_insn){.code = BPF_ALU64 | BPF_MOV | BPF_X,                    \
                       .dst_reg = DST, .src_reg = SRC, .off = SZ, .imm = 0})

// One program of the 64->32 or 32->64 sub-family. `wide_first` selects which view
// gets shaped first; the compare always follows the SECOND op's width, so the
// narrowing lands on the view the preceding op did not just rebuild.
static void run_mixed(int alu_i, int cmp_i, int wide_first, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[9];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    if (wide_first) {
        insns[1] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
        insns[3] = BPF_JMP32_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[4] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
        insns[6] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
    } else {
        insns[1] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
        insns[3] = BPF_JMP_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[4] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm3);
        insns[6] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
    }
    insns[5] = BPF_JMP_A(1);
    insns[7] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[8] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "mix#%s.%s.%s#%03d",
             wide_first ? "64-32" : "32-64", a->name, c->name, index);
    run_one(name, insns, 9);
}

// One program of the movsx sub-family: shape the low bits, sign-extend them into
// the upper half, then compare SIGNED 64-bit — the compare's outcome now depends on
// bits the 32-bit view produced.
static void run_movsx(int sz, int cmp_i, int index) {
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[9];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    insns[1] = BPF_ALU32_IMM(BPF_OR, BPF_REG_0, 0x80);   // make the sign bits reachable
    insns[2] = BPF_MOVSX64_REG(BPF_REG_0, BPF_REG_0, sz);
    insns[3] = BPF_JMP_IMM(c->op, BPF_REG_0, c->imm, 2);
    insns[4] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_0, 7);
    insns[5] = BPF_JMP_A(1);
    insns[6] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_0, 3);
    insns[7] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[8] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "mix#movsx%d.%s#%03d", sz, c->name, index);
    run_one(name, insns, 9);
}

// The shape that actually forces the two views apart on a well-synced verifier:
// shift the unknown bits into the UPPER half, then narrow only the LOWER one.
//
// Measured first, then written (0026): the 64->32 / 32->64 orderings above scored
// 152 independent views on the older host kernel but only 4 on bpf-next, because
// bpf-next's deduction reconciles the two views almost perfectly whenever the value
// fits in one 2^32 block — and a ctx u32 load always does. `r0 <<= 32` breaks that:
// the 64-bit range then spans many blocks (so the 64-bit endpoints constrain the low
// half not at all) while a 32-bit compare still pins the low half exactly. That is
// precisely the state where the two views must be independently maintained.
//
// Note a BPF property that rules out the obvious alternative: every 32-bit ALU op
// zero-extends into the upper half, so the low half cannot be edited while keeping
// the upper half unknown. The shaping has to be 64-bit; only the COMPARE is 32-bit.
static void run_upper_half(int alu_i, int cmp_i, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[9];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    insns[1] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_0, 32);   // unknown bits -> upper half
    insns[2] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
    insns[3] = BPF_JMP32_IMM(c->op, BPF_REG_0, c->imm, 2);
    insns[4] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
    insns[5] = BPF_JMP_A(1);
    insns[6] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
    insns[7] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[8] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "mix#hi.%s.%s#%03d", a->name, c->name, index);
    run_one(name, insns, 9);
}

static void run_mixed_family(void) {
    int index = 0;
    for (int wide_first = 1; wide_first >= 0; wide_first--)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_mixed(alu_i, cmp_i, wide_first, index++);
    static const int SIZES[] = {8, 16, 32};
    for (int i = 0; i < 3; i++)
        for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
            run_movsx(SIZES[i], cmp_i, index++);
    for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
        for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
            run_upper_half(alu_i, cmp_i, index++);
}

// ===========================================================================
// REGISTER-TO-REGISTER FAMILY (OI-9 next increment) — the classic --gen family
// combines a ranged register with a CONSTANT (BPF_K). The verifier takes a
// DIFFERENT path when both operands are registers carrying their own abstract
// state: scalar_min_max_* / reg_bounds_sync over two non-const scalars, and a
// reg-reg branch that back-propagates the narrowing onto BOTH registers. That path
// is historically the densest range-bug surface and the imm family never touches it.
//
// Two INDEPENDENT unknowns (separate ctx loads at r1+0 and r1+4) so the op is a
// genuine two-range combination, not a linked-reg tautology (mirrors the
// constant-tautology exclusion in the denominator). Both are shaped before they
// meet, so each carries partially-known bits AND a narrowed range — exactly the
// state the intrinsic tnum-vs-bounds leg needs to fire.
//
//   0: r0 = *(u32*)(r1+0)     unknown A
//   1: r6 = *(u32*)(r1+4)     unknown B (independent of A)
//   2: r6 <op> imm1           shape B (still non-constant)
//   3: r0 <op> imm1           shape A
//   4: if r0 <cmp> r6 goto 7  REG-REG compare -> narrows BOTH, differently per path
//   5: r0 <op> r6             REG-REG alu on the not-taken (fall-through) state
//   6: goto 8
//   7: r0 <op> r6             REG-REG alu on the taken state (same op, narrowed inputs)
//   8: r0 &= 0xffff           bound the return value
//   9: exit                   insn 8 MERGES the two reg-reg-combined states
//
// Bonus surfaces the imm family cannot reach: div/mod by a register whose range may
// include 0, and variable-amount shifts (shift by a register).
// ===========================================================================
static void run_generated_rr(int alu_i, int cmp_i, int w32, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[10];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    insns[1] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_1, 4);
    if (w32) {
        insns[2] = BPF_ALU32_IMM(a->op, BPF_REG_6, a->imm1);
        insns[3] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm1);
        insns[4] = BPF_JMP32_REG(c->op, BPF_REG_0, BPF_REG_6, 2);
        insns[5] = BPF_ALU32_REG(a->op, BPF_REG_0, BPF_REG_6);
        insns[7] = BPF_ALU32_REG(a->op, BPF_REG_0, BPF_REG_6);
    } else {
        insns[2] = BPF_ALU64_IMM(a->op, BPF_REG_6, a->imm1);
        insns[3] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
        insns[4] = BPF_JMP_REG(c->op, BPF_REG_0, BPF_REG_6, 2);
        insns[5] = BPF_ALU64_REG(a->op, BPF_REG_0, BPF_REG_6);
        insns[7] = BPF_ALU64_REG(a->op, BPF_REG_0, BPF_REG_6);
    }
    insns[6] = BPF_JMP_A(1);
    insns[8] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[9] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "genrr#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one(name, insns, 10);
}

// Every alu x compare x width, once each — same enumeration shape as --gen so a
// finding is reproducible from its label alone.
static void run_generated_rr_family(void) {
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated_rr(alu_i, cmp_i, w32, index++);
}

// ===========================================================================
// MULTI-BRANCH FAMILY (OI-9 next increment) — the --gen / --gen-rr families each
// have exactly ONE compare and ONE merge point. The verifier's state-merge logic
// (states_equal / regsafe / reg_bounds_sync at a join) is exercised once per
// program. A program with TWO sequential branches has TWO merge points, and the
// SECOND branch narrows a register whose abstract state is itself the JOIN of the
// first branch's two paths. That is a different surface: bounds/tnum must survive
// branch -> merge -> branch -> merge, and a desync introduced at merge 1 gets a
// second chance to surface (or to be masked) at branch 2 and merge 2.
//
//   0:  r0 = *(u32*)(r1+0)      unknown scalar
//   1:  r0 <op> imm1            shape it (tnum and/or bounds)
//   2:  if r0 <cmp> imm_a goto 5   BRANCH 1
//   3:  r0 <op> imm2            not-taken-1 arithmetic
//   4:  goto 6
//   5:  r0 <op> imm3            taken-1 arithmetic
//   6:  [MERGE 1] if r0 <cmp> imm_b goto 9   BRANCH 2, on the merged state
//   7:  r0 <op> imm2            not-taken-2
//   8:  goto 10
//   9:  r0 <op> imm3            taken-2
//   10: [MERGE 2] r0 &= 0xffff   bound the return value
//   11: exit
//
// imm_a = c->imm (first threshold), imm_b = a->imm2 (a DIFFERENT constant, so the
// second branch is a genuine second narrowing, not a trivially-decided repeat of the
// first). Both derive from the enumerated (alu, cmp) pair, so the label alone rebuilds
// the exact program -- same reproducible-from-recipe contract as the other families.
// All-accepted by construction (same valid ops as --gen, just chained), so the
// tnum-vs-bounds denominator stays clean.
// ===========================================================================
static void run_generated_mb(int alu_i, int cmp_i, int w32, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[12];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_0, BPF_REG_1, 0);
    if (w32) {
        insns[1] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_JMP32_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[3] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
        insns[5] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm3);
        insns[6] = BPF_JMP32_IMM(c->op, BPF_REG_0, a->imm2, 2);
        insns[7] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm2);
        insns[9] = BPF_ALU32_IMM(a->op, BPF_REG_0, a->imm3);
    } else {
        insns[1] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm1);
        insns[2] = BPF_JMP_IMM(c->op, BPF_REG_0, c->imm, 2);
        insns[3] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
        insns[5] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
        insns[6] = BPF_JMP_IMM(c->op, BPF_REG_0, a->imm2, 2);
        insns[7] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm2);
        insns[9] = BPF_ALU64_IMM(a->op, BPF_REG_0, a->imm3);
    }
    insns[4]  = BPF_JMP_A(1);
    insns[8]  = BPF_JMP_A(1);
    insns[10] = BPF_ALU64_IMM(BPF_AND, BPF_REG_0, 0xffff);
    insns[11] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "genmb#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one(name, insns, 12);
}

// Every alu x compare x width, once each -- same enumeration shape as --gen so a
// finding is reproducible from its label alone.
static void run_generated_mb_family(void) {
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated_mb(alu_i, cmp_i, w32, index++);
}

// ===========================================================================
// POINTER-ARITHMETIC FAMILY (OI-9 next increment) — the scalar families
// (--gen / --gen-rr / --gen-mb / --gen-mix) only ever combine SCALARS. This one
// aims the verifier's POINTER-safety decision: it takes a real PTR_TO_MAP_VALUE
// (from a bpf_map_lookup_elem on a 64-byte ARRAY value), adds a shaped+narrowed
// scalar offset to it, and then STORES through the adjusted pointer. The store is
// where the verifier decides "is this pointer access in bounds" (check_mem_access /
// adjust_ptr_min_max_vals / sanitize bounds). A logic bug here is not an OOB read of
// a log string (cf. F1) but a wrongly-ACCEPTED out-of-bounds WRITE — higher severity
// and a historically dense bug region, which is why this leg is flagged highest-EV.
//
//   0: *(u32*)(r10-4) = 0        key on stack
//   1: r2 = r10   2: r2 += -4     r2 = &key
//   3: r1 = map_fd (LD_MAP_FD, slots 3-4)
//   5: call bpf_map_lookup_elem   r0 = PTR_TO_MAP_VALUE_OR_NULL (value_size=64)
//   6: if r0 == 0 goto 15         mandatory null-check
//   7: r1 = *(u32*)(r0+0)         unknown scalar offset (read from the value)
//   8: r1 <alu> imm1              shape it (tnum and/or bounds)
//   9: if r1 <cmp> imm goto 12    narrow r1 differently on each path
//  10: r1 <alu> imm2  11: goto 13  (not-taken)      12: r1 <alu> imm3 (taken)
//  13: r0 += r1                    POINTER ARITHMETIC: map_value_ptr += scalar
//  14: *(u8*)(r0+0) = r1           STORE through the adjusted ptr -> the bounds check
//  15: r0 = 0   16: exit
//
// This family is NOT all-accepted by construction: acceptance depends on whether the
// verifier can prove the offset stays within value_size, which is exactly the
// decision under test. A mix of accept/reject is the point. Rejected programs still
// print their register state up to the faulting insn, so the intrinsic tnum-vs-bounds
// leg still has the shaped scalar (and the pointer's own var_off) to examine.
// First increment writes a 1-byte store (r1's low byte); wider stores are a follow-up.
// ===========================================================================
static void run_generated_ptr(int alu_i, int cmp_i, int w32, int index, int map_fd) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[17];
    insns[0] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    insns[1] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    insns[2] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    insns[3] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    insns[4] = (struct bpf_insn){0};
    insns[5] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    insns[6] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8);       /* null -> insn 15 */
    insns[7] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);
    if (w32) {
        insns[8]  = BPF_ALU32_IMM(a->op, BPF_REG_1, a->imm1);
        insns[9]  = BPF_JMP32_IMM(c->op, BPF_REG_1, c->imm, 2);  /* taken -> insn 12 */
        insns[10] = BPF_ALU32_IMM(a->op, BPF_REG_1, a->imm2);
        insns[12] = BPF_ALU32_IMM(a->op, BPF_REG_1, a->imm3);
    } else {
        insns[8]  = BPF_ALU64_IMM(a->op, BPF_REG_1, a->imm1);
        insns[9]  = BPF_JMP_IMM(c->op, BPF_REG_1, c->imm, 2);
        insns[10] = BPF_ALU64_IMM(a->op, BPF_REG_1, a->imm2);
        insns[12] = BPF_ALU64_IMM(a->op, BPF_REG_1, a->imm3);
    }
    insns[11] = BPF_JMP_A(1);                               /* -> insn 13 */
    insns[13] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);  /* ptr += scalar */
    insns[14] = BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0);   /* store through ptr */
    insns[15] = BPF_MOV64_IMM(BPF_REG_0, 0);
    insns[16] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "genptr#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one(name, insns, 17);
}

// Create the value_size=64 ARRAY map once, then every alu x compare x width, once
// each -- same enumeration/label contract as the scalar families.
static void run_generated_ptr_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 64;
    m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG genptr type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n"
               "---LOG---\n---END---\n", errno);
        return;
    }
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated_ptr(alu_i, cmp_i, w32, index++, map_fd);
    close(map_fd);
}

// ===========================================================================
// NEGATIVE-OFFSET MAP-VALUE FAMILY (T1-2) — the --gen-ptr family adds a POSITIVE
// bounded scalar to a map_value pointer, so the deciding check is the UPPER bound
// (umax + size <= value_size). The other, historically bug-prone edge is the LOWER
// bound: an offset whose signed minimum can go NEGATIVE, which would read/write BELOW
// the start of the map value. The kernel guards it with a distinct check
// (`check_map_access`: "R%d min value is negative, either use unsigned index or do a
// if (index >=0) check"). Historically that smin path has been skipped/mis-derived,
// which would ACCEPT an out-of-bounds-BELOW write — the severe class.
//
// The offset is pushed negative deterministically: mask to [0,15], then SUBTRACT a
// constant C so the signed window becomes [-C, 15-C] (smin = -C). Two forms:
//   raw  — no guard. If smin<0 the store MUST be rejected. A raw C>0 that ACCEPTS a
//          live store is the bug this leg hunts.
//   grd  — a signed guard `if (r1 s< 0) goto skip_store` before the arith. On the
//          store path the verifier must re-derive smin>=0 and ACCEPT (proving it is
//          not merely over-rejecting everything negative). Tests smin re-derivation
//          after a signed branch, the exact code path.
//
//   ... r1 = *(u32*)(r0+0);  r1 &= 15;  r1 -= C;   [grd: if r1 s<0 goto skip]
//       r0 += r1;  *(uW*)(r0+off) = r1;  skip: r0 = 0; exit
//
// Decision is a pure function of the instruction stream (load-time), same contract as
// --gen-ptr. Reject REASON (negative-min vs value_size) is read from the log to tell
// the lower-bound path from the upper-bound one.
// ===========================================================================
static const int PTRNEG_C[] = {0, 1, 2, 4, 8, 16, 24, 32, 48, 64};
#define PTRNEG_C_N ((int)(sizeof(PTRNEG_C) / sizeof(PTRNEG_C[0])))
static const struct { int off; int w; } PTRNEG_REACH[] = {
    {0, 1}, {0, 4}, {44, 4}, {48, 1}, {49, 1}, {48, 4}, /* last three cross value_size=64 */
};
#define PTRNEG_REACH_N ((int)(sizeof(PTRNEG_REACH) / sizeof(PTRNEG_REACH[0])))

static void run_generated_ptrneg(int form, int c_i, int reach_i, int index, int map_fd) {
    const int grd = (form == 1);
    const int C = PTRNEG_C[c_i];
    const int off = PTRNEG_REACH[reach_i].off;
    const int W = PTRNEG_REACH[reach_i].w;
    const int szmode = (W == 1) ? BPF_B : (W == 2) ? BPF_H : BPF_W;

    struct bpf_insn ins[16];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    ins[n++] = (struct bpf_insn){0};                              /* LD_DW upper half */
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);   /* patched */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);       /* unknown [0,2^32-1] */
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_1, 15);            /* -> [0,15] */
    ins[n++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_1, C);            /* -> smin = -C */
    int jguard = -1;
    if (grd) { jguard = n; ins[n++] = BPF_JMP_IMM(BPF_JSLT, BPF_REG_1, 0, 0); } /* patched */
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);      /* ptr += offset */
    ins[n++] = BPF_STX_MEM(szmode, BPF_REG_0, BPF_REG_1, off);    /* store through ptr */
    const int exitprep = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();

    ins[jnull].off = exitprep - jnull - 1;                        /* null -> r0=0 */
    if (grd) ins[jguard].off = exitprep - jguard - 1;            /* negative -> skip store */

    char name[80];
    snprintf(name, sizeof(name), "genptrneg#%s.C%d.o%d.w%d#%03d",
             grd ? "grd" : "raw", C, off, W, index);
    run_one(name, ins, n);
}

static void run_generated_ptrneg_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4;
    m.value_size = 64;
    m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG genptrneg type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n"
               "---LOG---\n---END---\n", errno);
        return;
    }
    int index = 0;
    for (int form = 0; form < 2; form++)
        for (int c_i = 0; c_i < PTRNEG_C_N; c_i++)
            for (int reach_i = 0; reach_i < PTRNEG_REACH_N; reach_i++)
                run_generated_ptrneg(form, c_i, reach_i, index++, map_fd);
    close(map_fd);
}

// ===========================================================================
// T1-1 SETUP PROBE — three hand-built programs, one per claim, to decide the family
// construction from MEASUREMENT (per-program reg32_checked + reject message), not
// from reading the kernel. Each is loaded against a value_size=64 map, same as --gen-ptr.
//   probe#naiveA : w1 &= 0x3f (32-bit ALU zero-extends) then r0 += r1. Claim: reg32=0
//                  (the two views coincide -> the 0025 payda-zero trap).
//   probe#hi     : r1 upper-unknown (<<32 | second load), then a 32-bit compare narrows
//                  ONLY the low half; then r0 += r1. Claim: reg32>0 (32-tight/64-loose),
//                  and the pointer add must REJECT (accept = the bug).
//   probe#ptr32  : w0 += w1 (32-bit ALU on the pointer). Claim: "32-bit pointer
//                  arithmetic prohibited" EACCES, never reaching bounds logic.
// ===========================================================================
static void run_probe_t1_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 64; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG probe type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    struct bpf_insn ld1 = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
        .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    struct bpf_insn ld2 = (struct bpf_insn){0};

    /* probe#naiveA -- 32-bit AND zero-extends; r0 += r1. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld2,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 4),          /* null -> r0=0 */
            BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
            BPF_ALU32_IMM(BPF_AND, BPF_REG_1, 0x3f),        /* 32-bit AND -> zext [0,0x3f] */
            BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),   /* ptr += bounded scalar */
            BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
            BPF_MOV64_IMM(BPF_REG_0, 0),
            BPF_EXIT_INSN(),
        };
        run_one("probe#naiveA#000", p, (int)(sizeof(p) / sizeof(p[0])));
    }

    /* probe#hi -- upper-unknown offset, 32-bit compare narrows only the low half. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld2,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 7),          /* null -> r0=0 */
            BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),    /* low unknown */
            BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),          /* unknown -> UPPER 32 */
            BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4),    /* second unknown, low 32 */
            BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_8),    /* -> full 64-bit unknown */
            BPF_JMP32_IMM(BPF_JGE, BPF_REG_1, 0x40, 2),     /* if w1>=64 skip: narrows LOW only */
            BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),   /* ptr += (umax huge) -> must reject */
            BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
            BPF_MOV64_IMM(BPF_REG_0, 0),
            BPF_EXIT_INSN(),
        };
        run_one("probe#hi#001", p, (int)(sizeof(p) / sizeof(p[0])));
    }

    /* probe#ptr32 -- 32-bit ALU directly on the pointer. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld2,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 3),          /* null -> r0=0 */
            BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),
            BPF_ALU32_REG(BPF_ADD, BPF_REG_0, BPF_REG_1),   /* 32-bit ALU on pointer -> prohibited */
            BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0),
            BPF_MOV64_IMM(BPF_REG_0, 0),
            BPF_EXIT_INSN(),
        };
        run_one("probe#ptr32#002", p, (int)(sizeof(p) / sizeof(p[0])));
    }
    close(map_fd);
}

// ===========================================================================
// 32<->64 x POINTER-OFFSET FAMILY (T1-1a) — the upper-unknown soundness probe.
// The probe above settled the construction from measurement: a 32-bit-shaped offset
// zero-extends (views coincide, reg32=0, the 0025 trap), and 32-bit ALU on a pointer
// is prohibited outright (Option B). Only the "hi" construction reaches the 32-tight/
// 64-loose surface (reg32>0). Two arms:
//
//   hi  (soundness, ~3/4): the offset has its UPPER 32 bits unknown while a 32-bit
//        compare narrows ONLY the low half. Its 64-bit smin is S64_MIN / umax ~ U64_MAX,
//        so adjust_ptr_min_max_vals (verifier.c:14665, check_reg_sane_offset_scalar on
//        the 64-bit bounds) MUST reject at `r0 += r1`. reg32>0 proves the independent
//        32-view formed; any ACCEPT is the bug. Two constructions (shift-or, u64 load)
//        x 5 low-narrowing compares x 4 thresholds K -- K cannot make it accept (upper
//        stays unknown for every K: mutual exclusivity), the variety is code-path breadth.
//   bnd (control, ~1/4): a 32-bit AND zero-extends to a genuinely 64-bounded offset
//        (reg32=0), which the verifier ACCEPTS when it fits -- proving it is not merely
//        over-rejecting everything 32-bit-shaped.
//
// value_size=64, same map as --gen-ptr. This arm is decision-invariant on the hi side
// (all-reject) BY the mutual-exclusivity theorem (reg32>0 <=> upper-unknown <=> reject);
// its signature is reg32_checked>0 with 0 wrongly-accepted hi programs, NOT an
// accept/reject balance. The discriminating "which view / sync" test is T1-1b (a
// separate oracle arm), not here.
// ===========================================================================
static const struct { const char *name; int op; } HI_CMP[] = {
    {"lt", BPF_JLT}, {"le", BPF_JLE}, {"gt", BPF_JGT}, {"ge", BPF_JGE}, {"set", BPF_JSET},
};
#define HI_CMP_N ((int)(sizeof(HI_CMP) / sizeof(HI_CMP[0])))
static const int HI_K[] = {8, 16, 64, 256};
#define HI_K_N ((int)(sizeof(HI_K) / sizeof(HI_K[0])))
static const int HI_MASK[] = {0x0f, 0x1f, 0x3f};
#define HI_MASK_N ((int)(sizeof(HI_MASK) / sizeof(HI_MASK[0])))
static const struct { int off; int w; } HI_REACH[] = { {0,1}, {0,4}, {8,4}, {48,1} };
#define HI_REACH_N ((int)(sizeof(HI_REACH) / sizeof(HI_REACH[0])))

static struct bpf_insn hi_ld1(int map_fd) {
    return (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                             .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
}

static void run_hi_soundness(int cons, int cmp_i, int k_i, int index, int map_fd) {
    const int K = HI_K[k_i];
    struct bpf_insn ins[18];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = hi_ld1(map_fd); ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    if (cons == 0) {                                    /* shift-or: unknown -> UPPER 32 */
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);
        ins[n++] = BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_8);
    } else {                                            /* direct 64-bit unknown load */
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0);
    }
    const int jskip = n;                                /* 32-bit compare narrows LOW only */
    ins[n++] = BPF_JMP32_IMM(HI_CMP[cmp_i].op, BPF_REG_1, K, 0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);   /* umax huge -> must reject */
    ins[n++] = BPF_STX_MEM(BPF_B, BPF_REG_0, BPF_REG_1, 0);
    const int exitp = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = exitp - jnull - 1;
    ins[jskip].off = exitp - jskip - 1;

    char name[80];
    snprintf(name, sizeof(name), "genhi#hi.%s.%s.K%d#%03d",
             cons ? "ld" : "so", HI_CMP[cmp_i].name, K, index);
    run_one(name, ins, n);
}

static void run_hi_bounded(int m_i, int r_i, int index, int map_fd) {
    const int mask = HI_MASK[m_i];
    const int off = HI_REACH[r_i].off, W = HI_REACH[r_i].w;
    const int szmode = (W == 1) ? BPF_B : (W == 2) ? BPF_H : BPF_W;
    struct bpf_insn ins[16];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = hi_ld1(map_fd); ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);
    ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_1, mask);        /* zext -> 64-bounded [0,mask] */
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_0, BPF_REG_1);
    ins[n++] = BPF_STX_MEM(szmode, BPF_REG_0, BPF_REG_1, off);
    const int exitp = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = exitp - jnull - 1;

    char name[80];
    snprintf(name, sizeof(name), "genhi#bnd.m%d.o%d.w%d#%03d", mask, off, W, index);
    run_one(name, ins, n);
}

static void run_generated_hi_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 64; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG genhi type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int index = 0;
    for (int cons = 0; cons < 2; cons++)
        for (int cmp_i = 0; cmp_i < HI_CMP_N; cmp_i++)
            for (int k_i = 0; k_i < HI_K_N; k_i++)
                run_hi_soundness(cons, cmp_i, k_i, index++, map_fd);
    for (int m_i = 0; m_i < HI_MASK_N; m_i++)
        for (int r_i = 0; r_i < HI_REACH_N; r_i++)
            run_hi_bounded(m_i, r_i, index++, map_fd);
    close(map_fd);
}

// ===========================================================================
// T1-1b ORACLE PROBE — does the EXISTING tnum32_bounds_inconsistent invariant (0026,
// diff.rs:652) actually RUN on the register state a CVE-2020-8835-shaped program
// produces, and stay SILENT on this (fixed) kernel? CVE-2020-8835 was a desync: the
// buggy __reg_bound_offset32 clamped the tnum's low-32 to {0} when the compares had
// established u32 in [0x200,0x400] (fix f2d67fec0b43). On a fixed kernel the two agree,
// so the leg must be silent; the probe confirms it also RUNS (reg32_checked>0), i.e. the
// state is genuinely reg32-independent, so a regression WOULD be caught.
//   probe#cve8835 : the commit's own reproducer -- a full-unknown r1 bounded by two
//                   jmp64 compares (into [0x2000000000, 0x4000000000]) then two jmp32
//                   compares (w1 into [0x200,0x400]). 64-bit range spans blocks, u32 is
//                   narrow -> the exact 32-tight/64-loose state where the desync lived.
//   probe#shift   : the <<32|load construction reaching the same independent-view state.
// ===========================================================================
static void run_probe_t1b_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 64; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG probe type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    struct bpf_insn ld1 = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
        .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    struct bpf_insn ld0 = (struct bpf_insn){0};

    /* probe#cve8835 -- the fix commit's own reproducer shape. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld0,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 11),               /* 6: null -> SKIP(18) */
            BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0),         /* 7: full 64-bit unknown */
            (struct bpf_insn){.code = BPF_LD|BPF_DW|BPF_IMM, .dst_reg = BPF_REG_2, .imm = 0}, /* 8 */
            (struct bpf_insn){.imm = 0x40},                       /* 9: r2 = 0x4000000000 */
            (struct bpf_insn){.code = BPF_LD|BPF_DW|BPF_IMM, .dst_reg = BPF_REG_3, .imm = 0}, /* 10 */
            (struct bpf_insn){.imm = 0x20},                       /* 11: r3 = 0x2000000000 */
            BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_2, 5),        /* 12: r1>umax -> SKIP */
            BPF_JMP_REG(BPF_JLT, BPF_REG_1, BPF_REG_3, 4),        /* 13: r1<umin -> SKIP */
            BPF_JMP32_IMM(BPF_JGT, BPF_REG_1, 0x400, 3),          /* 14: w1>0x400 -> SKIP */
            BPF_JMP32_IMM(BPF_JLT, BPF_REG_1, 0x200, 2),          /* 15: w1<0x200 -> SKIP */
            BPF_MOV64_IMM(BPF_REG_0, 0),                          /* 16: r1 constrained here */
            BPF_EXIT_INSN(),                                      /* 17 */
            BPF_MOV64_IMM(BPF_REG_0, 0),                          /* 18: SKIP */
            BPF_EXIT_INSN(),                                      /* 19 */
        };
        run_one("probe#cve8835#000", p, (int)(sizeof(p) / sizeof(p[0])));
    }

    /* probe#shift -- the <<32|load construction reaching the same independent-view state. */
    {
        struct bpf_insn p[] = {
            BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0),
            BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
            BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
            ld1, ld0,
            BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
            BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 8),                /* 6: null -> SKIP(15) */
            BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0),          /* 7: low unknown */
            BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32),               /* 8: -> UPPER 32 */
            BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4),          /* 9: second unknown */
            BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_8),          /* 10: full unknown */
            BPF_JMP32_IMM(BPF_JGT, BPF_REG_1, 0x400, 3),          /* 11: w1>0x400 -> SKIP */
            BPF_JMP32_IMM(BPF_JLT, BPF_REG_1, 0x200, 2),          /* 12: w1<0x200 -> SKIP */
            BPF_MOV64_IMM(BPF_REG_0, 0),                          /* 13: constrained here */
            BPF_EXIT_INSN(),                                      /* 14 */
            BPF_MOV64_IMM(BPF_REG_0, 0),                          /* 15: SKIP */
            BPF_EXIT_INSN(),                                      /* 16 */
        };
        run_one("probe#shift#001", p, (int)(sizeof(p) / sizeof(p[0])));
    }
    close(map_fd);
}

// ===========================================================================
// 32<->64 SYNC-FRAGILE FAMILY (T1-1b, first increment) — the discriminating half.
// The --probe-t1b probe confirmed by MEASUREMENT that the existing invariant B
// (tnum32_bounds_inconsistent, diff.rs:652) RUNS on a CVE-2020-8835-shaped state
// (reg32_checked>0) and stays SILENT on this fixed kernel (finding_count=0). So this
// family reuses that proven leg -- NO new oracle -- and enumerates the two VALIDATED
// constructions that drive a register into the 32-tight/64-loose state where a
// reg_bounds_sync desync (the CVE-2020-8835 class) would show as an empty tnum32-vs-u32
// intersection. Each program is an accepting scalar (the desync is a scalar property,
// caught at its source, upstream of any pointer use). Signature: reg32_checked>0 across
// many sync states + 0 divergence (the kernel is sync-consistent); a regression would fire B.
//   gensync#cve : full-unknown r1 -> two jmp64 compares into a multi-block [LO,HI] ->
//                 two jmp32 compares into a low window [KLO,KHI]. The fix commit's own
//                 reproducer shape (f2d67fec0b43), generalized over range and window.
//   gensync#shift : r1 = (unknown<<32)|unknown -> two jmp32 compares narrow the low half.
// Exotic sync paths (ARSH-under-ALU32, movsx, 32-bit div/mod) are a deferred 2nd increment.
// ===========================================================================
static const struct { uint64_t lo, hi; } SYNC_PAIRS[] = {
    {0x2000000000ULL, 0x4000000000ULL},   /* blocks 0x20..0x40 */
    {0x100000000ULL,  0x500000000ULL},    /* blocks 1..5 */
    {0x40000000ULL,   0x2c0000000ULL},    /* block 0 -> block 2 */
    {0x180000000ULL,  0x680000000ULL},    /* block 1 -> block 6 */
};
#define SYNC_PAIRS_N ((int)(sizeof(SYNC_PAIRS) / sizeof(SYNC_PAIRS[0])))
static const struct { int lo, hi; } SYNC_WIN[] = {
    {0x200, 0x400}, {0x10, 0x1000}, {0x100, 0x800}, {0, 0x40},
};
#define SYNC_WIN_N ((int)(sizeof(SYNC_WIN) / sizeof(SYNC_WIN[0])))

static void sync_emit_ld64(struct bpf_insn *ins, int *n, int reg, uint64_t val) {
    ins[(*n)++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
                                    .dst_reg = reg, .imm = (int)(uint32_t)(val & 0xffffffff)};
    ins[(*n)++] = (struct bpf_insn){.imm = (int)(uint32_t)(val >> 32)};
}

static void run_sync_cve(int p_i, int w_i, int index, int map_fd) {
    struct bpf_insn ins[26];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_1, BPF_REG_0, 0);         /* full 64-bit unknown */
    sync_emit_ld64(ins, &n, BPF_REG_2, SYNC_PAIRS[p_i].hi);
    sync_emit_ld64(ins, &n, BPF_REG_3, SYNC_PAIRS[p_i].lo);
    const int j1 = n; ins[n++] = BPF_JMP_REG(BPF_JGT, BPF_REG_1, BPF_REG_2, 0);   /* r1>HI */
    const int j2 = n; ins[n++] = BPF_JMP_REG(BPF_JLT, BPF_REG_1, BPF_REG_3, 0);   /* r1<LO */
    const int j3 = n; ins[n++] = BPF_JMP32_IMM(BPF_JGT, BPF_REG_1, SYNC_WIN[w_i].hi, 0); /* w1>KHI */
    const int j4 = n; ins[n++] = BPF_JMP32_IMM(BPF_JLT, BPF_REG_1, SYNC_WIN[w_i].lo, 0); /* w1<KLO */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);                          /* constrained state here */
    ins[n++] = BPF_EXIT_INSN();
    const int skip = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = skip - jnull - 1;
    ins[j1].off = skip - j1 - 1;
    ins[j2].off = skip - j2 - 1;
    ins[j3].off = skip - j3 - 1;
    ins[j4].off = skip - j4 - 1;

    char name[80];
    snprintf(name, sizeof(name), "gensync#cve.p%d.w%d#%03d", p_i, w_i, index);
    run_one(name, ins, n);
}

static void run_sync_shift(int w_i, int pol, int index, int map_fd) {
    const int op_hi = pol ? BPF_JGE : BPF_JGT;
    const int op_lo = pol ? BPF_JLE : BPF_JLT;
    struct bpf_insn ins[20];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_1, 32);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);
    ins[n++] = BPF_ALU64_REG(BPF_OR, BPF_REG_1, BPF_REG_8);
    const int j1 = n; ins[n++] = BPF_JMP32_IMM(op_hi, BPF_REG_1, SYNC_WIN[w_i].hi, 0);
    const int j2 = n; ins[n++] = BPF_JMP32_IMM(op_lo, BPF_REG_1, SYNC_WIN[w_i].lo, 0);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);                          /* constrained state here */
    ins[n++] = BPF_EXIT_INSN();
    const int skip = n; ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = skip - jnull - 1;
    ins[j1].off = skip - j1 - 1;
    ins[j2].off = skip - j2 - 1;

    char name[80];
    snprintf(name, sizeof(name), "gensync#shift.w%d.pol%d#%03d", w_i, pol, index);
    run_one(name, ins, n);
}

static void run_generated_sync_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 64; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG gensync type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int index = 0;
    for (int p_i = 0; p_i < SYNC_PAIRS_N; p_i++)
        for (int w_i = 0; w_i < SYNC_WIN_N; w_i++)
            run_sync_cve(p_i, w_i, index++, map_fd);
    for (int w_i = 0; w_i < SYNC_WIN_N; w_i++)
        for (int pol = 0; pol < 2; pol++)
            run_sync_shift(w_i, pol, index++, map_fd);
    close(map_fd);
}

// ===========================================================================
// PACKET-POINTER FAMILY (OI-9 next increment) — the pointer-arith family used a
// PTR_TO_MAP_VALUE, whose bound the verifier KNOWS (value_size). A packet pointer is
// the other kind: the verifier does NOT know where the packet ends. Instead the
// PROGRAM must prove the bound with its own `if (data + N > data_end)` compare, and
// the verifier statically TRACKS that proof as a per-pointer `range`
// (find_good_pkt_pointers, verifier.c) — then checks every packet access against the
// recorded range at load time. Nothing here is runtime: the harness only LOADS, and
// accept/reject is a pure function of the instruction stream, so the deterministic
// enumeration and its denominator carry over unchanged.
//
// The interesting edges live in that range machinery: MAX_PACKET_OFF (0xffff) — a
// larger offset umax gives NO range ("risk of overflow") and the access is rejected —
// and range_right_open (`>` vs `>=`). This is the historically densest packet-bounds
// bug region. socket_filter forbids direct packet access (sk_filter_is_valid_access
// returns false for data/data_end), so this family loads as SCHED_CLS.
//
//   0: r2 = *(u32*)(r1+76)      skb->data     -> PTR_TO_PACKET
//   1: r3 = *(u32*)(r1+80)      skb->data_end -> PTR_TO_PACKET_END
//   2: r4 = *(u32*)(r1+0)       skb->len       unknown scalar offset
//   3: r4 <alu> imm1            shape it
//   4: if r4 <cmp> imm goto 7   narrow it per path
//   5: r4 <alu> imm2  6: goto 8  (not-taken)     7: r4 <alu> imm3 (taken)
//   8: r2 += r4                  PACKET POINTER ARITH: data += bounded scalar
//   9: r5 = r2  10: r5 += 1      end of the intended 1-byte access
//  11: if r5 > r3 goto 13        THE PROGRAM'S OWN BOUNDS CHECK -> verifier sets range
//  12: *(u8*)(r2+0) = r4         STORE through the packet ptr, checked vs range
//  13: r0 = 0   14: exit
//
// Acceptance ~ whether the shaping bounds the offset's umax within MAX_PACKET_OFF so a
// range can be recorded: a genuine accept/reject sweep of exactly that guard. The
// data_end compare is held fixed at `>` (the canonical idiom) in this first increment;
// enumerating it (jgt/jge/jlt/jle -> right-open vs closed) is the natural follow-up.
// ===========================================================================
static void run_generated_pkt(int alu_i, int cmp_i, int w32, int index) {
    const struct gen_alu *a = &GEN_ALU[alu_i];
    const struct gen_cmp *c = &GEN_CMP[cmp_i];

    struct bpf_insn insns[15];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 76);   /* data */
    insns[1] = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 80);   /* data_end */
    insns[2] = BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1, 0);    /* len: unknown */
    if (w32) {
        insns[3] = BPF_ALU32_IMM(a->op, BPF_REG_4, a->imm1);
        insns[4] = BPF_JMP32_IMM(c->op, BPF_REG_4, c->imm, 2);  /* taken -> 7 */
        insns[5] = BPF_ALU32_IMM(a->op, BPF_REG_4, a->imm2);
        insns[7] = BPF_ALU32_IMM(a->op, BPF_REG_4, a->imm3);
    } else {
        insns[3] = BPF_ALU64_IMM(a->op, BPF_REG_4, a->imm1);
        insns[4] = BPF_JMP_IMM(c->op, BPF_REG_4, c->imm, 2);
        insns[5] = BPF_ALU64_IMM(a->op, BPF_REG_4, a->imm2);
        insns[7] = BPF_ALU64_IMM(a->op, BPF_REG_4, a->imm3);
    }
    insns[6]  = BPF_JMP_A(1);                                   /* -> 8 */
    insns[8]  = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_4);   /* pkt += scalar */
    insns[9]  = BPF_MOV64_REG(BPF_REG_5, BPF_REG_2);
    insns[10] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, 1);
    insns[11] = BPF_JMP_REG(BPF_JGT, BPF_REG_5, BPF_REG_3, 1);   /* OOB -> 13 */
    insns[12] = BPF_STX_MEM(BPF_B, BPF_REG_2, BPF_REG_4, 0);    /* store via pkt */
    insns[13] = BPF_MOV64_IMM(BPF_REG_0, 0);
    insns[14] = BPF_EXIT_INSN();

    char name[64];
    snprintf(name, sizeof(name), "genpkt#w%s.%s.%s#%03d",
             w32 ? "32" : "64", a->name, c->name, index);
    run_one_ex(name, insns, 15, BPF_PROG_TYPE_SCHED_CLS, "sched_cls", 0);
}

// Every alu x compare x width, once each -- same enumeration/label contract.
static void run_generated_pkt_family(void) {
    int index = 0;
    for (int w32 = 0; w32 < 2; w32++)
        for (int alu_i = 0; alu_i < GEN_ALU_N; alu_i++)
            for (int cmp_i = 0; cmp_i < GEN_CMP_N; cmp_i++)
                run_generated_pkt(alu_i, cmp_i, w32, index++);
}

// ===========================================================================
// PACKET data_end COMPARE-OPERATOR SWEEP (T1-3) — the --gen-pkt family held the
// program's own bounds check fixed at `>` (BPF_JGT), the canonical idiom. That
// operator is exactly where the packet-bounds machinery has been historically wrong:
// `find_good_pkt_pointers` records a per-pointer `range` from the compare, and whether
// the range's right endpoint is CLOSED (`>`, `<`) or RIGHT-OPEN (`>=`, `<=`) shifts the
// last provable byte by one. An off-by-one here means the verifier proves ONE BYTE MORE
// (or fewer) than the program actually checked — a real OOB-write accept if it errs high.
//
// This sweep pins the offset shaping to a small known scalar and varies ONLY the range
// machinery, over two orthogonal axes the base family never touched:
//   (1) closed vs right-open — {gt,lt} prove `r5 <= end`, {ge,le} prove `r5 < end`.
//   (2) operand-order symmetry — gt (`r5 > end`) vs lt (`end < r5`) are the SAME OOB
//       condition written two ways; the verifier must treat them identically. Likewise
//       ge vs le. A gt/lt or ge/le disagreement is a symmetry bug in find_good_pkt_pointers.
//
//   0: r2 = data   1: r3 = data_end   2: r4 = skb->len
//   3: r4 &= 7                 bounded scalar offset [0,7] (partially-known -> tnum leg)
//   4: r2 += r4                PTR_TO_PACKET at data + r4
//   5: r5 = r2   6: r5 += M     headroom: the compare proves M bytes past r2
//   7: if (r5 <dcmp> r3) goto 9   THE RANGE-SETTING COMPARE (swept)   -> skip store on OOB
//   8: *(uW *)(r2 + off) = r4  STORE reaching byte off+W; accept iff off+W <= range(M,form)
//   9: r0 = 0   10: exit
//
// Prediction is NOT hand-derived: the verifier is the oracle. We MEASURE the accept
// boundary per form and assert (a) gt==lt and ge==le exactly (symmetry), (b) the closed
// and open boundaries differ by exactly one byte, (c) 0 tnum-vs-bounds divergence across
// all programs. SCHED_CLS, same as --gen-pkt.
// ===========================================================================
static const struct { const char *name; int op; int swap; } PKT_DCMP[] = {
    {"gt", BPF_JGT, 0},   // if r5 >  end  -> OOB (skip store); proves r5 <= end   CLOSED
    {"ge", BPF_JGE, 0},   // if r5 >= end  -> OOB;              proves r5 <  end   RIGHT-OPEN
    {"lt", BPF_JLT, 1},   // if end <  r5  -> OOB (== r5 > end);  proves r5 <= end  CLOSED (swapped)
    {"le", BPF_JLE, 1},   // if end <= r5  -> OOB (== r5 >= end); proves r5 <  end  RIGHT-OPEN (swapped)
};
#define PKT_DCMP_N ((int)(sizeof(PKT_DCMP) / sizeof(PKT_DCMP[0])))
static const int PKTCMP_W[] = {1, 2, 4};   // BPF_B / BPF_H / BPF_W store width

static void run_generated_pktcmp(int form_i, int m, int off, int wi, int index) {
    const int W = PKTCMP_W[wi];
    const int szmode = (W == 1) ? BPF_B : (W == 2) ? BPF_H : BPF_W;

    struct bpf_insn insns[11];
    insns[0] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 76);   /* data */
    insns[1] = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 80);   /* data_end */
    insns[2] = BPF_LDX_MEM(BPF_W, BPF_REG_4, BPF_REG_1, 0);    /* len -> unknown */
    insns[3] = BPF_ALU64_IMM(BPF_AND, BPF_REG_4, 7);           /* bound offset to [0,7] */
    insns[4] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_4);   /* pkt ptr = data + r4 */
    insns[5] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_2);
    insns[6] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, m);           /* headroom M */
    if (PKT_DCMP[form_i].swap)
        insns[7] = BPF_JMP_REG(PKT_DCMP[form_i].op, BPF_REG_3, BPF_REG_5, 1); /* end <op> r5 */
    else
        insns[7] = BPF_JMP_REG(PKT_DCMP[form_i].op, BPF_REG_5, BPF_REG_3, 1); /* r5 <op> end */
    insns[8]  = BPF_STX_MEM(szmode, BPF_REG_2, BPF_REG_4, off); /* store reaching byte off+W */
    insns[9]  = BPF_MOV64_IMM(BPF_REG_0, 0);
    insns[10] = BPF_EXIT_INSN();

    char name[80];
    snprintf(name, sizeof(name), "genpc#%s.M%d.o%d.w%d#%03d",
             PKT_DCMP[form_i].name, m, off, W, index);
    run_one_ex(name, insns, 11, BPF_PROG_TYPE_SCHED_CLS, "sched_cls", 0);
}

// form x headroom x store-offset x width -- 4*5*4*3 = 240, same order as the label index.
static void run_generated_pktcmp_family(void) {
    int index = 0;
    for (int form_i = 0; form_i < PKT_DCMP_N; form_i++)
        for (int m = 1; m <= 5; m++)
            for (int off = 0; off <= 3; off++)
                for (int wi = 0; wi < 3; wi++)
                    run_generated_pktcmp(form_i, m, off, wi, index++);
}

// ---- runtime ground-truth oracle (--gen-rt) --------------------------------
// The FIRST oracle that does not trust the verifier's own log to be self-
// consistent. Load an accepted program that RETURNS a verifier-bounded value
// derived from a fully attacker-controlled 32-bit input (a map value we set from
// userspace), then EXECUTE it via BPF_PROG_TEST_RUN over a sweep of inputs and
// print the ACTUAL retval for each. The pipeline compares each retval against the
// verifier's claimed bound on the return register: a retval outside
// [u32_min,u32_max] means the verifier proved a bound the runtime violated -- a
// soundness bug caught even when the tnum and u32 views AGREE with each other
// (the "consistent-but-wrong" blind spot every log-only invariant shares).
//
// v1 keeps every shape's result within 32 bits (umax < 2^32) so retval is the
// return register's exact value and the comparison is unambiguous.

static int rt_map_set(int map_fd, uint32_t key, uint32_t val) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = map_fd;
    a.key = (uint64_t)(unsigned long)&key;
    a.value = (uint64_t)(unsigned long)&val;
    a.flags = 0; /* BPF_ANY */
    return bpf(BPF_MAP_UPDATE_ELEM, &a, sizeof(a));
}

/* extremes + interior values that hit the bound edges of the shapes below. */
static const uint32_t RT_INPUTS[] = {
    0x00000000u, 0x00000001u, 0x0000007fu, 0x000000ffu, 0x00007fffu, 0x0000ffffu,
    0x7fffffffu, 0x80000000u, 0xfffffffeu, 0xffffffffu, 0x5a5a5a5au, 0xdeadbeefu,
};
#define RT_INPUTS_N ((int)(sizeof(RT_INPUTS) / sizeof(RT_INPUTS[0])))

static void run_rt_one(const char *name, const struct bpf_insn *insns, int n, int map_fd) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        /* 64-byte zero packet: content is irrelevant (the computed input comes
           from the map), but skb-based test_run needs a non-empty packet. */
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < RT_INPUTS_N; i++) {
            uint32_t in = RT_INPUTS[i];
            int uerr = rt_map_set(map_fd, 0, in);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            if (r < 0 || uerr < 0)
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d map_err=%d\n",
                       in, r < 0 ? errno : 0, uerr);
            else
                printf("RUNTIME input=0x%08x retval=0x%08x\n", in,
                       (unsigned)t.test.retval);
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

enum rt_shape { RT_AND, RT_AND_ADD, RT_AND_LSH, RT_CMP, RT_ALU32 };
static const char *rt_shape_name(enum rt_shape s) {
    switch (s) {
    case RT_AND:     return "and";
    case RT_AND_ADD: return "andadd";
    case RT_AND_LSH: return "andlsh";
    case RT_CMP:     return "cmp";
    case RT_ALU32:   return "alu32";
    }
    return "?";
}

static void run_rt_prog(enum rt_shape shape, uint32_t p1, uint32_t p2,
                        int idx, int map_fd) {
    struct bpf_insn ins[32];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_fd};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int jnull = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0); /* r6 = attacker input */
    int jcmp = -1;
    switch (shape) {
    case RT_AND:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, p1);
        break;
    case RT_AND_ADD:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, p1);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, p2);
        break;
    case RT_AND_LSH:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, p1);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, p2);
        break;
    case RT_CMP:
        jcmp = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, p1, 0); /* >p1 -> return 0 */
        break;
    case RT_ALU32:
        ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, p1);
        ins[n++] = BPF_ALU32_IMM(BPF_OR, BPF_REG_6, p2);
        break;
    }
    ins[n++] = BPF_MOV64_REG(BPF_REG_0, BPF_REG_6); /* return the bounded value */
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jnull].off = exit0 - jnull - 1;
    if (jcmp >= 0) ins[jcmp].off = exit0 - jcmp - 1;

    char name[80];
    snprintf(name, sizeof(name), "genrt#%s#%03d", rt_shape_name(shape), idx);
    run_rt_one(name, ins, n, map_fd);
}

static void run_generated_rt_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_fd = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_fd < 0) {
        printf("===PROG genrt type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int idx = 0;
    const uint32_t and_masks[] = {0x1u, 0x7fu, 0xffu, 0xffffu, 0xfffffu, 0x7fffffffu};
    for (int i = 0; i < (int)(sizeof(and_masks)/sizeof(and_masks[0])); i++)
        run_rt_prog(RT_AND, and_masks[i], 0, idx++, map_fd);
    /* AND then ADD: [add, mask+add], both fit in 32 bits. */
    const uint32_t aa_mask[] = {0xffu, 0xffffu, 0xfffffu};
    const uint32_t aa_add[]  = {1u, 100u, 0x1000u};
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            run_rt_prog(RT_AND_ADD, aa_mask[i], aa_add[j], idx++, map_fd);
    /* AND then LSH: mask<<shift stays < 2^32. */
    const uint32_t al_mask[] = {0xfu, 0xffu, 0xfffu};
    const uint32_t al_shift[] = {4u, 8u, 12u};
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            run_rt_prog(RT_AND_LSH, al_mask[i], al_shift[j], idx++, map_fd);
    /* compare-narrow: return path has value in [0, K]. */
    const uint32_t cmp_k[] = {10u, 0xffu, 0xffffu, 0x7fffffu};
    for (int i = 0; i < 4; i++)
        run_rt_prog(RT_CMP, cmp_k[i], 0, idx++, map_fd);
    /* 32-bit ALU AND|OR: the CVE-2021-3490 flavour (32-bit bounds update path). */
    const uint32_t a32_and[] = {0xffu, 0xffffu, 0xf0f0f0u};
    const uint32_t a32_or[]  = {0x0u, 0x5u, 0xf00u};
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 3; j++)
            run_rt_prog(RT_ALU32, a32_and[i], a32_or[j], idx++, map_fd);
    close(map_fd);
}

// ---- runtime memory-safety oracle for map-value STORES (--gen-rtw) ----------
// The v2 extension of the runtime oracle: instead of checking a returned SCALAR
// against the verifier's bound, it checks MEMORY SAFETY directly. The program
// computes an attacker-controlled offset (verifier-bounded to be in-bounds) and
// STORES a sentinel through a map-value pointer at that offset. Userspace zeroes
// the target map, runs the program, reads the map back, and locates the sentinel.
//
// The check needs NO bound parsing: an accepted store is CLAIMED in-bounds, so on
// a sound kernel the sentinel MUST land inside the map value. If the sentinel is
// ABSENT, the store went out of bounds (into kernel memory we cannot see) — the
// verifier accepted an OOB write. This is the direct memory-safety property, the
// surface where real exploitable verifier bugs live.

static int rt_map_set_bytes(int map_fd, uint32_t key, const void *val) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = map_fd;
    a.key = (uint64_t)(unsigned long)&key;
    a.value = (uint64_t)(unsigned long)val;
    a.flags = 0;
    return bpf(BPF_MAP_UPDATE_ELEM, &a, sizeof(a));
}

static int rt_map_get(int map_fd, uint32_t key, void *val_out) {
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.map_fd = map_fd;
    a.key = (uint64_t)(unsigned long)&key;
    a.value = (uint64_t)(unsigned long)val_out;
    return bpf(BPF_MAP_LOOKUP_ELEM, &a, sizeof(a));
}

#define RTW_VALUE_SIZE 64
#define RTW_SENTINEL 0xFF

enum rtw_shape { RTW_AND, RTW_ANDADD, RTW_OVER };
static const char *rtw_shape_name(enum rtw_shape s) {
    switch (s) {
    case RTW_AND:    return "and";
    case RTW_ANDADD: return "andadd";
    case RTW_OVER:   return "over";
    }
    return "?";
}

static void run_rtw_one(const char *name, const struct bpf_insn *insns, int n,
                        int map_in, int map_out) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < RT_INPUTS_N; i++) {
            uint32_t in = RT_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE];
            memset(zero, 0, sizeof(zero));
            int ue = rt_map_set(map_in, 0, in);
            int ze = rt_map_set_bytes(map_out, 0, zero);
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none\n", in);
            else
                printf("RUNTIME input=0x%08x store_off=%d\n", in, off);
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_rtw_prog(enum rtw_shape shape, uint32_t mask, uint32_t add,
                         int idx, int map_in, int map_out) {
    struct bpf_insn ins[40];
    int n = 0;
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);            /* key = 0 */
    /* lookup map_in -> r0 */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int j1 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);     /* r6 = attacker input */
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, mask);         /* shape the offset */
    if (shape == RTW_ANDADD)
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, add);
    /* lookup map_out -> r0 (r6 survives: callee-saved) */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    const int j2 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);             /* r7 = map_out value ptr */
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);    /* r7 += offset */
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, 0, RTW_SENTINEL);   /* store sentinel byte */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[j1].off = exit0 - j1 - 1;
    ins[j2].off = exit0 - j2 - 1;

    char name[80];
    snprintf(name, sizeof(name), "genrtw#%s#%03d", rtw_shape_name(shape), idx);
    run_rtw_one(name, ins, n, map_in, map_out);
}

static void run_generated_rtw_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genrtw type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int idx = 0;
    /* in-bounds masks (off <= mask <= 63, 1-byte store fits) -> ACCEPT, runtime-checked. */
    const uint32_t masks[] = {0x7u, 0xfu, 0x1fu, 0x3fu};
    for (int i = 0; i < 4; i++)
        run_rtw_prog(RTW_AND, masks[i], 0, idx++, map_in, map_out);
    /* AND then ADD: off in [C, C+15], all <= 63 -> ACCEPT. */
    const uint32_t adds[] = {0u, 24u, 48u};
    for (int i = 0; i < 3; i++)
        run_rtw_prog(RTW_ANDADD, 0xfu, adds[i], idx++, map_in, map_out);
    /* over-wide masks (off up to 127 > 63) -> the verifier must REJECT (control). */
    const uint32_t over[] = {0x7fu, 0xffu};
    for (int i = 0; i < 2; i++)
        run_rtw_prog(RTW_OVER, over[i], 0, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- T2-2: multi-byte store-WIDTH memory-safety oracle (--gen-rtw2) ----------
// The off-by-one a real verifier bug would hit lives in the in-bounds check
// `off + size <= value_size`, so the axis under test is the store WIDTH, not just
// the base offset. A multi-byte store is memory-safe iff ALL `size` sentinel bytes
// land inside the map value; a store that ends one byte past the end is a partial
// OOB write even though its base offset is in-bounds. The program stores `size`
// bytes of 0xFF (BPF_ST_MEM imm=-1). Userspace zeroes map_out BEFORE EVERY run
// (inherited from --gen-rtw's per-input loop — the sole 0xFF source is this store,
// so a stale sentinel from a prior sweep step can never be miscounted), runs the
// program, reads the value back, finds the FIRST 0xFF (store_off) and counts the
// consecutive 0xFF run (store_len), and reports store_size. The pipeline requires
// store_len == store_size for an accepted store: a truncated run (store_len <
// store_size) or store_off=none is a partial/total OOB write the verifier accepted.
// Two shapes: (a) and.wN — attacker offset r6 &= MASK, store size N at map_out+r6
// (accept iff MASK + N <= value_size); (b) bndc.wN — a CONST offset baked into the
// ST insn's off field: off = V-N stores up to exactly the end (ACCEPT), off = V-N+1
// runs one byte past it (REJECT) — the exact off-by-one control.

static int rtw2_size_code(int size) {
    switch (size) {
    case 1: return BPF_B;
    case 2: return BPF_H;
    case 4: return BPF_W;
    case 8: return BPF_DW;
    }
    return BPF_B;
}

static void run_rtw2_one(const char *name, const struct bpf_insn *insns, int n,
                         int map_in, int map_out, int store_size) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < RT_INPUTS_N; i++) {
            uint32_t in = RT_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE];
            memset(zero, 0, sizeof(zero));
            int ue = rt_map_set(map_in, 0, in);
            int ze = rt_map_set_bytes(map_out, 0, zero); /* re-zero BEFORE every run */
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            if (off < 0) {
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=%d\n",
                       in, store_size);
            } else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++)
                    len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=%d\n",
                       in, off, len, store_size);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

enum rtw2_shape { RTW2_AND, RTW2_BNDC };

static void run_rtw2_prog(enum rtw2_shape shape, uint32_t mask, int store_size,
                          int const_off, int idx, int map_in, int map_out) {
    struct bpf_insn ins[40];
    int n = 0;
    int sc = rtw2_size_code(store_size);
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);               /* key = 0 */
    if (shape == RTW2_AND) {
        /* lookup map_in -> r0 (attacker offset source) */
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int j1 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);    /* r6 = attacker input */
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, mask);        /* r6 &= MASK -> [0,MASK] */
        /* lookup map_out -> r0 (r6 survives: callee-saved) */
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int j2 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);            /* r7 = map_out value ptr */
        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);   /* r7 += offset */
        ins[n++] = BPF_ST_MEM(sc, BPF_REG_7, 0, -1);              /* store N sentinel bytes */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        ins[j1].off = exit0 - j1 - 1;
        ins[j2].off = exit0 - j2 - 1;
    } else { /* RTW2_BNDC: const offset baked into the ST insn's off field */
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        const int j1 = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);            /* r7 = map_out value ptr */
        ins[n++] = BPF_ST_MEM(sc, BPF_REG_7, const_off, -1);      /* store N bytes at const off */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        ins[j1].off = exit0 - j1 - 1;
    }

    char name[96];
    snprintf(name, sizeof(name), "genrtw2#%s.w%d#%03d",
             shape == RTW2_AND ? "and" : "bndc", store_size, idx);
    run_rtw2_one(name, ins, n, map_in, map_out, store_size);
}

static void run_generated_rtw2_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genrtw2 type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    int idx = 0;
    const uint32_t masks[] = {0x7u, 0x1fu, 0x3fu};
    const int sizes[] = {1, 2, 4, 8};
    /* (a) and.wN: r6 &= MASK (umax = MASK), store size N at map_out+r6.
       Accept iff MASK + N <= value_size (64). 0x7/0x1f accept every N;
       0x3f accepts only N=1 (63+1=64), rejects N>=2 (65,67,71 > 64). */
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 4; j++)
            run_rtw2_prog(RTW2_AND, masks[i], sizes[j], 0, idx++, map_in, map_out);
    /* (b) bndc.wN: const offset. off = V-N ends exactly at V (ACCEPT);
       off = V-N+1 runs one byte past V (REJECT) — the exact off-by-one. */
    for (int j = 0; j < 4; j++) {
        run_rtw2_prog(RTW2_BNDC, 0, sizes[j], RTW_VALUE_SIZE - sizes[j],
                      idx++, map_in, map_out);       /* accept: ends at V */
        run_rtw2_prog(RTW2_BNDC, 0, sizes[j], RTW_VALUE_SIZE - sizes[j] + 1,
                      idx++, map_in, map_out);       /* reject: one past V */
    }
    close(map_in);
    close(map_out);
}

// ---- store-LOCATION desync oracle (--gen-loc) -------------------------------
// The runtime-write legs so far (0037/0038/0039) ask one question: did the store
// stay INSIDE the object? A verifier can pass that and still be wrong. If its
// abstract arithmetic for the offset is unsound, the store lands at an offset its
// OWN state says is impossible — and still inside the object, so every previous leg
// stays silent. That is the "consistent-but-wrong" class: the verifier's two views
// agree with each other and disagree only with reality, which is exactly what an
// internal-consistency oracle can never see.
//
// So this family asks the strictly stronger question: did the store land WHERE THE
// VERIFIER SAID it could? The verifier prints its own claim at the store:
//   17: R7=map_value(ks=4,vs=64,smin=0,smax=umax=7,var_off=(0x0; 0x7))
//   17: (72) *(u8 *)(r7 +0) = -1
// i.e. "offset in [0,7], and only at offsets whose bits fit (0x0; 0x7)". The runtime
// says where the sentinel actually landed. The diff stage compares the two.
//
// The AXIS is therefore the ALU chain that shapes the offset — one program per
// abstract transfer function, because that is where a too-narrow (unsound) bound
// would come from. Each chain is chosen so its proven window is TIGHT: a wide window
// would let a wrong offset pass, and the tnum arms (lsh/mul/compose) are the sharpest
// because their proven set has HOLES — `r6 &= 3; r6 <<= 2` proves {0,4,8,12}, so an
// offset of 6 is inside [0,12] and still impossible. An interval check alone would
// miss it; the tnum half is what makes "where it SAID" mean the exact set.
//
// The harness declares the store site (`STORE insn= reg= off= size=`) because it
// BUILT the program: which instruction stores, through which register, is ground
// truth about the input. Recovering it from the verifier's own disassembly would
// make the oracle depend on the component it is auditing.

enum loc_shape {
    LOC_AND7, LOC_AND31, LOC_ORAND, LOC_ADDC, LOC_SUBC,
    LOC_LSH2, LOC_LSH3, LOC_RSH, LOC_MUL, LOC_XOR,
    LOC_ALU32, LOC_JMP, LOC_SHPAIR, LOC_COMPOSE, LOC_OFF4,
};

static const char *loc_shape_name(enum loc_shape s) {
    switch (s) {
    case LOC_AND7:    return "and7";
    case LOC_AND31:   return "and31";
    case LOC_ORAND:   return "orand";
    case LOC_ADDC:    return "addc";
    case LOC_SUBC:    return "subc";
    case LOC_LSH2:    return "lsh2";
    case LOC_LSH3:    return "lsh3";
    case LOC_RSH:     return "rsh";
    case LOC_MUL:     return "mul";
    case LOC_XOR:     return "xor";
    case LOC_ALU32:   return "alu32";
    case LOC_JMP:     return "jmp";
    case LOC_SHPAIR:  return "shpair";
    case LOC_COMPOSE: return "compose";
    case LOC_OFF4:    return "off4";
    }
    return "?";
}

static void run_loc_one(const char *name, const struct bpf_insn *insns, int n,
                        int map_in, int map_out, int store_insn, int store_off) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);
    /* generator provenance: where the store IS, not where the verifier says it is */
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, store_off);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < RT_INPUTS_N; i++) {
            uint32_t in = RT_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE];
            memset(zero, 0, sizeof(zero));
            int ue = rt_map_set(map_in, 0, in);
            int ze = rt_map_set_bytes(map_out, 0, zero); /* re-zero BEFORE every run */
            union bpf_attr t;
            memset(&t, 0, sizeof(t));
            t.test.prog_fd = fd;
            t.test.data_in = (uint64_t)(unsigned long)pkt;
            t.test.data_size_in = sizeof(pkt);
            t.test.repeat = 1;
            int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
            unsigned char out[RTW_VALUE_SIZE];
            memset(out, 0, sizeof(out));
            int ge = rt_map_get(map_out, 0, out);
            if (r < 0 || ue < 0 || ze < 0 || ge < 0) {
                printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n",
                       in, r < 0 ? errno : 0);
                continue;
            }
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int executed = (t.test.retval == 1);
            if (off < 0) {
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            } else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++)
                    len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_loc_prog(enum loc_shape shape, int idx, int map_in, int map_out) {
    struct bpf_insn ins[48];
    int n = 0;
    int jfix[4]; int nj = 0;
    int st_off = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);               /* key = 0 */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jfix[nj++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);        /* r6 = attacker input */

    /* the axis: one abstract transfer function per program */
    switch (shape) {
    case LOC_AND7:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); break;            /* [0,7] */
    case LOC_AND31:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 31); break;           /* [0,31] */
    case LOC_ORAND:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_OR, BPF_REG_6, 8); break;             /* [8,15] */
    case LOC_ADDC:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 16); break;           /* [16,23] */
    case LOC_SUBC:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 32);
        ins[n++] = BPF_ALU64_IMM(BPF_SUB, BPF_REG_6, 8); break;            /* [24,31] */
    case LOC_LSH2:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 2); break;            /* {0,4,8,12} */
    case LOC_LSH3:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 3); break;            /* {0,8,..,56} */
    case LOC_RSH:
        ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 29); break;           /* [0,7] */
    case LOC_MUL:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3);
        ins[n++] = BPF_ALU64_IMM(BPF_MUL, BPF_REG_6, 5); break;            /* {0,5,10,15} */
    case LOC_XOR:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_XOR, BPF_REG_6, 5); break;            /* [0,7] */
    case LOC_ALU32:
        ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, 7); break;            /* 32-bit op */
    case LOC_JMP:
        /* bound by a BRANCH, not a mask: reg_set_min_max, a different code path */
        jfix[nj++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0); break;
    case LOC_SHPAIR:
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 60);
        ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 60); break;           /* [0,15] */
    case LOC_COMPOSE:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 2); break;            /* {4,8,12,16} */
    case LOC_OFF4:
        /* same [0,7] offset, but the store carries its own +4: exercises the
           `ptr_off + insn_off + var` arithmetic on both sides of the comparison */
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); st_off = 4; break;
    }

    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jfix[nj++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);                /* r7 = map_out value */
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);       /* r7 += shaped offset */
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, st_off, -1);           /* the observed store */
    /* EXECUTION WITNESS. `store_off=none` means "no sentinel in the value", which
       conflates two very different things: the store ran and went OUT OF BOUNDS, or
       the store never ran at all. Every earlier runtime-write family (--gen-rtw,
       --gen-rtw2, --gen-pktw) reached its store unconditionally, so `none` could only
       mean the first. The LOC_JMP arm breaks that: it bounds the offset with a BRANCH,
       so every sweep input above the bound skips the store entirely. The program
       itself reports which happened -- r0=1 only on the path that performed the
       store, r0=0 on every skip path -- so the disambiguation is runtime ground
       truth from the input side, not a guess in the diff stage. */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nj; i++)
        ins[jfix[i]].off = exit0 - jfix[i] - 1;

    char name[96];
    snprintf(name, sizeof(name), "genloc#%s#%03d", loc_shape_name(shape), idx);
    run_loc_one(name, ins, n, map_in, map_out, store_insn, st_off);
}

static void run_generated_loc_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 8; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genloc type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Every chain keeps the landing site well inside the 64-byte value, so the
       DECISION is not the surface here — all 15 are expected to be accepted, and the
       surface is WHERE each accepted store lands versus what the verifier proved. */
    const enum loc_shape shapes[] = {
        LOC_AND7, LOC_AND31, LOC_ORAND, LOC_ADDC, LOC_SUBC,
        LOC_LSH2, LOC_LSH3, LOC_RSH, LOC_MUL, LOC_XOR,
        LOC_ALU32, LOC_JMP, LOC_SHPAIR, LOC_COMPOSE, LOC_OFF4,
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++)
        run_loc_prog(shapes[i], idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- packet-write runtime memory-safety oracle (--gen-pktw) -----------------
// The runtime-write oracle so far (--gen-rtw / --gen-rtw2) stores through a
// PTR_TO_MAP_VALUE, whose bound the verifier KNOWS statically (value_size). This
// leg is the PACKET analog: a store through a PTR_TO_PACKET, whose bound the
// verifier does NOT know — the PROGRAM proves it with its own `data + M > data_end`
// compare and the verifier statically TRACKS the resulting `range`
// (find_good_pkt_pointers, verifier.c). That range machinery is the historically
// densest packet-bounds bug region, and the load-only packet families (--gen-pkt /
// --gen-pkt-cmp) can only see accept/reject and the verifier's OWN self-consistency
// — never where the store actually LANDS. This one EXECUTES the accepted program
// via BPF_PROG_TEST_RUN and reads the packet back, so it catches a range that is
// internally consistent but WRONG (the blind spot every log-only leg shares).
//
// Shape (SCHED_CLS — socket_filter forbids direct packet access):
//   0: r2 = *(u32*)(r1+76)   data      -> PTR_TO_PACKET
//   1: r3 = *(u32*)(r1+80)   data_end  -> PTR_TO_PACKET_END
//   2: r5 = r2   3: r5 += M   headroom the compare will prove
//   4: if (r5 > r3) goto 6    proves data + M <= data_end -> range = M bytes
//   5: *(uW*)(r2 + off) = -1  store W sentinel bytes; accepted iff off + W <= M
//   6: r0 = 0   7: exit
//
// The runtime packet length is set to EXACTLY M, so data_end lands at byte M and the
// compare `data+M > data_end` is false (M <= M) — the accepted store executes. On a
// sound kernel every accepted store has off + W <= M, so all W sentinel bytes land
// in [0, M) and are copied back in data_out (store_len == store_size). A verifier
// that accepted off + W = M + 1 (a range off-by-one) would put the store's last byte
// AT data_end — in skb tailroom, which test_run never copies back — so the sentinel
// run is truncated (store_len < store_size) or absent: exactly the runtime_oob_write
// the shared diff predicate already fires on. The one-past programs (off = M-W+1) are
// the reject control: a sound verifier rejects them, so they never execute and never
// count — a buggy one would accept, run, and truncate.
//
// The output format is byte-identical to --gen-rtw2, so the parser, the diff
// predicate (check_runtime_write_safety), and the metrics counters are reused
// UNCHANGED; only the bytes' provenance differs (packet read-back vs map read-back).
// First increment pins the compare to the canonical closed `>` idiom; sweeping the
// operator (`>=` right-open, operand-order symmetry) is the natural follow-up, as
// --gen-pkt -> --gen-pkt-cmp did for the load-only side.

#define PKTW_M 32   /* proven headroom == runtime packet length (>= ETH_HLEN = 14) */

static void run_pktw_one(const char *name, const struct bpf_insn *insns, int n,
                         int pkt_size, int store_size) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=sched_cls ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        /* Fresh skb per run: data_in is zeroed, so the ONLY 0xFF bytes come from
           the store. data_end lands at data + pkt_size, so byte pkt_size is the
           first out-of-bounds byte (skb tailroom, never copied back to data_out). */
        unsigned char in[RTW_VALUE_SIZE];
        unsigned char out[RTW_VALUE_SIZE];
        memset(in, 0, sizeof(in));
        memset(out, 0, sizeof(out));
        union bpf_attr t;
        memset(&t, 0, sizeof(t));
        t.test.prog_fd = fd;
        t.test.data_in = (uint64_t)(unsigned long)in;
        t.test.data_size_in = pkt_size;
        t.test.data_out = (uint64_t)(unsigned long)out;
        t.test.data_size_out = sizeof(out);
        t.test.repeat = 1;
        int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
        if (r < 0) {
            printf("RUNTIME input=0x%08x error=1 testrun_errno=%d\n", pkt_size, errno);
        } else {
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            if (off < 0) {
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=%d\n",
                       pkt_size, store_size);
            } else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++)
                    len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=%d\n",
                       pkt_size, off, len, store_size);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_pktw_prog(int store_size, int const_off, int idx) {
    struct bpf_insn ins[16];
    int n = 0;
    int sc = rtw2_size_code(store_size);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 76);   /* r2 = data */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 80);   /* r3 = data_end */
    ins[n++] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_2);            /* r5 = data */
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, PKTW_M);      /* r5 = data + M */
    const int jc = n;
    ins[n++] = BPF_JMP_REG(BPF_JGT, BPF_REG_5, BPF_REG_3, 0);  /* if r5 > data_end -> skip */
    ins[n++] = BPF_ST_MEM(sc, BPF_REG_2, const_off, -1);       /* store W sentinel bytes at data+off */
    const int skip = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    ins[jc].off = skip - jc - 1;

    char name[96];
    snprintf(name, sizeof(name), "genpktw#w%d.o%d#%03d", store_size, const_off, idx);
    run_pktw_one(name, ins, n, PKTW_M, store_size);
}

static void run_generated_pktw_family(void) {
    int idx = 0;
    const int sizes[] = {1, 2, 4, 8};
    /* Closed `>` form: the compare proves M bytes past data, so a store reaching
       byte off + W is accepted iff off + W <= M (= PKTW_M). Three arms per width:
       an interior accept at off 0, a boundary accept ending exactly at byte M-1
       (off = M-W, the tightest in-bounds store), and the off-by-one at off = M-W+1
       whose last byte would be AT data_end -> the verifier must REJECT it. */
    for (int j = 0; j < 4; j++) {
        int W = sizes[j];
        run_pktw_prog(W, 0, idx++);                 /* interior accept */
        run_pktw_prog(W, PKTW_M - W, idx++);        /* boundary accept: ends at byte M-1 */
        run_pktw_prog(W, PKTW_M - W + 1, idx++);    /* off-by-one -> reject */
    }
}

// ---- packet-write observation-channel probe (--probe-pktw) ------------------
// 0039's packet oracle rests on a CLAIM about the observation channel:
// bpf_prog_test_run_skb copies back only [0, skb->len), so a store past data_end lands
// in skb tailroom and is never returned — which is exactly why an absent or truncated
// sentinel run is read as an OOB write. That claim was ARGUED from reading the kernel,
// never MEASURED: on a sound verifier every OOB store is REJECTED, so 0039 never
// observed a true OOB and never exercised the channel's negative half. The next leg
// (store-location desync) will assert "the verifier proved X, the store landed at Y",
// so the channel has to be shown to resolve bytes precisely BEFORE it is trusted to
// locate a store — otherwise a desync finding could be a channel artefact.
//
// The probe measures the window using ACCEPTED programs only, by moving the WINDOW
// instead of the store: bpf_skb_change_tail() shrinks skb->len AFTER the store has run,
// so a byte that WAS written into the packet buffer ends up beyond the returned length —
// the exact geometry of an OOB store, produced without needing a buggy verifier.
//
//   probe#pktw.win32     in=32, store at 31           -> out_size == 32, store visible
//   probe#pktw.win40     in=40, same program          -> out_size tracks skb->len (40)
//   probe#pktw.trim.o19  in=32, store at 19, tail->20 -> VISIBLE: last returned byte
//   probe#pktw.trim.o20  in=32, store at 20, tail->20 -> ABSENT: first byte past it
//
// The last two are the byte-precise edge: identical shape, identical shrink, offsets one
// apart, opposite observability — so "absent" is positional, not an artefact of
// change_tail touching the data. `tail_zero` additionally reports that our pre-zeroed
// output buffer is STILL zero beyond out_size, so bytes out there can never be misread
// as a sentinel (the positive half of the same claim).

static void run_pktw_probe_one(const char *name, const struct bpf_insn *insns, int n,
                               int in_size) {
    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SCHED_CLS;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;

    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    printf("===PROG %s type=sched_cls ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e,
           (unsigned long long)dt);

    if (fd >= 0) {
        unsigned char in[RTW_VALUE_SIZE];
        unsigned char out[RTW_VALUE_SIZE];
        memset(in, 0, sizeof(in));
        memset(out, 0, sizeof(out));
        union bpf_attr t;
        memset(&t, 0, sizeof(t));
        t.test.prog_fd = fd;
        t.test.data_in = (uint64_t)(unsigned long)in;
        t.test.data_size_in = in_size;
        t.test.data_out = (uint64_t)(unsigned long)out;
        t.test.data_size_out = sizeof(out);
        t.test.repeat = 1;
        int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
        if (r < 0) {
            printf("CHANNEL in_size=%d error=1 testrun_errno=%d\n", in_size, errno);
        } else {
            /* the kernel writes the ACTUAL output length back into the attr */
            unsigned out_size = t.test.data_size_out;
            int off = -1;
            for (int b = 0; b < RTW_VALUE_SIZE; b++)
                if (out[b] == RTW_SENTINEL) { off = b; break; }
            int tail_zero = 1;
            for (unsigned b = out_size; b < (unsigned)RTW_VALUE_SIZE; b++)
                if (out[b] != 0) { tail_zero = 0; break; }
            if (off < 0)
                printf("CHANNEL in_size=%d out_size=%u retval=%u store_off=none tail_zero=%d\n",
                       in_size, out_size, t.test.retval, tail_zero);
            else
                printf("CHANNEL in_size=%d out_size=%u retval=%u store_off=%d tail_zero=%d\n",
                       in_size, out_size, t.test.retval, off, tail_zero);
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

/* store 1 sentinel byte at `off` behind the usual `data + PKTW_M > data_end` proof;
   when trim_to > 0, shrink skb->len to trim_to AFTERWARDS so the window moves under
   an already-written byte. r1 still holds the ctx at the call site. */
static void run_pktw_probe_prog(const char *name, int off, int in_size, int trim_to) {
    struct bpf_insn ins[16];
    int n = 0;
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1, 76);   /* r2 = data */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_1, 80);   /* r3 = data_end */
    ins[n++] = BPF_MOV64_REG(BPF_REG_5, BPF_REG_2);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_5, PKTW_M);      /* r5 = data + M */
    const int jc = n;
    ins[n++] = BPF_JMP_REG(BPF_JGT, BPF_REG_5, BPF_REG_3, 0);  /* skip store if short */
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, off, -1);          /* sentinel at data+off */
    const int skip = n;
    if (trim_to > 0) {
        ins[n++] = BPF_MOV64_IMM(BPF_REG_2, trim_to);          /* new_len */
        ins[n++] = BPF_MOV64_IMM(BPF_REG_3, 0);                /* flags */
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_skb_change_tail);    /* r0 = 0 on success */
    } else {
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    }
    ins[n++] = BPF_EXIT_INSN();
    ins[jc].off = skip - jc - 1;
    run_pktw_probe_one(name, ins, n, in_size);
}

static void run_probe_pktw_family(void) {
    /* window geometry: out_size == skb->len, and it MOVES with the input length */
    run_pktw_probe_prog("probe#pktw.win32",    PKTW_M - 1, PKTW_M,     0);
    run_pktw_probe_prog("probe#pktw.win40",    PKTW_M - 1, PKTW_M + 8, 0);
    /* byte-precise edge: same shrink, offsets one apart, opposite observability */
    run_pktw_probe_prog("probe#pktw.trim.o19", 19,         PKTW_M,     20);
    run_pktw_probe_prog("probe#pktw.trim.o20", 20,         PKTW_M,     20);
}

int main(int argc, char **argv) {
    // Two data sources, kept apart on purpose (different provenance):
    //   (no args) the fixed authoritative program set, pinned by tests
    //   --gen     the enumerated targeted family (devlog 0025)
    if (argc > 1 && strcmp(argv[1], "--gen") == 0) {
        run_generated_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-mix") == 0) {
        run_mixed_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rr") == 0) {
        run_generated_rr_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-mb") == 0) {
        run_generated_mb_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-ptr") == 0) {
        run_generated_ptr_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-ptr-neg") == 0) {
        run_generated_ptrneg_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-t1") == 0) {
        run_probe_t1_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-ptr-hi") == 0) {
        run_generated_hi_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-t1b") == 0) {
        run_probe_t1b_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-sync") == 0) {
        run_generated_sync_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-pkt") == 0) {
        run_generated_pkt_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-pkt-cmp") == 0) {
        run_generated_pktcmp_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rt") == 0) {
        run_generated_rt_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rtw") == 0) {
        run_generated_rtw_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rtw2") == 0) {
        run_generated_rtw2_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-loc") == 0) {
        run_generated_loc_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-pktw") == 0) {
        run_probe_pktw_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-pktw") == 0) {
        run_generated_pktw_family();
        return 0;
    }

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
