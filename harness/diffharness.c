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
#include <linux/btf.h>
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
/* 32-bit register move: the alu32 form zero-extends, which is exactly why the verifier
   keeps BPF_ADD_CONST32 and BPF_ADD_CONST64 as distinct link flags and refuses to prune
   across them. */
#define BPF_MOV32_REG(DST, SRC)                                                \
    ((struct bpf_insn){.code = BPF_ALU | BPF_MOV | BPF_X,                      \
                       .dst_reg = DST, .src_reg = SRC, .off = 0, .imm = 0})
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


// ---- pruning-soundness differential (--gen-prune) ---------------------------
// A NEW ORACLE CLASS: kernel-vs-kernel. Every earlier leg compares the verifier
// against something WE compute (an invariant, a bound, a runtime observation). This
// one compares the verifier against ITSELF under a flag the kernel provides for
// exactly this purpose, so there is no bound parsing and no oracle of ours to be
// wrong.
//
// BPF_F_TEST_STATE_FREQ (states.c: `force_new_state = env->test_state_freq || ...`,
// then `add_new_state = force_new_state`) makes the verifier record a checkpoint at
// EVERY instruction. The default heuristic only checkpoints after >= 2 jumps AND
// >= 8 instructions. So the flag does NOT disable pruning -- it makes pruning MORE
// aggressive, by handing regsafe()/states_equal() far more candidate pairs.
//
// That fixes the direction of the finding:
//   flagged ACCEPT + default REJECT  ->  a path that produces the rejection was
//                                        pruned away: a PRUNING SOUNDNESS bug.
//   flagged REJECT + default ACCEPT  ->  almost certainly a resource artefact
//                                        (BPF_COMPLEXITY_LIMIT_INSNS, "BPF program
//                                        is too large", -E2BIG), classified by the
//                                        reject reason and NOT counted as a finding.
// A difference in state COUNT is not a finding either -- it is the denominator that
// proves the flag engaged at all. Identical counts would make a zero finding count
// meaningless, exactly like store_locations_checked in 0041.
//
// For a wrong prune to be OBSERVABLE the program needs three things: convergent
// control flow, two incoming states that regsafe must genuinely judge (not identical),
// and a downstream access whose safety DEPENDS on which path was taken. The last one
// is what turns a wrong prune into a decision flip; without it the bug is silent.
//
// Shape: two attacker values (offset source r6, branch selector r9) are read from one
// map value, so the split does NOT constrain the offset -- each path's state for r6
// comes purely from its own shaper. The paths converge and store 1 byte at
// map_value + r6 + 56, which is in bounds iff umax(r6) <= 7. The verifier explores the
// FALL-THROUGH first (check_cond_jmp_op pushes the jump target for later), so the
// fall-through shaper is the one that records the checkpoint at the merge -- which is
// why the ORDER is an axis and not an accident.
/* Not in every distro's uapi header yet; the value is fixed ABI (uapi/linux/bpf.h). */
#ifndef BPF_F_TEST_STATE_FREQ
#define BPF_F_TEST_STATE_FREQ (1U << 3)
#endif
#ifndef BPF_F_TEST_REG_INVARIANTS
#define BPF_F_TEST_REG_INVARIANTS (1U << 7)
#endif

#define PRUNE_STORE_OFF 56   /* 1-byte store is in bounds iff umax(r6) <= 7 */

static char g_log2[256 * 1024];

enum prune_shaper {
    SH_N7,   /* r6 &= 7          -> [0,7]        SAFE  */
    SH_T6,   /* (r6 &= 3) << 1   -> {0,2,4,6}    SAFE, tnum-refined inside [0,7] */
    SH_W63,  /* r6 &= 63         -> [0,63]       unsafe, strict superset of [0,7] */
    SH_M39,  /* (r6 &= 7) | 32   -> [32,39]      unsafe, DISJOINT from [0,7] */
    SH_O19,  /* (r6 &= 15) + 4   -> [4,19]       unsafe, OVERLAPS [0,7] */
    SH_S56,  /* (r6 &= 7) << 3   -> {0,8,..,56}  unsafe, same umin, holey tnum */
    SH_A32,  /* r6 &= 63 (32-bit)-> [0,63]       unsafe, via the alu32 path */
};

static const char *prune_shaper_name(enum prune_shaper s) {
    switch (s) {
    case SH_N7:  return "n7";
    case SH_T6:  return "t6";
    case SH_W63: return "w63";
    case SH_M39: return "m39";
    case SH_O19: return "o19";
    case SH_S56: return "s56";
    case SH_A32: return "a32";
    }
    return "?";
}

static int emit_prune_shaper(struct bpf_insn *ins, int n, enum prune_shaper s) {
    switch (s) {
    case SH_N7:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); break;
    case SH_T6:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 3);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 1); break;
    case SH_W63:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 63); break;
    case SH_M39:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_OR, BPF_REG_6, 32); break;
    case SH_O19:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 15);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 4); break;
    case SH_S56:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 3); break;
    case SH_A32:
        ins[n++] = BPF_ALU32_IMM(BPF_AND, BPF_REG_6, 63); break;
    }
    return n;
}

/* Is a store at +PRUNE_STORE_OFF in bounds under this shaper's range? */
static int prune_shaper_is_safe(enum prune_shaper s) {
    return s == SH_N7 || s == SH_T6;
}

struct prune_load {
    int accept;
    int err;
    unsigned long states;
    const char *reason;   /* none | verdict | too_large | too_many_states | efault */
};

static struct prune_load prune_load_once(const struct bpf_insn *insns, int n,
                                         uint32_t flags, char *logbuf, size_t logsz) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)insns;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = logsz;
    attr.log_buf = (uint64_t)(unsigned long)logbuf;
    attr.prog_flags = flags;
    logbuf[0] = '\0';

    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    struct prune_load r;
    r.accept = fd >= 0;
    r.err = fd >= 0 ? 0 : e;
    /* `processed N insns (limit ...) max_states_per_insn M total_states T ...`
       -- take the LAST occurrence: one summary is printed per subprog. */
    r.states = 0;
    for (const char *p = logbuf; (p = strstr(p, "total_states ")) != NULL; p++)
        r.states = strtoul(p + strlen("total_states "), NULL, 10);
    if (fd >= 0)
        r.reason = "none";
    else if (strstr(logbuf, "BPF program is too large"))
        r.reason = "too_large";           /* BPF_COMPLEXITY_LIMIT_INSNS, not a finding */
    else if (strstr(logbuf, "too many states"))
        r.reason = "too_many_states";     /* BPF_COMPLEXITY_LIMIT_STATES, not a finding */
    else if (e == EFAULT)
        r.reason = "efault";              /* REG INVARIANTS VIOLATION path */
    else
        r.reason = "verdict";             /* the verifier actually decided */
    if (fd >= 0)
        close(fd);
    return r;
}

static void run_prune_prog(enum prune_shaper fall, enum prune_shaper taken,
                           int use_stack, int idx, int map_in, int map_out) {
    struct bpf_insn ins[64];
    int n = 0;
    int jexit[4]; int nx = 0;
    int jsplit, jmerge;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);                /* key = 0 */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);         /* offset source  */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, 4);         /* branch selector */

    /* The split tests r9, never r6: the two paths' states for the offset register
       come purely from their own shapers, not from the branch condition. */
    jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 0, 0);

    /* fall-through path -- explored FIRST, so this is the state that checkpoints */
    n = emit_prune_shaper(ins, n, fall);
    if (use_stack) {
        ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -16);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_6, 0);
    }
    jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);

    /* taken path */
    ins[jsplit].off = n - jsplit - 1;
    n = emit_prune_shaper(ins, n, taken);
    if (use_stack) {
        ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -16);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_6, 0);
    }

    /* merge */
    ins[jmerge].off = n - jmerge - 1;
    if (use_stack)
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_10, -16);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, PRUNE_STORE_OFF, -1);   /* the deciding access */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    /* Three loads of the SAME program: default, state-freq, reg-invariants. */
    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    char name[96];
    snprintf(name, sizeof(name), "genprune#%s%s-%s#%03d",
             use_stack ? "stk." : "", prune_shaper_name(fall),
             prune_shaper_name(taken), idx);

    printf("===PROG %s type=socket_filter ===\n", name);
    /* The block's RESULT is the DEFAULT load, so every existing stage keeps working. */
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           base.accept ? "accept" : "reject", base.accept ? 1 : -1, base.err);
    /* Generator provenance: what each path proves, and where the deciding store is. */
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, PRUNE_STORE_OFF);
    /* NOTE the token names: `*_verdict=` and NOT `*_decision=`. The pipeline and its
       measurement helpers match `decision=` as a SUBSTRING, so `base_decision=accept`
       would be counted as a fourth program decision. Same collision class as
       `find("off=")` matching inside `var_off=(...)` in 0041 -- a naming choice, made
       once, is cheaper than a boundary-aware matcher everywhere downstream. */
    printf("PRUNE fall=%s taken=%s fall_safe=%d taken_safe=%d stack=%d"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           prune_shaper_name(fall), prune_shaper_name(taken),
           prune_shaper_is_safe(fall), prune_shaper_is_safe(taken), use_stack,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);
    printf("---LOG---\n%s\n---END---\n", g_log);
}

// ---- back-edge / loop-convergence family (--gen-loop) -----------------------
// THE FIRST PROGRAM SHAPE WITH A BACK-EDGE. Every family before this one is a forward
// DAG, which is why six legs of oracle growth found nothing: the real bug list lives in
// state pruning, precision and convergence, and none of those can be reached without a
// loop. The ORACLE here is 0042's, transferred UNCHANGED -- same three loads, same
// directional predicate, same `freq_states > base_states` denominator -- so this leg is
// purely an INPUT increment. That is the whole point: aim the input, do not grow the
// oracle.
//
// MECHANISM: `may_goto`, chosen over open-coded iterators and bpf_loop in OI-13.
// Encoding is one raw instruction and nothing else (BPF_JCOND = 0xe0, BPF_MAY_GOTO = 0,
// and verifier.c:19075 requires dst_reg == 0 && imm == 0): no BTF, no kfunc, no subprog,
// no map. Confirmed against the kernel's own `__cond_break` macro, which emits
// `.byte 0xe5` with the offset pointing at `l_break` -- so the JUMP is the loop EXIT and
// the FALL-THROUGH continues into the body.
//
// WHAT IT LANDS ON (verifier.c:16923): the verifier follows the jump (exit), queues the
// fall-through (body) as a new state, bumps `may_goto_depth`, and calls
//   widen_imprecise_scalars(env, prev_st, queued_st)
// against the previous entry at the same instruction. That widening is a DELIBERATE
// over-approximation inserted to force convergence, sitting directly on top of precision
// marking and state pruning -- exactly the shape the 0042 instrument attacks.
//
// THE AXIS is the loop-carried transfer function: what the body does to the register the
// store's safety depends on. A too-narrow fixpoint is what an unsound convergence
// produces, and the store turns it into a decision.
//
// The `nop` arms cannot flip (the body never touches the deciding register) and are kept
// as explicit CONTROLS, labelled as such: they prove that adding a back-edge does not by
// itself change a verdict.
#define LOOP_STORE_OFF 56   /* 1-byte store in bounds iff umax(r6) <= 7 */

#ifndef BPF_JCOND
#define BPF_JCOND 0xe0
#endif
#ifndef BPF_MAY_GOTO
#define BPF_MAY_GOTO 0
#endif

/* may_goto +off : jump to +off when the budget is exhausted, else fall through. */
#define BPF_MAY_GOTO_INSN(OFF)                                                 \
    ((struct bpf_insn){.code = BPF_JMP | BPF_JCOND,                            \
                       .dst_reg = 0, .src_reg = BPF_MAY_GOTO, .off = OFF, .imm = 0})

enum loop_body {
    LB_NOP,      /* body leaves r6 alone            -> control, cannot flip     */
    LB_MASK,     /* r6 &= 7        idempotent       -> invariant [0,7]          */
    LB_INCMASK,  /* r6 += 1; r6 &= 7                -> [0,7]                    */
    LB_MASKINC,  /* r6 &= 7; r6 += 1                -> [1,8]  EXACT off-by-one  */
    LB_SHR,      /* r6 >>= 1       shrinks          -> [0,3]                    */
    LB_XOR3,     /* r6 ^= 3        stays in [0,7]                               */
    LB_COND,     /* if (r6 > 7) r6 = 0  -- invariant kept by a BRANCH, not a mask */
    LB_INC,      /* r6 += 1        unbounded growth -> must widen               */
    LB_SHL,      /* r6 <<= 1       growth                                       */
    LB_ADD8,     /* r6 += 8        growth                                       */
};

static const char *loop_body_name(enum loop_body b) {
    switch (b) {
    case LB_NOP:     return "nop";
    case LB_MASK:    return "mask";
    case LB_INCMASK: return "incmask";
    case LB_MASKINC: return "maskinc";
    case LB_SHR:     return "shr";
    case LB_XOR3:    return "xor3";
    case LB_COND:    return "cond";
    case LB_INC:     return "inc";
    case LB_SHL:     return "shl";
    case LB_ADD8:    return "add8";
    }
    return "?";
}

static int emit_loop_body(struct bpf_insn *ins, int n, enum loop_body b) {
    switch (b) {
    case LB_NOP:
        break;
    case LB_MASK:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); break;
    case LB_INCMASK:
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1);
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7); break;
    case LB_MASKINC:
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1); break;
    case LB_SHR:
        ins[n++] = BPF_ALU64_IMM(BPF_RSH, BPF_REG_6, 1); break;
    case LB_XOR3:
        ins[n++] = BPF_ALU64_IMM(BPF_XOR, BPF_REG_6, 3); break;
    case LB_COND:
        /* The invariant is re-established by a BRANCH -- reg_set_min_max inside a loop
           body, a different code path from a mask. The threshold is 3, not the entry
           bound 7, ON PURPOSE: with `r6 <= 7` the condition is always true for an entry
           range of [0,7], the reset is dead code and the branch is one-way, i.e. a
           vacuous arm. At 3 both sides are reachable and the join is genuinely computed. */
        ins[n++] = BPF_JMP_IMM(BPF_JLE, BPF_REG_6, 3, 1);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_6, 0); break;
    case LB_INC:
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 1); break;
    case LB_SHL:
        ins[n++] = BPF_ALU64_IMM(BPF_LSH, BPF_REG_6, 1); break;
    case LB_ADD8:
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, 8); break;
    }
    return n;
}

static void run_loop_prog(enum loop_body body, int init_mask, int idx,
                          int map_in, int map_out) {
    struct bpf_insn ins[64];
    int n = 0;
    int jexit[4]; int nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, init_mask);   /* the entry invariant */

    /* THE LOOP. The jump target of may_goto is the break label, so the state reaching
       the store is the JOIN over 0, 1, 2, ... iterations -- the ZERO-iteration path
       included. An arm whose body NARROWS the range is therefore still unsafe if its
       ENTRY range is unsafe, and that is a decision a wrong fixpoint could get wrong. */
    const int loop_head = n;
    const int jbreak = n; ins[n++] = BPF_MAY_GOTO_INSN(0);
    n = emit_loop_body(ins, n, body);
    /* The back-edge index MUST be taken before the store: writing
       `ins[n++] = BPF_JMP_IMM(..., loop_head - n - 1)` leaves the side effect on `n`
       unsequenced against the offset expression, and the first capture emitted
       `goto pc-4` (landing on the entry mask) instead of `pc-3` (the may_goto). That
       made every iteration re-establish the entry invariant, so all ten loop bodies
       produced identical states and identical verdicts -- a VACUOUS family that looked
       like ten clean accepts. */
    const int jback = n;
    ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - jback - 1);   /* back-edge */
    n++;
    ins[jbreak].off = n - jbreak - 1;

    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, LOOP_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    char name[96];
    snprintf(name, sizeof(name), "genloop#%s.m%d#%03d", loop_body_name(body), init_mask, idx);

    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           base.accept ? "accept" : "reject", base.accept ? 1 : -1, base.err);
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, LOOP_STORE_OFF);
    /* `fall`/`taken` carry the loop body and the entry mask so the differential line
       stays byte-compatible with --gen-prune: same parser, same predicate, same tests. */
    printf("PRUNE fall=%s taken=m%d fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           loop_body_name(body), init_mask,
           init_mask <= 7, init_mask <= 7,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);
    printf("LOOP body=%s init_mask=%d store_off=%d\n",
           loop_body_name(body), init_mask, LOOP_STORE_OFF);
    printf("---LOG---\n%s\n---END---\n", g_log);
}

/* Residue sweep shared by every loop family whose entry state is `input & 7`: the
   shared RT_INPUTS collapses to only five distinct residues, so seven of its twelve
   runs would buy nothing. Declared here because both --gen-iter and --gen-loopr use it. */
static const uint32_t LOOPR_INPUTS[] = { 0, 1, 2, 3, 4, 5, 6, 7 };
#define LOOPR_INPUTS_N ((int)(sizeof(LOOPR_INPUTS) / sizeof(LOOPR_INPUTS[0])))

// ---- open-coded iterators: BTF resolution + probe (--probe-iter) ------------
// The third loop mechanism from OI-13, and the one the kernel itself flags as risky:
// `bpf_is_state_visited` (states.c) special-cases iterator loop detection with the
// comment that `states_maybe_looping()` is "too simplistic in detecting states that
// *might* be equivalent, because it doesn't know about ID remapping, so don't even
// perform it". A special case in the pruning path, justified by an admitted
// simplification, is the densest target on the list.
//
// The cost is real and it is why this is a PROBE first: an iterator loop is built from
// kfunc calls, and a kfunc call is `BPF_CALL` with `src_reg = BPF_PSEUDO_KFUNC_CALL` and
// `imm` = the function's BTF id -- a number that only exists at load time, in the
// running kernel's own BTF. With no libbpf, the harness has to read
// /sys/kernel/btf/vmlinux and walk the type section itself.
//
// The walk is the fiddly part: every BTF type is a fixed 12-byte header followed by
// kind-specific trailing data, so skipping a type wrong desynchronises every id after
// it -- and a wrong id is not a load error, it is a call to a DIFFERENT function. The
// distro header we compile against stops at BTF_KIND_FLOAT, so the three kinds added
// since (DECL_TAG, TYPE_TAG, ENUM64) are defined here; without them the walk would
// silently drift on any modern vmlinux.
#ifndef BTF_KIND_DECL_TAG
#define BTF_KIND_DECL_TAG 17
#endif
#ifndef BTF_KIND_TYPE_TAG
#define BTF_KIND_TYPE_TAG 18
#endif
#ifndef BTF_KIND_ENUM64
#define BTF_KIND_ENUM64 19
#endif

static char *g_btf;
static unsigned g_btf_len;

static int btf_load_vmlinux(void) {
    if (g_btf) return 0;
    FILE *f = fopen("/sys/kernel/btf/vmlinux", "rb");
    if (!f) return -1;
    unsigned cap = 1u << 24, len = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); return -1; }
    size_t r;
    while ((r = fread(buf + len, 1, cap - len, f)) > 0) {
        len += (unsigned)r;
        if (len == cap) break;
    }
    fclose(f);
    g_btf = buf; g_btf_len = len;
    return 0;
}

/* Trailing bytes after the 12-byte btf_type header, per kind. */
static long btf_type_tail(unsigned kind, unsigned vlen) {
    switch (kind) {
    case BTF_KIND_INT:        return 4;
    case BTF_KIND_ARRAY:      return 12;                 /* struct btf_array */
    case BTF_KIND_STRUCT:
    case BTF_KIND_UNION:      return (long)vlen * 12;    /* struct btf_member */
    case BTF_KIND_ENUM:       return (long)vlen * 8;     /* struct btf_enum */
    case BTF_KIND_FUNC_PROTO: return (long)vlen * 8;     /* struct btf_param */
    case BTF_KIND_VAR:        return 4;                  /* struct btf_var */
    case BTF_KIND_DATASEC:    return (long)vlen * 12;    /* struct btf_var_secinfo */
    case BTF_KIND_DECL_TAG:   return 4;                  /* struct btf_decl_tag */
    case BTF_KIND_ENUM64:     return (long)vlen * 12;    /* struct btf_enum64 */
    default:                  return 0;                  /* PTR, FWD, TYPEDEF, CONST,
                                                            VOLATILE, RESTRICT, FUNC,
                                                            FLOAT, TYPE_TAG */
    }
}

/* Resolve a BTF_KIND_FUNC by name -> its BTF id, or -1. */
static int btf_find_func_id(const char *want) {
    if (btf_load_vmlinux() < 0) return -1;
    if (g_btf_len < sizeof(struct btf_header)) return -1;
    const struct btf_header *h = (const void *)g_btf;
    if (h->magic != 0xeB9F) return -1;
    const char *types = g_btf + h->hdr_len + h->type_off;
    const char *tend  = types + h->type_len;
    const char *strs  = g_btf + h->hdr_len + h->str_off;
    const char *p = types;
    int id = 0;
    while (p + 12 <= tend) {
        id++;
        unsigned name_off, info;
        memcpy(&name_off, p, 4);
        memcpy(&info, p + 4, 4);
        unsigned kind = BTF_INFO_KIND(info);
        unsigned vlen = info & 0xffff;
        if (kind == BTF_KIND_FUNC && name_off &&
            strcmp(strs + name_off, want) == 0)
            return id;
        p += 12 + btf_type_tail(kind, vlen);
    }
    return -1;
}

#ifndef BPF_PSEUDO_KFUNC_CALL
#define BPF_PSEUDO_KFUNC_CALL 2
#endif
#define BPF_KFUNC_CALL(BTF_ID)                                                 \
    ((struct bpf_insn){.code = BPF_JMP | BPF_CALL,                             \
                       .dst_reg = 0, .src_reg = BPF_PSEUDO_KFUNC_CALL,         \
                       .off = 0, .imm = (BTF_ID)})

/* struct bpf_iter_num is 8 bytes, 8-aligned (uapi/linux/bpf.h), so the iterator lives
   in the stack slot at fp-8 and the verifier tracks that slot's iterator state. */
#define ITER_SLOT 8

struct iter_ids { int new_id, next_id, destroy_id; };

static int iter_resolve(struct iter_ids *out) {
    out->new_id     = btf_find_func_id("bpf_iter_num_new");
    out->next_id    = btf_find_func_id("bpf_iter_num_next");
    out->destroy_id = btf_find_func_id("bpf_iter_num_destroy");
    return (out->new_id > 0 && out->next_id > 0 && out->destroy_id > 0) ? 0 : -1;
}

/* Emit the canonical open-coded iterator loop, with `body` shaping r6 each iteration.
   Layout:
       r1 = fp-8; r2 = start; r3 = end; call bpf_iter_num_new
   head:
       r1 = fp-8; call bpf_iter_num_next; if r0 == 0 goto done
       <body>
       goto head
   done:
       r1 = fp-8; call bpf_iter_num_destroy                                        */
static int emit_iter_loop(struct bpf_insn *ins, int n, const struct iter_ids *ids,
                          int start, int end, enum loop_body body) {
    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -ITER_SLOT);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_2, start);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_3, end);
    ins[n++] = BPF_KFUNC_CALL(ids->new_id);

    const int head = n;
    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -ITER_SLOT);
    ins[n++] = BPF_KFUNC_CALL(ids->next_id);
    const int jdone = n;
    ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    n = emit_loop_body(ins, n, body);
    const int jback = n;
    ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, head - jback - 1);
    n++;
    ins[jdone].off = n - jdone - 1;

    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, -ITER_SLOT);
    ins[n++] = BPF_KFUNC_CALL(ids->destroy_id);
    return n;
}

// ---- reaching RANGE_WITHIN on purpose (--gen-rw) ----------------------------
// 0051 predicted that the precision short-circuit would stop working inside a loop,
// because it is gated on `exact == NOT_EXACT`. The measurement said otherwise: a may_goto
// loop does not select RANGE_WITHIN, since the gate on the main path is
// `incomplete_read_marks` and not the presence of a back-edge.
//
// There IS a call site that passes RANGE_WITHIN unconditionally (states.c:1333):
//
//     if (is_iter_next_insn(env, insn_idx)) {
//             if (states_equal(env, &sl->state, cur, RANGE_WITHIN)) { ... }
//
// but note WHICH instruction it applies to: the iterator's next-call site, not every
// instruction in the loop body. So to put the precision pair under that comparison, the
// two states have to MEET at the loop head — which means the split has to happen BEFORE
// the iterator loop, not inside it. Getting that wrong would compare the pair at an
// ordinary instruction and measure the same NOT_EXACT path all over again.
//
// PREDICTION, now aimed at a call site rather than at "a loop": with the pair meeting at
// the iter_next instruction, the precision short-circuit is off, so the dead-register arm
// can no longer buy a prune and the gap that 0050 measured should CLOSE. The flat pair
// rides along in the same capture so the comparison is within one run.
#define RW_STORE_OFF 40

static void run_rw_prog(const struct iter_ids *ids, int use_iter, int store_src,
                        int idx, int map_in, int map_out) {
    struct bpf_insn ins[96];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);

    /* The split is BEFORE the loop on purpose: the two states must MEET at the
       iterator's next-call site, which is the instruction states.c:1333 compares with
       RANGE_WITHIN. Splitting inside the body would put the meeting point at an ordinary
       instruction and measure the main NOT_EXACT path again. */
    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 8);
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 16);
    ins[jmerge].off = n - jmerge - 1;

    if (use_iter)
        n = emit_iter_loop(ins, n, ids, 0, 4, LB_NOP);

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2,
                             store_src == 7 ? BPF_REG_7 : BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, RW_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    unsigned long mp_r7 = 0;
    for (const char *q = g_log; (q = strstr(q, "regs=r7 ")) != NULL; q++) mp_r7++;
    unsigned long iter_states = 0;
    for (const char *q = g_log; (q = strstr(q, "state=active")) != NULL; q++) iter_states++;

    char name[96];
    snprintf(name, sizeof(name), "genrw#%s.s%d#%03d",
             use_iter ? "iter" : "flat", store_src, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, RW_STORE_OFF);
    printf("RW ctx=%s store_src=%d r7_backtracked=%lu iter_active=%lu\n",
           use_iter ? "iter" : "flat", store_src, mp_r7, iter_states);
    printf("PRUNE fall=%s taken=s%d fall_safe=1 taken_safe=1 stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           use_iter ? "iter" : "flat", store_src,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 4, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
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
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_rw_family(void) {
    struct iter_ids ids;
    if (iter_resolve(&ids) < 0) {
        printf("===PROG genrw type=socket_filter ===\n"
               "RESULT decision=error btf_resolve_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genrw type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    const struct { int use_iter, src; } arms[] = {
        { 0, 7 },   /* flat baseline: r7 decides -> precise, no prune  */
        { 0, 6 },   /* flat baseline: r7 dead    -> imprecise, prune   */
        { 1, 7 },   /* the pair meets at the iter_next insn            */
        { 1, 6 },   /* ...where RANGE_WITHIN should disable the prune  */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_rw_prog(&ids, arms[i].use_iter, arms[i].src, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- which exact_level our shapes reach (--gen-exact) -----------------------
// `regsafe` takes an `exact_level` and behaves very differently per level (states.c):
//   EXACT        -> regs_exact(): memcmp + check_ids, the strictest possible comparison
//   NOT_EXACT    -> the precision short-circuit applies: `!rold->precise` matches anything
//   RANGE_WITHIN -> range/tnum logic runs, but the precision short-circuit does NOT
// and the three arrive from different call sites:
//   :1405  states_equal(..., loop ? RANGE_WITHIN : NOT_EXACT)   the main pruning path,
//          where `loop = incomplete_read_marks(env, &sl->state)` -- note this is NOT
//          simply "there is a back-edge"
//   :1333/:1358/:1364  RANGE_WITHIN, the iterator paths
//   :1372  EXACT, used ONLY for infinite-loop detection
//
// That last one is directly observable: reaching it prints "infinite loop detected at
// insn %d". So a program whose state repeats unchanged at a back-edge gives us a marker
// that the EXACT path ran -- the only level we can confirm from outside.
//
// The reason this leg exists is a PREDICTION from that table rather than a new mechanism.
// 0050 measured the precision lever on straight-line code: with the store using the
// register the two paths disagree about, r7 must be precise and both states are explored;
// with the store using a dead register, `!rold->precise` short-circuits and one state is
// pruned. That short-circuit is gated on `exact == NOT_EXACT`. So the SAME pair placed
// inside a loop should behave differently if the loop takes a RANGE_WITHIN comparison.
// Whether it does is exactly what `incomplete_read_marks` decides, which is not something
// to assert from a reading -- so the family carries both the flat pair and the looped
// pair in ONE capture and lets the state counts answer.
#define EXACT_STORE_OFF 40

enum exact_shape {
    EXS_INF,     /* back-edge whose state repeats unchanged -> infinite loop detected */
    EXS_FLAT,    /* 0050's pair, straight-line: the NOT_EXACT baseline                */
    EXS_LOOP,    /* the same pair inside a may_goto loop                              */
};

static const char *exact_shape_name(enum exact_shape e) {
    switch (e) {
    case EXS_INF:  return "inf";
    case EXS_FLAT: return "flat";
    case EXS_LOOP: return "loop";
    }
    return "?";
}

static void run_exact_prog(enum exact_shape shape, int store_src, int idx,
                           int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);

    if (shape == EXS_INF) {
        /* The state at the head repeats unchanged after the first pass (the mask is
           idempotent), which is what states_maybe_looping + EXACT detect.
           The back-edge must be CONDITIONAL: an unconditional `goto head` makes
           everything after it unreachable and check_cfg rejects the program outright
           ("Remove the unreachable instruction", processed 0 insns) before a single
           state is walked -- so the EXACT path would never be reached at all. The
           condition is always true for r6 in [0,7], so the loop really is infinite. */
        const int head = n;
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        const int jb = n;
        ins[jb] = BPF_JMP_IMM(BPF_JLT, BPF_REG_6, 10, head - jb - 1);
        n++;
    } else {
        int loop_head = -1, jbreak = -1;
        if (shape == EXS_LOOP) {
            /* r7 must be live BEFORE the head: may_goto can break out on entry, and on
               that zero-iteration path the split never runs. Same zero-iteration path
               that decides the verdicts in 0043 -- here it showed up as
               "Initialize R7 on every path before this instruction". */
            ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 8);
            loop_head = n;
            jbreak = n; ins[n++] = BPF_MAY_GOTO_INSN(0);
        }
        /* 0050's pair: the two paths differ ONLY in the constant they put in r7. */
        const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 8);
        const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
        ins[jsplit].off = n - jsplit - 1;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_7, 16);
        ins[jmerge].off = n - jmerge - 1;
        if (shape == EXS_LOOP) {
            const int jback = n;
            ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - jback - 1);
            n++;
            ins[jbreak].off = n - jbreak - 1;
        }
    }

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2,
                             store_src == 7 ? BPF_REG_7 : BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, EXACT_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    unsigned long mp_r7 = 0;
    for (const char *q = g_log; (q = strstr(q, "regs=r7 ")) != NULL; q++) mp_r7++;
    const int inf_detected = strstr(g_log, "infinite loop detected") != NULL;

    char name[96];
    snprintf(name, sizeof(name), "genexact#%s.s%d#%03d",
             exact_shape_name(shape), store_src, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, EXACT_STORE_OFF);
    printf("EXACT shape=%s store_src=%d infinite_loop_detected=%d r7_backtracked=%lu\n",
           exact_shape_name(shape), store_src, inf_detected, mp_r7);
    printf("PRUNE fall=%s taken=s%d fall_safe=1 taken_safe=1 stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           exact_shape_name(shape), store_src,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    /* The measurement here is state counts, but reporting a clean result with a zero
       location denominator is exactly what this project's own rule forbids -- so the
       accepted programs are executed like every other family's. */
    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 4, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
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
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_exact_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genexact type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* The flat and looped pairs sit in ONE capture so the precision gap can be compared
       between them directly rather than across two runs. */
    const struct { enum exact_shape shape; int src; } arms[] = {
        { EXS_INF,  6 },   /* marker: the EXACT path prints "infinite loop detected" */
        { EXS_FLAT, 7 },   /* NOT_EXACT, r7 decides   -> precise, no prune           */
        { EXS_FLAT, 6 },   /* NOT_EXACT, r7 dead      -> imprecise, prune            */
        { EXS_LOOP, 7 },   /* same pair, in a loop                                   */
        { EXS_LOOP, 6 },   /* same pair, in a loop, r7 dead                          */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_exact_prog(arms[i].shape, arms[i].src, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- precision as the pruning lever (--gen-prec) ----------------------------
// `regsafe` (states.c:551) contains the single most powerful pruning rule in the
// verifier:
//
//     if (!rold->precise && exact == NOT_EXACT)
//             return true;
//
// An IMPRECISE old scalar matches ANY current scalar. So precision is exactly what stops
// a prune: if a register whose value decides memory safety is not marked precise, two
// states differing only in that register are equated and the unsafe one is pruned away.
// `mark_chain_precision` is what has to get that right, `precise.c` is on the kernel's
// own danger list, and the backtracker logs its work (`mark_precise: frame%d: regs=%s`,
// backtrack.c:280), so the mechanism is observable rather than merely inferred.
//
// THE AXIS is whether the differing register PARTICIPATES in the deciding access:
//   * store through r7 -> r7's value decides safety -> it must be marked precise ->
//     the two states are not equatable -> both paths are explored;
//   * store through r6 (a masked, always-safe offset) -> r7 is never used -> it need not
//     be precise -> the short-circuit above applies and the second state CAN be pruned.
// The two differ in one operand of one instruction, so the state counts and the
// mark_precise lines isolate precision itself.
//
// Store offset 40 makes the decision a pure function of the constant: in bounds iff
// umax <= 23, so 23 accepts and 24 rejects — an exact one-byte boundary that proves the
// verdict tracks the VALUE and not the shape.
#define PREC_STORE_OFF 40

/* store_src: 7 = the register the two paths disagree about (precision required),
   6 = a masked always-safe offset (r7 unused, precision not required). */
static void run_prec_prog(int c_fall, int c_taken, int store_src, int idx,
                          int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);          /* always-safe offset */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 4);   /* path selector */

    /* The two paths differ ONLY in the constant they put in r7. */
    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_7, c_fall);
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_7, c_taken);
    ins[jmerge].off = n - jmerge - 1;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2,
                             store_src == 7 ? BPF_REG_7 : BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, PREC_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    /* How many `mark_precise:` lines the backtracker emitted for the DEFAULT load: the
       direct observable of whether precision work happened at all. */
    unsigned long mp = 0;
    for (const char *q = g_log; (q = strstr(q, "mark_precise:")) != NULL; q++)
        mp++;

    char name[96];
    snprintf(name, sizeof(name), "genprec#c%d_%d.s%d#%03d", c_fall, c_taken, store_src, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, PREC_STORE_OFF);
    printf("PREC c_fall=%d c_taken=%d store_src=%d store_off=%d mark_precise_lines=%lu\n",
           c_fall, c_taken, store_src, PREC_STORE_OFF, mp);
    printf("PRUNE fall=c%d taken=c%d fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           c_fall, c_taken,
           store_src == 7 ? (c_fall + PREC_STORE_OFF < 64) : 1,
           store_src == 7 ? (c_taken + PREC_STORE_OFF < 64) : 1,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 4, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
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
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_prec_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genprec type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* The first two arms differ in ONE operand of ONE instruction — which register the
       store adds — so any difference in state count or precision work between them is
       precision itself and nothing else. 23 vs 24 is the exact one-byte boundary. */
    const struct { int cf, ct, src; } arms[] = {
        {  8, 16, 7 },   /* r7 decides safety -> must be precise -> no prune -> accept */
        {  8, 16, 6 },   /* r7 unused -> need not be precise -> prune allowed -> accept */
        {  8, 23, 7 },   /* 40 + 23 + 1 == 64 exactly                        -> accept */
        {  8, 24, 7 },   /* one byte over                                    -> reject */
        {  8, 40, 7 },   /* well over                                        -> reject */
        {  8,  8, 7 },   /* identical states, trivial prune                  -> accept */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_prec_prog(arms[i].cf, arms[i].ct, arms[i].src, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- spilled links and delta arithmetic (--gen-spill) -----------------------
// Two gaps left by 0046-0048, both visible in sync_linked_regs (verifier.c:16847):
//
//   reg = e->is_reg ? &vstate->frame[e->frameno]->regs[e->regno]
//                   : &vstate->frame[e->frameno]->stack[e->spi].spilled_ptr;
//
// (1) A linked scalar's set spans STACK SLOTS, not just registers, and `stacksafe` has
//     its own check_ids calls for spilled state. Every id family so far kept its scalars
//     in registers, so the spilled half of both mechanisms is untested.
//
// (2) The ADD_CONST branch does real ARITHMETIC when two members of a class carry
//     different deltas:
//         __mark_reg_known(&fake_reg, (s64)reg->delta - (s64)known_reg->delta);
//         *reg = *known_reg;  /* then reg += fake_reg */
//     0046 and 0047 only ever had ONE delta (4) linked to a bare base, so the
//     subtraction never had two non-trivial operands. Two registers at different offsets
//     from the same base exercise it directly, and a wrong delta is a bounds error.
//
// Same paired design as 0046: every REJECT shape has an ACCEPT control differing only in
// whether the link exists on both paths, so the verdicts isolate linkage rather than
// shape. Store offset 44 keeps every correctly-narrowed variant in bounds -- bare gives
// umax 7, delta 4 gives 11, delta 12 gives 19, and 44 + 19 + 1 = 64 -- so the decision
// never turns on offset arithmetic, only on whether the class was narrowed.
enum spill_shape {
    SPL_NONE,      /* no link                                                        */
    SPL_SPILL,     /* r7 = r6, then spill r7: the linked copy lives in a stack slot   */
    SPL_DELTA,     /* r7 = r6; r7 += 4  and  r9 = r6; r9 += 12: two deltas, one base  */
};

static const char *spill_shape_name(enum spill_shape p) {
    switch (p) {
    case SPL_NONE:  return "none";
    case SPL_SPILL: return "spill";
    case SPL_DELTA: return "delta";
    }
    return "?";
}

/* `linked` selects whether this path forms the link at all; the unlinked variant still
   spills, so the two states differ ONLY in the id structure of the spilled slot. */
static int emit_spill_shape(struct bpf_insn *ins, int n, enum spill_shape p, int linked) {
    switch (p) {
    case SPL_NONE:
        ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -16);
        break;
    case SPL_SPILL:
        if (linked)
            ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -16);
        break;
    case SPL_DELTA:
        if (linked) {
            ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 4);
            ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_6);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 12);
        } else {
            /* same registers written, same widths, no shared base */
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 4);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 12);
        }
        break;
    }
    return n;
}

/* store_src: 0 = the slot reloaded from the stack, 7 = the delta-4 register,
   9 = the delta-12 register, 6 = the register the check narrows directly (control). */
static void run_spill_prog(enum spill_shape shape, int link_fall, int link_taken,
                           int store_src, int store_off, int idx,
                           int map_in, int map_out) {
    struct bpf_insn ins[96];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, 8);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 12);   /* path selector */

    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
    n = emit_spill_shape(ins, n, shape, link_fall);
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    n = emit_spill_shape(ins, n, shape, link_taken);
    ins[jmerge].off = n - jmerge - 1;

    /* Names r6 only. Everything else can be narrowed ONLY through the shared class --
       including, for the spill arms, a copy that is sitting in a stack slot. */
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0);
    if (store_src == 0)
        ins[n++] = BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_10, -16);  /* reload the slot */

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    int src = store_src == 0 ? BPF_REG_8
            : store_src == 7 ? BPF_REG_7
            : store_src == 9 ? BPF_REG_9 : BPF_REG_6;
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, src);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, store_off, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "genspill#%s.%s.s%d#%03d", spill_shape_name(shape),
             (link_fall && link_taken) ? "both" : (link_fall || link_taken) ? "one" : "no",
             store_src, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, store_off);
    printf("SPILL shape=%s link_fall=%d link_taken=%d store_src=%d store_off=%d\n",
           spill_shape_name(shape), link_fall, link_taken, store_src, store_off);
    printf("PRUNE fall=%s taken=s%d fall_safe=%d taken_safe=%d stack=1"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           spill_shape_name(shape), store_src, link_fall, link_taken,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            memcpy(val + 4, &in, 4);
            memcpy(val + 8, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 12, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
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
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_spill_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genspill type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    const struct { enum spill_shape shape; int lf, lt, src; } arms[] = {
        { SPL_SPILL, 0, 0, 0 },   /* baseline: spilled copy never linked   -> reject */
        { SPL_SPILL, 1, 0, 0 },   /* THE SHAPE: linked on one path         -> reject */
        { SPL_SPILL, 1, 1, 0 },   /* does a SPILLED copy get narrowed?     -> answer */
        { SPL_SPILL, 1, 0, 6 },   /* control: store through r6 directly    -> accept */
        { SPL_DELTA, 0, 0, 9 },   /* baseline for the delta arm            -> reject */
        { SPL_DELTA, 1, 0, 9 },   /* linked on one path                    -> reject */
        { SPL_DELTA, 1, 1, 9 },   /* delta 12: is the subtraction right?   -> answer */
        { SPL_DELTA, 1, 1, 7 },   /* delta 4, same class                   -> accept */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_spill_prog(arms[i].shape, arms[i].lf, arms[i].lt, arms[i].src, 44, idx++,
                       map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- multi-frame states / subprogs (--gen-frame) ----------------------------
// Every program this project has generated so far lives in ONE frame. `states_equal`
// opens with `if (old->curframe != cur->curframe) return false` and then compares each
// frame in turn, so the whole multi-frame half of state comparison has never been
// touched -- and `calls.c` is on the kernel's own danger list (it is one of the files
// that sets BPF_F_TEST_STATE_FREQ).
//
// A subprog call needs no BTF and no kfunc: `BPF_CALL` with `src_reg = BPF_PSEUDO_CALL`
// and `imm` = the pc-relative offset of the callee. The interesting question is what
// crosses the boundary. Only r1-r5 are passed; the callee's r6-r9 start uninitialised.
// If a scalar's link ID survives into the callee's argument register, then narrowing one
// argument narrows the other through sync_linked_regs -- INSIDE a different frame from
// the one where the link was formed. If it does not survive, the callee sees two
// independent scalars.
//
// The family answers that by construction rather than by assumption, using the same
// paired design as 0046: link on ONE path versus link on BOTH. If both variants reject,
// ids do not cross the frame boundary. If one-path rejects while both-path accepts, they
// do -- and the caller's differing linkage is something `states_equal` must distinguish
// while comparing two frames rather than one.
enum frame_shape {
    FRM_NOLINK,    /* no link at all -- baseline                                   */
    FRM_ONE,       /* link on the fall-through path only                           */
    FRM_BOTH,      /* link on both paths                                           */
};

static const char *frame_shape_name(enum frame_shape f) {
    switch (f) {
    case FRM_NOLINK: return "nolink";
    case FRM_ONE:    return "one";
    case FRM_BOTH:   return "both";
    }
    return "?";
}

/* `use_arg1` stores through the argument the callee narrows directly, which must be safe
   whatever the ids say -- the control that fences the result from the other side. */
static void run_frame_prog(enum frame_shape shape, int use_arg1, int store_off,
                           int idx, int map_in, int map_out) {
    struct bpf_insn ins[96];
    int n = 0, jexit[4], nx = 0;

    /* ---- caller frame ---- */
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 8);   /* path selector */

    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 0);
    if (shape != FRM_NOLINK)
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);       /* link, fall-through */
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    if (shape == FRM_BOTH)
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);       /* link, taken path */
    ins[jmerge].off = n - jmerge - 1;

    ins[n++] = BPF_MOV64_REG(BPF_REG_1, BPF_REG_6);           /* arg 1 */
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_7);           /* arg 2 */
    const int jcall = n; ins[n++] = (struct bpf_insn){0};     /* patched below */
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    /* ---- callee frame: narrows arg1, stores through the chosen arg ---- */
    const int sub = n;
    ins[jcall] = (struct bpf_insn){.code = BPF_JMP | BPF_CALL, .dst_reg = 0,
                                   .src_reg = BPF_PSEUDO_CALL, .off = 0,
                                   .imm = sub - jcall - 1};
    int sexit[4]; int sx = 0;
    ins[n++] = BPF_MOV64_REG(BPF_REG_6, BPF_REG_1);           /* keep args across the */
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_2);           /* upcoming helper call */
    /* Names r6 (= arg1) only: r7 can be narrowed ONLY through a shared id that survived
       the frame boundary. */
    sexit[sx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0);
    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    sexit[sx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_3, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_3, use_arg1 ? BPF_REG_6 : BPF_REG_7);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_3, store_off, -1);
    const int sexit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < sx; i++)
        ins[sexit[i]].off = sexit0 - sexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "genframe#%s.a%d#%03d",
             frame_shape_name(shape), use_arg1 ? 1 : 2, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=3 off=%d size=1\n", store_insn, store_off);
    printf("FRAME shape=%s store_arg=%d sub_at=%d store_off=%d\n",
           frame_shape_name(shape), use_arg1 ? 1 : 2, sub, store_off);
    printf("PRUNE fall=%s taken=a%d fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           frame_shape_name(shape), use_arg1 ? 1 : 2, base.accept, base.accept,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            memcpy(val + 4, &in, 4);
            uint32_t sel = i & 1;
            memcpy(val + 8, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
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
            /* The caller returns 1 only after the subprog returned, so the witness still
               means "the store path ran" -- the callee's own exit clears r0 to 0 first. */
            int executed = (off >= 0);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_frame_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genframe type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    const struct { enum frame_shape shape; int use_arg1; } arms[] = {
        { FRM_NOLINK, 0 },   /* baseline: arg2 never narrowed                     */
        { FRM_NOLINK, 1 },   /* control:  store through the narrowed arg1         */
        { FRM_ONE,    0 },   /* THE SHAPE: link on one path, store through arg2   */
        { FRM_BOTH,   0 },   /* the answer: does the link cross the frame at all? */
        { FRM_ONE,    1 },   /* control                                           */
        { FRM_BOTH,   1 },   /* control                                           */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_frame_prog(arms[i].shape, arms[i].use_arg1, 48, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- id-map BIJECTION / partition structure (--gen-idpart) ------------------
// 0046 asked whether a link is PRESENT. This asks whether the mapping between the two
// states' ids is a BIJECTION, which is the actual contract of check_ids (states.c:319):
//
//   for (i = 0; i < idmap->cnt; i++) {
//           if (map[i].old == old_id) return map[i].cur == cur_id;  /* consistency */
//           if (map[i].cur == cur_id) return false;                 /* injectivity */
//   }
//
// Which of those two `if`s fires is NOT controllable from the program: registers are
// compared in order and whichever inconsistency is reached first decides. What IS
// controllable, and what actually matters, is the id STRUCTURE -- the partition of
// registers into linked classes. Two states whose partitions differ in a way that
// matters must never be equated; two states whose partitions are IDENTICAL but whose id
// NUMBERS differ must be equated, or the mapping is vacuously strict.
//
// That second direction is the half every earlier leg is missing. Everything so far
// tests soundness (never accept something unsafe). `swap` tests COMPLETENESS: the same
// partition built by a different instruction order mints different id numbers
// (++env->id_gen is global), so accepting it is only possible if the remapping genuinely
// works. If check_ids required identical ids, that arm would over-reject.
//
// Shape: four attacker scalars and a selector, a split that constrains none of them, a
// narrowing check naming r6 alone, and a store through r9 -- so r9's safety is exactly
// "does r9 end up in r6's linked class". Store offset 48 leaves room for the +4 delta of
// the ADD_CONST arm: linked and narrowed, r9 is at most 7 (bare) or 11 (delta), and
// 48 + 11 + 1 = 60 <= 64, so the decision never turns on offset arithmetic.
enum idpart_shape {
    IDP_SAME,     /* r7 = r6; r9 = r6      one class {r6,r7,r9}                     */
    IDP_CHAIN,    /* r7 = r6; r9 = r7      transitive: r9 must still join r6's class */
    IDP_ADDC,     /* r7 = r6; r9 = r6; r9 += 4   class + BPF_ADD_CONST64 delta       */
    IDP_SWAPPED,  /* r9 = r6; r7 = r6      SAME partition, different mint order      */
    IDP_TIED8,    /* r7 = r6; r9 = r8      r9 in r8's class -> never narrowed        */
};

static const char *idpart_shape_name(enum idpart_shape p) {
    switch (p) {
    case IDP_SAME:    return "same";
    case IDP_CHAIN:   return "chain";
    case IDP_ADDC:    return "addc";
    case IDP_SWAPPED: return "swap";
    case IDP_TIED8:   return "tied8";
    }
    return "?";
}

static int emit_idpart(struct bpf_insn *ins, int n, enum idpart_shape p) {
    switch (p) {
    case IDP_SAME:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_6); break;
    case IDP_CHAIN:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_7); break;
    case IDP_ADDC:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_6);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_9, 4); break;
    case IDP_SWAPPED:
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6); break;
    case IDP_TIED8:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_MOV64_REG(BPF_REG_9, BPF_REG_8); break;
    }
    return n;
}

/* Does this shape put r9 in the class the narrowing check touches? */
static int idpart_narrows_r9(enum idpart_shape p) { return p != IDP_TIED8; }

static void run_idpart_prog(enum idpart_shape fall, enum idpart_shape taken,
                            int store_off, int idx, int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_8, BPF_REG_0, 8);
    /* The selector lives in a caller-saved register on purpose: no call happens between
       this load and the branch, and using r6-r9 would cost one of the four scalars. */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_0, 12);

    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_1, 0, 0);
    n = emit_idpart(ins, n, fall);
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    n = emit_idpart(ins, n, taken);
    ins[jmerge].off = n - jmerge - 1;

    /* Names r6 only: r9 can be narrowed ONLY by being in r6's linked class. */
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0);

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_2, BPF_REG_9);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_2, store_off, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "genidpart#%s-%s#%03d",
             idpart_shape_name(fall), idpart_shape_name(taken), idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=2 off=%d size=1\n", store_insn, store_off);
    printf("IDPART fall=%s taken=%s fall_narrows=%d taken_narrows=%d store_off=%d\n",
           idpart_shape_name(fall), idpart_shape_name(taken),
           idpart_narrows_r9(fall), idpart_narrows_r9(taken), store_off);
    printf("PRUNE fall=%s taken=%s fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           idpart_shape_name(fall), idpart_shape_name(taken),
           idpart_narrows_r9(fall), idpart_narrows_r9(taken),
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);
            memcpy(val + 4, &in, 4);
            memcpy(val + 8, &in, 4);
            uint32_t sel = i & 1;              /* both paths are taken at runtime */
            memcpy(val + 12, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
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
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_idpart_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genidpart type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Derived: accept iff BOTH paths put r9 in r6's linked class, because the state
       reaching the store is the join of the two. The `swap` pairs are the completeness
       half -- identical partitions, different id NUMBERS -- and must accept. */
    const struct { enum idpart_shape fall, taken; } arms[] = {
        { IDP_SAME,    IDP_SAME    },  /* both narrow r9                    -> accept */
        { IDP_SAME,    IDP_TIED8   },  /* second state leaves r9 unnarrowed -> reject */
        { IDP_TIED8,   IDP_SAME    },  /* mirror                            -> reject */
        { IDP_CHAIN,   IDP_CHAIN   },  /* transitive linking                -> accept */
        { IDP_CHAIN,   IDP_TIED8   },  /*                                   -> reject */
        { IDP_ADDC,    IDP_ADDC    },  /* ADD_CONST class, r9 = r6 + 4      -> accept */
        { IDP_ADDC,    IDP_TIED8   },  /*                                   -> reject */
        { IDP_SAME,    IDP_SWAPPED },  /* SAME partition, different id numbers        */
        { IDP_SWAPPED, IDP_SAME    },  /* mirror of the completeness arm              */
        { IDP_SAME,    IDP_CHAIN   },  /* same class reached two ways       -> accept */
        { IDP_SAME,    IDP_ADDC    },  /* class with and without the delta            */
        { IDP_TIED8,   IDP_TIED8   },  /* neither narrows r9                -> reject */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_idpart_prog(arms[i].fall, arms[i].taken, 48, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- scalar ID remapping (--gen-idmap) --------------------------------------
// THE thing states.c calls "too simplistic". `check_ids()` (states.c:319) builds a
// BIJECTIVE old<->cur id mapping while comparing two states, and `check_scalar_ids()`
// wraps it for scalars. The kernel's own comment in regsafe spells out why it must
// exist, and it is a program, not a hypothetical:
//
//   1: r6 = ... unbound scalar, ID=a ...
//   2: r7 = ... unbound scalar, ID=b ...
//   3: if (r6 > r7) goto +1
//   4: r6 = r7                 <- both now carry id=b: LINKED
//   5: if (r6 > X) goto ...    <- sync_linked_regs narrows r7 too, because they share id
//   6: ... memory operation using r7 ...
//
// Instruction 6 is reached in TWO states: I. r6{id=b}, r7{id=b} via 1-6, and
// II. r6{id=a}, r7{id=b} via 1-4,6. In state II the bound check at 5 never touched r7,
// so the memory operation is unsafe. If check_ids() equated the two, state II would be
// PRUNED against state I and the unsafe access accepted. That is a decision-flipping
// shape, which is what makes it testable at all.
//
// The axis is HOW the link is formed, because each form carries a different id:
//   * plain `rX = rY` mints an id on the source (assign_scalar_id_before_mov,
//     verifier.c:3470) and copies it, so both registers share a bare id;
//   * `rX = rY; rY += const` additionally sets BPF_ADD_CONST64 (bit 31) with a delta,
//     so the two registers carry id and id|flag -- and check_scalar_ids must map BOTH
//     the compound and the base id consistently;
//   * the 32-bit form sets BPF_ADD_CONST32 (bit 30) instead, and the kernel refuses to
//     prune across differing flag types because alu32 zero-extends and alu64 does not.
//
// Every arm pairs a REJECT shape (the link exists on one path only, so one state
// arrives unnarrowed) with an ACCEPT control (the link exists on both paths, or the
// store uses the register that is narrowed directly). Without the controls a reject
// would only prove the shape is unsafe, not that linkage is what decides it.
//
// 0042's instrument rides along unchanged and is an especially good fit here:
// BPF_F_TEST_STATE_FREQ multiplies the pruning attempts, so an id-mapping mistake has
// far more chances to be exercised with the flag than without.
enum idmap_link {
    IDL_NONE,      /* no link at all -- baseline: r7 is never narrowed          */
    IDL_MOV,       /* r7 = r6            bare shared id                          */
    IDL_ADDC64,    /* r7 = r6; r7 += 4   id | BPF_ADD_CONST64, delta 4           */
    IDL_ADDC32,    /* w7 = w6; w7 += 4   id | BPF_ADD_CONST32                    */
};

static const char *idmap_link_name(enum idmap_link l) {
    switch (l) {
    case IDL_NONE:   return "nolink";
    case IDL_MOV:    return "mov";
    case IDL_ADDC64: return "addc64";
    case IDL_ADDC32: return "addc32";
    }
    return "?";
}

static int emit_idmap_link(struct bpf_insn *ins, int n, enum idmap_link l) {
    switch (l) {
    case IDL_NONE:
        break;
    case IDL_MOV:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6); break;
    case IDL_ADDC64:
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, 4); break;
    case IDL_ADDC32:
        ins[n++] = BPF_MOV32_REG(BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_ALU32_IMM(BPF_ADD, BPF_REG_7, 4); break;
    }
    return n;
}

/* `both` = emit the link on BOTH paths (the control); otherwise only on the
   fall-through, so the two states arriving at the narrowing check differ in exactly
   their id structure. `use_r6` stores through the register the check narrows directly,
   which must be safe no matter what the ids say. */
static void run_idmap_prog(enum idmap_link link, int both, int use_r6, int store_off,
                           int idx, int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);   /* scalar A */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_7, BPF_REG_0, 4);   /* scalar B */
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_9, BPF_REG_0, 8);   /* path selector */

    /* The split tests r9 alone, so neither scalar is constrained by the branch and the
       only difference between the two arriving states is the LINK. */
    const int jsplit = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 0, 0);
    n = emit_idmap_link(ins, n, link);                        /* fall-through path */
    const int jmerge = n; ins[n++] = BPF_JMP_IMM(BPF_JA, 0, 0, 0);
    ins[jsplit].off = n - jsplit - 1;
    if (both)
        n = emit_idmap_link(ins, n, link);                    /* taken path too */
    ins[jmerge].off = n - jmerge - 1;

    /* The narrowing check names r6 only. r7 is narrowed ONLY through the shared id, by
       sync_linked_regs -- which is exactly the knowledge a wrong prune would smuggle
       into a state that never had it. */
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JGT, BPF_REG_6, 7, 0);

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_8, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_8, use_r6 ? BPF_REG_6 : BPF_REG_7);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_8, store_off, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++)
        ins[jexit[i]].off = exit0 - jexit[i] - 1;

    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "genidmap#%s.%s.r%d#%03d", idmap_link_name(link),
             both ? "both" : "one", use_r6 ? 6 : 7, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=8 off=%d size=1\n", store_insn, store_off);
    printf("IDMAP link=%s both=%d store_reg=r%d store_off=%d\n",
           idmap_link_name(link), both, use_r6 ? 6 : 7, store_off);
    printf("PRUNE fall=%s taken=%s fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           idmap_link_name(link), both ? "both" : "one", base.accept, base.accept,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
            unsigned char zero[RTW_VALUE_SIZE], val[16];
            memset(zero, 0, sizeof(zero));
            memset(val, 0, sizeof(val));
            memcpy(val + 0, &in, 4);          /* scalar A */
            memcpy(val + 4, &in, 4);          /* scalar B */
            uint32_t sel = i & 1;             /* exercise BOTH paths at runtime */
            memcpy(val + 8, &sel, 4);
            int ue = rt_map_set_bytes(map_in, 0, val);
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
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_idmap_family(void) {
    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = 16; m.max_entries = 1;   /* two scalars + selector */
    int map_in = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_in < 0 || map_out < 0) {
        printf("===PROG genidmap type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Store offset 48 leaves room for the +4 delta of the ADD_CONST arms: linked and
       narrowed, r7 is at most 7 (bare) or 11 (delta 4), so 48 + 11 + 1 = 60 <= 64. The
       decision therefore turns on LINKAGE, never on the offset arithmetic. */
    const struct { enum idmap_link link; int both, use_r6; } arms[] = {
        { IDL_NONE,   0, 0 },   /* baseline: r7 never narrowed on either path   */
        { IDL_NONE,   0, 1 },   /* control:  store through the narrowed r6       */
        { IDL_MOV,    0, 0 },   /* THE SHAPE: link on one path only              */
        { IDL_MOV,    1, 0 },   /* control:  link on both paths                  */
        { IDL_MOV,    0, 1 },   /* control:  one-path link, store through r6     */
        { IDL_ADDC64, 0, 0 },   /* BPF_ADD_CONST64 link on one path only         */
        { IDL_ADDC64, 1, 0 },   /* control:  both paths                          */
        { IDL_ADDC32, 0, 0 },   /* BPF_ADD_CONST32 link on one path only         */
        { IDL_ADDC32, 1, 0 },   /* control:  both paths                          */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_idmap_prog(arms[i].link, arms[i].both, arms[i].use_r6, 48, idx++,
                       map_in, map_out);
    close(map_in);
    close(map_out);
}

// ---- open-coded iterator family (--gen-iter) --------------------------------
// The SAME loop bodies as --gen-loop, driven by a DIFFERENT loop mechanism. That makes
// the leg a mechanism differential on top of everything else: both are back-edges over
// the same transfer function, so for a body whose reachable set does not depend on the
// trip count the two mechanisms must agree. Where they legitimately DIFFER is the
// interesting part -- an open-coded iterator over [0,8) is a BOUNDED loop, while
// may_goto's count is unbounded, so a body that grows the offset is bounded here and not
// there. The `.o48` arms exist to expose exactly that: at store offset 48 the access is
// in bounds iff umax(r6) <= 15, which an 8-trip `inc` satisfies ([0,7] entry + at most 8
// increments) and an unbounded may_goto loop cannot.
//
// Iterators are also CHEAP to execute: at most 8 iterations, with none of may_goto's
// 250ms time budget (0044), so the runtime store-location oracle rides along for free.
// Every accepted program is executed over the full residue sweep and the landing site is
// compared against what the verifier proved -- the strictly stronger question, now on
// the mechanism the kernel itself special-cases in its pruning path.
static void run_iter_prog(const struct iter_ids *ids, enum loop_body body,
                          int store_off, int idx, int map_in, int map_out) {
    struct bpf_insn ins[80];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -16, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);          /* entry invariant [0,7] */

    n = emit_iter_loop(ins, n, ids, 0, 8, body);              /* at most 8 trips */

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -16, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, store_off, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);                   /* witness: store ran */
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;

    /* 0042's instrument, unchanged, plus a fourth load that keeps the fd for running. */
    struct prune_load base = prune_load_once(ins, n, 0, g_log, sizeof(g_log));
    struct prune_load freq = prune_load_once(ins, n, BPF_F_TEST_STATE_FREQ,
                                             g_log2, sizeof(g_log2));
    struct prune_load inv  = prune_load_once(ins, n, BPF_F_TEST_REG_INVARIANTS,
                                             g_log2, sizeof(g_log2));

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;

    char name[96];
    snprintf(name, sizeof(name), "geniter#%s.o%d#%03d", loop_body_name(body), store_off, idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=0\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e);
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, store_off);
    printf("PRUNE fall=%s taken=o%d fall_safe=%d taken_safe=%d stack=0"
           " base_verdict=%s base_errno=%d base_states=%lu base_reason=%s"
           " freq_verdict=%s freq_errno=%d freq_states=%lu freq_reason=%s"
           " inv_verdict=%s inv_errno=%d inv_reason=%s\n",
           loop_body_name(body), store_off, base.accept, base.accept,
           base.accept ? "accept" : "reject", base.err, base.states, base.reason,
           freq.accept ? "accept" : "reject", freq.err, freq.states, freq.reason,
           inv.accept ? "accept" : "reject", inv.err, inv.reason);
    printf("LOOP body=%s init_mask=7 store_off=%d\n", loop_body_name(body), store_off);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
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
            int executed = (t.test.retval == 1);
            if (off < 0)
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_iter_family(void) {
    struct iter_ids ids;
    if (iter_resolve(&ids) < 0) {
        printf("===PROG geniter type=socket_filter ===\n"
               "RESULT decision=error btf_resolve_failed errno=%d\n---LOG---\n---END---\n",
               errno);
        return;
    }
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
        printf("===PROG geniter type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Ten bodies at offset 56 -- directly comparable to --gen-loop's may_goto table --
       plus the two `.o48` arms where BOUNDEDNESS decides: at 48 the access is in bounds
       iff umax(r6) <= 15, which an 8-trip `inc` can satisfy and an unbounded loop
       cannot. */
    const struct { enum loop_body body; int off; } arms[] = {
        { LB_NOP,     56 }, { LB_MASK,    56 }, { LB_INCMASK, 56 }, { LB_MASKINC, 56 },
        { LB_SHR,     56 }, { LB_XOR3,    56 }, { LB_COND,    56 }, { LB_INC,     56 },
        { LB_SHL,     56 }, { LB_ADD8,    56 },
        { LB_INC,     48 }, { LB_NOP,     48 },
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_iter_prog(&ids, arms[i].body, arms[i].off, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

/* --probe-iter: does the kfunc/BTF machinery work at all, and is there a decision
   surface? Reports the resolved ids so a WRONG id (which is not a load error, just a
   call to another function) is visible rather than silent. */
static void run_probe_iter(void) {
    struct iter_ids ids;
    if (iter_resolve(&ids) < 0) {
        printf("CHANNEL btf=fail new=%d next=%d destroy=%d\n",
               ids.new_id, ids.next_id, ids.destroy_id);
        return;
    }
    printf("CHANNEL btf=ok new=%d next=%d destroy=%d btf_bytes=%u\n",
           ids.new_id, ids.next_id, ids.destroy_id, g_btf_len);

    union bpf_attr m;
    memset(&m, 0, sizeof(m));
    m.map_type = BPF_MAP_TYPE_ARRAY;
    m.key_size = 4; m.value_size = RTW_VALUE_SIZE; m.max_entries = 1;
    int map_out = bpf(BPF_MAP_CREATE, &m, sizeof(m));
    if (map_out < 0) { printf("CHANNEL error=map_create errno=%d\n", errno); return; }

    /* arm 0: bare loop, no store -- does the mechanism verify at all?
       arm 1: accumulate then mask, then store: is there a decision surface?
       arm 2: accumulate WITHOUT mask, then store: the unsound-fixpoint shape. */
    for (int arm = 0; arm < 3; arm++) {
        struct bpf_insn ins[64];
        int n = 0, jexit[2], nx = 0;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_6, 0);
        n = emit_iter_loop(ins, n, &ids, 0, 8,
                           arm == 1 ? LB_INCMASK : LB_INC);
        if (arm > 0) {
            ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -16, 0);
            ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
            ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -16);
            ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM,
                                         .dst_reg = BPF_REG_1,
                                         .src_reg = BPF_PSEUDO_MAP_FD, .off = 0,
                                         .imm = map_out};
            ins[n++] = (struct bpf_insn){0};
            ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
            jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
            ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
            ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
            ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, LOOP_STORE_OFF, -1);
        }
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        if (nx) {
            /* Only emit the null-path exit when something actually BRANCHES to it.
               Arm 0 has no map lookup, so an unconditional trailing block would be
               unreachable and the verifier rejects before walking a single insn
               ("processed 0 insns", EINVAL) -- a malformed probe, not a signal. */
            const int exit0 = n;
            ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
            ins[n++] = BPF_EXIT_INSN();
            for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;
        }

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 1;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        int e = errno;
        const char *tail = "";
        if (fd < 0) {
            /* last non-empty line of the log = the reason */
            static char why[256];
            const char *nl = g_log, *last = g_log;
            for (const char *q = g_log; *q; q++) if (*q == '\n' && q[1]) last = q + 1;
            (void)nl;
            snprintf(why, sizeof(why), "%s", last);
            for (char *q = why; *q; q++) if (*q == '\n') { *q = '\0'; break; }
            tail = why;
        }
        printf("CHANNEL arm=%d insns=%d verdict=%s errno=%d reason=\"%s\"\n",
               arm, n, fd >= 0 ? "accept" : "reject", fd >= 0 ? 0 : e, tail);
        if (fd >= 0) close(fd);
    }
    close(map_out);
}

// ---- loop fixpoint vs runtime (--gen-loopr) ---------------------------------
// 0043 asked whether a back-edge program's VERDICT survives a change in checkpoint
// frequency. This asks the strictly stronger question 0041 introduced, now on a loop:
// the verifier proves a bound on the offset register at the store by computing a
// FIXPOINT over an unbounded number of iterations -- does that bound hold for the
// number of iterations the machine ACTUALLY runs?
//
// It also closes a hole in 0043: that family emits a STORE line but never executes, so
// `store_locations_checked` was 0 -- by this project's own rule, the claim was never
// read, and zero findings there meant nothing.
//
// COST, MEASURED FIRST (--probe-loopr): on x86-64 `bpf_jit_supports_timed_may_goto()`
// is true, so the budget is TIME-based and every run spends the full
// `NSEC_PER_SEC / 4`. Measured: 250.3 / 250.5 / 251.4 ms -- the budget exactly. Being
// time-based is what makes this affordable at all: KASAN/KCOV slowness lowers the
// iteration count inside the same 250ms instead of extending the run (OI-11).
// Six shapes x eight inputs x 250ms is about 12 seconds of kernel-side spinning.
//
// THE SWEEP IS THIS FAMILY'S OWN. The shared RT_INPUTS has twelve values, but the entry
// state here is `input & 7`, and those twelve collapse to only FIVE distinct residues --
// seven runs of 250ms each buying nothing. LOOPR_INPUTS covers all eight.
//
// NON-DETERMINISM IS A FEATURE HERE. The final offset depends on how many iterations
// fit in the time budget, so a shape like `incmask` lands somewhere different on every
// run. The oracle asks for MEMBERSHIP in the verifier's proven set, never equality, so
// each run samples the fixpoint at a fresh point. Nothing downstream may assert an exact
// store_off for these arms.

static void run_loopr_prog(enum loop_body body, int idx, int map_in, int map_out) {
    struct bpf_insn ins[64];
    int n = 0, jexit[4], nx = 0;

    ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
    ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
    const int loop_head = n;
    const int jbreak = n; ins[n++] = BPF_MAY_GOTO_INSN(0);
    n = emit_loop_body(ins, n, body);
    const int jback = n;
    ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - jback - 1);
    n++;
    ins[jbreak].off = n - jbreak - 1;
    ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
    ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
    ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                 .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
    ins[n++] = (struct bpf_insn){0};
    ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
    jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
    ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
    ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
    const int store_insn = n;
    ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, LOOP_STORE_OFF, -1);
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);   /* witness: the store path ran */
    ins[n++] = BPF_EXIT_INSN();
    const int exit0 = n;
    ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
    ins[n++] = BPF_EXIT_INSN();
    for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;

    g_log[0] = '\0';
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    attr.insn_cnt = n;
    attr.insns = (uint64_t)(unsigned long)ins;
    attr.license = (uint64_t)(unsigned long)"GPL";
    attr.log_level = 2;
    attr.log_size = sizeof(g_log);
    attr.log_buf = (uint64_t)(unsigned long)g_log;
    uint64_t t0 = now_ns();
    int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    int e = errno;
    uint64_t dt = now_ns() - t0;

    char name[96];
    snprintf(name, sizeof(name), "genloopr#%s#%03d", loop_body_name(body), idx);
    printf("===PROG %s type=socket_filter ===\n", name);
    printf("RESULT decision=%s fd=%d errno=%d load_ns=%llu\n",
           fd >= 0 ? "accept" : "reject", fd, fd >= 0 ? 0 : e, (unsigned long long)dt);
    printf("STORE insn=%d reg=7 off=%d size=1\n", store_insn, LOOP_STORE_OFF);

    if (fd >= 0) {
        unsigned char pkt[64];
        memset(pkt, 0, sizeof(pkt));
        for (int i = 0; i < LOOPR_INPUTS_N; i++) {
            uint32_t in = LOOPR_INPUTS[i];
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
            int executed = (t.test.retval == 1);
            if (off < 0) {
                printf("RUNTIME input=0x%08x store_off=none store_len=0 store_size=1"
                       " executed=%d\n", in, executed);
            } else {
                int len = 0;
                for (int b = off; b < RTW_VALUE_SIZE && out[b] == RTW_SENTINEL; b++) len++;
                printf("RUNTIME input=0x%08x store_off=%d store_len=%d store_size=1"
                       " executed=%d\n", in, off, len, executed);
            }
        }
        close(fd);
    }
    printf("---LOG---\n%s\n---END---\n", g_log);
}

static void run_generated_loopr_family(void) {
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
        printf("===PROG genloopr type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* The six shapes 0043 measured as ACCEPTED, plus one rejected shape as a control
       that the decision surface is still real here. A rejected program never runs, so
       it contributes no runtime samples and no 250ms. */
    const enum loop_body shapes[] = {
        LB_NOP, LB_MASK, LB_INCMASK, LB_SHR, LB_XOR3, LB_COND,
        LB_MASKINC,   /* control: join [0,8] -> rejected, contributes no runtime */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(shapes) / sizeof(shapes[0]); i++)
        run_loopr_prog(shapes[i], idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

/* --probe-loopr: MEASURE before committing to a runtime loop family.
 *
 * On x86-64 `bpf_jit_supports_timed_may_goto()` is true, so the may_goto budget is
 * TIME-based: bpf_check_timed_may_goto() refreshes a 0xffff counter until
 * `NSEC_PER_SEC / 4` has elapsed, i.e. ~250ms of kernel-side spinning PER RUN. A full
 * 12-input sweep over the six accepted loop shapes would be ~18s of that, in 250ms
 * uninterruptible chunks -- and OI-11 is exactly the lesson that says do not guess about
 * this. So: one run per shape, wall time and landing site reported, and the family gets
 * sized from the measurement instead of from an assumption.
 *
 * Being time-based is the reassuring half: KASAN/KCOV slowness cannot extend the budget,
 * it only lowers the iteration count inside the same 250ms. The measurement says whether
 * the whole idea is affordable. */
static void run_probe_loopr(void) {
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
        printf("CHANNEL error=map_create errno=%d\n", errno);
        return;
    }
    const enum loop_body shapes[] = { LB_NOP, LB_INCMASK, LB_SHR };
    for (unsigned si = 0; si < sizeof(shapes) / sizeof(shapes[0]); si++) {
        struct bpf_insn ins[64];
        int n = 0, jexit[4], nx = 0;
        ins[n++] = BPF_ST_MEM(BPF_W, BPF_REG_10, -4, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_in};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_LDX_MEM(BPF_W, BPF_REG_6, BPF_REG_0, 0);
        ins[n++] = BPF_ALU64_IMM(BPF_AND, BPF_REG_6, 7);
        const int loop_head = n;
        const int jbreak = n; ins[n++] = BPF_MAY_GOTO_INSN(0);
        n = emit_loop_body(ins, n, shapes[si]);
        const int jback = n;
        ins[jback] = BPF_JMP_IMM(BPF_JA, 0, 0, loop_head - jback - 1);
        n++;
        ins[jbreak].off = n - jbreak - 1;
        ins[n++] = BPF_MOV64_REG(BPF_REG_2, BPF_REG_10);
        ins[n++] = BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4);
        ins[n++] = (struct bpf_insn){.code = BPF_LD | BPF_DW | BPF_IMM, .dst_reg = BPF_REG_1,
                                     .src_reg = BPF_PSEUDO_MAP_FD, .off = 0, .imm = map_out};
        ins[n++] = (struct bpf_insn){0};
        ins[n++] = BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem);
        jexit[nx++] = n; ins[n++] = BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 0);
        ins[n++] = BPF_MOV64_REG(BPF_REG_7, BPF_REG_0);
        ins[n++] = BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_6);
        ins[n++] = BPF_ST_MEM(BPF_B, BPF_REG_7, LOOP_STORE_OFF, -1);
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 1);
        ins[n++] = BPF_EXIT_INSN();
        const int exit0 = n;
        ins[n++] = BPF_MOV64_IMM(BPF_REG_0, 0);
        ins[n++] = BPF_EXIT_INSN();
        for (int i = 0; i < nx; i++) ins[jexit[i]].off = exit0 - jexit[i] - 1;

        g_log[0] = '\0';
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
        attr.insn_cnt = n;
        attr.insns = (uint64_t)(unsigned long)ins;
        attr.license = (uint64_t)(unsigned long)"GPL";
        attr.log_level = 1;
        attr.log_size = sizeof(g_log);
        attr.log_buf = (uint64_t)(unsigned long)g_log;
        int fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
        if (fd < 0) {
            printf("CHANNEL shape=%s load=reject errno=%d\n", loop_body_name(shapes[si]), errno);
            continue;
        }
        unsigned char zero[RTW_VALUE_SIZE], out[RTW_VALUE_SIZE], pkt[64];
        memset(zero, 0, sizeof(zero)); memset(pkt, 0, sizeof(pkt));
        rt_map_set(map_in, 0, 0x5a5a5a5a);
        rt_map_set_bytes(map_out, 0, zero);
        union bpf_attr t;
        memset(&t, 0, sizeof(t));
        t.test.prog_fd = fd;
        t.test.data_in = (uint64_t)(unsigned long)pkt;
        t.test.data_size_in = sizeof(pkt);
        t.test.repeat = 1;
        uint64_t t0 = now_ns();
        int r = bpf(BPF_PROG_TEST_RUN, &t, sizeof(t));
        uint64_t dt = now_ns() - t0;
        memset(out, 0, sizeof(out));
        rt_map_get(map_out, 0, out);
        int off = -1;
        for (int b = 0; b < RTW_VALUE_SIZE; b++)
            if (out[b] == RTW_SENTINEL) { off = b; break; }
        printf("CHANNEL shape=%s load=accept testrun_rc=%d retval=%u wall_ns=%llu",
               loop_body_name(shapes[si]), r, (unsigned)t.test.retval,
               (unsigned long long)dt);
        if (off < 0) printf(" store_off=none\n"); else printf(" store_off=%d\n", off);
        close(fd);
    }
    close(map_in);
    close(map_out);
}

static void run_generated_loop_family(void) {
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
        printf("===PROG genloop type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* Derived expectation (the capture is the authority): with the store at +56 the
       access is in bounds iff the JOIN over all iteration counts keeps umax(r6) <= 7.
       `maskinc` vs `incmask` is the sharp pair -- same two operations, opposite ORDER,
       [1,8] vs [0,7], one byte apart. `narrow` is the zero-iteration probe: its body
       tightens the range, but entering with [0,63] and taking the break immediately
       leaves [0,63] at the store, so it must still be rejected. */
    const struct { enum loop_body body; int init_mask; } arms[] = {
        { LB_NOP,     7  },   /* control: back-edge alone must not change a verdict */
        { LB_MASK,    7  },
        { LB_INCMASK, 7  },
        { LB_MASKINC, 7  },   /* [1,8] -- the exact off-by-one against incmask */
        { LB_SHR,     7  },
        { LB_XOR3,    7  },
        { LB_COND,    7  },
        { LB_INC,     7  },
        { LB_SHL,     7  },
        { LB_ADD8,    7  },
        { LB_MASK,    63 },   /* zero-iteration path: body narrows, entry does not */
        { LB_NOP,     63 },   /* control: wide entry, nothing narrows it */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_loop_prog(arms[i].body, arms[i].init_mask, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
}

static void run_generated_prune_family(void) {
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
        printf("===PROG genprune type=socket_filter ===\n"
               "RESULT decision=error map_create_failed errno=%d\n---LOG---\n---END---\n", errno);
        return;
    }
    /* The axis is the RELATION between the two merging states, crossed with the ORDER
       (which one checkpoints first). `dang.*` puts the SAFE state on the fall-through,
       so a wrong prune of the unsafe path would flip the decision to accept -- the
       only arms where a pruning bug is observable. `ctrl.*` is the mirror: the unsafe
       state checkpoints first and the safe one is legitimately subsumed, so a prune
       there is SOUND and proves the mechanism engages. `safe.*` accepts on both paths.
       A pure-tnum arm (same interval, different tnum) is deliberately ABSENT: the
       store's safety depends on umax alone, so no tnum difference can flip the
       decision -- it could only be a vacuous arm. */
    const struct { enum prune_shaper fall, taken; int stack; } arms[] = {
        { SH_N7,  SH_N7,  0 },   /* safe.eq    -- identical states, trivial prune */
        { SH_T6,  SH_N7,  0 },   /* safe.tnum  -- both safe, refined vs interval  */
        { SH_N7,  SH_W63, 0 },   /* dang.sup   -- superset arrives second         */
        { SH_N7,  SH_M39, 0 },   /* dang.disj  -- disjoint                        */
        { SH_N7,  SH_O19, 0 },   /* dang.ovl   -- overlapping                     */
        { SH_N7,  SH_S56, 0 },   /* dang.shift -- same umin, holey tnum           */
        { SH_N7,  SH_A32, 0 },   /* dang.alu32 -- 32-bit shaping path             */
        { SH_T6,  SH_W63, 0 },   /* dang.tnum  -- refined first, wide second      */
        { SH_W63, SH_N7,  0 },   /* ctrl.sup   -- sound prune (subset second)     */
        { SH_M39, SH_N7,  0 },   /* ctrl.disj                                     */
        { SH_O19, SH_N7,  0 },   /* ctrl.ovl                                      */
        { SH_S56, SH_N7,  0 },   /* ctrl.shift                                    */
        { SH_A32, SH_N7,  0 },   /* ctrl.alu32                                    */
        { SH_W63, SH_T6,  0 },   /* ctrl.tnum                                     */
        { SH_N7,  SH_W63, 1 },   /* stk.dang   -- the judge is stacksafe, not regsafe */
        { SH_W63, SH_N7,  1 },   /* stk.ctrl                                      */
    };
    int idx = 0;
    for (unsigned i = 0; i < sizeof(arms) / sizeof(arms[0]); i++)
        run_prune_prog(arms[i].fall, arms[i].taken, arms[i].stack, idx++, map_in, map_out);
    close(map_in);
    close(map_out);
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
    if (argc > 1 && strcmp(argv[1], "--gen-prune") == 0) {
        run_generated_prune_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-loop") == 0) {
        run_generated_loop_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-loopr") == 0) {
        run_probe_loopr();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-loopr") == 0) {
        run_generated_loopr_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--probe-iter") == 0) {
        run_probe_iter();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-iter") == 0) {
        run_generated_iter_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-idmap") == 0) {
        run_generated_idmap_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-idpart") == 0) {
        run_generated_idpart_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-frame") == 0) {
        run_generated_frame_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-spill") == 0) {
        run_generated_spill_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-prec") == 0) {
        run_generated_prec_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-exact") == 0) {
        run_generated_exact_family();
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--gen-rw") == 0) {
        run_generated_rw_family();
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
