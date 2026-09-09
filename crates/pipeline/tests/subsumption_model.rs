//! THE SUBSUMPTION MODEL'S OWN TEETH (devlog 0099/0100, reviewer bulgusu B1/B4).
//!
//! `scripts/subsume-check.py` is an independent implementation of `states_equal`'s scalar
//! arm — the project's first same-kernel reference for the PRUNING DECISION. Until this
//! file it was also the only oracle here with no test at all: `prunepair-sample.log` sat
//! in `tests/fixtures/volume/` next to 37 fixtures that are all `include_str!`-ed, and
//! nothing read it.
//!
//! That mattered, because the model shipped with a real transcription bug. The kernel does
//! the final comparison of `cnum_is_subset` in `ut` arithmetic, so the addition WRAPS
//! (`cnum_defs.h:244`); the model wrote the same line in Python, where it does not. The two
//! part company when `bigger.size == UT_MAX` and the rebased `smaller` wraps: kernel says
//! contained, model says not — a FALSE FINDING, and precisely on the wrapping arcs
//! `--probe-wraparc` is built to produce.
//!
//! THE RULE THIS FILE ENFORCES: a model's test must FAIL on the model's broken version.
//! A vector that passes on both sides is not a test of the bug, it is a vector that walks
//! past it. `SELFTEST_SUBSET`'s three wrap vectors fail on the unmasked model (measured:
//! `failed=3`, exit 1) and pass on the fixed one.
//!
//! The model is Python and this suite is Rust. It is invoked rather than ported ON PURPOSE:
//! a second implementation of the same predicate would be free to drift from the first, and
//! this project only benefits from independent implementations when the independence is
//! deliberate (`bpfref.h`, `bpflive.h`), never when it is an accident of language.
//!
//! If `python3` is missing the tests FAIL — they do not skip. A test that quietly skips is
//! the denominator-zero trap in another costume.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/pipeline must sit two levels under the repo root")
        .to_path_buf()
}

fn run_model(args: &[&str]) -> (String, bool) {
    let root = repo_root();
    let out = Command::new("python3")
        .arg(root.join("scripts/subsume-check.py"))
        .args(args)
        .current_dir(&root)
        .output()
        .expect("python3 must be available: the subsumption model is the only reference \
                 this project has for the pruning decision, so it is not optional");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.success(),
    )
}

fn field<'a>(text: &'a str, prefix: &str, key: &str) -> &'a str {
    let line = text
        .lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no line starting with {prefix:?} in:\n{text}"));
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix(key))
        .unwrap_or_else(|| panic!("no field {key:?} on line {line:?}"))
}

/// The vectors, and the reason each one exists. Every vector is tied to a measured event.
#[test]
fn model_self_test_passes() {
    let (out, ok) = run_model(&["--self-test"]);
    assert!(
        ok,
        "the model's own vectors must pass; output was:\n{out}"
    );
    assert_eq!(
        field(&out, "SELFTEST", "failed="),
        "0",
        "vectors failed:\n{out}"
    );
    // Guard against the vectors quietly disappearing: a self-test that checks nothing
    // reports failed=0 just as loudly as one that checks everything.
    let vectors: usize = field(&out, "SELFTEST", "vectors=").parse().unwrap();
    assert!(
        vectors >= 20,
        "the vector set shrank to {vectors}; it pins B1 (wrap), the 2f2ec8e7730e base-id \
         cross-check, and the B3a liveness-gate GAP — losing one silently un-pins a limit"
    );
}

/// The orphan fixture, adopted. These numbers are a real capture from the 896-program
/// composition corpus, taken through `patches/prunepair-instrumentation.patch`.
#[test]
fn model_agrees_with_the_kernel_on_the_sample_capture() {
    let (out, ok) = run_model(&["crates/pipeline/tests/fixtures/volume/prunepair-sample.log"]);
    assert!(ok, "model run failed:\n{out}");

    assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), "50");
    assert_eq!(field(&out, "SUBSUME pairs=", "agree="), "50");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "0");
    assert_eq!(field(&out, "SUBSUME pairs=", "unmodelled="), "0");
}

/// THE DENOMINATOR RULE, applied to this oracle (devlog 0066's guard, reviewer finding B3).
///
/// `agree=50` on its own is worth nothing: the precision short-circuit passes a register
/// without comparing it, so a pair can "agree" having computed nothing. The four terminal
/// categories must therefore partition the pairs, and the non-trivial half must be a
/// stated number rather than an implied one.
#[test]
fn denominator_partitions_the_pairs() {
    let (out, _) = run_model(&["crates/pipeline/tests/fixtures/volume/prunepair-sample.log"]);
    let pairs: usize = field(&out, "SUBSUME denominator", "pairs=").parse().unwrap();
    let trivial: usize = field(&out, "SUBSUME denominator", "trivial=").parse().unwrap();
    let nontrivial: usize = field(&out, "SUBSUME denominator", "nontrivial=").parse().unwrap();
    let breaks: usize = field(&out, "SUBSUME denominator", "breaks=").parse().unwrap();
    let unmodelled: usize = field(&out, "SUBSUME denominator", "unmodelled=").parse().unwrap();

    assert_eq!(
        field(&out, "SUBSUME denominator", "sums="),
        "ok",
        "the model must say so itself:\n{out}"
    );
    assert_eq!(
        trivial + nontrivial + breaks + unmodelled,
        pairs,
        "terminal categories do not partition the pairs:\n{out}"
    );
    assert_eq!(nontrivial, 31, "the sample's real denominator");
    assert!(
        trivial > 0,
        "a capture with no trivial pairs would mean the short-circuit never fired, which \
         contradicts every measurement since 0099 — suspect the parser, not the corpus"
    );
}

/// THE ARMS THE MODEL DOES NOT IMPLEMENT (reviewer finding B3). All three were measured
/// inert on the 896-program corpus, and none of them was written down. A silent
/// precondition is not a result; the first real disagreement has to eliminate these three
/// before it can be called a kernel finding, and that triage is only cheap if they are
/// counted.
#[test]
fn unimplemented_arms_are_counted_not_silent() {
    let (out, _) = run_model(&["crates/pipeline/tests/fixtures/volume/prunepair-sample.log"]);
    let line = out
        .lines()
        .find(|l| l.starts_with("SUBSUME unimplemented_arms"))
        .expect("the model must declare the arms it does not implement");

    for key in [
        "ptr_id_pairs=",                  // kernel seeds the idmap here, the model does not
        "dead_reg_cmps=",                 // comparisons the kernel never makes (liveness gate)
        "live_reg_cmps=",                 // its denominator
        "pairs_without_liveness_claim=",  // bpflive refused the program
        "pairs_without_tracked_reg=",     // claim exists, but the pair holds only r10
    ] {
        assert!(line.contains(key), "missing {key} in:\n{line}");
    }

    // refsafe() seeds the SAME idmap before any frame is walked, and the capture patch
    // prints neither refs[] nor active_lock_id — so this arm cannot be counted at all.
    // Saying that is the measurement.
    assert!(
        line.contains("refsafe_idmap_seed=not-observable-from-capture"),
        "the unobservable arm must still be named:\n{line}"
    );
}

// ---- PAIR THIRTEEN: `2f2ec8e7730e`, AND THE FIRST POSITIVE CALIBRATION OF THIS CHANNEL ----
//
// Every calibration before this one certified an oracle by making it fire on a planted
// violation, or measured a BOUNDARY where it could not fire at all. The pruning /
// cross-state channel had never had a positive: 0092 built `--probe-idbase` as the prune
// differential's first positive control and the differential reported NOTHING, because
// `BPF_F_TEST_STATE_FREQ` only makes pruning more aggressive and this bug is one the
// default checkpointing already takes (OI-15).
//
// The subsumption model sees it, and the reason it can is the distinction the channel
// verification drew: `2f2ec8e7730e` is a PREDICATE bug — sixteen lines wholly inside
// `check_scalar_ids`, corrupting no field the model reads — while `f54c7898ed1c`, the
// candidate this replaced, is a STATE bug (it corrupts `precise`, which the model reads
// from the capture and therefore inherits).
//
//     buggy `2f2ec8e7730e^`   unlinked: accept   linked: accept
//     fixed `2f2ec8e7730e`    unlinked: REJECT   linked: accept
//
// The pair the model objects to is the commit's own example, verbatim:
//
//     old   r2 id=1   r3 id=80000001 (delta=1)      base ids: 1 -> 1
//     cur   r2 id=1   r3 id=80000002 (delta=1)      base ids: 1 -> 2   <-- conflict
//
// The compound ids map cleanly (0x80000001 -> 0x80000002); only the BASE cross-check the
// fix added catches that `1` is already mapped to `1`. Without it the states compare equal
// and the verifier prunes a path it never proved.
//
// NOTE THE DENOMINATOR MOVES TOO, and that is confirmatory rather than incidental: the
// buggy capture carries TWO prune pairs, the fixed one carries ONE. On the fixed kernel
// `states_equal` returns false, so `hit:` is never reached and the prune event the model
// objected to does not exist. A calibration where the fixed side merely fell silent would
// be weaker than one where the event itself disappears.
//
// Captures: `--probe-idbase` on two kernels built from the same config, differing in the
// commit and in the era instrumentation patch (`patches/prunepair-instrumentation-minmax.patch`,
// which prints min/max because this revision predates cnum — see the era-floor typology).

const IDBASE_BUGGY: &str = include_str!("fixtures/volume/idbase-instr-buggy-2.log");
const IDBASE_FIXED: &str = include_str!("fixtures/volume/idbase-instr-fixed-1.log");

fn run_on_fixture(body: &str, tag: &str) -> String {
    // Unique per CALL, not per (pid, tag): these tests run in parallel inside one binary,
    // so two of them sharing a temp path race on write-then-delete. Found by running the
    // whole workspace — alone, this file passed.
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir()
        .join(format!("vl-subsume-{}-{n}-{tag}.log", std::process::id()));
    std::fs::write(&path, body).unwrap();
    let (out, ok) = run_model(&[path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);
    assert!(ok, "model run failed on {tag}:\n{out}");
    out
}

#[test]
fn pair_thirteen_fires_on_the_buggy_kernel() {
    let out = run_on_fixture(IDBASE_BUGGY, "buggy");

    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "1", "{out}");
    assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), "2", "{out}");

    // THE ARM IS THE CALIBRATION. A disagreement count alone does not close this: the
    // model has four known ways to disagree wrongly, and the whole point is that this one
    // lands on the predicate the commit repairs.
    let cand = out
        .lines()
        .find(|l| l.starts_with("SUBSUME candidate"))
        .expect("the buggy capture must name its candidate");
    assert!(
        cand.contains("arm=check_scalar_ids"),
        "the disagreement must be on the arm `2f2ec8e7730e` fixes, not another: {cand}"
    );

    // ...and the alternative explanations must be measured zero in the SAME output, so the
    // triage is read off the artifact rather than reconstructed later (reviewer B3).
    let arms = out
        .lines()
        .find(|l| l.starts_with("SUBSUME unimplemented_arms"))
        .unwrap();
    assert!(arms.contains("dead_reg_cmps=0"), "liveness gate not ruled out: {arms}");
    assert!(arms.contains("ptr_id_pairs=0"), "pointer-id idmap not ruled out: {arms}");
}

#[test]
fn pair_thirteen_is_silent_on_the_fixed_kernel() {
    let out = run_on_fixture(IDBASE_FIXED, "fixed");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "0", "{out}");
    // The prune itself is gone, not merely tolerated.
    assert_eq!(
        field(&out, "SUBSUME pairs=", "pairs="),
        "1",
        "the fixed kernel must not reach `hit:` for the trigger at all:\n{out}"
    );
}

/// The era format is a second capture format, and a parser that silently failed to read it
/// would report `pairs=0 disagree=0` — indistinguishable from a clean kernel. This is the
/// 0065 lesson (a parser blind spot reads as a meaningless clean) applied in advance.
#[test]
fn era_captures_actually_parse() {
    for (body, tag, want_pairs) in [(IDBASE_BUGGY, "buggy", "2"), (IDBASE_FIXED, "fixed", "1")] {
        let out = run_on_fixture(body, tag);
        assert_eq!(field(&out, "SUBSUME pairs=", "unmodelled="), "0", "{out}");
        assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), want_pairs, "{out}");
        assert_ne!(
            field(&out, "SUBSUME nontrivial_pairs=", "scalar_comparisons="),
            "0",
            "a capture that parses but compares nothing is the denominator-zero trap:\n{out}"
        );
    }
}

// ---- PAIR FOURTEEN: `fd675184fc7a`, THE SECOND POSITIVE — AND ON A DIFFERENT ARM --------
//
// Pair thirteen calibrated `check_scalar_ids`. This one calibrates `range_within`, from a
// bug five years older, and it exists because the 0101 fan-out screened 40 historical
// state-quoting verifier fixes under the predicate/state typology and found exactly ONE the
// model could see. The screen's value was not the hit rate; it was that 23 of the 40 turned
// out to corrupt a field the model READS, which is a structural blindness, not a gap to
// close by trying harder.
//
// THE FIX IS FOUR ADDED COMPARISONS, nothing else:
//
//     +	       old->u32_min_value <= cur->u32_min_value &&
//     +	       old->u32_max_value >= cur->u32_max_value &&
//     +	       old->s32_min_value <= cur->s32_min_value &&
//     +	       old->s32_max_value >= cur->s32_max_value;
//
// so a jmp32-narrowed pair is judged on 64-bit bounds alone. The fields are written
// correctly; only the decision is wrong — which is exactly and only what this model can see.
//
// HAND-VERIFIED AGAINST THE COMMIT. The captured pair matches the bounds the maintainer
// quoted, field for field:
//
//     old r0  u64=0..ffffffffffffffff  s64=8000000000000000..7fffffffffffffff
//             u32=0..ffffffff          s32=80000000..3030
//     cur r0  u64=0..ffffffff7fffffff  s64=8000000000000000..7fffffff7fffffff
//             u32=3031..7fffffff       s32=3031..7fffffff
//
// old.s32_max (12336) >= cur.s32_max (2147483647) is false, so the eight-comparison form
// refuses. The four-comparison form sees only the 64-bit pairs, which hold, and prunes.
//
// THE VERDICT CHANNEL IS BLIND HERE, and that is the point: both kernels ACCEPT both arms.
// Upstream's reported consequence is a HANG (the unwalked branch is dead-code rewritten to
// `goto pc-1`), and a hang is observable by no oracle this project has — `run-harness-vm.sh`
// wraps the boot in `timeout … || true`, so it is indistinguishable from a slow round. The
// subsumption model is the only thing here that sees this bug at all.
//
// THE 2021 ERA IS A THIRD CAPTURE FORMAT (`patches/prunepair-instrumentation-2021.patch`):
// no exact_level, no cnum, no delta/BPF_ADD_CONST, and regsafe's scalar arm is a
// REG_LIVE_READ gate, a two-sided precision short-circuit, then range_within && tnum_in.
// The `live=` field is printed for the gate and doubles as the era marker — the row tells
// its consumer which regsafe it owes.

const JMP32_BUGGY: &str = include_str!("fixtures/volume/jmp32prune-instr-buggy-4.log");
const JMP32_FIXED: &str = include_str!("fixtures/volume/jmp32prune-instr-fixed-2.log");

#[test]
fn pair_fourteen_fires_on_the_buggy_kernel() {
    let out = run_on_fixture(JMP32_BUGGY, "j32buggy");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "2", "{out}");
    assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), "4", "{out}");

    // Both candidates must land on range_within — the arm the commit repairs. An equal
    // count on another arm would be a different bug, or ours.
    let cands: Vec<&str> = out
        .lines()
        .filter(|l| l.starts_with("SUBSUME candidate"))
        .collect();
    assert_eq!(cands.len(), 2, "{out}");
    for c in &cands {
        assert!(c.contains("arm=range_within"), "wrong arm: {c}");
        assert!(c.contains("insn=7"), "wrong instruction: {c}");
    }

    // The era gate was applied, not guessed: this revision's regsafe opens with
    // `if (!(rold->live & REG_LIVE_READ)) return true;` and the capture prints `live=`.
    let arms = out
        .lines()
        .find(|l| l.starts_with("SUBSUME unimplemented_arms"))
        .unwrap();
    assert!(arms.contains("live_gated_regs=2"), "{arms}");
}

#[test]
fn pair_fourteen_is_silent_on_the_fixed_kernel() {
    let out = run_on_fixture(JMP32_FIXED, "j32fixed");
    assert_eq!(field(&out, "SUBSUME pairs=", "disagree="), "0", "{out}");
    // Same signature as pair thirteen: the objected-to prune does not merely become
    // tolerable, it stops happening. 4 pairs on the buggy kernel, 2 on the fixed one.
    assert_eq!(field(&out, "SUBSUME pairs=", "pairs="), "2", "{out}");
    assert_ne!(
        field(&out, "SUBSUME nontrivial_pairs=", "scalar_comparisons="),
        "0",
        "a silent fixed side proves nothing if nothing was compared:\n{out}"
    );
}

/// SPECIFICITY. The two arms differ in ONE thing — whether the narrowing jumps are jmp32 or
/// jmp64 — and a 64-bit jump narrows the bounds the buggy `range_within` already compares.
/// So every disagreement must sit in the `jmp32` arm and none in `jmp64`. Without this the
/// count alone would not distinguish "the model found the bug" from "the model dislikes this
/// program shape".
#[test]
fn pair_fourteen_control_arm_is_clean() {
    let buggy_only_jmp64: String = JMP32_BUGGY
        .split("===PROG ")
        .filter(|blk| blk.starts_with("jmp32prune#fd675184fc7a#jmp64"))
        .map(|blk| format!("===PROG {blk}"))
        .collect();
    assert!(
        buggy_only_jmp64.contains("PRUNEPAIR"),
        "the control arm must itself produce a prune pair, or its silence is vacuous"
    );
    let out = run_on_fixture(&buggy_only_jmp64, "j32control");
    assert_eq!(
        field(&out, "SUBSUME pairs=", "disagree="),
        "0",
        "the control arm fired on the BUGGY kernel — the signal is not specific to the bug:\n{out}"
    );
}
