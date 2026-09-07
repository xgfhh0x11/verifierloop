//! The liveness GATE oracle (devlog 0088) — the first cross-state check whose reference is
//! neither the verifier nor a second kernel.
//!
//! Since `0fb3cf6110a5` (2025-03) `func_states_equal` compares only the registers the
//! verifier believes are live where two states meet, so a register wrongly called dead is a
//! prune that never had to justify itself. 0088 measured that the pruning DECISION is not
//! auditable from the log — the prune record carries neither state (verifier.c:18387-18392)
//! and the log cannot express `range_within`'s domain — but the GATE is printed, and unlike
//! the decision it is a property of the instruction stream alone.
//!
//! These arms pin the PREDICATE. The measured agreement against real captures lives with
//! the corpus fixtures; what must never drift is the direction.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

fn run(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-live-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("c.log");
    std::fs::write(&src, text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("c", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (norm, out)
}

/// One program, two instructions. The kernel's table says r0 is live before insn 0 and
/// nothing is live before insn 1; `claim` is the harness's independent mask, three hex
/// digits per instruction.
fn capture(claim: &str) -> String {
    format!(
        "===PROG livegate#synth type=socket_filter ===\n\
         RESULT decision=accept fd=1 errno=0 load_ns=0\n\
         LIVENESS status=ok n=2 mask={claim}\n\
         ---LOG---\n\
         Live regs before insn:\n\
         \x20     0: 0......... (b7) r0 = 1\n\
         \x20     1: .......... (95) exit\n\
         ---END---\n"
    )
}

/// AGREEMENT: the denominator counts the cells that could have fired — the ones the
/// independent analysis calls LIVE — and nothing fires.
#[test]
fn agreement_counts_the_cells_that_could_have_fired_and_reports_nothing() {
    let (norm, out) = run(&capture("001000"), "agree");
    assert_eq!(norm.records.len(), 1);
    assert_eq!(out.summary.liveness_gate_checked, 1, "r0 at insn 0 is the only live cell");
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// THE FINDING DIRECTION: the kernel calls dead a register the independent analysis calls
/// live, so state equality at that instruction never had to compare it.
#[test]
fn a_register_the_kernel_drops_but_the_reference_keeps_is_a_finding() {
    let (_, out) = run(&capture("001001"), "over");
    assert_eq!(out.summary.liveness_gate_checked, 2, "both claimed-live cells are compared");
    let hits: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.kind == "liveness_gate_overreach")
        .collect();
    assert_eq!(hits.len(), 1, "{:?}", out.findings);
    assert!(hits[0].observed.contains("insn 1"), "{}", hits[0].observed);
    assert!(hits[0].observed.contains("r0"), "{}", hits[0].observed);
}

/// THE OTHER DIRECTION IS NOT A FINDING and is not counted. The kernel comparing a register
/// it did not have to costs precision and risks nothing; counting it would put comparisons
/// that cannot fail into the denominator.
#[test]
fn the_kernel_being_conservative_is_neither_reported_nor_counted() {
    let (_, out) = run(&capture("000000"), "cons");
    assert_eq!(out.summary.liveness_gate_checked, 0);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// A program the reference REFUSES contributes nothing rather than noise. This is the whole
/// reason `bpflive.h` has an UNSUPPORTED status: the finding direction is also the direction
/// a coarser analysis produces, so approximating a subprogram call would manufacture
/// findings out of the model's own gaps.
#[test]
fn an_unsupported_program_contributes_no_comparisons() {
    let text = capture("001000").replace(
        "LIVENESS status=ok n=2 mask=001000",
        "LIVENESS status=unsupported n=2 at=1 why=opcode_outside_the_model",
    );
    let (norm, out) = run(&text, "unsup");
    assert_eq!(norm.records.len(), 1, "the record still parses");
    assert_eq!(
        norm.unparsed.iter().filter(|u| u.kind == UnparsedKind::Unrecognized).count(),
        0
    );
    assert_eq!(out.summary.liveness_gate_checked, 0);
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

// ===========================================================================================
// MEASURED AGAINST REAL CAPTURES
// ===========================================================================================
//
// Two families whose every program the model accepts, so the agreement is not a statement
// about the easy half. The 896-program composition corpus is measured the same way by
// `FAMILIES=comp scripts/run-liveness.sh` and is not committed here: it is 17 MB, and the
// numbers it produces (562 modelled, 334 refused for the subprogram call, 92,784 cells,
// zero disagreements) are reported in devlog 0088 with the command that reproduces them.

const LIVE_PRUNE: &str = include_str!("fixtures/volume/live-prune-16.log");
const LIVE_SPILL: &str = include_str!("fixtures/volume/live-spill-12.log");

/// THE HEADLINE. An independent recomputation of the verifier's liveness gate, over the
/// emitted bytes, agrees with the kernel on every cell it is willing to judge.
#[test]
fn the_independent_analysis_agrees_with_the_kernel_on_two_whole_families() {
    // Floors, not equalities: measured at 491 and 571 firing-capable cells, and a parser
    // improvement that reads MORE of the table must not have to edit this test.
    for (text, tag, progs, floor) in
        [(LIVE_PRUNE, "f-prune", 16usize, 450u64), (LIVE_SPILL, "f-spill", 12, 500)]
    {
        let (norm, out) = run(text, tag);
        assert_eq!(norm.records.len(), progs, "{tag}");
        // Every program in these two families is inside the model: an agreement measured
        // over a subset the model happened to like would say much less.
        assert_eq!(text.matches("LIVENESS status=unsupported").count(), 0, "{tag}");
        assert_eq!(text.matches("LIVENESS status=ok").count(), progs, "{tag}");

        assert_eq!(
            out.findings.iter().filter(|f| f.kind == "liveness_gate_overreach").count(),
            0,
            "{tag}: {:?}",
            out.findings
        );
        // The denominator behind that zero. Without it the assertion above would hold just
        // as well for a capture nothing was compared in.
        assert!(
            out.summary.liveness_gate_checked > floor,
            "{tag}: only {} cells could have fired",
            out.summary.liveness_gate_checked
        );
        assert_eq!(
            norm.unparsed.iter().filter(|u| u.kind == UnparsedKind::Unrecognized).count(),
            0,
            "{tag}"
        );
    }
}

/// THE DENOMINATOR IS NOT THE WHOLE TABLE, and the gap is the point. The kernel prints one
/// cell per (instruction, register); only the cells the independent analysis calls LIVE can
/// ever produce a finding, so only those are counted. Asserting the ratio keeps a future
/// change from quietly counting the other 70% and reporting a much larger zero.
#[test]
fn only_the_cells_that_could_fire_are_counted() {
    let (_, out) = run(LIVE_PRUNE, "f-ratio");
    let printed = LIVE_PRUNE
        .lines()
        .filter(|l| {
            l.starts_with(' ')
                && l.split_once(':').is_some_and(|(h, r)| {
                    h.split_whitespace().last().is_some_and(|t| t.parse::<u32>().is_ok())
                        && r.strip_prefix(' ').is_some_and(|c| {
                            c.len() >= 10
                                && c[..10].bytes().all(|b| b == b'.' || b.is_ascii_digit())
                        })
                })
        })
        .count() as u64
        * 10;
    assert!(printed > 0, "the table must be present at all");
    assert!(
        out.summary.liveness_gate_checked < printed,
        "counted {} of {printed} printed cells — the dead ones cannot fail and must not count",
        out.summary.liveness_gate_checked
    );
}

// ===========================================================================================
// PAIR NINE — 3157f7e29996: the gate oracle calibrated against a real kernel bug
// ===========================================================================================
//
// `can_jump()` enumerates the conditional-jump opcodes whose taken edge `insn_successors()`
// reports, and BPF_JSET was not in the list — one missing `case` label. So the CFG the
// liveness analysis walks lost an edge, and the commit says exactly what that costs:
// "a jump to (5) would be missed and r2 won't be marked as alive at (3)".
//
// A register the verifier calls dead is never compared by `func_states_equal`, so a liveness
// that is too SMALL is a prune that never had to justify itself. That is the direction
// `check_liveness_gate` reports, and this is the bug that proves it fires on a real one.
//
// All three halves are real captures from `--probe-jsetlive`. `buggy` is 3157f7e29996~1 and
// `fixed` is 3157f7e29996 itself, built from BYTE-IDENTICAL .config files: the two kernels
// differ in one case label and nothing else. `tip` is today's bpf-next, kept separate because
// the whole analysis moved into `kernel/bpf/liveness.c` after this commit.

const JS_BUGGY: &str = include_str!("fixtures/calibration/jsetlive-3157f7e29996-buggy.log");
const JS_FIXED: &str = include_str!("fixtures/calibration/jsetlive-3157f7e29996-fixed.log");
const JS_TIP: &str = include_str!("fixtures/calibration/jsetlive-3157f7e29996-tip.log");

/// Findings paired with the program label they belong to, so an arm can be named.
fn labelled_findings(text: &str, tag: &str) -> Vec<(String, String)> {
    let (norm, out) = run(text, tag);
    out.findings
        .iter()
        .map(|f| {
            let label = f
                .record_index
                .and_then(|i| norm.records.get(i as usize))
                .and_then(|r| r.source_label.clone())
                .unwrap_or_default();
            (label, f.kind.clone())
        })
        .collect()
}

/// THE CALIBRATION: the oracle fires on the kernel that had the bug and is silent on the one
/// that fixed it — with the SAME denominator on both sides, so the zero is a real zero.
#[test]
fn the_gate_oracle_fires_on_the_kernel_that_had_the_missing_jset_edge() {
    let (_, buggy) = run(JS_BUGGY, "js-b");
    let (_, fixed) = run(JS_FIXED, "js-f");
    let (_, tip) = run(JS_TIP, "js-t");

    assert_eq!(
        buggy.findings.iter().filter(|f| f.kind == "liveness_gate_overreach").count(),
        1,
        "{:?}",
        buggy.findings
    );
    assert_eq!(fixed.summary.finding_count, 0, "{:?}", fixed.findings);
    assert_eq!(tip.summary.finding_count, 0, "{:?}", tip.findings);
    for (name, s) in
        [("buggy", &buggy.summary), ("fixed", &fixed.summary), ("tip", &tip.summary)]
    {
        assert_eq!(s.liveness_gate_checked, 20, "{name}");
    }
}

/// THE CONTROL: the two arms are the same program with one token changed — the comparison
/// opcode. `jne` was in the buggy `can_jump()` and `jset` was not, so only the jset arm may
/// diverge. If the control fired too, the finding would be about the shape.
#[test]
fn only_the_jset_arm_diverges_and_only_on_the_buggy_kernel() {
    let hits = labelled_findings(JS_BUGGY, "js-b-arm");
    assert_eq!(hits.len(), 1, "{hits:?}");
    assert!(hits[0].0.ends_with("jset"), "{hits:?}");
    assert_eq!(hits[0].1, "liveness_gate_overreach");

    // Straight out of the captures: the buggy kernel drops r2 at the jump in the jset arm
    // and keeps it in the jne arm, on the very same kernel.
    assert!(JS_BUGGY.contains(" 4: 01........ (45) if r1 & 0x7"), "jset arm must lose r2");
    assert!(JS_BUGGY.contains(" 4: 012....... (55) if r1 != 0x7"), "jne control must keep it");
    assert!(JS_FIXED.contains(" 4: 012....... (45) if r1 & 0x7"), "the fix restores it");
}

/// The finding names the register the commit named, and the instruction it named.
#[test]
fn the_finding_points_at_r2_at_the_jump() {
    let (_, buggy) = run(JS_BUGGY, "js-b-txt");
    let f = buggy
        .findings
        .iter()
        .find(|f| f.kind == "liveness_gate_overreach")
        .expect("the finding must exist");
    assert!(f.observed.contains("insn 4"), "{}", f.observed);
    assert!(f.observed.contains("r2"), "{}", f.observed);
    // The masks are reported side by side so triage never has to re-derive them.
    assert!(f.observed.contains("0x003"), "kernel mask: {}", f.observed);
    assert!(f.observed.contains("0x007"), "independent mask: {}", f.observed);
}
