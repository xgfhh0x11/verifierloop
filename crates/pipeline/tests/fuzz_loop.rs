//! COVERAGE-GUIDED CONTINUOUS FUZZING (devlog 0078) — the throughput leg.
//!
//! The strategic position: after seven calibration pairs the ORACLE stopped being the
//! bottleneck. Volume and aim became it, and the honest estimate of finding anything in
//! another batch-sized run was low single digits. This mode trades batch runs for a loop
//! that keeps and perturbs whatever reaches new verifier code.
//!
//! WHAT IS MUTATED IS THE GENOME, NOT THE BYTECODE. Byte-level mutation produces
//! mostly-malformed programs the verifier discards before any oracle sees them — the
//! denominator-zero trap one layer above the ones 0041-0050 kept finding, and the reason
//! 0054 built a typed walk in the first place. Perturbing genes keeps every mutant inside
//! the grammar.
//!
//! Coverage decides only what is KEPT; every program is still judged by the oracle whose
//! reference is not the verifier.

const SMOKE: &str = include_str!("fixtures/calibration/fuzz-smoke.log");

fn field(line: &str, key: &str) -> u64 {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key))
        .unwrap_or_else(|| panic!("no {key} in {line}"))
        .trim_end_matches(|c: char| !c.is_ascii_digit())
        .parse()
        .unwrap_or_else(|_| panic!("bad {key} in {line}"))
}

fn status_lines() -> Vec<&'static str> {
    SMOKE.lines().filter(|l| l.starts_with("STATUS ")).collect()
}

/// THE THROUGHPUT, which is the whole point of the leg.
///
/// Measured on a 240-second budget: ~456k programs loaded and ~3.6M return values compared
/// against the independent reference — roughly 1900 programs a second. The previous mode
/// managed 4096 programs a run.
#[test]
fn the_loop_runs_at_a_useful_rate() {
    let last = status_lines().last().copied().expect("status lines");
    let iters = field(last, "iters=");
    let elapsed = field(last, "elapsed=").max(1);
    let compared = field(last, "compared=");
    assert!(iters > 100_000, "only {iters} iterations");
    assert!(iters / elapsed > 500, "only {} programs/sec", iters / elapsed);
    assert!(compared > iters, "every accepted program must contribute several comparisons");
}

/// THE FEEDBACK ACTUALLY FEEDS BACK: coverage grows, and the corpus grows with it.
#[test]
fn coverage_and_corpus_both_grow() {
    let ss = status_lines();
    let first = ss.first().unwrap();
    let last = ss.last().unwrap();
    assert!(field(last, "seen_pcs=") > field(first, "seen_pcs="));
    assert!(field(last, "corpus=") > field(first, "corpus="));
    assert!(SMOKE.contains("CORPUS n=1 "), "the first keep must be recorded");
    // Monotone: the seen-set only grows and the corpus only grows.
    let mut pcs = 0;
    let mut corp = 0;
    for l in &ss {
        assert!(field(l, "seen_pcs=") >= pcs);
        assert!(field(l, "corpus=") >= corp);
        pcs = field(l, "seen_pcs=");
        corp = field(l, "corpus=");
    }
}

/// AND THE LIMIT THIS RUN EXPOSED, recorded rather than glossed.
///
/// Every one of 456k programs was ACCEPTED — the grammar emits pure scalar work with no
/// memory access whose bound must be proven, so the verifier never has to make a hard
/// decision and the whole rejection path is unreachable. Coverage plateaus accordingly:
/// 4509 PCs at two thousand iterations, 4789 at four hundred and fifty thousand.
///
/// The loop is not the bottleneck; the grammar's ceiling is. This test pins the ceiling so
/// that raising it is visible as a change in the number rather than an assertion.
#[test]
fn the_grammars_coverage_ceiling_is_the_current_limit() {
    let ss = status_lines();
    let last = ss.last().unwrap();
    assert_eq!(
        field(last, "reject="),
        0,
        "if this became non-zero the grammar gained a decision surface — re-measure the \
         ceiling below, it should have moved"
    );
    let early = field(ss[0], "seen_pcs=");
    let end = field(last, "seen_pcs=");
    assert!(
        end - early < 500,
        "coverage grew by {} after warm-up, which would mean the ceiling moved",
        end - early
    );
}

/// The run must refuse rather than degrade. Without KCOV this would still LOOK like
/// fuzzing while being a plain random walk.
#[test]
fn the_loop_refuses_to_run_without_feedback() {
    assert!(!SMOKE.contains("FUZZ abort"), "the smoke run aborted");
    assert!(SMOKE.contains("FUZZ start"), "no start line");
    assert!(SMOKE.contains("FUZZ done"), "the run did not finish cleanly");
}
