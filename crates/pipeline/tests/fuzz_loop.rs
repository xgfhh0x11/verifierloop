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

/// THE CEILING, RAISED AND RE-MEASURED (devlog 0079).
///
/// 0078's version of this test asserted `reject == 0` and said: "if this became non-zero
/// the grammar gained a decision surface — re-measure the ceiling below, it should have
/// moved." It did, so this is that re-measurement.
///
/// The grammar gained a store through a map value whose bound the verifier must PROVE.
/// That is the difference between a program the verifier waves through and one it has to
/// decide about, and it opened check_mem_access and the pointer-bounds refinement around
/// it. Rejections went from none at all to roughly a quarter of everything emitted, and the
/// coverage plateau moved 4789 -> 4942 PCs.
///
/// The plateau is REAL, not an artefact: `trunc=0` says no load ever filled the KCOV
/// buffer, so nothing was lost to truncation. What limits coverage now is still the
/// grammar — fourteen step kinds over three scalar registers, one pointer and one map — and
/// the next lift is more KINDS of memory, not more programs.
#[test]
fn the_decision_surface_is_live_and_the_ceiling_moved() {
    let ss = status_lines();
    let last = ss.last().unwrap();
    let acc = field(last, "accept=");
    let rej = field(last, "reject=");
    assert!(rej > 0, "the grammar must be able to produce a rejection at all");
    assert!(
        rej * 10 > acc && rej < acc,
        "the decision surface must be genuinely two-sided, not a token minority or a \
         majority: accept {acc}, reject {rej}"
    );
    assert!(
        field(last, "seen_pcs=") > 4_900,
        "the ceiling should sit above the pre-store plateau of 4789"
    );
    assert_eq!(
        field(last, "trunc="),
        0,
        "a load that filled the KCOV buffer lost coverage, and lost coverage looks exactly \
         like a plateau — the ceiling claim is only honest while this is zero"
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
