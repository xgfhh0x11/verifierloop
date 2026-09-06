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

/// THE CEILING, AND WHAT MOVES IT (devlog 0079, 0080).
///
/// 0078's version asserted `reject == 0` and said that if it ever became non-zero the
/// grammar had gained a decision surface and the ceiling should be re-measured. It has now
/// been re-measured twice, and the pattern is the point:
///
///     grammar                       coverage   rejections
///     scalar only (0078)             4789        0%
///     + map-value store (0079)       4942       23%
///     + var-offset stack (0080)      5188       39%
///
/// Each new KIND of memory adds roughly 150-250 PCs; more programs add none. The limit is
/// the number of distinct memory kinds the grammar can express, not the number of programs
/// it emits — which is why the next lift is packet pointers rather than a longer run.
///
/// The plateau is real rather than an artefact: `trunc=0` says no load ever filled the KCOV
/// buffer, so nothing was lost to truncation. Without that check "we plateaued" and "we
/// overflowed" would look identical.
///
/// NOTE the cost, recorded rather than hidden: rejections buy coverage and spend
/// throughput, because a rejected program never reaches the oracle. Comparisons fell from
/// 3.17M to 2.36M as rejections rose from 23% to 39%. There is a point past which more
/// decision surface stops paying, and this is the number that will show it.
#[test]
fn the_ceiling_is_set_by_memory_kinds_not_by_program_count() {
    let ss = status_lines();
    let last = ss.last().unwrap();
    let acc = field(last, "accept=");
    let rej = field(last, "reject=");
    assert!(rej > 0 && rej < acc, "two-sided decision surface: accept {acc}, reject {rej}");
    assert!(
        field(last, "seen_pcs=") > 5_100,
        "the ceiling should sit above the 4942 of the map-store grammar"
    );
    assert_eq!(
        field(last, "trunc="),
        0,
        "a load that filled the KCOV buffer lost coverage, and lost coverage looks exactly \
         like a plateau — the ceiling claim is only honest while this is zero"
    );
    // The corpus must keep growing too: a ceiling that rose without new keeps would mean
    // the coverage came from noise rather than from programs worth mutating.
    assert!(field(last, "corpus=") > 120, "corpus {}", field(last, "corpus="));
}

/// The run must refuse rather than degrade. Without KCOV this would still LOOK like
/// fuzzing while being a plain random walk.
#[test]
fn the_loop_refuses_to_run_without_feedback() {
    assert!(!SMOKE.contains("FUZZ abort"), "the smoke run aborted");
    assert!(SMOKE.contains("FUZZ start"), "no start line");
    assert!(SMOKE.contains("FUZZ done"), "the run did not finish cleanly");
}
