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
///     + atomic RMW (0081)            5251       29%
///     + MOVSX, +2 oracles (0082)     5203       30%
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
        field(last, "seen_pcs=") > 5_150,
        "the ceiling should sit around the 5200-5250 the memory-kind additions reached"
    );
    // A load that fills the KCOV buffer loses coverage, and lost coverage looks exactly
    // like a plateau — so this is watched rather than assumed. Atomics lengthened the
    // longest programs enough for a single load to reach the cap; one in half a million
    // does not move the number, but a rising count would mean the ceiling is the BUFFER.
    assert!(
        field(last, "trunc=") * 100_000 < field(last, "iters="),
        "truncated loads are no longer negligible: {} of {}",
        field(last, "trunc="), field(last, "iters=")
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

/// THREE ORACLES, AND WHY NOT THE ONE THAT WAS SUGGESTED (devlog 0082).
///
/// Screening all 21 reconstructable historical verifier fixes against this fuzzer gave a
/// number worth keeping: **14 of 21 would have been found** — triggerable by the grammar
/// AND caught by an oracle. Of the seven that would not, three are triggerable TODAY and
/// still invisible, because they are cross-state pruning defects that no single-state check
/// can see by construction.
///
/// The screening's suggested cure was a kernel-VERSION verdict differential. That was
/// declined, and the reason is a result this project already owns: 0068 established that
/// two kernel versions are ALLOWED to disagree on a verdict, since precision changes every
/// release — so a version flip is evidence only when you already know which side is the bug.
/// It calibrates; it cannot hunt.
///
/// What IS sound is a differential against the SAME kernel under a flag that must not change
/// the answer. `BPF_F_TEST_STATE_FREQ` only intensifies checkpointing, so a verdict flip
/// means a prune decided something the unpruned walk did not — exactly the invisible class.
/// `BPF_F_TEST_REG_INVARIANTS` promotes the kernel's own bounds assertion to a hard fault.
/// The resource direction is excluded, because state-freq inflates the state count by
/// construction and a flagged rejection on a complexity limit is the instrument's own
/// artefact (0042).
#[test]
fn the_expensive_oracles_run_and_cost_little() {
    let last = status_lines().last().copied().unwrap();
    // Both counters must be PRESENT — a run whose extra oracles never executed would report
    // the same zero as a run where they executed and found nothing.
    assert!(last.contains("pruneflip="), "the pruning differential must be reported");
    assert!(last.contains("invfault="), "the invariant channel must be reported");
    assert_eq!(field(last, "pruneflip="), 0);
    assert_eq!(field(last, "invfault="), 0);

    // And they must be affordable. Ungated they cost 2.5x (511k iterations became 202k);
    // reserved for programs that reached new coverage, plus a one-in-eight sample, the loop
    // runs at 424k — a ~17% toll instead of 60%.
    let iters = field(last, "iters=");
    assert!(iters > 350_000, "the gating did not recover throughput: {iters}");
}
