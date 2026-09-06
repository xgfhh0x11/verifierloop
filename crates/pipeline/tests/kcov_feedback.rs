//! KCOV FEEDBACK — the measurement that decides whether coverage-guided generation is
//! possible at all (devlog 0077).
//!
//! The plan is to keep and mutate the programs that reach verifier code nothing has reached
//! yet. That only works if a program's load produces a DISTINGUISHING coverage signal. If
//! two different program shapes light up the same PCs, the feedback carries no information
//! and the idea is dead — so this was measured before anything was built on it.
//!
//! KCOV is per-task and excludes interrupts, so what it records across a `BPF_PROG_LOAD` is
//! essentially the verifier. `CONFIG_KCOV_INSTRUMENT_ALL` means every kernel function is
//! instrumented, so the absolute counts are large and heavily repeated (36k raw PCs dedup
//! to ~3.2k unique); what matters is whether the SETS differ between shapes.

const PROBE: &str = include_str!("fixtures/calibration/kcov-probe.log");

#[derive(Debug)]
struct Row {
    kind: u32,
    pcs: u64,
    new: u64,
    total: u64,
}

fn rows() -> Vec<Row> {
    PROBE
        .lines()
        .filter(|l| l.starts_with("KCOV prog="))
        .map(|l| {
            let f = |k: &str| -> u64 {
                l.split_whitespace()
                    .find_map(|t| t.strip_prefix(k))
                    .unwrap_or_else(|| panic!("no {k} in {l}"))
                    .parse()
                    .unwrap()
            };
            Row { kind: f("kind=") as u32, pcs: f("pcs="), new: f("new="), total: f("total_seen=") }
        })
        .collect()
}

/// THE DECIDING MEASUREMENT: different program shapes reach different amounts of verifier
/// code, by margins far larger than the run-to-run noise.
#[test]
fn coverage_actually_distinguishes_program_shapes() {
    let rs = rows();
    assert!(rs.len() >= 24, "probe truncated: {} rows", rs.len());

    // Per-shape PC counts, taken from the first appearance of each.
    let mut first: std::collections::BTreeMap<u32, u64> = Default::default();
    for r in &rs {
        first.entry(r.kind).or_insert(r.pcs);
    }
    assert!(first.len() >= 6, "the probe must exercise several distinct shapes");
    let lo = *first.values().min().unwrap();
    let hi = *first.values().max().unwrap();
    assert!(
        hi > lo + 10_000,
        "the shapes must differ by far more than the run-to-run noise: {first:?}"
    );

    // Run-to-run noise on the SAME shape, for contrast: repeats of one shape stay within a
    // few hundred PCs of each other, two orders below the between-shape spread.
    let same: Vec<u64> = rs.iter().filter(|r| r.kind == 0).map(|r| r.pcs).collect();
    let spread = same.iter().max().unwrap() - same.iter().min().unwrap();
    assert!(spread < 1_000, "same-shape spread {spread} is too large to call the rest signal");
}

/// AND IT SATURATES, which is what makes "new coverage" a usable trigger rather than noise.
///
/// Each shape contributes new PCs the first time it appears and essentially none
/// afterwards. A feedback loop keyed on "did this program reach anything new" therefore
/// fires rarely and meaningfully — the property the whole design rests on.
#[test]
fn new_coverage_is_a_rare_signal_not_a_constant_drip() {
    let rs = rows();
    let n = rs.len();
    let firsts: u64 = rs.iter().take(6).map(|r| r.new).sum();
    let later: u64 = rs.iter().skip(12).map(|r| r.new).sum();
    assert!(firsts > 3_000, "the first pass must discover the bulk: {firsts}");
    assert!(
        later * 20 < firsts,
        "after warm-up new coverage must nearly stop, or the signal is noise: \
         first six {firsts}, last {} rows {later}",
        n - 12
    );
    // And the running total is monotone — the set only grows.
    let mut prev = 0;
    for r in &rs {
        assert!(r.total >= prev, "seen-set shrank: {r:?}");
        prev = r.total;
    }
}

/// The probe must have actually run. A kernel without KCOV, or a VM without debugfs
/// mounted, prints an unavailability line instead — and reading that as "no coverage
/// variation" would be the wrong conclusion entirely.
#[test]
fn the_probe_reports_unavailability_rather_than_silently_measuring_nothing() {
    assert!(!PROBE.contains("KCOV unavailable"), "KCOV was not reachable in the VM");
    assert!(PROBE.contains("verdict=accept"), "no program was actually loaded");
    assert!(PROBE.contains("verdict=reject"), "the rejecting shape must be exercised too");
}
