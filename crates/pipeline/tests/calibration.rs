//! CALIBRATION AGAINST A REAL VERIFIER BUG (devlog 0061).
//!
//! Every leg so far proved its oracle fires on a violation WE PLANTED. None ever proved
//! one fires on a bug the kernel actually had. Without that, eighteen legs of "clean" are
//! ambiguous: either bpf-next is sound on these surfaces, or our oracle has a blind spot.
//! This test removes the ambiguity for one bug class.
//!
//! THE BUG. Commit 3844d153a41a, "bpf: Fix insufficient bounds propagation from
//! adjust_scalar_min_max_vals" (2022-07-01), reported by Kuee K1r0a:
//!
//!   "a corner case where the tnum becomes constant after the call to
//!    __reg_bound_offset(), but the register's bounds are not, that is, its min bounds
//!    are still not equal to the register's max bounds. This in turn allows to LEAK
//!    POINTERS through turning a pointer register as is into an unknown scalar via
//!    adjust_ptr_min_max_vals()."
//!
//! It is a soundness bug, not an over-rejection, and its signature is precisely the
//! property this project has been checking for thirty legs. The two fixtures are the
//! kernel's OWN printed state, quoted verbatim from the commit's "Before:" and "After:"
//! logs — the differing line is the one the commit marks `<--- [*]`:
//!
//!   before:  9: (07) r3 += -32767  ; R3_w=scalar(imm=0,umax=1,var_off=(0x0; 0x0))
//!   after:   9: (07) r3 += -32767  ; R3_w=scalar(imm=0,umax=0,var_off=(0x0; 0x0))
//!
//! WHAT CALIBRATION FOUND, before any kernel was rebuilt — two blind spots, either of
//! which alone made the oracle unable to see this bug:
//!
//!   1. The parser did not accept the `R<n>_w=` register form that older kernels print,
//!      so NOTHING parsed and the denominator went silently to zero — `tnum_bounds_checked
//!      = 0` with `parser_unrecognized = 0`. The exact failure shape the denominator rule
//!      exists to catch, arriving from a new direction.
//!   2. The tnum-vs-bounds invariant only tested that the tnum's span INTERSECTS
//!      [umin, umax]. For the buggy state the span is [0,0] and the bounds are [0,1] —
//!      they intersect, so the check stayed silent even once the state parsed. The
//!      missing property is the stronger one the kernel checks itself under the same
//!      name: a CONSTANT tnum must PIN the bounds.
//!
//! Both are fixed, and this test keeps them fixed.

use contract::PeriodPaths;
use pipeline::diff;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const BUGGY: &str = include_str!("fixtures/calibration/cve-3844d153a41a-buggy.log");
const FIXED: &str = include_str!("fixtures/calibration/cve-3844d153a41a-fixed.log");

/// The second pair, and a different KIND of calibration: captured by running the kernel
/// that had the bug, not quoted from a commit message. See the module note below.
const FR_BUGGY: &str = include_str!("fixtures/calibration/fakereg-92424801261d-buggy.log");
const FR_FIXED: &str = include_str!("fixtures/calibration/fakereg-92424801261d-fixed.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-cal-{}-{tag}", std::process::id()));
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

/// THE HEADLINE: the oracle catches a real verifier soundness bug, at the exact
/// instruction the fix commit marks.
#[test]
fn the_oracle_catches_the_real_bug() {
    let (_, out) = run_diff(BUGGY, "buggy");
    let hits: Vec<_> = out
        .findings
        .iter()
        .filter(|f| f.kind == "const_tnum_range_mismatch")
        .collect();
    assert_eq!(
        hits.len(), 1,
        "the state the buggy verifier printed must fire exactly once: {:?}", out.findings
    );
    assert!(
        hits[0].detail.contains("insn 9") && hits[0].detail.contains("r3"),
        "and at the instruction the commit marks with [*]: {}", hits[0].detail
    );
}

/// AND THE OTHER HALF: it does not fire on the fixed state. A check that fires on both
/// would prove nothing at all.
#[test]
fn the_oracle_stays_silent_on_the_fix() {
    let (_, out) = run_diff(FIXED, "fixed");
    assert_eq!(
        out.summary.finding_count, 0,
        "the corrected state is consistent and must not be reported: {:?}", out.findings
    );
}

/// The first blind spot, pinned: an older kernel's `R<n>_w=` form must parse, or the
/// denominator silently goes to zero and a calibration run reports a meaningless clean.
#[test]
fn the_older_register_form_parses_instead_of_silently_vanishing() {
    assert!(BUGGY.contains("R3_w="), "the fixture must use the older form");
    let (norm, out) = run_diff(BUGGY, "wform");
    assert!(
        out.summary.tnum_bounds_checked > 0,
        "a zero denominator here is the silent failure this test exists to prevent"
    );
    let states: usize = norm
        .records
        .iter()
        .flat_map(|r| r.core.register_evolution.iter())
        .map(|s| s.regs.len())
        .sum();
    assert!(states > 0, "no register state parsed at all");
    let blind: Vec<_> = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(blind.is_empty(), "parser blind-spots: {blind:?}");
}

/// The second blind spot, pinned as a property rather than a fixture: intersecting the
/// bounds is not enough, because the buggy tnum span [0,0] sits inside [0,1].
#[test]
fn intersecting_the_bounds_is_not_enough_to_catch_it() {
    use metrics::core::{RegState, Tnum};
    let buggy = RegState {
        reg: 3,
        reg_type: "scalar".to_string(),
        tnum: Tnum { value: 0, mask: 0 },
        umin: 0,
        umax: 1,
        ..Default::default()
    };
    // The old test: does the tnum span meet the bounds? It does — which is exactly why
    // the intersection check could never have caught this bug.
    let (lo, hi) = (buggy.tnum.value, buggy.tnum.value | buggy.tnum.mask);
    assert!(
        !(hi < buggy.umin || lo > buggy.umax),
        "the spans intersect, so a disjointness test stays silent on the real bug"
    );
    // The property that does catch it.
    assert!(
        buggy.umin != buggy.tnum.value || buggy.umax != buggy.tnum.value,
        "a constant tnum must pin both bounds"
    );
}

// ---------------------------------------------------------------------------------
// SECOND PAIR: 92424801261d, "bpf: Fix reg_set_min_max corruption of fake_reg" (2024-06)
//
// A different kind of calibration, and the reason it is worth the cost of a kernel build.
// The first pair could be read straight out of a commit message because the inconsistent
// state was printed as ordinary register state. This one cannot: the violating registers
// (true_reg2, false_reg1, false_reg2) live inside reg_set_min_max and are never printed
// that way — they appear only inside the kernel's own "REG INVARIANTS VIOLATION" message.
//
// So the detection channel is not a parsed state but a VERDICT: 0042's third load, where
// BPF_F_TEST_REG_INVARIANTS turns reg_bounds_sanity_check from warn-and-recover into a
// hard -EFAULT. Both fixtures are real captures — the same probe run against two kernels
// built from the same config, differing only in whether the fix is applied.
//
// HONEST SCOPE: this validates the REG_INVARIANTS channel end to end. It does NOT show
// that our parsed-state invariants would catch this bug — they cannot, because the
// corrupt registers are never printed as state. Two bugs, two channels; neither result
// transfers to the other.

fn accepted_and_inv(text: &str) -> (bool, String) {
    let line = text.lines().find(|l| l.starts_with("PRUNE ")).expect("a PRUNE line");
    let f = |k: &str| {
        line.split_whitespace()
            .find_map(|t| t.strip_prefix(k))
            .unwrap()
            .to_string()
    };
    (f("base_verdict=") == "accept", f("inv_reason="))
}

/// THE FIRING HALF, on the kernel that actually had the bug: the default load succeeds
/// while the REG_INVARIANTS load faults, and the pipeline turns that into a finding.
#[test]
fn the_instrument_catches_the_fake_reg_corruption_on_the_buggy_kernel() {
    let (base_ok, inv) = accepted_and_inv(FR_BUGGY);
    assert!(base_ok, "the buggy kernel accepts the program by default");
    assert_eq!(inv, "efault", "and faults under BPF_F_TEST_REG_INVARIANTS");
    assert!(
        FR_BUGGY.contains("REG INVARIANTS VIOLATION"),
        "the kernel says so itself, which is what makes this capture self-evidencing"
    );
    let (_, out) = run_diff(FR_BUGGY, "fr-buggy");
    assert_eq!(
        out.findings.iter().filter(|f| f.kind == "reg_invariants_violation").count(), 1,
        "and the pipeline must report it exactly once: {:?}", out.findings
    );
}

/// THE SILENT HALF, on the fixed kernel: same probe, same config, only the fix differs.
#[test]
fn the_instrument_is_silent_on_the_fixed_kernel() {
    let (base_ok, inv) = accepted_and_inv(FR_FIXED);
    assert!(base_ok);
    assert_eq!(inv, "none", "no fault once the fix is in");
    assert!(!FR_FIXED.contains("REG INVARIANTS VIOLATION"));
    let (_, out) = run_diff(FR_FIXED, "fr-fixed");
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

/// The kernel's own diagnosis, pinned: the two properties it names are the two this
/// project checks under different names, which is why the channel is worth having.
#[test]
fn the_kernels_own_violation_names_our_two_invariants() {
    assert!(
        FR_BUGGY.contains("range bounds violation"),
        "an inverted unsigned range — our unsigned_bounds_inverted"
    );
    assert!(
        FR_BUGGY.contains("const tnum out of sync with range bounds"),
        "a constant tnum that does not pin its bounds — our const_tnum_range_mismatch, \
         the very property 0061 had to ADD"
    );
}

