//! Targeted generation (devlog 0025) — does an aimed corpus actually buy the
//! detector anything a random one does not?
//!
//! The reviewer's diagnosis was that bug hunting is `oracle x input`, and that this
//! project had grown the oracle while the input stayed at ~241 executions on TCG.
//! The claim these tests pin is stronger and more specific than "more programs":
//! the committed syzkaller volume gives the intrinsic tnum-vs-bounds check
//! **literally nothing to check**, so that leg's "0 divergences" was 0 out of 0 —
//! an absence of evidence. The targeted corpus makes it 0 out of ~1500.
//!
//! Both halves are pinned. If a future parser change ever makes the syzkaller
//! corpus report checkable observations, or makes the targeted one stop reporting
//! them, that is a regression in the measurement itself and must fail loudly.

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;
use metrics::core::{RegState, Tnum};

/// The full enumerated family, captured in the bpf-next VM.
const TARGETED: &str = include_str!("fixtures/volume/gen-targeted-242.log");
/// The larger of the two syzkaller volume captures, for the contrast.
const SYZ: &str = include_str!("fixtures/volume/syz-replay-184.log");

fn run_diff(text: &str, tag: &str) -> (normalize::NormalizedMetrics, diff::DiffFindings) {
    let dir = std::env::temp_dir().join(format!("vl-gen-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("capture.log");
    std::fs::write(&src, text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("capture", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    (norm, out)
}

#[test]
fn the_targeted_corpus_gives_the_intrinsic_leg_a_real_denominator() {
    let (norm, out) = run_diff(TARGETED, "targeted");
    assert_eq!(norm.records.len(), 242, "the full enumerated family");
    assert!(
        out.summary.tnum_bounds_checked > 1000,
        "the aimed corpus must actually exercise the tnum-vs-bounds check; got {}",
        out.summary.tnum_bounds_checked
    );
    // And with that denominator, "0 findings" finally means something.
    assert_eq!(out.summary.finding_count, 0, "{:?}", out.findings);
}

#[test]
fn the_syzkaller_volume_gives_it_nothing_at_all() {
    // THE measurement of 0025, pinned. Not a defect in syzkaller: its programs are
    // syscall sequences, and their scalars are either fully known or fully unknown,
    // never partially known. A tnum tracker is never exercised by such a program, so
    // the strongest intrinsic check cannot fire on this corpus no matter how long it
    // runs.
    let (norm, out) = run_diff(SYZ, "syz");
    assert_eq!(norm.records.len(), 151);
    assert_eq!(
        out.summary.tnum_bounds_checked, 0,
        "if this ever becomes non-zero the corpus or the parser changed — re-measure \
         before trusting any 'clean' period from it"
    );
}

#[test]
fn the_targeted_corpus_is_fully_parsed() {
    // A corpus that buys checks is worthless if the parser cannot read it. The five
    // new state shapes (32-bit compares, arsh, div/mod, branch merges) must not open
    // a blind spot — the 0018 lesson.
    let (norm, _) = run_diff(TARGETED, "parse");
    let unrecognized = norm
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .count();
    assert_eq!(unrecognized, 0, "parser blind-spots in the targeted corpus");
    assert!(
        norm.records.iter().all(|r| r.parse_notes.is_empty()),
        "no lower-confidence records"
    );
}

#[test]
fn every_program_in_the_family_is_labelled_with_its_own_recipe() {
    // Reproducibility without a seed or a corpus file: the label names the exact
    // program, so a finding can be rebuilt from the report alone.
    let (norm, _) = run_diff(TARGETED, "labels");
    let labels: Vec<&str> = norm
        .records
        .iter()
        .filter_map(|r| r.source_label.as_deref())
        .collect();
    assert_eq!(labels.len(), 242, "every record carries its label");
    assert!(labels.contains(&"gen#w64.and.jeq#000"));
    assert!(labels.contains(&"gen#w32.mod.jset#241"));
    let mut sorted = labels.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), 242, "no two programs share a label");
}

// ---------------------------------------------------------------------------
// The denominator predicate itself — it decides what counts as evidence, so its
// exclusions are the part most worth testing.
// ---------------------------------------------------------------------------

fn reg(reg_type: &str, value: u64, mask: u64, umin: u64, umax: u64) -> RegState {
    RegState {
        reg: 0,
        reg_type: reg_type.to_string(),
        tnum: Tnum { value, mask },
        umin,
        umax,
        smin: 0,
        smax: 0,
    }
}

#[test]
fn a_constant_is_not_a_check_it_is_a_tautology() {
    // `R0=13` gives the parser ONE token from which it derives both the tnum and the
    // bounds. Comparing them compares 13 with 13; it cannot fail whatever the
    // verifier does, so counting it would manufacture a denominator out of nothing.
    assert!(!diff::tnum_bounds_checkable(&reg("scalar", 13, 0, 13, 13)));
}

#[test]
fn a_fully_unknown_scalar_cannot_contradict_anything() {
    // Spans the whole domain, so it intersects every bound range by construction.
    assert!(!diff::tnum_bounds_checkable(&reg("scalar", 0, u64::MAX, 0, u64::MAX)));
    // Even narrowed bounds cannot help while the tnum says "anything".
    assert!(!diff::tnum_bounds_checkable(&reg("scalar", 0, u64::MAX, 10, 20)));
}

#[test]
fn placeholder_pointer_registers_do_not_count() {
    // The parser stores zeros for ctx/fp/map_ptr; those are filler, not observations.
    assert!(!diff::tnum_bounds_checkable(&reg("ctx", 0, 0, 0, 0)));
    assert!(!diff::tnum_bounds_checkable(&reg("fp", 0, 0, 0, 0)));
}

#[test]
fn a_partially_known_scalar_with_real_bounds_is_the_thing_that_counts() {
    // Both trackers were printed by the verifier independently — this is the only
    // shape where they can be caught disagreeing.
    assert!(diff::tnum_bounds_checkable(&reg("scalar", 0, 0xff, 0, 255)));
    assert!(diff::tnum_bounds_checkable(&reg("scalar", 0x100, 0xff, 256, 511)));
}
