//! Parser blind-spot RATE on a real volume capture — the result metric, not a
//! process claim.
//!
//! A period's "0 divergences" is only trustworthy if the parser actually read the
//! data. This pins that on the real 95-block capture from replaying the syzkaller
//! corpus in the bpf-next VM (devlog 0018), and enforces the distinction that
//! makes the number readable:
//!
//!   blocks = records + unparsed
//!   unparsed = not_observed (verifier never ran)  +  unrecognized (PARSER FAILED)
//!
//! Only `unrecognized` measures the parser. `not_observed` is the data having
//! nothing to observe (loads rejected at the syscall boundary) and is expected at
//! volume — conflating the two makes a healthy parser look 26% broken.

use contract::PeriodPaths;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;

const VOLUME: &str = include_str!("fixtures/volume/syz-replay-95.log");

fn normalized(tag: &str) -> normalize::NormalizedMetrics {
    let dir = std::env::temp_dir().join(format!("vl-volume-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("diffharness.log");
    std::fs::write(&src, VOLUME).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("syzreplay", &src)], 95).unwrap();
    let n = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    n
}

#[test]
fn no_unrecognized_blocks_in_the_real_volume_capture() {
    let n = normalized("unrec");
    let unrecognized: Vec<_> = n
        .unparsed
        .iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized)
        .collect();
    assert!(
        unrecognized.is_empty(),
        "parser blind-spots on real volume data (must stay 0): {unrecognized:?}"
    );
}

#[test]
fn counts_reconcile_and_every_observable_block_became_a_record() {
    let n = normalized("reconcile");
    let blocks = VOLUME.lines().filter(|l| l.starts_with("===PROG ")).count();
    assert_eq!(blocks, 95, "the committed capture is the 95-block volume run");
    assert_eq!(
        n.records.len() + n.unparsed.len(),
        blocks,
        "blocks must reconcile: records + unparsed"
    );
    // Every block that carried verifier output produced a record.
    assert_eq!(n.records.len(), 70);
    assert_eq!(n.unparsed.len(), 25);
    assert!(
        n.unparsed.iter().all(|u| u.kind == UnparsedKind::NotObserved),
        "all 25 are 'verifier never ran', not parser failures"
    );
}

#[test]
fn parsed_records_are_mostly_caveat_free_and_reasons_are_real_text() {
    let n = normalized("caveats");
    let with_notes = n.records.iter().filter(|r| !r.parse_notes.is_empty()).count();
    // Volume-quality bar: caveats stay a small minority of parsed records.
    assert!(
        with_notes * 10 <= n.records.len(),
        "records with parse caveats should stay under 10%: {with_notes}/{}",
        n.records.len()
    );

    // The reject reasons must be real verifier text, not a fabricated placeholder.
    let mut unknown = 0;
    let mut distinct = std::collections::BTreeSet::new();
    for r in &n.records {
        if let metrics::core::VerifierDecision::Reject { reason } = &r.core.verifier_decision {
            if reason == "unknown" {
                unknown += 1;
            } else {
                distinct.insert(reason.clone());
            }
        }
    }
    assert!(
        distinct.len() >= 15,
        "volume should yield a wide spread of real reject texts, got {}",
        distinct.len()
    );
    // A few loads genuinely print no failure text; those are noted, not invented.
    assert!(unknown <= 5, "too many unidentified reject reasons: {unknown}");
}
