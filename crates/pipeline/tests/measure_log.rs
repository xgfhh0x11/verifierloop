//! Generic whole-capture measurement (run manually, not part of the suite).
//!
//! Reads a captured harness log from the MEASURE_LOG env var and runs the full pipeline
//! over it, printing records / reg32_checked / tnum_bounds_checked / finding_count and the
//! kind of any finding. Used to measure a family before it is pinned as a fixture+test.
//!
//!   MEASURE_LOG=.lab/harness-sync-out.log cargo test -p pipeline --test measure_log \
//!       -- --ignored --nocapture

use contract::PeriodPaths;
use pipeline::groundtruth::NoGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, UnparsedKind};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::diff;

#[test]
#[ignore = "manual: set MEASURE_LOG to a captured harness log"]
fn measure_whole_capture() {
    let path = match std::env::var("MEASURE_LOG") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("MEASURE: set MEASURE_LOG=<captured harness log>");
            return;
        }
    };
    let text = std::fs::read_to_string(&path).expect("read MEASURE_LOG");
    let dir = std::env::temp_dir().join(format!("vl-measure-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("c.log");
    std::fs::write(&src, &text).unwrap();
    let period = PeriodPaths::new(&dir.join("data"), 1);
    let raw = ingest::run(&period, &[Source::new("c", &src)], 1).unwrap();
    let norm = normalize::run(&period, &raw, &VerifierLogParser).unwrap();
    let out = diff::run(&period, &norm, &NoGroundTruth).unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    let accept = text.matches("decision=accept").count();
    let reject = text.matches("decision=reject").count();
    let unrecognized = norm.unparsed.iter()
        .filter(|u| u.kind == UnparsedKind::Unrecognized).count();

    eprintln!("MEASURE ==========================================");
    eprintln!("MEASURE records={} (accept={accept} reject={reject})", norm.records.len());
    eprintln!("MEASURE reg32_checked={}", out.summary.reg32_checked);
    eprintln!("MEASURE runtime_checked={}", out.summary.runtime_checked);
    eprintln!("MEASURE runtime_writes_checked={}", out.summary.runtime_writes_checked);
    eprintln!("MEASURE tnum_bounds_checked={}", out.summary.tnum_bounds_checked);
    eprintln!("MEASURE finding_count={}", out.summary.finding_count);
    eprintln!("MEASURE parser_unrecognized={unrecognized}");
    for f in &out.findings {
        eprintln!("MEASURE   finding kind={} detail={}", f.kind, f.detail);
    }
    eprintln!("MEASURE ==========================================");
}
