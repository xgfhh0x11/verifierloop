//! Demo: REAL verifier data through the whole pipeline.
//!   diffharness native output
//!     -> ingest -> normalize(VerifierLogParser) -> score -> diff -> report
//!
//! Uses the committed authoritative bpf-next sample (harness/samples/bpf-next-sample.txt),
//! captured in-VM. It runs without root or a VM and demonstrates that real verifier
//! observations — including ranged/unknown-bit scalars — flow end to end AND produce
//! NO false anomalies (the real verifier's states are self-consistent), which is the
//! result. (Requires python3 for the score stage.)
//!
//!   cargo run -p pipeline --example harness_demo -- <base_dir>

use contract::{Artifact, PeriodPaths};
use pipeline::groundtruth::StaticGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::report::{self, PeriodReport};
use pipeline::verifier_log::VerifierLogParser;
use pipeline::{diff, normalize, score};
use std::fs;
use std::path::PathBuf;

// The real diffharness output, embedded at build time (skips leading `#` header).
const HARNESS_SAMPLE: &str = include_str!("../../../harness/samples/bpf-next-sample.txt");

fn main() {
    let base = PathBuf::from(std::env::args().nth(1).expect("usage: harness_demo <base_dir>"));
    fs::create_dir_all(&base).unwrap();
    let src = base.join("diffharness.log");
    fs::write(&src, HARNESS_SAMPLE).unwrap();

    let period = PeriodPaths::new(&base.join("data"), 1);

    // 1-2. ingest the harness output unchanged, then normalize with the REAL parser.
    let raw = ingest::run(&period, &[Source::new("diffharness", &src)], 1).expect("ingest");
    let norm = normalize::run(&period, &raw, &VerifierLogParser).expect("normalize");

    // 3. score (real Python analyzer over the contract).
    let mut analyzer = score::PythonAnalyzer::new();
    if let Some(pp) = score::repo_pythonpath() {
        analyzer = analyzer.with_pythonpath(pp.display().to_string());
    }
    score::run(&period, &analyzer).expect("score");

    // 4. diff against ground truth (empty oracle -> only intrinsic invariants run).
    diff::run(&period, &norm, &StaticGroundTruth::default()).expect("diff");

    // 5. report.
    let report = report::run(&period, Some(1_700_000_000)).expect("report");

    println!(
        "PERIOD REPORT  exec_count={}  records={}  flagged={}  divergences={}",
        report.exec_count,
        report.summary.record_count,
        report.summary.flagged,
        report.summary.divergence_count,
    );
    println!("real verifier observations (from diffharness):");
    for (i, rec) in norm.records.iter().enumerate() {
        let decision = match &rec.core.verifier_decision {
            metrics::core::VerifierDecision::Accept => "accept".to_string(),
            metrics::core::VerifierDecision::Reject { reason } => format!("reject: {reason}"),
        };
        println!(
            "  rec{i}: {decision}  insn_processed={}  reg_snapshots={}",
            rec.core.processed.insn_processed,
            rec.core.register_evolution.len(),
        );
    }
    println!("triage (score DESC):");
    if report.items.iter().all(|it| it.score == 0.0 && it.divergences.is_empty()) {
        println!("  (no anomalies — correct: clean + legitimately-rejected programs)");
    }
    for it in &report.items {
        if it.score > 0.0 || !it.divergences.is_empty() {
            println!("  rec{} score={} divergences={}", it.record_index, it.score, it.divergences.len());
        }
    }

    let art: Artifact<PeriodReport> =
        contract::read_artifact(&period.period_report()).expect("read PERIOD_REPORT");
    assert_eq!(art.payload.items.len(), report.items.len());
    println!("period_report: {}", period.period_report().display());
}
