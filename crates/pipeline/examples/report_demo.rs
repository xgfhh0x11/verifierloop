//! Demo: the FULL period pipeline end to end, then the triaged PERIOD_REPORT.
//!   ingest -> normalize -> score (real Python) -> diff -> report
//!
//! Shows the human-in-the-loop batch: records ordered by anomaly score, each
//! joined with its documented-vs-observed divergences. Requires `python3`.
//!
//!   cargo run -p pipeline --example report_demo -- <base_dir>

use contract::{Artifact, PeriodPaths};
use metrics::core::{
    CoreMetrics, CoverageDelta, HelperArgViolation, JitInterpDiff, Processed, RegSnapshot,
    RegState, Tnum, VerifierDecision,
};
use pipeline::groundtruth::helper_proto::HelperProtoModel;
use pipeline::groundtruth::StaticGroundTruth;
use pipeline::ingest::{self, Source};
use pipeline::normalize::{self, RecordParser};
use pipeline::report::{self, PeriodReport};
use pipeline::{diff, score};
use std::fs;
use std::path::PathBuf;

/// `clean` -> well-formed accepted record; `buggy` -> malformed tnum + JIT/interp
/// divergence + a helper arg_type violation (trips diff and lifts the score).
struct DemoParser;
impl RecordParser for DemoParser {
    fn parse(&self, _tool: &str, bytes: &[u8]) -> Vec<CoreMetrics> {
        String::from_utf8_lossy(bytes)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let buggy = l.trim() == "buggy";
                CoreMetrics {
                    verifier_decision: VerifierDecision::Accept,
                    register_evolution: vec![RegSnapshot {
                        insn_idx: 0,
                        regs: vec![RegState {
                            reg: 0,
                            reg_type: "scalar".to_string(),
                            tnum: if buggy {
                                Tnum { value: 1, mask: 0xff }
                            } else {
                                Tnum { value: 0, mask: 0xff }
                            },
                            umin: 0,
                            umax: 255,
                            smin: 0,
                            smax: 255,
                        }],
                    }],
                    processed: Processed { insn_processed: 12, states_processed: 3 },
                    jit_interp_diff: Some(JitInterpDiff {
                        retval_jit: if buggy { 1 } else { 0 },
                        retval_interp: 0,
                        data_out_equal: true,
                    }),
                    coverage_delta: CoverageDelta::default(),
                    helper_arg_violations: if buggy {
                        vec![HelperArgViolation {
                            helper: "bpf_map_lookup_elem".to_string(),
                            arg_index: 1,
                            expected: "PTR_TO_MAP_KEY".to_string(),
                            observed: "SCALAR_VALUE".to_string(),
                        }]
                    } else {
                        Vec::new()
                    },
                }
            })
            .collect()
    }
}

fn main() {
    let base = PathBuf::from(std::env::args().nth(1).expect("usage: report_demo <base_dir>"));
    let out = base.join("verifier.log");
    fs::create_dir_all(&base).unwrap();
    fs::write(&out, b"clean\nbuggy\n").unwrap();

    let period = PeriodPaths::new(&base.join("data"), 1);

    // 1-2. ingest + normalize.
    let raw = ingest::run(&period, &[Source::new("syzkaller", &out)], 4200).expect("ingest");
    normalize::run(&period, &raw, &DemoParser).expect("normalize");

    // 3. score (real Python analyzer over the contract).
    let mut analyzer = score::PythonAnalyzer::new();
    if let Some(pp) = score::repo_pythonpath() {
        analyzer = analyzer.with_pythonpath(pp.display().to_string());
    }
    score::run(&period, &analyzer).expect("score");

    // 4. diff against ground truth (helper proto oracle + intrinsic invariants).
    let norm = contract::read_artifact::<normalize::NormalizedMetrics>(&period.normalized())
        .expect("read NORMALIZED")
        .payload;
    let gt = StaticGroundTruth::with_helper_proto(
        HelperProtoModel::new().with_contract("bpf_map_lookup_elem", 1, "PTR_TO_MAP_KEY"),
    );
    diff::run(&period, &norm, &gt).expect("diff");

    // 5. report: join score + diff into the triaged batch (timestamp = label only).
    let report = report::run(&period, Some(1_700_000_000)).expect("report");

    println!(
        "PERIOD REPORT  exec_count={}  records={}  flagged={}  divergences={}  top_score={}",
        report.exec_count,
        report.summary.record_count,
        report.summary.flagged,
        report.summary.divergence_count,
        report.summary.top_score,
    );
    println!("triage (score DESC):");
    for it in &report.items {
        println!(
            "  rec{} score={} reasons={:?} divergences={}",
            it.record_index,
            it.score,
            it.score_reasons,
            it.divergences.len()
        );
        for d in &it.divergences {
            println!("      - [{:?}] {} ({})", d.source, d.kind, d.aspect);
        }
    }
    if !report.period_findings.is_empty() {
        println!("period-level findings: {}", report.period_findings.len());
    }

    // Prove PERIOD_REPORT round-trips through the contract.
    let art: Artifact<PeriodReport> =
        contract::read_artifact(&period.period_report()).expect("read PERIOD_REPORT");
    assert_eq!(art.payload.items.len(), report.items.len());
    println!("period_report artifact: {}", period.period_report().display());
}
