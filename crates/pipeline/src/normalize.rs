//! Stage 2 — NORMALIZE: shape harvested raw output into the metric schema.
//!
//! This is the ONLY place normalization happens. It reads the period's harvested
//! raw blobs (the UNCHANGED copies under `raw/`), interprets each via a
//! [`RecordParser`], and assembles [`NormalizedMetrics`] — CORE records plus the
//! opt-in COUNTERFACTUAL layer, the expectation flag, and period-level DERIVED.
//!
//! UNCHANGED-AT-SOURCE: parsers read raw bytes and never mutate them; shaping into
//! the schema is interpretation, done here and nowhere earlier.
//!
//! Real per-tool parsers (syzkaller verifier log, differential harness, KCOV)
//! depend on each tool's native format and are TODO — see [`UnimplementedParser`].
//! The parser is injected so the assembly/provenance/artifact logic is testable
//! now with a reference parser, and real parsers slot in later.

use crate::ingest::RawObservation;
use contract::{Artifact, PeriodPaths, Producer};
use metrics::core::CoreMetrics;
use metrics::counterfactual::CounterfactualLayer;
use metrics::derived::DerivedMetrics;
use metrics::expectation::ExpectationFlag;
use serde::{Deserialize, Serialize};

/// One normalized record: a CORE observation plus the opt-in counterfactual layer
/// and the expectation flag that sit ON TOP of it (never inside core).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricRecord {
    /// Raw CORE observation.
    pub core: CoreMetrics,
    /// Opt-in counterfactual layer (default OFF; never mutates `core`).
    pub counterfactual: CounterfactualLayer,
    /// Confirmation-bias probe (default NoPrediction).
    pub expectation: ExpectationFlag,
}

/// The NORMALIZED payload for a period: many CORE records + period-level derived.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NormalizedMetrics {
    /// Total exec count N (provenance carried from ingest).
    pub exec_count: u64,
    /// One record per verifier invocation parsed from the raw output.
    pub records: Vec<MetricRecord>,
    /// Period-level derived metrics.
    pub derived: DerivedMetrics,
}

/// Converts one tool's native output blob into zero or more CORE observations.
///
/// A parser reads raw bytes and does not mutate them; it only *interprets* them
/// into the schema.
pub trait RecordParser {
    /// Parse `bytes` (one collected file from `tool`) into CORE observations.
    fn parse(&self, tool: &str, bytes: &[u8]) -> Vec<CoreMetrics>;
}

/// Placeholder parser: yields no records. Swap in real per-tool parsers as their
/// native formats are wired up.
///
/// TODO(normalize): implement real parsers (syzkaller verifier log, differential
/// harness retvals, KCOV coverage). Until then this yields nothing.
pub struct UnimplementedParser;

impl RecordParser for UnimplementedParser {
    fn parse(&self, _tool: &str, _bytes: &[u8]) -> Vec<CoreMetrics> {
        Vec::new()
    }
}

/// Errors from the normalize stage.
#[derive(Debug)]
pub enum NormalizeError {
    /// Filesystem I/O failure (reading a harvested blob).
    Io(std::io::Error),
    /// Failed to write the NORMALIZED contract artifact.
    Contract(contract::ContractError),
}

impl std::fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NormalizeError::Io(e) => write!(f, "normalize i/o error: {e}"),
            NormalizeError::Contract(e) => write!(f, "normalize contract error: {e}"),
        }
    }
}

impl std::error::Error for NormalizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NormalizeError::Io(e) => Some(e),
            NormalizeError::Contract(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for NormalizeError {
    fn from(e: std::io::Error) -> Self {
        NormalizeError::Io(e)
    }
}

impl From<contract::ContractError> for NormalizeError {
    fn from(e: contract::ContractError) -> Self {
        NormalizeError::Contract(e)
    }
}

/// Normalize a period's harvested raw output into the metric schema and write the
/// NORMALIZED artifact.
///
/// Reads each entry's harvested copy under the period's `raw/` dir, dispatches it
/// to `parser`, wraps each CORE observation with a default (OFF) counterfactual
/// layer and a NoPrediction expectation flag, and stamps the exec counter N onto
/// any record that did not already carry it.
pub fn run(
    period: &PeriodPaths,
    raw: &RawObservation,
    parser: &dyn RecordParser,
) -> Result<NormalizedMetrics, NormalizeError> {
    let raw_root = period.artifact("raw");
    let mut records = Vec::new();

    for entry in &raw.entries {
        let path = raw_root.join(&entry.stored_path);
        let bytes = std::fs::read(&path)?;
        for mut core in parser.parse(&entry.tool, &bytes) {
            // Carry provenance: stamp exec counter N if the parser left it unset.
            if core.coverage_delta.exec_n == 0 {
                core.coverage_delta.exec_n = raw.exec_count;
            }
            records.push(MetricRecord {
                core,
                counterfactual: CounterfactualLayer::default(), // opt-in; OFF here
                expectation: ExpectationFlag::default(),         // NoPrediction
            });
        }
    }

    let derived = DerivedMetrics {
        // Report-only; needs more execs to be meaningful. TODO(derived).
        efficiency_per_exec: None,
        record_count: records.len() as u64,
    };

    let normalized = NormalizedMetrics {
        exec_count: raw.exec_count,
        records,
        derived,
    };

    // Write NORMALIZED (borrow the payload so we can return it after the block).
    {
        let artifact = Artifact::new(period.period_id, Producer::Normalize, &normalized);
        contract::write_artifact(&period.normalized(), &artifact)?;
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{self, Source};
    use metrics::core::{CoverageDelta, Processed, VerifierDecision};
    use metrics::expectation::Expectation;
    use std::path::PathBuf;

    /// A trivial reference parser for tests: each non-empty line is one record.
    /// Format: `accept` | `reject <reason>`. Proves the assembly logic without
    /// depending on any real tool's native format.
    struct LineParser;
    impl RecordParser for LineParser {
        fn parse(&self, _tool: &str, bytes: &[u8]) -> Vec<CoreMetrics> {
            String::from_utf8_lossy(bytes)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .map(|l| {
                    let mut it = l.split_whitespace();
                    let kind = it.next().unwrap_or("");
                    let decision = if kind == "accept" {
                        VerifierDecision::Accept
                    } else {
                        VerifierDecision::Reject {
                            reason: it.next().unwrap_or("unknown").to_string(),
                        }
                    };
                    CoreMetrics {
                        verifier_decision: decision,
                        register_evolution: Vec::new(),
                        processed: Processed::default(),
                        jit_interp_diff: None,
                        coverage_delta: CoverageDelta::default(),
                        helper_arg_violations: Vec::new(),
                    }
                })
                .collect()
        }
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "verifierloop-normalize-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn assembles_records_stamps_provenance_and_writes_artifact() {
        let base = scratch_dir("assemble");
        let out = base.join("verifier.log");
        std::fs::write(&out, b"accept\nreject bad_ptr\n").unwrap();

        let period = PeriodPaths::new(&base.join("data"), 1);
        let raw = ingest::run(&period, &[Source::new("syzkaller", &out)], 99).unwrap();

        let norm = run(&period, &raw, &LineParser).unwrap();

        assert_eq!(norm.exec_count, 99);
        assert_eq!(norm.records.len(), 2);
        assert_eq!(norm.derived.record_count, 2);

        // Provenance stamped onto each record.
        assert_eq!(norm.records[0].core.coverage_delta.exec_n, 99);
        // Decisions parsed.
        assert_eq!(norm.records[0].core.verifier_decision, VerifierDecision::Accept);
        assert_eq!(
            norm.records[1].core.verifier_decision,
            VerifierDecision::Reject { reason: "bad_ptr".into() }
        );
        // Counterfactual OFF, expectation NoPrediction (defaults on top of core).
        assert!(!norm.records[0].counterfactual.enabled);
        assert_eq!(norm.records[0].expectation.expected, Expectation::NoPrediction);

        // The NORMALIZED artifact round-trips through the contract.
        let art: Artifact<NormalizedMetrics> =
            contract::read_artifact(&period.normalized()).unwrap();
        assert_eq!(art.producer, Producer::Normalize);
        assert_eq!(art.period_id, 1);
        assert_eq!(art.payload.records.len(), 2);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn unimplemented_parser_yields_no_records() {
        let base = scratch_dir("unimpl");
        let out = base.join("blob.bin");
        std::fs::write(&out, b"whatever native bytes").unwrap();
        let period = PeriodPaths::new(&base.join("data"), 5);
        let raw = ingest::run(&period, &[Source::new("trinity", &out)], 3).unwrap();

        let norm = run(&period, &raw, &UnimplementedParser).unwrap();
        assert!(norm.records.is_empty());
        assert_eq!(norm.derived.record_count, 0);
        assert_eq!(norm.exec_count, 3);

        std::fs::remove_dir_all(&base).ok();
    }
}
