//! Stage 4 — DOCUMENTED-vs-OBSERVED DIFF.
//!
//! Compares observed verifier behavior (the NORMALIZED metrics) against ground
//! truth. This is classic logical analysis against documentation + patch diffs —
//! it is NOT a formal proof (see README, "not-a-proof").
//!
//! Two kinds of check:
//!   * INTRINSIC logical invariants — computed directly from CORE, no external
//!     file needed (the "classic logical analysis" pillar): tnum well-formedness,
//!     bound ordering, tnum/bounds consistency, JIT/interpreter equivalence.
//!   * SOURCE-BACKED — consult the injected [`GroundTruth`] oracle. Today that is
//!     the helper `arg_type` contract (source 3); verifier.c / verifier.rst /
//!     patch-diff queries are TODO (their loaders need a bpf-next tree).
//!
//! GUARDRAIL: `diff` STATES documented-vs-observed divergences; it does not rank,
//! score, or select. Findings carry NO severity — ranking is `score`'s job (which
//! `diff` never reads), and human triage owns the decision. Keeping `diff`
//! independent of the loop's own scores is part of the confirmation-bias guardrail:
//! the objective divergence record must not be shaped by what the loop expected.

use crate::groundtruth::GroundTruth;
use crate::normalize::{MetricRecord, NormalizedMetrics};
use contract::{Artifact, PeriodPaths, Producer};
use metrics::core::Tnum;
use serde::{Deserialize, Serialize};

/// Which ground-truth pillar a divergence was found against.
///
/// The four named external sources plus `logical_invariant` (the intrinsic
/// "classic logical analysis" pillar — no external file). Serializes snake_case;
/// the Python mirror must use the same strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundTruthSource {
    /// Source 1 — verifier.c state-transition logic (loader TODO).
    VerifierC,
    /// Source 2 — Documentation/bpf/verifier.rst (loader TODO).
    Documentation,
    /// Source 3 — helper bpf_func_proto / arg_type contracts.
    HelperProto,
    /// Source 4 — cross-version patch diffs (loader TODO).
    PatchDiff,
    /// Intrinsic logical invariant ("classic logical analysis"; no external file).
    LogicalInvariant,
}

/// One documented-vs-observed discrepancy.
///
/// Rich shape (FROZEN contract, mirrored in `python/.../schemas/diff.py`):
/// which record, which source, what was compared, and expected-vs-observed kept
/// separate so `report` can tabulate without re-parsing free text. Intentionally
/// carries no severity/score — `diff` states, `score` ranks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceFinding {
    /// Index into `NormalizedMetrics.records`, or `None` for a period-level finding.
    pub record_index: Option<u64>,
    /// Which ground-truth pillar this was found against.
    pub source: GroundTruthSource,
    /// Machine-ish label for the divergence kind, verbatim (e.g. "tnum_malformed").
    pub kind: String,
    /// What was compared: "tnum" | "bounds" | "jit_interp" | "helper_arg" | ...
    pub aspect: String,
    /// Documented / expected value (verbatim).
    pub expected: String,
    /// Observed value (verbatim).
    pub observed: String,
    /// Human-readable explanation for triage.
    pub detail: String,
}

/// Per-source finding counts (mirror of the [`GroundTruthSource`] variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct BySource {
    /// Findings against source 1.
    pub verifier_c: u64,
    /// Findings against source 2.
    pub documentation: u64,
    /// Findings against source 3.
    pub helper_proto: u64,
    /// Findings against source 4.
    pub patch_diff: u64,
    /// Findings against the intrinsic logical-invariant pillar.
    pub logical_invariant: u64,
}

impl BySource {
    fn bump(&mut self, source: GroundTruthSource) {
        match source {
            GroundTruthSource::VerifierC => self.verifier_c += 1,
            GroundTruthSource::Documentation => self.documentation += 1,
            GroundTruthSource::HelperProto => self.helper_proto += 1,
            GroundTruthSource::PatchDiff => self.patch_diff += 1,
            GroundTruthSource::LogicalInvariant => self.logical_invariant += 1,
        }
    }
}

/// Period-level diff summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Number of NORMALIZED records examined.
    pub record_count: u64,
    /// Total findings.
    pub finding_count: u64,
    /// Findings broken down by ground-truth source.
    pub by_source: BySource,
}

/// The DIFF_FINDINGS payload for a period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffFindings {
    /// Exec count N (carried through from NORMALIZED).
    pub exec_count: u64,
    /// All documented-vs-observed discrepancies.
    pub findings: Vec<DivergenceFinding>,
    /// Period-level summary.
    pub summary: DiffSummary,
}

/// Errors from the diff stage.
#[derive(Debug)]
pub enum DiffError {
    /// Failed to write the DIFF_FINDINGS contract artifact.
    Contract(contract::ContractError),
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffError::Contract(e) => write!(f, "diff contract error: {e}"),
        }
    }
}

impl std::error::Error for DiffError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DiffError::Contract(e) => Some(e),
        }
    }
}

impl From<contract::ContractError> for DiffError {
    fn from(e: contract::ContractError) -> Self {
        DiffError::Contract(e)
    }
}

/// Compare a period's NORMALIZED observation against ground truth and write the
/// DIFF_FINDINGS artifact.
///
/// Reads only the observation (never ANOMALY_SCORES — guardrail). Runs the
/// intrinsic logical-invariant checks over every record, plus the source-backed
/// helper-proto check via `ground_truth`.
pub fn run(
    period: &PeriodPaths,
    metrics: &NormalizedMetrics,
    ground_truth: &dyn GroundTruth,
) -> Result<DiffFindings, DiffError> {
    let mut findings = Vec::new();
    for (idx, record) in metrics.records.iter().enumerate() {
        let idx = idx as u64;
        check_logical_invariants(idx, record, &mut findings);
        check_helper_proto(idx, record, ground_truth, &mut findings);
        check_helper_observations(idx, record, ground_truth, &mut findings);
    }

    let mut by_source = BySource::default();
    for f in &findings {
        by_source.bump(f.source);
    }
    let summary = DiffSummary {
        record_count: metrics.records.len() as u64,
        finding_count: findings.len() as u64,
        by_source,
    };

    let out = DiffFindings {
        exec_count: metrics.exec_count,
        findings,
        summary,
    };

    // Write DIFF_FINDINGS (borrow the payload so we can return it after the block).
    {
        let artifact = Artifact::new(period.period_id, Producer::Diff, &out);
        contract::write_artifact(&period.diff_findings(), &artifact)?;
    }

    Ok(out)
}

/// Intrinsic "classic logical analysis": invariants that must hold for a sound
/// verifier, checkable straight from CORE with no external source.
fn check_logical_invariants(idx: u64, record: &MetricRecord, out: &mut Vec<DivergenceFinding>) {
    for snap in &record.core.register_evolution {
        for reg in &snap.regs {
            let where_ = format!("insn {} r{} ({})", snap.insn_idx, reg.reg, reg.reg_type);

            // tnum well-formedness: known bits (value) and unknown bits (mask) must
            // be disjoint. A bit that is both known-1 and unknown is a corrupt tnum.
            let overlap = reg.tnum.value & reg.tnum.mask;
            if overlap != 0 {
                out.push(DivergenceFinding {
                    record_index: Some(idx),
                    source: GroundTruthSource::LogicalInvariant,
                    kind: "tnum_malformed".to_string(),
                    aspect: "tnum".to_string(),
                    expected: "value & mask == 0".to_string(),
                    observed: format!(
                        "value=0x{:x} mask=0x{:x} overlap=0x{:x}",
                        reg.tnum.value, reg.tnum.mask, overlap
                    ),
                    detail: format!("{where_}: tnum known/unknown bits overlap"),
                });
            }

            // Bound ordering: an empty/inverted range is a contradiction.
            if reg.umin > reg.umax {
                out.push(DivergenceFinding {
                    record_index: Some(idx),
                    source: GroundTruthSource::LogicalInvariant,
                    kind: "unsigned_bounds_inverted".to_string(),
                    aspect: "bounds".to_string(),
                    expected: "umin <= umax".to_string(),
                    observed: format!("umin={} umax={}", reg.umin, reg.umax),
                    detail: format!("{where_}: inverted unsigned range"),
                });
            }
            if reg.smin > reg.smax {
                out.push(DivergenceFinding {
                    record_index: Some(idx),
                    source: GroundTruthSource::LogicalInvariant,
                    kind: "signed_bounds_inverted".to_string(),
                    aspect: "bounds".to_string(),
                    expected: "smin <= smax".to_string(),
                    observed: format!("smin={} smax={}", reg.smin, reg.smax),
                    detail: format!("{where_}: inverted signed range"),
                });
            }

            // tnum/bounds consistency: the tnum's representable range
            // [value, value|mask] must intersect [umin, umax]. Disjoint => the two
            // range trackers contradict each other (a range-desync logic bug).
            if reg.umin <= reg.umax {
                let (lo, hi) = tnum_unsigned_span(reg.tnum);
                if hi < reg.umin || lo > reg.umax {
                    out.push(DivergenceFinding {
                        record_index: Some(idx),
                        source: GroundTruthSource::LogicalInvariant,
                        kind: "tnum_bounds_inconsistent".to_string(),
                        aspect: "bounds".to_string(),
                        expected: "tnum span [value, value|mask] intersects [umin, umax]"
                            .to_string(),
                        observed: format!(
                            "tnum_span=[{lo},{hi}] umin={} umax={}",
                            reg.umin, reg.umax
                        ),
                        detail: format!("{where_}: tnum and unsigned bounds disjoint"),
                    });
                }
            }
        }
    }

    // JIT/interpreter equivalence: a verified program must execute identically
    // under the JIT and the interpreter. Any divergence is a soundness violation.
    if let Some(d) = &record.core.jit_interp_diff {
        if d.retval_jit != d.retval_interp || !d.data_out_equal {
            out.push(DivergenceFinding {
                record_index: Some(idx),
                source: GroundTruthSource::LogicalInvariant,
                kind: "jit_interp_divergence".to_string(),
                aspect: "jit_interp".to_string(),
                expected: "retval_jit == retval_interp && data_out_equal".to_string(),
                observed: format!(
                    "retval_jit={} retval_interp={} data_out_equal={}",
                    d.retval_jit, d.retval_interp, d.data_out_equal
                ),
                detail: "JIT and interpreter diverged on a verified program".to_string(),
            });
        }
    }
}

/// Source-backed check (source 3): corroborate the CORE `helper_arg_violation`
/// signal against the documented `arg_type` from the ground-truth oracle.
fn check_helper_proto(
    idx: u64,
    record: &MetricRecord,
    ground_truth: &dyn GroundTruth,
    out: &mut Vec<DivergenceFinding>,
) {
    for v in &record.core.helper_arg_violations {
        // Ask ground truth for the documented arg_type. `None` = not loaded, so we
        // cannot corroborate (real proto loader TODO) and stay silent here — the
        // CORE signal still stands and `score` still flags it.
        let Some(expected_gt) = ground_truth.helper_arg_type(&v.helper, v.arg_index) else {
            continue;
        };
        // Emit only when ground truth actually disagrees with what was observed.
        if expected_gt != v.observed {
            out.push(DivergenceFinding {
                record_index: Some(idx),
                source: GroundTruthSource::HelperProto,
                kind: "helper_arg_type_mismatch".to_string(),
                aspect: "helper_arg".to_string(),
                expected: expected_gt,
                observed: v.observed.clone(),
                detail: format!(
                    "{}(arg{}): observed arg_type disagrees with documented bpf_func_proto",
                    v.helper, v.arg_index
                ),
            });
        }
    }
}

/// Source-backed check (source 3, REAL path): compare each OBSERVED helper-arg
/// reg-type (from the verifier log) against the EXPECTED reg-type from the loaded
/// `bpf_func_proto` slice. The expected comes ONLY from ground truth — never from
/// CORE — so this decision is external, not pre-baked. `None` = slice doesn't
/// cover this arg (cannot corroborate; stay silent).
fn check_helper_observations(
    idx: u64,
    record: &MetricRecord,
    ground_truth: &dyn GroundTruth,
    out: &mut Vec<DivergenceFinding>,
) {
    for o in &record.core.helper_arg_observations {
        let Some(expected) = ground_truth.helper_arg_regtype(&o.helper, o.arg_index) else {
            continue;
        };
        if expected != o.observed {
            out.push(DivergenceFinding {
                record_index: Some(idx),
                source: GroundTruthSource::HelperProto,
                kind: "helper_arg_type_mismatch".to_string(),
                aspect: "helper_arg".to_string(),
                expected,
                observed: o.observed.clone(),
                detail: format!(
                    "{}(arg{}): observed reg-type disagrees with bpf_func_proto (ground truth)",
                    o.helper, o.arg_index
                ),
            });
        }
    }
}

/// The unsigned range a tnum can represent: `[value, value | mask]` (unknown bits
/// all 0 .. all 1).
fn tnum_unsigned_span(t: Tnum) -> (u64, u64) {
    (t.value, t.value | t.mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groundtruth::helper_proto::HelperProtoModel;
    use crate::groundtruth::{NoGroundTruth, StaticGroundTruth};
    use crate::normalize::MetricRecord;
    use metrics::core::{
        CoreMetrics, CoverageDelta, HelperArgViolation, JitInterpDiff, Processed, RegSnapshot,
        RegState, Tnum, VerifierDecision,
    };
    use metrics::counterfactual::CounterfactualLayer;
    use metrics::expectation::ExpectationFlag;
    use std::path::PathBuf;

    fn scratch_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "verifierloop-diff-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Build a record with one register snapshot and no jit/interp/helper signals.
    fn record_with_reg(reg: RegState) -> MetricRecord {
        MetricRecord {
            core: CoreMetrics {
                verifier_decision: VerifierDecision::Accept,
                register_evolution: vec![RegSnapshot {
                    insn_idx: 0,
                    regs: vec![reg],
                }],
                processed: Processed::default(),
                jit_interp_diff: None,
                coverage_delta: CoverageDelta::default(),
                helper_arg_observations: Vec::new(),
                helper_arg_violations: Vec::new(),
            },
            counterfactual: CounterfactualLayer::default(),
            expectation: ExpectationFlag::default(),
            parse_notes: Vec::new(),
        }
    }

    fn well_formed_reg() -> RegState {
        RegState {
            reg: 0,
            reg_type: "scalar".to_string(),
            tnum: Tnum { value: 0, mask: 0xff },
            umin: 0,
            umax: 255,
            smin: 0,
            smax: 255,
        }
    }

    fn metrics_of(records: Vec<MetricRecord>) -> NormalizedMetrics {
        NormalizedMetrics {
            exec_count: 100,
            records,
            unparsed: Vec::new(),
            derived: metrics::derived::DerivedMetrics {
                efficiency_per_exec: None,
                record_count: 0,
            },
        }
    }

    #[test]
    fn clean_observation_yields_no_findings() {
        let base = scratch_dir("clean");
        let period = PeriodPaths::new(&base.join("data"), 1);
        let m = metrics_of(vec![record_with_reg(well_formed_reg())]);

        let out = run(&period, &m, &NoGroundTruth).unwrap();
        assert_eq!(out.findings.len(), 0);
        assert_eq!(out.summary.record_count, 1);
        assert_eq!(out.summary.finding_count, 0);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn detects_malformed_tnum() {
        let base = scratch_dir("tnum");
        let period = PeriodPaths::new(&base.join("data"), 1);
        // value bit 0 is known-1 AND mask bit 0 is unknown => overlap = 1.
        let mut reg = well_formed_reg();
        reg.tnum = Tnum { value: 1, mask: 0xff };
        let m = metrics_of(vec![record_with_reg(reg)]);

        let out = run(&period, &m, &NoGroundTruth).unwrap();
        assert!(out
            .findings
            .iter()
            .any(|f| f.kind == "tnum_malformed" && f.source == GroundTruthSource::LogicalInvariant));
        assert_eq!(out.summary.by_source.logical_invariant, out.summary.finding_count);

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn detects_inverted_bounds() {
        let base = scratch_dir("bounds");
        let period = PeriodPaths::new(&base.join("data"), 1);
        let mut reg = well_formed_reg();
        reg.umin = 10;
        reg.umax = 5; // inverted
        let m = metrics_of(vec![record_with_reg(reg)]);

        let out = run(&period, &m, &NoGroundTruth).unwrap();
        assert!(out.findings.iter().any(|f| f.kind == "unsigned_bounds_inverted"));

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn detects_jit_interp_divergence() {
        let base = scratch_dir("jit");
        let period = PeriodPaths::new(&base.join("data"), 1);
        let mut rec = record_with_reg(well_formed_reg());
        rec.core.jit_interp_diff = Some(JitInterpDiff {
            retval_jit: 1,
            retval_interp: 0,
            data_out_equal: true,
        });
        let m = metrics_of(vec![rec]);

        let out = run(&period, &m, &NoGroundTruth).unwrap();
        assert!(out.findings.iter().any(|f| f.kind == "jit_interp_divergence"));

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn helper_proto_finding_needs_the_oracle() {
        let base = scratch_dir("helper");
        let period = PeriodPaths::new(&base.join("data"), 3);
        let mut rec = record_with_reg(well_formed_reg());
        rec.core.helper_arg_violations = vec![HelperArgViolation {
            helper: "bpf_map_lookup_elem".to_string(),
            arg_index: 1,
            expected: "PTR_TO_MAP_KEY".to_string(),
            observed: "SCALAR_VALUE".to_string(),
        }];
        let m = metrics_of(vec![rec]);

        // Without the oracle: cannot corroborate -> no helper_proto finding.
        let out_none = run(&period, &m, &NoGroundTruth).unwrap();
        assert!(!out_none
            .findings
            .iter()
            .any(|f| f.source == GroundTruthSource::HelperProto));

        // With a ground-truth proto table that disagrees with the observation.
        let gt = StaticGroundTruth::with_helper_proto(
            HelperProtoModel::new().with_contract("bpf_map_lookup_elem", 1, "PTR_TO_MAP_KEY"),
        );
        let out_gt = run(&period, &m, &gt).unwrap();
        let hit = out_gt
            .findings
            .iter()
            .find(|f| f.source == GroundTruthSource::HelperProto)
            .expect("helper_proto finding");
        assert_eq!(hit.kind, "helper_arg_type_mismatch");
        assert_eq!(hit.expected, "PTR_TO_MAP_KEY");
        assert_eq!(hit.observed, "SCALAR_VALUE");
        assert_eq!(out_gt.summary.by_source.helper_proto, 1);

        // The DIFF_FINDINGS artifact round-trips through the contract.
        let art: Artifact<DiffFindings> = contract::read_artifact(&period.diff_findings()).unwrap();
        assert_eq!(art.producer, Producer::Diff);
        assert_eq!(art.period_id, 3);
        assert_eq!(art.payload.summary.finding_count, out_gt.summary.finding_count);

        std::fs::remove_dir_all(&base).ok();
    }
}
