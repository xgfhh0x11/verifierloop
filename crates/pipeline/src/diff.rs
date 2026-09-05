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
use metrics::core::{RegState, Tnum, VerifierDecision};
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

/// One piece of QUALIFIED EVIDENCE — an observation that bears on a possible
/// divergence without being one.
///
/// Same shape as [`DivergenceFinding`], deliberately a DIFFERENT type in a
/// DIFFERENT channel, because it carries a different claim. A note says "here is a
/// fact a reviewer should weigh"; a finding says "the kernel and its ground truth
/// disagree". Notes are NOT counted in `finding_count`, so a period with notes and
/// no findings still reads as clean — which is the honest reading when the only
/// thing that differed was a reworded error string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceNote {
    /// Index into `NormalizedMetrics.records`, or `None` for a period-level note.
    pub record_index: Option<u64>,
    /// Which ground-truth pillar the evidence came from.
    pub source: GroundTruthSource,
    /// Machine-ish label, verbatim (e.g. "documented_message_drift").
    pub kind: String,
    /// What was compared: "reject_reason" | ...
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
    /// Helper-arg observations seen across all records (any decision).
    pub helper_args_observed: u64,
    /// Documented-behaviour cases (source 2) actually compared this period — the
    /// same denominator logic as `helper_args_checked`.
    #[serde(default)]
    pub documented_cases_checked: u64,
    /// Of those, how many the helper check actually COMPARED against ground truth
    /// (accepted programs only, and only args the loaded `bpf_func_proto` slice
    /// covers). This is the DENOMINATOR that makes "0 helper findings"
    /// interpretable: 0 out of many checks means the programs were sound; 0 out of
    /// ZERO checks means the leg never ran and proves nothing.
    #[serde(default)]
    pub helper_args_checked: u64,
    /// Evidence notes emitted this period. Reported next to `finding_count`, never
    /// folded into it: evidence is not a verdict.
    #[serde(default)]
    pub note_count: u64,
    /// Register observations the tnum-vs-bounds check could actually EVALUATE —
    /// the intrinsic leg's missing denominator.
    ///
    /// Sources 2 and 3 have reported their denominators since 0016/0022, but the
    /// intrinsic leg never did, and that hid something: measured 2026-09-01, the
    /// entire committed syzkaller volume (221 records) contains **zero** such
    /// observations, because its programs never produce a partially-known scalar.
    /// So this leg's "0 findings" was 0 out of 0 — no evidence at all — while
    /// reading exactly like the other legs' 0 out of many. Reported now so that can
    /// never happen silently again.
    #[serde(default)]
    pub tnum_bounds_checked: u64,
    /// Register observations where the 32-bit subregister view carried INDEPENDENT
    /// information about the 64-bit one — the denominator for the 32<->64 checks.
    ///
    /// Same discipline as `tnum_bounds_checked`: the verifier often prints the two
    /// views as one shared token (`umax=umax32=255`), and comparing a value with
    /// itself cannot fail. Only observations where the two views actually SAY
    /// something different are counted.
    #[serde(default)]
    pub reg32_checked: u64,
    /// Runtime ground-truth samples (BPF_PROG_TEST_RUN retvals) actually compared
    /// against the verifier's proven bound on the return register. The denominator
    /// for the runtime oracle — the ONLY leg that does not trust the verifier log
    /// to be internally consistent.
    #[serde(default)]
    pub runtime_checked: u64,
    /// Store samples (BPF_PROG_TEST_RUN + map read-back) checked for memory safety:
    /// an accepted store must land INSIDE the map value. The denominator for the
    /// runtime memory-safety oracle.
    #[serde(default)]
    pub runtime_writes_checked: u64,
    /// Runtime store observations the STORE-LOCATION check could evaluate — the
    /// denominator that makes "0 location findings" mean something. Distinct from
    /// `runtime_writes_checked`, which only asks whether the store stayed inside
    /// the object; this one asks whether it landed where the verifier PROVED it
    /// could, which is a strictly stronger question.
    #[serde(default)]
    pub store_locations_checked: u64,
    /// Pruning differentials the check could actually EVALUATE — the denominator for
    /// the kernel-vs-kernel leg. A pair only counts once it is known that the flag
    /// CHANGED the state space (`freq_states > base_states`); if the flagged load
    /// explored no more states than the default, nothing was pruned differently and
    /// agreement between the two proves nothing.
    #[serde(default)]
    pub prune_pairs_checked: u64,
    /// Differentials that flipped in the RESOURCE direction (flagged rejects, default
    /// accepts, and the flagged rejection is a complexity limit). Reported next to
    /// the findings, never folded into them: state-freq inflates the state count by
    /// construction, so this direction is an expected artefact of the instrument.
    #[serde(default)]
    pub prune_resource_artifacts: u64,
}

/// The DIFF_FINDINGS payload for a period.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffFindings {
    /// Exec count N (carried through from NORMALIZED).
    pub exec_count: u64,
    /// All documented-vs-observed discrepancies.
    pub findings: Vec<DivergenceFinding>,
    /// Qualified evidence that is explicitly NOT a verdict. `skip_serializing_if`
    /// keeps existing golden artifacts byte-identical when there is none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<EvidenceNote>,
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
    let mut notes = Vec::new();
    let mut helper_args_observed = 0u64;
    let mut helper_args_checked = 0u64;
    let mut documented_cases_checked = 0u64;
    let mut tnum_bounds_checked = 0u64;
    let mut reg32_checked = 0u64;
    let mut runtime_checked = 0u64;
    let mut runtime_writes_checked = 0u64;
    let mut store_locations_checked = 0u64;
    let mut prune_pairs_checked = 0u64;
    let mut prune_resource_artifacts = 0u64;
    for (idx, record) in metrics.records.iter().enumerate() {
        let idx = idx as u64;
        helper_args_observed += record.core.helper_arg_observations.len() as u64;
        check_logical_invariants(idx, record, &mut findings, &mut tnum_bounds_checked);
        check_subregister_invariants(idx, record, &mut findings, &mut reg32_checked);
        check_runtime_ground_truth(idx, record, &mut findings, &mut runtime_checked);
        check_runtime_write_safety(idx, record, &mut findings, &mut runtime_writes_checked);
        check_store_location(idx, record, &mut findings, &mut store_locations_checked);
        check_prune_differential(
            idx,
            record,
            &mut findings,
            &mut prune_pairs_checked,
            &mut prune_resource_artifacts,
        );
        check_helper_proto(idx, record, ground_truth, &mut findings);
        check_helper_observations(
            idx,
            record,
            ground_truth,
            &mut findings,
            &mut helper_args_checked,
        );
        if check_documented_behavior(idx, record, ground_truth, &mut findings, &mut notes) {
            documented_cases_checked += 1;
        }
    }

    let mut by_source = BySource::default();
    for f in &findings {
        by_source.bump(f.source);
    }
    let summary = DiffSummary {
        record_count: metrics.records.len() as u64,
        finding_count: findings.len() as u64,
        by_source,
        helper_args_observed,
        helper_args_checked,
        documented_cases_checked,
        note_count: notes.len() as u64,
        tnum_bounds_checked,
        reg32_checked,
        runtime_checked,
        runtime_writes_checked,
        store_locations_checked,
        prune_pairs_checked,
        prune_resource_artifacts,
    };

    let out = DiffFindings {
        exec_count: metrics.exec_count,
        findings,
        notes,
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
fn check_logical_invariants(
    idx: u64,
    record: &MetricRecord,
    out: &mut Vec<DivergenceFinding>,
    checkable: &mut u64,
) {
    for snap in &record.core.register_evolution {
        for reg in &snap.regs {
            let where_ = format!("insn {} r{} ({})", snap.insn_idx, reg.reg, reg.reg_type);
            if tnum_bounds_checkable(reg) {
                *checkable += 1;
            }

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
    checked: &mut u64,
) {
    // ACCEPTED PROGRAMS ONLY. On a rejected program a helper arg-type mismatch is
    // the verifier doing its job — agreement with ground truth, not divergence.
    // The bug-hunting signal is the opposite: a program the verifier ACCEPTED even
    // though an argument violates its documented `bpf_func_proto` contract.
    // (Volume made this concrete: rejected programs routinely carry mismatched
    // arg types, which is exactly why they were rejected.)
    if !matches!(record.core.verifier_decision, VerifierDecision::Accept) {
        return;
    }
    for o in &record.core.helper_arg_observations {
        let Some(expected) = ground_truth.helper_arg_regtype(&o.helper, o.arg_index) else {
            continue; // slice does not cover this arg -> cannot corroborate
        };
        *checked += 1; // a real comparison against ground truth happened
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

/// Source-backed check (source 2): compare the OBSERVED verifier decision against
/// what `Documentation/bpf/verifier.rst` says about this exact program.
///
/// This is the documented-vs-observed axis proper: intrinsic invariants check the
/// verifier against itself and helper contracts check one argument, but only the
/// documentation states end-to-end behaviour ("this program is rejected"). A
/// mismatch means the kernel and its own documentation disagree — either the
/// verifier regressed or the documentation is stale; both are findings worth a
/// human. Returns whether a comparison was actually performed (the denominator).
fn check_documented_behavior(
    idx: u64,
    record: &MetricRecord,
    ground_truth: &dyn GroundTruth,
    out: &mut Vec<DivergenceFinding>,
    notes: &mut Vec<EvidenceNote>,
) -> bool {
    let Some(label) = record.source_label.as_deref() else {
        return false;
    };
    let Some(documented) = ground_truth.documented_outcome(label) else {
        return false; // no documented claim for this program (or its anchor drifted)
    };
    let observed_accept = matches!(record.core.verifier_decision, VerifierDecision::Accept);
    let documented_accept = matches!(
        documented,
        crate::groundtruth::verifier_rst::DocumentedOutcome::Accept
    );
    if observed_accept != documented_accept {
        let (expected, observed) = if documented_accept {
            ("accept".to_string(), "reject".to_string())
        } else {
            ("reject".to_string(), "accept".to_string())
        };
        out.push(DivergenceFinding {
            record_index: Some(idx),
            source: GroundTruthSource::Documentation,
            kind: "documented_behavior_mismatch".to_string(),
            aspect: "decision".to_string(),
            expected,
            observed,
            detail: match ground_truth.doc_staleness_evidence() {
                // Source 4 qualifies source 2: the first triage question about a
                // documented divergence is "regression, or stale prose?" — answer it
                // with git facts up front instead of leaving it to be asked.
                Some(ev) => format!(
                    "{label}: verifier decision disagrees with Documentation/bpf/verifier.rst \
                     — {ev}"
                ),
                None => format!(
                    "{label}: verifier decision disagrees with Documentation/bpf/verifier.rst"
                ),
            },
        });
        return true;
    }

    // The decision matched. The document may also print the exact error string it
    // expects — but that is deliberately NOT held to the same standard. Error text
    // is reworded constantly (`'imm'` became `'scalar'`, `invalid stack off=` grew
    // a register name), so a mismatch here says "the documentation has drifted",
    // not "the verifier is wrong". It is recorded as evidence a reviewer can weigh,
    // and it does not touch `finding_count`.
    if let (Some(expected_error), VerifierDecision::Reject { reason }) = (
        ground_truth.documented_expected_error(label),
        &record.core.verifier_decision,
    ) {
        if !reason.contains(&expected_error) {
            notes.push(EvidenceNote {
                record_index: Some(idx),
                source: GroundTruthSource::Documentation,
                kind: "documented_message_drift".to_string(),
                aspect: "reject_reason".to_string(),
                expected: expected_error,
                observed: reason.clone(),
                detail: format!(
                    "{label}: rejected as documented, but the verifier's message differs                      from the one Documentation/bpf/verifier.rst prints — evidence of                      documentation drift, NOT a verifier divergence"
                ),
            });
        }
    }
    true
}

/// Whether the 32-bit view of this register is INDEPENDENT information.
///
/// The verifier prints the two views collapsed into one token whenever they agree
/// (`smax=umax=smax32=umax32=255`), so a register whose 32-bit endpoints simply
/// equal the low half of its 64-bit endpoints tells us nothing new — comparing them
/// compares a value with itself, the same tautology `tnum_bounds_checkable` excludes
/// for constants. It only becomes a check when the two views diverge, or when the
/// 64-bit range spans more than one 2^32 block (there the 32-bit view constrains
/// something the 64-bit endpoints alone do not).
/// (Runtime memory safety) An accepted store is CLAIMED in-bounds, so on a sound
/// kernel the sentinel it writes MUST land inside the map value. The harness zeroes
/// the target map, runs the program, reads it back, and reports where the sentinel
/// landed (`store_off`) — or that it was ABSENT (`Some(-1)`), meaning the store went
/// out of the readable value into kernel memory: an OOB write the verifier accepted.
/// This needs NO bound parsing — it is the direct memory-safety property.
/// STORE-LOCATION DESYNC — the strictly stronger memory-safety question.
///
/// Every earlier runtime-write leg (0037/0038/0039) asks only "did the store stay
/// INSIDE the object?". A verifier can pass that and still be wrong: if its abstract
/// arithmetic for the offset is unsound, the store lands at an offset its own state
/// says is IMPOSSIBLE, yet still inside the object — the "consistent-but-wrong"
/// class no internal-consistency invariant can see, because the verifier's two views
/// agree with each other and only disagree with reality.
///
/// So this check compares the observed landing site against the verifier's OWN claim
/// at the store instruction:
///
///   proven window = ptr_off + insn_off + [umin, umax], narrowed by var_off's tnum
///
/// A store outside that window is a desync between what the verifier proved and what
/// the machine did. The tnum half matters as much as the interval: `r6 &= 3; r6 <<= 2`
/// proves offsets {0,4,8,12} — an offset of 6 is inside [0,12] and still impossible.
///
/// Provenance: which instruction stores, through which register, comes from the
/// GENERATOR (`store_site`), never from the verifier's own disassembly — the oracle
/// must not learn the question from the component it is auditing. The pointer state
/// is taken from the snapshot at that instruction BEFORE it executes: that is the
/// state on which the verifier based its authorization.
///
/// Silence is the honest answer when no claim is available: a non-pointer base, a
/// missing snapshot, or a state whose bounds the verifier did not print (a var_off
/// with unknown bits but no `umax=`) are all SKIPPED rather than guessed, so the
/// denominator never counts a comparison that did not happen.
fn check_store_location(
    idx: u64,
    record: &MetricRecord,
    out: &mut Vec<DivergenceFinding>,
    checked: &mut u64,
) {
    let site = match record.core.store_site {
        Some(s) => s,
        None => return,
    };
    // A store instruction reached on SEVERAL paths has several proven states, and the
    // verifier prints one per path. Taking the first is wrong in exactly the way 0036
    // already fixed for the retval channel: the reference must be the UNION over every
    // claim at that instruction. A union is a conservative superset, so it can only MISS
    // a violation, never fabricate one — and fabricate one is precisely what the
    // first-match version did on the first multi-path family (`--gen-idpart`, where one
    // path proves r9 in [0,7] and the other r9 = r6 + 4 in [4,11]).
    let claims: Vec<&metrics::core::RegState> = record
        .core
        .register_evolution
        .iter()
        .filter(|snap| snap.insn_idx == site.insn_idx)
        .filter_map(|snap| snap.regs.iter().find(|r| r.reg == site.base_reg))
        .filter(|p| p.reg_type != "scalar")
        // A pointer with unknown bits but NO stated upper bound is not a usable claim:
        // the interval half says nothing, so there is no window to test against. (When
        // the mask is 0 the variable part is a known constant and the tnum alone pins
        // the landing site exactly, so that case stays checkable.)
        .filter(|p| !(p.tnum.mask != 0 && p.umax == u64::MAX))
        .filter(|p| p.umin <= p.umax)
        .collect();
    let ptr = match claims.first() {
        Some(p) => *p, // used only for the reported window of the first claim
        None => return, // no usable pointer state at the store: nothing was proven
    };
    let base = ptr.ptr_off.unwrap_or(0) + site.insn_off;
    let lo = base.saturating_add(ptr.umin as i64);
    let hi = base.saturating_add(ptr.umax as i64);

    for smp in &record.core.runtime_samples {
        let off = match smp.store_off {
            Some(o) if !smp.error && o >= 0 => o,
            // An absent sentinel is an OOB write, which check_runtime_write_safety
            // already reports; re-reporting it here would double-count one event.
            _ => continue,
        };
        *checked += 1;
        // The store is where the verifier said IF ANY of the claims at this instruction
        // admits it — the program only ever takes one path per run, and we cannot tell
        // from the sentinel alone which one it was.
        let admitted = claims.iter().any(|p| admits(p, site.insn_off, off));
        if admitted {
            continue;
        }
        // Reported against the FIRST claim; `admits` above already decided against all
        // of them. An unstated upper bound is not an endpoint, so it is not reported as
        // one either.
        let in_window = off >= lo && (ptr.umax == u64::MAX || off <= hi);
        let why = if !in_window {
            if ptr.umax == u64::MAX {
                format!("below the proven base {lo}")
            } else {
                format!("outside the proven window [{lo}, {hi}]")
            }
        } else {
            format!(
                "inside [{lo}, {hi}] but impossible under var_off=(0x{:x}; 0x{:x})",
                ptr.tnum.value, ptr.tnum.mask
            )
        };
        out.push(DivergenceFinding {
            record_index: Some(idx),
            source: GroundTruthSource::LogicalInvariant,
            kind: "store_location_desync".to_string(),
            aspect: "runtime".to_string(),
            expected: format!(
                "a store through R{} at insn {} lands in {} + [{}, {}] with var_off=(0x{:x}; 0x{:x})",
                site.base_reg, site.insn_idx, base, ptr.umin, ptr.umax,
                ptr.tnum.value, ptr.tnum.mask
            ),
            observed: format!(
                "input=0x{:x}: the store landed at {off} — {why}{}",
                smp.input,
                if claims.len() > 1 {
                    format!(" (and outside all {} claims at this insn)", claims.len())
                } else {
                    String::new()
                }
            ),
            detail: "the verifier accepted a store that landed where its own proven pointer state says it could not"
                .to_string(),
        });
    }
}

/// (Kernel vs kernel) Compare the SAME program's verdict with and without
/// `BPF_F_TEST_STATE_FREQ`, which forces a verifier checkpoint at every instruction
/// instead of the default "at least 2 jumps and 8 instructions" heuristic
/// (`states.c`: `force_new_state = env->test_state_freq || ...`). The flag makes
/// pruning MORE aggressive, not less: `regsafe`/`states_equal` are handed far more
/// candidate pairs to judge.
///
/// Nothing here is a bound we parsed or a value we computed — both sides of the
/// comparison are the kernel's own verdict — so this leg has no oracle of ours that
/// can be wrong. That also makes it the first detector aimed at state pruning, the
/// densest historical bug region and one no internal-consistency or runtime-value
/// oracle can reach.
///
/// THE PREDICATE IS DIRECTIONAL, and that matters more than it looks:
///   * flagged ACCEPT + default REJECT — the extra checkpoints let the verifier prune
///     away a path that produced the rejection. Only an UNSOUND `regsafe` can do
///     that, so this is the finding.
///   * flagged REJECT + default ACCEPT — the extra checkpoints inflate the state
///     count, so `BPF_COMPLEXITY_LIMIT_INSNS` ("BPF program is too large", -E2BIG) or
///     the states limit can reject a program the default run accepts. That is an
///     artefact of the instrument, counted separately and never as a finding. A
///     reject in this direction that is NOT a resource limit is a real disagreement
///     and is reported as one — an over-rejection is still the verifier contradicting
///     itself, just not the soundness half.
///
/// The denominator only counts a pair once the flag DEMONSTRABLY changed the state
/// space (`freq_states > base_states`). Agreement between two runs that explored the
/// same states is not evidence about pruning; it is evidence that nothing was tried.
fn check_prune_differential(
    idx: u64,
    record: &MetricRecord,
    out: &mut Vec<DivergenceFinding>,
    checked: &mut u64,
    artifacts: &mut u64,
) {
    let p = match &record.core.prune_probe {
        Some(p) => p,
        None => return,
    };
    // The kernel's OWN bounds sanity check (reg_bounds_sanity_check), promoted from
    // warn-and-recover to a hard -EFAULT. This is independent of the pruning
    // question, and it is checked even when the flag changed nothing: an EFAULT here
    // is the verifier reporting an internal inconsistency about ITSELF.
    if p.inv_reason == "efault" && p.base_accept {
        out.push(DivergenceFinding {
            record_index: Some(idx),
            source: GroundTruthSource::LogicalInvariant,
            kind: "reg_invariants_violation".to_string(),
            aspect: "bounds".to_string(),
            expected: "a program the verifier accepts also passes its own reg_bounds_sanity_check"
                .to_string(),
            observed: format!(
                "accepted by default, -EFAULT under BPF_F_TEST_REG_INVARIANTS (errno={})",
                p.inv_errno
            ),
            detail: "the kernel's own register-bounds invariant fired on a program it otherwise accepts"
                .to_string(),
        });
    }
    if p.freq_states <= p.base_states {
        return; // the flag changed nothing here: this pair proves nothing either way
    }
    *checked += 1;
    if p.base_accept == p.freq_accept {
        return;
    }
    if p.freq_accept && !p.base_accept {
        // The soundness direction.
        out.push(DivergenceFinding {
            record_index: Some(idx),
            source: GroundTruthSource::LogicalInvariant,
            kind: "prune_soundness_desync".to_string(),
            aspect: "pruning".to_string(),
            expected: "a program's verdict does not depend on how often the verifier checkpoints"
                .to_string(),
            observed: format!(
                "fall={} taken={} (fall_safe={} taken_safe={}, stack={}): rejected by default                  ({} states) but ACCEPTED with BPF_F_TEST_STATE_FREQ ({} states)",
                p.fall, p.taken, p.fall_safe, p.taken_safe, p.stack,
                p.base_states, p.freq_states
            ),
            detail: "extra checkpoints let the verifier prune away the path that produced the rejection"
                .to_string(),
        });
        return;
    }
    // The reverse direction: classify before counting.
    if p.freq_reason == "too_large" || p.freq_reason == "too_many_states" {
        *artifacts += 1;
        return;
    }
    out.push(DivergenceFinding {
        record_index: Some(idx),
        source: GroundTruthSource::LogicalInvariant,
        kind: "prune_verdict_disagreement".to_string(),
        aspect: "pruning".to_string(),
        expected: "a program's verdict does not depend on how often the verifier checkpoints"
            .to_string(),
        observed: format!(
            "fall={} taken={}: accepted by default ({} states) but REJECTED with \
             BPF_F_TEST_STATE_FREQ ({} states, reason={}, errno={})",
            p.fall, p.taken, p.base_states, p.freq_states, p.freq_reason, p.freq_errno
        ),
        detail: "the flagged run rejected for a reason that is not a complexity limit — an over-rejection, not the soundness half"
            .to_string(),
    });
}

/// Does one printed pointer claim admit a store landing at absolute offset `off`?
///
/// The comparison runs on the VARIABLE part `v = off - (ptr_off + insn_off)` and stays in
/// u64 throughout, which matters: an absent `umax` means U64_MAX by the log's convention,
/// and `u64::MAX as i64` is -1, so adding it to the base produced an INVERTED window
/// (`[40, 39]`) that rejected every landing site. An unstated upper bound constrains
/// nothing; it is not an endpoint. When the tnum mask is 0 the variable part is pinned
/// exactly and the tnum test alone decides.
fn admits(p: &metrics::core::RegState, insn_off: i64, off: i64) -> bool {
    let base = p.ptr_off.unwrap_or(0) + insn_off;
    let v = match off.checked_sub(base) {
        Some(v) if v >= 0 => v as u64,
        _ => return false,
    };
    let fits_tnum = (v & !p.tnum.mask) == p.tnum.value;
    let in_interval = v >= p.umin && (p.umax == u64::MAX || v <= p.umax);
    fits_tnum && in_interval
}

fn check_runtime_write_safety(
    idx: u64,
    record: &MetricRecord,
    out: &mut Vec<DivergenceFinding>,
    checked: &mut u64,
) {
    for smp in &record.core.runtime_samples {
        let off = match smp.store_off {
            Some(o) if !smp.error => o,
            _ => continue,
        };
        // A run that never REACHED the store has nothing to judge: `store_off = none`
        // there means "the branch skipped it", not "the bytes went out of bounds".
        // Only the harness families whose store sits behind a branch report this
        // witness at all, and only `Some(false)` skips — an unconditional store still
        // reports nothing (`None`) and keeps the original reading, so the teeth on
        // --gen-rtw / --gen-rtw2 / --gen-pktw are untouched. Judging a skipped run
        // would report a memory-safety violation for a store that never happened.
        if smp.executed == Some(false) {
            continue;
        }
        *checked += 1;
        // A store is memory-safe iff its base landed inside the value (off >= 0) AND,
        // for a multi-byte store (--gen-rtw2), the full run landed inside it
        // (store_len == store_size). `map_or(true)` keeps the single-byte --gen-rtw
        // family — which reports presence via store_off alone and emits no size —
        // passing on presence. A short run (store_len < store_size) is a PARTIAL OOB
        // write: some sentinel bytes fell outside the value even though the base did
        // not — exactly the `off + size <= value_size` off-by-one this family targets.
        let full_run = smp
            .store_len
            .zip(smp.store_size)
            .map_or(true, |(l, s)| l == s);
        if off < 0 || !full_run {
            let observed = if off < 0 {
                format!("input=0x{:x}: sentinel absent — store landed out of bounds", smp.input)
            } else {
                format!(
                    "input=0x{:x}: sentinel run {} of {} bytes — store crossed the value end",
                    smp.input,
                    smp.store_len.unwrap_or(0),
                    smp.store_size.unwrap_or(0),
                )
            };
            out.push(DivergenceFinding {
                record_index: Some(idx),
                source: GroundTruthSource::LogicalInvariant,
                kind: "runtime_oob_write".to_string(),
                aspect: "runtime".to_string(),
                expected: "an accepted store lands entirely inside the map value".to_string(),
                observed,
                detail: "the verifier accepted a program whose runtime store escaped the map value"
                    .to_string(),
            });
        }
    }
}

/// (Runtime ground truth) Compare each BPF_PROG_TEST_RUN sample's ACTUAL retval
/// against the verifier's own proven bound on the return register (r0). A retval
/// outside the bound means the verifier accepted a program whose runtime return
/// value escaped what it proved — a soundness bug caught WITHOUT trusting the
/// verifier log to be self-consistent (the "consistent-but-wrong" blind spot the
/// tnum/reg32 legs share). The reference bound is the UNION of r0's scalar bounds
/// over every snapshot: a conservative superset of the true per-exit bound, so a
/// too-wide union can only MISS a violation, never fabricate one. retval is the
/// low 32 bits, so the 64-bit leg is only sound when the bound fits in 32 bits
/// (a wider bound is skipped, not guessed); the 32-bit-view leg always applies.
fn check_runtime_ground_truth(
    idx: u64,
    record: &MetricRecord,
    out: &mut Vec<DivergenceFinding>,
    checked: &mut u64,
) {
    if record.core.runtime_samples.is_empty() {
        return;
    }
    let mut any = false;
    let mut last_insn = 0u32;
    let (mut umin, mut umax) = (u64::MAX, 0u64);
    let (mut u32lo, mut u32hi) = (u64::MAX, 0u64);
    let mut have32 = false;
    for snap in &record.core.register_evolution {
        for reg in &snap.regs {
            if reg.reg != 0 || reg.reg_type != "scalar" {
                continue;
            }
            any = true;
            last_insn = last_insn.max(snap.insn_idx);
            umin = umin.min(reg.umin);
            umax = umax.max(reg.umax);
            if let (Some(a), Some(b)) = (reg.u32_min, reg.u32_max) {
                have32 = true;
                u32lo = u32lo.min(a);
                u32hi = u32hi.max(b);
            }
        }
    }
    let check64 = any && umax <= u32::MAX as u64;
    if !check64 && !have32 {
        // No 32-bit-meaningful bound to compare a (32-bit) retval against.
        return;
    }
    for smp in &record.core.runtime_samples {
        if smp.error || smp.store_off.is_some() {
            continue; // store samples are checked by check_runtime_write_safety
        }
        *checked += 1;
        let rv = smp.retval & 0xffff_ffff;
        let viol64 = check64 && (rv < umin || rv > umax);
        let viol32 = have32 && (rv < u32lo || rv > u32hi);
        if viol64 || viol32 {
            let (elo, ehi) = if viol32 { (u32lo, u32hi) } else { (umin, umax) };
            out.push(DivergenceFinding {
                record_index: Some(idx),
                source: GroundTruthSource::LogicalInvariant,
                kind: "runtime_bound_violation".to_string(),
                aspect: "runtime".to_string(),
                expected: format!("retval in [{elo},{ehi}] (verifier's proven r0 bound)"),
                observed: format!("input=0x{:x} retval={rv} (0x{rv:x})", smp.input),
                detail: format!(
                    "r0 up to insn {last_insn}: runtime return value escaped the \
                     verifier's proven bound"
                ),
            });
        }
    }
}

pub fn reg32_checkable(reg: &RegState) -> bool {
    if reg.reg_type != "scalar" {
        return false;
    }
    let (lo32, hi32) = reg32_unsigned(reg);
    // A full 32-bit range says nothing and can contradict nothing.
    if lo32 == 0 && hi32 == u32::MAX as u64 {
        return false;
    }
    lo32 != (reg.umin & 0xffff_ffff)
        || hi32 != (reg.umax & 0xffff_ffff)
        || (reg.umin >> 32) != (reg.umax >> 32)
}

/// The 32-bit unsigned range, resolving an omitted bound to its extreme.
///
/// `kernel/bpf/log.c:print_scalar_ranges()` omits a bound that sits at its extreme,
/// so an absent `umin32=` means 0 and an absent `umax32=` means `U32_MAX`. The
/// PARSER keeps the silence (`None`); the interpretation lives here, next to the
/// check that depends on it.
fn reg32_unsigned(reg: &RegState) -> (u64, u64) {
    (
        reg.u32_min.unwrap_or(0),
        reg.u32_max.unwrap_or(u32::MAX as u64),
    )
}

/// Intrinsic checks on the 32-bit subregister view (devlog 0026).
///
/// The verifier tracks a scalar twice — as a 64-bit value and as its 32-bit
/// subregister — and `reg_bounds_sync()` has to keep the two reconciled. A
/// disagreement between them is a soundness-relevant bug class neither view can
/// reveal alone, and historically the densest one in the verifier's range tracking.
///
/// Every check below is an OVER-APPROXIMATION INTERSECTION: each tracker
/// independently over-approximates the same non-empty set of reachable values, so
/// any two of them must intersect. An empty intersection is a contradiction the
/// verifier produced against itself — no external ground truth needed.
fn check_subregister_invariants(
    idx: u64,
    record: &MetricRecord,
    out: &mut Vec<DivergenceFinding>,
    checked: &mut u64,
) {
    for snap in &record.core.register_evolution {
        for reg in &snap.regs {
            if reg.reg_type != "scalar" {
                continue;
            }
            let (u32min, u32max) = reg32_unsigned(reg);
            let where_ = format!("insn {} r{} ({})", snap.insn_idx, reg.reg, reg.reg_type);

            // (A) Ordering. An inverted 32-bit range denotes the empty set — a
            // contradiction on its own, independent of the 64-bit view.
            if u32min > u32max {
                out.push(DivergenceFinding {
                    record_index: Some(idx),
                    source: GroundTruthSource::LogicalInvariant,
                    kind: "u32_bounds_inverted".to_string(),
                    aspect: "bounds32".to_string(),
                    expected: "u32_min <= u32_max".to_string(),
                    observed: format!("u32_min={u32min} u32_max={u32max}"),
                    detail: format!("{where_}: inverted 32-bit unsigned range"),
                });
            }
            // Omitted signed bounds resolve to the extremes, which can never be
            // inverted — so this fires only on values the verifier actually printed.
            let s32min = reg.s32_min.unwrap_or(i32::MIN as i64);
            let s32max = reg.s32_max.unwrap_or(i32::MAX as i64);
            {
                let (a, b) = (s32min, s32max);
                if a > b {
                    out.push(DivergenceFinding {
                        record_index: Some(idx),
                        source: GroundTruthSource::LogicalInvariant,
                        kind: "s32_bounds_inverted".to_string(),
                        aspect: "bounds32".to_string(),
                        expected: "s32_min <= s32_max".to_string(),
                        observed: format!("s32_min={a} s32_max={b}"),
                        detail: format!("{where_}: inverted 32-bit signed range"),
                    });
                }
            }

            if !reg32_checkable(reg) {
                continue;
            }
            *checked += 1;

            // (B) The tnum's low 32 bits vs the 32-bit range: both describe the same
            // set of reachable low halves, from different trackers.
            let tlo = reg.tnum.value & 0xffff_ffff;
            let thi = (reg.tnum.value | reg.tnum.mask) & 0xffff_ffff;
            if thi < u32min || tlo > u32max {
                out.push(DivergenceFinding {
                    record_index: Some(idx),
                    source: GroundTruthSource::LogicalInvariant,
                    kind: "tnum32_bounds_inconsistent".to_string(),
                    aspect: "bounds32".to_string(),
                    expected: "tnum low-32 span intersects [u32_min, u32_max]".to_string(),
                    observed: format!("tnum32_span=[{tlo},{thi}] u32=[{u32min},{u32max}]"),
                    detail: format!("{where_}: tnum and 32-bit bounds disjoint"),
                });
            }

            // (C) 64-bit range vs 32-bit range. Sound ONLY while the 64-bit range is
            // confined to one 2^32 block: then every value shares an upper half and
            // its low half must fall in the window the 64-bit endpoints cut. Across
            // a block boundary the low half wraps and the 64-bit endpoints constrain
            // nothing, so the check is SKIPPED there rather than guessed.
            if (reg.umin >> 32) == (reg.umax >> 32) {
                let wlo = reg.umin & 0xffff_ffff;
                let whi = reg.umax & 0xffff_ffff;
                if whi < u32min || wlo > u32max {
                    out.push(DivergenceFinding {
                        record_index: Some(idx),
                        source: GroundTruthSource::LogicalInvariant,
                        kind: "reg32_reg64_inconsistent".to_string(),
                        aspect: "bounds32".to_string(),
                        expected: "64-bit low-half window intersects [u32_min, u32_max]"
                            .to_string(),
                        observed: format!(
                            "low_half_window=[{wlo},{whi}] u32=[{u32min},{u32max}] \
                             (umin={} umax={})",
                            reg.umin, reg.umax
                        ),
                        detail: format!("{where_}: 32-bit and 64-bit views disagree"),
                    });
                }
            }
        }
    }
}

/// Whether the tnum-vs-bounds consistency check has INDEPENDENT information about
/// this register — i.e. whether it could possibly fire.
///
/// Three exclusions, each of which would otherwise inflate the denominator with
/// something that can never produce a finding:
///
/// 1. **Non-scalar registers.** The parser stores placeholder zeros for pointer /
///    ctx / fp registers (see `build_regstate`). Those are filler, not observations.
/// 2. **A fully-unknown tnum, or un-narrowed bounds.** The check fires when the
///    tnum's span and the bound range are DISJOINT. A fully-unknown tnum spans
///    everything and an un-narrowed range contains everything, so either one alone
///    makes the intersection non-empty by construction.
/// 3. **Constants — and this one is subtle.** For `R0=13` the parser derives BOTH
///    the tnum (`{13, mask 0}`) and the bounds (`umin=umax=13`) from the SAME token.
///    Comparing them therefore compares a value with itself: the check is a
///    tautology there and cannot fail no matter what the verifier does. Counting
///    those would manufacture a denominator out of nothing — which is precisely the
///    error this field exists to prevent. So a register only counts when the
///    verifier printed a genuinely partial `var_off=` alongside real bounds, making
///    the two trackers independently observed.
///
/// The predicate deliberately UNDER-counts (a `var_off=(0xd; 0x0)` printed next to
/// bounds is independent information but is indistinguishable from a const once
/// parsed). Under-counting makes "0 findings" read weaker than it is, which is the
/// safe direction to be wrong in.
pub fn tnum_bounds_checkable(reg: &RegState) -> bool {
    reg.reg_type == "scalar"
        && reg.tnum.mask != 0
        && reg.tnum.mask.count_ones() < 64
        && (reg.umin > 0 || reg.umax < u64::MAX)
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
                runtime_samples: Vec::new(),
                store_site: None,
                prune_probe: None,
                helper_arg_violations: Vec::new(),
            },
            counterfactual: CounterfactualLayer::default(),
            expectation: ExpectationFlag::default(),
            parse_notes: Vec::new(),
            source_label: None,
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
            ..Default::default()
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
