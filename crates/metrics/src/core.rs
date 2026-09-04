//! CORE metrics — the operational bedrock of the loop.
//!
//! Design contract (do not weaken):
//!   * Fixed schema. Pure, raw operational observation.
//!   * Tied to ground truth; ALWAYS on.
//!   * INDEPENDENT of the counterfactual layer — core is read straight from
//!     observation, never from loop-generated alternatives.
//!
//! `reg_type` and reject `reason` are verbatim Strings: the verifier's own text,
//! robust across kernel versions and consistent with "don't reshape raw output".

use serde::{Deserialize, Serialize};

/// The verifier's final decision on a program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum VerifierDecision {
    /// Program accepted.
    Accept,
    /// Program rejected, with the verifier's reason text (verbatim).
    Reject { reason: String },
}

/// A tnum (tristate number): known bit values + unknown-bit mask
/// (kernel `struct tnum`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Tnum {
    /// Known bit values.
    pub value: u64,
    /// Unknown-bit mask (1 = unknown).
    pub mask: u64,
}

/// One register's abstract state at a point in verification.
///
/// The verifier tracks a scalar TWICE: as a full 64-bit value and as its 32-bit
/// subregister, and it must keep the two views reconciled (`__reg32_deduce_bounds`
/// / `__reg64_deduce_bounds`). Both views are recorded here because a disagreement
/// BETWEEN them is a bug class neither view can show on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegState {
    /// Register number (0..=10).
    pub reg: u8,
    /// Verifier `reg_type`, verbatim (e.g. "scalar", "map_value", "ptr_to_ctx").
    pub reg_type: String,
    /// tnum (known bits + unknown mask).
    pub tnum: Tnum,
    /// Unsigned min bound.
    pub umin: u64,
    /// Unsigned max bound.
    pub umax: u64,
    /// Signed min bound.
    pub smin: i64,
    /// Signed max bound.
    pub smax: i64,
    /// 32-bit unsigned min, when the verifier printed a 32-bit view.
    ///
    /// `None` means the verifier did NOT print one — which is not the same as zero,
    /// and the difference matters: an absent view is nothing to check, a present
    /// zero is an observation. Serialized only when present, so artifacts written
    /// before the 32-bit view existed stay byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub u32_min: Option<u64>,
    /// 32-bit unsigned max, when printed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub u32_max: Option<u64>,
    /// 32-bit signed min, when printed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s32_min: Option<i64>,
    /// 32-bit signed max, when printed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s32_max: Option<i64>,
}

/// Registers of interest at one instruction index — a snapshot in the evolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegSnapshot {
    /// Instruction index this snapshot was taken at.
    pub insn_idx: u32,
    /// Register states of interest at this point.
    pub regs: Vec<RegState>,
}

/// Processed-work counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Processed {
    /// `insn_processed` reported by the verifier.
    pub insn_processed: u64,
    /// Number of verifier states processed.
    pub states_processed: u64,
}

/// JIT vs interpreter divergence for one program run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JitInterpDiff {
    /// Return value under the JIT.
    pub retval_jit: i64,
    /// Return value under the interpreter.
    pub retval_interp: i64,
    /// Whether the `data_out` buffers matched.
    pub data_out_equal: bool,
}

/// KCOV coverage delta for one exec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoverageDelta {
    /// New basic blocks covered by this exec.
    pub new_bb: u64,
    /// The exec counter N at which this was observed (provenance).
    pub exec_n: u64,
}

/// One helper-call argument OBSERVATION: which helper, which argument, and the
/// verifier reg-type family observed for it at the call site (e.g. "map_ptr",
/// "fp", "scalar"). PURE observation — the EXPECTED `arg_type` is deliberately
/// NOT stored here; it lives in ground truth (`bpf_func_proto`), so a mismatch is
/// DECIDED at `diff`, never pre-baked into CORE. This is the real-path counterpart
/// of the (legacy, synthetic) [`HelperArgViolation`] which carried its own expected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperArgObservation {
    /// Helper name, verbatim (e.g. "bpf_map_lookup_elem").
    pub helper: String,
    /// Argument index (0-based; arg N is register R(N+1)).
    pub arg_index: u8,
    /// Observed verifier reg-type family for this argument.
    pub observed: String,
}

/// Helper `arg_type` contract-violation signal (from `bpf_func_proto` checks).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperArgViolation {
    /// Helper name (or id), verbatim.
    pub helper: String,
    /// Argument index that violated its contract.
    pub arg_index: u8,
    /// Expected `arg_type`, verbatim.
    pub expected: String,
    /// Observed `arg_type`, verbatim.
    pub observed: String,
}

/// One CORE observation for a single verifier invocation / fuzzing exec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMetrics {
    /// accept/reject + reason.
    pub verifier_decision: VerifierDecision,
    /// Register-state evolution (per-insn snapshots).
    pub register_evolution: Vec<RegSnapshot>,
    /// insn_processed / states processed.
    pub processed: Processed,
    /// JIT<->interpreter retval + data_out diff (absent if not run).
    pub jit_interp_diff: Option<JitInterpDiff>,
    /// KCOV coverage delta + exec counter N.
    pub coverage_delta: CoverageDelta,
    /// Helper arg_type contract violations (zero or more). LEGACY / synthetic path
    /// (carries its own expected); the real path uses `helper_arg_observations`.
    pub helper_arg_violations: Vec<HelperArgViolation>,
    /// Helper-call argument observations from the real verifier log. Expected
    /// arg_type comes from ground truth, so mismatches are decided at `diff`.
    /// Skipped when empty so existing artifacts stay byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub helper_arg_observations: Vec<HelperArgObservation>,
    /// Runtime ground-truth samples from BPF_PROG_TEST_RUN: for each attacker-
    /// controlled input, the ACTUAL value the program returned. The diff stage
    /// checks each retval against the verifier's own proven bound on the return
    /// register — a violation is a soundness bug caught WITHOUT trusting the
    /// verifier log to be self-consistent. Skipped when empty so existing
    /// artifacts stay byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_samples: Vec<RuntimeSample>,
}

/// One runtime observation: the program was executed via BPF_PROG_TEST_RUN with a
/// chosen attacker-controlled `input`, and returned `retval` (the low 32 bits of
/// the return register). `error` marks a sample the harness could not run (the
/// diff stage never treats an errored sample as a violation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeSample {
    /// The attacker-controlled input fed to the program (a 32-bit map value).
    pub input: u64,
    /// The value the program actually returned (retval, low 32 bits).
    pub retval: u64,
    /// For a STORE program: the offset inside the map value where the sentinel
    /// actually landed, or `Some(-1)` if it was absent (the store went out of the
    /// readable value — an OOB write). `None` for return-value samples.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_off: Option<i64>,
    /// True if the harness could not execute this sample (skipped by the oracle).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub error: bool,
}
