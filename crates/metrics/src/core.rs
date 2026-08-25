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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Helper arg_type contract violations (zero or more).
    pub helper_arg_violations: Vec<HelperArgViolation>,
}
