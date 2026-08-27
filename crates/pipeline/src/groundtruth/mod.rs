//! Ground-truth adapters for the documented-vs-observed diff engine.
//!
//! The loop's "ground truth" is NOT a formal model. It is documentation + patch
//! diffs + classic logical analysis, drawn from four concrete external sources:
//!   1. `verifier_c`   — verifier.c state-transition logic (accept/reject + reg state)
//!   2. `verifier_rst` — Documentation/bpf/verifier.rst (documented behavior)
//!   3. `helper_proto` — helper bpf_func_proto / arg_type contracts
//!   4. `patch_diff`   — version patch diffs (git log between kernel versions)
//!
//! ...plus the intrinsic **logical invariants** (tnum well-formedness, bound
//! ordering, JIT/interpreter equivalence) that the `diff` stage checks directly —
//! the "classic logical analysis" pillar, which needs no external file.
//!
//! # Injectable oracle
//!
//! [`GroundTruth`] is a trait so the `diff` logic is testable now with a reference
//! oracle, and the real disk-backed loaders slot in later. The one source-backed
//! query available today is [`GroundTruth::helper_arg_type`] (source 3): the other
//! three sources need a bpf-next checkout and their loaders are TODO.

pub mod helper_proto;
pub mod patch_diff;
pub mod verifier_c;
pub mod verifier_rst;

use helper_proto::HelperProtoModel;

/// The ground-truth oracle the `diff` stage consults for **source-backed** checks.
///
/// Intrinsic logical invariants (tnum/bounds/jit-interp) are computed by `diff`
/// directly and do NOT go through this trait. This trait answers questions that
/// require an external source; each returns `Option` so "source not loaded" is
/// distinct from "no divergence".
///
/// Today only [`Self::helper_arg_type`] (source 3) is answerable. Queries for
/// verifier.c decisions (source 1), documented rules (source 2), and cross-version
/// deltas (source 4) will be added here as their loaders come online.
pub trait GroundTruth {
    /// Documented `arg_type` for helper argument `(helper, arg_index)`, or `None`
    /// if this oracle has no contract loaded for it (real proto loader TODO).
    fn helper_arg_type(&self, helper: &str, arg_index: u8) -> Option<String>;

    /// Expected verifier reg-type FAMILY for a helper arg (source 3, real path) —
    /// what the diff stage compares an OBSERVED arg reg-type against. Default
    /// `None`; impls carrying a `bpf_func_proto` slice override it.
    fn helper_arg_regtype(&self, _helper: &str, _arg_index: u8) -> Option<String> {
        None
    }
}

/// The empty oracle: knows nothing, corroborates nothing. Used when only the
/// intrinsic logical-invariant checks should run (no external sources loaded).
///
/// Analogous to `normalize::UnimplementedParser`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoGroundTruth;

impl GroundTruth for NoGroundTruth {
    fn helper_arg_type(&self, _helper: &str, _arg_index: u8) -> Option<String> {
        None
    }
}

/// An in-memory oracle: real for whatever it has been populated with, `None`
/// elsewhere. The reference oracle for tests/examples and the shape the real
/// aggregated ground truth (once the disk loaders exist) will fill in.
#[derive(Debug, Default, Clone)]
pub struct StaticGroundTruth {
    /// Source 3 — helper arg_type contracts.
    pub helper_proto: HelperProtoModel,
    // TODO(groundtruth): VerifierCModel, VerifierRstModel, PatchDiffModel — added
    // here (and exposed via new trait methods) as their loaders land.
}

impl StaticGroundTruth {
    /// Build from a helper-proto table (the one source usable without a tree).
    pub fn with_helper_proto(helper_proto: HelperProtoModel) -> Self {
        Self { helper_proto }
    }
}

impl GroundTruth for StaticGroundTruth {
    fn helper_arg_type(&self, helper: &str, arg_index: u8) -> Option<String> {
        self.helper_proto
            .arg_type(helper, arg_index)
            .map(str::to_string)
    }

    fn helper_arg_regtype(&self, helper: &str, arg_index: u8) -> Option<String> {
        self.helper_proto
            .arg_regtype(helper, arg_index)
            .map(str::to_string)
    }
}

/// Load and aggregate all four external ground-truth sources from a bpf-next
/// checkout. STUB.
/// TODO(groundtruth): load verifier.c + verifier.rst + helper protos + patch diffs
/// into a [`StaticGroundTruth`]. Needs the kernel tree.
pub fn load(_kernel_src: &std::path::Path) -> StaticGroundTruth {
    todo!("scaffold: load the four ground-truth sources from a bpf-next tree")
}
