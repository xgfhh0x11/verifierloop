//! Ground-truth source 2 — `Documentation/bpf/verifier.rst` (documented behavior).

use std::path::Path;

/// Parsed reference view of the documented verifier behavior.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct VerifierRstModel {
    // TODO(gt-verifier-rst): finalize.
}

/// Load from a bpf-next checkout's `Documentation/bpf/verifier.rst`. STUB.
/// TODO(gt-verifier-rst): extract documented rules to diff against observation.
pub fn load(_verifier_rst: &Path) -> VerifierRstModel {
    todo!("scaffold: parse documented verifier behavior")
}
