//! Ground-truth source 4 — version patch diffs (git log between kernel versions).

use std::path::Path;

/// Reference view derived from cross-version verifier patch diffs.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct PatchDiffModel {
    // TODO(gt-patch-diff): finalize.
}

/// Load patch diffs across kernel versions from a git tree. STUB.
/// TODO(gt-patch-diff): `git log`/`git diff` over verifier paths between revisions.
pub fn load(_kernel_git: &Path) -> PatchDiffModel {
    todo!("scaffold: extract cross-version verifier patch diffs")
}
