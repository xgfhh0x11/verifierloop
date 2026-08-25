//! Ground-truth source 3 — helper `bpf_func_proto` / `arg_type` contracts.
//!
//! A helper's `bpf_func_proto` documents the `arg_type` each argument must have.
//! This model is the reference table the `diff` stage checks the CORE
//! `helper_arg_violation` signal against.
//!
//! The real extraction (parsing `bpf_func_proto` definitions out of a bpf-next
//! checkout) is TODO — it needs the kernel tree. Until then the table can be
//! populated in-memory (see [`HelperProtoModel::with_contract`]) so the diff
//! oracle path is exercised now.

use std::collections::BTreeMap;
use std::path::Path;

/// Reference view of helper argument-type contracts:
/// `(helper, arg_index) -> documented arg_type` (verbatim, drift-robust String).
#[derive(Debug, Default, Clone)]
pub struct HelperProtoModel {
    contracts: BTreeMap<(String, u8), String>,
}

impl HelperProtoModel {
    /// An empty model (no contracts loaded).
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one documented `(helper, arg_index) -> arg_type` contract (builder).
    pub fn with_contract(
        mut self,
        helper: impl Into<String>,
        arg_index: u8,
        arg_type: impl Into<String>,
    ) -> Self {
        self.contracts
            .insert((helper.into(), arg_index), arg_type.into());
        self
    }

    /// Documented `arg_type` for `(helper, arg_index)`, if this source knows it.
    /// `None` means the contract is not loaded (real loader TODO) — the diff stage
    /// treats that as "cannot corroborate", not "no violation".
    pub fn arg_type(&self, helper: &str, arg_index: u8) -> Option<&str> {
        self.contracts
            .get(&(helper.to_string(), arg_index))
            .map(String::as_str)
    }

    /// Number of loaded contracts.
    pub fn len(&self) -> usize {
        self.contracts.len()
    }

    /// Whether no contracts are loaded.
    pub fn is_empty(&self) -> bool {
        self.contracts.is_empty()
    }
}

/// Load helper protos from a bpf-next checkout. STUB.
/// TODO(gt-helper-proto): extract per-helper `arg_type` contracts from
/// `bpf_func_proto` definitions to diff against the CORE `helper_arg_violation`
/// signal. Needs the kernel tree; until then build the table in-memory.
pub fn load(_kernel_src: &Path) -> HelperProtoModel {
    todo!("scaffold: build helper arg_type contract reference from a bpf-next tree")
}
