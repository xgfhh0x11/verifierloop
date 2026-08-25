"""DIFF_FINDINGS payload (mirror of crates/pipeline/src/diff.rs) — FROZEN schema.

The documented-vs-observed diff artifact the `diff` stage writes. `diff` STATES
divergences; it carries NO severity/score — ranking is `score`'s job. The report
stage reads this alongside ANOMALY_SCORES. Kept in lockstep with Rust.

`source` is a snake_case string enum; the values below must match the Rust
`GroundTruthSource` variants exactly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# GroundTruthSource values (mirror of the Rust enum).
SOURCE_VERIFIER_C = "verifier_c"          # source 1 (loader TODO)
SOURCE_DOCUMENTATION = "documentation"    # source 2 (loader TODO)
SOURCE_HELPER_PROTO = "helper_proto"      # source 3
SOURCE_PATCH_DIFF = "patch_diff"          # source 4 (loader TODO)
SOURCE_LOGICAL_INVARIANT = "logical_invariant"  # intrinsic "classic logical analysis"


@dataclass
class DivergenceFinding:
    record_index: Optional[int]  # None = period-level finding
    source: str                  # one of the SOURCE_* values above
    kind: str                    # e.g. "tnum_malformed"
    aspect: str                  # "tnum" | "bounds" | "jit_interp" | "helper_arg"
    expected: str                # documented / expected (verbatim)
    observed: str                # observed (verbatim)
    detail: str                  # human-readable explanation


@dataclass
class BySource:
    verifier_c: int = 0
    documentation: int = 0
    helper_proto: int = 0
    patch_diff: int = 0
    logical_invariant: int = 0


@dataclass
class DiffSummary:
    record_count: int = 0
    finding_count: int = 0
    by_source: BySource = field(default_factory=BySource)


@dataclass
class DiffFindings:
    exec_count: int
    findings: "list[DivergenceFinding]"
    summary: DiffSummary
