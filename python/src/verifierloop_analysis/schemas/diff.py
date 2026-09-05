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
SOURCE_DOCUMENTATION = "documentation"    # source 2 (verifier.rst, anchor-verified)
SOURCE_HELPER_PROTO = "helper_proto"      # source 3 (bpf_func_proto, extracted)
SOURCE_PATCH_DIFF = "patch_diff"          # source 4 (partial: evidence, not findings)
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
class EvidenceNote:
    """Qualified evidence that is explicitly NOT a verdict.

    Same fields as DivergenceFinding, a separate channel on purpose: a note says
    "weigh this fact", a finding says "kernel and ground truth disagree". Notes are
    NOT counted in `finding_count`, so a period carrying only notes still reads
    clean. Used for e.g. a documented error string that was reworded upstream while
    the verifier's decision stayed exactly as documented.
    """

    record_index: Optional[int]
    source: str
    kind: str                    # e.g. "documented_message_drift"
    aspect: str                  # e.g. "reject_reason"
    expected: str
    observed: str
    detail: str


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
    # Denominators: they are what make "0 findings" interpretable. 0 out of many
    # checks means the programs were sound; 0 out of ZERO means the leg never ran.
    helper_args_observed: int = 0
    documented_cases_checked: int = 0
    helper_args_checked: int = 0
    note_count: int = 0
    # The intrinsic leg's denominator (0025). Measured: the committed syzkaller
    # volume scores 0 here, so that leg's "0 findings" was 0 out of 0.
    tnum_bounds_checked: int = 0
    # The 32<->64 denominator (0026). A corpus of single-width programs scores 0
    # here however large it gets — the verifier prints the two views as one token.
    reg32_checked: int = 0
    # The bound-ORDERING denominator (0065). The four `umin <= umax` style checks are
    # ungated and were therefore uncounted since 0026; a bound the verifier omitted
    # resolves to its extreme and can never be on the wrong side, so only comparisons
    # with both endpoints away from their extremes are counted.
    bounds_order_checked: int = 0


@dataclass
class DiffFindings:
    exec_count: int
    findings: "list[DivergenceFinding]"
    summary: DiffSummary
    # Omitted from the artifact when empty (Rust: skip_serializing_if).
    notes: "list[EvidenceNote]" = field(default_factory=list)
