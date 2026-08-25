"""NORMALIZED payload (mirror of crates/pipeline/src/normalize.rs).

This is the artifact the `normalize` stage writes and the Python scoring side
reads. Python typically works with the raw JSON dicts; these dataclasses document
the shape and keep it in lockstep with Rust.
"""
from __future__ import annotations

from dataclasses import dataclass

from .core import CoreMetrics
from .counterfactual import CounterfactualLayer
from .derived import DerivedMetrics
from .expectation import ExpectationFlag


@dataclass
class MetricRecord:
    core: CoreMetrics
    counterfactual: CounterfactualLayer  # opt-in, OFF by default
    expectation: ExpectationFlag         # NoPrediction by default


@dataclass
class NormalizedMetrics:
    exec_count: int
    records: "list[MetricRecord]"
    derived: DerivedMetrics
