# verifierloop

An **operational vulnerability-research lab loop** targeting the Linux **eBPF
verifier** on the `bpf-next` kernel tree. It hunts for verifier **logic bugs**,
**temporal-logic bugs**, and **corruption-to-primitive** research leads by
running self-built kernels under disposable VMs, observing verifier behavior, and
diffing what it observes against documented/expected behavior.

> **Status: SCAFFOLDING.** This repository is a compilable/importable skeleton.
> Pipeline stages, ground-truth loaders, VM control, scoring, and the loop
> runtime are **stubs** — each stops at a clearly-marked `TODO` at its boundary.
> No hunt logic is implemented yet.

---

## What this is — and what it is NOT

- It **is** a self-contained hunting loop: fuzz → observe → normalize → score →
  diff-against-ground-truth → hand a triaged batch to a human → repeat.
- It is **NOT a formal proof system.** There is no theorem prover, no formal
  verification, and no attempt to prove the loop's own soundness or consistency.
  The loop's **"ground truth" is not a formal model** — it is documentation +
  patch diffs + classic logical analysis (see [Ground truth](#ground-truth-4-sources)).
- **The loop closes on itself.** There is no external engine to integrate.

## Target & environment

- **Research target:** the eBPF verifier in the `bpf-next` kernel tree.
- **Host / orchestration layer:** WSL2 Ubuntu 22.04 on Windows 11 (KVM enabled,
  nested virtualization on). This layer is **only** host/orchestration.
- **Execution:** QEMU/KVM **disposable VMs** running **self-built `bpf-next`
  kernels**. The actual hunt runs **inside** those VMs, not on the Ubuntu layer.
- **TCG fallback:** a KVM-less pure-software path exists (slower) for **manual
  PoC / differential** only — never the main hunting throughput.
  See `config/wsl/wslconfig.note.md` for enabling `/dev/kvm`.

## Architecture

Two languages with a **clean, documented boundary**:

- **Rust** — architecture, orchestration, services, the loop runtime, VM control.
- **Python** — statistics, data processing, metric analysis, anomaly scoring.

They meet at a **typed, file-based JSON artifact contract**: the Rust
orchestrator writes normalized-metric artifacts into a period directory, invokes
the Python analyzer, and reads scores back — no shared process memory. The
contract is defined in the `contract` crate and mirrored in
`python/.../contract.py`; keep the two in lockstep. *(The envelope is
**implemented** — serde (de)serialization, schema-version check, atomic writes,
unit tests, and a Rust↔Python round-trip. The payload stays generic
(`Artifact<T>` / untyped JSON on the Python side) until the metric types are
finalized.)*

### Repo layout

```
verifierloop/
├── Cargo.toml                       # Rust workspace (fine-grained crates)
├── crates/
│   ├── metrics/                     # the 4 metric-schema groups
│   ├── contract/                    # Rust<->Python JSON artifact contract (the boundary)
│   ├── pipeline/                    # period pipeline stages (modules) + ground-truth adapters
│   ├── vmctl/                       # disposable QEMU VM control (KVM primary / TCG fallback)
│   └── orchestrator/                # loop runtime (binary); hosts the confirmation-bias guardrail
├── python/                          # verifierloop-analysis package (stats / scoring)
├── config/
│   ├── kernel/bpf-verifier-lab.config    # .config fragment (KCOV/KASAN/KCSAN/UBSAN/BPF_JIT/BTF...)
│   ├── qemu/launch-kvm.sh                # QEMU launch (KVM)
│   ├── qemu/launch-tcg.sh                # QEMU launch (TCG fallback)
│   ├── syzkaller/syzkaller.cfg.placeholder
│   └── wsl/wslconfig.note.md             # nested-virt note for the WSL2 host
├── data/                            # per-period harvest artifacts (runtime; gitignored)
└── justfile                         # build-kernel, boot-vm (kvm/tcg), run-fuzzers, ...
```

## The loop (pipeline)

```
fuzzer/recon output
  → metric normalization
  → anomaly scoring            (Python, over the JSON artifact contract)
  → documented-vs-observed diff (against the 4 ground-truth sources)
  → period report              → feeds back into the next period
```

Each stage is a separate module in the `pipeline` crate
(`ingest → normalize → score → diff → report`) with a typed input/output
interface. `ingest` and `normalize` are **implemented**: `ingest` collects native
output unchanged into the period's `raw/` dir and writes `RAW_INDEX`
(`cargo run -p pipeline --example ingest_demo`); `normalize` interprets those raw
blobs into the frozen metric schema and writes `NORMALIZED`
(`cargo run -p pipeline --example normalize_demo`) — via an injectable
`RecordParser`, though the real per-tool parsers (native formats) are still
`TODO`. `score` is **implemented** too: Rust delegates to the Python analyzer over
the contract (`python -m verifierloop_analysis`), which writes `ANOMALY_SCORES`
(`cargo run -p pipeline --example score_demo`) — a transparent baseline
hard-signal scorer (`baseline-hard-signals-v0`), with statistical scoring `TODO`.
`diff` is **implemented**: it compares the NORMALIZED observation against ground
truth and writes `DIFF_FINDINGS` (`cargo run -p pipeline --example diff_demo`).
Two check kinds — **intrinsic logical invariants** computed straight from CORE
(tnum well-formedness, bound ordering, tnum/bounds consistency, JIT/interpreter
equivalence — the "classic logical analysis" pillar) and **source-backed** checks
via an injectable [`GroundTruth`] oracle (helper `arg_type` today; verifier.c /
verifier.rst / patch-diff loaders `TODO`, they need a bpf-next tree). Findings
carry **no severity** — `diff` states, `score` ranks — and `diff` never reads
`ANOMALY_SCORES` (guardrail). `report` is **implemented** too: it JOINS the two
judgment artifacts (`ANOMALY_SCORES` + `DIFF_FINDINGS`) into a per-record triage
batch ordered by the **existing** anomaly score, and writes `PERIOD_REPORT`
(`cargo run -p pipeline --example report_demo`) — the human-in-the-loop handoff.
It invents no new ranking or severity (score ranks; diff states; report
assembles), and any timestamp in it is a label only. **All five pipeline stages
now run end to end** (`ingest → normalize → score → diff → report`); what remains
is real integration — native-format parsers, a real fuzz driver / VM, and the
external ground-truth loaders.

**Tool-output principle:** every tool's **DEFAULT-mode native output** is
collected **unchanged** in `ingest`; **normalization is a separate later stage**,
never done at the source.

## Ground truth (4 sources)

The documented-vs-observed diff engine compares observed kernel behavior against
four external sources (loaders under `pipeline::groundtruth`) **plus** the
intrinsic logical-invariant pillar:

1. **`verifier.c`** state-transition logic (accept/reject + register-state evolution) — loader `TODO`
2. **`Documentation/bpf/verifier.rst`** (documented behavior) — loader `TODO`
3. helper **`bpf_func_proto` / `arg_type`** contracts — usable now via the `GroundTruth` oracle
4. **version patch diffs** (git log between kernel versions) — loader `TODO`
5. **classic logical analysis** (`logical_invariant`) — intrinsic invariants over CORE, no external file

Sources 1/2/4 need a bpf-next checkout, so their loaders are `TODO`; the oracle is
injectable so the `diff` logic runs and is tested today against 3 and 5.

## Period model — period N = exec count, NOT time

- A **period** = the loop runs, grows, then hands a human a **triaged data
  batch** (periodic harvest; **human-in-the-loop at the period boundary**).
- **Period N is measured by the total fuzzing exec count (a counter). It is NOT
  a fixed duration.** Wall-clock **time is only a timestamp stamped onto the
  data — never a stopping criterion.**
- A secondary **efficiency observation** (new coverage / new state per exec) is
  recorded **for the report only** — it is **not** a decision criterion.

## Metric groups

Four groups, defined as separate schema modules in the `metrics` crate (and
mirrored in `python/.../schemas/`). The schema is now **frozen** (serde types):
**CORE** uses the full + register-state-evolution shape; DERIVED / COUNTERFACTUAL /
EXPECTATION carry concrete-but-minimal shapes with `TODO`s for later enrichment.

1. **CORE** — fixed, pure operational observation, tied to ground truth, always
   on, **independent of the counterfactual layer**, meaningful on its own.
   Includes: verifier decision (accept/reject + reason); register-state evolution
   (tnum mask, umin/umax/smin/smax, reg type); `insn_processed` / processed
   states; JIT↔interpreter retval + `data_out` diff; coverage delta (KCOV, new BB
   per exec) + exec counter N; helper `arg_type` contract-violation signal.
2. **DERIVED** — schema fixed now; values fill as the loop grows.
3. **COUNTERFACTUAL** — extra / opt-in; sits **on top of** core, never modifies
   it. Deliberately kept **outside** core so the engine reads raw observation,
   not the loop's own generated alternatives.
4. **"Did the loop expect this?" flag** — a separate field to **measure
   confirmation bias**.

## Confirmation-bias guardrail (HARD)

The loop's obligation to produce counterfactual output **must not** turn it into a
counterfactual-**optimizing** process that generates input to confirm its own
expectation — i.e. a **confirmation-biased fuzzer**. **This is not a solved
problem; it is a live stress point** that every change to the scoring /
counterfactual / input-selection path must be checked against.

The guards are: **CORE metrics kept independent of the counterfactual layer**;
the **"expected?" flag** (so bias is measured, not hidden); and
**human-in-the-loop at every period boundary**. The full statement is embedded as
a comment in `crates/orchestrator/src/loop_runtime.rs` — keep it there.

## Fuzzing stack

- Multiple **concurrent fuzzers** under QEMU. **Primary: syzkaller** (requires
  Go). Plus a **differential harness** (verifier-accepts vs interpreter-vs-JIT
  retval). Optional: **Trinity**.
- syzkaller is **set up and running** (`scripts/setup-syzkaller.sh` builds it;
  `scripts/gen-syz-config.sh` writes a real manager config; `just run-fuzzers`
  drives it). It runs its own QEMU VMs on **TCG** (no KVM here), focused on the
  verifier via `enable_syscalls: ["bpf*"]` (44/8300 syscalls). Verified end to
  end: executor deploys over ssh, **KCOV coverage feedback works** (0→5177 BB in
  ~30s), corpus grows. Throughput on TCG is ~40 execs/s aggregate (4 VMs) after a
  ~90s warm-up — slower than KVM but functional; since a period is an **exec
  count**, only wall-clock is affected, not the loop's logic.
  > The VM image uses **name-agnostic** DHCP (`systemd-networkd` wildcard) so
  > syzkaller's `e1000` NIC (which renames to `enp0s4`) gets an address — see
  > devlog 0009.
- Kernel config enables: **KCOV, KASAN, KCSAN, UBSAN, BPF_JIT,
  BPF_JIT_ALWAYS_ON, DEBUG_INFO_BTF** + BTF/pahole prerequisites — see
  `config/kernel/bpf-verifier-lab.config`.
  > **Note (KASAN vs KCSAN):** these two sanitizers are **mutually exclusive** in
  > one build — `olddefconfig` keeps KASAN and drops KCSAN. The primary hunt kernel
  > runs KASAN (memory safety); **KCSAN is a separate build** for data-race hunting.

## Lab bring-up (real kernel + VM)

The `config/` placeholders are now **runnable scripts** under `scripts/`, driven by
`just`. They build a self-built bpf-next kernel and boot it in a disposable QEMU VM:

```
just fetch-kernel     # blobless partial clone of bpf-next -> .lab/bpf-next
just build-kernel     # defconfig + kvm_guest.config + lab fragment -> .lab/build/bzImage (with BTF)
just create-rootfs    # debootstrap Debian minimal -> .lab/images/rootfs.img (disposable)
just verify-vm        # boot, assert BTF + bpffs + kcov in-VM, power off
just boot-vm-kvm      # interactive disposable VM (KVM primary)  |  just boot-vm-tcg (fallback)
```

All heavy artifacts live under `.lab/` (gitignored). Bring-up has been run
end-to-end: the kernel boots and BTF (`/sys/kernel/btf/vmlinux`), bpffs, and kcov
are all confirmed **inside** the VM.

> **KVM requires working nested virtualization.** On this WSL2 host `-enable-kvm`
> currently fails (`Hyper-V: Nested features: 0x0`) despite `nestedVirtualization=true`
> in `.wslconfig`, so `verify-vm` fell back to **TCG** (software emulation, slower —
> per policy, manual PoC / differential only). To unlock the primary KVM path, run
> `wsl --shutdown` from Windows and restart WSL; if the Windows host is itself a VM,
> expose VT-x/EPT to it. See `config/wsl/wslconfig.note.md`.

## Tasks (`just`)

| Recipe | Purpose |
| --- | --- |
| `just fetch-kernel` | Blobless partial clone of bpf-next into `.lab/bpf-next` |
| `just build-kernel` | Build the self-built bpf-next `bzImage` (defconfig + lab fragment, BTF) |
| `just create-rootfs` | Create the disposable Debian rootfs image (debootstrap) |
| `just verify-vm` | Boot the VM, assert BTF + bpffs + kcov, power off |
| `just boot-vm-kvm` | Boot a disposable KVM VM (primary) |
| `just boot-vm-tcg` | Boot a disposable TCG VM (fallback; slower) |
| `just run-fuzzers` | Start syzkaller + differential harness (+ Trinity) |
| `just collect-metrics` | Ingest → normalize → hand to Python scoring |
| `just run-period` | Run one period (boundary = exec count N) |
| `just period-report` | Emit the triaged period report |

The hunt recipes above are **placeholders** that print intent and exit non-zero.
Two self-checks actually run against the skeleton:

- `just build-rust` — compile the Rust workspace.
- `just check-python` — confirm the Python package imports.

## Operator manual

Step-by-step "what to run, from where, in what order" lives in
[`docs/RUNBOOK.md`](docs/RUNBOOK.md) — health checks, the end-to-end demo, the
fuzzer, lab bring-up, and the KVM-vs-TCG situation. (`just` is optional and not
required; the runbook gives the direct `./scripts/...` commands.)

## Development log

Implementation steps taken *after* the initial scaffold — what was built, why,
and which design decisions were made — are recorded (per work item, all in one
file) in [`docs/devlog/devlog.md`](docs/devlog/devlog.md). So far: `contract`
serde (0001), the `ingest`
stage (0002), the orchestrator loop spine (0003 — period = exec-count N, `ingest`
wired; real fuzz driver still a stub), the `normalize` stage + frozen CORE metric
schema (0004 — real per-tool parsers still a stub), the `score` stage (0005 —
Rust↔Python anomaly scoring over the contract; baseline scorer, statistical
method still a stub), the `diff` stage (0006 — documented-vs-observed with
intrinsic logical invariants + an injectable ground-truth oracle; the frozen
`DIFF_FINDINGS` schema; external source loaders still a stub), and the `report`
stage (0007 — joins `ANOMALY_SCORES` + `DIFF_FINDINGS` into the triaged
`PERIOD_REPORT` batch; completes the pipeline end to end), and the real
kernel/VM bring-up (0008 — `scripts/` build a self-built bpf-next kernel + a
disposable QEMU VM; booted end to end with BTF/bpffs/kcov confirmed in-VM; KVM
blocked on host-side nested virt, TCG working), and syzkaller integration (0009 —
the primary fuzzer builds and runs against the self-built kernel on TCG; fixed a
VM networking mismatch so syzkaller can ssh in; KCOV-guided fuzzing confirmed).

## Scope boundaries

No external engine is integrated. There is no formal-proof / theorem-proving
component. Anything not specified for this scaffolding pass is left as a `TODO`
rather than decided ad hoc.
