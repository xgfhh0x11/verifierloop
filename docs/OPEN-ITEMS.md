# Open items — tracked, not blocking

Findings and hypotheses that are **deliberately left open** rather than closed or
dropped. Each says *why* it is open, what would settle it, and its priority. This
file exists so an unresolved item cannot quietly become a settled one.

Closed items are removed from here and their resolution recorded in the devlog.

---

## OI-1 — Two `int3` crashes: artifact hypothesis is FALSIFIABLE BUT UNTESTED

- **Status:** OPEN (low priority). *Not* "diagnosed and closed."
- **Raised:** 2026-08-28 (devlog 0020)
- **Blocked by:** KVM unavailable on this host (probed 2026-08-28: `/dev/kvm` exists
  but `-enable-kvm` → `No such device`, and `grep -c '(vmx|svm)' /proc/cpuinfo` = **0**,
  i.e. the CPU virtualization flags are not exposed at all).

**What happened.** A 30-minute syzkaller campaign produced two crashes:
`int3 in sk_filter_trim_cap` and `int3 in __seccomp_filter`
(`.lab/syzkaller/workdir/crashes/`).

**Hypothesis (emulation artifact, not a verifier logic bug).** Supporting evidence,
strongest first:

1. **Both RIPs are the same site**: `filter.h:763` =
   `static_branch_unlikely(&bpf_stats_enabled_key)` (declared `filter.h:744`) — a
   live-patched static branch, exactly where int3-based text poking happens.
2. **The crashes are not in the fuzzed programs**: they land in unrelated daemons
   (`udev-worker` via a netlink broadcast socket filter; `systemd-udevd` via
   seccomp). Any process running a BPF program can be at that site when the key flips.
3. **The trigger is present**: syzkaller's enabled surface includes `bpf$ENABLE_STATS`,
   which toggles `bpf_stats_enabled_key`, forcing the kernel to text-patch that branch.
4. We run **`-accel tcg,thread=multi`**; concurrent code patching across vCPUs is a
   known weak area for TCG.

**Explicitly NOT decisive evidence.** Both crashes are `repro=false`. Non-reproducibility
is *consistent with* an emulation race, but **genuine race-condition kernel bugs are
also non-deterministic**, so this is supporting, not discriminating. (Devlog 0020
originally leaned on it too heavily; corrected.)

**What would settle it (the falsifying test).** Re-run the same campaign under **KVM**
(or bare metal), same kernel, same syzkaller config:

```bash
# once /dev/kvm works: flip the accel in the manager config, regenerate, re-run
QEMU_ARGS="-enable-kvm -cpu host" ./scripts/gen-syz-config.sh
DURATION=... ./scripts/run-syzkaller.sh
```

- Crashes **disappear** under KVM → supports the TCG-artifact hypothesis.
- Crashes **reproduce** under KVM → the hypothesis is wrong; this becomes a real
  kernel-side lead and gets triaged properly.

**Power caveat (do not run a token test and call it settled).** The observed base rate
is ~2 crashes per 30 minutes across 4 TCG VMs. A single short KVM run showing zero
crashes is **weak** evidence. Match or exceed the original exposure — and note KVM is
~10–20x faster, so equal *exec count* is reached in far less wall-clock; compare on
**execs, not minutes**, consistent with the project's period model.

**Available-now tests and why they are not run.** Two partial discriminators exist
without KVM: (a) single-threaded `-accel tcg` (removes the concurrency the hypothesis
blames), (b) dropping `bpf$ENABLE_STATS` from the enabled syscalls (removes the key
flip). Both are **underpowered** at the observed base rate — a null result in one
30-minute run would not distinguish the hypotheses — and (b) also narrows the hunt
surface. Left unrun deliberately rather than run for the appearance of rigor.

**Why low priority.** This is not the target bug class (verifier logic), it does not
affect the pipeline's correctness, and the crashes are outside the loop's data path
(syzkaller crash reports are not yet ingested — see OI-2).

---

## OI-2 — syzkaller crash reports are outside the pipeline

- **Status:** OPEN (medium priority)
- **What:** crashes land in `.lab/syzkaller/workdir/crashes/` and are read by hand.
  They are not ingested, normalized, or surfaced in a period report.
- **Why it matters:** a crash is a real signal channel the loop currently cannot see;
  triage depends on someone remembering to look.
- **Shape of the fix:** a syzkaller crash/coverage parser feeding DERIVED + a
  period-level finding (not CORE — a crash is not a per-verifier-invocation observation).

---

## OI-3 — One of five ground-truth sources is still a stub

- **Status:** OPEN (medium priority) — *narrowed 2026-08-28 by devlog 0022.*
- **Live now:** intrinsic invariants; helper `bpf_func_proto` (source 3, extracted —
  274 contracts); **`Documentation/bpf/verifier.rst` (source 2, 3 anchored cases)**.
- **Also live (0023):** **patch-diff (source 4), partially** — as doc-vs-code
  staleness EVIDENCE qualifying source 2, not as an independent check.
- **Still a stub:** `verifier.c` state-transition logic (source 1).
- **Why it matters:** source 1 is a research problem in itself (parsing verifier
  semantics into checkable transitions). Source 4 remains partial for a *dependency*
  reason, not effort: a real cross-version behavioural diff needs observations from
  **two** kernel revisions and the lab builds one.
- **Also open within source 2:** only 3 documented claims are encoded. Each new case
  requires finding another sentence the document states OUTRIGHT — deliberately not
  inferred from prose.

---

---

*(OI-4 — `bpf_func_proto` slice curated rather than extracted — **CLOSED** 2026-08-28
by devlog 0021: `helper_proto::extract_from_tree` now generates the slice from the
kernel tree; 12 → 274 contracts, 8 → 194 helpers, validated with 0 false positives on
both volume captures.)*

---

## OI-5 — The extracted proto table is too large to audit by inspection

- **Status:** OPEN (low priority, but load-bearing when it matters)
- **Raised:** 2026-08-28 (review of devlog 0021)
- **What:** `data/groundtruth/helper_protos.tsv` holds **274 contracts across 194
  helpers**, generated by `helper_proto::extract_from_tree`. The *inclusion rule*
  (only `arg_type`s that pin exactly one verifier reg-type family) has been reviewed
  and tested. **The 274 individual contracts have not been, and cannot practically be,
  audited one by one.**
- **Why it matters (the failure mode):** a rule that is correct in general can still
  be wrong for a specific argument — e.g. an arg that legitimately accepts different
  reg types depending on program type, promoted to a strict contract. That produces a
  **false mismatch that looks exactly like a real finding**: "the verifier accepted a
  program violating its documented contract".
- **Standing instruction:** when the FIRST real `helper_arg_type_mismatch` appears,
  the extraction table is the **first suspect**, before the verifier. Confirm against
  `bpf_func_proto` in the tree and check whether the arg is program-type dependent,
  BEFORE reporting it as a verifier bug.
- **Partial mitigations in place:** the accept-only gate (a rejected program's
  mismatch is the verifier working, not a finding); 0 false positives across two real
  volume captures (~150 checks); the mapping table is small and commented.

---

## OI-6 — A documented divergence will have two possible causes

- **Status:** OPEN (standing triage instruction, not a defect)
- **Raised:** 2026-08-28 (review of devlog 0022)
- **What:** citation anchoring guarantees a documented sentence still EXISTS in
  `verifier.rst`; it cannot guarantee the sentence is still TRUE. So the first
  `documented_behavior_mismatch` has two candidate causes: a real verifier
  regression, or documentation that fell behind the code.
- **Evidence already attached (0023):** source 4 puts git facts on the finding —
  currently *"documentation last changed 2025-09-18, verifier.c last changed
  2026-08-18, 351 verifier.c commits since"*. The documentation is roughly eleven
  months and 351 verifier commits behind, so **stale prose is a live hypothesis, not
  a remote one**.
- **Standing instruction:** on the first divergence, check whether the specific
  behaviour changed in those commits (`git log -S` over the relevant verifier code)
  BEFORE reporting a regression.
- **Related:** OI-5 is the same shape for source 3 (extraction table first suspect).

---

## Coverage note — documented cases grow by hand, on purpose

Source 2 currently encodes **3** documented claims. Unlike `bpf_func_proto`
contracts, these cannot be auto-extracted: they are assertions embedded in prose, so
each new case means finding another sentence the document states OUTRIGHT. The
intended ceiling is **a few dozen high-value invariants, not hundreds** — coverage
here is curated depth, not breadth.
