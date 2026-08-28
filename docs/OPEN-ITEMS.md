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

## OI-3 — Three of five ground-truth sources are still stubs

- **Status:** OPEN (medium priority)
- **What:** `verifier.c` state-transition logic, `Documentation/bpf/verifier.rst`, and
  cross-version patch diffs have no loaders (`crates/pipeline/src/groundtruth/`).
  Only the helper `bpf_func_proto` slice (curated, partial) and the intrinsic
  invariants are live.
- **Why it matters:** the detector has two legs; three documented sources are unused,
  so whole classes of documented-vs-observed divergence cannot be seen at all.

---

---

*(OI-4 — `bpf_func_proto` slice curated rather than extracted — **CLOSED** 2026-08-28
by devlog 0021: `helper_proto::extract_from_tree` now generates the slice from the
kernel tree; 12 → 274 contracts, 8 → 194 helpers, validated with 0 false positives on
both volume captures.)*
