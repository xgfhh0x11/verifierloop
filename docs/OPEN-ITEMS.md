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
  **Correction (reviewer, 2026-09-01):** WSL2 nested virtualization is **Windows
  11-specific** and does not work on Windows 10. An earlier expectation that it might
  work on Win10 was wrong and is retracted. So the Win11 migration is a genuine
  PRECONDITION for KVM, not an optional tweak — which also means this item cannot be
  settled by any amount of work inside the repo.

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

- **Status:** OPEN (medium priority) — *narrowed 2026-08-28 by devlog 0022,
  narrowed again 2026-09-01 by devlog 0024.*
- **Live now:** intrinsic invariants; helper `bpf_func_proto` (source 3, extracted —
  274 contracts); **`Documentation/bpf/verifier.rst` (source 2, 13 anchored cases —
  12 checked + 1 superseded)**.
- **Also live (0023):** **patch-diff (source 4), partially** — as doc-vs-code
  staleness EVIDENCE qualifying source 2, not as an independent check.
- **Still a stub:** `verifier.c` state-transition logic (source 1). **This is now the
  only stub**, and the next planned step is a pilot on ONE transition family (e.g.
  `check_alu_op` bounds) rather than the whole file — the point is to learn whether
  source 1 is mechanically extractable before investing in all of it.
- **Why it matters:** source 1 is a research problem in itself (parsing verifier
  semantics into checkable transitions). Source 4 remains partial for a *dependency*
  reason, not effort: a real cross-version behavioural diff needs observations from
  **two** kernel revisions and the lab builds one.

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
- **FIRST REAL INSTANCE (2026-09-01, devlog 0024) — and it was the documentation.**
  `doc_msg_uninit_stack_arg` (verifier.rst:398, "doesn't initialize stack before
  passing its address into function") is **accepted** by the tree. Cause located in
  the source, not guessed: `kernel/bpf/verifier.c:21141`
  `env->allow_uninit_stack = bpf_allow_uninit_stack(env->prog->aux->token)` →
  `bpf_token_capable(token, CAP_PERFMON)` (`include/linux/bpf.h:2869`). The documented
  rejection is **unprivileged-only** and the document states it unconditionally. So
  the first decision-level divergence this source produced was a documentation gap —
  exactly the outcome this item predicted. The case is now superseded (see OI-7),
  not deleted.
- **Related:** OI-5 is the same shape for source 3 (extraction table first suspect);
  OI-8 is the same shape for the source-2 harness programs.

---

## OI-7 — `superseded_by` is a silencer, and silencers create false negatives

- **Status:** OPEN (standing audit instruction, not a defect)
- **Raised:** 2026-09-01 (devlog 0024)
- **What:** a documented case may be silenced by a [`SourcePrecondition`] — a kernel
  source citation showing the documented claim does not apply to our load path. Today
  exactly **one** case is silenced this way (`doc_msg_uninit_stack_arg`, see OI-6).
- **Why it matters (the failure mode):** this is the only mechanism in the loop that
  can turn a real divergence into silence. A loosely chosen citation — one that is
  merely *nearby* the behaviour rather than *causing* it — would hide precisely the
  signal the leg exists to produce, and it would hide it permanently and quietly.
- **Guards already in place:** silencing needs a file + line + verbatim code text;
  `verifier_rst::load` re-checks that text is still in the tree on every load; a case
  whose citation disappears **revives by itself**; an unreadable source silences
  nothing; superseded cases are counted and printed with their reason, and are
  excluded from `documented_cases_checked` so they cannot inflate the denominator.
- **Standing instruction:** review the superseded list at every review, and require of
  each citation that it *causally* establishes the precondition. When in doubt, leave
  the case live and accept the false alarm — a visible false positive is cheaper than
  an invisible false negative.

---

## OI-8 — The documented-message programs carry translation judgements

- **Status:** OPEN (standing triage instruction, not a defect)
- **Raised:** 2026-09-01 (devlog 0024)
- **What:** the 11 examples in verifier.rst:353-560 are printed in `BPF_*` macro form,
  so transcription is exact — but the document leaves three things unstated, and
  `harness/diffharness.c` had to choose them (each marked JUDGEMENT at its case):
  a real map fd where the document writes `BPF_LD_MAP_FD(…, 0)` yet its own log shows
  a real map; `value_size = 16`, which the document never states; and the program type
  / load flag two cases need (`sched_cls` for the socket helpers, and
  `BPF_F_STRICT_ALIGNMENT`, without which x86's efficient-unaligned-access support
  makes the alignment claim inapplicable).
- **Why it matters:** a wrong choice here changes *which condition the program
  actually exercises*, so it can produce a mismatch that looks exactly like a real
  finding — the same shape as OI-5 for source 3.
- **Standing instruction:** on the first `documented_behavior_mismatch` from a
  `doc_msg_*` case, re-read that case's JUDGEMENT comment and confirm the program
  still reaches the documented condition BEFORE reporting a verifier bug.

---

## OI-9 — The targeted family covers one program SHAPE, not the input space

- **Status:** OPEN, **NARROWED 2026-09-01 by devlog 0026.** The 32<->64 half is done;
  what is listed below under "still not reached" is what remains.
- **Raised:** 2026-09-01 (devlog 0025)
- **Closed half (0026):** mixed-width programs now exist — four sub-families, 396
  programs (`mix#64-32`, `mix#32-64`, `mix#movsx*`, `mix#hi`), and the 32<->64
  denominator went from **0 to 353** on the real tree. Measured along the way: the
  obvious version of this (just interleaving widths) scored only **4** on bpf-next,
  because its deduction reconciles the two views almost perfectly whenever the value
  fits in one 2^32 block — and a ctx `u32` load always does. What actually reaches
  the region is `mix#hi`: shift the unknown bits into the UPPER half, then narrow only
  the lower one. Yield is still only ~18% of registers that print a 32-bit view.
- **Still not reached:** register-to-register ALU operands (a different verifier path
  from the immediate forms), multi-branch and looping control flow, pointer
  arithmetic, and `BPF_LD_IMM64` 64-bit constants.
- **What:** `diffharness --gen` enumerates `11 alu x 11 compare x {64,32}-bit` = 242
  programs, and that cross-product IS covered. But every one of them is the same
  8-instruction skeleton: one shaping op, one branch, one op per path, immediate
  operands only.
- **What it therefore does NOT reach:** register-to-register ALU (the immediate
  forms take a different verifier path from the register forms), multi-branch and
  looping control flow, pointer arithmetic, sign-extension moves (`movsx`), 64-bit
  immediates, and — most importantly — **32-bit and 64-bit operations mixed inside
  one program**. Each generated program is purely one width, so the reconciliation
  between `u32_min/u32_max` and the 64-bit bounds is exercised only across programs,
  never within one.
- **Why it matters:** "0 findings out of 1497 checks" is a real result, but it is a
  result about ONE program shape. Reading it as "the verifier's range tracking is
  sound" would be exactly the over-reading this file exists to prevent.
- **Next increment (highest value first):** register-register operands, then
  multi-branch flow. (Mixed-width and `movsx` were the previous two and are done.)

---

## Standing rule — a detector leg without a denominator is not measurable

- **Established:** 2026-09-01 (devlog 0025), the hard way.
- Sources 2 and 3 had reported denominators since 0022/0016. The **intrinsic leg
  never did**, and that hid the single most important fact about the corpus: across
  279 blocks of committed syzkaller volume the capture contains **zero** `var_off=`
  and **zero** `umin=`, so that leg had literally nothing to examine. Its
  "0 divergences" looked identical to the other legs' "0 out of 101" while being
  "0 out of 0".
- **The rule:** every leg reports how many times it was actually GIVEN something to
  check, and the denominator must exclude comparisons that cannot fail (see
  `diff::tnum_bounds_checkable` — a constant's tnum and bounds come from the same
  parsed token, so comparing them is a tautology and must not be counted).
- **Applies to source 1** when its pilot lands: no leg ships without its denominator.

---

## Coverage note — source 2's ceiling, MEASURED (corrected 2026-09-01)

Source 2 now encodes **13** documented claims (12 checked + 1 superseded). Unlike
`bpf_func_proto` contracts, these cannot be auto-extracted: they are assertions
embedded in prose, so each new case means finding another sentence the document
states OUTRIGHT.

**The earlier "a few dozen high-value invariants" target was wrong and is corrected
here.** It was an estimate, never a measurement. Measured (V14, devlog 0024): the
prose vein holds 7 candidate claims, 3 of them encoded, so ~4 remain; the message
vein holds 11 examples and **all 11 are now encoded**. The document's real ceiling is
therefore about **17 cases**, not "a few dozen" — and past that, growth in source 2
requires the *document itself* to grow, which is outside this project's control.
