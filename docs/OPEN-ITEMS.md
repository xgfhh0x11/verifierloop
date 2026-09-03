# Open items — tracked, not blocking

Findings and hypotheses that are **deliberately left open** rather than closed or
dropped. Each says *why* it is open, what would settle it, and its priority. This
file exists so an unresolved item cannot quietly become a settled one.

Closed items are removed from here and their resolution recorded in the devlog.

---

## OI-1 — Two `int3` crashes: artifact hypothesis is FALSIFIABLE; KVM-TESTED BUT NULL STILL VOID

- **Status:** OPEN (low priority). *Not* "diagnosed and closed." **Now KVM-tested but
  the null is still VOID** — see the 2026-09-03 update.
- **Raised:** 2026-08-28 (devlog 0020)
- **Update (2026-09-03, devlog 0028):** KVM is available (0027) so the block is no
  longer the accelerator — it is now **pipeline instability**. Across five KVM
  campaigns this turn, **int3 never recurred** (~0.67M cumulative execs), which
  *supports* the TCG-artifact hypothesis. BUT the pre-registered criterion (one CLEAN
  run clearing exec ≥ 150k; a self-crashing campaign voids the null) was **never met**:
  every campaign eventually self-crashed. Three poisons were fixed (binfmt, F1 panic,
  `PROG_TEST_RUN` RCU stall = OI-11) and a fourth contained (reproduction-starvation =
  OI-12), but an underlying elevated VM-death rate under nested KVM degrades every long
  run. So the int3=0 result is **suggestive, not sufficient**; OI-1 stays open. Cheapest
  next probe: a **single-VM** KVM campaign (removes 8-VM contention; also one of OI-1's
  original partial discriminators).
- **Update (2026-09-03, devlog 0029) — single-VM probe RUN, also VOID:** it was
  *worse*, not better — **31 VM disconnects in 30 min**, corpus triage NEVER completed
  (candidates stuck at 1057), only **~4.2k execs** (35x under the 150k bar). So the
  instability is NOT 8-VM contention: even one VM disconnects constantly under
  sustained load. (Confound: this probe also raised VMCPU 2→4 / VMMEM 2048→4096; the
  pre-registered hard-stop forbade a re-run to disambiguate, and the conclusion holds
  either way.) **Verdict:** WSL2 nested-KVM on this host cannot sustain a productive
  syzkaller campaign, so OI-1 cannot be settled on the syzkaller path here. int3=0
  across ~0.68M cumulative execs is accepted as **SUGGESTIVE** of the TCG-artifact
  hypothesis, not proof. OI-1 stays open at low priority; a real settling needs
  bare-metal or a non-nested KVM host (outside this repo's control, like the original
  Win11 precondition).
- **Superseded block (kept for history) — Blocked by:** KVM unavailable on this host (probed 2026-08-28: `/dev/kvm` exists
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
  what is listed below under "still not reached" is what remains. Register-register operands are now DONE (2026-09-01): the reg-reg leg (`--gen-rr`, 242 programs, all accepted) scores tnum_bounds_checked=**2453** — the largest denominator of any family (single-width 1497, mixed >1500) — with 0/2453 divergences and 0 parser blind-spots; pinned in `crates/pipeline/tests/register_register_calibration.rs`. reg-reg is a different axis from 32<->64 (reg32_checked=0). **Multi-branch/multi-merge now DONE (2026-09-03, devlog 0029):** the `--gen-mb` family (242 programs, all accepted, two sequential branches + two merge points) scores tnum_bounds_checked=**2050**, 0/2050 divergences, 0 parser blind-spots, reg32_checked=0; pinned in `crates/pipeline/tests/multi_branch_calibration.rs`. True *looping* (back-edges) is still open. **Pointer arithmetic now DONE — FIRST increment (2026-09-03, devlog 0030):** `--gen-ptr` (242 programs, map_value ptr += bounded scalar, then a STORE through it — the OOB-*write* decision) is a genuine accept/reject surface: **34 accept / 208 reject** (199 EACCES + 9 EINVAL diagnostics-path), tnum_bounds_checked=**1191** (on the scalar offset AND the pointer's own var_off), 0 divergences, **0 parser blind-spots** (robust first run); pinned in `crates/pipeline/tests/pointer_arith_calibration.rs`. This first increment is 1-byte store + map-value only. **Packet pointer now DONE — FIRST increment (2026-09-03, devlog 0031):** `--gen-pkt` (242 programs, SCHED_CLS; `data += bounded scalar`, then the program's own `if data+1 > data_end` compare, then a STORE) exercises the OTHER pointer kind — a bound the PROGRAM proves and the verifier statically tracks as `range` (`find_good_pkt_pointers`). **49 accept / 193 reject** (184 EACCES = the MAX_PACKET_OFF guard, + the same 9 EINVAL indices as map-value → a scalar-shaping property), tnum_bounds_checked=**1254**, 0 divergences, 0 blind-spots; the static range is visible in the log (`r=0` → `r=16` across the compare). Pinned in `crates/pipeline/tests/packet_pointer_calibration.rs`. Corrected along the way: NO runtime `data_end`-fixing mechanism is needed — the decision is load-time static. **Packet `data_end` compare-op sweep (T1-3) now DONE (2026-09-03, devlog 0032):** `--gen-pkt-cmp` (240 programs, SCHED_CLS; offset shaping pinned to `r4 &= 7` so the decision is a pure function of the range machinery; grid form{gt,ge,lt,le} × headroom M(1..5) × store-offset(0..3) × width{1,2,4}B) isolates `find_good_pkt_pointers`' two historically bug-prone axes. **128 accept / 112 reject**, per form gt=27/ge=37/lt=27/le=37; **operand-order symmetry holds exactly** (gt==lt, ge==le) and the **closed vs right-open boundary differs by EXACTLY one byte** — all 240 decisions match `accept ⟺ off+W ≤ range` with closed range=M, right-open range=M+1, 0 exceptions; tnum_bounds_checked=**720**, 0 divergences, 0 blind-spots. The verifier proves precisely what the program checked — no off-by-one on this kernel. Pinned in `crates/pipeline/tests/packet_compare_calibration.rs` (5 tests). **Negative-offset map-value smin path (T1-2) now DONE (2026-09-03, devlog 0033):** `--gen-ptr-neg` (120 programs; `r1 &= 15; r1 -= C` pushes smin to -C; form{raw = no guard, grd = `if r1 s<0 goto skip`} × C(10) × reach(6)) drives the LOWER bound — an OOB-*below* write. **60 accept / 60 reject**; raw=4/60 (every accept is C==0 — NO negative-capable store is accepted) and grd=56/60 (the signed guard rescues, so the verifier is not merely over-rejecting). Decision predicate matches all 120 with 0 exceptions; the "R0 min value is negative" check is exercised and enforced; tnum_bounds_checked=**438**, 0 divergences, 0 blind-spots. Verdict: the smin lower-bound check is enforced — no OOB-below accept on this kernel; pinned in `crates/pipeline/tests/pointer_neg_calibration.rs`. **32<->64 × pointer-offset, SOUNDNESS HALF (T1-1a) now DONE (2026-09-03, devlog 0034):** setup decided by measurement (the `--probe-t1` three-claim probe: naive 32-bit shaping zero-extends → reg32=0, the 0025 trap; 32-bit ALU on a pointer is prohibited outright → Option B dead; only the "hi" upper-unknown construction reaches the surface). `--gen-ptr-hi` (52 programs = hi{cons(2)×cmp(5)×K(4)}=40 + bnd{mask(3)×reach(4)}=12) is the **first family to lift reg32_checked off zero in a pointer context: reg32_checked=52, ENTIRELY from the hi arm (bnd=0)**. hi is all-reject (0/40 accept — mutual exclusivity: reg32>0 ⟺ upper-unknown ⟺ reject; a reviewer's K<value_size idea was ruled out pre-build as it yields the empty set in hi), rejecting at `adjust_ptr_min_max_vals` (verifier.c:14665, on the 64-bit `off_reg` bounds — the verifier structurally never consults u32/s32 for a pointer offset). bnd=8/12 accept (control: not over-rejecting). 0 divergences, 0 blind-spots; pinned in `crates/pipeline/tests/pointer_hi_calibration.rs`. **The DISCRIMINATING half (T1-1b) now DONE (2026-09-04, devlog 0035, `--gen-sync`):** the CVE-2020-8835 class desync guard. The 0034 prediction was CORRECTED — NO new oracle arm was needed: reviewing fix commit `f2d67fec0b43` (`__reg_bound_offset32`) showed the desync is EXACTLY the existing invariant B (`tnum32_bounds_inconsistent`, diff.rs) — the buggy code clamped the tnum low-32 to {0} while u32 compares set [0x200,0x400], so tnum32=[0,0] vs u32=[512,1024] are disjoint → B fires. So T1-1b was ONE job: a sync-fragile family reusing B, not a new invariant. `--gen-sync` (24 programs = cve{pair×win}=16 + shift{win×pol}=8; SYNC_WIN[0]=[0x200,0x400] the historical CVE window) drives the verifier into the narrowed 32↔64 state; the programs are trivially safe (`MOV r0,0; EXIT` after narrowing) so the surface is the register STATE, not the decision — **24 accept / 0 reject**. **reg32_checked=56 (cve=32, shift=24), finding_count=0**: B ran across all sync states (a regression WOULD fire) and stayed silent (the 32↔64 views are consistent = a working guard, no false positives). The sharp result: **all 56 checkable scalar-states are multi-block** (umin>>32≠umax>>32), so invariant C (single-block gated) is disabled throughout and B is the SOLE live guard — exactly why CVE-2020-8835 was historically catchable only by the tnum-vs-u32 redundancy (pre-5.7 had no separate u32 bounds). 0 divergences, 0 blind-spots; pinned in `crates/pipeline/tests/sync_calibration.rs` (6 tests). Bound: the consistency oracle catches DESYNC; a "consistent-but-wrong" corruption (both views wrong identically) is the deferred (b) differential-recompute territory — CVE-2020-8835 was a desync, so it is in B's scope. Still open from T1-1: wider map-value stores (2/4/8B) and the EINVAL sub-family; true looping (back-edges).
- **Raised:** 2026-09-01 (devlog 0025)
- **Closed half (0026):** mixed-width programs now exist — four sub-families, 396
  programs (`mix#64-32`, `mix#32-64`, `mix#movsx*`, `mix#hi`), and the 32<->64
  denominator went from **0 to 353** on the real tree. Measured along the way: the
  obvious version of this (just interleaving widths) scored only **4** on bpf-next,
  because its deduction reconciles the two views almost perfectly whenever the value
  fits in one 2^32 block — and a ctx `u32` load always does. What actually reaches
  the region is `mix#hi`: shift the unknown bits into the UPPER half, then narrow only
  the lower one. Yield is still only ~18% of registers that print a 32-bit view.
- **Still not reached:** **looping** control flow (back-edges), `BPF_LD_IMM64`
  64-bit constants, the **stack** pointer, the DISCRIMINATING 32<->64 × pointer-offset
  test (T1-1b — the CVE-2020-8835-class sync arm, needs a new 32↔64-sync oracle leg;
  T1-1a soundness half DONE 2026-09-03), and the map-value family's WIDER store surface
  (2/4/8-byte stores). (reg-reg
  DONE 2026-09-01; multi-branch DONE 2026-09-03; map-value pointer AND packet pointer
  FIRST increments DONE 2026-09-03; packet `data_end` compare-op sweep — jgt/jge/jlt/jle
  → `range_right_open` — DONE 2026-09-03 as T1-3, devlog 0032: symmetric, one-byte-exact,
  0/720 divergence; map-value negative offset / smin lower-bound — DONE 2026-09-03 as
  T1-2, devlog 0033: enforced, no OOB-below accept, 0/438 divergence.)
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
- **Next increment (highest value first):** the packet `data_end` **compare-operator
  sweep** (jgt/jge/jlt/jle → the `range_right_open` off-by-one edge, the kernel's own
  densest packet-bounds bug region), then wider stores (2/4/8-byte) on both pointer
  families, the shared 9-EINVAL signed-compare sub-family, then looping (back-edges —
  a separate leg, needs a provably-bounded counter). (scalar imm, reg-reg, mixed-width,
  `movsx`, multi-branch, map-value pointer, packet pointer: all first increments done.)

---

## OI-10 — The capture transport is shared with the kernel, and the repair is a mitigation

- **Opened:** 2026-09-01 (devlog 0027).
- **What:** the harness and syzreplay both capture their output over the VM's serial
  console (`console=ttyS0`), which the kernel also writes to. A printk can land in
  the MIDDLE of a verifier line. `repair_console_interleaving` now mends this and
  NOTES it, and three tests pin the behaviour against verbatim real captures.
- **Why this stays open:** the repair rests on an ASSUMPTION about how the
  interleaving looks — that the printk carries its own newline and the original
  line's remainder resumes on the next one. Both shapes observed so far obey it. A
  printk emitted without a trailing newline, or two CPUs interleaving into the same
  line, would not, and the repair would then mis-join rather than mend. It is a
  mitigation for a lossy transport, not a guarantee.
- **The real fix** is to stop sharing the transport: give the harness its own
  channel (a dedicated virtio-serial port, or write the output to a file inside the
  rootfs and pull it off the image afterwards) so kernel messages cannot reach it at
  all. Then the repair becomes a belt-and-braces check instead of a load-bearing one.
- **Measured impact so far (why this is not urgent):** across seven committed
  captures there are 7 interleavings; 6 are whole console lines (harmless) and 1 is
  a real mid-line splice (`syz-replay-184.log:5094`). CORE metrics over 885 records
  are BYTE-IDENTICAL before and after the fix — the one real splice happened to land
  on an indented line the parser already skips. Past results stand, but **by luck,
  not by design**, which is precisely why the transport should not stay shared.
- **Frequency scales with runs:** KVM (devlog 0027) makes runs cheap, so the absolute
  number of interleavings will grow even though the rate does not.

---

## OI-11 — `BPF_PROG_TEST_RUN` high-`repeat` trips the RCU-stall detector under KCOV+KASAN

- **Opened:** 2026-09-03 (devlog 0028), during the OI-1 clean-retest attempt.
- **Status:** OPEN (contained, not a target bug). Pipeline-side containment applied;
  the "is it a real DoS" question is left open deliberately.
- **What:** with `enable_syscalls: ["bpf*"]`, syzkaller reaches
  `bpf$BPF_PROG_TEST_RUN` and issues it with a large `repeat`. On our KCOV+KASAN
  kernel every basic block is instrumented (`__sanitizer_cov_trace_pc`), so the
  program-execution loop (`bpf_test_timer_continue`, `net/bpf/test_run.c:83`, via
  `bpf_test_run` / `bpf_prog_test_run_skb`, `kernel/bpf/syscall.c:4804`) runs long
  enough to cross the 21s RCU-stall threshold (`t=21002 jiffies`). syzkaller saves
  the coverage-raising program to the corpus and replays it on every VM, so ONE
  such program wedges all 8 VMs → an `INFO: rcu detected stall in sys_bpf` followed
  by a `SYZFAIL: repeatedly failed to execute the program` cascade; throughput fell
  ~720 → 70 exec/s. This is what poisoned the 0028 OI-1 retest (see below).
- **Why it is NOT a target bug, twice over:** (1) `PROG_TEST_RUN` is program
  EXECUTION, not verification — off the verifier surface the loop hunts; (2) the
  stall is a well-known KCOV+KASAN instrumentation artifact — the loop reschedules
  cooperatively, so it is a soft "stall", not a hang, and vanishes on a
  non-instrumented kernel.
- **Containment (devlog 0028):** `disable_syscalls: [bpf$BPF_PROG_TEST_RUN,
  bpf$BPF_PROG_TEST_RUN_LIVE, bpf$auto_BPF_PROG_TEST_RUN]` in
  `scripts/gen-syz-config.sh`. This AIMS the input budget at the verifier
  (`oracle × input` rule: aim, don't just enlarge) rather than merely enlarging it.
  A first `disable_syscalls: ["bpf$*TEST_RUN*"]` glob was rejected
  (`[FATAL] unknown disabled syscall`) — syzkaller wants recognized names, so the
  three exact variants are listed.
- **Left open on purpose:** whether an *uninstrumented* kernel also lets a crafted
  `repeat`/program make `PROG_TEST_RUN` run unreasonably long (a genuine local DoS)
  is a separate question this containment does NOT answer — it only removes the
  artifact from the verifier hunt. Not chased now; not the target class.

---
## OI-12 — syzkaller reproduction-starvation on executor/infra failures under nested KVM

- **Opened:** 2026-09-03 (devlog 0028), during the OI-1 powered retest.
- **Status:** OPEN. Containment applied (ignore the infra-failure title so it is not
  reproduced); efficacy PARTIAL (measured): it stops the `repeatedly failed` reproduction loop
  (0 afterward), but smoke4 showed reproduction just shifts to `lost connection` and
  the underlying VM-death rate persists (16 lost-connections in 6 min, throughput
  851→79 exec/s). The root cause is environment-level, below any single ignore.
- **What:** after F1 and the PROG_TEST_RUN stall (OI-11) were contained, a 20-min KVM
  campaign was healthy for ~2 min (~700 exec/s, peak 988) then **progressively
  degraded** (700→260→120→7 exec/s) and sat dead for its final ~10 min. No int3,
  **no rcu stall, no kernel crash report** was saved (b83ebc/9deb carry no
  OOM/hung-task/lockup signature; host memory stayed at 18 GB free). The manager log
  shows the trigger: at 04:24:56 syzkaller `start reproducing 'SYZFAIL: repeatedly
  failed to execute the program'`, and throughput fell immediately after. syzkaller
  dedicates VMs to REPRODUCING an executor/infra failure that is not a reproducible
  kernel bug; those VMs leave the fuzzing pool, the remaining VMs fail more, more
  reproduction is queued → a starvation cascade (47 `repeatedly failed` over the run).
  Same shape as F1's reproduction churn, one layer down.
- **Why "repeatedly failed to execute" is infra, not a kernel bug:** it is syz-executor
  in the guest failing to run programs, not a verifier/kernel fault. It never produces
  a symbolized crash; it is `[suppressed]` for SAVING but was still being REPRODUCED.
- **Containment (devlog 0028):** add `"SYZFAIL: repeatedly failed to execute the
  program"` to `ignores` so it is never reproduced (reproduction, not saving, is what
  starved the pool). Deliberately NOT ignoring `"lost connection to test machine"` —
  that can signal a real kernel hang and must stay visible; int3 is symbolized
  separately and is unaffected by these ignores.
- **The deeper open question:** WHY do executor failures accumulate over ~10 min at
  all? Leading hypothesis: nested-virt (WSL2→KVM→QEMU) VM instability under sustained
  8-VM load, and/or slow guest resource accumulation under KASAN in 2 GB guests. The
  ignore removes the *starvation amplifier*; it does not prove the underlying failure
  rate is acceptable. Cheap next probes (not yet run): raise `VMMEM` 2048→4096; lower
  `VMCOUNT` 8→4 to reduce nested-virt contention; enable periodic VM reboots.
- **Impact on OI-1:** every KVM campaign so far self-crashes before a single
  CLEAN run clears the pre-registered 150k-exec bar; int3 has NOT recurred across
  ~0.5M cumulative execs (suggestive of the TCG-artifact hypothesis) but no run met
  the clean-powered criterion, so OI-1 stays OPEN.

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
