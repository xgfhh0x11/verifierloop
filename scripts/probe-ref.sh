#!/usr/bin/env bash
# Calibrate the reference interpreter (harness/bpfref.h) against the real kernel.
#
# bpfref.h exists so the intent oracle has a reference that never consults the kernel — but
# a second implementation is only worth having if it agrees with the first everywhere the
# first is right. This runs the sixteen places a naive interpreter goes wrong (32-bit
# zero-extension, JMP32's low-half compare, x/0 and x%0, S64_MIN sdiv -1, DW immediate
# sign-extension, MEMSX vs plain loads, MOVSX in each ALU class, LD_IMM64's two slots, the
# signed off field) through BOTH and requires every one to match.
#
# Every line must end verdict=agree. `not-run` means the program was rejected at load and
# the trap measured nothing — fix the program, do not read it as agreement. `DISAGREE` is
# the only interesting outcome, and the suspect order is: the trap program, then bpfref,
# then the kernel.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="${1:-$REPO_ROOT/.lab/harness-ref.log}"
HARNESS_ARGS=--probe-ref TIMEOUT="${TIMEOUT:-120}" scripts/run-harness-vm.sh "$LOG" >/dev/null
grep -oE 'name=[a-z0-9_]+ .*verdict=[A-Za-z-]+' "$LOG" |
  sed 's/name=//' | awk '{printf "  %-34s %s\n", $1, $NF}'
echo "  ---"
grep -oE 'verdict=[A-Za-z-]+' "$LOG" | sort | uniq -c | sed 's/^/  /'
grep -q 'verdict=DISAGREE' "$LOG" && { echo "  DISAGREEMENT — triage: trap program, then bpfref, then the kernel" >&2; exit 1; }
grep -q 'verdict=not-run' "$LOG" && { echo "  a trap did not run — it measured nothing" >&2; exit 1; }
echo "  reference interpreter calibrated"
