#!/usr/bin/env bash
# COMPOSITION GENERATOR (--gen-comp) — random compositions of the pieces built across
# 0043-0053, with the oracles held fixed.
#
# WHY: every family before this produces shapes whose bug class can be NAMED, so "clean"
# has only meant "clean on the shapes I thought to write". Random composition starts to
# say something about shapes nobody named.
#
# THE HARD PART IS VALIDITY. A randomly concatenated program is almost always rejected and
# never reaches the runtime oracles — a denominator-zero trap one layer above the ones
# 0041-0050 kept finding. The generator therefore walks a typed CONTEXT: each piece
# declares what it REQUIRES of the live state and what it PROVIDES, and only pieces whose
# requirements hold are offered. dynptr is the piece that forces the context to be richer
# than register types: it consumes a STACK_DYNPTR slot pair tracked by id and yields a
# PTR_TO_MEM plus an OFFSET into the map value that the store's declared offset must be
# expressed in (0053's coordinate translation, generalised).
#
# THE NUMBER TO WATCH IS NOT THE ACCEPT RATE — a rejection is a legitimate verdict. It is
# the SPLIT of rejection reasons: every rejection should be BOUNDS-related ("Add or adjust
# a bounds check"), and STRUCTURAL rejections (uninitialised register, unreachable
# instruction, invalid instruction) should be ZERO. A structural rejection means the walk
# emitted garbage the oracle can never see.
#
# Seeds are fixed and printed per program, so the corpus is reproducible and any single
# program can be replayed on its own.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
LOG="$REPO_ROOT/.lab/harness-comp-out.log"

echo "[run-comp] building harness + running --gen-comp in the VM ..."
HARNESS_ARGS=--gen-comp TIMEOUT=180 scripts/run-harness-vm.sh "$LOG"

echo
echo "=== validity: rejection reasons must be semantic, never structural ==="
printf "programs               : %s\n" "$(grep -c '^RESULT' "$LOG")"
printf "accepted               : %s\n" "$(grep -c 'RESULT decision=accept' "$LOG")"
printf "rejected (bounds)      : %s\n" "$(grep -c 'Add or adjust a bounds check' "$LOG")"
printf "rejected (STRUCTURAL)  : %s   <- must be 0\n" \
  "$(grep -cE 'Initialize R|unreachable instruction|invalid ' "$LOG" || true)"

echo
echo "=== novelty: distinct compositions the walk produced ==="
grep -oE "recipe=[a-z,]*" "$LOG" | sort | uniq -c | sort -rn | head -15
printf "distinct recipes: %s\n" "$(grep -oE 'recipe=[a-z,]*' "$LOG" | sort -u | wc -l)"

echo
echo "=== pipeline measurement (the numbers) ==="
MEASURE_LOG="$LOG" cargo test -p pipeline --test measure_log -- --ignored --nocapture 2>&1 | grep -E "MEASURE"
