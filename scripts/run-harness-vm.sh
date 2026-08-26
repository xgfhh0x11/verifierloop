#!/usr/bin/env bash
# Run the differential/verifier-log harness INSIDE the disposable bpf-next VM and
# capture its DEFAULT native output on the host. Mirrors verify-vm.sh: an init
# script + serial console (no ssh/networking). The harness binary is injected into
# the rootfs via loop-mount; the boot itself uses -snapshot, so the VM's own writes
# stay ephemeral. This doubles as the in-VM authoritative capture of the verifier
# log format on our self-built kernel.
#
#   scripts/run-harness-vm.sh [OUTFILE]      # default OUTFILE: .lab/harness-out.log
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
ROOTFS="${ROOTFS:-$LAB/images/rootfs.img}"
OUT="${1:-$LAB/harness-out.log}"
SERIAL="$LAB/harness-serial.log"
TIMEOUT="${TIMEOUT:-180}"

# 1. fresh static harness binary
"$REPO_ROOT/scripts/build-harness.sh" >/dev/null
BIN="$REPO_ROOT/harness/diffharness"
[ -x "$BIN" ]     || { echo "[harness-vm] no harness binary at $BIN" >&2; exit 1; }
[ -f "$ROOTFS" ]  || { echo "[harness-vm] no rootfs at $ROOTFS" >&2; exit 1; }

# 2. inject binary + init wrapper into the rootfs (loop-mount; persists on base img)
MNT="$(mktemp -d)"
cleanup() { mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" || true; rmdir "$MNT" 2>/dev/null || true; }
trap cleanup EXIT
mount -o loop "$ROOTFS" "$MNT"
install -m755 "$BIN" "$MNT/root/diffharness"
cat > "$MNT/root/run-harness.sh" <<'EOS'
#!/bin/sh
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
echo "===HARNESS-BEGIN==="
/root/diffharness
echo "===HARNESS-END==="
poweroff -f 2>/dev/null || { echo 1 > /proc/sys/kernel/sysrq 2>/dev/null; echo o > /proc/sysrq-trigger; }
EOS
chmod +x "$MNT/root/run-harness.sh"
sync
cleanup
trap - EXIT

# 3. boot (TCG), init = harness wrapper, capture serial console
echo "[harness-vm] booting (tcg), timeout ${TIMEOUT}s ..."
ACCEL=tcg \
APPEND="console=ttyS0 root=/dev/vda rw panic=1 oops=panic init=/root/run-harness.sh" \
  timeout "$TIMEOUT" "$REPO_ROOT/scripts/boot-vm.sh" >"$SERIAL" 2>&1 || true

# 4. extract the harness native output between the markers
if grep -q "===HARNESS-BEGIN===" "$SERIAL" && grep -q "===HARNESS-END===" "$SERIAL"; then
  sed -n '/===HARNESS-BEGIN===/,/===HARNESS-END===/p' "$SERIAL" | sed '1d;$d' | tr -d '\r' > "$OUT"
  echo "[harness-vm] captured $(grep -c '===PROG' "$OUT" || echo 0) program block(s) -> $OUT"
else
  echo "[harness-vm] FAILED: markers not found. Last 30 serial lines:" >&2
  tail -30 "$SERIAL" >&2
  exit 1
fi
