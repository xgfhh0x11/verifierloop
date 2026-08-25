#!/usr/bin/env bash
# Generate a real syz-manager config from the lab layout (replaces the
# config/syzkaller/*.placeholder). QEMU vm type on TCG (no KVM here), focused on
# the eBPF verifier: enable_syscalls is restricted to bpf* (BPF_PROG_LOAD is where
# the verifier runs). syzkaller collects DEFAULT-mode output; normalization is a
# separate pipeline stage, never at the source.
#
#   scripts/gen-syz-config.sh            # -> .lab/syzkaller/manager.cfg
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
SYZ="$LAB/syzkaller"
OUT="${OUT:-$SYZ/manager.cfg}"

VMCOUNT="${VMCOUNT:-4}"     # parallel TCG VMs (raise to trade cores for throughput)
VMCPU="${VMCPU:-2}"
VMMEM="${VMMEM:-2048}"
PROCS="${PROCS:-4}"
HTTP="${HTTP:-127.0.0.1:56741}"
# TCG (no KVM on this host); thread=multi lets one VM use several host threads.
QEMU_ARGS="${QEMU_ARGS:--accel tcg,thread=multi -cpu qemu64}"

mkdir -p "$SYZ/workdir"

cat > "$OUT" <<JSON
{
  "target": "linux/amd64",
  "http": "$HTTP",
  "workdir": "$SYZ/workdir",
  "kernel_obj": "$LAB/build",
  "image": "$LAB/images/rootfs.img",
  "sshkey": "$LAB/images/vm-id_ed25519",
  "syzkaller": "$SYZ",
  "procs": $PROCS,
  "sandbox": "none",
  "type": "qemu",
  "enable_syscalls": ["bpf*"],
  "vm": {
    "count": $VMCOUNT,
    "kernel": "$LAB/build/bzImage",
    "cpu": $VMCPU,
    "mem": $VMMEM,
    "qemu_args": "$QEMU_ARGS"
  }
}
JSON

echo "[syz-cfg] wrote $OUT"
echo "[syz-cfg] vm.count=$VMCOUNT cpu=$VMCPU mem=$VMMEM procs=$PROCS accel=TCG focus=bpf*"
