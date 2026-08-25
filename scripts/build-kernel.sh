#!/usr/bin/env bash
# Build a self-built bpf-next bzImage for the verifier lab: BPF+JIT, KCOV, the
# sanitizers, and DEBUG_INFO_BTF (needs pahole), plus the KVM-guest bits so it
# boots under QEMU. Config = x86_64 defconfig + kvm_guest.config + the lab
# fragment (config/kernel/bpf-verifier-lab.config), resolved with olddefconfig.
#
#   scripts/build-kernel.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$REPO_ROOT/.lab}"
SRC="$LAB/bpf-next"
FRAG="$REPO_ROOT/config/kernel/bpf-verifier-lab.config"
JOBS="${JOBS:-$(nproc)}"

[ -d "$SRC/.git" ] || { echo "[build] no source at $SRC — run scripts/fetch-kernel.sh first" >&2; exit 1; }
command -v pahole >/dev/null 2>&1 || { echo "[build] pahole (dwarves) required for DEBUG_INFO_BTF" >&2; exit 1; }

echo "[build] pahole $(pahole --version 2>/dev/null) | gcc $(gcc -dumpfullversion) | -j$JOBS"
cd "$SRC"

# 1. Base config: x86_64 defconfig, then merge the KVM-guest fragment shipped in
#    the kernel tree, then our lab fragment, then resolve everything.
make -j"$JOBS" defconfig
make -j"$JOBS" kvm_guest.config
./scripts/kconfig/merge_config.sh -m .config "$FRAG"
make -j"$JOBS" olddefconfig

# 2. Sanity: the symbols we depend on actually survived olddefconfig.
echo "[build] key symbols after olddefconfig:"
for s in CONFIG_BPF_SYSCALL CONFIG_BPF_JIT CONFIG_BPF_JIT_ALWAYS_ON \
         CONFIG_KCOV CONFIG_KASAN CONFIG_KCSAN CONFIG_UBSAN CONFIG_DEBUG_INFO_BTF; do
  if grep -q "^$s=y" .config; then printf '  %-28s = y\n' "$s"; else printf '  %-28s !! NOT ENABLED\n' "$s"; fi
done

# 3. Build.
make -j"$JOBS" bzImage

BZ="arch/x86/boot/bzImage"
[ -f "$BZ" ] || { echo "[build] bzImage not produced" >&2; exit 1; }

mkdir -p "$LAB/build"
cp "$BZ" "$LAB/build/bzImage"
[ -f vmlinux ] && cp vmlinux "$LAB/build/vmlinux" || true
cp .config "$LAB/build/kernel.config"

# 4. Verify BTF is embedded in the FINAL artifact (the point of the pahole
#    prerequisite). Authoritative confirmation is in-VM (/sys/kernel/btf/vmlinux,
#    checked by scripts/verify-vm.sh); this is the static cross-check.
if readelf -S "$LAB/build/vmlinux" 2>/dev/null | grep -qE '\.BTF([[:space:]]|_ids)'; then
  echo "[build] .BTF section present in vmlinux (confirm in-VM with verify-vm.sh)"
else
  echo "[build] WARNING: no .BTF section in $LAB/build/vmlinux"
fi
echo "[build] bzImage  -> $LAB/build/bzImage ($(du -h "$BZ" | cut -f1))"
echo "[build] vmlinux  -> $LAB/build/vmlinux"
echo "[build] config   -> $LAB/build/kernel.config"
echo "[build] revision -> $(cat "$LAB/kernel.rev" 2>/dev/null || echo unknown)"
