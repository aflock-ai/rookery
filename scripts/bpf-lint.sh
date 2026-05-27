#!/usr/bin/env bash
# Compile-lint the eBPF object source with the SAME strict flags the
# runtime rebuild path uses (clang -Wall -Werror -target bpf). This is a
# fast fail before the full pipeline / before a program ever reaches the
# kernel verifier (which is the authoritative safety check at load time).
#
# Requires: clang, bpftool, libbpf-dev, and a BTF-enabled kernel
# (/sys/kernel/btf/vmlinux) to generate the CO-RE vmlinux.h.
set -euo pipefail

SRC="plugins/attestors/commandrun/ebpf/bpf/openat_kprobe.bpf.c"
[ -f "$SRC" ] || { echo "bpf-lint: $SRC not found (run from repo root)" >&2; exit 1; }

for tool in clang bpftool; do
	command -v "$tool" >/dev/null 2>&1 || { echo "bpf-lint: $tool not on PATH" >&2; exit 1; }
done
[ -r /sys/kernel/btf/vmlinux ] || { echo "bpf-lint: /sys/kernel/btf/vmlinux unreadable (need CONFIG_DEBUG_INFO_BTF)" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# CO-RE vmlinux.h matched to the running kernel's BTF.
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$TMP/vmlinux.h"

case "$(uname -m)" in
	x86_64)  ARCH_DEF="-D__TARGET_ARCH_x86";   INC="/usr/include/x86_64-linux-gnu" ;;
	aarch64) ARCH_DEF="-D__TARGET_ARCH_arm64"; INC="/usr/include/aarch64-linux-gnu" ;;
	*) echo "bpf-lint: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

clang -g -O2 -Wall -Werror -target bpf "$ARCH_DEF" \
	-I "$TMP" -I "$INC" \
	-c "$SRC" -o "$TMP/openat_kprobe.bpf.o"

echo "bpf-lint: $SRC compiles clean (clang -Wall -Werror -target bpf, $(uname -m))"
