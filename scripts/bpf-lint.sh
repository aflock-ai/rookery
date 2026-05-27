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

command -v clang >/dev/null 2>&1 || { echo "bpf-lint: clang not on PATH" >&2; exit 1; }
[ -r /sys/kernel/btf/vmlinux ] || { echo "bpf-lint: /sys/kernel/btf/vmlinux unreadable (need CONFIG_DEBUG_INFO_BTF)" >&2; exit 1; }

# Resolve a REAL bpftool the same way the runtime rebuild path does
# (rebuild_linux.go: findBpftool). Ubuntu's /usr/sbin/bpftool is a
# version-dispatch wrapper that, when its kernel-matched linux-tools
# package is absent, still "works" but can emit an incomplete vmlinux.h
# (e.g. a struct pt_regs missing the x86 di/si/dx register fields),
# which makes the CO-RE PT_REGS_* macros fail to compile. The real
# binaries shipped by linux-tools-generic live under
# /usr/lib/linux-tools/<kver>/bpftool — prefer those.
BPFTOOL=""
for cand in /usr/lib/linux-tools/*/bpftool /usr/lib/linux-tools-*/bpftool /snap/bin/bpftool; do
	[ -x "$cand" ] && { BPFTOOL="$cand"; break; }
done
[ -n "$BPFTOOL" ] || BPFTOOL="$(command -v bpftool || true)"
[ -n "$BPFTOOL" ] || { echo "bpf-lint: no bpftool found (need linux-tools-generic)" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# CO-RE vmlinux.h matched to the running kernel's BTF.
"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$TMP/vmlinux.h"

# Guard against a partial dump: the x86/arm64 PT_REGS_* CO-RE macros
# need a complete struct pt_regs, but a stub/mismatched bpftool can emit
# a truncated header whose pt_regs lacks the register fields — surfacing
# later as a confusing "no member named 'di'" deep in a macro expansion.
# A real kernel vmlinux.h is multiple MB; flag a suspiciously small dump.
dump_lines="$(wc -l < "$TMP/vmlinux.h")"
if [ "$dump_lines" -lt 10000 ]; then
	echo "bpf-lint: dumped vmlinux.h is only $dump_lines lines — wrong/stub bpftool ($BPFTOOL)?" >&2
	exit 1
fi

case "$(uname -m)" in
	x86_64)  ARCH_DEF="-D__TARGET_ARCH_x86";   INC="/usr/include/x86_64-linux-gnu" ;;
	aarch64) ARCH_DEF="-D__TARGET_ARCH_arm64"; INC="/usr/include/aarch64-linux-gnu" ;;
	*) echo "bpf-lint: unsupported arch $(uname -m)" >&2; exit 1 ;;
esac

clang -g -O2 -Wall -Werror -target bpf "$ARCH_DEF" \
	-I "$TMP" -I "$INC" \
	-c "$SRC" -o "$TMP/openat_kprobe.bpf.o"

echo "bpf-lint: $SRC compiles clean (clang -Wall -Werror -target bpf, $(uname -m))"
