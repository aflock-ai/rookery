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
# version-dispatch wrapper that refuses to run unless the per-running-
# kernel linux-tools package is installed (the common failure on Azure-
# flavored hosted runners). The real binaries shipped by
# linux-tools-generic live under /usr/lib/linux-tools/<kver>/bpftool and
# can dump /sys/kernel/btf/vmlinux regardless of kernel version — prefer
# those over the PATH wrapper.
BPFTOOL=""
for cand in /usr/lib/linux-tools/*/bpftool /usr/lib/linux-tools-*/bpftool /snap/bin/bpftool; do
	[ -x "$cand" ] && { BPFTOOL="$cand"; break; }
done
[ -n "$BPFTOOL" ] || BPFTOOL="$(command -v bpftool || true)"
[ -n "$BPFTOOL" ] || { echo "bpf-lint: no bpftool found (need linux-tools-generic)" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# CO-RE vmlinux.h matched to the RUNNING kernel's BTF (correct arch).
"$BPFTOOL" btf dump file /sys/kernel/btf/vmlinux format c > "$TMP/vmlinux.h"

# Guard against a partial dump: a complete kernel vmlinux.h is multiple
# MB. A stub/mismatched bpftool can emit a truncated header, which later
# surfaces as a confusing macro-expansion error rather than a clear one.
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

# Compile a COPY of the source placed next to the fresh vmlinux.h, exactly
# like the runtime rebuild path (rebuild_linux.go) does. The source uses
# `#include "vmlinux.h"` — a quoted include, which clang resolves relative
# to the SOURCE FILE'S directory first. Compiling in-place would pick up
# the committed bpf/vmlinux.h (a single fixed arch, e.g. aarch64) and, when
# the target arch differs, fail with a baffling "no member named 'di' in
# struct pt_regs". Compiling from $TMP makes the quoted include resolve to
# the freshly-dumped, correct-arch header.
cp "$SRC" "$TMP/openat_kprobe.bpf.c"
clang -g -O2 -Wall -Werror -target bpf "$ARCH_DEF" \
	-I "$TMP" -I "$INC" \
	-c "$TMP/openat_kprobe.bpf.c" -o "$TMP/openat_kprobe.bpf.o"

echo "bpf-lint: $SRC compiles clean (clang -Wall -Werror -target bpf, $(uname -m))"
