# BPF object build pipeline for cilock's eBPF tracer.
#
# THE COMMITTED openat_kprobe.bpf.o IS A GENERATED ARTIFACT.
#   - It is go:embed'd at runtime by ../openat_consumer.go.
#   - We check it in so consumers don't need clang+libbpf-dev at build time.
#   - It is regenerated and byte-verified in CI (the bpf-build job: `make
#     bpf-build` then `git diff --exit-code` on the .o). If you edit
#     openat_kprobe.bpf.c, run `make bpf-build` to regenerate the committed
#     .o the SAME way CI verifies it — otherwise CI fails on drift.
#
# CANONICAL ARCH IS PINNED (NOT derived from `uname -m`).
#   The committed artifact targets a single, fixed arch so it is byte-identical
#   no matter who/where builds it. `-target bpf` codegen is host-arch
#   independent (an amd64 host and an arm64 host produce the identical object),
#   so pinning the arch define is sufficient for a deterministic artifact.
#
#   We pin arm64 (BPF_CANONICAL_ARCH ?= arm64) because:
#     - The committed vmlinux.h is an arm64 BTF dump, and __TARGET_ARCH_x86
#       cannot compile against it (libbpf's PT_REGS_PARM*_CORE_SYSCALL macros
#       expand to x86 register members `di`/`si`/... which do not exist in the
#       arm64 `struct pt_regs`). An x86-pinned artifact would require committing
#       a second, large, distro-coupled x86 vmlinux.h — extra provenance and
#       maintenance surface for no functional gain.
#     - The runtime rebuild path (../rebuild_linux.go) rebuilds against the
#       ACTUAL host kernel's freshly-dumped, arch-matched BTF on CO-RE failure,
#       so amd64 hosts already produce a host-correct object at load time. The
#       committed embed is only the fallback; pinning it arm64 keeps today's
#       behavior (amd64 hosts rebuild, arm64 hosts use the embed directly).
#   To re-pin to x86 in the future: set BPF_CANONICAL_ARCH=x86 AND replace the
#   committed vmlinux.h with an x86_64 BTF dump (see the `vmlinux` target).
#
# Build requirements:
#   - clang 14+ (we use 18 in CI)
#   - libbpf-dev (for bpf/bpf_helpers.h etc.); ships the headers under the
#     default /usr/include/bpf, so no multiarch -I is needed.
#   - bpftool + linux-headers ONLY to refresh vmlinux.h (the `vmlinux` target).
#
# Reproducibility:
#   - vmlinux.h is generated from a kernel's BTF and checked in. Different
#     kernels yield byte-different vmlinux.h files, so we do NOT re-dump it in
#     the canonical build — the committed header is the fixed input. Regenerate
#     it only on an intentional kernel-BTF refresh (and re-run `make bpf-build`).
#   - -ffile-prefix-map / -fdebug-compilation-dir force the embedded DWARF
#     comp-dir and source filename to a relative "." so no absolute build path
#     (e.g. a developer's /home or /Users tree) is ever baked into the object.
#     The only path string in the object is "openat_kprobe.bpf.c".

CLANG ?= clang
BPF_TARGET ?= bpf

# Pinned canonical arch for the COMMITTED artifact. Deliberately NOT
# `uname -m` — the committed .o must be deterministic regardless of host arch.
BPF_CANONICAL_ARCH ?= arm64

# Canonical flags for the committed artifact. Host-arch independent: the only
# arch input is the pinned -D__TARGET_ARCH_$(BPF_CANONICAL_ARCH), and the
# include path is just `-I.` (libbpf-dev installs bpf_helpers.h on the default
# search path on modern distros). This is byte-reproducible across amd64/arm64
# build hosts and is exactly what the CI bpf-build gate verifies.
CFLAGS ?= \
	-g -O2 -Wall -Werror \
	-target $(BPF_TARGET) \
	-D__TARGET_ARCH_$(BPF_CANONICAL_ARCH) \
	-ffile-prefix-map=$(CURDIR)=. \
	-fdebug-compilation-dir=. \
	-I.

OBJ := openat_kprobe.bpf.o
SRC := openat_kprobe.bpf.c

.PHONY: all bpf-build clean vmlinux

all: $(OBJ)

# bpf-build: regenerate the committed canonical artifact. This is the local
# entrypoint a contributor runs after editing openat_kprobe.bpf.c, and it is
# byte-identical to what CI rebuilds and diffs. `-B` forces a rebuild even when
# make thinks the .o is up to date, so the committed bytes are always refreshed.
bpf-build:
	$(MAKE) -B $(OBJ)

$(OBJ): $(SRC) vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

# Regenerate vmlinux.h from the host kernel's BTF. Only do this on an
# intentional refresh — different kernels produce byte-different files, and
# the arch must match BPF_CANONICAL_ARCH (currently arm64) or the canonical
# build will not compile. After refreshing, re-run `make bpf-build`.
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f $(OBJ)
