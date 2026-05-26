# BPF object build pipeline for cilock's eBPF tracer.
#
# The .bpf.o is loaded at runtime via go:embed in openat_consumer.go.
# We check it in so consumers don't need clang+libbpf-dev at build
# time, but it must be regenerated whenever openat_kprobe.bpf.c changes.
#
# Build requirements:
#   - clang 14+ (we use 18 in CI)
#   - linux-headers + bpftool (for vmlinux.h regeneration)
#
# Reproducibility:
#   - vmlinux.h is generated from the current kernel's BTF. Different
#     kernels yield byte-different vmlinux.h files. We check vmlinux.h
#     in so the .bpf.o build is reproducible regardless of host kernel.
#     Regenerate it only on intentional kernel-BTF refresh.

CLANG ?= clang
BPF_TARGET ?= bpf

# Use the host kernel's BTF for CO-RE relocations. We don't depend on
# /sys/kernel/btf/vmlinux at runtime — the embedded BTF in the .bpf.o
# is sufficient.
CFLAGS ?= \
	-g -O2 -Wall -Werror \
	-target $(BPF_TARGET) \
	-D__TARGET_ARCH_$(shell uname -m | sed 's/aarch64/arm64/' | sed 's/x86_64/x86/') \
	-I. \
	-I/usr/include/$(shell uname -m)-linux-gnu

OBJ := openat_kprobe.bpf.o
SRC := openat_kprobe.bpf.c

.PHONY: all clean vmlinux

all: $(OBJ)

$(OBJ): $(SRC) vmlinux.h
	$(CLANG) $(CFLAGS) -c $< -o $@

# Regenerate vmlinux.h from the host kernel's BTF. Only do this on
# intentional refresh — different kernels produce byte-different files.
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

clean:
	rm -f $(OBJ)
