// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// looksLikeCOREFailure returns true when the error from cilium/ebpf's
// NewCollection looks like a poisoned CO-RE relocation rather than a
// permission / kernel-feature problem. The cilium/ebpf message format
// for a poison is "load program: bad CO-RE relocation: <verifier log>"
// and the verifier emits "instruction poisoned by CO-RE @ :0" / the
// 0xBAD2310 sentinel ("unknown#195896080"). Match generously — we'd
// rather rebuild on a borderline error than emit a stale embed.
func looksLikeCOREFailure(err error) bool {
	if err == nil {
		return false
	}
	s := verboseErr(err)
	return strings.Contains(s, "bad CO-RE relocation") ||
		strings.Contains(s, "poisoned by CO-RE") ||
		strings.Contains(s, "unknown#195896080")
}

// rebuildBPFAgainstHostKernel writes the embedded .bpf.c to a tempdir,
// regenerates vmlinux.h from /sys/kernel/btf/vmlinux via bpftool, and
// invokes clang -target bpf to produce a .bpf.o matched to the host
// kernel's BTF. Returns the compiled object bytes.
//
// Dependencies: clang, bpftool, libbpf-dev (for bpf_helpers.h /
// bpf_tracing.h). cilock-action's shim installs them on first run;
// otherwise the caller's environment must have them on PATH.
func rebuildBPFAgainstHostKernel() ([]byte, error) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		return nil, fmt.Errorf("clang not on PATH: %w (install: apt install -y clang)", err)
	}
	bpftool, btErr := findBpftool()
	if btErr != nil {
		return nil, btErr
	}

	dir, err := os.MkdirTemp("", "cilock-bpf-rebuild-*")
	if err != nil {
		return nil, fmt.Errorf("mkdir tempdir: %w", err)
	}
	// We deliberately do not RemoveAll on success — the rebuilt .bpf.o
	// stays available for diagnosis. The runner is ephemeral anyway.

	srcPath := filepath.Join(dir, "openat_kprobe.bpf.c")
	if werr := os.WriteFile(srcPath, bpfSrcBytes, 0o644); werr != nil {
		return nil, fmt.Errorf("write bpf source: %w", werr)
	}

	// vmlinux.h matched to the running kernel.
	vmlinuxPath := filepath.Join(dir, "vmlinux.h")
	fmt.Fprintf(os.Stderr, "cilock-ebpf: using bpftool at %s\n", bpftool)
	dumpStderr := &strings.Builder{}
	dumpCmd := exec.Command("sudo", bpftool, "btf", "dump", "file",
		"/sys/kernel/btf/vmlinux", "format", "c")
	dumpCmd.Stderr = dumpStderr
	out, err := dumpCmd.Output()
	if err != nil {
		// Try without sudo (when already root or btf is world-readable).
		dumpStderr2 := &strings.Builder{}
		dumpCmd2 := exec.Command(bpftool, "btf", "dump", "file",
			"/sys/kernel/btf/vmlinux", "format", "c")
		dumpCmd2.Stderr = dumpStderr2
		out, err = dumpCmd2.Output()
		if err != nil {
			return nil, fmt.Errorf("bpftool (%s) btf dump: %w; sudo-stderr: %q; nosudo-stderr: %q",
				bpftool, err, dumpStderr.String(), dumpStderr2.String())
		}
	}
	if werr := os.WriteFile(vmlinuxPath, out, 0o644); werr != nil {
		return nil, fmt.Errorf("write vmlinux.h: %w", werr)
	}

	// Pick the target-arch define and multi-arch include from the Go
	// arch (not uname -m so cross-arch QEMU runs do the right thing).
	// The multi-arch include matters because libbpf-dev installs
	// bpf/bpf_helpers.h under /usr/include/<triple>-linux-gnu/.
	var archDef, multiarchInc string
	switch runtime.GOARCH {
	case "amd64":
		archDef = "-D__TARGET_ARCH_x86"
		multiarchInc = "/usr/include/x86_64-linux-gnu"
	case "arm64":
		archDef = "-D__TARGET_ARCH_arm64"
		multiarchInc = "/usr/include/aarch64-linux-gnu"
	default:
		return nil, fmt.Errorf("unsupported GOARCH %q for BPF rebuild", runtime.GOARCH)
	}

	objPath := filepath.Join(dir, "openat_kprobe.bpf.o")
	// -ffile-prefix-map / -fdebug-compilation-dir canonicalize the embedded
	// DWARF comp-dir and source filename to a relative "." so the absolute
	// tempdir path (and, on a dev machine, the home tree) is never baked into
	// the rebuilt object. Mirrors bpf/Makefile and scripts/bpf-lint.sh; keeps
	// a host-rebuilt .bpf.o reproducible and free of leaked build paths.
	cmd := exec.Command(clang,
		"-g", "-O2", "-Wall", "-Werror",
		"-target", "bpf",
		archDef,
		"-ffile-prefix-map="+dir+"=.",
		"-fdebug-compilation-dir=.",
		"-I", dir,
		"-I", multiarchInc,
		"-c", srcPath,
		"-o", objPath,
	)
	cmd.Stderr = os.Stderr
	if cerr := cmd.Run(); cerr != nil {
		return nil, fmt.Errorf("clang -target bpf failed: %w", cerr)
	}
	return os.ReadFile(objPath)
}

// findBpftool returns a usable bpftool path. /usr/sbin/bpftool on
// Ubuntu is a STUB wrapper that demands a kernel-version-matched
// linux-tools-*-azure package — it exits 2 with "WARNING: bpftool
// not found for kernel ..." when that package isn't installed,
// which is the common case on Microsoft Azure-flavored hosted
// runners. Prefer the explicit /usr/lib/linux-tools/*/bpftool
// binaries (shipped by linux-tools-generic) and the snap install
// over the PATH lookup.
func findBpftool() (string, error) {
	candidates := []string{}
	// Try real bpftool binaries first.
	for _, pat := range []string{
		"/usr/lib/linux-tools/*/bpftool",
		"/usr/lib/linux-tools-*/bpftool",
		"/snap/bin/bpftool",
	} {
		matches, _ := filepath.Glob(pat)
		candidates = append(candidates, matches...)
	}
	// PATH last (might point to the kernel-version-checking wrapper).
	if p, err := exec.LookPath("bpftool"); err == nil {
		candidates = append(candidates, p)
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() {
			return c, nil
		}
	}
	return "", fmt.Errorf("bpftool not found in /usr/lib/linux-tools or on PATH (install: apt install -y linux-tools-generic)")
}
