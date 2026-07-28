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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// syntheticVmlinuxH reproduces the failure class that sank the v4.1.1
// release fan-out: bpftool's BTF dump of some kernels emits member-less
// declarations at file scope, which clang flags as "declaration does
// not declare anything" (-Wmissing-declarations). Under the rebuild's
// -Wall -Werror that single warning class hard-failed the whole
// runtime rebuild — on amd64 hosts the ONLY working load path (the
// committed .bpf.o is arm64-pinned by design).
const syntheticVmlinuxH = `
typedef unsigned int __u32;
struct { int x; };
`

// compileWithProdArgs runs the host clang with the EXACT production
// rebuild args (clangBPFArgs) over the given source/header pair and
// returns clang's combined output plus the run error.
func compileWithProdArgs(t *testing.T, src, header string) (string, error) {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang not on PATH; skipping rebuild flag-contract test")
	}

	dir := t.TempDir()
	incDir := filepath.Join(dir, "include")
	if merr := os.Mkdir(incDir, 0o755); merr != nil {
		t.Fatalf("mkdir include dir: %v", merr)
	}
	if werr := os.WriteFile(filepath.Join(incDir, "vmlinux.h"), []byte(header), 0o644); werr != nil {
		t.Fatalf("write vmlinux.h: %v", werr)
	}
	srcPath := filepath.Join(dir, "prog.c")
	if werr := os.WriteFile(srcPath, []byte(src), 0o644); werr != nil {
		t.Fatalf("write source: %v", werr)
	}

	objPath := filepath.Join(dir, "prog.o")
	// archDef is arch-agnostic for this contract (no libbpf macros in the
	// test source); the multiarch dir deliberately doesn't exist —
	// nonexistent -isystem paths are harmless, same as prod on non-Debian
	// layouts.
	args := clangBPFArgs("-D__TARGET_ARCH_x86", dir, incDir,
		filepath.Join(dir, "no-such-multiarch"), srcPath, objPath)
	out, cerr := exec.Command(clang, args...).CombinedOutput()
	return string(out), cerr
}

// TestRebuildToleratesGeneratedHeaderWarnings pins the load-bearing
// half of the contract: a machine-generated vmlinux.h whose shape we
// don't control may carry -Wall warnings, and the rebuild must still
// succeed (the header is included via -isystem, so its warnings are
// suppressed rather than promoted to errors).
func TestRebuildToleratesGeneratedHeaderWarnings(t *testing.T) {
	out, err := compileWithProdArgs(t, "#include \"vmlinux.h\"\n__u32 cilock_keep = 1;\n", syntheticVmlinuxH)
	if err != nil {
		t.Fatalf("rebuild args must tolerate warnings in the generated vmlinux.h (v4.1.1 regression), got: %v\n%s", err, out)
	}
}

// TestRebuildStillGatesOwnSource pins the other half: -Wall -Werror
// must keep failing the compile when the warning is in OUR source, not
// the generated header — the -isystem change must not have weakened the
// gate on openat_kprobe.bpf.c itself.
func TestRebuildStillGatesOwnSource(t *testing.T) {
	src := "#include \"vmlinux.h\"\nstruct { int y; };\n__u32 cilock_keep = 1;\n"
	out, err := compileWithProdArgs(t, src, "typedef unsigned int __u32;\n")
	if err == nil {
		t.Fatalf("-Wall -Werror must still gate our own source; compile unexpectedly succeeded\n%s", out)
	}
	if !strings.Contains(out, "-Werror") {
		t.Fatalf("expected a -Werror-promoted diagnostic, got: %v\n%s", err, out)
	}
}
