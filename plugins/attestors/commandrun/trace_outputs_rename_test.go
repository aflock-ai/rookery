// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package commandrun

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestTraceOutputs_AtomicRenameProducesProduct reproduces the gh-CLI
// build pattern locally: the tracee writes to an absolute temp path
// then RENAME(2)s to a relative target ('bin/gh' from inside the
// workspace). Confirms that:
//
//  1. TraceOutputs resolves the relative rename target against the
//     tracee's working directory.
//  2. The write-tap digest captured on the temp file's content
//     transfers to the rename target (rename moves bytes unchanged).
//  3. The final product entry has a real content digest, not a
//     witness-only nil-digest entry.
//
// Smoke runs of cilock-action v1.0.5-rc{8,9,10,11} on github.com/cli/cli
// produced empty products[] because of this path — the kernel records
// rename targets as-given (relative), and TraceOutputs was either
// re-stating from the wrong cwd or losing the digest in transit.
func TestTraceOutputs_AtomicRenameProducesProduct(t *testing.T) {
	// Build a real on-disk product file. Use TempDir so the test
	// cleans up, but DO NOT use a Chdir — TraceOutputs's resolvePath
	// is supposed to anchor against ctx.WorkingDir() / a stashed
	// tracee cwd, not the test process's cwd.
	workdir := t.TempDir()
	binDir := filepath.Join(workdir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	productPath := filepath.Join(binDir, "gh")
	productBytes := []byte("#!/bin/sh\necho hello from fake gh\n")
	if err := os.WriteFile(productPath, productBytes, 0o755); err != nil {
		t.Fatalf("write product: %v", err)
	}
	wantSHA := sha256.Sum256(productBytes)
	wantHex := hex.EncodeToString(wantSHA[:])

	// Simulate the trace's data structures the way the BPF +
	// userspace dispatcher would populate them after running
	//   go build -o bin/gh ./cmd/gh
	// in a tracee whose cwd is workdir.
	rc := &CommandRun{
		Processes: []ProcessInfo{
			{
				ProcessID: 1234,
				Program:   "/usr/bin/go",
				// Write-tap captured the temp file (absolute path).
				WrittenDigests: map[string]cryptoutil.DigestSet{
					"/tmp/go-buildXXX/exe/a.out": {
						cryptoutil.DigestValue{Hash: 5}: wantHex, // 5 = crypto.SHA256
					},
				},
				FileOps: &FileActivity{
					Writes: []FileWrite{
						{Path: "/tmp/go-buildXXX/exe/a.out", Bytes: len(productBytes)},
					},
					Renames: []FileRename{
						// Kernel records the new path AS-GIVEN; go
						// passes the -o argument so the rename target
						// is RELATIVE to the tracee's cwd.
						{OldPath: "/tmp/go-buildXXX/exe/a.out", NewPath: "bin/gh"},
					},
				},
			},
		},
		// traceeWorkdir would be set by runCmd when the trace starts;
		// for the unit test we set it directly.
		traceeWorkdir: workdir,
	}

	out := rc.TraceOutputs()
	t.Logf("TraceOutputs returned %d entries", len(out))
	for p, e := range out {
		t.Logf("  %s  src=%s digest=%v", p, e.Source, e.Digest)
	}

	// The product should be at the absolute resolved path.
	got, ok := out[productPath]
	if !ok {
		t.Fatalf("expected product at %q in TraceOutputs map; got keys = %v",
			productPath, keys(out))
	}
	if got.Digest == nil {
		t.Fatalf("product %q has nil digest — write-tap digest didn't transfer through rename", productPath)
	}
	if sha, ok := got.Digest["sha256"]; !ok || sha != wantHex {
		t.Fatalf("product digest mismatch: got %v want sha256=%s", got.Digest, wantHex)
	}
	if got.Source != "trace-write-tap" {
		t.Errorf("expected Source=trace-write-tap (kernel-rooted), got %q", got.Source)
	}
}

func keys(m map[string]attestation.CaptureEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
