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

// TestTraceOutputs_AtomicRenameProducesProduct_WriteTapMissed reproduces
// the EXACT production failure observed in
// github.com/colek42/cli@nk/cilock-smoke run 26425328748:
//
//   - sys_write/pwrite64 write-tap recorded a 83-byte write for
//     '/tmp/go-build…/exe/a.out' (likely the gotoolchain shim), but the
//     LINKER's full-binary write went through writev/mmap and was not
//     captured by write-tap.
//   - WrittenDigests for that path is EMPTY.
//   - FileOps.Renames carries the rename to 'bin/gh' (relative).
//   - The product file ('bin/gh') exists on disk under the tracee's
//     workdir at exit.
//
// Expected behaviour: TraceOutputs still returns an entry for
// 'bin/gh' (absolute, resolved against traceeWorkdir), but with
// Source="trace-write-only" and a digest from the os.Stat +
// pathHashIfExists fallback path. This is the kernel-rooted-write
// missed-it but file-exists-on-disk pattern; we must NOT silently
// drop the product.
func TestTraceOutputs_AtomicRenameProducesProduct_WriteTapMissed(t *testing.T) {
	workdir := t.TempDir()
	binDir := filepath.Join(workdir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	productPath := filepath.Join(binDir, "gh")
	// Use realistic binary-like content; we'll verify the fallback
	// hash matches sha256 of this exact byte sequence.
	productBytes := []byte("\x7fELF\x02\x01\x01" + string(make([]byte, 4096)))
	if err := os.WriteFile(productPath, productBytes, 0o755); err != nil {
		t.Fatalf("write product: %v", err)
	}
	wantSHA := sha256.Sum256(productBytes)
	wantHex := hex.EncodeToString(wantSHA[:])

	rc := &CommandRun{
		Processes: []ProcessInfo{
			{
				ProcessID: 1234,
				Program:   "/usr/bin/go",
				// CRITICAL: NO WrittenDigests entry for the linker
				// output. Write-tap missed it (writev/mmap path).
				WrittenDigests: map[string]cryptoutil.DigestSet{},
				FileOps: &FileActivity{
					Writes: []FileWrite{
						// Trace recorded the write but write-tap
						// didn't hash it (e.g. 0-byte truncate write
						// then the actual content via writev).
						{Path: "/tmp/go-buildXXX/exe/a.out", Bytes: 0},
					},
					Renames: []FileRename{
						{OldPath: "/tmp/go-buildXXX/exe/a.out", NewPath: "bin/gh"},
					},
				},
			},
		},
		traceeWorkdir: workdir,
	}

	out := rc.TraceOutputs()
	t.Logf("TraceOutputs returned %d entries", len(out))
	for p, e := range out {
		t.Logf("  %s  src=%s digest=%v", p, e.Source, e.Digest)
	}

	got, ok := out[productPath]
	if !ok {
		t.Fatalf("expected product at %q in TraceOutputs map; got keys = %v",
			productPath, keys(out))
	}
	if got.Digest == nil {
		t.Fatalf("product %q has nil digest — stat+pathHash fallback didn't fire", productPath)
	}
	if sha, ok := got.Digest["sha256"]; !ok || sha != wantHex {
		t.Fatalf("product digest mismatch: got %v want sha256=%s", got.Digest, wantHex)
	}
	// When write-tap missed, the fallback labels the source so verifiers
	// know it's a post-exit stat-hash, not a kernel-streamed digest.
	if got.Source != "trace-pathhash" {
		t.Errorf("unexpected Source %q (want trace-pathhash from stat+pathHash fallback)", got.Source)
	}
}
