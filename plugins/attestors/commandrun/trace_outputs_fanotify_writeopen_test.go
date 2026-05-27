// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package commandrun

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestTraceOutputs_FanotifyWriteOpenStaysProduct is the regression for the
// empty-product-tree failure on GitHub's Azure runner. When fanotify is on, it
// hashes EVERY open — including the build's write-open of its output file — and
// the merge upgrades that nil-digest OpenedFiles entry with an open-time hash.
// Before the fix, TraceOutputs counted that as a "read", so the written product
// landed in readPaths and was dropped as an "intermediate", shipping an empty
// product set. The fanotifyWriteOpenClaimed flag must keep it a product.
func TestTraceOutputs_FanotifyWriteOpenStaysProduct(t *testing.T) {
	workdir := t.TempDir()
	productPath := filepath.Join(workdir, "app.bin")
	productBytes := []byte("the real built binary content")
	if err := os.WriteFile(productPath, productBytes, 0o755); err != nil {
		t.Fatalf("write product: %v", err)
	}
	wantSHA := sha256.Sum256(productBytes)
	wantHex := hex.EncodeToString(wantSHA[:])

	// fanotify's (wrong, open-time) hash that the merge stamped onto the
	// write-open OpenedFiles entry — deliberately NOT the real content hash.
	fanotifyOpenHex := hex.EncodeToString(sha256.New().Sum(nil))

	rc := &CommandRun{
		traceeWorkdir: workdir,
		Processes: []ProcessInfo{{
			OpenedFiles: map[string]cryptoutil.DigestSet{
				productPath: {cryptoutil.DigestValue{Hash: crypto.SHA256}: fanotifyOpenHex},
			},
			FileOps: &FileActivity{
				Writes: []FileWrite{{Path: productPath}},
			},
			// eBPF write-tap failed → no WrittenDigests (the Azure case).
		}},
		fanotifyWriteOpenClaimed: map[string]bool{productPath: true},
	}

	out := rc.TraceOutputs()

	entry, ok := out[productPath]
	if !ok {
		t.Fatalf("written product was dropped from TraceOutputs (demoted to intermediate); products = %v", out)
	}
	if entry.Digest == nil {
		t.Fatalf("product entry has nil digest; expected attest-time content hash")
	}
	found := false
	for _, v := range entry.Digest {
		if v == wantHex {
			found = true
		}
	}
	if !found {
		t.Fatalf("product digest = %v, want content hash %s (not the fanotify open-time hash %s)",
			entry.Digest, wantHex, fanotifyOpenHex)
	}
}

// TestTraceOutputs_GenuineReadWriteStaysIntermediate is the negative control:
// a file the build genuinely READ (real BPF read-tap digest, NOT fanotify-
// write-open-claimed) and also wrote is still treated as an intermediate and
// excluded from products. Proves the exclusion is gated specifically on the
// fanotify-write-open flag, not on "appears in OpenedFiles".
func TestTraceOutputs_GenuineReadWriteStaysIntermediate(t *testing.T) {
	workdir := t.TempDir()
	p := filepath.Join(workdir, "rewritten.txt")
	if err := os.WriteFile(p, []byte("content"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	rc := &CommandRun{
		traceeWorkdir: workdir,
		Processes: []ProcessInfo{{
			OpenedFiles: map[string]cryptoutil.DigestSet{
				// Genuine BPF read-tap digest — NOT fanotify-claimed.
				p: {cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123"},
			},
			FileOps: &FileActivity{
				Writes: []FileWrite{{Path: p}},
			},
		}},
		// fanotifyWriteOpenClaimed intentionally empty.
	}

	out := rc.TraceOutputs()
	if _, ok := out[p]; ok {
		t.Fatalf("a genuinely read+written file must remain an intermediate, not a product; got %v", out)
	}
}
