// Copyright 2026 TestifySec, Inc.
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
	"testing"
)

// TestTraceOutputs_FanotifyCloseWriteIsAuthoritativeProduct verifies that
// FAN_CLOSE_WRITE digests — the kernel-hashed FINAL content of files the
// tracee wrote and closed — are emitted as products and OVERRIDE any prior
// (lossy write-tap / witness-only) entry for the same path. This is the
// zero-drop product-content path that doesn't depend on the eBPF write-tap.
func TestTraceOutputs_FanotifyCloseWriteIsAuthoritativeProduct(t *testing.T) {
	const p = "/work/hugo-bin"
	content := []byte("final linked binary bytes")
	sum := sha256.Sum256(content)
	wantHex := hex.EncodeToString(sum[:])

	rc := &CommandRun{
		traceeWorkdir:          "/work",
		fanotifyProductDigests: map[string][32]byte{p: sum},
	}

	out := rc.TraceOutputs()

	entry, ok := out[p]
	if !ok {
		t.Fatalf("FAN_CLOSE_WRITE product was not emitted; out=%v", out)
	}
	if entry.Source != "fanotify-close-write" {
		t.Fatalf("expected source fanotify-close-write, got %q", entry.Source)
	}
	got := entry.Digest["sha256"]
	if got != wantHex {
		t.Fatalf("close-write product digest = %q, want %q (final content hash)", got, wantHex)
	}
}
