// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package cryptoutil

import (
	"os"
	"testing"
)

// TestVeritySupported_Probe runs the probe and reports the outcome.
// Always passes — fs-verity is opportunistic, not required. The
// log line tells operators / CI what to expect when running
// fanotify+fs-verity sealing in this environment.
func TestVeritySupported_Probe(t *testing.T) {
	dir := t.TempDir()
	if err := VeritySupported(dir); err != nil {
		t.Logf("fs-verity NOT available on %s: %v", dir, err)
		t.Logf("post-write seal will fall back to streaming SHA-256 in this environment")
		return
	}
	t.Logf("fs-verity IS available on %s", dir)
}

// TestEnableAndMeasure_RoundTrip — only runs when verity is actually
// supported on the test mount. Creates a small file, enables verity,
// reads back the Merkle root, asserts it's a non-empty digest.
func TestEnableAndMeasure_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := VeritySupported(dir); err != nil {
		t.Skipf("fs-verity unsupported on %s: %v", dir, err)
	}
	path := dir + "/verity-test.bin"
	if err := os.WriteFile(path, []byte("hello fs-verity"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := EnableVerity(path, 0); err != nil {
		t.Fatalf("EnableVerity: %v", err)
	}
	hex, err := VerityHexDigest(path)
	if err != nil {
		t.Fatalf("VerityHexDigest: %v", err)
	}
	if hex == "" {
		t.Fatalf("expected non-empty digest after enable")
	}
	if len(hex) != 64 { // SHA-256 = 32 bytes = 64 hex chars
		t.Errorf("expected 64-char SHA-256 hex, got %d chars: %s", len(hex), hex)
	}
	t.Logf("fs-verity Merkle root: %s", hex)
}
