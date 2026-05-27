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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestTraceOutputs_MtimeSurvivorCapturesUntappedProduct is the deeper
// product-accuracy regression. Products must be anchored on filesystem
// reality (modified-during-the-command-window + survives), not solely on the
// eBPF write-tap's events, which silently drop on some kernels (GitHub's Azure
// 6.17 dropped the ENTIRE write event for syft's SBOM output — writes=0). A
// surviving workspace file with a fresh mtime is a product even when:
//   - no write event was captured for it (write-tap loss), AND
//   - it was also read in this step (one-step build+scan → multiple products).
func TestTraceOutputs_MtimeSurvivorCapturesUntappedProduct(t *testing.T) {
	workdir := t.TempDir()

	// The command "started" a minute ago.
	start := time.Now().Add(-time.Minute)

	// Product the write-tap entirely missed: no FileOps.Writes, no
	// WrittenDigests. Mtime is after command-start (written during the run).
	untapped := filepath.Join(workdir, "sbom.cdx.json")
	if err := os.WriteFile(untapped, []byte(`{"bomFormat":"CycloneDX"}`), 0o644); err != nil {
		t.Fatalf("write untapped product: %v", err)
	}
	fresh := start.Add(10 * time.Second)
	if err := os.Chtimes(untapped, fresh, fresh); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// A pre-existing input the command only READ (mtime predates the run).
	input := filepath.Join(workdir, "go.sum")
	if err := os.WriteFile(input, []byte("deadbeef"), 0o644); err != nil {
		t.Fatalf("write input: %v", err)
	}
	old := start.Add(-time.Hour)
	if err := os.Chtimes(input, old, old); err != nil {
		t.Fatalf("chtimes input: %v", err)
	}

	rc := &CommandRun{
		traceeWorkdir:  workdir,
		traceStartTime: start,
		Processes: []ProcessInfo{{
			OpenedFiles: map[string]cryptoutil.DigestSet{
				// The product was ALSO read this step (e.g. inspected) — it
				// must still be captured as a product.
				untapped: {cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc"},
				// The genuine input was read too.
				input: {cryptoutil.DigestValue{Hash: crypto.SHA256}: "def"},
			},
		}},
	}

	out := rc.TraceOutputs()

	if _, ok := out[untapped]; !ok {
		t.Fatalf("surviving product modified during the run must be captured via the mtime walk even with no write event; out=%v", out)
	}
	if _, ok := out[input]; ok {
		t.Fatalf("an untouched pre-existing input (mtime before command-start) must NOT be a product; out=%v", out)
	}
}
