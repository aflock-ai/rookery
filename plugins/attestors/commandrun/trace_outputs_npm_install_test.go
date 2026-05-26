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
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestTraceOutputs_NpmInstall_ManyProducts exercises the stat-fallback
// + pre-state snapshot at REAL scale: actually run `npm install
// express` in a temp workdir, then synthesise a CommandRun whose
// FileOps.Writes covers every file npm just created. Validates:
//
//   - snapshotPrePaths handles a fresh-but-non-empty workdir (init+lock)
//   - TraceOutputs returns a product for every npm-created file
//   - mtime-skip doesn't accidentally drop the package-lock/files
//   - source classification is "trace-pathhash" (clean creation)
//
// Skipped automatically when npm isn't on PATH; skipped under
// `-short` because real npm install takes 3-10s.
func TestTraceOutputs_NpmInstall_ManyProducts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short: real npm install")
	}
	npmPath, err := exec.LookPath("npm")
	if err != nil {
		t.Skip("npm not on PATH")
	}

	workdir := t.TempDir()

	// Step 1: npm init creates package.json. This file PRE-EXISTS when
	// we later run `npm install`, so it should appear in prePaths.
	initCmd := exec.Command(npmPath, "init", "-y")
	initCmd.Dir = workdir
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("npm init failed: %v\n%s", err, out)
	}

	// Step 2: snapshot pre-state RIGHT before the install (mirrors
	// what runCmd does). prePaths should contain only package.json.
	traceStart := time.Now()
	prePaths := snapshotPrePaths(workdir)
	t.Logf("prePaths snapshot: %d entries (expect 1: package.json)", len(prePaths))
	if len(prePaths) < 1 {
		t.Fatalf("expected at least package.json in prePaths, got %d", len(prePaths))
	}
	preJSON := filepath.Join(workdir, "package.json")
	if _, ok := prePaths[preJSON]; !ok {
		t.Errorf("package.json missing from prePaths: %v", keysOfSet(prePaths))
	}

	// Step 3: run npm install. This creates node_modules/, populates
	// package-lock.json, modifies package.json (the build overwrites
	// it — that's the rare overwrite case we should detect).
	time.Sleep(20 * time.Millisecond) // ensure mtime separation
	installCmd := exec.Command(npmPath, "install", "express", "--no-audit", "--no-fund", "--no-progress")
	installCmd.Dir = workdir
	installCmd.Env = append(os.Environ(),
		"npm_config_cache="+filepath.Join(workdir, ".npm-cache"),
	)
	installStart := time.Now()
	if out, err := installCmd.CombinedOutput(); err != nil {
		t.Fatalf("npm install failed: %v\n%s", err, out)
	}
	installDur := time.Since(installStart)
	t.Logf("npm install completed in %v", installDur)

	// Step 4: collect every file npm created/modified on disk. This
	// simulates the FileOps.Writes the BPF write-tap would have
	// emitted (if we were on Linux, which we're not). Skip the
	// npm cache subdir we redirected — that's not under workspace
	// semantically (we set it explicitly to isolate the run).
	var writes []FileWrite
	_ = filepath.WalkDir(workdir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".npm-cache" && p != workdir {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		writes = append(writes, FileWrite{Path: p, Bytes: 0})
		return nil
	})
	t.Logf("npm install wrote %d files to workdir (excluding .npm-cache)", len(writes))
	if len(writes) < 50 {
		t.Fatalf("expected >=50 files from npm install express, got %d", len(writes))
	}

	// Step 5: synthesise a CommandRun with no WrittenDigests (write-tap
	// missed everything — the classic mmap-write / writev gap). The
	// stat-fallback must produce real digests for every written path.
	rc := &CommandRun{
		traceeWorkdir:  workdir,
		traceStartTime: traceStart,
		prePaths:       prePaths,
		Processes: []ProcessInfo{
			{
				ProcessID: 1234,
				Program:   npmPath,
				FileOps:   &FileActivity{Writes: writes},
			},
		},
	}

	out := rc.TraceOutputs()
	t.Logf("TraceOutputs returned %d entries from %d candidate writes", len(out), len(writes))

	// Classify outputs by Source. The mtime-skip should not drop ANY
	// npm-created file (their mtimes are all > traceStart). The
	// overwrite tag should fire for package.json (which existed in
	// prePaths AND was modified by npm install — it now lists
	// "express" as a dep).
	bySource := map[string]int{}
	for p, e := range out {
		bySource[e.Source]++
		if strings.HasSuffix(p, "/package.json") && filepath.Dir(p) == workdir {
			if e.Source != "trace-pathhash-overwrite" {
				t.Errorf("expected package.json Source=trace-pathhash-overwrite (npm modified pre-existing), got %q", e.Source)
			}
		}
	}
	t.Logf("source breakdown: %v", bySource)

	// Quality checks:
	//   (a) We get back MOST of the writes (some files may be
	//       transient — npm rewrites then deletes lock journals).
	if got, want := len(out), int(float64(len(writes))*0.95); got < want {
		t.Errorf("too few entries in TraceOutputs: got %d, want >= %d (95%% of %d writes)", got, want, len(writes))
	}
	//   (b) The clean-creation count (trace-pathhash) dominates —
	//       only package.json should be flagged as overwrite.
	if bySource["trace-pathhash"] < 50 {
		t.Errorf("expected dozens of clean-creation products, got %d", bySource["trace-pathhash"])
	}
	if bySource["trace-pathhash-overwrite"] != 1 {
		t.Errorf("expected exactly 1 overwrite (package.json), got %d", bySource["trace-pathhash-overwrite"])
	}

	// Spot-check: a known-existing file (node_modules/express/package.json)
	// must be present with a real digest.
	expressPkg := filepath.Join(workdir, "node_modules", "express", "package.json")
	if _, err := os.Stat(expressPkg); err == nil {
		entry, ok := out[expressPkg]
		if !ok {
			t.Errorf("express's package.json missing from products")
		} else {
			data, _ := os.ReadFile(expressPkg)
			sum := sha256.Sum256(data)
			want := hex.EncodeToString(sum[:])
			if entry.Digest["sha256"] != want {
				t.Errorf("digest mismatch for %s: got %v want sha256=%s",
					expressPkg, entry.Digest, want)
			}
		}
	}

	t.Logf("✓ npm install attested via stat-fallback: %d total entries (%d clean, %d overwrite)",
		len(out), bySource["trace-pathhash"], bySource["trace-pathhash-overwrite"])
}

func keysOfSet(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// preventUnused keeps imports honest if the test changes shape.
var _ = cryptoutil.DigestSet{}
var _ = fmt.Sprintf
