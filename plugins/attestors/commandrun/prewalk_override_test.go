// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package commandrun

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSnapshotPrePaths_DefaultSkipDirs asserts the built-in skip
// set (.git, node_modules, vendor, .cache) is honoured when no
// override is supplied.
func TestSnapshotPrePaths_DefaultSkipDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "keep.txt"), "keep")
	mustMkdir(t, filepath.Join(root, ".git"))
	mustWrite(t, filepath.Join(root, ".git", "HEAD"), "ref: refs/heads/main")
	mustMkdir(t, filepath.Join(root, "node_modules"))
	mustWrite(t, filepath.Join(root, "node_modules", "lib.js"), "module.exports = {}")
	mustMkdir(t, filepath.Join(root, "vendor"))
	mustWrite(t, filepath.Join(root, "vendor", "v.go"), "package vendor")
	mustMkdir(t, filepath.Join(root, ".cache"))
	mustWrite(t, filepath.Join(root, ".cache", "cached"), "cached")

	got := snapshotPrePaths(root, nil, nil)
	if _, ok := got[filepath.Join(root, "keep.txt")]; !ok {
		t.Fatalf("expected keep.txt in snapshot, got %v", got)
	}
	for _, base := range []string{".git", "node_modules", "vendor", ".cache"} {
		for p := range got {
			rel, _ := filepath.Rel(root, p)
			if strings.HasPrefix(rel, base+string(filepath.Separator)) || rel == base {
				t.Fatalf("expected %s/ to be skipped but found %s in snapshot", base, p)
			}
		}
	}
}

// TestSnapshotPrePaths_UserSkipDirs asserts --prewalk-skip-dir
// additively skips beyond the defaults.
func TestSnapshotPrePaths_UserSkipDirs(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "keep.txt"), "keep")
	mustMkdir(t, filepath.Join(root, "target"))
	mustWrite(t, filepath.Join(root, "target", "binary"), "ELF...")

	// Without override: target/ is walked.
	withoutOverride := snapshotPrePaths(root, nil, nil)
	if _, ok := withoutOverride[filepath.Join(root, "target", "binary")]; !ok {
		t.Fatalf("expected target/binary in default snapshot, got %v", withoutOverride)
	}

	// With --prewalk-skip-dir=target: target/ is skipped.
	withOverride := snapshotPrePaths(root, []string{"target"}, nil)
	if _, ok := withOverride[filepath.Join(root, "target", "binary")]; ok {
		t.Fatalf("expected target/binary to be skipped after --prewalk-skip-dir=target")
	}
}

// TestSnapshotPrePaths_UserIncludeDirs asserts --prewalk-include-dir
// removes a default-skipped directory from the skip set so the
// walk descends into it. Most-specific wins.
func TestSnapshotPrePaths_UserIncludeDirs(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "vendor"))
	mustWrite(t, filepath.Join(root, "vendor", "v.go"), "package vendor")

	// Default: vendor/ skipped.
	def := snapshotPrePaths(root, nil, nil)
	if _, ok := def[filepath.Join(root, "vendor", "v.go")]; ok {
		t.Fatalf("expected vendor/v.go to be skipped by default")
	}

	// With include: vendor/ walked.
	inc := snapshotPrePaths(root, nil, []string{"vendor"})
	if _, ok := inc[filepath.Join(root, "vendor", "v.go")]; !ok {
		t.Fatalf("expected vendor/v.go in snapshot after --prewalk-include-dir=vendor, got %v", inc)
	}
}

// TestSnapshotPrePaths_IncludeBeatsSkip asserts the include set
// wins over a user-supplied skip for the same name. Documents the
// most-specific-wins rule in docs/configuration.md.
func TestSnapshotPrePaths_IncludeBeatsSkip(t *testing.T) {
	root := t.TempDir()
	mustMkdir(t, filepath.Join(root, "dist"))
	mustWrite(t, filepath.Join(root, "dist", "out"), "out")

	got := snapshotPrePaths(root, []string{"dist"}, []string{"dist"})
	if _, ok := got[filepath.Join(root, "dist", "out")]; !ok {
		t.Fatalf("expected dist/out in snapshot: --prewalk-include-dir must beat --prewalk-skip-dir")
	}
}

func mustWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", p, err)
	}
}
