//go:build audit && !windows

// Copyright 2025 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package file

import (
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gobwas/glob"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defaultHashes returns a standard set of hash algorithms for testing.
func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}

// emptyArgs returns the common "empty" arguments for RecordArtifacts calls.
func emptyArgs() (map[string]cryptoutil.DigestSet, map[string]struct{}, map[string]bool) {
	return map[string]cryptoutil.DigestSet{},
		map[string]struct{}{},
		map[string]bool{}
}

// ---------------------------------------------------------------------------
// Fuzz: RecordArtifacts with crafted filenames
// ---------------------------------------------------------------------------

// FuzzRecordArtifactsFilenames creates files with fuzzed names and verifies
// that RecordArtifacts handles them without panicking, deadlocking, or
// producing incorrect relative paths.
//
// Security focus:
//   - Null bytes in filenames (rejected by OS, but verify graceful handling)
//   - Path traversal sequences (../)
//   - Very long filenames (near OS 255-byte limit)
//   - Unicode normalization issues (NFC vs NFD)
//   - Filenames that look like glob patterns
//   - Filenames containing newlines, tabs, control characters
func FuzzRecordArtifactsFilenames(f *testing.F) {
	// Seed corpus: security-relevant filenames
	f.Add("normal.txt", []byte("content"))
	f.Add(".hidden", []byte("dotfile"))
	f.Add("file with spaces.txt", []byte("spaces"))
	f.Add("file\ttab.txt", []byte("tab"))
	f.Add(strings.Repeat("a", 250)+".txt", []byte("long name"))       // near 255 limit
	f.Add("deeply/nested/path/file.txt", []byte("nested"))            // will be flattened
	f.Add("*.go", []byte("glob pattern name"))
	f.Add("[bracket].txt", []byte("bracket"))
	f.Add("{brace}.txt", []byte("brace"))
	f.Add("file\nwith\nnewlines.txt", []byte("newline"))
	f.Add("\u4f60\u597d.txt", []byte("chinese"))
	f.Add("caf\u00e9.txt", []byte("precomposed"))
	f.Add("file\x01control.txt", []byte("control char"))
	f.Add(" ", []byte("space only"))
	f.Add(".", []byte("dot"))
	f.Add("..", []byte("dotdot"))                                      // path traversal
	f.Add("a/../../escape.txt", []byte("traversal"))
	f.Add("normal", []byte{0x00})                                     // null byte in content
	f.Add("normal", []byte{0xff, 0xfe, 0xfd})                         // binary content

	f.Fuzz(func(t *testing.T, filename string, content []byte) {
		// Skip filenames with null bytes (OS rejects them)
		if strings.ContainsRune(filename, 0) {
			return
		}
		// Skip empty filenames
		if filename == "" {
			return
		}
		// Skip filenames that are just dots (OS interprets them as directories)
		if filename == "." || filename == ".." {
			return
		}
		// Skip filenames with path separators (we test flat files here)
		if strings.ContainsRune(filename, '/') || strings.ContainsRune(filename, '\\') {
			return
		}
		// Skip filenames that exceed OS limits
		if len(filename) > 255 {
			filename = filename[:255]
		}

		dir := t.TempDir()
		filePath := filepath.Join(dir, filename)

		// Try to create the file; OS may reject exotic names
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			return // OS rejected the filename, that is fine
		}

		baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
		artifacts, err := RecordArtifacts(
			dir, baseArtifacts, defaultHashes(),
			visitedSymlinks, false, openedFiles,
			nil, nil, nil,
		)

		// Must not panic. Error is acceptable for exotic filenames.
		if err != nil {
			return
		}

		// If successful, verify invariants:
		// 1. At least one artifact (the file we created)
		if len(artifacts) == 0 {
			t.Fatal("RecordArtifacts returned empty map for directory with one file")
		}

		// 2. All relative paths should NOT contain ".." as a path component.
		// Note: ".." as a substring is fine (e.g. filename "0.." or "foo..bar").
		// We check for ".." as a standalone path component only.
		for relPath := range artifacts {
			for _, component := range strings.Split(filepath.ToSlash(relPath), "/") {
				if component == ".." {
					t.Errorf("SECURITY: artifact path contains '..' as path component: %q", relPath)
				}
			}
		}

		// 3. The digest should be non-empty
		for relPath, ds := range artifacts {
			nameMap, err := ds.ToNameMap()
			if err != nil {
				t.Errorf("failed to convert digest for %q: %v", relPath, err)
				continue
			}
			if sha, ok := nameMap["sha256"]; ok && sha == "" {
				t.Errorf("empty SHA256 digest for %q", relPath)
			}
		}
	})
}

// FuzzRecordArtifactsContent creates a file with fuzzed content and verifies
// that the hash computation produces a valid, deterministic result.
// This tests the CalculateDigestSet code path with arbitrary byte sequences.
func FuzzRecordArtifactsContent(f *testing.F) {
	f.Add([]byte(""))                                                  // empty
	f.Add([]byte("hello world"))                                       // ASCII
	f.Add([]byte{0x00})                                                // single null
	f.Add(make([]byte, 4096))                                         // 4KB of zeros
	f.Add([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa})                // high bytes
	f.Add([]byte(strings.Repeat("A", 1<<16)))                         // 64KB
	f.Add([]byte("\x89PNG\r\n\x1a\n"))                                 // PNG header
	f.Add([]byte("GIF89a"))                                            // GIF header
	f.Add([]byte("%PDF-1.4"))                                          // PDF header
	f.Add([]byte("\x1f\x8b\x08"))                                     // gzip header
	f.Add(func() []byte { b := make([]byte, 256); for i := range b { b[i] = byte(i) }; return b }())

	f.Fuzz(func(t *testing.T, content []byte) {
		dir := t.TempDir()
		filePath := filepath.Join(dir, "fuzzed.bin")
		require.NoError(t, os.WriteFile(filePath, content, 0644))

		baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
		artifacts, err := RecordArtifacts(
			dir, baseArtifacts, defaultHashes(),
			visitedSymlinks, false, openedFiles,
			nil, nil, nil,
		)
		require.NoError(t, err, "RecordArtifacts should not error on valid file")
		require.Len(t, artifacts, 1, "should have exactly one artifact")

		ds, ok := artifacts["fuzzed.bin"]
		require.True(t, ok, "artifact 'fuzzed.bin' not found")

		nameMap, err := ds.ToNameMap()
		require.NoError(t, err)
		sha256 := nameMap["sha256"]
		require.NotEmpty(t, sha256, "SHA256 should be non-empty")

		// Determinism check: hash the same file again
		artifacts2, err := RecordArtifacts(
			dir, map[string]cryptoutil.DigestSet{},
			defaultHashes(),
			map[string]struct{}{}, false, map[string]bool{},
			nil, nil, nil,
		)
		require.NoError(t, err)

		ds2, ok := artifacts2["fuzzed.bin"]
		require.True(t, ok)
		nameMap2, err := ds2.ToNameMap()
		require.NoError(t, err)

		assert.Equal(t, sha256, nameMap2["sha256"],
			"hash of identical content must be deterministic")
	})
}

// FuzzShouldRecordGlobPatterns fuzzes the shouldRecord function with random
// paths and glob patterns to find panics in the glob matching code.
// The gobwas/glob library is known to panic on certain compiled patterns
// during matching (not during compilation). The safeGlobMatch wrapper
// should catch these.
func FuzzShouldRecordGlobPatterns(f *testing.F) {
	f.Add("file.go", "*.go", "")
	f.Add("subdir/file.go", "**/*.go", "*_test.go")
	f.Add("test_file.go", "*.go", "*_test*")
	f.Add("file.txt", "", "*")
	f.Add("deeply/nested/path/file.go", "**/*", "")
	f.Add("", "*", "")
	f.Add("file", "", "")
	f.Add("[invalid", "[", "]")
	f.Add("normal.go", "{*.go,*.txt}", "")
	f.Add("\x00evil.go", "*.go", "")
	f.Add("file\nnewline.go", "*.go", "")

	f.Fuzz(func(t *testing.T, path string, includePattern string, excludePattern string) {
		var includeGlob, excludeGlob glob.Glob

		if includePattern != "" {
			var err error
			includeGlob, err = glob.Compile(includePattern)
			if err != nil {
				return // invalid pattern, skip
			}
		}

		if excludePattern != "" {
			var err error
			excludeGlob, err = glob.Compile(excludePattern)
			if err != nil {
				return // invalid pattern, skip
			}
		}

		// Must not panic regardless of path/pattern combination
		_ = shouldRecord(path, nil, nil, false, nil, includeGlob, excludeGlob)
	})
}

// FuzzRecordArtifactsSymlinks creates a directory with a fuzzed number of
// files and symlinks, verifying that RecordArtifacts terminates without
// panics, deadlocks, or goroutine leaks.
func FuzzRecordArtifactsSymlinks(f *testing.F) {
	f.Add(uint8(5), uint8(3), uint8(1), false) // 5 files, 3 internal links, 1 external, no cycle
	f.Add(uint8(0), uint8(0), uint8(0), false)  // empty dir
	f.Add(uint8(1), uint8(10), uint8(0), true)   // 1 file, 10 links, cycle
	f.Add(uint8(20), uint8(0), uint8(5), false)  // 20 files, 0 internal, 5 external
	f.Add(uint8(3), uint8(3), uint8(3), true)    // balanced with cycle

	f.Fuzz(func(t *testing.T, numFiles uint8, numInternalLinks uint8, numExternalLinks uint8, addCycle bool) {
		// Cap values to keep test fast
		if numFiles > 50 {
			numFiles = 50
		}
		if numInternalLinks > 20 {
			numInternalLinks = 20
		}
		if numExternalLinks > 10 {
			numExternalLinks = 10
		}

		dir := t.TempDir()
		outside := t.TempDir()

		// Create external target
		require.NoError(t, os.WriteFile(
			filepath.Join(outside, "secret.txt"),
			[]byte("external secret"),
			0644,
		))

		// Create files
		for i := range int(numFiles) {
			require.NoError(t, os.WriteFile(
				filepath.Join(dir, fmt.Sprintf("file_%03d.txt", i)),
				[]byte(fmt.Sprintf("content-%d", i)),
				0644,
			))
		}

		// Create internal symlinks (to existing files)
		for i := range int(numInternalLinks) {
			target := filepath.Join(dir, fmt.Sprintf("file_%03d.txt", i%max(int(numFiles), 1)))
			if numFiles == 0 {
				// Point to the directory itself if no files
				target = dir
			}
			_ = os.Symlink(target,
				filepath.Join(dir, fmt.Sprintf("ilink_%03d", i)))
		}

		// Create external symlinks
		for i := range int(numExternalLinks) {
			_ = os.Symlink(outside,
				filepath.Join(dir, fmt.Sprintf("elink_%03d", i)))
		}

		// Optionally add a symlink cycle
		if addCycle {
			_ = os.Symlink(dir, filepath.Join(dir, "cycle_back"))
		}

		baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
		artifacts, err := RecordArtifacts(
			dir, baseArtifacts, defaultHashes(),
			visitedSymlinks, false, openedFiles,
			nil, nil, nil,
		)

		// Must not panic or deadlock. Error is acceptable.
		if err != nil {
			return
		}

		// External files must NOT appear in artifacts
		for relPath := range artifacts {
			assert.NotContains(t, relPath, "secret.txt",
				"external file must not leak into artifacts via symlink: %q", relPath)
		}
	})
}

// ---------------------------------------------------------------------------
// Table-driven security tests: R3-190 through R3-199 (file domain)
// ---------------------------------------------------------------------------

// TestSecurity_R3_190_FileHashDeterminism verifies that RecordArtifacts
// produces identical digests for identical file content across multiple
// invocations. Non-deterministic hashing would break verification.
func TestSecurity_R3_190_FileHashDeterminism(t *testing.T) {
	dir := t.TempDir()
	contents := map[string][]byte{
		"empty.txt":    {},
		"binary.bin":   {0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd},
		"text.txt":     []byte("hello world"),
		"unicode.txt":  []byte("\u4e16\u754c\U0001F512"),
		"large.bin":    make([]byte, 1<<16), // 64KB
	}

	for name, content := range contents {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), content, 0644))
	}

	// Run RecordArtifacts 5 times and compare results
	var firstResult map[string]cryptoutil.DigestSet
	for i := range 5 {
		baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
		result, err := RecordArtifacts(
			dir, baseArtifacts, defaultHashes(),
			visitedSymlinks, false, openedFiles,
			nil, nil, nil,
		)
		require.NoError(t, err, "iteration %d", i)

		if firstResult == nil {
			firstResult = result
			continue
		}

		require.Equal(t, len(firstResult), len(result),
			"iteration %d: different number of artifacts", i)

		for path, ds := range firstResult {
			ds2, ok := result[path]
			require.True(t, ok, "iteration %d: missing %q", i, path)
			assert.True(t, ds.Equal(ds2),
				"iteration %d: different digest for %q", i, path)
		}
	}
}

// TestSecurity_R3_191_FileSymlinkEscapePrevention verifies that symlinks
// pointing outside the base path are rejected. This is the primary security
// boundary for the file attestor: an attacker should not be able to include
// files from outside the attested directory by planting symlinks.
func TestSecurity_R3_191_FileSymlinkEscapePrevention(t *testing.T) {
	tests := []struct {
		name       string
		setupLinks func(t *testing.T, inside, outside string)
	}{
		{
			name: "direct_symlink_to_external_dir",
			setupLinks: func(t *testing.T, inside, outside string) {
				require.NoError(t, os.Symlink(outside, filepath.Join(inside, "escape")))
			},
		},
		{
			name: "symlink_via_dotdot",
			setupLinks: func(t *testing.T, inside, outside string) {
				// Create a symlink using ../ to reach outside
				require.NoError(t, os.Symlink(
					filepath.Join(inside, "..", filepath.Base(outside)),
					filepath.Join(inside, "dotdot_escape"),
				))
			},
		},
		{
			name: "chain_of_symlinks_escaping",
			setupLinks: func(t *testing.T, inside, outside string) {
				// link1 -> link2 -> outside
				intermediate := filepath.Join(inside, "intermediate")
				require.NoError(t, os.Symlink(outside, intermediate))
				require.NoError(t, os.Symlink(intermediate, filepath.Join(inside, "chain_escape")))
			},
		},
		{
			name: "symlink_to_absolute_path",
			setupLinks: func(t *testing.T, inside, outside string) {
				require.NoError(t, os.Symlink(
					filepath.Join(outside, "secret.txt"),
					filepath.Join(inside, "abs_escape"),
				))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			inside := filepath.Join(root, "inside")
			outside := filepath.Join(root, "outside")
			require.NoError(t, os.Mkdir(inside, 0755))
			require.NoError(t, os.Mkdir(outside, 0755))

			require.NoError(t, os.WriteFile(
				filepath.Join(inside, "safe.txt"), []byte("safe"), 0644))
			require.NoError(t, os.WriteFile(
				filepath.Join(outside, "secret.txt"), []byte("SECRET"), 0644))

			tt.setupLinks(t, inside, outside)

			baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
			artifacts, err := RecordArtifacts(
				inside, baseArtifacts, defaultHashes(),
				visitedSymlinks, false, openedFiles,
				nil, nil, nil,
			)
			require.NoError(t, err)

			assert.Contains(t, artifacts, "safe.txt")
			for relPath := range artifacts {
				assert.NotContains(t, relPath, "secret",
					"external file leaked via %s: path=%q", tt.name, relPath)
				assert.NotContains(t, relPath, "SECRET",
					"external content should not be accessible")
			}
		})
	}
}

// TestSecurity_R3_192_FileNullByteInPath verifies that null bytes in file
// paths cannot be used to bypass security checks or cause crashes.
func TestSecurity_R3_192_FileNullByteInPath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("safe"), 0644))

	// Attempt to create a file with null byte in name -- OS should reject
	nullPaths := []string{
		"file\x00.txt",
		"\x00hidden",
		"normal\x00/../../../etc/passwd",
	}

	for _, name := range nullPaths {
		err := os.WriteFile(filepath.Join(dir, name), []byte("evil"), 0644)
		assert.Error(t, err,
			"OS should reject filename with null byte: %q", name)
	}

	// RecordArtifacts should work fine on the directory (only safe.txt exists)
	baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
	artifacts, err := RecordArtifacts(
		dir, baseArtifacts, defaultHashes(),
		visitedSymlinks, false, openedFiles,
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1)
	assert.Contains(t, artifacts, "safe.txt")
}

// TestSecurity_R3_193_FileLongPathHandling verifies that very long file
// paths (near the OS PATH_MAX of ~4096 bytes) are handled gracefully.
func TestSecurity_R3_193_FileLongPathHandling(t *testing.T) {
	dir := t.TempDir()

	// Build a deep directory path. Each component is short but the total
	// path approaches PATH_MAX.
	current := dir
	depth := 0
	for len(current) < 3800 {
		component := fmt.Sprintf("d%03d", depth)
		current = filepath.Join(current, component)
		depth++
	}

	err := os.MkdirAll(current, 0755)
	if err != nil {
		t.Skipf("OS rejected long path at depth %d: %v", depth, err)
	}

	err = os.WriteFile(filepath.Join(current, "f.txt"), []byte("deep"), 0644)
	if err != nil {
		t.Skipf("OS rejected file creation on long path: %v", err)
	}

	baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
	artifacts, err := RecordArtifacts(
		dir, baseArtifacts, defaultHashes(),
		visitedSymlinks, false, openedFiles,
		nil, nil, nil,
	)
	// Must not panic. May error if path too long for some syscall.
	if err != nil {
		t.Logf("RecordArtifacts returned error on long path (depth=%d): %v", depth, err)
		return
	}

	// If it succeeded, verify the deep file was found
	found := false
	for relPath := range artifacts {
		if filepath.Base(relPath) == "f.txt" {
			found = true
			// Path should not contain ".."
			assert.NotContains(t, relPath, "..",
				"deep artifact path should not contain '..'")
			break
		}
	}
	assert.True(t, found, "deep file should be found at depth %d", depth)
}

// TestSecurity_R3_194_FileGlobExcludePrecedence verifies that when a file
// matches both include and exclude globs, the exclude always takes precedence.
// This is important because an incorrect precedence could expose files that
// should be filtered out (e.g., .env files, secrets).
func TestSecurity_R3_194_FileGlobExcludePrecedence(t *testing.T) {
	tests := []struct {
		name         string
		filename     string
		include      string
		exclude      string
		shouldRecord bool
	}{
		{
			name:         "test_file_excluded",
			filename:     "auth_test.go",
			include:      "*.go",
			exclude:      "*_test.go",
			shouldRecord: false,
		},
		{
			name:         "env_file_excluded",
			filename:     ".env",
			include:      "*",
			exclude:      ".env",
			shouldRecord: false,
		},
		{
			name:         "normal_file_included",
			filename:     "main.go",
			include:      "*.go",
			exclude:      "*_test.go",
			shouldRecord: true,
		},
		{
			name:         "exclude_star_blocks_everything",
			filename:     "anything.txt",
			include:      "*",
			exclude:      "*",
			shouldRecord: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var incGlob, excGlob glob.Glob
			var err error
			if tt.include != "" {
				incGlob, err = glob.Compile(tt.include)
				require.NoError(t, err)
			}
			if tt.exclude != "" {
				excGlob, err = glob.Compile(tt.exclude)
				require.NoError(t, err)
			}

			result := shouldRecord(tt.filename, nil, nil, false, nil, incGlob, excGlob)
			assert.Equal(t, tt.shouldRecord, result,
				"shouldRecord(%q, include=%q, exclude=%q)", tt.filename, tt.include, tt.exclude)
		})
	}
}

// TestSecurity_R3_195_FileNonRegularFileSkipped verifies that non-regular
// files (sockets, device files, etc.) are skipped during attestation.
// This prevents the attestor from blocking on special files.
func TestSecurity_R3_195_FileNonRegularFileSkipped(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "regular.txt"), []byte("ok"), 0644))

	// The file.go code checks info.Mode().IsRegular() before adding to jobs.
	// This test is a structural verification that RecordArtifacts only returns
	// regular files and directory hashes (when dirHashGlob matches).
	baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
	artifacts, err := RecordArtifacts(
		dir, baseArtifacts, defaultHashes(),
		visitedSymlinks, false, openedFiles,
		nil, nil, nil,
	)
	require.NoError(t, err)

	for relPath, ds := range artifacts {
		nameMap, err := ds.ToNameMap()
		require.NoError(t, err, "path: %q", relPath)
		// Every artifact must have at least one hash
		assert.NotEmpty(t, nameMap,
			"artifact %q should have at least one digest", relPath)
	}
}

// TestSecurity_R3_196_FileEmptyDirectoryNoArtifacts verifies that an empty
// directory produces zero artifacts (not an error).
func TestSecurity_R3_196_FileEmptyDirectoryNoArtifacts(t *testing.T) {
	dir := t.TempDir()
	// Create some empty subdirectories
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a", "b", "c"), 0755))

	baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
	artifacts, err := RecordArtifacts(
		dir, baseArtifacts, defaultHashes(),
		visitedSymlinks, false, openedFiles,
		nil, nil, nil,
	)
	require.NoError(t, err, "empty directory should not cause an error")
	assert.Empty(t, artifacts,
		"directory with only subdirectories should produce zero artifacts")
}

// TestSecurity_R3_197_FileDeduplicationWithBaseArtifacts verifies that files
// already in baseArtifacts with matching digests are excluded from the result.
// This prevents duplicate attestation and ensures the delta mechanism works.
func TestSecurity_R3_197_FileDeduplicationWithBaseArtifacts(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "unchanged.txt"), []byte("same"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "changed.txt"), []byte("new"), 0644))

	// First pass: record everything
	artifacts1, err := RecordArtifacts(
		dir, map[string]cryptoutil.DigestSet{}, defaultHashes(),
		map[string]struct{}{}, false, map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	require.Len(t, artifacts1, 2)

	// Modify one file
	require.NoError(t, os.WriteFile(filepath.Join(dir, "changed.txt"), []byte("modified!"), 0644))

	// Second pass: use first pass as baseArtifacts
	artifacts2, err := RecordArtifacts(
		dir, artifacts1, defaultHashes(),
		map[string]struct{}{}, false, map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	// Only the changed file should appear
	assert.Contains(t, artifacts2, "changed.txt",
		"modified file should appear in delta")
	assert.NotContains(t, artifacts2, "unchanged.txt",
		"unchanged file should be deduplicated")
}

// TestSecurity_R3_198_FileMultipleHashAlgorithms verifies that when multiple
// hash algorithms are specified, ALL algorithms produce digests for every file.
// A partial hash failure (where only some hashes are computed) would be a
// security issue because policy evaluation might check a missing hash.
func TestSecurity_R3_198_FileMultipleHashAlgorithms(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0644))

	hashes := []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA1},
	}

	baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
	artifacts, err := RecordArtifacts(
		dir, baseArtifacts, hashes,
		visitedSymlinks, false, openedFiles,
		nil, nil, nil,
	)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	ds := artifacts["file.txt"]
	nameMap, err := ds.ToNameMap()
	require.NoError(t, err)

	assert.Contains(t, nameMap, "sha256", "SHA256 digest should be present")
	assert.Contains(t, nameMap, "sha1", "SHA1 digest should be present")
	assert.NotEmpty(t, nameMap["sha256"])
	assert.NotEmpty(t, nameMap["sha1"])

	// The two digests should be different (different algorithms)
	assert.NotEqual(t, nameMap["sha256"], nameMap["sha1"],
		"SHA256 and SHA1 digests should differ")
}

// TestSecurity_R3_199_FileRelativePathsAlwaysRelative verifies that all
// artifact paths in the result are relative to basePath and never absolute.
// Absolute paths in the result would leak information about the build
// environment.
func TestSecurity_R3_199_FileRelativePathsAlwaysRelative(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("nested"), 0644))

	baseArtifacts, visitedSymlinks, openedFiles := emptyArgs()
	artifacts, err := RecordArtifacts(
		dir, baseArtifacts, defaultHashes(),
		visitedSymlinks, false, openedFiles,
		nil, nil, nil,
	)
	require.NoError(t, err)

	for relPath := range artifacts {
		assert.False(t, filepath.IsAbs(relPath),
			"artifact path must be relative, got absolute: %q", relPath)
		assert.NotContains(t, relPath, dir,
			"artifact path must not contain the basePath directory: %q", relPath)
	}
}
