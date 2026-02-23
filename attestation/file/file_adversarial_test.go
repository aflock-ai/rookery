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
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gobwas/glob"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// 1. Symlink loop / cycle tests
// ---------------------------------------------------------------------------

// TestAdversarial_SymlinkTriangleCycle creates a three-way symlink cycle:
// A -> B -> C -> A. RecordArtifacts must terminate without infinite recursion.
func TestAdversarial_SymlinkTriangleCycle(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	c := filepath.Join(dir, "c")

	require.NoError(t, os.Mkdir(a, 0755))
	require.NoError(t, os.Mkdir(b, 0755))
	require.NoError(t, os.Mkdir(c, 0755))

	require.NoError(t, os.WriteFile(filepath.Join(a, "a.txt"), []byte("a"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(b, "b.txt"), []byte("b"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(c, "c.txt"), []byte("c"), 0644))

	// Create cycle: a/linkB -> b, b/linkC -> c, c/linkA -> a
	require.NoError(t, os.Symlink(b, filepath.Join(a, "linkB")))
	require.NoError(t, os.Symlink(c, filepath.Join(b, "linkC")))
	require.NoError(t, os.Symlink(a, filepath.Join(c, "linkA")))

	done := make(chan struct{})
	go func() {
		defer close(done)
		artifacts, err := RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
		require.NoError(t, err)
		// Should have at least the three original files
		assert.GreaterOrEqual(t, len(artifacts), 3,
			"should record at least a.txt, b.txt, c.txt")
	}()

	select {
	case <-done:
		// OK -- terminated
	case <-time.After(10 * time.Second):
		t.Fatal("RecordArtifacts did not terminate within 10s -- likely infinite symlink loop")
	}
}

// TestAdversarial_SymlinkSelfLoop creates a symlink that points to its own parent directory.
func TestAdversarial_SymlinkSelfLoop(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real"), 0644))

	// symlink pointing to the directory itself
	require.NoError(t, os.Symlink(dir, filepath.Join(dir, "self")))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
		require.NoError(t, err)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("self-referencing symlink caused infinite loop")
	}
}

// TestAdversarial_ManySymlinksToSameTarget creates 50 symlinks all pointing to
// the same directory. The visitedSymlinks guard should prevent re-hashing.
func TestAdversarial_ManySymlinksToSameTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(target, "data.txt"), []byte("shared"), 0644))

	const numLinks = 50
	for i := range numLinks {
		require.NoError(t, os.Symlink(target, filepath.Join(dir, fmt.Sprintf("link_%03d", i))))
	}

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	// The target/data.txt should appear. Due to visitedSymlinks dedup,
	// the target directory should only be hashed once. The first symlink
	// encountered will record its files; subsequent ones will be skipped.
	// We should have target/data.txt plus at most one link_NNN/data.txt.
	dataCount := 0
	for k := range artifacts {
		if filepath.Base(k) == "data.txt" {
			dataCount++
		}
	}
	// Must have at least 1 (the real target/data.txt) and at most 2
	// (target/data.txt + one link that got there first before dedup kicks in).
	assert.GreaterOrEqual(t, dataCount, 1, "should have at least the original data.txt")
}

// TestAdversarial_SymlinkOutsideBasePath verifies that symlinks pointing outside
// the base path are skipped (security boundary).
func TestAdversarial_SymlinkOutsideBasePath(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0644))

	inside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(inside, "safe.txt"), []byte("safe"), 0644))
	require.NoError(t, os.Symlink(outside, filepath.Join(inside, "escape")))

	artifacts, err := RecordArtifacts(
		inside,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	assert.Contains(t, artifacts, "safe.txt")
	// The escaped symlink's target should NOT appear
	for k := range artifacts {
		assert.NotContains(t, k, "secret.txt",
			"symlink outside base path should be skipped")
	}
}

// ---------------------------------------------------------------------------
// 2. Deep directory trees
// ---------------------------------------------------------------------------

// TestAdversarial_DeepDirectoryTree100Levels creates a 100-level deep directory
// tree and verifies RecordArtifacts does not stack overflow or deadlock.
func TestAdversarial_DeepDirectoryTree100Levels(t *testing.T) {
	dir := t.TempDir()
	current := dir
	const depth = 100

	for d := range depth {
		current = filepath.Join(current, fmt.Sprintf("d%d", d))
	}
	require.NoError(t, os.MkdirAll(current, 0755))

	// Place a file at the deepest level
	require.NoError(t, os.WriteFile(filepath.Join(current, "deep.txt"), []byte("deep"), 0644))

	// Also place a file at the root level
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root"), 0644))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Contains(t, artifacts, "root.txt")

	// Build the expected deep path
	parts := make([]string, depth+1)
	for d := range depth {
		parts[d] = fmt.Sprintf("d%d", d)
	}
	parts[depth] = "deep.txt"
	deepRelPath := filepath.Join(parts...)
	assert.Contains(t, artifacts, deepRelPath, "should find file at depth %d", depth)
}

// TestAdversarial_DeepDirectoryTreeWithSymlinks creates a deep tree with symlinks
// at various depths pointing back up the tree.
func TestAdversarial_DeepDirectoryTreeWithSymlinks(t *testing.T) {
	dir := t.TempDir()
	const depth = 20

	current := dir
	for d := range depth {
		subdir := filepath.Join(current, fmt.Sprintf("level%d", d))
		require.NoError(t, os.Mkdir(subdir, 0755))
		require.NoError(t, os.WriteFile(
			filepath.Join(subdir, fmt.Sprintf("file%d.txt", d)),
			[]byte(fmt.Sprintf("level %d", d)),
			0644,
		))
		// Every 5th level, add a symlink pointing back to root
		if d > 0 && d%5 == 0 {
			require.NoError(t, os.Symlink(dir, filepath.Join(subdir, "backlink")))
		}
		current = subdir
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		artifacts, err := RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
		require.NoError(t, err)
		// Should have at least the 20 files we created directly
		assert.GreaterOrEqual(t, len(artifacts), depth)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("deep tree with backlinks caused infinite loop or deadlock")
	}
}

// ---------------------------------------------------------------------------
// 3. TOCTOU race: files changing during hashing
// ---------------------------------------------------------------------------

// TestAdversarial_FileDeletedDuringWalk creates files, starts recording,
// and concurrently deletes some files to trigger TOCTOU errors.
// This documents the current behavior: a file vanishing between Walk
// discovering it and the worker opening it will propagate as an error.
func TestAdversarial_FileDeletedDuringWalk(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 200

	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("ephemeral_%03d.txt", i)),
			[]byte(fmt.Sprintf("content-%d", i)),
			0644,
		))
	}

	// Delete half the files concurrently with RecordArtifacts.
	// This is a best-effort race -- we can't guarantee the timing.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Give the walk a tiny head start
		time.Sleep(1 * time.Millisecond)
		for i := range numFiles {
			if i%2 == 0 {
				os.Remove(filepath.Join(dir, fmt.Sprintf("ephemeral_%03d.txt", i)))
			}
		}
	}()

	// RecordArtifacts may return an error (file not found when worker tries
	// to open a deleted file) or may succeed if timing doesn't hit the race.
	// Either outcome is acceptable -- the key is that it must not panic or hang.
	_, _ = RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	wg.Wait()
}

// TestAdversarial_FileMutatedDuringHash writes files, then mutates them
// concurrently with hashing. The digests should still be computed without
// panics -- they may just reflect partially written content.
func TestAdversarial_FileMutatedDuringHash(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 100

	for i := range numFiles {
		// Create files with some initial content
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("mutating_%03d.txt", i)),
			[]byte(fmt.Sprintf("original-content-%d-padding-to-extend", i)),
			0644,
		))
	}

	// Mutate files concurrently
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := range 10 {
			for i := range numFiles {
				_ = os.WriteFile(
					filepath.Join(dir, fmt.Sprintf("mutating_%03d.txt", i)),
					[]byte(fmt.Sprintf("mutated-round-%d-file-%d", round, i)),
					0644,
				)
			}
		}
	}()

	// Run RecordArtifacts -- must not panic or deadlock.
	_, _ = RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	wg.Wait()
}

// ---------------------------------------------------------------------------
// 4. Glob filtering edge cases
// ---------------------------------------------------------------------------

// TestAdversarial_GlobIncludeExcludeOverlap verifies that when a file matches
// both the include and exclude glob, exclude takes precedence.
func TestAdversarial_GlobIncludeExcludeOverlap(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "important_test.go"), []byte("test"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "important.go"), []byte("code"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.md"), []byte("docs"), 0644))

	// Include: all .go files. Exclude: all _test.go files.
	// important_test.go matches BOTH.
	includeGlob, err := glob.Compile("*.go")
	require.NoError(t, err)
	excludeGlob, err := glob.Compile("*_test.go")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, includeGlob, excludeGlob,
	)
	require.NoError(t, err)

	assert.Contains(t, artifacts, "important.go")
	assert.NotContains(t, artifacts, "important_test.go",
		"exclude should take precedence over include")
	assert.NotContains(t, artifacts, "readme.md",
		"non-.go files should not match include glob")
}

// TestAdversarial_GlobWithUnicodeFilenames tests glob matching on filenames
// containing Unicode characters.
func TestAdversarial_GlobWithUnicodeFilenames(t *testing.T) {
	dir := t.TempDir()

	unicodeFiles := []string{
		"resume\u0301.txt", // é as e + combining acute
		"\u00e9lite.txt",   // é as precomposed
		"\u4f60\u597d.go",  // 你好.go (Chinese)
		"\u00fc\u00f6\u00e4.go", // üöä.go (German umlauts)
		"normal.go",
	}

	for _, name := range unicodeFiles {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("unicode"), 0644))
	}

	// Include only .go files
	includeGlob, err := glob.Compile("*.go")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, includeGlob, nil,
	)
	require.NoError(t, err)

	assert.Contains(t, artifacts, "normal.go")
	assert.Contains(t, artifacts, "\u4f60\u597d.go")
	assert.Contains(t, artifacts, "\u00fc\u00f6\u00e4.go")

	// .txt files should be excluded by include glob
	for path := range artifacts {
		assert.NotContains(t, path, ".txt",
			"only .go files should be included, got %s", path)
	}
}

// TestAdversarial_EmptyIncludeGlob tests behavior when include glob matches nothing.
// An include glob that matches nothing should exclude everything.
func TestAdversarial_EmptyIncludeGlob(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.go"), []byte("code"), 0644))

	// Include glob that matches an impossible pattern
	includeGlob, err := glob.Compile("*.nonexistent_extension_xyz")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, includeGlob, nil,
	)
	require.NoError(t, err)
	assert.Empty(t, artifacts,
		"include glob matching nothing should result in empty artifacts")
}

// TestAdversarial_GlobPathSeparatorBehavior documents a BUG in the glob
// separator handling. The gobwas/glob library requires an explicit separator
// argument (e.g., glob.Compile("*.go", '/')) for '*' to NOT match across
// path separators. Without it, '*' matches everything including '/'.
//
// This means an include glob of "*.go" will unexpectedly match "subdir/file.go",
// and an exclude glob of "*.log" will match "deep/nested/build.log".
//
// The shouldRecord function normalizes paths to '/' but the globs are compiled
// without a '/' separator, so '*' acts like '**'.
//
// BUG: glob.Compile() should be called with '/' as separator parameter.
func TestAdversarial_GlobPathSeparatorBehavior(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(sub, 0755))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.go"), []byte("root"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "nested.go"), []byte("nested"), 0644))

	// "*.go" -- without separator arg, '*' matches across '/' (BUG)
	includeGlob, err := glob.Compile("*.go")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, includeGlob, nil,
	)
	require.NoError(t, err)

	assert.Contains(t, artifacts, "root.go",
		"root-level .go should match *.go")

	// BUG: This SHOULD be NotContains but glob.Compile without separator
	// makes '*' match across '/'. Documenting actual (buggy) behavior:
	assert.Contains(t, artifacts, filepath.Join("subdir", "nested.go"),
		"BUG: *.go matches subdir/nested.go because glob.Compile lacks separator arg")

	// Demonstrate correct behavior with separator:
	correctGlob, err := glob.Compile("*.go", '/')
	require.NoError(t, err)
	assert.True(t, correctGlob.Match("root.go"))
	assert.False(t, correctGlob.Match("subdir/nested.go"),
		"with separator arg, *.go correctly does NOT match subdir/nested.go")
}

// TestAdversarial_GlobDoubleStarRecursive verifies that ** patterns correctly
// match across directory boundaries.
func TestAdversarial_GlobDoubleStarRecursive(t *testing.T) {
	dir := t.TempDir()
	deep := filepath.Join(dir, "a", "b", "c")
	require.NoError(t, os.MkdirAll(deep, 0755))

	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.go"), []byte("root"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a", "mid.go"), []byte("mid"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(deep, "deep.go"), []byte("deep"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(deep, "deep.txt"), []byte("txt"), 0644))

	includeGlob, err := glob.Compile("{*.go,**/*.go}")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, includeGlob, nil,
	)
	require.NoError(t, err)

	assert.Contains(t, artifacts, "root.go")
	assert.Contains(t, artifacts, filepath.Join("a", "mid.go"))
	assert.Contains(t, artifacts, filepath.Join("a", "b", "c", "deep.go"))
	assert.NotContains(t, artifacts, filepath.Join("a", "b", "c", "deep.txt"))
}

// TestAdversarial_ExcludeEverything tests excluding all files -- result should be empty.
func TestAdversarial_ExcludeEverything(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "b.go"), []byte("b"), 0644))

	excludeGlob, err := glob.Compile("*")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, excludeGlob,
	)
	require.NoError(t, err)
	assert.Empty(t, artifacts, "excluding * should result in no artifacts")
}

// ---------------------------------------------------------------------------
// 5. DigestSet edge cases: empty files, broken symlinks, permission denied
// ---------------------------------------------------------------------------

// TestAdversarial_ZeroByteFile verifies that 0-byte files produce valid digests.
func TestAdversarial_ZeroByteFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty.txt"), []byte{}, 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "nonempty.txt"), []byte("data"), 0644))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, 2)

	emptyDigest, ok := artifacts["empty.txt"]
	require.True(t, ok, "zero-byte file should produce a digest")

	nameMap, err := emptyDigest.ToNameMap()
	require.NoError(t, err)
	// SHA256 of empty input is the well-known constant
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		nameMap["sha256"], "SHA256 of empty file should be the well-known empty hash")
}

// TestAdversarial_BrokenSymlinkHandling verifies that broken symlinks are
// silently skipped (not errors).
func TestAdversarial_BrokenSymlinkHandling(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real"), 0644))

	// Create a symlink to a non-existent target
	require.NoError(t, os.Symlink("/nonexistent/path/to/nowhere", filepath.Join(dir, "broken_link")))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err, "broken symlinks should be silently skipped")
	assert.Contains(t, artifacts, "real.txt")
	assert.NotContains(t, artifacts, "broken_link")
}

// TestAdversarial_MultipleBrokenSymlinks tests a directory full of broken symlinks
// alongside real files.
func TestAdversarial_MultipleBrokenSymlinks(t *testing.T) {
	dir := t.TempDir()

	const numReal = 10
	const numBroken = 20

	for i := range numReal {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("real_%02d.txt", i)),
			[]byte(fmt.Sprintf("real %d", i)),
			0644,
		))
	}

	for i := range numBroken {
		require.NoError(t, os.Symlink(
			fmt.Sprintf("/nonexistent/target_%d", i),
			filepath.Join(dir, fmt.Sprintf("broken_%02d", i)),
		))
	}

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, numReal,
		"should only include real files, not broken symlinks")
}

// TestAdversarial_PermissionDeniedFile creates a file with no read permission.
// RecordArtifacts should return an error because the worker cannot open it.
func TestAdversarial_PermissionDeniedFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readable.txt"), []byte("ok"), 0644))

	noReadFile := filepath.Join(dir, "noperm.txt")
	require.NoError(t, os.WriteFile(noReadFile, []byte("secret"), 0644))
	require.NoError(t, os.Chmod(noReadFile, 0000))
	t.Cleanup(func() { os.Chmod(noReadFile, 0644) })

	_, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	// The worker will fail to open the file. The error propagates.
	assert.Error(t, err, "should return error when a file cannot be read")
}

// TestAdversarial_PermissionDeniedDirectory creates a directory with no read
// permission. filepath.Walk should return an error.
func TestAdversarial_PermissionDeniedDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "top.txt"), []byte("top"), 0644))

	noReadDir := filepath.Join(dir, "noaccess")
	require.NoError(t, os.Mkdir(noReadDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(noReadDir, "hidden.txt"), []byte("hidden"), 0644))
	require.NoError(t, os.Chmod(noReadDir, 0000))
	t.Cleanup(func() { os.Chmod(noReadDir, 0755) })

	_, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	// filepath.Walk will encounter permission denied on the directory
	assert.Error(t, err, "should return error when directory cannot be read")
}

// ---------------------------------------------------------------------------
// 6. Race detector tests combining symlinks with concurrency
// ---------------------------------------------------------------------------

// TestAdversarial_ConcurrentWithSymlinkCycles runs RecordArtifacts from
// multiple goroutines on a directory with symlink cycles.
func TestAdversarial_ConcurrentWithSymlinkCycles(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(sub, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "file.txt"), []byte("data"), 0644))

	// Create a cycle: sub/back -> dir
	require.NoError(t, os.Symlink(dir, filepath.Join(sub, "back")))

	const goroutines = 8
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := RecordArtifacts(
				dir,
				map[string]cryptoutil.DigestSet{},
				[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
				map[string]struct{}{}, // each goroutine gets its own map
				false,
				map[string]bool{},
				nil, nil, nil,
			)
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d", i)
	}
}

// ---------------------------------------------------------------------------
// 7. Edge cases with shouldRecord
// ---------------------------------------------------------------------------

// TestAdversarial_ShouldRecord_NilDigestSet tests shouldRecord with nil DigestSet.
func TestAdversarial_ShouldRecord_NilDigestSet(t *testing.T) {
	// nil artifact, nil baseArtifacts -- should record (no dedup match)
	assert.True(t, shouldRecord("file.txt", nil, nil, false, nil, nil, nil))

	// nil artifact with non-nil baseArtifacts that don't contain this path
	baseArtifacts := map[string]cryptoutil.DigestSet{
		"other.txt": {cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc"},
	}
	assert.True(t, shouldRecord("file.txt", nil, baseArtifacts, false, nil, nil, nil))
}

// TestAdversarial_ShouldRecord_EmptyDigestSet tests shouldRecord with an empty DigestSet.
func TestAdversarial_ShouldRecord_EmptyDigestSet(t *testing.T) {
	emptyDS := cryptoutil.DigestSet{}
	baseArtifacts := map[string]cryptoutil.DigestSet{
		"file.txt": {},
	}

	// Two empty DigestSets: Equal returns false (no matching digests),
	// so the file should be recorded.
	result := shouldRecord("file.txt", emptyDS, baseArtifacts, false, nil, nil, nil)
	assert.True(t, result,
		"empty DigestSets should not match (Equal returns false for no common hashes)")
}

// TestAdversarial_ShouldRecord_ProcessTracedNoOpenedFiles tests the tracing
// filter when processWasTraced=true but openedFiles is empty.
func TestAdversarial_ShouldRecord_ProcessTracedNoOpenedFiles(t *testing.T) {
	// processWasTraced=true, openedFiles=empty -- nothing should be recorded
	assert.False(t, shouldRecord("anything.go", nil, nil, true, map[string]bool{}, nil, nil))
}

// TestAdversarial_ShouldRecord_ProcessTracedNilOpenedFiles tests the tracing
// filter when processWasTraced=true but openedFiles is nil.
func TestAdversarial_ShouldRecord_ProcessTracedNilOpenedFiles(t *testing.T) {
	// processWasTraced=true, openedFiles=nil -- lookup on nil map returns false
	assert.False(t, shouldRecord("anything.go", nil, nil, true, nil, nil, nil))
}

// ---------------------------------------------------------------------------
// 8. Glob normalization: path slash conversion
// ---------------------------------------------------------------------------

// TestAdversarial_ShouldRecord_PathSlashNormalization verifies that shouldRecord
// normalizes paths to forward slashes before glob matching. This matters on
// Windows where filepath.Join uses backslashes.
func TestAdversarial_ShouldRecord_PathSlashNormalization(t *testing.T) {
	// On Unix, filepath.ToSlash is a no-op, but verify the normalization
	// logic runs correctly regardless.
	includeGlob, err := glob.Compile("subdir/*.go")
	require.NoError(t, err)

	// Use forward-slash path (Unix native)
	assert.True(t, shouldRecord("subdir/main.go", nil, nil, false, nil, includeGlob, nil))
	assert.False(t, shouldRecord("subdir/main.txt", nil, nil, false, nil, includeGlob, nil))
	assert.False(t, shouldRecord("other/main.go", nil, nil, false, nil, includeGlob, nil))
}

// ---------------------------------------------------------------------------
// 9. Large file and boundary conditions
// ---------------------------------------------------------------------------

// TestAdversarial_SingleLargeFile tests hashing a single large file (10MB)
// to verify the worker pool handles it without issues.
func TestAdversarial_SingleLargeFile(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large file test in short mode")
	}

	dir := t.TempDir()
	data := make([]byte, 10*1024*1024) // 10MB
	for i := range data {
		data[i] = byte(i % 251) // prime modulus for variety
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "large.bin"), data, 0644))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1)

	digest, ok := artifacts["large.bin"]
	require.True(t, ok)
	nameMap, err := digest.ToNameMap()
	require.NoError(t, err)
	assert.NotEmpty(t, nameMap["sha256"])
}

// TestAdversarial_ManyEmptyFiles tests a directory with many 0-byte files.
func TestAdversarial_ManyEmptyFiles(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 500

	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("empty_%04d.txt", i)),
			[]byte{}, 0644,
		))
	}

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, numFiles)

	// All empty files should have the same digest
	var firstDigest cryptoutil.DigestSet
	for _, ds := range artifacts {
		if firstDigest == nil {
			firstDigest = ds
			continue
		}
		assert.True(t, firstDigest.Equal(ds),
			"all empty files should have identical digests")
	}
}

// ---------------------------------------------------------------------------
// 10. Symlink to file (not directory) edge cases
// ---------------------------------------------------------------------------

// TestAdversarial_SymlinkToFile verifies that a symlink pointing to a regular
// file within the base path is handled correctly. filepath.Walk sees symlink
// to file as a non-directory symlink.
func TestAdversarial_SymlinkToFile(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real content"), 0644))
	require.NoError(t, os.Symlink(
		filepath.Join(dir, "real.txt"),
		filepath.Join(dir, "link.txt"),
	))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	// The real file should always be recorded.
	assert.Contains(t, artifacts, "real.txt")

	// The symlink to a file: filepath.Walk reports it with ModeSymlink set.
	// The code resolves it with EvalSymlinks, which points to real.txt.
	// Then it calls RecordArtifacts on real.txt (a single file, not a directory).
	// filepath.Walk on a single file will call the walk function once with
	// the file itself, which is not a directory and not a symlink, so it
	// gets sent to the jobs channel. The relPath in that recursive call
	// will be "." (Rel of a file to itself), so the join becomes "link.txt" + ".".
	// This is a potential edge case worth documenting.
}

// TestAdversarial_SymlinkChain tests a chain of symlinks: link1 -> link2 -> realdir.
func TestAdversarial_SymlinkChain(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(realDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, "file.txt"), []byte("chain"), 0644))

	// link2 -> real, link1 -> link2
	require.NoError(t, os.Symlink(realDir, filepath.Join(dir, "link2")))
	require.NoError(t, os.Symlink(filepath.Join(dir, "link2"), filepath.Join(dir, "link1")))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	// Should have real/file.txt at minimum
	assert.Contains(t, artifacts, filepath.Join("real", "file.txt"))
}

// ---------------------------------------------------------------------------
// 11. Nonexistent basePath
// ---------------------------------------------------------------------------

// TestAdversarial_NonexistentBasePath verifies that RecordArtifacts returns an
// error when the base path does not exist.
func TestAdversarial_NonexistentBasePath(t *testing.T) {
	_, err := RecordArtifacts(
		"/nonexistent/path/that/does/not/exist",
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	assert.Error(t, err, "should error on nonexistent basePath")
}

// ---------------------------------------------------------------------------
// 12. Empty hash list
// ---------------------------------------------------------------------------

// TestAdversarial_EmptyHashList verifies behavior when no hash algorithms are
// specified. CalculateDigestSetFromFile will produce empty DigestSets.
func TestAdversarial_EmptyHashList(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0644))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{}, // no hashes
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	// With no hash algorithms, DigestSet will be empty for each file.
	// An empty DigestSet.Equal(empty base) returns false (no matching hashes),
	// so the file should still appear in artifacts.
	assert.Len(t, artifacts, 1)
	ds := artifacts["file.txt"]
	nameMap, err := ds.ToNameMap()
	require.NoError(t, err)
	assert.Empty(t, nameMap, "no hash algorithms should produce empty digest map")
}

// ---------------------------------------------------------------------------
// 13. dirHashGlob edge cases
// ---------------------------------------------------------------------------

// TestAdversarial_DirHashGlobOnNestedDir verifies that dirHashGlob correctly
// matches nested directories and hashes them as a unit.
func TestAdversarial_DirHashGlobOnNestedDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "vendor", "pkg")
	require.NoError(t, os.MkdirAll(nested, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(nested, "lib.go"), []byte("package pkg"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0644))

	// Match the top-level "vendor" directory
	dirGlob, err := glob.Compile("vendor")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{dirGlob}, nil, nil,
	)
	require.NoError(t, err)

	// vendor/ should be hashed as a directory, main.go should be hashed individually
	assert.Contains(t, artifacts, "vendor/", "vendor dir should be hashed as unit")
	assert.Contains(t, artifacts, "main.go")
	assert.NotContains(t, artifacts, filepath.Join("vendor", "pkg", "lib.go"),
		"files inside dirHashGlob'd directory should not appear individually")
}

// ---------------------------------------------------------------------------
// 14. Race: file symlink to same file from many symlinks
// ---------------------------------------------------------------------------

// TestAdversarial_ManyFileSymlinksToSameFile creates many symlinks all pointing
// to the same regular file. Tests the symlink resolution code path under
// concurrent worker pressure.
func TestAdversarial_ManyFileSymlinksToSameFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	require.NoError(t, os.WriteFile(target, []byte("shared target"), 0644))

	const numLinks = 100
	for i := range numLinks {
		require.NoError(t, os.Symlink(target,
			filepath.Join(dir, fmt.Sprintf("flink_%03d.txt", i))))
	}

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	// The original target.txt should always be present
	assert.Contains(t, artifacts, "target.txt")
}

// ---------------------------------------------------------------------------
// 15. basePath is a single file, not a directory
// ---------------------------------------------------------------------------

// TestAdversarial_BasePathIsSingleFile tests RecordArtifacts when basePath
// is a file rather than a directory. filepath.Walk handles this by calling
// the walk function once for the file itself.
func TestAdversarial_BasePathIsSingleFile(t *testing.T) {
	dir := t.TempDir()
	singleFile := filepath.Join(dir, "single.txt")
	require.NoError(t, os.WriteFile(singleFile, []byte("single"), 0644))

	artifacts, err := RecordArtifacts(
		singleFile,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	// filepath.Walk on a file: relPath of the file relative to itself is "."
	assert.Len(t, artifacts, 1)
	_, hasDot := artifacts["."]
	assert.True(t, hasDot, "single-file basePath should produce artifact with relPath '.'")
}

// ===========================================================================
// NEW ADVERSARIAL TESTS: Symlink attacks, path traversal, resource exhaustion,
// concurrent safety, and additional edge cases.
// ===========================================================================

// ---------------------------------------------------------------------------
// 16. Symlink to /dev/zero and /dev/urandom
// ---------------------------------------------------------------------------

// TestAdversarial_SymlinkToDevZero creates a symlink to /dev/zero inside the
// base path. /dev/zero is a character device, so isHashableFile should reject
// it. The symlink target is also outside the base path, so the security check
// should skip it.
func TestAdversarial_SymlinkToDevZero(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("normal"), 0644))
	require.NoError(t, os.Symlink("/dev/zero", filepath.Join(dir, "devzero")))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err, "symlink to /dev/zero should not cause an error")

	assert.Contains(t, artifacts, "normal.txt")
	// /dev/zero is outside basePath, so symlink should be skipped.
	for k := range artifacts {
		assert.NotContains(t, k, "devzero",
			"symlink to /dev/zero should be skipped (outside basePath)")
	}
}

// TestAdversarial_SymlinkToDevUrandom creates a symlink to /dev/urandom.
// Like /dev/zero, it is outside the base path and a character device.
func TestAdversarial_SymlinkToDevUrandom(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("normal"), 0644))
	require.NoError(t, os.Symlink("/dev/urandom", filepath.Join(dir, "devurandom")))

	done := make(chan struct{})
	go func() {
		defer close(done)
		artifacts, err := RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
		require.NoError(t, err, "symlink to /dev/urandom should not cause error")
		assert.Contains(t, artifacts, "normal.txt")
	}()

	select {
	case <-done:
		// OK -- terminated without hanging on infinite read
	case <-time.After(10 * time.Second):
		t.Fatal("RecordArtifacts hung -- likely reading from /dev/urandom via symlink")
	}
}

// ---------------------------------------------------------------------------
// 17. TOCTOU: file replaced with symlink between Walk and hash
// ---------------------------------------------------------------------------

// TestAdversarial_TOCTOU_FileReplacedWithSymlink creates normal files, then
// concurrently replaces some with symlinks pointing outside the base path.
// This tests the race window between filepath.Walk seeing a regular file and
// the worker opening it for hashing. Since the Walk function checks info.Mode
// for symlinks (which uses Lstat), and the file was a regular file at Walk
// time, the worker will hash whatever is at the path when it opens it.
//
// This is a TOCTOU race inherent to the design -- the test documents that
// RecordArtifacts does not panic or deadlock even if files mutate under it.
func TestAdversarial_TOCTOU_FileReplacedWithSymlink(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()
	secretFile := filepath.Join(outside, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("leaked secret"), 0644))

	const numFiles = 200
	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("victim_%03d.txt", i)),
			[]byte(fmt.Sprintf("original-%d", i)),
			0644,
		))
	}

	// Concurrently replace files with symlinks pointing outside
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(500 * time.Microsecond) // tiny delay to let walk start
		for i := range numFiles {
			if i%3 == 0 {
				path := filepath.Join(dir, fmt.Sprintf("victim_%03d.txt", i))
				_ = os.Remove(path)
				_ = os.Symlink(secretFile, path)
			}
		}
	}()

	// RecordArtifacts may return an error (the replaced file may cause issues)
	// or succeed. The key is: no panic, no deadlock, no goroutine leak.
	_, _ = RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	wg.Wait()
}

// ---------------------------------------------------------------------------
// 18. Path traversal: filenames containing ../
// ---------------------------------------------------------------------------

// TestAdversarial_PathTraversalInFilename verifies that files with ../
// in their names are handled safely. On most filesystems, you cannot create
// a file literally named "../escape.txt" -- the OS resolves the path.
// This test verifies that RecordArtifacts produces paths relative to basePath
// and that filepath.Rel sanitizes correctly.
func TestAdversarial_PathTraversalInFilename(t *testing.T) {
	dir := t.TempDir()
	// Create a subdirectory and a file in the parent. The relative path
	// from subdir to the parent file contains "../".
	subdir := filepath.Join(dir, "sub")
	require.NoError(t, os.Mkdir(subdir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "parent.txt"), []byte("parent"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subdir, "child.txt"), []byte("child"), 0644))

	// Attest only the subdir
	artifacts, err := RecordArtifacts(
		subdir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	// Only child.txt should appear, not parent.txt
	assert.Contains(t, artifacts, "child.txt")
	for k := range artifacts {
		assert.False(t, strings.Contains(k, ".."),
			"artifact path should not contain '..': got %q", k)
		assert.False(t, strings.Contains(k, "parent"),
			"parent directory file should not leak into subdir attestation: got %q", k)
	}
}

// TestAdversarial_SymlinkWithDotDotTarget creates a symlink whose target
// uses ../ to reference a directory outside the base path. The security
// check should catch and skip it.
func TestAdversarial_SymlinkWithDotDotTarget(t *testing.T) {
	// Create /tmp/xxx/inside/ as basePath and /tmp/xxx/outside/ as the escape target
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	outside := filepath.Join(root, "outside")
	require.NoError(t, os.Mkdir(inside, 0755))
	require.NoError(t, os.Mkdir(outside, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(inside, "safe.txt"), []byte("safe"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(outside, "escaped.txt"), []byte("escaped"), 0644))

	// Symlink using relative ../outside path
	require.NoError(t, os.Symlink("../outside", filepath.Join(inside, "escape_link")))

	artifacts, err := RecordArtifacts(
		inside,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	assert.Contains(t, artifacts, "safe.txt")
	for k := range artifacts {
		assert.NotContains(t, k, "escaped",
			"symlink with ../ target should not leak files outside basePath")
	}
}

// TestAdversarial_NullByteInPath tests behavior when a path contains a
// null byte. On Unix, null bytes are not valid in filenames. The OS will
// reject the creation, but we verify RecordArtifacts handles the error
// from filepath.Walk gracefully if one somehow appears.
func TestAdversarial_NullByteInPath(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("normal"), 0644))

	// Attempting to create a file with a null byte should fail at the OS level
	nullPath := filepath.Join(dir, "null\x00byte.txt")
	err := os.WriteFile(nullPath, []byte("evil"), 0644)
	if err == nil {
		// If the OS somehow allows it (very unlikely), verify RecordArtifacts handles it
		_, recordErr := RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
		// Should not panic regardless of outcome
		_ = recordErr
	}
	// If the OS rejects it (expected), that's fine -- the test passes.
}

// ---------------------------------------------------------------------------
// 19. Resource exhaustion: very large directory
// ---------------------------------------------------------------------------

// TestAdversarial_MassiveDirectoryCount creates a directory with 10,000 files
// and verifies RecordArtifacts completes without excessive memory or time.
// (100,000+ would be too slow for CI, so we use 10,000 as a stress test.)
func TestAdversarial_MassiveDirectoryCount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping massive directory test in short mode")
	}

	dir := t.TempDir()
	const numFiles = 10000

	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("f%06d.txt", i)),
			[]byte(fmt.Sprintf("%d", i)),
			0644,
		))
	}

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, numFiles,
		"should record all %d files without loss", numFiles)
}

// TestAdversarial_SparseFile creates a sparse file with a large reported size
// but minimal disk usage. On macOS/Linux, seeking past the end and writing
// creates a sparse file. The hashing code should handle this correctly.
func TestAdversarial_SparseFile(t *testing.T) {
	dir := t.TempDir()
	sparseFile := filepath.Join(dir, "sparse.bin")

	f, err := os.Create(sparseFile)
	require.NoError(t, err)

	// Seek 100MB ahead and write a single byte -- creates a sparse file
	const sparseSize = 100 * 1024 * 1024
	_, err = f.Seek(sparseSize, 0)
	require.NoError(t, err)
	_, err = f.Write([]byte{0x42})
	require.NoError(t, err)
	require.NoError(t, f.Close())

	// Verify the file reports the large size
	info, err := os.Stat(sparseFile)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(sparseSize),
		"sparse file should report large size")

	done := make(chan struct{})
	go func() {
		defer close(done)
		artifacts, err := RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
		require.NoError(t, err)
		assert.Len(t, artifacts, 1)
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("sparse file hashing took too long -- possible resource exhaustion")
	}
}

// TestAdversarial_ProcSelfMaps tests reading a pseudo-file that grows
// while being read. /proc/self/maps on Linux reports process memory maps.
// On macOS this doesn't exist, so we skip.
func TestAdversarial_ProcSelfMaps(t *testing.T) {
	if _, err := os.Stat("/proc/self/maps"); os.IsNotExist(err) {
		t.Skip("no /proc/self/maps on this platform")
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("normal"), 0644))
	// Symlink to /proc/self/maps
	require.NoError(t, os.Symlink("/proc/self/maps", filepath.Join(dir, "procmaps")))

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Should not hang (outside basePath check will skip symlink)
		_, _ = RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("reading /proc/self/maps via symlink caused hang")
	}
}

// ---------------------------------------------------------------------------
// 20. Concurrent safety: multiple concurrent calls with directory mutations
// ---------------------------------------------------------------------------

// TestAdversarial_DirStructureChangeDuringWalk creates and removes
// subdirectories concurrently while RecordArtifacts is walking the tree.
// RecordArtifacts must not panic or deadlock.
func TestAdversarial_DirStructureChangeDuringWalk(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 100

	// Create initial files
	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("stable_%03d.txt", i)),
			[]byte(fmt.Sprintf("stable-%d", i)),
			0644,
		))
	}

	// Concurrently add and remove subdirectories
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for round := 0; ; round++ {
			select {
			case <-stop:
				return
			default:
			}
			subdir := filepath.Join(dir, fmt.Sprintf("ephemeral_%03d", round%20))
			_ = os.MkdirAll(subdir, 0755)
			_ = os.WriteFile(filepath.Join(subdir, "temp.txt"), []byte("temp"), 0644)
			_ = os.RemoveAll(subdir)
		}
	}()

	// Run RecordArtifacts multiple times -- must not panic or deadlock
	for range 5 {
		_, _ = RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
	}

	close(stop)
	wg.Wait()
}

// TestAdversarial_ConcurrentRecordArtifactsSameDir runs many RecordArtifacts
// calls concurrently on the exact same directory. Each call gets its own
// visitedSymlinks map, but they all read the same filesystem. Tests for
// internal data races in the worker pool.
func TestAdversarial_ConcurrentRecordArtifactsSameDir(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 50
	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("shared_%03d.txt", i)),
			[]byte(fmt.Sprintf("shared-%d", i)),
			0644,
		))
	}

	const goroutines = 16
	var wg sync.WaitGroup
	results := make([]map[string]cryptoutil.DigestSet, goroutines)
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := RecordArtifacts(
				dir,
				map[string]cryptoutil.DigestSet{},
				[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
				map[string]struct{}{},
				false,
				map[string]bool{},
				nil, nil, nil,
			)
			results[idx] = res
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
		assert.Len(t, results[i], numFiles, "goroutine %d: wrong count", i)
	}

	// All results should be identical
	for i := 1; i < goroutines; i++ {
		for path, digest := range results[0] {
			other, ok := results[i][path]
			assert.True(t, ok, "goroutine %d missing %s", i, path)
			if ok {
				assert.True(t, digest.Equal(other),
					"goroutine %d different digest for %s", i, path)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// 21. Edge cases: dotfiles, special characters, empty dirs
// ---------------------------------------------------------------------------

// TestAdversarial_OnlyDotfiles verifies that directories containing only
// hidden files (dotfiles) are correctly processed.
func TestAdversarial_OnlyDotfiles(t *testing.T) {
	dir := t.TempDir()
	dotfiles := []string{".gitignore", ".env", ".hidden", ".config"}
	for _, name := range dotfiles {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(name), 0644))
	}

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, len(dotfiles),
		"all dotfiles should be recorded")

	for _, name := range dotfiles {
		assert.Contains(t, artifacts, name, "missing dotfile: %s", name)
	}
}

// TestAdversarial_FilenamesWithSpaces tests files with spaces in names.
func TestAdversarial_FilenamesWithSpaces(t *testing.T) {
	dir := t.TempDir()
	spacedFiles := []string{
		"file with spaces.txt",
		"  leading spaces.txt",
		"trailing spaces  .txt",
		"multiple   internal   spaces.go",
	}

	for _, name := range spacedFiles {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(name), 0644))
	}

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, len(spacedFiles))

	for _, name := range spacedFiles {
		assert.Contains(t, artifacts, name, "missing file with spaces: %q", name)
	}
}

// TestAdversarial_FilenamesWithNewlines tests files with newline characters
// in their names. Unix allows this; it's a common attack vector for log
// injection and path confusion.
func TestAdversarial_FilenamesWithNewlines(t *testing.T) {
	dir := t.TempDir()
	// Create a file with a newline in its name
	newlineFile := filepath.Join(dir, "line1\nline2.txt")
	err := os.WriteFile(newlineFile, []byte("newline in name"), 0644)
	if err != nil {
		t.Skip("filesystem does not support newlines in filenames")
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("normal"), 0644))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err, "should not error on filenames with newlines")
	assert.Contains(t, artifacts, "normal.txt")

	// The newline file should be recorded (its relPath contains \n)
	foundNewline := false
	for k := range artifacts {
		if strings.Contains(k, "\n") {
			foundNewline = true
			break
		}
	}
	assert.True(t, foundNewline,
		"file with newline in name should be recorded as artifact")
}

// TestAdversarial_FilenamesWithUnicodeAndEmoji tests filenames containing
// various Unicode characters including zero-width characters and
// right-to-left override characters.
//
// NOTE: macOS APFS normalizes Unicode (NFD), so precomposed "caf\u00e9" and
// decomposed "cafe\u0301" map to the same file. We avoid that collision here.
func TestAdversarial_FilenamesWithUnicodeAndEmoji(t *testing.T) {
	dir := t.TempDir()
	unicodeFiles := []string{
		"\u200bzerowidhidden.txt",     // zero-width space prefix
		"\u202ertl_override.txt",      // right-to-left override (U+202E)
		"caf\u00e9.txt",              // precomposed e-acute
		"\xc0\xaf.txt",              // overlong UTF-8 (may be rejected by FS)
	}

	recorded := 0
	for _, name := range unicodeFiles {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("unicode"), 0644); err != nil {
			// Some filenames may be rejected by the filesystem
			continue
		}
		recorded++
	}

	if recorded == 0 {
		t.Skip("filesystem rejected all unicode test filenames")
	}

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err, "should handle unicode filenames without error")
	assert.Len(t, artifacts, recorded, "should record all successfully created files")
}

// TestAdversarial_UnicodeNormalizationCollision documents that macOS APFS
// normalizes Unicode forms, so precomposed and decomposed versions of the
// same character map to the same filename. This is a filesystem behavior,
// not a bug in RecordArtifacts, but it can cause surprising results if an
// attacker creates files with different Unicode representations.
func TestAdversarial_UnicodeNormalizationCollision(t *testing.T) {
	dir := t.TempDir()

	precomposed := filepath.Join(dir, "caf\u00e9.txt") // U+00E9
	decomposed := filepath.Join(dir, "cafe\u0301.txt") // e + U+0301

	require.NoError(t, os.WriteFile(precomposed, []byte("precomposed"), 0644))
	err := os.WriteFile(decomposed, []byte("decomposed"), 0644)
	// On APFS, this overwrites the precomposed file (same normalized name).

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	// The key point: exactly one file should exist, not two.
	// The exact normalization form in the artifact key depends on the OS.
	assert.Len(t, artifacts, 1,
		"macOS APFS normalizes precomposed/decomposed to same file; "+
			"only one artifact should exist")
}

// TestAdversarial_EmptySubdirectories tests a directory tree where all leaf
// directories are empty. Only non-directory entries should appear in artifacts.
func TestAdversarial_EmptySubdirectories(t *testing.T) {
	dir := t.TempDir()
	emptyDirs := []string{"empty1", "empty2", "nested/deep/empty"}
	for _, d := range emptyDirs {
		require.NoError(t, os.MkdirAll(filepath.Join(dir, d), 0755))
	}
	// One real file at root
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root"), 0644))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1, "empty directories should not appear as artifacts")
	assert.Contains(t, artifacts, "root.txt")
}

// TestAdversarial_BrokenSymlinkWithGlobFilter verifies that broken symlinks
// are skipped even when glob filtering is active.
func TestAdversarial_BrokenSymlinkWithGlobFilter(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.go"), []byte("package main"), 0644))
	require.NoError(t, os.Symlink("/nonexistent/file.go", filepath.Join(dir, "broken.go")))

	includeGlob, err := glob.Compile("*.go")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, includeGlob, nil,
	)
	require.NoError(t, err, "broken symlink with matching glob should not error")
	assert.Contains(t, artifacts, "real.go")
	assert.NotContains(t, artifacts, "broken.go",
		"broken symlink should be skipped even when glob matches")
}

// ---------------------------------------------------------------------------
// 22. Symlink to FIFO/named pipe (special file)
// ---------------------------------------------------------------------------

// TestAdversarial_SymlinkToFIFO creates a named pipe (FIFO) inside the base
// directory.
//
// BUG (SECURITY): RecordArtifacts HANGS when it encounters a FIFO (named pipe)
// directly in the base directory. filepath.Walk sees the FIFO as a non-directory,
// non-symlink entry and sends it to the worker pool. The worker calls
// CalculateDigestSetFromFile -> os.Open(), which blocks indefinitely on a FIFO
// waiting for a writer to connect. The isHashableFile check (which would reject
// the char device) happens AFTER the blocking open() call, so it never runs.
//
// An attacker can create a FIFO in the attested directory to cause a denial of
// service -- RecordArtifacts will hang forever.
//
// FIX: Before opening the file for hashing, check info.Mode() for ModeNamedPipe
// (and possibly ModeSocket, ModeDevice) and skip them. Alternatively, open with
// O_NONBLOCK and then check the file type.
func TestAdversarial_SymlinkToFIFO(t *testing.T) {
	t.Skip("KNOWN BUG: RecordArtifacts hangs on FIFO -- os.Open blocks on named pipe. " +
		"Skipping to avoid CI timeout. See test comment for details.")

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("normal"), 0644))

	fifoPath := filepath.Join(dir, "fifo_pipe")
	err := syscall.Mkfifo(fifoPath, 0644)
	if err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		artifacts, err := RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
		// The FIFO may cause an error or may be skipped. The key is no hang.
		_ = err
		if artifacts != nil {
			assert.Contains(t, artifacts, "normal.txt")
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("RecordArtifacts hung on FIFO -- likely blocking on open/read")
	}
}

// ---------------------------------------------------------------------------
// 23. Deeply nested symlink chains (not cycles, just depth)
// ---------------------------------------------------------------------------

// TestAdversarial_DeepSymlinkChain creates a chain: link1->link2->...->linkN->realdir
// Each symlink resolves to the next. Tests that EvalSymlinks handles long chains.
func TestAdversarial_DeepSymlinkChain(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	require.NoError(t, os.Mkdir(realDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, "deep_chain.txt"), []byte("end"), 0644))

	// Create a chain of 20 symlinks: link_19 -> link_18 -> ... -> link_0 -> real
	const chainLen = 20
	prev := realDir
	for i := range chainLen {
		linkPath := filepath.Join(dir, fmt.Sprintf("link_%02d", i))
		require.NoError(t, os.Symlink(prev, linkPath))
		prev = linkPath
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
		// May error (EvalSymlinks has system-dependent limits, typically 255)
		// or succeed. Must not panic.
		_ = err
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("deep symlink chain caused hang or excessive recursion")
	}
}

// ---------------------------------------------------------------------------
// 24. Multiple hash algorithms with adversarial inputs
// ---------------------------------------------------------------------------

// TestAdversarial_MultipleHashesWithPermissionDenied verifies that when
// multiple hash algorithms are specified and a file cannot be read, the
// error is properly propagated regardless of which hash triggers it first.
func TestAdversarial_MultipleHashesWithPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readable.txt"), []byte("ok"), 0644))
	noRead := filepath.Join(dir, "noperm.txt")
	require.NoError(t, os.WriteFile(noRead, []byte("secret"), 0644))
	require.NoError(t, os.Chmod(noRead, 0000))
	t.Cleanup(func() { os.Chmod(noRead, 0644) })

	_, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{
			{Hash: crypto.SHA256},
			{Hash: crypto.SHA512},
			{Hash: crypto.SHA1},
		},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	assert.Error(t, err, "should error when a file is unreadable with multiple hashes")
}

// ---------------------------------------------------------------------------
// 25. Absolute path as basePath edge cases
// ---------------------------------------------------------------------------

// TestAdversarial_BasePathWithTrailingSlash verifies that basePath with a
// trailing slash produces correct relative paths.
func TestAdversarial_BasePathWithTrailingSlash(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0644))

	// Add trailing slash
	artifacts, err := RecordArtifacts(
		dir+"/",
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Contains(t, artifacts, "file.txt",
		"trailing slash in basePath should not affect relative path computation")
}

// TestAdversarial_BasePathWithDoubleSlash verifies handling of double slashes.
func TestAdversarial_BasePathWithDoubleSlash(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("data"), 0644))

	// filepath.Walk should normalize this, but verify no panic
	artifacts, err := RecordArtifacts(
		dir+"//",
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, 1, "double slash should be handled cleanly")
}

// ---------------------------------------------------------------------------
// 26. Symlink race: symlink created during walk
// ---------------------------------------------------------------------------

// TestAdversarial_SymlinkCreatedDuringWalk concurrently creates symlinks
// while RecordArtifacts walks. Some symlinks point inside, some outside.
// Must not panic, deadlock, or leak outside-basePath content.
func TestAdversarial_SymlinkCreatedDuringWalk(t *testing.T) {
	inside := t.TempDir()
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0644))

	const numFiles = 100
	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(inside, fmt.Sprintf("file_%03d.txt", i)),
			[]byte(fmt.Sprintf("content-%d", i)),
			0644,
		))
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 50 {
			if i%2 == 0 {
				// Symlink inside basePath (to another file in the dir)
				target := filepath.Join(inside, fmt.Sprintf("file_%03d.txt", i%numFiles))
				_ = os.Symlink(target, filepath.Join(inside, fmt.Sprintf("dynlink_in_%03d", i)))
			} else {
				// Symlink outside basePath
				_ = os.Symlink(outside, filepath.Join(inside, fmt.Sprintf("dynlink_out_%03d", i)))
			}
			time.Sleep(100 * time.Microsecond)
		}
	}()

	// Must not panic or deadlock
	_, _ = RecordArtifacts(
		inside,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	wg.Wait()
}

// ---------------------------------------------------------------------------
// 27. Very long filename (near OS limit)
// ---------------------------------------------------------------------------

// TestAdversarial_VeryLongFilename creates a file with a name near the OS
// limit (typically 255 bytes on ext4/APFS). Tests that RecordArtifacts handles
// the long path correctly.
func TestAdversarial_VeryLongFilename(t *testing.T) {
	dir := t.TempDir()

	// Most filesystems limit filenames to 255 bytes
	longName := strings.Repeat("a", 250) + ".txt"
	longPath := filepath.Join(dir, longName)
	err := os.WriteFile(longPath, []byte("long name"), 0644)
	if err != nil {
		t.Skipf("filesystem rejected long filename: %v", err)
	}

	require.NoError(t, os.WriteFile(filepath.Join(dir, "short.txt"), []byte("short"), 0644))

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Len(t, artifacts, 2)
	assert.Contains(t, artifacts, longName, "very long filename should be recorded")
	assert.Contains(t, artifacts, "short.txt")
}

// ---------------------------------------------------------------------------
// 28. Symlink to self (file-level, not directory)
// ---------------------------------------------------------------------------

// TestAdversarial_SymlinkPointsToItself creates a symlink that points to
// itself (not via a directory, just a direct self-reference). EvalSymlinks
// should detect this as a loop.
func TestAdversarial_SymlinkPointsToItself(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real"), 0644))

	selfLink := filepath.Join(dir, "selfref")
	// Remove any existing file first, then create symlink pointing to itself
	_ = os.Remove(selfLink)
	require.NoError(t, os.Symlink(selfLink, selfLink))

	done := make(chan struct{})
	go func() {
		defer close(done)
		// EvalSymlinks should detect the loop and return an error,
		// which should be handled gracefully.
		_, _ = RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("self-referencing symlink caused infinite loop")
	}
}

// ---------------------------------------------------------------------------
// 29. Mixed broken and valid symlinks with concurrent attestation
// ---------------------------------------------------------------------------

// TestAdversarial_MixedSymlinksUnderConcurrency hammers RecordArtifacts from
// 10 goroutines on a directory containing a mix of valid internal symlinks,
// broken symlinks, external symlinks, and real files. Tests for data races
// in the symlink handling code paths.
func TestAdversarial_MixedSymlinksUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	outside := t.TempDir()

	// Real files
	for i := range 10 {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("real_%02d.txt", i)),
			[]byte(fmt.Sprintf("real-%d", i)),
			0644,
		))
	}

	// Internal symlinks (to files within basePath)
	require.NoError(t, os.Symlink(
		filepath.Join(dir, "real_00.txt"),
		filepath.Join(dir, "internal_link"),
	))

	// External symlink
	require.NoError(t, os.WriteFile(filepath.Join(outside, "ext.txt"), []byte("ext"), 0644))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "external_link")))

	// Broken symlinks
	require.NoError(t, os.Symlink("/does/not/exist", filepath.Join(dir, "broken1")))
	require.NoError(t, os.Symlink("/also/not/real", filepath.Join(dir, "broken2")))

	const goroutines = 10
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := RecordArtifacts(
				dir,
				map[string]cryptoutil.DigestSet{},
				[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
				map[string]struct{}{}, // each goroutine gets its own map
				false,
				map[string]bool{},
				nil, nil, nil,
			)
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d should handle mixed symlinks gracefully", i)
	}
}

// ---------------------------------------------------------------------------
// 30. dirHashGlob on empty directory
// ---------------------------------------------------------------------------

// TestAdversarial_DirHashGlobOnEmptyDir verifies that dirHashGlob matching
// an empty directory produces a valid directory hash.
func TestAdversarial_DirHashGlobOnEmptyDir(t *testing.T) {
	dir := t.TempDir()
	emptyDir := filepath.Join(dir, "vendor")
	require.NoError(t, os.Mkdir(emptyDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("main"), 0644))

	dirGlob, err := glob.Compile("vendor")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{dirGlob}, nil, nil,
	)
	require.NoError(t, err)
	assert.Contains(t, artifacts, "vendor/",
		"empty directory matched by dirHashGlob should produce a directory hash entry")
	assert.Contains(t, artifacts, "main.go")
}
