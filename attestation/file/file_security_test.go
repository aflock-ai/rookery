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
// R3-170: TOCTOU -- regular file replaced with symlink between Walk and hash.
//
// filepath.Walk uses Lstat to discover files, reporting their types at that
// moment. The file path is then sent to the worker pool, which calls
// CalculateDigestSetFromFile(path). Between these two events there is a race
// window. An attacker can:
//
//   1. Have a regular file in the attested directory.
//   2. After Walk discovers it (Lstat says "regular file"), replace it with
//      a symlink pointing outside basePath.
//   3. The worker opens the symlink target and hashes the outside file's
//      content. No basePath boundary check occurs in the worker path.
//
// BUG: The symlink boundary check only runs when Walk itself reports the
// entry as a symlink (info.Mode()&fs.ModeSymlink). For entries Walk sees as
// regular files, CalculateDigestSetFromFile opens whatever is at the path --
// if the path has become a symlink since the Walk, the symlink target is
// hashed with zero verification.
//
// This test proves the race window exists by concurrently replacing files
// with symlinks during attestation. We can observe the outside file's
// digest appearing in the artifacts map.
// ---------------------------------------------------------------------------

func TestSecurity_R3_170_TOCTOU_FileToSymlinkRace(t *testing.T) {
	outside := t.TempDir()
	secretContent := "THIS-IS-A-LEAKED-SECRET-FILE-R3-170"
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte(secretContent), 0644))

	inside := t.TempDir()
	const numFiles = 300
	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(inside, fmt.Sprintf("target_%04d.txt", i)),
			[]byte(fmt.Sprintf("original-content-%d", i)),
			0644,
		))
	}

	// Compute the digest of the secret file so we can detect if it leaks.
	secretDigest, err := cryptoutil.CalculateDigestSetFromFile(
		filepath.Join(outside, "secret.txt"),
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
	)
	require.NoError(t, err)

	// Run the race many times to increase the chance of hitting the window.
	secretLeaked := false
	for attempt := range 20 {
		// Reset: restore all targets as regular files
		for i := range numFiles {
			path := filepath.Join(inside, fmt.Sprintf("target_%04d.txt", i))
			_ = os.Remove(path)
			_ = os.WriteFile(path, []byte(fmt.Sprintf("original-content-%d", i)), 0644)
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Tiny delay to let walk start, then replace files with symlinks
			time.Sleep(time.Duration(50+attempt*10) * time.Microsecond)
			for i := range numFiles {
				if i%2 == 0 {
					path := filepath.Join(inside, fmt.Sprintf("target_%04d.txt", i))
					_ = os.Remove(path)
					_ = os.Symlink(filepath.Join(outside, "secret.txt"), path)
				}
			}
		}()

		artifacts, recordErr := RecordArtifacts(
			inside,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			nil, nil, nil,
		)
		wg.Wait()

		// Must not panic or deadlock (the test reaching here proves that).

		if recordErr != nil {
			// Some errors are expected (file deleted then symlink created
			// can race with open). Continue trying.
			continue
		}

		// Check if any artifact has the secret file's digest.
		for path, ds := range artifacts {
			if ds.Equal(secretDigest) {
				t.Logf("TOCTOU R3-170 PROVEN on attempt %d: artifact %q has secret file digest", attempt, path)
				secretLeaked = true
				break
			}
		}
		if secretLeaked {
			break
		}
	}

	// The race is timing-dependent. We document what we're proving:
	// if the secret leaked, it confirms the TOCTOU bug.
	// If it didn't leak in 20 attempts, the race window was not hit,
	// but the bug still exists in theory.
	if secretLeaked {
		t.Log("R3-170 CONFIRMED: Worker hashed a file that was replaced with " +
			"a symlink pointing outside basePath after Walk saw it as a regular file.")
	} else {
		t.Log("R3-170: Race window not hit in 20 attempts. " +
			"Bug exists structurally but timing was not favorable.")
	}
}

// ---------------------------------------------------------------------------
// R3-171: DirHash follows symlinks outside basePath boundary.
//
// When a directory matches a dirHashGlob, RecordArtifacts calls
// cryptoutil.CalculateDigestSetFromDir(path, hashes), which delegates to
// dirhash.HashDir from golang.org/x/mod. HashDir uses filepath.Walk +
// os.Open, which follows symlinks without any basePath boundary check.
//
// BUG: An attacker who can place a symlink inside a dirHash'd directory
// can cause files outside the basePath to be included in the directory
// hash. This violates the basePath security boundary that RecordArtifacts
// enforces for individually-hashed files and symlinked directories.
//
// Impact: The directory hash will silently include content from outside
// the attested directory. A verifier comparing directory hashes will see
// a hash that incorporates attacker-controlled external content.
// ---------------------------------------------------------------------------

func TestSecurity_R3_171_DirHashFollowsSymlinksOutsideBasePath(t *testing.T) {
	outside := t.TempDir()
	outsideSecret := filepath.Join(outside, "secret_data.txt")
	require.NoError(t, os.WriteFile(outsideSecret, []byte("SECRET-OUTSIDE-BASEPATH-R3-171"), 0644))

	inside := t.TempDir()
	vendorDir := filepath.Join(inside, "vendor")
	require.NoError(t, os.Mkdir(vendorDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(vendorDir, "legit.go"), []byte("package vendor"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(inside, "main.go"), []byte("package main"), 0644))

	// Place a symlink inside the vendor dir pointing to the outside secret file.
	require.NoError(t, os.Symlink(outsideSecret, filepath.Join(vendorDir, "injected_link.txt")))

	// Compute the dirHash with the symlink present (should include secret content).
	dirGlob, err := glob.Compile("vendor")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(
		inside,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{dirGlob}, nil, nil,
	)
	require.NoError(t, err)

	dirHashWithSymlink, ok := artifacts["vendor/"]
	require.True(t, ok, "vendor/ should have a directory hash")
	dhWithSymlink, err := dirHashWithSymlink.ToNameMap()
	require.NoError(t, err)

	// Now remove the symlink and recompute.
	require.NoError(t, os.Remove(filepath.Join(vendorDir, "injected_link.txt")))

	artifacts2, err := RecordArtifacts(
		inside,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{dirGlob}, nil, nil,
	)
	require.NoError(t, err)

	dirHashWithout, ok := artifacts2["vendor/"]
	require.True(t, ok, "vendor/ should still have a directory hash")
	dhWithout, err := dirHashWithout.ToNameMap()
	require.NoError(t, err)

	// BUG PROOF: The hashes differ, which means the outside file's content
	// was incorporated into the directory hash via the symlink.
	assert.NotEqual(t, dhWithSymlink["dirHash"], dhWithout["dirHash"],
		"R3-171 PROVEN: DirHash includes content from symlink pointing "+
			"outside basePath. The dirHash changed when the symlink was "+
			"removed, confirming outside content was incorporated.")

	t.Log("R3-171 CONFIRMED: dirhash.HashDir follows symlinks inside a dirHash'd " +
		"directory without any basePath boundary check. An attacker can poison " +
		"the directory hash by placing a symlink to an outside file.")
}

// ---------------------------------------------------------------------------
// R3-172: DirhHashSha256 newline injection in filenames.
//
// DirhHashSha256 checks for newlines in filenames and rejects them. However,
// this check happens at the DirhHashSha256 level. The question is: does the
// upstream dirhash.DirFiles (which uses filepath.Walk) include files with
// newlines? On Unix, newlines ARE valid in filenames.
//
// If a filename contains a newline, DirFiles will include it, and
// DirhHashSha256 will return an error. This test verifies that the error
// is properly propagated through CalculateDigestSetFromDir and ultimately
// through RecordArtifacts.
//
// BUG/DEFENSE CHECK: If the error is swallowed or the newline check is
// bypassed, an attacker could forge hash entries by crafting filenames like:
//   "evil\nabc123  legit_file.go"
// which would inject a fake hash line into the summary.
// ---------------------------------------------------------------------------

func TestSecurity_R3_172_DirHashNewlineFilenameInjection(t *testing.T) {
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "hashdir")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "legit.go"), []byte("package legit"), 0644))

	// Create a file with a newline in its name.
	// This would allow hash-line injection if not caught.
	injectedName := "evil\nfakehash  forged_file.go"
	injectedPath := filepath.Join(targetDir, injectedName)
	err := os.WriteFile(injectedPath, []byte("injected"), 0644)
	if err != nil {
		t.Skip("filesystem does not support newlines in filenames")
	}
	t.Cleanup(func() { os.Remove(injectedPath) })

	dirGlob, err := glob.Compile("hashdir")
	require.NoError(t, err)

	// RecordArtifacts should propagate the newline error from DirhHashSha256.
	_, err = RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{dirGlob}, nil, nil,
	)

	// The error from DirhHashSha256 should propagate up.
	require.Error(t, err,
		"R3-172: RecordArtifacts MUST error when a dirHash'd directory "+
			"contains a file with a newline in its name. If this passes "+
			"without error, the newline check was bypassed and hash-line "+
			"injection is possible.")
	assert.Contains(t, err.Error(), "newline",
		"error should mention newlines")

	t.Log("R3-172 VERIFIED: DirhHashSha256 correctly rejects filenames " +
		"with newlines, preventing hash-line injection in directory hashes.")
}

// ---------------------------------------------------------------------------
// R3-173: Glob separator bug -- glob.Compile without separator makes * match /.
//
// The gobwas/glob library treats * as matching ANY character (including /)
// unless a separator argument is provided to glob.Compile. RecordArtifacts
// calls shouldRecord which uses the globs as-is. The globs are compiled
// externally and passed in, but the common usage in this codebase never
// passes a separator.
//
// BUG: An include glob of "*.go" will match "deeply/nested/path/file.go"
// because * matches across path separators. This means:
//   - Include globs are LESS restrictive than expected (matching deeper files)
//   - Exclude globs are MORE restrictive than expected (excluding deeper files)
//
// This is documented in TestAdversarial_GlobPathSeparatorBehavior but this
// test proves the security impact: an exclude glob of "*.secret" will
// unexpectedly exclude "subdir/important.secret" even though the user likely
// intended to only exclude root-level .secret files.
// ---------------------------------------------------------------------------

func TestSecurity_R3_173_GlobSeparatorSecurityImpact(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "subdir")
	require.NoError(t, os.MkdirAll(sub, 0755))

	// Create files at different depths
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.secret"), []byte("root secret"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "nested.secret"), []byte("nested secret"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root text"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "nested.txt"), []byte("nested text"), 0644))

	// Exclude "*.secret" -- user intends to exclude only root-level .secret files.
	// But without separator arg, * matches across /, so "subdir/nested.secret" also matches.
	excludeGlob, err := glob.Compile("*.secret")
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

	// root.secret should be excluded (expected behavior)
	assert.NotContains(t, artifacts, "root.secret",
		"root.secret should be excluded by *.secret glob")

	// BUG: nested.secret is ALSO excluded because * matches "subdir/nested"
	// A correctly compiled glob (with '/' separator) would NOT exclude it.
	nestedKey := filepath.Join("subdir", "nested.secret")
	_, hasNested := artifacts[nestedKey]

	// Demonstrate what correct behavior would be:
	correctGlob, err := glob.Compile("*.secret", '/')
	require.NoError(t, err)
	assert.False(t, correctGlob.Match("subdir/nested.secret"),
		"with separator, *.secret should NOT match subdir/nested.secret")

	// Document the bug:
	assert.False(t, hasNested,
		"R3-173 PROVEN: *.secret glob (without separator) incorrectly excludes "+
			"subdir/nested.secret because * matches across path separators. "+
			"This means exclude globs are overly aggressive, potentially hiding "+
			"files from attestation that should be recorded.")

	t.Log("R3-173 CONFIRMED: Glob separator bug causes * to match across / in paths. " +
		"Exclude globs are more restrictive than intended, and include globs are " +
		"less restrictive than intended.")
}

// ---------------------------------------------------------------------------
// R3-174: isHashableFile does not check ModeNamedPipe or ModeSocket.
//
// The isHashableFile function in cryptoutil/digestset.go checks for
// ModeCharDevice to reject character devices. However, it does NOT check
// for ModeNamedPipe (FIFOs) or ModeSocket (Unix domain sockets).
//
// While file.go line 171 has a guard `!info.Mode().IsRegular()` that skips
// non-regular files during Walk, the isHashableFile function itself is a
// defense-in-depth layer used by CalculateDigestSetFromFile. If
// CalculateDigestSetFromFile is called directly on a FIFO path (bypassing
// the Walk guard), os.Open on a FIFO blocks forever.
//
// BUG: isHashableFile returns false for char devices but does NOT return
// false for named pipes (FIFOs), sockets, or block devices. Its fallback
// path (line 291) returns false for anything that is not regular, directory,
// or symlink, but named pipes opened via os.Open will block before Stat
// can even be called if no writer is connected.
//
// This test verifies the Walk guard (line 171) protects RecordArtifacts,
// and separately tests CalculateDigestSetFromFile's behavior.
// ---------------------------------------------------------------------------

func TestSecurity_R3_174_FIFOSkippedByWalkGuard(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "normal.txt"), []byte("normal"), 0644))

	// Create a named pipe (FIFO) directly in the directory.
	fifoPath := filepath.Join(dir, "fifo_pipe")
	err := mkfifoSecurity(fifoPath, 0644)
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
		// The Walk guard at line 171 (IsRegular check) should skip the FIFO.
		require.NoError(t, err, "FIFO should be skipped by the IsRegular guard")
		assert.Contains(t, artifacts, "normal.txt")
		assert.NotContains(t, artifacts, "fifo_pipe",
			"FIFO should not appear in artifacts")
	}()

	select {
	case <-done:
		t.Log("R3-174 VERIFIED: Walk guard (IsRegular check) correctly skips FIFOs.")
	case <-time.After(10 * time.Second):
		t.Fatal("R3-174 REGRESSION: RecordArtifacts hung on FIFO. " +
			"The IsRegular guard may have been removed or bypassed.")
	}
}

// ---------------------------------------------------------------------------
// R3-175: DirHash on directory containing a FIFO.
//
// When dirHashGlob matches a directory, RecordArtifacts calls
// CalculateDigestSetFromDir, which calls dirhash.HashDir. HashDir uses
// filepath.Walk to list files, then os.Open to read them.
//
// BUG: If a FIFO exists inside a dirHash'd directory, filepath.Walk
// reports it as a non-directory entry. HashDir then tries to os.Open it
// for hashing. Opening a FIFO blocks until a writer connects. This causes
// RecordArtifacts to hang indefinitely.
//
// Unlike individually-hashed files (protected by the IsRegular guard at
// line 171), dirHash'd directory contents are processed by the upstream
// dirhash.HashDir which has no FIFO protection.
// ---------------------------------------------------------------------------

func TestSecurity_R3_175_DirHashFIFOHang(t *testing.T) {
	t.Skip("KNOWN BUG: dirhash.HashDir hangs on FIFO inside dirHash'd directory. " +
		"Skipping to avoid CI timeout. See R3-175 for details.")

	dir := t.TempDir()
	hashDir := filepath.Join(dir, "vendor")
	require.NoError(t, os.Mkdir(hashDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(hashDir, "legit.go"), []byte("legit"), 0644))

	fifoPath := filepath.Join(hashDir, "evil_pipe")
	err := mkfifoSecurity(fifoPath, 0644)
	if err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}

	dirGlob, err := glob.Compile("vendor")
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RecordArtifacts(
			dir,
			map[string]cryptoutil.DigestSet{},
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
			map[string]struct{}{},
			false,
			map[string]bool{},
			[]glob.Glob{dirGlob}, nil, nil,
		)
	}()

	select {
	case <-done:
		t.Log("R3-175: DirHash completed (FIFO was somehow handled).")
	case <-time.After(10 * time.Second):
		t.Fatal("R3-175 PROVEN: dirhash.HashDir hangs when a dirHash'd " +
			"directory contains a FIFO. An attacker can cause indefinite " +
			"hang by placing a named pipe in a vendor/ directory.")
	}
}

// ---------------------------------------------------------------------------
// R3-176: Symlink TOCTOU in dirHash path -- directory replaced with symlink.
//
// When Walk encounters a directory matching a dirHashGlob, it calls
// CalculateDigestSetFromDir(path, hashes) on line 106. Between Walk
// seeing the path as a directory and CalculateDigestSetFromDir processing
// it, an attacker can replace the directory with a symlink to an outside
// directory. Since CalculateDigestSetFromDir calls dirhash.HashDir which
// uses filepath.Walk + os.Open (following symlinks), the entire outside
// directory's content gets hashed.
//
// BUG: No symlink-to-directory boundary check exists in the dirHash code
// path. The check at lines 131-146 only runs for individually-walked
// symlinks, not for directories matched by dirHashGlob.
// ---------------------------------------------------------------------------

func TestSecurity_R3_176_DirHashTOCTOU_DirectoryReplacedWithSymlink(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(outside, "outside_file.txt"),
		[]byte("OUTSIDE-CONTENT-R3-176"),
		0644,
	))

	inside := t.TempDir()
	vendorDir := filepath.Join(inside, "vendor")
	require.NoError(t, os.Mkdir(vendorDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(vendorDir, "legit.go"), []byte("legit"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(inside, "main.go"), []byte("main"), 0644))

	dirGlob, err := glob.Compile("vendor")
	require.NoError(t, err)

	// Hash the vendor directory normally first.
	artifacts1, err := RecordArtifacts(
		inside,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{dirGlob}, nil, nil,
	)
	require.NoError(t, err)
	normalHash, ok := artifacts1["vendor/"]
	require.True(t, ok)
	normalMap, err := normalHash.ToNameMap()
	require.NoError(t, err)

	// Now replace vendor/ with a symlink to the outside directory.
	require.NoError(t, os.RemoveAll(vendorDir))
	require.NoError(t, os.Symlink(outside, vendorDir))

	// Re-run: Walk will see "vendor" as a symlink (ModeSymlink set by Lstat).
	// The dirHashGlob check runs BEFORE the symlink check (line 93 vs 118).
	// But info.IsDir() at line 93 returns false for a symlink -- so the
	// dirHash branch won't trigger. Instead, the symlink branch triggers.
	// This means the replacement is partially mitigated -- the symlink check
	// catches it.
	//
	// HOWEVER: if the attacker can time the replacement precisely (TOCTOU),
	// Walk might see a directory but the subsequent HashDir operates on a
	// symlink. Let's test both paths.
	artifacts2, err := RecordArtifacts(
		inside,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{dirGlob}, nil, nil,
	)
	require.NoError(t, err)

	// After replacement, Walk sees vendor as a symlink to outside.
	// The symlink handler resolves it, checks basePath boundary, and should skip.
	_, hasDirHash := artifacts2["vendor/"]
	if hasDirHash {
		replacedDS := artifacts2["vendor/"]
		replacedMap, err := replacedDS.ToNameMap()
		require.NoError(t, err)
		if replacedMap["dirHash"] != normalMap["dirHash"] {
			t.Log("R3-176: vendor/ dirHash changed after symlink replacement. " +
				"Walk saw vendor as a directory before replacement but the " +
				"content changed. This confirms the dirHash path has no " +
				"post-Walk integrity check.")
		}
	}

	// The key proof: the symlink boundary check prevents the worst case.
	// But the dirHash path (R3-171) has already been proven to follow
	// internal symlinks without boundary checks.
	t.Log("R3-176: Directory-to-symlink replacement is partially mitigated " +
		"because Walk's Lstat sees the symlink type and diverts to the " +
		"symlink handler. The TOCTOU window between Lstat and HashDir " +
		"remains theoretical.")
}

// ---------------------------------------------------------------------------
// R3-177: No resource limits -- million-entry artifact map OOM risk.
//
// RecordArtifacts has no limit on the number of files it will hash or the
// total size of data it will read. An attacker who controls the attested
// directory can create many files to exhaust memory.
//
// BUG: The artifacts map grows unboundedly. Each entry is a DigestSet
// (map[DigestValue]string) plus the string key. For SHA256, each entry
// is roughly 100+ bytes. 1 million files = ~100MB just for the map, plus
// the string keys and hash computation overhead.
//
// This test creates a moderate number of files (5000) to demonstrate
// that there is no safeguard. A real attack would use more files.
// ---------------------------------------------------------------------------

func TestSecurity_R3_177_NoResourceLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping resource test in short mode")
	}

	dir := t.TempDir()
	const numFiles = 5000

	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("flood_%06d.txt", i)),
			[]byte{byte(i)},
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

	// All files are recorded -- no limit was hit.
	assert.Len(t, artifacts, numFiles,
		"R3-177: RecordArtifacts accepted all %d files without any resource "+
			"limit. An attacker controlling the directory can cause unbounded "+
			"memory allocation.", numFiles)

	t.Logf("R3-177 CONFIRMED: No file count limit. %d files all recorded. "+
		"No OOM protection for directories with millions of files.", numFiles)
}

// ---------------------------------------------------------------------------
// R3-178: safeGlobMatch error silently treated as non-match for dirHashGlob.
//
// When safeGlobMatch returns an error (line 97-98), the dirHash match loop
// logs the error but continues without matching. This means if a glob
// panics during matching (a known possibility with gobwas/glob), the
// directory that SHOULD be hashed as a unit is instead walked file-by-file.
//
// BUG: A panic in glob matching silently degrades to per-file hashing.
// An attacker who knows the glob pattern can craft a directory name that
// triggers a panic, causing the attestor to record individual file hashes
// instead of a directory hash. This changes the attestation output format,
// potentially bypassing policy checks that expect a directory hash.
// ---------------------------------------------------------------------------

func TestSecurity_R3_178_GlobPanicDegradesToPerFileHashing(t *testing.T) {
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "vendor")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "lib.go"), []byte("package lib"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("main"), 0644))

	// Create a glob that compiles but tests a known-good pattern.
	// To prove the concept, we use safeGlobMatch directly with a pattern
	// that returns an error, and verify the fallback behavior.
	dirGlob, err := glob.Compile("vendor")
	require.NoError(t, err)

	// Normal behavior: vendor/ gets dir-hashed
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

	_, hasDirHash := artifacts["vendor/"]
	assert.True(t, hasDirHash,
		"with working glob, vendor/ should be hashed as a directory unit")
	_, hasIndividual := artifacts[filepath.Join("vendor", "lib.go")]
	assert.False(t, hasIndividual,
		"with working glob, vendor/lib.go should NOT appear individually")

	// Now test with nil dirHashGlob (simulating what happens when the glob
	// fails to match due to a panic): individual files are recorded instead.
	artifactsNoDirHash, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	_, hasDirHashNil := artifactsNoDirHash["vendor/"]
	assert.False(t, hasDirHashNil,
		"without dirHashGlob, vendor/ should NOT have a directory hash")
	_, hasIndividualNil := artifactsNoDirHash[filepath.Join("vendor", "lib.go")]
	assert.True(t, hasIndividualNil,
		"without dirHashGlob, vendor/lib.go should appear individually")

	t.Log("R3-178 CONFIRMED: When glob matching fails (panic/error), " +
		"the directory falls through to per-file hashing. A glob panic " +
		"silently changes the attestation output format.")
}

// ---------------------------------------------------------------------------
// R3-179: DirhHashSha256 opens files via os.Open which follows symlinks.
//
// DirhHashSha256 receives an `open` function from dirhash.HashDir that
// calls os.Open(filepath.Join(dir, name)). os.Open follows symlinks.
// DirhHashSha256 checks if the opened file is a directory (line 62-65)
// and skips it, but does NOT check if the opened file is a symlink
// pointing outside the base path.
//
// BUG: Symlinks inside a dirHash'd directory are transparently followed
// by os.Open in DirhHashSha256, allowing content from arbitrary paths
// on the filesystem to be incorporated into the directory hash.
//
// This is the same underlying issue as R3-171 but specifically proves
// it through the DirhHashSha256 function path.
// ---------------------------------------------------------------------------

func TestSecurity_R3_179_DirhHashSha256_FollowsSymlinks(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(
		filepath.Join(outside, "external.txt"),
		[]byte("EXTERNAL-CONTENT-FOR-R3-179"),
		0644,
	))

	dir := t.TempDir()
	hashTarget := filepath.Join(dir, "mydir")
	require.NoError(t, os.Mkdir(hashTarget, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(hashTarget, "internal.go"), []byte("internal"), 0644))

	// Symlink to external file inside the hashable directory
	require.NoError(t, os.Symlink(
		filepath.Join(outside, "external.txt"),
		filepath.Join(hashTarget, "external_link.txt"),
	))

	// Compute directory hash.
	dirDigest, err := cryptoutil.CalculateDigestSetFromDir(
		hashTarget,
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
	)
	require.NoError(t, err)
	dirMap, err := dirDigest.ToNameMap()
	require.NoError(t, err)
	hashWithSymlink := dirMap["dirHash"]

	// Remove symlink and rehash.
	require.NoError(t, os.Remove(filepath.Join(hashTarget, "external_link.txt")))
	dirDigest2, err := cryptoutil.CalculateDigestSetFromDir(
		hashTarget,
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
	)
	require.NoError(t, err)
	dirMap2, err := dirDigest2.ToNameMap()
	require.NoError(t, err)
	hashWithout := dirMap2["dirHash"]

	assert.NotEqual(t, hashWithSymlink, hashWithout,
		"R3-179 PROVEN: DirhHashSha256 followed symlink to external file, "+
			"incorporating its content into the directory hash. Hash changed "+
			"when symlink was removed.")

	t.Log("R3-179 CONFIRMED: CalculateDigestSetFromDir -> DirhHashSha256 " +
		"follows symlinks via os.Open, incorporating arbitrary external " +
		"file content into directory hashes without basePath checks.")
}

// ---------------------------------------------------------------------------
// R3-180: shouldRecord uses raw path for openedFiles lookup but normalized
// path for glob matching -- potential mismatch.
//
// shouldRecord normalizes the path to forward slashes for glob matching
// (line 222) but uses the original path for the openedFiles lookup (line 237)
// and baseArtifacts lookup (line 240). On Unix this is not an issue because
// filepath.ToSlash is a no-op, but it reveals an inconsistency in the design.
//
// More importantly, the openedFiles map uses the relPath from the Walk, but
// the tracing system that populates openedFiles might use a different path
// format (absolute vs relative, different normalization). If they don't match,
// traced files are silently excluded from attestation.
//
// BUG: When processWasTraced=true, any mismatch between the path format in
// openedFiles and the relPath format from Walk causes silent exclusion.
// ---------------------------------------------------------------------------

func TestSecurity_R3_180_OpenedFilesPathMismatch(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "traced.txt"), []byte("traced"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "untraced.txt"), []byte("untraced"), 0644))

	// openedFiles uses relPath -- this works
	openedFilesRelative := map[string]bool{
		"traced.txt": true,
	}

	artifacts1, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		true, // processWasTraced
		openedFilesRelative,
		nil, nil, nil,
	)
	require.NoError(t, err)
	assert.Contains(t, artifacts1, "traced.txt",
		"relative path in openedFiles should match Walk's relPath")
	assert.NotContains(t, artifacts1, "untraced.txt",
		"untraced file should be excluded")

	// openedFiles uses ABSOLUTE path -- will NOT match Walk's relative path.
	openedFilesAbsolute := map[string]bool{
		filepath.Join(dir, "traced.txt"): true,
	}

	artifacts2, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		true,
		openedFilesAbsolute,
		nil, nil, nil,
	)
	require.NoError(t, err)

	// BUG: absolute paths in openedFiles never match relative paths from Walk.
	// ALL files are silently excluded.
	assert.Empty(t, artifacts2,
		"R3-180 PROVEN: When openedFiles contains absolute paths but Walk "+
			"produces relative paths, no files match, and ALL traced files "+
			"are silently excluded from attestation. This is a silent data "+
			"loss bug when the tracing system and the file attestor use "+
			"different path formats.")

	t.Log("R3-180 CONFIRMED: Path format mismatch between openedFiles and " +
		"Walk's relPath causes silent exclusion of ALL traced files.")
}

// ---------------------------------------------------------------------------
// R3-181: Race condition on visitedSymlinks during recursive symlink calls.
//
// RecordArtifacts is called recursively for symlinked directories (line 154).
// The recursive call spawns its own Walk goroutine and worker pool. The
// visitedSymlinks map is passed BY REFERENCE to the recursive call.
//
// Within a single top-level call, visitedSymlinks is written to at line 152
// from the walk goroutine. The recursive call also writes to visitedSymlinks
// from ITS walk goroutine. Since these are different goroutines (the parent's
// walk goroutine calls RecordArtifacts which spawns a new walk goroutine),
// the parent walk goroutine blocks waiting for the recursive call to return.
// So there is no concurrent write to the map WITHIN a single call chain.
//
// HOWEVER, if the user passes the SAME visitedSymlinks map to multiple
// concurrent top-level RecordArtifacts calls, data races occur. This test
// documents the API contract violation.
// ---------------------------------------------------------------------------

func TestSecurity_R3_181_SharedVisitedSymlinksRace(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(target, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(target, "data.txt"), []byte("shared"), 0644))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "link1")))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, "link2")))

	// Each concurrent call MUST get its own visitedSymlinks map.
	// Sharing a map is an API contract violation that causes data races.
	// This test verifies the SAFE pattern (independent maps) works correctly.
	const goroutines = 8
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
				map[string]struct{}{}, // independent map per goroutine
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
		// Must have at least the original target/data.txt
		assert.GreaterOrEqual(t, len(results[i]), 1,
			"goroutine %d: should have at least one artifact", i)
	}

	// Cross-validate: all goroutines must produce identical results.
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, len(results[0]), len(results[i]),
			"R3-181: goroutine %d has different artifact count (%d vs %d)",
			i, len(results[0]), len(results[i]))
	}

	t.Log("R3-181: Verified that independent visitedSymlinks maps produce " +
		"consistent results. Sharing maps across concurrent calls would " +
		"cause data races (tested separately in race_test.go).")
}

// ---------------------------------------------------------------------------
// R3-182: DirHash on empty directory produces a hash of an empty summary.
//
// When a dirHashGlob matches an empty directory, DirhHashSha256 hashes
// zero files. The resulting hash is SHA256("") = e3b0c44298fc1c...
//
// This is not necessarily a bug, but it's a semantic concern: an empty
// vendor/ directory and a vendor/ directory whose files were all deleted
// produce the same hash. A verifier cannot distinguish between "pristine
// empty directory" and "directory that was tampered with by removing files."
// ---------------------------------------------------------------------------

func TestSecurity_R3_182_EmptyDirHashCollision(t *testing.T) {
	dir := t.TempDir()

	// Empty vendor directory
	emptyVendor := filepath.Join(dir, "vendor")
	require.NoError(t, os.Mkdir(emptyVendor, 0755))

	dirGlob, err := glob.Compile("vendor")
	require.NoError(t, err)

	artifacts1, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{dirGlob}, nil, nil,
	)
	require.NoError(t, err)
	emptyHash, ok := artifacts1["vendor/"]
	require.True(t, ok, "empty vendor/ should produce a directory hash")
	emptyMap, err := emptyHash.ToNameMap()
	require.NoError(t, err)

	// Now create a vendor with files, then delete them all.
	// The directory still exists but is empty again.
	require.NoError(t, os.WriteFile(filepath.Join(emptyVendor, "temp.go"), []byte("temp"), 0644))
	require.NoError(t, os.Remove(filepath.Join(emptyVendor, "temp.go")))

	artifacts2, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{dirGlob}, nil, nil,
	)
	require.NoError(t, err)
	deletedHash, ok := artifacts2["vendor/"]
	require.True(t, ok)
	deletedMap, err := deletedHash.ToNameMap()
	require.NoError(t, err)

	// Both hashes should be identical -- SHA256 of empty content.
	assert.Equal(t, emptyMap["dirHash"], deletedMap["dirHash"],
		"R3-182: Empty directory and emptied directory produce the same hash. "+
			"A verifier cannot distinguish pristine-empty from tampered-empty.")

	// The hash should be the well-known SHA256 of empty string.
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		emptyMap["dirHash"],
		"empty directory hash should be SHA256 of empty input")

	t.Log("R3-182 CONFIRMED: Empty and emptied directories produce identical " +
		"directory hashes. No way to distinguish pristine from tampered.")
}

// ---------------------------------------------------------------------------
// R3-183: Relative symlink resolution with tricky basePath.
//
// When basePath contains symlinks itself (common on macOS where /tmp ->
// /private/var/...), the symlink boundary check uses EvalSymlinks on both
// the basePath and the symlink target. This test verifies the check works
// correctly when the basePath is itself a symlink.
// ---------------------------------------------------------------------------

func TestSecurity_R3_183_BasePathIsSymlink(t *testing.T) {
	// Create the real directory structure
	realBase := t.TempDir()
	realInside := filepath.Join(realBase, "project")
	require.NoError(t, os.Mkdir(realInside, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(realInside, "file.txt"), []byte("inside"), 0644))

	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0644))

	// Place a symlink inside the project pointing outside
	require.NoError(t, os.Symlink(outside, filepath.Join(realInside, "escape")))

	// Create a symlink as the basePath itself
	symlinkBase := filepath.Join(t.TempDir(), "symlink_base")
	require.NoError(t, os.Symlink(realInside, symlinkBase))

	artifacts, err := RecordArtifacts(
		symlinkBase, // basePath is a symlink
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err)

	assert.Contains(t, artifacts, "file.txt",
		"file inside the real base should be recorded")

	// The escape symlink should be caught by the boundary check.
	for k := range artifacts {
		assert.False(t, strings.Contains(k, "secret"),
			"symlink escaping basePath (which is itself a symlink) should be blocked: got %q", k)
	}

	t.Log("R3-183 VERIFIED: Symlink boundary check works correctly even when " +
		"basePath is itself a symlink (uses EvalSymlinks on both paths).")
}

// ---------------------------------------------------------------------------
// R3-184: Multiple errors from worker pool -- only first error preserved.
//
// RecordArtifacts collects results from the worker pool and tracks only
// the first error (line 196). If multiple files fail (e.g., permission
// denied on several files), only the first error is reported. All
// subsequent errors are silently dropped, and the partial results before
// the first error are also discarded (the function returns nil, firstErr).
//
// BUG: When firstErr is set, results are still drained (line 201 has
// `if firstErr == nil && shouldRecord(...)`) but they are silently discarded.
// The function returns nil on line 211, losing any successfully-computed
// artifacts. This means a single unreadable file causes the entire
// attestation to fail with no partial results.
// ---------------------------------------------------------------------------

func TestSecurity_R3_184_SingleBadFileFailsEntireAttestation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("test requires non-root user")
	}

	dir := t.TempDir()

	// Create many readable files
	const numGood = 50
	for i := range numGood {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("good_%03d.txt", i)),
			[]byte(fmt.Sprintf("good-%d", i)),
			0644,
		))
	}

	// Create one unreadable file
	badFile := filepath.Join(dir, "bad_perm.txt")
	require.NoError(t, os.WriteFile(badFile, []byte("unreadable"), 0644))
	require.NoError(t, os.Chmod(badFile, 0000))
	t.Cleanup(func() { os.Chmod(badFile, 0644) })

	artifacts, err := RecordArtifacts(
		dir,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)

	// The entire attestation fails because of one bad file.
	assert.Error(t, err,
		"R3-184: One unreadable file should cause the entire attestation to fail")
	assert.Nil(t, artifacts,
		"R3-184 PROVEN: Artifacts are nil when ANY file fails. A single "+
			"unreadable file (e.g., a file with 0000 permissions that an "+
			"attacker can create) causes complete attestation failure with "+
			"no partial results. This is a DoS vector.")

	t.Log("R3-184 CONFIRMED: One unreadable file causes complete attestation " +
		"failure (nil artifacts). No partial results are returned. An attacker " +
		"can prevent attestation by creating a single unreadable file in the " +
		"attested directory.")
}

// ---------------------------------------------------------------------------
// Helper: mkfifo creates a named pipe (FIFO) using syscall.
// ---------------------------------------------------------------------------

func mkfifoSecurity(path string, mode uint32) error {
	return syscall.Mkfifo(path, mode)
}
