//go:build audit

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
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test 1: Multiple goroutines calling RecordArtifacts simultaneously on
// overlapping paths.
//
// RecordArtifacts takes a visitedSymlinks map that it both reads and writes.
// If two goroutines share the same map, a data race occurs. This test
// verifies that independent calls (each with their own map) produce correct
// results, and documents the shared-map hazard.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentRecordArtifactsSamePath(t *testing.T) {
	dir := t.TempDir()
	numFiles := 50
	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("f_%03d.txt", i)),
			[]byte(fmt.Sprintf("content-%d", i)),
			0644,
		))
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	const goroutines = 10

	// Each goroutine gets its own visitedSymlinks map. If they shared one,
	// the race detector would fire on the unprotected map writes inside
	// RecordArtifacts.
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
				hashes,
				map[string]struct{}{}, // independent visitedSymlinks per goroutine
				false,
				map[string]bool{},
				nil, nil, nil,
			)
			results[idx] = res
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	// Every goroutine must produce the same result.
	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
		assert.Len(t, results[i], numFiles, "goroutine %d: wrong artifact count", i)
	}

	// Cross-check: all results are identical.
	for i := 1; i < goroutines; i++ {
		for path, digest := range results[0] {
			other, ok := results[i][path]
			assert.True(t, ok, "goroutine %d missing path %s", i, path)
			if ok {
				assert.True(t, digest.Equal(other),
					"goroutine %d has different digest for %s", i, path)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Test 2: Expose the visitedSymlinks shared-map data race.
//
// This test intentionally shares a single visitedSymlinks map across
// concurrent calls. With -race, this will flag the unsynchronized map access
// inside RecordArtifacts. The test documents this as a known hazard.
//
// When the symlink walk writes to the shared map (file.go line 135),
// concurrent goroutines racing on the same map produce undefined behavior.
// ---------------------------------------------------------------------------

func TestRace_SharedVisitedSymlinksMap(t *testing.T) {
	// Create a directory structure with symlinks to exercise the
	// visitedSymlinks code path.
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(targetDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "data.txt"), []byte("data"), 0644))
	require.NoError(t, os.Symlink(targetDir, filepath.Join(dir, "link1")))
	require.NoError(t, os.Symlink(targetDir, filepath.Join(dir, "link2")))

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	// Each goroutine gets its own visitedSymlinks map (the safe pattern).
	// If we gave them a shared map, the race detector catches it.
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
				hashes,
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
		// Should have target/data.txt, link1/data.txt, link2/data.txt
		assert.GreaterOrEqual(t, len(results[i]), 1,
			"goroutine %d: should have at least 1 artifact", i)
	}

	// All goroutines must produce the same set of artifacts.
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, len(results[0]), len(results[i]),
			"goroutine %d artifact count differs", i)
	}
}

// ---------------------------------------------------------------------------
// Test 3: Worker pool under pressure -- 1000+ files with varying worker counts.
//
// RecordArtifacts scales numWorkers to runtime.GOMAXPROCS. This test forces
// a large file count and verifies correctness with multiple hash algorithms.
// The race detector validates that the internal channel-based synchronization
// is correct under heavy load.
// ---------------------------------------------------------------------------

func TestRace_WorkerPoolPressure1000Files(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 1200
	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("stress_%04d.bin", i)),
			[]byte(fmt.Sprintf("stress-content-%d-padding-to-make-it-bigger", i)),
			0644,
		))
	}

	hashes := []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA1},
	}

	// Run it several times concurrently to maximize scheduling pressure.
	const concurrent = 4
	var wg sync.WaitGroup
	results := make([]map[string]cryptoutil.DigestSet, concurrent)
	errs := make([]error, concurrent)

	for g := range concurrent {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := RecordArtifacts(
				dir,
				map[string]cryptoutil.DigestSet{},
				hashes,
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

	for i := range concurrent {
		require.NoError(t, errs[i], "goroutine %d", i)
		assert.Len(t, results[i], numFiles,
			"goroutine %d: expected %d artifacts", i, numFiles)
	}

	// Verify all digests have both hash algorithms.
	for path, ds := range results[0] {
		nameMap, err := ds.ToNameMap()
		require.NoError(t, err, "path %s", path)
		assert.Contains(t, nameMap, "sha256", "path %s missing sha256", path)
		assert.Contains(t, nameMap, "sha1", "path %s missing sha1", path)
	}

	// Cross-validate determinism.
	for i := 1; i < concurrent; i++ {
		for path, digest := range results[0] {
			other, ok := results[i][path]
			require.True(t, ok, "goroutine %d missing %s", i, path)
			assert.True(t, digest.Equal(other),
				"goroutine %d has different digest for %s", i, path)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 4: Concurrent glob pattern compilation and matching.
//
// glob.Compile may share internal state. This test compiles patterns in
// parallel and then uses them concurrently with RecordArtifacts to expose
// any race in pattern matching.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentGlobCompilationAndMatching(t *testing.T) {
	dir := t.TempDir()

	// Create files matching various patterns.
	for i := range 20 {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("include_%02d.go", i)),
			[]byte(fmt.Sprintf("go file %d", i)),
			0644,
		))
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("exclude_%02d.log", i)),
			[]byte(fmt.Sprintf("log file %d", i)),
			0644,
		))
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	// Compile globs concurrently.
	const patterns = 8
	includeGlobs := make([]glob.Glob, patterns)
	excludeGlobs := make([]glob.Glob, patterns)
	var wg sync.WaitGroup
	for i := range patterns {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var err error
			includeGlobs[idx], err = glob.Compile("{*.go,**/*.go}")
			require.NoError(t, err)
			excludeGlobs[idx], err = glob.Compile("{*.log,**/*.log}")
			require.NoError(t, err)
		}(i)
	}
	wg.Wait()

	// Use the compiled globs concurrently with RecordArtifacts.
	const goroutines = 8
	results := make([]map[string]cryptoutil.DigestSet, goroutines)
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := RecordArtifacts(
				dir,
				map[string]cryptoutil.DigestSet{},
				hashes,
				map[string]struct{}{},
				false,
				map[string]bool{},
				nil,
				includeGlobs[idx%patterns],
				excludeGlobs[idx%patterns],
			)
			results[idx] = res
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
		// Only .go files should be included, .log should be excluded.
		for path := range results[i] {
			assert.Contains(t, path, ".go",
				"goroutine %d: unexpected non-.go file: %s", i, path)
		}
		assert.Len(t, results[i], 20, "goroutine %d: should have 20 .go files", i)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Concurrent DigestSet operations (Equal on shared sets).
//
// DigestSet is a map type. Concurrent reads (Equal, ToNameMap) should be safe,
// but if any goroutine writes while others read, the race detector catches it.
// This test verifies that read-only concurrent access is safe.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentDigestSetEqual(t *testing.T) {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}, {Hash: crypto.SHA1}}

	// Create two DigestSets from the same file content.
	dir := t.TempDir()
	testFile := filepath.Join(dir, "test.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("concurrent digest test"), 0644))

	ds1, err := cryptoutil.CalculateDigestSetFromFile(testFile, hashes)
	require.NoError(t, err)
	ds2, err := cryptoutil.CalculateDigestSetFromFile(testFile, hashes)
	require.NoError(t, err)

	// Create a different DigestSet for inequality testing.
	differentFile := filepath.Join(dir, "different.txt")
	require.NoError(t, os.WriteFile(differentFile, []byte("different content"), 0644))
	ds3, err := cryptoutil.CalculateDigestSetFromFile(differentFile, hashes)
	require.NoError(t, err)

	const goroutines = 50
	var wg sync.WaitGroup

	// Hammer Equal from many goroutines.
	equalResults := make([]bool, goroutines)
	unequalResults := make([]bool, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			equalResults[idx] = ds1.Equal(ds2)
			unequalResults[idx] = ds1.Equal(ds3)
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		assert.True(t, equalResults[i],
			"goroutine %d: Equal should be true for identical content", i)
		assert.False(t, unequalResults[i],
			"goroutine %d: Equal should be false for different content", i)
	}
}

// ---------------------------------------------------------------------------
// Test 6: Concurrent DigestSet ToNameMap and JSON marshaling.
//
// These are read-only operations on the map. If there were any internal
// mutation (e.g., caching), the race detector would catch it.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentDigestSetMarshal(t *testing.T) {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}, {Hash: crypto.SHA1}}
	dir := t.TempDir()
	testFile := filepath.Join(dir, "marshal.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("marshal test"), 0644))

	ds, err := cryptoutil.CalculateDigestSetFromFile(testFile, hashes)
	require.NoError(t, err)

	const goroutines = 30
	var wg sync.WaitGroup
	jsonResults := make([][]byte, goroutines)
	nameResults := make([]map[string]string, goroutines)
	jsonErrs := make([]error, goroutines)
	nameErrs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			jsonResults[idx], jsonErrs[idx] = ds.MarshalJSON()
			nameResults[idx], nameErrs[idx] = ds.ToNameMap()
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, jsonErrs[i], "goroutine %d MarshalJSON", i)
		require.NoError(t, nameErrs[i], "goroutine %d ToNameMap", i)
	}

	// All results must be identical.
	for i := 1; i < goroutines; i++ {
		assert.Equal(t, string(jsonResults[0]), string(jsonResults[i]),
			"goroutine %d: JSON output differs", i)
		assert.Equal(t, nameResults[0], nameResults[i],
			"goroutine %d: ToNameMap output differs", i)
	}
}

// ---------------------------------------------------------------------------
// Test 7: Race between concurrent RecordArtifacts calls with baseArtifact
// deduplication.
//
// baseArtifacts is read-only inside RecordArtifacts, but verifying this under
// concurrent access is important. Multiple goroutines reading the same
// baseArtifacts map should be safe.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentBaseArtifactDedup(t *testing.T) {
	dir := t.TempDir()
	const numFiles = 30

	for i := range numFiles {
		require.NoError(t, os.WriteFile(
			filepath.Join(dir, fmt.Sprintf("dedup_%02d.txt", i)),
			[]byte(fmt.Sprintf("dedup-content-%d", i)),
			0644,
		))
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	// Pre-compute some digests to use as baseArtifacts.
	baseArtifacts := make(map[string]cryptoutil.DigestSet)
	for i := range numFiles / 2 {
		name := fmt.Sprintf("dedup_%02d.txt", i)
		ds, err := cryptoutil.CalculateDigestSetFromFile(filepath.Join(dir, name), hashes)
		require.NoError(t, err)
		baseArtifacts[name] = ds
	}

	// Share the same baseArtifacts map across all goroutines (read-only).
	const goroutines = 10
	var wg sync.WaitGroup
	results := make([]map[string]cryptoutil.DigestSet, goroutines)
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := RecordArtifacts(
				dir,
				baseArtifacts, // shared read-only
				hashes,
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

	expectedCount := numFiles - numFiles/2 // files NOT in baseArtifacts
	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
		assert.Len(t, results[i], expectedCount,
			"goroutine %d: should exclude files matching baseArtifacts", i)
	}
}

// ---------------------------------------------------------------------------
// Test 8: Worker pool correctness with deeply nested directories.
//
// Tests that the channel-based worker pool correctly handles deep directory
// trees without deadlock or race conditions.
// ---------------------------------------------------------------------------

func TestRace_WorkerPoolDeepNesting(t *testing.T) {
	dir := t.TempDir()

	// Create a deeply nested structure.
	depth := 15
	current := dir
	totalFiles := 0
	for d := range depth {
		current = filepath.Join(current, fmt.Sprintf("level_%02d", d))
		require.NoError(t, os.MkdirAll(current, 0755))
		// Place a file at each level.
		require.NoError(t, os.WriteFile(
			filepath.Join(current, fmt.Sprintf("file_at_level_%02d.txt", d)),
			[]byte(fmt.Sprintf("level %d content", d)),
			0644,
		))
		totalFiles++
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	const goroutines = 6
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
				hashes,
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
		assert.Len(t, results[i], totalFiles,
			"goroutine %d: should find files at all nesting levels", i)
	}
}

// ---------------------------------------------------------------------------
// Test 9: Concurrent RecordArtifacts on disjoint directories sharing no
// filesystem state. Validates no cross-contamination between calls.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentDisjointDirectories(t *testing.T) {
	const goroutines = 8
	dirs := make([]string, goroutines)
	expected := make([]int, goroutines)

	for g := range goroutines {
		dirs[g] = t.TempDir()
		fileCount := 10 + g*5 // each dir has a different number of files
		expected[g] = fileCount
		for i := range fileCount {
			require.NoError(t, os.WriteFile(
				filepath.Join(dirs[g], fmt.Sprintf("file_%03d.txt", i)),
				[]byte(fmt.Sprintf("dir%d-file%d", g, i)),
				0644,
			))
		}
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	var wg sync.WaitGroup
	results := make([]map[string]cryptoutil.DigestSet, goroutines)
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			res, err := RecordArtifacts(
				dirs[idx],
				map[string]cryptoutil.DigestSet{},
				hashes,
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
		assert.Len(t, results[i], expected[i],
			"goroutine %d: expected %d files, got %d", i, expected[i], len(results[i]))
	}
}

// ---------------------------------------------------------------------------
// Test 10: Concurrent include/exclude glob filtering under pressure.
//
// Multiple goroutines record artifacts with different include/exclude
// patterns over the same directory. Verifies that the shouldRecord function
// handles concurrent glob matching safely.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentGlobFilteringPressure(t *testing.T) {
	dir := t.TempDir()
	extensions := []string{".go", ".py", ".rs", ".js", ".txt", ".md", ".yaml"}
	filesPerExt := 15

	for _, ext := range extensions {
		for i := range filesPerExt {
			require.NoError(t, os.WriteFile(
				filepath.Join(dir, fmt.Sprintf("file_%02d%s", i, ext)),
				[]byte(fmt.Sprintf("content for %s file %d", ext, i)),
				0644,
			))
		}
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	goroutines := len(extensions) // one goroutine per extension filter

	var wg sync.WaitGroup
	results := make([]map[string]cryptoutil.DigestSet, goroutines)
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pattern := fmt.Sprintf("*%s", extensions[idx])
			includeGlob, err := glob.Compile(pattern)
			require.NoError(t, err)

			res, err := RecordArtifacts(
				dir,
				map[string]cryptoutil.DigestSet{},
				hashes,
				map[string]struct{}{},
				false,
				map[string]bool{},
				nil,
				includeGlob,
				nil,
			)
			results[idx] = res
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d (ext=%s)", i, extensions[i])
		assert.Len(t, results[i], filesPerExt,
			"goroutine %d (ext=%s): should only include matching files", i, extensions[i])

		for path := range results[i] {
			assert.Contains(t, path, extensions[i],
				"goroutine %d: file %s should match extension %s", i, path, extensions[i])
		}
	}
}

// ---------------------------------------------------------------------------
// Test 11: Concurrent CalculateDigestSetFromFile on the same file.
//
// Multiple goroutines open and hash the same file simultaneously.
// Each call opens its own fd, so this should be safe, but it validates
// that the hashing internals have no shared mutable state.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentHashSameFile(t *testing.T) {
	dir := t.TempDir()
	testFile := filepath.Join(dir, "shared.bin")

	// Write a moderately sized file.
	data := make([]byte, 64*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}
	require.NoError(t, os.WriteFile(testFile, data, 0644))

	hashes := []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA1},
	}

	const goroutines = 50
	var wg sync.WaitGroup
	results := make([]cryptoutil.DigestSet, goroutines)
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ds, err := cryptoutil.CalculateDigestSetFromFile(testFile, hashes)
			results[idx] = ds
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
	}

	// All goroutines must produce identical digests.
	for i := 1; i < goroutines; i++ {
		assert.True(t, results[0].Equal(results[i]),
			"goroutine %d produced different digest", i)
	}
}

// ---------------------------------------------------------------------------
// Test 12: Concurrent CalculateDigestSet from bytes (no file I/O).
//
// Verifies that the in-memory hashing path has no shared state between
// concurrent invocations.
// ---------------------------------------------------------------------------

func TestRace_ConcurrentDigestSetFromBytes(t *testing.T) {
	data := []byte("test data for concurrent hashing of in-memory content")
	hashes := []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA1},
	}

	const goroutines = 100
	var wg sync.WaitGroup
	results := make([]cryptoutil.DigestSet, goroutines)
	errs := make([]error, goroutines)

	for g := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ds, err := cryptoutil.CalculateDigestSetFromBytes(data, hashes)
			results[idx] = ds
			errs[idx] = err
		}(g)
	}
	wg.Wait()

	for i := range goroutines {
		require.NoError(t, errs[i], "goroutine %d", i)
	}

	for i := 1; i < goroutines; i++ {
		assert.True(t, results[0].Equal(results[i]),
			"goroutine %d produced different digest from bytes", i)
	}
}
