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
	"testing"

	"github.com/gobwas/glob"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConcurrentHashingMultipleFiles(t *testing.T) {
	dir := t.TempDir()

	fileContents := map[string]string{
		"file1.txt": "content one",
		"file2.txt": "content two",
		"file3.txt": "content three",
		"file4.txt": "content four",
		"file5.txt": "content five",
	}

	for name, content := range fileContents {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0644))
	}

	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
	require.NoError(t, err)
	assert.Len(t, artifacts, 5)

	for name := range fileContents {
		_, ok := artifacts[name]
		assert.True(t, ok, "expected artifact for %s", name)
	}
}

func TestConcurrentHashingLargeFileCount(t *testing.T) {
	dir := t.TempDir()
	numFiles := 100

	for i := range numFiles {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%03d.txt", i)), []byte(fmt.Sprintf("content %d", i)), 0644))
	}

	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
	require.NoError(t, err)
	assert.Len(t, artifacts, numFiles)
}

func TestConcurrentHashingWithSubdirectories(t *testing.T) {
	dir := t.TempDir()

	// Create nested structure
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "a", "b", "c"), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "d"), 0755))

	files := []string{
		filepath.Join(dir, "root.txt"),
		filepath.Join(dir, "a", "a.txt"),
		filepath.Join(dir, "a", "b", "b.txt"),
		filepath.Join(dir, "a", "b", "c", "c.txt"),
		filepath.Join(dir, "d", "d.txt"),
	}

	for _, f := range files {
		require.NoError(t, os.WriteFile(f, []byte("content for "+f), 0644))
	}

	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
	require.NoError(t, err)
	assert.Len(t, artifacts, 5)

	expectedRelPaths := []string{
		"root.txt",
		filepath.Join("a", "a.txt"),
		filepath.Join("a", "b", "b.txt"),
		filepath.Join("a", "b", "c", "c.txt"),
		filepath.Join("d", "d.txt"),
	}
	for _, rel := range expectedRelPaths {
		_, ok := artifacts[rel]
		assert.True(t, ok, "expected artifact for %s", rel)
	}
}

func TestConcurrentHashingDeterministic(t *testing.T) {
	dir := t.TempDir()
	for i := range 20 {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("file_%02d.txt", i)), []byte(fmt.Sprintf("deterministic content %d", i)), 0644))
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	// Run multiple times and verify results are identical
	var firstRun map[string]cryptoutil.DigestSet
	for run := range 5 {
		artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, hashes, map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
		require.NoError(t, err, "run %d", run)

		if firstRun == nil {
			firstRun = artifacts
			continue
		}

		assert.Len(t, artifacts, len(firstRun), "run %d: artifact count mismatch", run)
		for path, digest := range firstRun {
			artDigest, ok := artifacts[path]
			assert.True(t, ok, "run %d: missing path %s", run, path)
			assert.True(t, digest.Equal(artDigest), "run %d: digest mismatch for %s", run, path)
		}
	}
}

func TestConcurrentHashingBaseArtifactDedup(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "unchanged.txt"), []byte("same content"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "changed.txt"), []byte("new content"), 0644))

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	// Compute digest for unchanged.txt to use as baseArtifact
	unchangedDigest, err := cryptoutil.CalculateDigestSetFromFile(filepath.Join(dir, "unchanged.txt"), hashes)
	require.NoError(t, err)

	baseArtifacts := map[string]cryptoutil.DigestSet{
		"unchanged.txt": unchangedDigest,
	}

	artifacts, err := RecordArtifacts(dir, baseArtifacts, hashes, map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
	require.NoError(t, err)

	// unchanged.txt should be excluded (same digest as base)
	_, hasUnchanged := artifacts["unchanged.txt"]
	assert.False(t, hasUnchanged, "unchanged.txt should be excluded by baseArtifact dedup")

	// changed.txt should be included
	_, hasChanged := artifacts["changed.txt"]
	assert.True(t, hasChanged, "changed.txt should be included")
}

func TestConcurrentHashingTracedProcess(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "opened.txt"), []byte("opened"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "not_opened.txt"), []byte("not opened"), 0644))

	openedFiles := map[string]bool{
		"opened.txt": true,
	}

	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, true, openedFiles, nil, nil, nil)
	require.NoError(t, err)

	_, hasOpened := artifacts["opened.txt"]
	assert.True(t, hasOpened, "opened.txt should be included when process was traced")

	_, hasNotOpened := artifacts["not_opened.txt"]
	assert.False(t, hasNotOpened, "not_opened.txt should be excluded when process was traced")
}

func TestConcurrentHashingMultipleHashAlgorithms(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("test content"), 0644))

	hashes := []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA1},
	}

	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, hashes, map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
	require.NoError(t, err)
	require.Len(t, artifacts, 1)

	digest := artifacts["test.txt"]
	nameMap, err := digest.ToNameMap()
	require.NoError(t, err)

	_, hasSHA256 := nameMap["sha256"]
	assert.True(t, hasSHA256, "should have SHA256 digest")
	_, hasSHA1 := nameMap["sha1"]
	assert.True(t, hasSHA1, "should have SHA1 digest")
}

func TestConcurrentHashingEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, artifacts)
}

func TestConcurrentHashingWithDirHashGlob(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "hashme")
	require.NoError(t, os.Mkdir(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "inner.txt"), []byte("inner content"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "outer.txt"), []byte("outer content"), 0644))

	g, err := glob.Compile("hashme")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, []glob.Glob{g}, nil, nil)
	require.NoError(t, err)

	// Should have dir hash for hashme/ and the outer file
	_, hasDirHash := artifacts["hashme/"]
	assert.True(t, hasDirHash, "should have dir hash for hashme/")
	_, hasOuter := artifacts["outer.txt"]
	assert.True(t, hasOuter, "should have outer.txt")
	// inner.txt should NOT be separate (it's inside the hashed dir)
	_, hasInner := artifacts[filepath.Join("hashme", "inner.txt")]
	assert.False(t, hasInner, "inner.txt should not be separate; it's inside hashed dir")
}

func TestConcurrentHashingSymlinkWithinBase(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "target")
	require.NoError(t, os.Mkdir(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "linked.txt"), []byte("linked content"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "regular.txt"), []byte("regular content"), 0644))

	require.NoError(t, os.Symlink(subDir, filepath.Join(dir, "link")))

	artifacts, err := RecordArtifacts(dir, map[string]cryptoutil.DigestSet{}, []cryptoutil.DigestValue{{Hash: crypto.SHA256}}, map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
	require.NoError(t, err)

	// Should have: regular.txt, target/linked.txt, link/linked.txt
	_, hasRegular := artifacts["regular.txt"]
	assert.True(t, hasRegular)
	_, hasTarget := artifacts[filepath.Join("target", "linked.txt")]
	assert.True(t, hasTarget)
	_, hasLinked := artifacts[filepath.Join("link", "linked.txt")]
	assert.True(t, hasLinked)
}
