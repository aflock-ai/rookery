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
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/gobwas/glob"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "main_test.go"), []byte("package main"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# readme"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "build.log"), []byte("build output"), 0644))

	subDir := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(subDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "lib.go"), []byte("package lib"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(subDir, "lib_test.go"), []byte("package lib"), 0644))
	return dir
}

func hashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}

func TestRecordArtifacts_NilGlobs(t *testing.T) {
	dir := setupTestDir(t)

	// nil globs should record everything (no filtering)
	artifacts, err := RecordArtifacts(dir, nil, hashes(), map[string]struct{}{}, false, map[string]bool{}, nil, nil, nil)
	require.NoError(t, err)
	assert.Len(t, artifacts, 6) // all 6 files
	assert.Contains(t, artifacts, "main.go")
	assert.Contains(t, artifacts, "main_test.go")
	assert.Contains(t, artifacts, "readme.md")
	assert.Contains(t, artifacts, "build.log")
	assert.Contains(t, artifacts, filepath.Join("subdir", "lib.go"))
	assert.Contains(t, artifacts, filepath.Join("subdir", "lib_test.go"))
}

func TestRecordArtifacts_IncludeGlob(t *testing.T) {
	dir := setupTestDir(t)

	includeGlob, err := glob.Compile("*.go")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(dir, nil, hashes(), map[string]struct{}{}, false, map[string]bool{}, nil, includeGlob, nil)
	require.NoError(t, err)

	// Should only include .go files at the top level (glob "*.go" doesn't match paths with separators)
	assert.Contains(t, artifacts, "main.go")
	assert.Contains(t, artifacts, "main_test.go")
	assert.NotContains(t, artifacts, "readme.md")
	assert.NotContains(t, artifacts, "build.log")
}

func TestRecordArtifacts_IncludeGlobRecursive(t *testing.T) {
	dir := setupTestDir(t)

	// {*.go,**/*.go} matches .go files at root and any depth
	includeGlob, err := glob.Compile("{*.go,**/*.go}")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(dir, nil, hashes(), map[string]struct{}{}, false, map[string]bool{}, nil, includeGlob, nil)
	require.NoError(t, err)

	// Should include all .go files at any depth
	assert.Contains(t, artifacts, "main.go")
	assert.Contains(t, artifacts, "main_test.go")
	assert.Contains(t, artifacts, filepath.Join("subdir", "lib.go"))
	assert.Contains(t, artifacts, filepath.Join("subdir", "lib_test.go"))
	assert.NotContains(t, artifacts, "readme.md")
	assert.NotContains(t, artifacts, "build.log")
}

func TestRecordArtifacts_ExcludeGlob(t *testing.T) {
	dir := setupTestDir(t)

	excludeGlob, err := glob.Compile("*.log")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(dir, nil, hashes(), map[string]struct{}{}, false, map[string]bool{}, nil, nil, excludeGlob)
	require.NoError(t, err)

	// Should exclude .log files
	assert.NotContains(t, artifacts, "build.log")
	assert.Contains(t, artifacts, "main.go")
	assert.Contains(t, artifacts, "readme.md")
}

func TestRecordArtifacts_ExcludeGlobRecursive(t *testing.T) {
	dir := setupTestDir(t)

	// Use {pattern,pattern} to match both root-level and nested files
	excludeGlob, err := glob.Compile("{*_test.go,**/*_test.go}")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(dir, nil, hashes(), map[string]struct{}{}, false, map[string]bool{}, nil, nil, excludeGlob)
	require.NoError(t, err)

	// Should exclude all test files at any depth
	assert.NotContains(t, artifacts, "main_test.go")
	assert.NotContains(t, artifacts, filepath.Join("subdir", "lib_test.go"))
	assert.Contains(t, artifacts, "main.go")
	assert.Contains(t, artifacts, filepath.Join("subdir", "lib.go"))
	assert.Contains(t, artifacts, "readme.md")
	assert.Contains(t, artifacts, "build.log")
}

func TestRecordArtifacts_IncludeAndExcludeGlobs(t *testing.T) {
	dir := setupTestDir(t)

	// Include only .go files at any depth, exclude test files at any depth
	includeGlob, err := glob.Compile("{*.go,**/*.go}")
	require.NoError(t, err)
	excludeGlob, err := glob.Compile("{*_test.go,**/*_test.go}")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(dir, nil, hashes(), map[string]struct{}{}, false, map[string]bool{}, nil, includeGlob, excludeGlob)
	require.NoError(t, err)

	// Should only include non-test .go files at all depths
	assert.Contains(t, artifacts, "main.go")
	assert.Contains(t, artifacts, filepath.Join("subdir", "lib.go"))
	assert.NotContains(t, artifacts, "main_test.go")
	assert.NotContains(t, artifacts, filepath.Join("subdir", "lib_test.go"))
	assert.NotContains(t, artifacts, "readme.md")
	assert.NotContains(t, artifacts, "build.log")
}

func TestRecordArtifacts_ExcludeTakesPrecedence(t *testing.T) {
	dir := setupTestDir(t)

	// Include everything, exclude .go — exclude should win
	includeGlob, err := glob.Compile("*")
	require.NoError(t, err)
	excludeGlob, err := glob.Compile("*.go")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(dir, nil, hashes(), map[string]struct{}{}, false, map[string]bool{}, nil, includeGlob, excludeGlob)
	require.NoError(t, err)

	assert.NotContains(t, artifacts, "main.go")
	assert.NotContains(t, artifacts, "main_test.go")
	assert.Contains(t, artifacts, "readme.md")
	assert.Contains(t, artifacts, "build.log")
}

func TestShouldRecord_IncludeGlobFiltering(t *testing.T) {
	includeGlob, err := glob.Compile("*.go")
	require.NoError(t, err)

	assert.True(t, shouldRecord("main.go", nil, nil, false, nil, includeGlob, nil))
	assert.False(t, shouldRecord("readme.md", nil, nil, false, nil, includeGlob, nil))
	assert.False(t, shouldRecord("build.log", nil, nil, false, nil, includeGlob, nil))
}

func TestShouldRecord_ExcludeGlobFiltering(t *testing.T) {
	excludeGlob, err := glob.Compile("*.log")
	require.NoError(t, err)

	assert.True(t, shouldRecord("main.go", nil, nil, false, nil, nil, excludeGlob))
	assert.False(t, shouldRecord("build.log", nil, nil, false, nil, nil, excludeGlob))
}

func TestShouldRecord_BothGlobs(t *testing.T) {
	includeGlob, err := glob.Compile("*.go")
	require.NoError(t, err)
	excludeGlob, err := glob.Compile("*_test.go")
	require.NoError(t, err)

	assert.True(t, shouldRecord("main.go", nil, nil, false, nil, includeGlob, excludeGlob))
	assert.False(t, shouldRecord("main_test.go", nil, nil, false, nil, includeGlob, excludeGlob))
	assert.False(t, shouldRecord("readme.md", nil, nil, false, nil, includeGlob, excludeGlob))
}

func TestShouldRecord_NilGlobsPassThrough(t *testing.T) {
	// nil globs should not filter anything
	assert.True(t, shouldRecord("anything.txt", nil, nil, false, nil, nil, nil))
}

func TestShouldRecord_TracingStillApplied(t *testing.T) {
	// Even with nil globs, tracing-based filtering should still work
	openedFiles := map[string]bool{"main.go": true}
	assert.True(t, shouldRecord("main.go", nil, nil, true, openedFiles, nil, nil))
	assert.False(t, shouldRecord("other.go", nil, nil, true, openedFiles, nil, nil))
}

func TestShouldRecord_BaseArtifactDedup(t *testing.T) {
	ds := cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc123"}
	baseArtifacts := map[string]cryptoutil.DigestSet{"main.go": ds}

	// Same digest should not be recorded
	assert.False(t, shouldRecord("main.go", ds, baseArtifacts, false, nil, nil, nil))
	// Different path should be recorded
	assert.True(t, shouldRecord("other.go", ds, baseArtifacts, false, nil, nil, nil))
}

func TestRecordArtifacts_GlobWithSubdirPattern(t *testing.T) {
	dir := setupTestDir(t)

	// Include only files in subdir
	includeGlob, err := glob.Compile("subdir/*")
	require.NoError(t, err)

	artifacts, err := RecordArtifacts(dir, nil, hashes(), map[string]struct{}{}, false, map[string]bool{}, nil, includeGlob, nil)
	require.NoError(t, err)

	assert.Contains(t, artifacts, filepath.Join("subdir", "lib.go"))
	assert.Contains(t, artifacts, filepath.Join("subdir", "lib_test.go"))
	assert.NotContains(t, artifacts, "main.go")
	assert.NotContains(t, artifacts, "readme.md")
}
