// Copyright 2024 The Witness Contributors
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

package lockfiles

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// chdirTemp changes to a temp directory and returns a cleanup function
// that restores the original directory.
func chdirTemp(t *testing.T) string {
	t.Helper()
	tempDir := t.TempDir()
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(tempDir))
	t.Cleanup(func() {
		_ = os.Chdir(oldWd)
	})
	return tempDir
}

func TestAttestor_Attest(t *testing.T) {
	tempDir := chdirTemp(t)

	testFiles := map[string]string{
		"Gemfile.lock":      "test content for Gemfile.lock",
		"package-lock.json": "test content for package-lock.json",
	}

	for filename, content := range testFiles {
		require.NoError(t, os.WriteFile(filepath.Join(tempDir, filename), []byte(content), 0644))
	}

	attestor := &Attestor{}
	ctx := &attestation.AttestationContext{}

	err := attestor.Attest(ctx)
	require.NoError(t, err)
	assert.Len(t, attestor.Lockfiles, len(testFiles))

	for _, lockfile := range attestor.Lockfiles {
		// Filename is now the path (e.g. "Gemfile.lock" when in current dir)
		base := filepath.Base(lockfile.Filename)
		expectedContent, ok := testFiles[base]
		assert.True(t, ok, "Unexpected lockfile %s found", lockfile.Filename)
		assert.Equal(t, expectedContent, lockfile.Content)
	}
}

func TestAttestor_Name(t *testing.T) {
	attestor := &Attestor{}
	assert.Equal(t, "lockfiles", attestor.Name())
}

func TestAttestor_Methods(t *testing.T) {
	attestor := &Attestor{}
	assert.Equal(t, Name, attestor.Name())
	assert.Equal(t, Type, attestor.Type())
	assert.Equal(t, RunType, attestor.RunType())
	schema := attestor.Schema()
	assert.NotNil(t, schema)
}

func TestAttestor_Interfaces(t *testing.T) {
	attestor := &Attestor{}
	assert.Implements(t, (*attestation.Attestor)(nil), attestor)
	assert.Implements(t, (*attestation.Subjecter)(nil), attestor)
}

func TestNewLockfilesAttestor(t *testing.T) {
	t.Run("default (no env var)", func(t *testing.T) {
		require.NoError(t, os.Unsetenv("WITNESS_LOCKFILES_SEARCH_PATHS"))
		a := NewLockfilesAttestor().(*Attestor)
		assert.Equal(t, "", a.SearchPaths)
		assert.Empty(t, a.Lockfiles)
	})

	t.Run("env var set", func(t *testing.T) {
		t.Setenv("WITNESS_LOCKFILES_SEARCH_PATHS", "foo:bar")
		a := NewLockfilesAttestor().(*Attestor)
		assert.Equal(t, "foo:bar", a.SearchPaths)
	})

	t.Run("recursive", func(t *testing.T) {
		t.Setenv("WITNESS_LOCKFILES_SEARCH_PATHS", "recursive")
		a := NewLockfilesAttestor().(*Attestor)
		assert.Equal(t, "recursive", a.SearchPaths)
	})
}

func TestParseSearchPaths(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "single path",
			input: "node-app",
			want:  []string{"node-app"},
		},
		{
			name:  "multiple paths",
			input: "node-app:python-app:go-service",
			want:  []string{"node-app", "python-app", "go-service"},
		},
		{
			name:  "paths with spaces",
			input: " node-app : python-app ",
			want:  []string{"node-app", "python-app"},
		},
		{
			name:  "empty input",
			input: "",
			want:  []string{"."},
		},
		{
			name:  "dot only",
			input: ".",
			want:  []string{"."},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSearchPaths(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAttestor_Attest_SpecificDirectories(t *testing.T) {
	tempDir := chdirTemp(t)

	// Create subdirectories with lockfiles
	for _, sub := range []string{"node-app", "python-app"} {
		require.NoError(t, os.MkdirAll(filepath.Join(tempDir, sub), 0755))
	}

	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "node-app", "package-lock.json"), []byte("npm lock content"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "python-app", "requirements.txt"), []byte("flask==2.0\nrequests==2.28"), 0644))
	// Also create a lockfile in the root that should NOT be found
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "Gemfile.lock"), []byte("root lockfile"), 0644))

	attestor := &Attestor{SearchPaths: "node-app:python-app"}
	ctx := &attestation.AttestationContext{}

	err := attestor.Attest(ctx)
	require.NoError(t, err)
	assert.Len(t, attestor.Lockfiles, 2)

	filenames := make([]string, len(attestor.Lockfiles))
	for i, lf := range attestor.Lockfiles {
		filenames[i] = lf.Filename
	}
	sort.Strings(filenames)

	assert.Equal(t, filepath.Join("node-app", "package-lock.json"), filenames[0])
	assert.Equal(t, filepath.Join("python-app", "requirements.txt"), filenames[1])

	// Root Gemfile.lock should NOT be included
	for _, lf := range attestor.Lockfiles {
		assert.NotEqual(t, "Gemfile.lock", filepath.Base(lf.Filename),
			"Root lockfile should not be found when searching specific paths")
	}
}

func TestAttestor_Attest_RecursiveSearch(t *testing.T) {
	tempDir := chdirTemp(t)

	// Create a nested directory structure
	dirs := []string{
		"frontend",
		"frontend/packages/ui",
		"backend",
		"backend/services/api",
	}
	for _, d := range dirs {
		require.NoError(t, os.MkdirAll(filepath.Join(tempDir, d), 0755))
	}

	// Create lockfiles at various depths
	files := map[string]string{
		"go.sum":                                       "root go.sum",
		"frontend/package-lock.json":                   "frontend npm lock",
		"frontend/packages/ui/yarn.lock":               "ui yarn lock",
		"backend/requirements.txt":                     "backend requirements",
		"backend/services/api/Cargo.lock":              "api cargo lock",
	}
	for path, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(tempDir, path), []byte(content), 0644))
	}

	attestor := &Attestor{SearchPaths: "recursive"}
	ctx := &attestation.AttestationContext{}

	err := attestor.Attest(ctx)
	require.NoError(t, err)
	assert.Len(t, attestor.Lockfiles, len(files))

	foundPaths := make(map[string]bool)
	for _, lf := range attestor.Lockfiles {
		foundPaths[lf.Filename] = true
	}

	for path := range files {
		assert.True(t, foundPaths[path], "Expected lockfile not found: %s", path)
	}
}

func TestAttestor_Attest_RecursiveIgnoresDirs(t *testing.T) {
	tempDir := chdirTemp(t)

	// Create directories that should be ignored
	ignoreDirs := []string{
		"node_modules",
		"vendor",
		".git",
		"__pycache__",
		"venv",
		"build",
	}
	for _, d := range ignoreDirs {
		require.NoError(t, os.MkdirAll(filepath.Join(tempDir, d), 0755))
		require.NoError(t, os.WriteFile(
			filepath.Join(tempDir, d, "package-lock.json"),
			[]byte("should be ignored"),
			0644,
		))
	}

	// Create one legitimate lockfile
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "Cargo.lock"), []byte("real lockfile"), 0644))

	attestor := &Attestor{SearchPaths: "recursive"}
	ctx := &attestation.AttestationContext{}

	err := attestor.Attest(ctx)
	require.NoError(t, err)

	// Only the root Cargo.lock should be found
	assert.Len(t, attestor.Lockfiles, 1)
	assert.Equal(t, "Cargo.lock", attestor.Lockfiles[0].Filename)
	assert.Equal(t, "real lockfile", attestor.Lockfiles[0].Content)
}

func TestAttestor_Attest_RecursiveIgnoresHiddenDirs(t *testing.T) {
	tempDir := chdirTemp(t)

	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, ".hidden-dir"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(tempDir, ".hidden-dir", "go.sum"),
		[]byte("hidden go.sum"),
		0644,
	))

	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "go.sum"), []byte("visible go.sum"), 0644))

	attestor := &Attestor{SearchPaths: "recursive"}
	ctx := &attestation.AttestationContext{}

	err := attestor.Attest(ctx)
	require.NoError(t, err)
	assert.Len(t, attestor.Lockfiles, 1)
	assert.Equal(t, "go.sum", attestor.Lockfiles[0].Filename)
}

func TestAttestor_Attest_DefaultSearchesCurrentDir(t *testing.T) {
	tempDir := chdirTemp(t)

	// Create lockfiles in current dir and subdir
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "poetry.lock"), []byte("poetry content"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(tempDir, "sub"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "sub", "Cargo.lock"), []byte("cargo content"), 0644))

	attestor := &Attestor{} // empty SearchPaths = default behavior
	ctx := &attestation.AttestationContext{}

	err := attestor.Attest(ctx)
	require.NoError(t, err)

	// Only current directory lockfile should be found
	assert.Len(t, attestor.Lockfiles, 1)
	assert.Equal(t, "poetry.lock", attestor.Lockfiles[0].Filename)
}

func TestAttestor_Attest_RequirementsTxt(t *testing.T) {
	tempDir := chdirTemp(t)

	require.NoError(t, os.WriteFile(filepath.Join(tempDir, "requirements.txt"), []byte("flask==2.0\nrequests"), 0644))

	attestor := &Attestor{}
	ctx := &attestation.AttestationContext{}

	err := attestor.Attest(ctx)
	require.NoError(t, err)
	assert.Len(t, attestor.Lockfiles, 1)
	assert.Equal(t, "requirements.txt", attestor.Lockfiles[0].Filename)
	assert.Equal(t, "flask==2.0\nrequests", attestor.Lockfiles[0].Content)
}

func TestAttestor_Subjects(t *testing.T) {
	attestor := &Attestor{
		Lockfiles: []LockfileInfo{
			{Filename: "go.sum", Content: "test"},
			{Filename: "frontend/package-lock.json", Content: "test2"},
		},
	}

	subjects := attestor.Subjects()
	assert.Len(t, subjects, 2)
	_, ok := subjects["file:go.sum"]
	assert.True(t, ok)
	_, ok = subjects["file:frontend/package-lock.json"]
	assert.True(t, ok)
}

func TestAttestor_Attest_EmptyDirectory(t *testing.T) {
	_ = chdirTemp(t)

	attestor := &Attestor{}
	ctx := &attestation.AttestationContext{}

	err := attestor.Attest(ctx)
	require.NoError(t, err)
	assert.Empty(t, attestor.Lockfiles)
}

func TestAttestor_Attest_NonexistentSearchPath(t *testing.T) {
	_ = chdirTemp(t)

	attestor := &Attestor{SearchPaths: "does-not-exist"}
	ctx := &attestation.AttestationContext{}

	// Glob returns no matches for nonexistent dirs (not an error)
	err := attestor.Attest(ctx)
	require.NoError(t, err)
	assert.Empty(t, attestor.Lockfiles)
}

func TestLockfilePatterns(t *testing.T) {
	patterns := lockfilePatterns()
	assert.Greater(t, len(patterns), 10, "should have at least 10 known lockfile patterns")
	assert.Contains(t, patterns, "requirements.txt")
	assert.Contains(t, patterns, "go.sum")
	assert.Contains(t, patterns, "package-lock.json")
	assert.Contains(t, patterns, "pnpm-lock.yaml")
}
