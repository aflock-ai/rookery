// Copyright 2026 TestifySec, Inc.
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

package testkit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMaterializeWorkdirPreservesSubpaths is the regression test for the
// .git-tree bug: materializeWorkdir used to flatten every file to its basename
// (filepath.Base), so a committed `.git/HEAD` and `.git/refs/heads/main`
// collapsed to `HEAD` and `main` in the same dir — destroying the directory
// structure that PlainOpen/DetectDotGit needs. The materializer must recreate
// the SUBPATH tree under the workdir, not just the basenames.
//
// It also covers the dot-git rename trick: a committed `dot-git/...` subtree is
// materialized as `.git/...` so a real repo can be stored inside this repo
// (git refuses to track a nested `.git/`).
func TestMaterializeWorkdirPreservesSubpaths(t *testing.T) {
	// A committed fixture-input tree with nested paths under dot-git/.
	src := t.TempDir()
	writeTree(t, src, map[string]string{
		"dot-git/HEAD":            "ref: refs/heads/main\n",
		"dot-git/refs/heads/main": "abc123\n",
		"dot-git/config":          "[core]\n",
		"README.md":               "hello\n",
	})

	fx := &Fixture{
		Name: "subpath",
		Mode: ModeWorkdir,
		Workdir: []string{
			filepath.Join(src, "dot-git", "HEAD"),
			filepath.Join(src, "dot-git", "refs", "heads", "main"),
			filepath.Join(src, "dot-git", "config"),
			filepath.Join(src, "README.md"),
		},
		// The workdir paths are relative to this Dir; the materializer must
		// reconstruct the tree relative to Dir, then apply the dot-git rename.
		Dir: src,
	}

	wd := materializeWorkdir(t, fx)
	if wd == "" {
		t.Fatal("materializeWorkdir returned empty workdir")
	}

	// dot-git/ must have been renamed to .git/, with the nested tree intact.
	wantFiles := map[string]string{
		".git/HEAD":            "ref: refs/heads/main\n",
		".git/refs/heads/main": "abc123\n",
		".git/config":          "[core]\n",
		"README.md":            "hello\n",
	}
	for rel, want := range wantFiles {
		got, err := os.ReadFile(filepath.Join(wd, rel)) //nolint:gosec // test path
		if err != nil {
			t.Errorf("expected materialized file %s: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("file %s = %q, want %q", rel, got, want)
		}
	}

	// The basename-flattening bug would have created these at the workdir root.
	for _, bad := range []string{"HEAD", "main", "config"} {
		if _, err := os.Stat(filepath.Join(wd, bad)); err == nil {
			t.Errorf("file %q exists at workdir root — paths were flattened (the bug), want preserved subpaths", bad)
		}
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
}
