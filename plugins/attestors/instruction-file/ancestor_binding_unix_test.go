// Copyright 2026 The Rookery Contributors
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

//go:build unix

package instructionfile

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenRefusesInRootAncestorSymlink is the regression for the finding that
// containment is not identity.
//
// The workspace holds two real directories, `sub/` and `other/`, each with its
// own CLAUDE.md. Replacing `sub` with a symlink to `other` — a swap that stays
// entirely INSIDE the workspace — leaves os.Root perfectly happy, because
// nothing resolves outside the root. The previous implementation resolved
// ancestors through os.Root and applied O_NOFOLLOW only to the leaf, so it
// followed that link and published `other/CLAUDE.md`'s bytes under the subject
// path `sub/CLAUDE.md`. The signed statement bound a path to a digest that did
// not belong to it.
//
// The open must refuse. Containment was never the property under test.
func TestOpenRefusesInRootAncestorSymlink(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()

	sub := filepath.Join(workspace, "sub")
	other := filepath.Join(workspace, "other")
	for _, d := range []string{sub, other} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	const honest = "# the real sub instructions\n"
	const foreign = "# the OTHER directory's instructions\n"
	if err := os.WriteFile(filepath.Join(sub, "CLAUDE.md"), []byte(honest), 0o600); err != nil {
		t.Fatalf("write sub/CLAUDE.md: %v", err)
	}
	if err := os.WriteFile(filepath.Join(other, "CLAUDE.md"), []byte(foreign), 0o600); err != nil {
		t.Fatalf("write other/CLAUDE.md: %v", err)
	}

	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() { _ = root.Close() }()

	// Sanity: before the swap the honest bytes are readable through the root.
	handle, err := openInstructionFile(root, filepath.Join("sub", "CLAUDE.md"))
	if err != nil {
		t.Fatalf("precondition: open sub/CLAUDE.md before swap: %v", err)
	}
	got, readErr := io.ReadAll(handle)
	_ = handle.Close()
	if readErr != nil {
		t.Fatalf("precondition: read sub/CLAUDE.md: %v", readErr)
	}
	if string(got) != honest {
		t.Fatalf("precondition: sub/CLAUDE.md = %q, want %q", got, honest)
	}

	// The swap: sub becomes an in-root symlink to other.
	if err := os.Remove(filepath.Join(sub, "CLAUDE.md")); err != nil {
		t.Fatalf("remove sub/CLAUDE.md: %v", err)
	}
	if err := os.Remove(sub); err != nil {
		t.Fatalf("remove sub: %v", err)
	}
	// RELATIVE, and that detail is the whole test. os.Root refuses an ABSOLUTE
	// symlink outright ("symbolic links must not be absolute"), so a test that
	// links to the absolute path of `other` is refused for the wrong reason and
	// passes against the very implementation it is meant to catch — measured:
	// it did. A relative in-root link is the case the reviewer described and the
	// one os.Root deliberately follows.
	if err := os.Symlink("other", sub); err != nil {
		t.Skipf("cannot create symlink on this filesystem: %v", err)
	}

	swapped, err := openInstructionFile(root, filepath.Join("sub", "CLAUDE.md"))
	if err == nil {
		// Read from the HANDLE, not from swapped.Name(): the name is the
		// workspace-relative path and resolving it again from the test's own cwd
		// would report an empty read and hide what was actually published.
		content, _ := io.ReadAll(swapped)
		_ = swapped.Close()
		t.Fatalf("open through a symlinked ancestor succeeded and read %q under the subject path sub/CLAUDE.md; it must refuse", content)
	}

	// The assertion is the PROPERTY — the open refused, so no foreign bytes can
	// reach a digest — and deliberately not a specific errno. Opening a symlink
	// with O_DIRECTORY|O_NOFOLLOW reports ELOOP on Linux and ENOTDIR on the
	// BSD/macOS lineage, because there the "not a directory" condition is
	// evaluated first. Pinning one of those would make this test pass on one CI
	// platform and fail on the other while the security behaviour was identical
	// on both. inspectFile records either as an open failure, which drives the
	// scan to `incomplete` and carries the real error text as the reason.
	if !strings.Contains(err.Error(), "sub") {
		t.Errorf("open error = %v, want an error naming the refused path", err)
	}
}

// TestOpenRefusesEscapingAncestorSymlink keeps the containment property that
// the previous implementation did have. A no-follow traversal must not trade
// the escape guarantee away while it gains the identity one.
func TestOpenRefusesEscapingAncestorSymlink(t *testing.T) {
	t.Parallel()

	workspace := t.TempDir()
	outside := t.TempDir()

	if err := os.WriteFile(filepath.Join(outside, "CLAUDE.md"), []byte("# outside\n"), 0o600); err != nil {
		t.Fatalf("write outside/CLAUDE.md: %v", err)
	}

	sub := filepath.Join(workspace, "sub")
	if err := os.Symlink(outside, sub); err != nil {
		t.Skipf("cannot create symlink on this filesystem: %v", err)
	}

	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() { _ = root.Close() }()

	handle, err := openInstructionFile(root, filepath.Join("sub", "CLAUDE.md"))
	if err == nil {
		content, _ := os.ReadFile(handle.Name())
		_ = handle.Close()
		t.Fatalf("open through an escaping ancestor succeeded and read %q; it must refuse", content)
	}
}

// TestSplitRelativeRefusesNonDescendingPaths pins the refusal-not-normalization
// choice. filepath.Clean would rewrite `a/../b` into `b`; for evidence that is
// the wrong answer, because the caller asked for the path the walk classified
// and a path needing rewriting is not that path.
func TestSplitRelativeRefusesNonDescendingPaths(t *testing.T) {
	t.Parallel()

	// Built as literals, never with filepath.Join: Join CLEANS its result, so
	// Join("a","..","b") is already "b" and would test nothing. The whole point
	// of splitRelative is what it does with a path that has NOT been cleaned.
	bad := []string{
		"",
		"/absolute/CLAUDE.md",
		"../escape/CLAUDE.md",
		"a/../b/CLAUDE.md",
		"a/./CLAUDE.md",
		"a//CLAUDE.md",
		"./CLAUDE.md",
	}

	for _, rel := range bad {
		if comps, err := splitRelative(rel); err == nil {
			t.Errorf("splitRelative(%q) = %v, nil; want a refusal", rel, comps)
		}
	}

	good := filepath.Join("a", "b", "CLAUDE.md")
	comps, err := splitRelative(good)
	if err != nil {
		t.Fatalf("splitRelative(%q) returned %v, want the components", good, err)
	}
	if want := []string{"a", "b", "CLAUDE.md"}; strings.Join(comps, "/") != strings.Join(want, "/") {
		t.Errorf("splitRelative(%q) = %v, want %v", good, comps, want)
	}
}
