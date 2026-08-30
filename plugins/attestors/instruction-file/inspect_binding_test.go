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

package instructionfile

import (
	"crypto"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// ---------------------------------------------------------------------------
// One open, one handle: path, size and digest must describe the same file.
// ---------------------------------------------------------------------------
//
// The defect class: a property is established about a PATH at one moment, and
// bytes are read from that path at another, and the two are published in one
// signed predicate as though they described the same thing. The walk lstats an
// entry and calls it a regular file; a separate open then re-resolves the name
// and takes whatever is there now.
//
// There are TWO independent ways to exploit that, and closing one does not
// close the other:
//
//   - the FINAL component becomes a symlink. O_NOFOLLOW refuses this
//     atomically.
//   - an ANCESTOR DIRECTORY becomes a symlink. O_NOFOLLOW is useless here —
//     the leaf is still a regular file, so the flag has nothing to refuse.
//     Only resolving every component under a root handle stops it.
//
// Both are swept below. The ancestor case is the one the first fix missed, and
// it is strictly the more dangerous of the two: it redirects the read to an
// arbitrary directory anywhere the build user can read.
//
// Following either turns the attestor into a content-confirmation oracle. The
// SHA-256 of any readable file gets published as a subject keyed by a path
// those bytes never came from. The digest is genuine and the signature
// verifies, which is the worst shape a supply-chain claim can take.

// staleEntryFor returns the DirEntry a walk would have produced for name in
// dir, captured BEFORE the swap the caller is about to perform.
//
// This is what makes these tests deterministic rather than racy. A real attack
// needs to win a race between the walk's lstat and the read; reproducing that
// with goroutines produces a test that fails intermittently and gets deleted
// within a month. Capturing the DirEntry first and swapping afterwards
// reproduces the exact STATE that race produces — a classification that was
// true when it was made and is false when it is used — with no timing
// dependency at all.
func staleEntryFor(t *testing.T, dir, name string) fs.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.Name() == name {
			if e.Type()&fs.ModeSymlink != 0 || e.IsDir() {
				t.Fatalf("fixture %s is not a regular file before the swap; the test would not reproduce the stale classification", name)
			}
			return e
		}
	}
	t.Fatalf("fixture %s not found in %s", name, dir)
	return nil
}

// swapCase is one thing the path can become after the walk classified the leaf
// as a regular file.
type swapCase struct {
	// rel is where the instruction file lives, relative to the workspace root.
	// Cases that attack an ancestor put it in a subdirectory.
	rel string
	// name is the subtest name.
	name string
	// swap mutates the workspace. secret is a readable file OUTSIDE the
	// workspace whose bytes must never appear in the predicate; outsideDir is
	// the directory holding it, for ancestor swaps.
	swap func(t *testing.T, root, secret, outsideDir string)
}

// portableSwapCases enumerates the swaps constructible without mkfifo.
func portableSwapCases() []swapCase {
	return []swapCase{
		{
			name: "ancestor-directory-becomes-an-escaping-symlink",
			rel:  "sub/CLAUDE.md",
			// The case O_NOFOLLOW cannot see. Every component of the path is
			// still a regular file at the end of this swap — only the PARENT
			// changed, and it changed into a link pointing out of the
			// workspace. A leaf-only defense reads the outside file and
			// publishes its digest under the in-workspace path.
			swap: func(t *testing.T, root, _, outsideDir string) {
				t.Helper()
				if err := os.RemoveAll(filepath.Join(root, "sub")); err != nil {
					t.Fatalf("remove sub: %v", err)
				}
				if err := os.Symlink(outsideDir, filepath.Join(root, "sub")); err != nil {
					t.Fatalf("symlink ancestor: %v", err)
				}
			},
		},
		{
			name: "final-component-becomes-an-escaping-symlink",
			rel:  "CLAUDE.md",
			swap: func(t *testing.T, root, secret, _ string) {
				t.Helper()
				mustRemove(t, filepath.Join(root, "CLAUDE.md"))
				if err := os.Symlink(secret, filepath.Join(root, "CLAUDE.md")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "final-component-becomes-an-in-root-symlink",
			rel:  "CLAUDE.md",
			// The case a containment-only defense misses. os.Root FOLLOWS this
			// one — measured on this toolchain — because the target stays
			// inside the root. Containment is not the property under test: the
			// walk classified a regular file, so any link met at open time is a
			// swap, and its target being in-root does not make that
			// classification true again.
			swap: func(t *testing.T, root, _, _ string) {
				t.Helper()
				inner := filepath.Join(root, "inner-secret.txt")
				if err := os.WriteFile(inner, []byte("in-root bytes that are not this file\n"), 0o600); err != nil {
					t.Fatalf("write inner: %v", err)
				}
				mustRemove(t, filepath.Join(root, "CLAUDE.md"))
				if err := os.Symlink("inner-secret.txt", filepath.Join(root, "CLAUDE.md")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "dangling-symlink",
			rel:  "CLAUDE.md",
			swap: func(t *testing.T, root, _, _ string) {
				t.Helper()
				mustRemove(t, filepath.Join(root, "CLAUDE.md"))
				if err := os.Symlink(filepath.Join(root, "nothing-here"), filepath.Join(root, "CLAUDE.md")); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			},
		},
		{
			name: "directory",
			rel:  "CLAUDE.md",
			swap: func(t *testing.T, root, _, _ string) {
				t.Helper()
				mustRemove(t, filepath.Join(root, "CLAUDE.md"))
				if err := os.Mkdir(filepath.Join(root, "CLAUDE.md"), 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
			},
		},
	}
}

// TestSweep_NoPostClassificationSwapYieldsAForeignDigest is the sweep that
// kills the class.
//
// It ranges over every way the resolved path can be redirected after the walk
// classified the leaf — at the leaf itself and at an ancestor — and asserts the
// same three things each time: the entry is still REPORTED (a file found and
// refused is a different fact from one that was never there), it carries NO
// digest, and — the invariant that actually matters — the digest is not that of
// the file outside the workspace.
//
// The last assertion is the one with teeth. A fix that merely returned an error
// would satisfy the first two; only reading through a handle that cannot have
// followed the redirect satisfies the third.
func TestSweep_NoPostClassificationSwapYieldsAForeignDigest(t *testing.T) {
	secretBytes := []byte("SECRET: bytes from outside the workspace that must never be digested\n")
	secretDigest, err := cryptoutil.CalculateDigestSetFromBytes(secretBytes, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err != nil {
		t.Fatalf("digest secret: %v", err)
	}

	for _, tc := range append(portableSwapCases(), unixSwapCases()...) {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()

			// The workspace-external target. For an ancestor swap the parent
			// is redirected AT this directory, so the decoy inside it carries
			// the same base name as the real file.
			outsideDir := t.TempDir()
			secret := filepath.Join(outsideDir, filepath.Base(tc.rel))
			if err := os.WriteFile(secret, secretBytes, 0o600); err != nil {
				t.Fatalf("write secret: %v", err)
			}

			full := filepath.Join(root, filepath.FromSlash(tc.rel))
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(full, []byte("the real instruction file\n"), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}

			// Classify first, swap second — the stale state a winning race
			// produces, reached deterministically.
			d := staleEntryFor(t, filepath.Dir(full), filepath.Base(tc.rel))
			tc.swap(t, root, secret, outsideDir)

			rootHandle, err := os.OpenRoot(root)
			if err != nil {
				t.Fatalf("open root: %v", err)
			}
			defer func() { _ = rootHandle.Close() }()

			f, _, matched := inspectFile(rootHandle, root, full, d)
			if !matched {
				t.Fatal("the entry was dropped entirely; a recognized path that could not be digested must still be reported, or a policy cannot tell 'refused' from 'absent'")
			}
			if reflect.DeepEqual(f.Digest, secretDigest) {
				t.Fatalf("CATASTROPHIC: the predicate carries the digest of a file outside the workspace, keyed as %q. The attestor is a content-confirmation oracle", f.Path)
			}
			if len(f.Digest) != 0 {
				t.Errorf("a swapped %s produced a digest %v; nothing at this path is the regular file the walk classified", tc.name, f.Digest)
			}
			if f.SkipReason == "" {
				t.Error("no SkipReason recorded; a refusal that does not say why reads as a clean empty result")
			}
		})
	}
}

// TestSweep_SizeAndDigestAlwaysDescribeTheSameBytes ranges over the complete
// boundary set around the size cap and asserts the two published facts about a
// file agree with each other.
//
// SizeBytes and Digest are independently derivable, which is exactly why they
// can disagree: take the size from a cached lstat and the bytes from a later
// read and you get a record whose own fields contradict each other. Requiring
// SizeBytes to equal the length of the bytes that produced Digest makes that
// disagreement a test failure rather than a subtle artifact in signed evidence.
func TestSweep_SizeAndDigestAlwaysDescribeTheSameBytes(t *testing.T) {
	sizes := []struct {
		name string
		n    int
	}{
		{"empty", 0},
		{"one-byte", 1},
		{"one-under-cap", maxFileBytes - 1},
		{"exactly-cap", maxFileBytes},
		{"one-over-cap", maxFileBytes + 1},
	}

	for _, s := range sizes {
		t.Run(s.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "CLAUDE.md")
			body := make([]byte, s.n)
			for i := range body {
				body[i] = byte('a' + i%26)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			files, _, err := scan(root)
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if len(files) != 1 {
				t.Fatalf("scan returned %d files, want 1", len(files))
			}
			f := files[0]

			if s.n > maxFileBytes {
				if len(f.Digest) != 0 {
					t.Errorf("a file over the %d byte cap was digested anyway", int64(maxFileBytes))
				}
				if !strings.Contains(f.SkipReason, "cap") {
					t.Errorf("SkipReason = %q, want it to name the size cap", f.SkipReason)
				}
				return
			}

			if len(f.Digest) == 0 {
				t.Fatalf("a %d byte file at or under the cap was not digested: %s", s.n, f.SkipReason)
			}
			if f.SizeBytes != int64(len(body)) {
				t.Errorf("SizeBytes = %d, want %d: the size and the digested bytes must come off the same open handle", f.SizeBytes, len(body))
			}
			want, err := cryptoutil.CalculateDigestSetFromBytes(body, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
			if err != nil {
				t.Fatalf("digest: %v", err)
			}
			if !reflect.DeepEqual(f.Digest, want) {
				t.Errorf("digest does not match the bytes written to the path")
			}
		})
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove %s: %v", path, err)
	}
}
