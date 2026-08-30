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
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// unixSwapCases adds the entry types that need Unix-specific creation.
func unixSwapCases() []swapCase {
	return []swapCase{
		{
			// A FIFO is the case that makes O_NONBLOCK load-bearing rather
			// than decorative. open(2) for reading on a FIFO BLOCKS until a
			// writer arrives — so a path-based read does not merely publish
			// something wrong here, it never returns at all. The attestation
			// hangs, the build hangs, and no evidence is ever produced. A
			// regular-file check placed AFTER the open cannot save it, because
			// control never reaches the check.
			name: "fifo",
			rel:  "CLAUDE.md",
			swap: func(t *testing.T, root, _, _ string) {
				t.Helper()
				mustRemove(t, filepath.Join(root, "CLAUDE.md"))
				if err := syscall.Mkfifo(filepath.Join(root, "CLAUDE.md"), 0o600); err != nil {
					t.Skipf("mkfifo unavailable on this filesystem: %v", err)
				}
			},
		},
	}
}

// TestOpenInstructionFileRefusesALeafSymlinkDirectly exercises the opener on
// its own, below inspectFile.
//
// The sweep above proves the behaviour through the whole scan, which is what
// matters. This one pins the primitive, because the two halves of the guard
// live in different mechanisms — ancestors in os.Root, the leaf in an openat
// flag — and a change that dropped the flag would leave os.Root still refusing
// the escaping cases while silently following in-root leaf links. That is a
// narrow regression the end-to-end sweep would still catch, but only in the
// one subtest that constructs an in-root link; asserting it here says plainly
// which mechanism is missing.
func TestOpenInstructionFileRefusesALeafSymlinkDirectly(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "inner.txt"), []byte("target\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A RELATIVE, in-root target: the exact shape os.Root follows on its own.
	if err := os.Symlink("inner.txt", filepath.Join(root, "CLAUDE.md")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() { _ = rootHandle.Close() }()

	f, openErr := openInstructionFile(rootHandle, "CLAUDE.md")
	if openErr == nil {
		_ = f.Close()
		t.Fatal("opened a symlinked leaf whose target sits inside the root; os.Root alone follows this case, so O_NOFOLLOW must be what refuses it")
	}
	if !isSymlinkRefusal(openErr) {
		t.Errorf("open failed with %v, which isSymlinkRefusal does not recognize; the refusal would be recorded as a generic open failure instead of a symlink", openErr)
	}
}

// TestOpenInstructionFileRefusesAnEscapingAncestor pins the other half against
// the primitive: O_NOFOLLOW cannot see this case at all, so a pass here is
// attributable to the root handle and nothing else.
func TestOpenInstructionFileRefusesAnEscapingAncestor(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "CLAUDE.md"), []byte("SECRET\n"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "sub")); err != nil {
		t.Fatalf("symlink ancestor: %v", err)
	}

	rootHandle, err := os.OpenRoot(root)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer func() { _ = rootHandle.Close() }()

	f, openErr := openInstructionFile(rootHandle, filepath.Join("sub", "CLAUDE.md"))
	if openErr == nil {
		_ = f.Close()
		t.Fatal("opened through an ancestor symlink pointing outside the workspace; every component must resolve under the root handle")
	}
}
