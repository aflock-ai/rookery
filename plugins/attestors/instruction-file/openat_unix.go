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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// openInstructionFile opens rel — a path relative to the workspace root — by
// descending ONE COMPONENT AT A TIME from a descriptor on that root, refusing a
// symlink at EVERY component rather than only at the last.
//
// # Why every component, and not just the leaf
//
// The previous construction resolved the parent directory through os.Root and
// applied O_NOFOLLOW only to the final component. That is not enough, and the
// gap is not theoretical.
//
// os.Root guarantees CONTAINMENT: no component may resolve outside the root.
// It does not guarantee IDENTITY: it deliberately follows a symlink among the
// parent components when the target stays inside the root. So with a workspace
// holding both `sub/` and `other/`, replacing `sub` with a symlink to `other`
// between the walk and the open leaves containment intact — `other` is inside
// the workspace — while the digest published under the subject path
// `sub/CLAUDE.md` is actually the bytes of `other/CLAUDE.md`. The signed
// statement binds a path to a digest, and that binding was false.
//
// Containment was never the property under test. The walk classified a
// specific file at a specific path; anything that changes which bytes live at
// that path between classification and read invalidates the record, whether or
// not the substitute is a workspace neighbour.
//
// So every component is opened with openat(O_NOFOLLOW|O_DIRECTORY) against the
// descriptor of the component before it. No name is ever re-resolved by the
// kernel's path walker, no symlink is followed anywhere along the chain, and
// there is no window between checking a component and using it — the descriptor
// IS the check. `..` and absolute paths are refused outright by splitRelative
// rather than normalized, because a traversal that never accepts `..` needs no
// argument about where it could have landed.
//
// O_NONBLOCK on the leaf is not decorative: opening a FIFO for reading blocks
// until a writer arrives, so without it a named pipe left where an instruction
// file belongs hangs the attestation forever and no evidence is produced at
// all. It is a no-op on the regular files this actually wants.
func openInstructionFile(root *os.Root, rel string) (*os.File, error) {
	comps, err := splitRelative(rel)
	if err != nil {
		return nil, err
	}

	// A descriptor on the workspace root itself. This is the only name os.Root
	// resolves for us; every component below is opened against a descriptor.
	dirFile, err := root.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	// cur is the descriptor the next component is opened against. It starts as
	// the root and is replaced as the walk descends; each replaced directory is
	// closed immediately so a deep path holds at most two descriptors.
	cur := dirFile
	defer func() {
		if cur != nil {
			_ = cur.Close()
		}
	}()

	for _, dir := range comps[:len(comps)-1] {
		//nolint:gosec // G115: cur.Fd() is a valid open descriptor (a small non-negative int); the uintptr->int conversion cannot overflow.
		fd, openErr := unix.Openat(int(cur.Fd()), dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr != nil {
			return nil, &os.PathError{Op: "openat", Path: rel, Err: openErr}
		}
		//nolint:gosec // G115: fd comes from a successful Openat and is non-negative; the int->uintptr conversion cannot overflow.
		next := os.NewFile(uintptr(fd), dir)
		_ = cur.Close()
		cur = next
	}

	base := comps[len(comps)-1]
	//nolint:gosec // G115: cur.Fd() is a valid open descriptor (a small non-negative int); the uintptr->int conversion cannot overflow.
	fd, openErr := unix.Openat(int(cur.Fd()), base, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if openErr != nil {
		return nil, &os.PathError{Op: "openat", Path: rel, Err: openErr}
	}

	//nolint:gosec // G115: fd comes from a successful Openat and is non-negative; the int->uintptr conversion cannot overflow.
	return os.NewFile(uintptr(fd), rel), nil
}

// splitRelative breaks a workspace-relative path into its components and
// refuses anything that is not a plain downward path.
//
// It is deliberately a REFUSAL rather than a normalization. filepath.Clean
// would happily turn `a/../b` into `b`, which is the right answer for a name
// and the wrong answer for evidence: the caller asked to read a specific walked
// path, and a path needing rewriting is not that path. Refusing keeps the
// no-follow traversal's guarantee simple enough to state — every component is
// a real directory entry opened against its parent, so there is no case where
// `..` could climb past a descriptor the traversal already pinned.
func splitRelative(rel string) ([]string, error) {
	if rel == "" {
		return nil, fmt.Errorf("empty relative path")
	}
	if filepath.IsAbs(rel) {
		return nil, fmt.Errorf("relative path required, got absolute %q", rel)
	}

	comps := strings.Split(rel, string(filepath.Separator))
	for _, c := range comps {
		if c == "" || c == "." || c == ".." {
			return nil, fmt.Errorf("path %q contains a non-descending component %q", rel, c)
		}
	}
	return comps, nil
}

// isSymlinkRefusal reports O_NOFOLLOW rejecting a symlink at ANY component —
// the leaf or any ancestor, since every one of them is opened with the flag.
// POSIX specifies ELOOP; FreeBSD-lineage kernels, macOS included, document
// EMLINK. Both must be recognized or the refusal is misreported as a generic
// open failure on exactly one of the two platforms CI runs.
//
// ENOTDIR is deliberately NOT in this set. An ancestor swapped for a regular
// file fails O_DIRECTORY with ENOTDIR, which is a real refusal but not a
// symlink one, and reporting it as "symlink not followed" would put a false
// reason in signed evidence. It surfaces as an open failure whose error text
// names the actual cause.
func isSymlinkRefusal(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}
