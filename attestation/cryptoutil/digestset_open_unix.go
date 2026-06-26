// Copyright 2026 The Witness Contributors
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

package cryptoutil

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// openRegularInRoot opens the final component of name relative to root while
// atomically refusing a symlink final component — escaping OR in-root.
//
// This is the core of the #5994 fix. os.Root.Open / os.Root.OpenFile cannot be
// used directly for the final component: on unix they open it with O_NOFOLLOW,
// get ELOOP, and then deliberately re-resolve the link and follow it when the
// target stays inside the root (see os.checkSymlink). That in-root-following is
// exactly the residual TOCTOU the reviewer flagged: the walker only ever
// dispatches Lstat-classified REGULAR files to a worker, so any symlink the
// worker meets at open time is a post-classification swap and must be refused —
// even if it resolves inside the root.
//
// We therefore resolve only the PARENT directory through os.Root (which keeps
// the escape protection: a symlinked parent component cannot point outside the
// root), then perform the final open ourselves with a raw openat carrying
// O_NOFOLLOW. openat with O_NOFOLLOW fails with ELOOP if the final component is
// a symlink of any kind, with no userspace re-resolution — so this is a single
// atomic syscall on the leaf with no recheck window.
func openRegularInRoot(root *os.Root, name string) (*os.File, error) {
	dir := filepath.Dir(name)
	base := filepath.Base(name)

	// Resolve the parent directory through the root. os.Root follows in-root
	// symlinks among the parent components but refuses any that escape, so the
	// returned fd is guaranteed to be a directory contained by the root.
	dirFile, err := root.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dirFile.Close() }()

	// Final-component open relative to the parent fd. O_NOFOLLOW makes openat
	// fail with ELOOP for a symlink leaf (escaping or in-root), atomically.
	//nolint:gosec // G115: dirFile.Fd() is a valid open file descriptor (small non-negative int); the uintptr->int conversion cannot overflow.
	fd, err := unix.Openat(int(dirFile.Fd()), base, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "openat", Path: name, Err: err}
	}

	//nolint:gosec // G115: fd is a valid descriptor returned by a successful Openat (non-negative int); the int->uintptr conversion cannot overflow.
	return os.NewFile(uintptr(fd), filepath.Join(root.Name(), name)), nil
}
