//go:build !windows

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

package cryptoutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDirHashWithinRoot_FormatIdenticalForSymlinkFreeTree is the load-bearing
// compatibility guarantee: the boundary-enforcing dir hash must produce the
// EXACT same "dirHash" value as the legacy CalculateDigestSetFromDir for a tree
// with no symlinks, so existing attestations still verify.
func TestDirHashWithinRoot_FormatIdenticalForSymlinkFreeTree(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0o644))
	sub := filepath.Join(root, "sub")
	require.NoError(t, os.Mkdir(sub, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "b.txt"), []byte("bravo"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(sub, "c.txt"), []byte("charlie"), 0o644))

	legacy, err := CalculateDigestSetFromDir(root, nil)
	require.NoError(t, err)
	guarded, err := CalculateDigestSetFromDirWithinRoot(root, root, nil)
	require.NoError(t, err)

	legacyMap, err := legacy.ToNameMap()
	require.NoError(t, err)
	guardedMap, err := guarded.ToNameMap()
	require.NoError(t, err)
	require.Equal(t, legacyMap["dirHash"], guardedMap["dirHash"],
		"within-root dir hash must be byte-identical to the legacy dir hash for a symlink-free tree")
}

// TestDirHashWithinRoot_RejectsEscapingSymlink: a symlink escaping the root
// fails the whole hash (no out-of-tree content leaks in).
func TestDirHashWithinRoot_RejectsEscapingSymlink(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret"), []byte("SECRET"), 0o644))

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(outside, "secret"), filepath.Join(root, "link")))

	_, err := CalculateDigestSetFromDirWithinRoot(root, root, nil)
	require.Error(t, err, "a symlink escaping the root must fail the dir hash")
}

// TestDirHashWithinRoot_RejectsEscapingSymlinkToDirInSubdir pins the exact
// scenario a reviewer flagged as a possible gap: an escaping symlink that points
// at an out-of-tree DIRECTORY and lives inside a SUBDIRECTORY of the hashed tree
// (e.g. vendor/link -> /outside). dirhash.DirFiles enumerates via filepath.Walk,
// which classifies entries with Lstat: a symlink is reported as a symlink (not a
// dir), so the entry IS surfaced in the file list and reaches openWithinRoot,
// which resolves the target and fails closed when it escapes the root. This guards
// against a regression that would silently omit the symlink and hash "successfully".
func TestDirHashWithinRoot_RejectsEscapingSymlinkToDirInSubdir(t *testing.T) {
	outside := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(outside, "secret"), []byte("SECRET"), 0o644))

	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "a.txt"), []byte("alpha"), 0o644))
	sub := filepath.Join(root, "vendor")
	require.NoError(t, os.Mkdir(sub, 0o755))
	// vendor/link -> outside DIRECTORY (not a file).
	require.NoError(t, os.Symlink(outside, filepath.Join(sub, "link")))

	_, err := CalculateDigestSetFromDirWithinRoot(root, root, nil)
	require.Error(t, err,
		"an escaping symlink-to-directory inside a subdirectory must fail the dir hash, not be silently omitted")
}

// TestDirHashWithinRoot_FollowsInTreeSymlink: an in-tree symlink is followed and
// hashed (behavior preserved, e.g. pnpm-style node_modules), and the resulting
// dirHash is BYTE-IDENTICAL to the legacy CalculateDigestSetFromDir — the
// backwards-compat guarantee that existing attestations of trees containing
// in-tree symlinks still verify after the within-root switch.
func TestDirHashWithinRoot_FollowsInTreeSymlink(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "target.txt"), []byte("target"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(root, "target.txt"), filepath.Join(root, "link.txt")))

	legacy, err := CalculateDigestSetFromDir(root, nil)
	require.NoError(t, err)
	guarded, err := CalculateDigestSetFromDirWithinRoot(root, root, nil)
	require.NoError(t, err, "an in-tree symlink must still be followed and hashed")

	legacyMap, err := legacy.ToNameMap()
	require.NoError(t, err)
	guardedMap, err := guarded.ToNameMap()
	require.NoError(t, err)
	require.Equal(t, legacyMap["dirHash"], guardedMap["dirHash"],
		"within-root dir hash must be byte-identical to the legacy dir hash for an in-tree symlink")
}
