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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/sumdb/dirhash"
)

// CalculateDigestSetFromDirWithinRoot computes the same directory hash as
// CalculateDigestSetFromDir (identical "dirHash" value for an equivalent tree),
// but confines every file open beneath `root`: an in-tree symlink is followed
// (so e.g. pnpm-style node_modules still hash), while a symlink whose resolved
// target escapes root fails the whole hash.
//
// This is the RESTRICTED dir-hash mode — the DEFAULT file-attestor behavior,
// which refuses out-of-tree content (the safe default, e.g. attesting an
// untrusted tree). The opt-in unrestricted mode instead follows escaping
// symlinks via CalculateDigestSetFromDir to faithfully record what a trusted
// build consumed.
//
// It is race-free against symlink swaps: each file is opened through an os.Root
// handle, which resolves every path component beneath root and refuses to
// traverse any symlink, so neither a parent-directory nor a final-component
// swap (a classic dir-hash TOCTOU) can escape the root regardless of concurrent
// writes during attestation (GHSA-v6px-jqx8-8xwj). hashes is accepted for
// signature parity with CalculateDigestSetFromDir.
func CalculateDigestSetFromDirWithinRoot(dir, root string, _ []DigestValue) (DigestSet, error) {
	files, err := dirhash.DirFiles(dir, "")
	if err != nil {
		return nil, err
	}

	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if resolved, rerr := filepath.EvalSymlinks(absRoot); rerr == nil {
		absRoot = resolved
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	// os.Root confines all opens beneath absRoot and refuses to traverse symlink
	// components, closing the parent- and final-component TOCTOU races.
	rootHandle, err := os.OpenRoot(absRoot)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rootHandle.Close() }()

	// dirhash.HashDir(dir, "", DirhHashSha256) is DirhHashSha256(DirFiles(dir,
	// ""), osOpen) where osOpen(name) opens filepath.Join(dir, name). We reuse
	// the same file list and hash function and only swap the open callback, so
	// the resulting hash is byte-identical for an equivalent tree.
	open := func(name string) (io.ReadCloser, error) {
		return openWithinRoot(rootHandle, absRoot, filepath.Join(absDir, name))
	}

	dirHash, err := DirhHashSha256(files, open)
	if err != nil {
		return nil, err
	}

	return NewDigestSet(map[string]string{"dirHash": dirHash})
}

// openWithinRoot resolves fullPath (following in-tree symlinks) to its canonical
// real path and opens that path THROUGH the root handle. Because os.Root re-walks
// every component beneath root and refuses symlink traversal, the open is
// confined and race-free: a target that resolves outside root is rejected, and a
// component swapped to a symlink after EvalSymlinks fails the os.Root open rather
// than escaping. absRoot must be absolute and symlink-resolved.
func openWithinRoot(rootHandle *os.Root, absRoot, fullPath string) (io.ReadCloser, error) {
	resolved, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		// Broken symlink / missing file: matches the legacy os.Open failure.
		return nil, err
	}
	rel, err := filepath.Rel(absRoot, resolved)
	if err != nil {
		return nil, err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil, fmt.Errorf("dirhash: refusing %q: target %q escapes attestation root %q", fullPath, resolved, absRoot)
	}
	return rootHandle.Open(rel)
}
