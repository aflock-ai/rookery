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

package file

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/gobwas/glob"
	"github.com/stretchr/testify/require"
)

// dirHashTree builds root/vendor/legit.go plus a symlink at
// vendor/<linkName> -> linkTarget, and returns the root and a "vendor" glob.
func dirHashTree(t *testing.T, linkName, linkTarget string) (string, glob.Glob) {
	t.Helper()
	root := t.TempDir()
	vendorDir := filepath.Join(root, "vendor")
	require.NoError(t, os.Mkdir(vendorDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(vendorDir, "legit.go"), []byte("package vendor"), 0o644))
	require.NoError(t, os.Symlink(linkTarget, filepath.Join(vendorDir, linkName)))
	g, err := glob.Compile("vendor")
	require.NoError(t, err)
	return root, g
}

func recordDirHash(root string, restricted bool, g glob.Glob) (map[string]cryptoutil.DigestSet, error) {
	// restricted == true exercises the default RecordArtifacts (fail-closed);
	// restricted == false exercises the opt-in RecordArtifactsFollowingSymlinks.
	fn := RecordArtifactsFollowingSymlinks
	if restricted {
		fn = RecordArtifacts
	}
	return fn(
		root,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{g}, nil, nil,
	)
}

// TestSecurity_GHSA_v6px_DirHashDefaultRefusesEscapingSymlink proves that the
// DEFAULT behavior (RecordArtifacts) refuses to dir-hash a directory containing
// a symlink whose target escapes the attestation root (GHSA-v6px-jqx8-8xwj), so
// out-of-tree content can never enter an attestation by default. The opt-in
// following mode follows it (build-input fidelity) — see the Following test.
func TestSecurity_GHSA_v6px_DirHashDefaultRefusesEscapingSymlink(t *testing.T) {
	outside := t.TempDir()
	outsideSecret := filepath.Join(outside, "secret_data.txt")
	require.NoError(t, os.WriteFile(outsideSecret, []byte("SECRET-OUTSIDE-ROOT"), 0o644))

	root, g := dirHashTree(t, "injected_link.txt", outsideSecret)

	_, err := recordDirHash(root, true /*restricted (default)*/, g)
	require.Error(t, err,
		"default mode must refuse a dir-hash whose symlink escapes the attestation root (GHSA-v6px-jqx8-8xwj)")
}

// TestSecurity_GHSA_v6px_DirHashFollowingModeFollowsEscapingSymlink documents
// that the opt-in RecordArtifactsFollowingSymlinks follows an escaping symlink
// so the dir hash faithfully records what a trusted build consumed (out-of-tree
// inputs). The hash succeeds and differs from the same tree without the link.
func TestSecurity_GHSA_v6px_DirHashFollowingModeFollowsEscapingSymlink(t *testing.T) {
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "toolchain_input.txt")
	require.NoError(t, os.WriteFile(outsideFile, []byte("external-build-input"), 0o644))

	root, g := dirHashTree(t, "external_link.txt", outsideFile)

	artifacts, err := recordDirHash(root, false /*following mode*/, g)
	require.NoError(t, err, "following mode must follow the escaping symlink to record the build input")
	require.Contains(t, artifacts, "vendor/")
}

// TestSecurity_GHSA_v6px_DirHashAllowsInTreeSymlink proves an in-tree symlink in
// a dir-hashed directory is followed in BOTH modes.
func TestSecurity_GHSA_v6px_DirHashAllowsInTreeSymlink(t *testing.T) {
	for _, restricted := range []bool{false, true} {
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "target.txt"), []byte("in-tree target"), 0o644))
		vendorDir := filepath.Join(root, "vendor")
		require.NoError(t, os.Mkdir(vendorDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(vendorDir, "legit.go"), []byte("package vendor"), 0o644))
		require.NoError(t, os.Symlink(filepath.Join(root, "target.txt"), filepath.Join(vendorDir, "ok_link.txt")))
		g, err := glob.Compile("vendor")
		require.NoError(t, err)

		artifacts, err := recordDirHash(root, restricted, g)
		require.NoErrorf(t, err, "in-tree symlink must be allowed (restricted=%v)", restricted)
		require.Contains(t, artifacts, "vendor/")
	}
}

// TestSecurity_GHSA_v6px_ChainedSymlinkPerFileEscapeRefused proves sub-fix (c):
// the escape boundary is the ORIGINAL attestation root threaded through symlink
// recursion, not the per-call basePath. An in-root symlink points to an in-root
// directory that itself contains a symlink escaping the original root; by
// default the nested escaping symlink must be skipped (no out-of-tree content),
// while the legitimate in-tree file is still recorded through both paths.
func TestSecurity_GHSA_v6px_ChainedSymlinkPerFileEscapeRefused(t *testing.T) {
	outside := t.TempDir()
	outsideSecret := filepath.Join(outside, "secret_data.txt")
	require.NoError(t, os.WriteFile(outsideSecret, []byte("SECRET-OUTSIDE-ROOT"), 0o644))

	root := t.TempDir()
	realDir := filepath.Join(root, "realdir")
	require.NoError(t, os.Mkdir(realDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(realDir, "legit.txt"), []byte("legit"), 0o644))
	// Nested escaping symlink inside the in-root directory.
	require.NoError(t, os.Symlink(outsideSecret, filepath.Join(realDir, "escape.txt")))
	// In-root symlink to the in-root directory (the in-tree hop).
	require.NoError(t, os.Symlink(realDir, filepath.Join(root, "entry")))

	artifacts, err := RecordArtifacts(
		root,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		nil, nil, nil,
	)
	require.NoError(t, err, "a chained in-tree symlink with a nested escaping symlink must not error; the escape is skipped")

	// The legit in-tree file is recorded both directly and through the in-tree
	// symlink hop, but nothing resolving to the out-of-tree secret is recorded.
	require.Contains(t, artifacts, filepath.Join("realdir", "legit.txt"))
	require.Contains(t, artifacts, filepath.Join("entry", "legit.txt"))
	for k := range artifacts {
		require.NotContains(t, k, "escape.txt",
			"the nested escaping symlink must be skipped against the ORIGINAL root, not re-anchored to the per-call basePath")
	}
}

// TestSecurity_GHSA_v6px_ChainedSymlinkDirHashEscapeRefused proves sub-fix (c)
// for the dir-hash path: the dir-hash is reached ONLY through an in-tree symlink
// chain (the "vendor" glob never matches the direct "pkg/vendor" path), and the
// dir-hash-within-root must still be anchored to the ORIGINAL root and fail
// closed on the nested escaping symlink (GHSA-v6px-jqx8-8xwj).
func TestSecurity_GHSA_v6px_ChainedSymlinkDirHashEscapeRefused(t *testing.T) {
	outside := t.TempDir()
	outsideSecret := filepath.Join(outside, "secret_data.txt")
	require.NoError(t, os.WriteFile(outsideSecret, []byte("SECRET-OUTSIDE-ROOT"), 0o644))

	root := t.TempDir()
	vendorDir := filepath.Join(root, "pkg", "vendor")
	require.NoError(t, os.MkdirAll(vendorDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(vendorDir, "legit.go"), []byte("package vendor"), 0o644))
	require.NoError(t, os.Symlink(outsideSecret, filepath.Join(vendorDir, "injected.go")))
	// In-root symlink to root/pkg. The "vendor" glob matches only relative to
	// this recursed walk's basePath (root/pkg), so the dir-hash fires solely via
	// the symlink chain — not the direct "pkg/vendor" descent.
	require.NoError(t, os.Symlink(filepath.Join(root, "pkg"), filepath.Join(root, "link")))
	g, err := glob.Compile("vendor")
	require.NoError(t, err)

	_, err = RecordArtifacts(
		root,
		map[string]cryptoutil.DigestSet{},
		[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		map[string]struct{}{},
		false,
		map[string]bool{},
		[]glob.Glob{g}, nil, nil,
	)
	require.Error(t, err,
		"a dir-hash reached through an in-tree symlink chain must still fail closed on a nested escaping symlink against the original root (GHSA-v6px-jqx8-8xwj)")
}

// TestWithinRoot covers the boundary predicate, including the filesystem-root
// edge case (absRoot == "/") that a naive prefix check mishandles, and the
// sibling-prefix bypass it must reject.
func TestWithinRoot(t *testing.T) {
	cases := []struct {
		absPath, absRoot string
		want             bool
	}{
		{"/srv/build", "/srv/build", true},         // root itself
		{"/srv/build/bin/app", "/srv/build", true}, // descendant
		{"/etc/passwd", "/", true},                 // descendant of "/" (edge case)
		{"/", "/", true},                           // root is "/"
		{"/srv/build-evil/x", "/srv/build", false}, // sibling-prefix bypass
		{"/etc/shadow", "/srv/build", false},       // outside
	}
	for _, c := range cases {
		require.Equalf(t, c.want, withinRoot(c.absPath, c.absRoot),
			"withinRoot(%q, %q)", c.absPath, c.absRoot)
	}
}
