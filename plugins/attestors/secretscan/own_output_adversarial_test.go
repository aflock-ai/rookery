// jade:ring local
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

package secretscan

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// Adversarial cases for the own-output skip, from the capability of whoever
// controls the repository content or the wrapped command: they can name files,
// make links and write log-shaped text, but none of that may make a file with
// a secret count as this process's own untracked stream.

// scanProductWithStream scans rel as a product while `stream` stands in for
// this process's stdout/stderr.
func scanProductWithStream(t *testing.T, dir, rel string, stream *os.File, opts ...Option) *Attestor {
	t.Helper()
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	recorded, err := cryptoutil.CalculateDigestSetFromFile(filepath.Join(dir, filepath.FromSlash(rel)), hashes)
	require.NoError(t, err)
	scan := New(opts...)
	scan.ownStreams = func() []*os.File { return []*os.File{stream} }
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{rel: {MimeType: "text/plain", Digest: recorded}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return scan
}

// A symlink in the working tree that points at this process's stream is not
// that file. The skip is for the regular file the stream writes, named as
// itself; a link placed next to it must not get the target's bytes skipped
// under the link's untracked name.
func TestUntrackedSymlinkToOwnStreamIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	target := filepath.Join(t.TempDir(), "stderr.log")
	require.NoError(t, os.WriteFile(target, []byte("token="+scopePAT+"\n"), 0o600))

	rel := "out/link.log"
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "out"), 0o750))
	require.NoError(t, os.Symlink(target, filepath.Join(dir, filepath.FromSlash(rel))))

	// The working-tree walk reads no symlink at all (scanOneFile), so this
	// pins the skip decision itself, which any route would consult.
	scan := New()
	scan.ownStreams = func() []*os.File { return []*os.File{openAppend(t, target)} }
	ctx, err := attestation.NewContext("test", nil, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.False(t, scan.skipAsOwnOutput(ctx, rel, filepath.Join(dir, filepath.FromSlash(rel)), openedInfo(t, filepath.Join(dir, filepath.FromSlash(rel)))),
		"a symlink to this process's stream is not the stream")
}

// A symlinked PARENT directory: `alias` -> `tracked-dir`. The product
// `alias/report.log` is the same inode as the tracked `tracked-dir/report.log`
// that this process writes its stream to, and git has no entry named
// `alias/report.log`. Asking git about the spelled path would prove a tracked
// file "untracked", so the proof must be about the real path.
func TestSymlinkedParentDirToTrackedStreamIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	writeFiles(t, dir, map[string]string{"tracked-dir/report.log": "token=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "tracked-dir/report.log")
	gitRun(t, dir, "commit", "-q", "-m", "track the report")
	require.NoError(t, os.Symlink("tracked-dir", filepath.Join(dir, "alias")))

	// Neither the diff nor the tree walk descends a symlinked directory today,
	// so this pins the skip decision itself, which any route would consult.
	scan := New()
	scan.ownStreams = func() []*os.File { return []*os.File{openAppend(t, filepath.Join(dir, "tracked-dir", "report.log"))} }
	ctx, err := attestation.NewContext("test", nil, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.False(t, scan.skipAsOwnOutput(ctx, "alias/report.log", filepath.Join(dir, "alias", "report.log"), openedInfo(t, filepath.Join(dir, "alias", "report.log"))),
		"a tracked file reached through a symlinked directory must not be skipped")
	require.False(t, scan.skipAsOwnOutput(ctx, "tracked-dir/report.log", filepath.Join(dir, "tracked-dir", "report.log"), openedInfo(t, filepath.Join(dir, "tracked-dir", "report.log"))),
		"the tracked file under its own name is not skipped either")
}

// The route that does follow the parent link: a recorded product named
// alias/report.log is read through it, and the own-stream skip is consulted.
func TestSymlinkedParentDirProductToTrackedStreamIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	writeFiles(t, dir, map[string]string{"tracked-dir/report.log": "token=" + scopePAT + "\n"})
	gitRun(t, dir, "add", "tracked-dir/report.log")
	gitRun(t, dir, "commit", "-q", "-m", "track the report")
	require.NoError(t, os.Symlink("tracked-dir", filepath.Join(dir, "alias")))

	rel := "alias/report.log"
	scan := scanProductWithStream(t, dir, rel, openAppend(t, filepath.Join(dir, "tracked-dir", "report.log")), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, rel), "a tracked file recorded through a symlinked directory was skipped; findings=%v", findingLocations(scan))
}

// Content that merely LOOKS like cilock's own log, at the path an agent would
// use for it, is not skipped when it is not this process's stream.
func TestLogLookingFileThatIsNotOwnStreamIsStillScanned(t *testing.T) {
	dir, base := diffRepo(t)
	rel := ".pushgate/run-1/evidence-secrets.stderr"
	writeFiles(t, dir, map[string]string{rel: "level=info msg=\"Starting secretscan attestor...\"\ntoken=" + scopePAT + "\n"})
	other, err := os.CreateTemp(t.TempDir(), "stderr")
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })

	scan := scanDiffWithStream(t, dir, base, other)
	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
}

// The threat-model baseline this skip is measured against. Whoever can write
// an untracked file in the working tree can already keep a diff scope from
// reading it by listing it in .git/info/exclude, which no commit carries. So a
// skip limited to untracked files grants that writer nothing new: what keeps a
// secret out of a push is that committed and staged blobs are always read,
// and the own-output skip never sees them. If this ever stops holding (a diff
// scope starts reading ignored files), the untracked-only argument in
// own_output.go must be re-derived.
func TestDiffScopeAlreadySkipsAnIgnoredUntrackedFile(t *testing.T) {
	dir, base := diffRepo(t)
	writeFiles(t, dir, map[string]string{
		"hidden.env":  "SECRET=" + scopePAT + "\n",
		"visible.env": "SECRET=" + scopePAT + "\n",
	})
	exclude := filepath.Join(dir, ".git", "info", "exclude")
	require.NoError(t, os.MkdirAll(filepath.Dir(exclude), 0o750))
	require.NoError(t, os.WriteFile(exclude, []byte("hidden.env\n"), 0o600))

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, "visible.env"), "the fixture must be found when not ignored; findings=%v", findingLocations(scan))
	require.False(t, hasFindingAt(scan, "hidden.env"), "findings=%v", findingLocations(scan))
}

// A file with the stream's base name in another directory is a different
// file: identity is the inode, never the name.
func TestSameNameInAnotherDirectoryIsStillScanned(t *testing.T) {
	dir, base := diffRepo(t)
	streamRel := "logs/run.log"
	rel := "dist/run.log"
	writeFiles(t, dir, map[string]string{streamRel: "cilock log\n", rel: "token=" + scopePAT + "\n"})
	scan := scanDiffWithStream(t, dir, base, openAppend(t, filepath.Join(dir, filepath.FromSlash(streamRel))))
	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
}

// scanTreeWithStream runs a tree-scope scan (the working-tree walk) with
// `stream` standing in for this process's stdout/stderr and no products.
func scanTreeWithStream(t *testing.T, dir string, stream *os.File) *Attestor {
	t.Helper()
	scan := New(WithScope("tree"), WithScanAttestations(false))
	scan.ownStreams = func() []*os.File { return []*os.File{stream} }
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return scan
}

// scanDiffWithStream runs a diff-scope scan (the working-tree walk lists
// untracked files) with `stream` standing in for this process's stream.
func scanDiffWithStream(t *testing.T, dir, base string, stream *os.File) *Attestor {
	t.Helper()
	scan := New(WithScope("diff:"+base), WithScanAttestations(false))
	scan.ownStreams = func() []*os.File { return []*os.File{stream} }
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return scan
}

// nestedRepo makes dir/sub its own repository with report.log committed in it.
func nestedRepo(t *testing.T, dir string) string {
	t.Helper()
	sub := filepath.Join(dir, "sub")
	require.NoError(t, os.MkdirAll(sub, 0o750))
	gitRun(t, sub, "init", "-q", "-b", "main", ".")
	writeFiles(t, sub, map[string]string{"report.log": "token=" + scopePAT + "\n"})
	gitRun(t, sub, "add", "report.log")
	gitRun(t, sub, "commit", "-q", "-m", "sub")
	return sub
}

// openedInfo is the identity a read of path would see: the file an open of
// path reaches, symlinks followed, as readFileContentInfo returns it.
func openedInfo(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	return info
}

func openAppend(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test fixture path
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// A file inside a submodule is tracked by the submodule, while the parent's
// index and HEAD list only the gitlink `sub`. An exact-path lookup in the
// parent would call sub/report.log untracked; the proof must fail closed for
// any path at or under a gitlink.
func TestOwnStreamInsideASubmoduleIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	sub := nestedRepo(t, dir)
	gitRun(t, dir, "add", "sub")
	gitRun(t, dir, "commit", "-q", "-m", "add submodule gitlink")

	scan := scanTreeWithStream(t, dir, openAppend(t, filepath.Join(sub, "report.log")))
	require.True(t, hasFindingAt(scan, "sub/report.log"), "a submodule's tracked file was skipped; findings=%v", findingLocations(scan))
}

// A nested repository that is not a submodule owns its own files: the parent
// repository's index says nothing about them either way, so nothing about
// them can be proven untracked by it.
func TestOwnStreamInsideANestedRepositoryIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	sub := nestedRepo(t, dir)

	scan := scanTreeWithStream(t, dir, openAppend(t, filepath.Join(sub, "report.log")))
	require.True(t, hasFindingAt(scan, "sub/report.log"), "a nested repository's file was skipped; findings=%v", findingLocations(scan))
}
