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
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// These tests pin which of cilock's OWN outputs a scan may skip, and, more
// importantly, which it may not. Measured friction (onbsim run
// mx-hugo-l6-muguxxn1): an agent redirected each step's stdout and stderr into
// the repository. The secrets step then read its own stderr, which it was
// still writing, and reported it as a product that changed between recording
// and scanning. The file was not in the push.
//
// The rule that keeps this from hiding a committed secret: a file is skipped
// only when git positively says it is untracked (in neither the index nor
// HEAD), and only when it is identified by what it IS (the inode this process
// writes its stdout or stderr to), never by its name. Committed and staged blobs are read from
// the object store and never pass through this filter at all.

// diffRepo is a repository with a base commit and one pushed change, so a
// diff scope against the returned base has something of its own to read.
func diffRepo(t *testing.T) (dir, base string) {
	t.Helper()
	requireGit(t)
	dir = t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main", ".")
	writeFiles(t, dir, map[string]string{"main.go": "package main\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	base = gitRun(t, dir, "rev-parse", "HEAD")
	writeFiles(t, dir, map[string]string{"main.go": "package main\n// change\n"})
	gitRun(t, dir, "commit", "-q", "-am", "change")
	return dir, base
}

func hasFindingAt(a *Attestor, rel string) bool {
	for _, f := range a.Findings {
		if strings.HasSuffix(f.Location, ":"+rel) {
			return true
		}
	}
	return false
}

// ownStreamRun records rel as a product with the digest of `early`, then
// appends `later` to it the way a process appends to its own log, and scans
// with rel standing in for this process's stderr.
func ownStreamRun(t *testing.T, dir, rel, early, later string, opts ...Option) *Attestor {
	t.Helper()
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	abs := filepath.Join(dir, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
	require.NoError(t, os.WriteFile(abs, []byte(early), 0o600))
	recorded, err := cryptoutil.CalculateDigestSetFromFile(abs, hashes)
	require.NoError(t, err)

	stream, err := os.OpenFile(abs, os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // test fixture path
	require.NoError(t, err)
	t.Cleanup(func() { _ = stream.Close() })
	_, err = stream.WriteString(later)
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

// The measured case: `cilock run ... 2> .pushgate/secrets.stderr`. The file is
// this process's own stderr, still being written when it is scanned, so it
// always "changed between recording and scanning". Untracked, it is skipped:
// no disagreement, no subject.
func TestOwnStderrRedirectedIntoTheRepoIsNotAChangedProduct(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := ".pushgate/run-1/evidence-secrets.stderr"
	scan := ownStreamRun(t, dir, rel, "level=info msg=\"Starting product attestors stage...\"\n",
		"level=info msg=\"Starting secretscan attestor...\"\n")

	require.Nil(t, scan.Scope, "no disagreement is recorded for this process's own output; scope=%+v", scan.Scope)
	require.NotContains(t, subjectKeys(scan), "product:"+rel)
}

// The same under a diff scope, where the file is also listed as untracked: it
// is read by neither route.
func TestOwnStderrIsNotScannedUnderDiffScopeEither(t *testing.T) {
	dir, base := diffRepo(t)
	rel := ".pushgate/run-1/evidence-secrets.stderr"
	scan := ownStreamRun(t, dir, rel, "early\n", "later\n", WithScope("diff:"+base), WithScanAttestations(false))

	require.NotNil(t, scan.Scope)
	require.Empty(t, scan.Scope.ProductDigestMismatches)
	require.NotContains(t, subjectKeys(scan), "product:"+rel)
	require.NotContains(t, subjectKeys(scan), "file:"+rel)
}

// A tracked file is never skipped, even when it is this process's own
// stream: a committed secret still on disk is found, and the disagreement is
// still recorded.
func TestOwnStreamThatGitTracksIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := "build.log"
	writeFiles(t, dir, map[string]string{rel: "committed\n"})
	gitRun(t, dir, "add", rel)
	gitRun(t, dir, "commit", "-q", "-m", "track the log")

	scan := ownStreamRun(t, dir, rel, "token="+scopePAT+"\n", "more\n")

	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
	require.NotNil(t, scan.Scope)
	require.Len(t, scan.Scope.ProductDigestMismatches, 1)
	require.Equal(t, rel, scan.Scope.ProductDigestMismatches[0].Path)
}

// A staged file is what the next commit carries, so it is tracked: even as
// this process's own stream, its secret is found.
func TestOwnStreamThatIsStagedIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := "staged.log"
	writeFiles(t, dir, map[string]string{rel: "staged\n"})
	gitRun(t, dir, "add", rel)

	scan := ownStreamRun(t, dir, rel, "token="+scopePAT+"\n", "more\n")

	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
}

// Outside a git repository nothing can be proven untracked, so nothing is
// skipped: the scan fails toward reading.
func TestOwnStreamOutsideAGitRepositoryIsStillScanned(t *testing.T) {
	dir := t.TempDir()
	rel := "run.log"
	scan := ownStreamRun(t, dir, rel, "token="+scopePAT+"\n", "more\n")

	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
	require.NotNil(t, scan.Scope)
	require.Len(t, scan.Scope.ProductDigestMismatches, 1)
}

// A file that is NOT this process's stream is not skipped for being
// untracked: an untracked product carrying a secret is found.
func TestUntrackedProductThatIsNotOwnOutputIsStillScanned(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := "dist/config.env"
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	writeFiles(t, dir, map[string]string{rel: "SECRET=" + scopePAT + "\n"})
	recorded, err := cryptoutil.CalculateDigestSetFromFile(filepath.Join(dir, rel), hashes)
	require.NoError(t, err)

	other, err := os.CreateTemp(t.TempDir(), "stderr")
	require.NoError(t, err)
	t.Cleanup(func() { _ = other.Close() })

	scan := New()
	scan.ownStreams = func() []*os.File { return []*os.File{other} }
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{rel: {MimeType: "text/plain", Digest: recorded}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
}
