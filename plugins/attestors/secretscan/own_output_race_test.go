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

// Codex round 3 on #10174: the skip decision must be about the file the
// scanned bytes came from. A concurrent writer that renames this process's
// stream over an untracked, secret-bearing file AFTER its bytes were read
// used to make a fresh Lstat of the path answer "own stream", and the secret
// already in the buffer was dropped. These tests perform that swap between
// the read and the decision, on both routes that read a file off disk.

// swapInStreamAfterRead renames stream over the file at victim the moment
// victim's bytes have been read.
func swapInStreamAfterRead(t *testing.T, scan *Attestor, victim, stream string) {
	t.Helper()
	scan.afterRead = func(absPath string) {
		if absPath != victim {
			return
		}
		require.NoError(t, os.Rename(stream, victim))
	}
}

// outsideStream is a stream file outside the repository, so no scan route
// reads it in its own right, opened for append the way a redirect holds it.
func outsideStream(t *testing.T) (path string, f *os.File) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "stderr.log")
	require.NoError(t, os.WriteFile(path, []byte("cilock log line\n"), 0o600))
	return path, openAppend(t, path)
}

func TestStreamSwappedInAfterAProductIsReadDoesNotDropItsSecret(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := "out/secret.log"
	writeFiles(t, dir, map[string]string{rel: "token=" + scopePAT + "\n"})
	victim := filepath.Join(dir, filepath.FromSlash(rel))
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	recorded, err := cryptoutil.CalculateDigestSetFromFile(victim, hashes)
	require.NoError(t, err)

	streamPath, stream := outsideStream(t)
	scan := New()
	scan.ownStreams = func() []*os.File { return []*os.File{stream} }
	swapInStreamAfterRead(t, scan, victim, streamPath)
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{
			&fixedProducts{products: map[string]attestation.Product{rel: {MimeType: "text/plain", Digest: recorded}}},
			scan,
		},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.True(t, hasFindingAt(scan, rel), "the secret read before the swap was dropped; findings=%v", findingLocations(scan))
	require.Empty(t, scan.ownOutputSkips, "bytes that did not come from the stream were skipped as the stream")
}

func TestStreamSwappedInAfterAWorkingTreeFileIsReadDoesNotDropItsSecret(t *testing.T) {
	dir, base := diffRepo(t)
	rel := "out/secret.log"
	writeFiles(t, dir, map[string]string{rel: "token=" + scopePAT + "\n"})
	victim := filepath.Join(dir, filepath.FromSlash(rel))

	streamPath, stream := outsideStream(t)
	scan := New(WithScope("diff:"+base), WithScanAttestations(false))
	scan.ownStreams = func() []*os.File { return []*os.File{stream} }
	swapInStreamAfterRead(t, scan, victim, streamPath)
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	require.True(t, hasFindingAt(scan, rel), "the secret read before the swap was dropped; findings=%v", findingLocations(scan))
	require.Empty(t, scan.ownOutputSkips, "bytes that did not come from the stream were skipped as the stream")
}

// The other direction stays as it was: the stream itself, read and then
// left alone, is still skipped.
func TestStreamReadInPlaceIsStillSkipped(t *testing.T) {
	dir, base := diffRepo(t)
	rel := "out/stderr.log"
	writeFiles(t, dir, map[string]string{rel: "cilock log line\n"})
	scan := scanDiffWithStream(t, dir, base, openAppend(t, filepath.Join(dir, filepath.FromSlash(rel))))
	require.Len(t, scan.ownOutputSkips, 1)
	require.Equal(t, rel, scan.ownOutputSkips[0].Path)
}
