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

// The envelope skip is recognition by SHAPE, so it is confined to the one
// route where it grants nothing new: an untracked file a diff scope's
// working-tree walk discovered, which the operator could already keep out of
// that walk with .git/info/exclude. A recorded product is what the step
// publishes (untracked build artifacts are normal), and a tree scope reads
// the whole working tree on purpose, so on both an envelope is scanned like
// any other file, secret in its payload included.

// An untracked product whose envelope payload carries a secret is scanned.
func TestRecordedProductEnvelopeWithASecretInItsPayloadIsScanned(t *testing.T) {
	dir, base := diffRepo(t)
	rel := "dist/evidence.json"
	writeFiles(t, dir, map[string]string{rel: evidenceEnvelope(t, attestation.CollectionType, scopePAT)})
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	recorded, err := cryptoutil.CalculateDigestSetFromFile(filepath.Join(dir, filepath.FromSlash(rel)), hashes)
	require.NoError(t, err)

	for _, opts := range [][]Option{nil, {WithScope("diff:" + base), WithScanAttestations(false)}} {
		scan := New(opts...)
		ctx, err := attestation.NewContext("test",
			[]attestation.Attestor{
				&fixedProducts{products: map[string]attestation.Product{rel: {MimeType: "application/json", Digest: recorded}}},
				scan,
			},
			attestation.WithWorkingDir(dir),
			attestation.WithHashes(hashes))
		require.NoError(t, err)
		require.NoError(t, ctx.RunAttestors())
		require.True(t, hasFindingAt(scan, rel), "a recorded product's envelope payload was not scanned; findings=%v", findingLocations(scan))
		require.Contains(t, subjectKeys(scan), "product:"+rel)
	}
}

// A tree scope reads every file under the working directory; an untracked
// envelope there is scanned.
func TestTreeScopeScansAnUntrackedEnvelope(t *testing.T) {
	dir, _ := diffRepo(t)
	rel := "evidence.json"
	writeFiles(t, dir, map[string]string{rel: evidenceEnvelope(t, attestation.CollectionType, scopePAT)})

	scan := runScanOnly(t, dir, WithScope("tree"), WithScanAttestations(false))
	require.True(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
}

// Sibling of the own-stream symlinked-parent case: on the one route that may
// skip an envelope, a tracked envelope named through `alias` -> `tracked-dir`
// is not proven untracked. Neither walk descends a symlinked directory today,
// so this pins the decision itself.
func TestTrackedEnvelopeThroughASymlinkedDirectoryIsNotSkipped(t *testing.T) {
	dir, base := diffRepo(t)
	content := evidenceEnvelope(t, attestation.CollectionType, scopePAT)
	writeFiles(t, dir, map[string]string{"tracked-dir/evidence.json": content})
	gitRun(t, dir, "add", "tracked-dir/evidence.json")
	gitRun(t, dir, "commit", "-q", "-m", "commit evidence")
	require.NoError(t, os.Symlink("tracked-dir", filepath.Join(dir, "alias")))

	scan := New(WithScope("diff:" + base))
	ctx, err := attestation.NewContext("test", nil, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.False(t, scan.skipAsOwnOutput(ctx, routeWorkingTree, "alias/evidence.json", filepath.Join(dir, "alias", "evidence.json"), []byte(content), openedInfo(t, filepath.Join(dir, "alias", "evidence.json")), nil),
		"a tracked envelope reached through a symlinked directory must not be skipped")
	require.False(t, scan.skipAsOwnOutput(ctx, routeWorkingTree, "untracked.json", filepath.Join(dir, "untracked.json"), []byte(content), nil, nil),
		"a path that does not exist cannot be proven untracked by its real path")
}

// The one route the envelope skip keeps: a diff scope's walk, untracked.
func TestDiffWalkStillSkipsAnUntrackedEnvelope(t *testing.T) {
	dir, base := diffRepo(t)
	rel := "evidence.json"
	writeFiles(t, dir, map[string]string{rel: evidenceEnvelope(t, attestation.CollectionType, scopePAT)})

	scan := runScanOnly(t, dir, WithScope("diff:"+base), WithScanAttestations(false))
	require.False(t, hasFindingAt(scan, rel), "findings=%v", findingLocations(scan))
	require.NotContains(t, subjectKeys(scan), "file:"+rel)
}
