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

package product

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// TestFromCaptureEntries_NilDigestFallbackHashesSurvivingFile is the
// regression for the empty-product-tree bug observed on GHA's Azure 6.17
// kernel: the trace write-tap failed to produce a content digest (the rebuilt
// BPF object's write-tap didn't fire / ringbuf hash-failure silent drops), so
// every product entry had a nil digest and buildTree() dropped them all,
// shipping a signed attestation with ZERO products and no subject for the
// verify gate to anchor on.
//
// When the file is a surviving deliverable (exists-at-exit), the attestor must
// hash it directly at attest time rather than emit a digest-less entry.
func TestFromCaptureEntries_NilDigestFallbackHashesSurvivingFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.bin")
	content := []byte("deliverable-binary-content")
	require.NoError(t, os.WriteFile(p, content, 0o644))

	// Trace surfaced the path but captured NO content digest.
	entries := map[string]attestation.CaptureEntry{
		p: {Digest: nil, Source: "trace-write-only"},
	}

	out := fromCaptureEntries(entries, true)

	prod, ok := out[p]
	require.True(t, ok, "a surviving written file must be recorded as a product")
	require.NotNil(t, prod.Digest,
		"a nil-trace-digest product that still exists must be hashed at attest time, not dropped from the tree")

	sum := sha256.Sum256(content)
	got, ok := prod.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
	require.True(t, ok, "fallback must produce a sha256 digest")
	require.Equal(t, hex.EncodeToString(sum[:]), got, "fallback digest must match the file content")
}

// TestFromCaptureEntries_NilDigestGoneFileStillDropped confirms the fallback
// doesn't resurrect files that no longer exist: under requireExistsAtExit, a
// nil-digest entry whose path is gone is still dropped (it was scratch).
func TestFromCaptureEntries_NilDigestGoneFileStillDropped(t *testing.T) {
	entries := map[string]attestation.CaptureEntry{
		filepath.Join(t.TempDir(), "never-existed.bin"): {Digest: nil},
	}
	out := fromCaptureEntries(entries, true)
	require.Empty(t, out, "a nil-digest entry for a non-existent file must not be recorded under requireExistsAtExit")
}
