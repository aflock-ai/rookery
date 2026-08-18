// Copyright 2022 The Witness Contributors
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

package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests pin the behaviour the nightly factory-image scan depends on.
// `cilock run -a oci` measures a `crane pull` tarball of every factory image;
// real base images routinely carry layers far larger than maxTarEntrySize and
// manifests that name one physical blob more than once. Both used to abort the
// whole oci attestor, which cost the image its signed envelope.

// sha256Only mirrors what `cilock run` actually passes: --hashes defaults to
// "sha256" and cilock builds every DigestValue with GitOID:false
// (cilock/internal/options/run.go, cilock/cli/run.go).
func sha256Only() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}

// patternReader emits n bytes of a repeating 0..255 ramp without ever holding
// them in memory — large layer fixtures must not be materialised as a slice.
type patternReader struct {
	remaining int64
	next      byte
}

func newPattern(n int64) io.Reader { return &patternReader{remaining: n} }

func (p *patternReader) Read(b []byte) (int, error) {
	if p.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(b)
	if int64(n) > p.remaining {
		n = int(p.remaining)
	}
	for i := 0; i < n; i++ {
		b[i] = p.next
		p.next++
	}
	p.remaining -= int64(n)
	return n, nil
}

type streamEntry struct {
	name string
	size int64
	body func() io.Reader
}

func bytesEntry(name string, content []byte) streamEntry {
	return streamEntry{name: name, size: int64(len(content)), body: func() io.Reader { return bytes.NewReader(content) }}
}

// buildStreamedTar writes a tar to disk without buffering entry bodies.
func buildStreamedTar(t *testing.T, entries ...streamEntry) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "image.tar")
	f, err := os.Create(p)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	tw := tar.NewWriter(f)
	for _, e := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0600, Size: e.size}))
		n, err := io.Copy(tw, e.body())
		require.NoError(t, err)
		require.Equal(t, e.size, n, "entry %q short write", e.name)
	}
	require.NoError(t, tw.Close())
	return p
}

// hashesWithGitOID mirrors the AttestationContext default, which does include
// the buffering gitoid hashers. Named distinctly from the audit-tagged
// defaultHashes() so both files can compile together under `-tags audit`.
func hashesWithGitOID() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA256, GitOID: true},
		{Hash: crypto.SHA1, GitOID: true},
	}
}

// gitoidOnlyHashes is a hash set with NOTHING a layer can be streamed through:
// every value buffers the whole payload. Reachable through
// attestation.WithHashes, which any library consumer of this attestor may call.
func gitoidOnlyHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{
		{Hash: crypto.SHA256, GitOID: true},
		{Hash: crypto.SHA1, GitOID: true},
	}
}

// layerTestProducer registers the tar as a product so a context can be built.
type layerTestProducer struct {
	path   string
	digest cryptoutil.DigestSet
}

func (p *layerTestProducer) Name() string                                   { return "layer-test-producer" }
func (p *layerTestProducer) Type() string                                   { return "layer-test" }
func (p *layerTestProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (p *layerTestProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (p *layerTestProducer) Schema() *jsonschema.Schema                     { return nil }
func (p *layerTestProducer) Products() map[string]attestation.Product {
	return map[string]attestation.Product{p.path: {MimeType: "application/x-tar", Digest: p.digest}}
}

// ctxWithHashes builds a context whose only job is to carry a hash set into
// getLayerDIFFIDs. The product digest is computed with sha256 only so a large
// fixture is never buffered by the test harness itself.
func ctxWithHashes(t *testing.T, tarPath string, hashes []cryptoutil.DigestValue) *attestation.AttestationContext {
	t.Helper()
	ds, err := cryptoutil.CalculateDigestSetFromFile(tarPath, sha256Only())
	require.NoError(t, err)
	prod := &layerTestProducer{path: tarPath, digest: ds}

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{prod},
		attestation.WithWorkingDir(filepath.Dir(tarPath)),
		attestation.WithHashes(hashes),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return ctx
}

// ctxWithMatchingProductDigest is ctxWithHashes for the cases where the product
// digest must be computed with the SAME hash set the context carries.
//
// ctxWithHashes deliberately uses sha256 only so a multi-hundred-megabyte
// fixture is never buffered by a gitoid hasher inside the harness. A gitoid-only
// context needs agreement, though: DigestSet.Equal requires the strongest
// algorithm to be present on both sides, so a sha256-only product digest against
// a gitoid-only recomputation fails getCandidate on integrity grounds long
// before the layer walk is reached — which would make an end-to-end test pass
// for entirely the wrong reason.
func ctxWithMatchingProductDigest(t *testing.T, tarPath string, hashes []cryptoutil.DigestValue) *attestation.AttestationContext {
	t.Helper()
	ds, err := cryptoutil.CalculateDigestSetFromFile(tarPath, hashes)
	require.NoError(t, err)
	prod := &layerTestProducer{path: tarPath, digest: ds}

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{prod},
		attestation.WithWorkingDir(filepath.Dir(tarPath)),
		attestation.WithHashes(hashes),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return ctx
}

func sha256Of(t *testing.T, r io.Reader) string {
	t.Helper()
	ds, err := cryptoutil.CalculateDigestSet(r, sha256Only())
	require.NoError(t, err)
	return ds[cryptoutil.DigestValue{Hash: crypto.SHA256}]
}

func manifestJSON(t *testing.T, layers []string) []byte {
	t.Helper()
	b, err := json.Marshal([]Manifest{{Config: "config.json", RepoTags: []string{"test:latest"}, Layers: layers}})
	require.NoError(t, err)
	return b
}

// A manifest may name the same physical blob twice: identical layers are
// stored once in the tar and referenced by every position that uses them.
// The old nested loop re-read the already-consumed tar entry and got io.EOF,
// which is the `failed to read layer: EOF` that cost judge-flagger-loadtester
// its envelope on run 32091624366.
func TestGetLayerDIFFIDs_DuplicateLayerReference(t *testing.T) {
	shared := []byte("shared layer bytes")
	other := []byte("second layer bytes")

	layers := []string{"a.tar", "b.tar", "a.tar"}
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, layers)),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("a.tar", shared),
		bytesEntry("b.tar", other),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: layers}

	got, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.NoError(t, err)
	require.Len(t, got, 3, "one diffID per manifest layer slot, duplicates included")

	key := cryptoutil.DigestValue{Hash: crypto.SHA256}
	assert.Equal(t, sha256Of(t, bytes.NewReader(shared)), got[0][key])
	assert.Equal(t, sha256Of(t, bytes.NewReader(other)), got[1][key])
	assert.Equal(t, got[0][key], got[2][key], "the repeated blob must yield the same diffID")
}

// diffIDs are positional: layerdiffid00 must be the manifest's first layer.
// Tar entry order is an artefact of how the archive was written and does not
// have to match the manifest.
func TestGetLayerDIFFIDs_OrderFollowsManifestNotTar(t *testing.T) {
	first := []byte("first")
	second := []byte("second")

	layers := []string{"first.tar", "second.tar"}
	// Deliberately write the layers to the tar in reverse order.
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, layers)),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("second.tar", second),
		bytesEntry("first.tar", first),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: layers}

	got, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.NoError(t, err)
	require.Len(t, got, 2)

	key := cryptoutil.DigestValue{Hash: crypto.SHA256}
	assert.Equal(t, sha256Of(t, bytes.NewReader(first)), got[0][key], "diffID 0 must be the manifest's first layer")
	assert.Equal(t, sha256Of(t, bytes.NewReader(second)), got[1][key])
}

// An uncompressed layer bigger than maxTarEntrySize. This is the
// `layer entry has invalid size: 829440509` failure from judge-scanner-infra.
func TestGetLayerDIFFIDs_UncompressedLayerOverMaxTarEntrySize(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a >256MiB tar on disk")
	}
	const size = int64(maxTarEntrySize) + 4096

	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, []string{"big.tar"})),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		streamEntry{name: "big.tar", size: size, body: func() io.Reader { return newPattern(size) }},
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: []string{"big.tar"}}

	got, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.NoError(t, err, "a layer larger than maxTarEntrySize must still be measured")
	require.Len(t, got, 1)
	assert.Equal(t, sha256Of(t, newPattern(size)), got[0][cryptoutil.DigestValue{Hash: crypto.SHA256}])
}

// A gzipped layer that is small on the wire but decompresses past
// maxTarEntrySize — the `decompressed layer exceeds maximum size of
// 268435456 bytes` failure that hit 8 of the 12 degraded images.
func TestGetLayerDIFFIDs_GzipLayerDecompressingOverMaxTarEntrySize(t *testing.T) {
	if testing.Short() {
		t.Skip("decompresses >256MiB")
	}
	const size = int64(maxTarEntrySize) + 4096

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, err := io.Copy(zw, newPattern(size))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	compressed := gzBuf.Bytes()
	require.Less(t, int64(len(compressed)), int64(maxTarEntrySize), "fixture must pass the compressed-entry check")

	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, []string{"big.tar.gz"})),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("big.tar.gz", compressed),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: []string{"big.tar.gz"}}

	got, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.NoError(t, err, "a layer decompressing past maxTarEntrySize must still be measured")
	require.Len(t, got, 1)
	// The diffID is the digest of the DECOMPRESSED layer.
	assert.Equal(t, sha256Of(t, newPattern(size)), got[0][cryptoutil.DigestValue{Hash: crypto.SHA256}])
}

// Removing the 256MiB ceiling must not remove bomb protection: a stream that
// runs past the decompressed ceiling still fails loudly rather than running
// until the box dies.
func TestGetLayerDIFFIDs_DecompressionBombStillRejected(t *testing.T) {
	original := maxDecompressedLayerSize
	maxDecompressedLayerSize = 1 << 20 // 1 MiB
	t.Cleanup(func() { maxDecompressedLayerSize = original })

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, err := io.Copy(zw, newPattern(maxDecompressedLayerSize+1))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, []string{"bomb.tar.gz"})),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("bomb.tar.gz", gzBuf.Bytes()),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: []string{"bomb.tar.gz"}}

	_, err = m.getLayerDIFFIDs(ctx, tarPath)
	require.Error(t, err, "a layer past the decompressed ceiling must be rejected, not truncated")
	assert.Contains(t, err.Error(), "exceeds maximum size")
}

// Streaming is only constant-memory while no hasher buffers. gitoid hashers
// accumulate the whole payload (attestation/cryptoutil/gitoid.go), so a layer
// diffID is measured with the non-gitoid hashes only. cilock is unaffected: it
// already passes sha256 with GitOID:false.
func TestGetLayerDIFFIDs_ExcludesBufferingGitOIDHashes(t *testing.T) {
	layer := []byte("layer bytes")
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, []string{"a.tar"})),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("a.tar", layer),
	)

	ctx := ctxWithHashes(t, tarPath, hashesWithGitOID()) // includes two gitoid values
	m := Manifest{Config: "config.json", Layers: []string{"a.tar"}}

	got, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.NoError(t, err)
	require.Len(t, got, 1)

	for dv := range got[0] {
		assert.False(t, dv.GitOID, "layer diffIDs must not carry a buffering gitoid hash")
	}
	// The plain sha256 the OCI spec defines as the diffID is still present and
	// byte-identical to the buffered implementation it replaces.
	want, err := cryptoutil.CalculateDigestSetFromBytes(layer, sha256Only())
	require.NoError(t, err)
	assert.Equal(t, want[cryptoutil.DigestValue{Hash: crypto.SHA256}], got[0][cryptoutil.DigestValue{Hash: crypto.SHA256}])
}

// End-to-end: the whole attestor, not just the layer walk, over an image
// whose layer is bigger than maxTarEntrySize. This is the shape the nightly
// factory scan feeds it — `crane pull` tar, sha256-only hashes — and the
// subjects it must come back with are exactly the ones the signed envelope
// carries: manifest digest, image ID, tag and a diffID per layer.
func TestAttest_OversizedLayerImageStillProducesSubjects(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a >256MiB tar on disk")
	}
	const size = int64(maxTarEntrySize) + 4096

	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, []string{"big.tar"})),
		bytesEntry("config.json", config),
		streamEntry{name: "big.tar", size: size, body: func() io.Reader { return newPattern(size) }},
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	a := New()
	require.NoError(t, a.Attest(ctx), "an image with an oversized layer must still attest")

	subjects := a.Subjects()
	key := cryptoutil.DigestValue{Hash: crypto.SHA256}

	require.Len(t, a.LayerDiffIDs, 1)
	assert.Equal(t, sha256Of(t, newPattern(size)), a.LayerDiffIDs[0][key])

	var haveManifest, haveImageID, haveTag, haveDiffID bool
	for k := range subjects {
		switch {
		case len(k) > 15 && k[:15] == "manifestdigest:":
			haveManifest = true
		case len(k) > 8 && k[:8] == "imageid:":
			haveImageID = true
		case len(k) > 9 && k[:9] == "imagetag:":
			haveTag = true
		case len(k) > 13 && k[:13] == "layerdiffid00":
			haveDiffID = true
		}
	}
	assert.True(t, haveManifest, "subjects: %v", subjects)
	assert.True(t, haveImageID, "subjects: %v", subjects)
	assert.True(t, haveTag, "subjects: %v", subjects)
	assert.True(t, haveDiffID, "subjects: %v", subjects)
}

// gzipOf returns the gzip of n bytes of a pattern starting at `seed`, so
// sibling fixtures are byte-distinct without ever being held uncompressed.
func gzipOf(t *testing.T, n int64, seed byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := io.Copy(zw, &patternReader{remaining: n, next: seed})
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// bombImage builds an image whose layers are each `perLayer` decompressed bytes.
func bombImage(t *testing.T, count int, perLayer int64) (string, []string) {
	t.Helper()
	names := make([]string, 0, count)
	entries := []streamEntry{{}, {}} // placeholders for manifest + config
	for i := 0; i < count; i++ {
		name := fmt.Sprintf("bomb%02d.tar.gz", i)
		names = append(names, name)
		entries = append(entries, bytesEntry(name, gzipOf(t, perLayer, byte(i))))
	}
	entries[0] = bytesEntry("manifest.json", manifestJSON(t, names))
	entries[1] = bytesEntry("config.json", []byte(`{"architecture":"amd64"}`))
	return buildStreamedTar(t, entries...), names
}

// The per-layer ceiling is correct in isolation and bounds nothing in
// aggregate. Every layer here is comfortably UNDER it — proven by the
// single-layer and under-budget cases below, which succeed — yet together they
// decompress past what the attestor is willing to spend on one image. Before
// the cumulative budget existed, a manifest could buy N times the allowance
// simply by naming N layers, so a compact tar of many small bombs forced
// unbounded decompression and hashing with no single layer ever crossing a
// limit.
func TestGetLayerDIFFIDs_CumulativeBudgetAcrossLayers(t *testing.T) {
	originalLayer, originalImage := maxDecompressedLayerSize, maxDecompressedImageSize
	maxDecompressedLayerSize = 1 << 20 // 1 MiB per layer
	maxDecompressedImageSize = 2 << 20 // 2 MiB for the whole image
	t.Cleanup(func() {
		maxDecompressedLayerSize = originalLayer
		maxDecompressedImageSize = originalImage
	})

	// Under the per-layer ceiling, so no layer is individually rejectable.
	const perLayer = int64(768 << 10) // 0.75 MiB
	require.Less(t, perLayer, maxDecompressedLayerSize, "fixture must clear the per-layer ceiling")

	t.Run("one layer under both ceilings is measured", func(t *testing.T) {
		tarPath, names := bombImage(t, 1, perLayer)
		ctx := ctxWithHashes(t, tarPath, sha256Only())
		m := Manifest{Config: "config.json", Layers: names}

		got, err := m.getLayerDIFFIDs(ctx, tarPath)
		require.NoError(t, err)
		require.Len(t, got, 1)
	})

	t.Run("two layers still inside the image budget are measured", func(t *testing.T) {
		// 2 x 0.75 MiB = 1.5 MiB, under the 2 MiB image budget. This is the
		// control: the budget must reject an over-budget image, not every
		// multi-layer one.
		tarPath, names := bombImage(t, 2, perLayer)
		require.Less(t, 2*perLayer, maxDecompressedImageSize)

		ctx := ctxWithHashes(t, tarPath, sha256Only())
		m := Manifest{Config: "config.json", Layers: names}

		got, err := m.getLayerDIFFIDs(ctx, tarPath)
		require.NoError(t, err)
		require.Len(t, got, 2)
	})

	t.Run("four layers, each legal, together over the image budget", func(t *testing.T) {
		// 4 x 0.75 MiB = 3 MiB against a 2 MiB budget.
		tarPath, names := bombImage(t, 4, perLayer)
		require.Greater(t, 4*perLayer, maxDecompressedImageSize)

		ctx := ctxWithHashes(t, tarPath, sha256Only())
		m := Manifest{Config: "config.json", Layers: names}

		got, err := m.getLayerDIFFIDs(ctx, tarPath)
		require.Error(t, err, "layers that are individually legal must still be bounded in aggregate")
		assert.Contains(t, err.Error(), "cumulative maximum",
			"the refusal must name the IMAGE-wide budget, not a per-layer overrun")
		assert.Nil(t, got, "a refused image must yield no diffIDs at all")
	})
}

// The whole attestor, not just the layer walk: an image over the cumulative
// budget must not produce a signed envelope carrying a partial layer set.
func TestAttest_CumulativeBudgetFailsTheWholeAttestation(t *testing.T) {
	originalLayer, originalImage := maxDecompressedLayerSize, maxDecompressedImageSize
	maxDecompressedLayerSize = 1 << 20
	maxDecompressedImageSize = 2 << 20
	t.Cleanup(func() {
		maxDecompressedLayerSize = originalLayer
		maxDecompressedImageSize = originalImage
	})

	tarPath, _ := bombImage(t, 4, int64(768<<10))
	ctx := ctxWithHashes(t, tarPath, sha256Only())

	a := New()
	err := a.Attest(ctx)
	require.Error(t, err, "an over-budget image must fail the attestation, not attest partially")
	assert.Contains(t, err.Error(), "cumulative maximum")
	assert.Empty(t, a.LayerDiffIDs, "no layer may be recorded from a refused image")
}

// A manifest naming more layer positions than any real image has is rejected
// before anything is sized from that count. wanted, byName and the emitted
// diffID slice are all allocated from len(m.Layers), which manifest.json
// supplies — the same per-item-versus-aggregate shape as the byte ceilings,
// applied to allocations.
func TestGetLayerDIFFIDs_LayerCountIsBounded(t *testing.T) {
	layers := make([]string, maxLayerCount+1)
	for i := range layers {
		layers[i] = fmt.Sprintf("l%04d.tar", i)
	}

	// The tar itself stays tiny: the point is that the COUNT is refused before
	// the archive is even opened, so no fixture has to carry the layers.
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, layers)),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: layers}

	got, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "above the maximum")
	assert.Nil(t, got)

	// And the bound is not so tight that a plausible image trips it.
	t.Run("a layer count real images actually reach is accepted", func(t *testing.T) {
		entries := []streamEntry{
			bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		}
		names := make([]string, 0, 128)
		for i := 0; i < 128; i++ {
			name := fmt.Sprintf("real%03d.tar", i)
			names = append(names, name)
			entries = append(entries, bytesEntry(name, []byte(name)))
		}
		entries = append([]streamEntry{bytesEntry("manifest.json", manifestJSON(t, names))}, entries...)
		p := buildStreamedTar(t, entries...)

		c := ctxWithHashes(t, p, sha256Only())
		mm := Manifest{Config: "config.json", Layers: names}
		got, err := mm.getLayerDIFFIDs(c, p)
		require.NoError(t, err)
		assert.Len(t, got, 128)
	})
}

// A context whose every requested hash buffers leaves NOTHING to measure a
// layer with. That must be a loud refusal, because the alternative is the worst
// outcome this attestor has: a successful, signed attestation whose layer
// subjects assert a measurement that was never taken.
func TestGetLayerDIFFIDs_NoStreamableHashFailsClosed(t *testing.T) {
	layer := []byte("layer bytes")
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, []string{"a.tar"})),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("a.tar", layer),
	)

	ctx := ctxWithHashes(t, tarPath, gitoidOnlyHashes())

	// The precise defect, pinned at its source: the streamable set is empty,
	// and that emptiness is what the refusal is about.
	streamable, err := layerHashes(ctx)
	require.ErrorIs(t, err, errNoStreamableLayerHash)
	assert.Empty(t, streamable)

	// Why an empty set cannot simply be passed through: CalculateDigestSet does
	// NOT error on one. It drains the reader and hands back an empty DigestSet,
	// which is exactly the unmeasured-but-recorded diffID being refused here.
	// If this ever starts returning an error of its own, the guard above is
	// still the right place for the refusal — but this assertion is what makes
	// "fail closed" load-bearing rather than belt-and-braces.
	unmeasured, err := cryptoutil.CalculateDigestSet(bytes.NewReader(layer), nil)
	require.NoError(t, err, "an empty hash set is not an error to cryptoutil")
	require.Empty(t, unmeasured, "...it yields a digest set with no digest in it")

	m := Manifest{Config: "config.json", Layers: []string{"a.tar"}}
	got, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.ErrorIs(t, err, errNoStreamableLayerHash,
		"must refuse for the no-streamable-hash reason specifically, not some incidental failure")
	assert.Nil(t, got, "an unmeasurable layer must not come back as a digest set")
}

// End-to-end fail-closed: the attestor refuses rather than emitting a
// "layerdiffidNN:" subject with no digest behind it. Asserting on the sentinel
// matters here — a gitoid-only context can also fail getCandidate on digest-set
// equality, and a test that only checked "Attest errored" would pass on that
// unrelated path while the unmeasured-subject hole stayed open.
func TestAttest_NoStreamableHashProducesNoUnmeasuredSubject(t *testing.T) {
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, []string{"a.tar"})),
		bytesEntry("config.json", []byte(`{"architecture":"amd64","os":"linux"}`)),
		bytesEntry("a.tar", []byte("layer bytes")),
	)

	ctx := ctxWithMatchingProductDigest(t, tarPath, gitoidOnlyHashes())

	a := New()
	err := a.Attest(ctx)
	require.ErrorIs(t, err, errNoStreamableLayerHash,
		"the attestation must fail on the unmeasurable layer, not on an incidental earlier check")

	assert.Empty(t, a.LayerDiffIDs)
	for k, ds := range a.Subjects() {
		assert.NotContains(t, k, "layerdiffid",
			"a refused run must publish no layer subject; got %q -> %v", k, ds)
	}
}

// A manifest naming a layer the tar does not contain is corrupt evidence and
// must fail loudly, not silently yield a short diffID list.
func TestGetLayerDIFFIDs_MissingLayerIsLoud(t *testing.T) {
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, []string{"present.tar", "absent.tar"})),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("present.tar", []byte("here")),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: []string{"present.tar", "absent.tar"}}

	_, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "absent.tar")
}

// ── The decompression ceilings, and the evidence they are set from ──────────
//
// Survey taken 2026-08-18 with `crane manifest --platform linux/amd64` plus
// `crane blob <repo>@<layer-digest> | gzip -dc | wc -c` — i.e. the same
// decompressed bytes maxDecompressedLayerSize and maxDecompressedImageSize
// bound — against the registries the judge factory actually mirrors from:
//
//	image                                                 layers  decompressed  largest layer
//	envoyproxy/gateway:v1.8.2                                 16       240 MiB        224 MiB
//	grafana/grafana:11.6.0                                    10       640 MiB        347 MiB
//	grafana/alloy:v1.18.0                                      7       554 MiB        450 MiB
//	library/golang:1.26                                        7       859 MiB        267 MiB
//	summerwind/actions-runner-dind:v2.335.1-ubuntu-24.04      15      1.32 GiB        654 MiB  <- fattest FACTORY image
//	nvidia/cuda:12.6.3-cudnn-devel-ubuntu24.04                12      7.67 GiB       4.63 GiB
//	pytorch/pytorch:2.6.0-cuda12.4-cudnn9-devel               15     12.38 GiB       5.59 GiB  <- fattest ANYWHERE
//
// The bottom two are not factory images. They are the fattest class of image
// anyone legitimately ships, and this attestor is a general-purpose library that
// cilock users point at their own images, so the ceilings have to clear them too
// — refusing one costs it its signed envelope, which is the exact regression
// this file exists to prevent.
//
// Largest observed layer COUNT across the whole survey was 18
// (cloudflare/cloudflared:2026.7.3), against maxLayerCount = 512.
const (
	largestMeasuredLayerSize  = int64(6005932032)  // pytorch cuda devel, single layer
	largestMeasuredImageSize  = int64(13291800576) // pytorch cuda devel, all 15 layers
	largestMeasuredLayerCount = 18                 // cloudflare/cloudflared:2026.7.3
)

// A ceiling is only defensible between two bounds, and BOTH halves are
// load-bearing:
//
//   - Too low and a legitimate image loses its envelope. That is not
//     hypothetical: the 256 MiB maxTarEntrySize did exactly that to 12 factory
//     images every night, which is why this work exists.
//   - Too high and it stops being a control. A tenant-controlled gzip is compact
//     — 2 GiB of maximally compressible input packs into 8.3 MB — so the ceiling,
//     not the upload, is what bounds the decompression and hashing an attacker
//     can force. Measured on an M-series core, gzip feeding SHA-256 runs at
//     1874 MiB/s over that input: the old 64 GiB budget bought ~35s of a core for
//     a ~10 MB push, where 24 GiB buys ~13s — roughly twice what legitimately
//     scanning the largest real image above already costs, and less than the time
//     its tarball spends being pulled.
//
// So this asserts the ceilings BRACKET the measured maximum rather than merely
// exceeding it. Raising them back toward 32/64 GiB fails the upper bound and has
// to argue with the survey above instead of with an intuition.
func TestCeilings_AdmitLargestRealImagesAndBoundTheAttacker(t *testing.T) {
	const maxHeadroom = 2.5 // generous, but nowhere near the 5x+ that 32/64 GiB needed

	require.Greater(t, maxDecompressedLayerSize, largestMeasuredLayerSize,
		"the per-layer ceiling must admit the largest layer of any real image")
	require.Greater(t, maxDecompressedImageSize, largestMeasuredImageSize,
		"the image budget must admit the largest real image whole")

	assert.LessOrEqual(t, float64(maxDecompressedLayerSize), maxHeadroom*float64(largestMeasuredLayerSize),
		"per-layer ceiling is %d, more than %.1fx the largest measured real layer (%d) — that is not a measured limit, it is a guess",
		maxDecompressedLayerSize, maxHeadroom, largestMeasuredLayerSize)
	assert.LessOrEqual(t, float64(maxDecompressedImageSize), maxHeadroom*float64(largestMeasuredImageSize),
		"image budget is %d, more than %.1fx the largest measured real image (%d) — that is not a measured limit, it is a guess",
		maxDecompressedImageSize, maxHeadroom, largestMeasuredImageSize)

	// The aggregate is what actually bounds the attacker, so it must not be
	// reachable by a single layer: a one-layer bomb has to die on the per-layer
	// ceiling first, and the budget's job is to stop the many-layer variant.
	assert.Greater(t, maxDecompressedImageSize, maxDecompressedLayerSize,
		"the image budget must sit above the per-layer ceiling")

	assert.Greater(t, int64(maxLayerCount), int64(largestMeasuredLayerCount),
		"the layer-count ceiling must admit the deepest real manifest")
}

// A COMPACT bomb — the shape the review named: a tenant-controlled gzip that is
// tiny on the wire and enormous once expanded. The assertions pin that the
// fixture really is compact (so this is not the large-layer case in disguise)
// and that the reader STOPS rather than draining the bomb and reporting the
// overrun afterwards. Bytes actually consumed is the property that matters for
// CPU exhaustion; an error raised after decompressing everything is no defence.
func TestCappedReader_CompactBombStopsAtTheCeilingWithoutDraining(t *testing.T) {
	const ceiling = int64(4 << 20) // small so the test is fast
	const bombSize = int64(256 << 20)

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, err := io.Copy(zw, newPattern(bombSize))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	compressed := gzBuf.Bytes()
	require.Less(t, int64(len(compressed)), int64(1<<20),
		"fixture must be COMPACT — a merely large layer is a different case")
	require.Greater(t, bombSize/int64(len(compressed)), int64(100),
		"fixture must actually amplify")

	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	require.NoError(t, err)
	capped := &cappedReader{r: zr, limit: ceiling, budget: &decompressionBudget{limit: maxDecompressedImageSize}}

	n, _ := io.Copy(io.Discard, capped)

	assert.True(t, capped.exceeded(), "the overrun must be detectable")
	assert.Equal(t, ceiling+1, capped.read,
		"the reader must stop one byte past the ceiling, not drain the bomb")
	assert.Equal(t, ceiling+1, n)
	assert.Less(t, capped.read, bombSize/10,
		"consumption must be bounded by the ceiling, not by the bomb's payload")
}

// End-to-end twin: a compact bomb inside a real image tar must cost the image
// its attestation, not merely log a warning. The ceilings are lowered so the
// fixture stays small; the constants themselves are pinned above.
func TestAttest_CompactBombFailsTheAttestation(t *testing.T) {
	originalLayer, originalImage := maxDecompressedLayerSize, maxDecompressedImageSize
	maxDecompressedLayerSize = 4 << 20
	maxDecompressedImageSize = 8 << 20
	t.Cleanup(func() {
		maxDecompressedLayerSize = originalLayer
		maxDecompressedImageSize = originalImage
	})

	bomb := gzipOf(t, 256<<20, 0)
	require.Less(t, int64(len(bomb)), int64(1<<20), "fixture must be compact")

	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, []string{"bomb.tar.gz"})),
		bytesEntry("config.json", []byte(`{"architecture":"amd64","os":"linux"}`)),
		bytesEntry("bomb.tar.gz", bomb),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	a := New()
	err := a.Attest(ctx)
	require.Error(t, err, "a compact bomb must not yield a signed envelope")
	assert.Contains(t, err.Error(), "exceeds maximum size")

	assert.Empty(t, a.LayerDiffIDs)
	for k := range a.Subjects() {
		assert.NotContains(t, k, "layerdiffid", "a refused run must publish no layer subject; got %q", k)
	}
}

// ── Duplicate PHYSICAL tar entries ─────────────────────────────────────────
//
// tar assigns no meaning to a repeated name, and every extractor in common use
// resolves it LAST-ENTRY-WINS (GNU tar, bsdtar, docker/podman image load all
// overwrite as they go). Digesting the FIRST entry and ignoring the rest
// therefore attests bytes a consumer never sees while the bytes it does see go
// unmeasured — a signed envelope that disagrees with the archive it describes,
// which is the one outcome this attestor exists to make impossible.
func TestDigestTarEntries_DuplicatePhysicalEntryIsRefused(t *testing.T) {
	benign := []byte("the bytes we would have attested")
	actual := []byte("the bytes an extractor actually keeps")
	require.NotEqual(t, benign, actual)

	layers := []string{"a.tar"}
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, layers)),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("a.tar", benign),
		bytesEntry("a.tar", actual), // same name, second physical entry
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: layers}

	got, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.ErrorIs(t, err, errDuplicateTarEntry,
		"an archive with two answers for one layer is ambiguous evidence and must be refused")
	assert.Contains(t, err.Error(), "a.tar")
	assert.Nil(t, got)

	// And the refusal must reach the envelope, not stop at the helper.
	a := New()
	require.ErrorIs(t, a.Attest(ctx), errDuplicateTarEntry)
	assert.Empty(t, a.LayerDiffIDs)
}

// The same split one level down: `./a.tar` and `a.tar` are two tar entries and
// ONE extracted file. Matching on the raw header name would treat them as
// unrelated, so the refusal above would never fire and the attestor would sign
// the first while an extractor keeps the second — the identical defect wearing
// a path separator.
func TestDigestTarEntries_PathNormalizedDuplicateIsRefused(t *testing.T) {
	layers := []string{"a.tar"}
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, layers)),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("a.tar", []byte("attested bytes")),
		bytesEntry("./a.tar", []byte("extracted bytes")),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: layers}

	_, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.ErrorIs(t, err, errDuplicateTarEntry,
		"`./a.tar` and `a.tar` are one file to every extractor; the refusal must see through the prefix")
}

// The mirror image, and the reason the fix is scoped to PHYSICAL entries: a
// manifest may legitimately name one stored blob from several positions, and
// that must keep working. Written here with a `./` prefix the manifest omits, so
// this also proves the normalisation is a MATCH and not only a rejection.
func TestGetLayerDIFFIDs_RepeatedReferenceToOneEntryStillWorks(t *testing.T) {
	shared := []byte("one physical blob")
	other := []byte("a different blob")

	layers := []string{"a.tar", "b.tar", "a.tar"}
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, layers)),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("./a.tar", shared),
		bytesEntry("b.tar", other),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: layers}

	got, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.NoError(t, err, "repeated REFERENCES are legitimate and must survive the duplicate-entry fix")
	require.Len(t, got, 3)

	key := cryptoutil.DigestValue{Hash: crypto.SHA256}
	assert.Equal(t, sha256Of(t, bytes.NewReader(shared)), got[0][key])
	assert.Equal(t, sha256Of(t, bytes.NewReader(other)), got[1][key])
	assert.Equal(t, got[0][key], got[2][key])
}

// Two DIFFERENT manifest strings resolving to one extracted path is the same
// ambiguity a level up: the positional evidence would claim two layers where the
// image holds one file.
func TestGetLayerDIFFIDs_ManifestNamesCollidingAfterCleaningAreRefused(t *testing.T) {
	layers := []string{"a.tar", "./a.tar"}
	tarPath := buildStreamedTar(t,
		bytesEntry("manifest.json", manifestJSON(t, layers)),
		bytesEntry("config.json", []byte(`{"architecture":"amd64"}`)),
		bytesEntry("a.tar", []byte("only one blob here")),
	)

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: layers}

	_, err := m.getLayerDIFFIDs(ctx, tarPath)
	require.ErrorIs(t, err, errDuplicateTarEntry)
}

// tarEntryKey is the single place the "same file?" question is answered, so its
// table is the real statement of which header spellings collide. Every real
// `crane pull` name is already its own key — verified against
// docker.io/library/busybox:1.31.1 and quay.io/brancz/kube-rbac-proxy:v0.13.1,
// whose entries are flat regular files — so normalisation is identity on
// legitimate input and only ever bites a crafted archive.
func TestTarEntryKey_CollapsesTheSpellingsAnExtractorCollapses(t *testing.T) {
	same := []string{
		"a.tar",
		"./a.tar",
		"/a.tar",
		"//a.tar",
		"x/../a.tar",
		"./x/./../a.tar",
	}
	for _, n := range same {
		assert.Equal(t, "a.tar", tarEntryKey(n), "%q extracts to a.tar", n)
	}

	// Real crane-pull names must survive untouched.
	for _, n := range []string{
		"manifest.json",
		"sha256:1c35c441208254cb7c3844ba95a96485388cef9ccc0646d562c7fc026e04c807",
		"76df9210b28cbd4bc127844914d0a23937ed213048dc6289b2a2d4f7d675c75e.tar.gz",
		"blobs/sha256/deadbeef",
	} {
		assert.Equal(t, n, tarEntryKey(n), "a real tarball name must be its own key")
	}
}

// A layer name resolving to a SYMLINK is unmeasurable, not empty. tar stores the
// link target rather than any payload, so streaming it digests zero bytes — and
// an empty diffID published as a subject is a signed claim to have measured
// something that was never read, the same failure layerHashes refuses for a
// hash set with nothing streamable in it.
func TestDigestTarEntries_NonRegularLayerEntryIsRefused(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "image.tar")
	f, err := os.Create(tarPath)
	require.NoError(t, err)

	tw := tar.NewWriter(f)
	manifest := manifestJSON(t, []string{"a.tar"})
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(manifest))}))
	_, err = tw.Write(manifest)
	require.NoError(t, err)
	config := []byte(`{"architecture":"amd64"}`)
	require.NoError(t, tw.WriteHeader(&tar.Header{Name: "config.json", Mode: 0600, Size: int64(len(config))}))
	_, err = tw.Write(config)
	require.NoError(t, err)
	// The layer, as a symlink: no payload, so a naive read measures nothing.
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "a.tar", Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: "config.json",
	}))
	require.NoError(t, tw.Close())
	require.NoError(t, f.Close())

	ctx := ctxWithHashes(t, tarPath, sha256Only())
	m := Manifest{Config: "config.json", Layers: []string{"a.tar"}}

	_, err = m.getLayerDIFFIDs(ctx, tarPath)
	require.ErrorIs(t, err, errUnmeasurableTarEntry,
		"a layer with no bytes in the archive must refuse, not publish the digest of nothing")

	a := New()
	require.ErrorIs(t, a.Attest(ctx), errUnmeasurableTarEntry)
	assert.Empty(t, a.LayerDiffIDs)
	for k := range a.Subjects() {
		assert.NotContains(t, k, "layerdiffid", "a refused run must publish no layer subject; got %q", k)
	}
}
