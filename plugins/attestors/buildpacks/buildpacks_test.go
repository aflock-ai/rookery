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

package buildpacks

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sha256Hex returns the sha256 hex of b — the content address a product is
// selected by.
func sha256Hex(t *testing.T, b []byte) string {
	t.Helper()
	d, err := cryptoutil.CalculateDigestSetFromBytes(b, defaultHashes())
	require.NoError(t, err)
	return d[cryptoutil.DigestValue{Hash: crypto.SHA256}]
}

// ociChain builds a valid config→manifest chain carrying the given labels and
// returns the report (manifest) digest hex plus the two product blobs. The
// manifest names the config blob by its real sha256, and the returned reportHex
// is the manifest's real sha256 — so an attestor that walks report→manifest→
// config by content address reaches exactly these labels. This is how a genuine
// `crane manifest` + `crane config` export chains to report.toml's digest.
func ociChain(t *testing.T, labels map[string]string) (reportHex string, manifest, config []byte) {
	t.Helper()
	config, err := json.Marshal(map[string]any{"config": map[string]any{"Labels": labels}})
	require.NoError(t, err)
	manifest, err = json.Marshal(map[string]any{
		"config": map[string]any{"digest": "sha256:" + sha256Hex(t, config)},
	})
	require.NoError(t, err)
	return sha256Hex(t, manifest), manifest, config
}

// reportTOML renders a minimal registry-export report.toml for the given
// manifest-digest hex.
func reportTOML(digestHex string) []byte {
	return []byte("[image]\n  tags = [\"localhost:5001/demo-app\"]\n  digest = \"sha256:" + digestHex + "\"\n  manifest-size = 1538\n")
}

// fixtureLabelMap pulls the REAL io.buildpacks.* label values out of the
// committed fixture (a docker-inspect dump: .Config.Labels) so chain tests carry
// real label content even though the chain digests are synthesized.
func fixtureLabelMap(t *testing.T) map[string]string {
	t.Helper()
	var insp struct {
		Config struct {
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
	}
	require.NoError(t, json.Unmarshal(fixtureBytes(t, "labels.json"), &insp))
	require.NotEmpty(t, insp.Config.Labels, "fixture labels.json must carry io.buildpacks.* labels")
	return insp.Config.Labels
}

// contextWithMistrustedProduct writes fileBytes to path but records the product
// digest of DIFFERENT bytes — modelling a file swapped after cilock hashed it.
func contextWithMistrustedProduct(t *testing.T, path string, fileBytes []byte) *attestation.AttestationContext {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, path)
	require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
	require.NoError(t, os.WriteFile(abs, fileBytes, 0o600))
	stale, err := cryptoutil.CalculateDigestSetFromBytes([]byte("the trusted bytes cilock hashed"), defaultHashes())
	require.NoError(t, err)
	prod := &fakeProducer{products: map[string]attestation.Product{
		path: {MimeType: "application/octet-stream", Digest: stale},
	}}
	ctx, err := attestation.NewContext("test", []attestation.Attestor{prod},
		attestation.WithWorkingDir(dir), attestation.WithHashes(defaultHashes()))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return ctx
}

// The fixture digests below come from a REAL `pack build … --publish` run
// (heroku/builder:24, pack 0.40.9, 2026-09-06) whose outputs are committed
// under testdata/fixtures/pack-publish — the tests parse real bytes, not
// hand-typed samples.
const (
	fixtureImageDigestHex    = "0f067a8e564d23f4f8982ce47e3b1302b8ecba415bf433764b07b2eeb98576d3"
	fixtureRunImageDigestHex = "26197de1f4fcef5e57504d18a650c82fd74a976ba0de227e3bf7cfbf2583e5ff"
	// The SBOM-layer diffID the lifecycle wrote into the fixture image's
	// io.buildpacks.lifecycle.metadata label.
	fixtureSBOMLayerHex = "fd794d639158a012e78e84adee9fa35d9e84a31b15de7ec27d74e4007475ad44"
)

func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
}

// fakeProducer registers files as products, mirroring what cilock's product
// attestor does for files the wrapped command wrote.
type fakeProducer struct {
	products map[string]attestation.Product
}

func (fp *fakeProducer) Name() string                                   { return "fake-producer" }
func (fp *fakeProducer) Type() string                                   { return "fake" }
func (fp *fakeProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (fp *fakeProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (fp *fakeProducer) Schema() *jsonschema.Schema                     { return nil }
func (fp *fakeProducer) Products() map[string]attestation.Product       { return fp.products }

// contextWithFiles writes the given relative-path→bytes files under a temp
// working dir, registers each as a product, and returns the run context.
func contextWithFiles(t *testing.T, files map[string][]byte) *attestation.AttestationContext {
	t.Helper()
	dir := t.TempDir()
	products := map[string]attestation.Product{}
	for rel, data := range files {
		abs := filepath.Join(dir, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
		require.NoError(t, os.WriteFile(abs, data, 0o600))
		digest, err := cryptoutil.CalculateDigestSetFromFile(abs, defaultHashes())
		require.NoError(t, err)
		products[rel] = attestation.Product{MimeType: "application/octet-stream", Digest: digest}
	}
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{&fakeProducer{products: products}},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(defaultHashes()),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return ctx
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "unit", name))
	require.NoError(t, err)
	return data
}

// The real fixture report.toml (registry export) mints the image identity and
// subjects, with no labels product present.
func TestAttest_RealReportIdentity(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml": fixtureBytes(t, "report.toml"),
	})
	a := New()
	require.NoError(t, a.Attest(ctx))

	assert.Equal(t, fixtureImageDigestHex, a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])
	assert.Equal(t, []string{"localhost:5001/demo-app"}, a.ImageTags)
	assert.Equal(t, int64(1538), a.ManifestSize)

	// No config blob present: label-derived claims stay unset, identity stands.
	assert.Nil(t, a.RunImage)
	assert.Empty(t, a.Buildpacks)
	assert.Empty(t, a.SBOMLayer)

	subj := a.Subjects()
	assert.Contains(t, subj, "imagedigest:"+fixtureImageDigestHex)
	assert.Contains(t, subj, "imagereference:localhost:5001/demo-app")
}

// Labels are bound to the reported image only through the OCI content chain:
// report digest == manifest sha256, manifest.config.digest == config sha256,
// labels from that config. The chain carries the fixture's REAL label content.
func TestAttest_LabelChainBound(t *testing.T) {
	reportHex, manifest, config := ociChain(t, fixtureLabelMap(t))

	// Loose --sbom-output-dir files are present as products but must NOT be read
	// — the SBOM record is the config's own sbom-layer digest.
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml":   reportTOML(reportHex),
		"out/manifest.json": manifest,
		"out/config.json":   config,
		"out/sbom/sbom/launch/buildpacksio_lifecycle/launcher/sbom.cdx.json": []byte(`{"bomFormat":"CycloneDX"}`),
	})

	a := New()
	require.NoError(t, a.Attest(ctx))

	assert.Equal(t, reportHex, a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])

	// Run image from the config's lifecycle-metadata label — digest-resolved.
	require.NotNil(t, a.RunImage)
	assert.Contains(t, a.RunImage.Reference, "@sha256:"+fixtureRunImageDigestHex)
	assert.Equal(t, "docker.io/heroku/heroku:24", a.RunImage.Image)

	// Buildpack group + lifecycle provenance from the config's build-metadata label.
	require.Len(t, a.Buildpacks, 1)
	assert.Equal(t, "heroku/go", a.Buildpacks[0].ID)
	assert.Equal(t, "4.1.0", a.Buildpacks[0].Version)
	require.NotNil(t, a.Launcher)
	assert.Equal(t, "github.com/buildpacks/lifecycle", a.Launcher.Repository)

	require.NotNil(t, a.BaseDistro)
	assert.Equal(t, "ubuntu", a.BaseDistro.Name)
	assert.Equal(t, "24.04", a.BaseDistro.Version)

	// SBOM-layer digest from the config, not the loose file.
	assert.Equal(t, fixtureSBOMLayerHex, a.SBOMLayer[cryptoutil.DigestValue{Hash: crypto.SHA256}])

	subj := a.Subjects()
	assert.Contains(t, subj, "imagedigest:"+reportHex)
	assert.Contains(t, subj, "runimagedigest:"+fixtureRunImageDigestHex)
}

func TestAttest_NoProducts(t *testing.T) {
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithHashes(defaultHashes()))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	assert.ErrorContains(t, New().Attest(ctx), "no products")
}

func TestAttest_ProductsButNoReport(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"binary": []byte("not a report"),
	})
	err := New().Attest(ctx)
	assert.ErrorContains(t, err, "--report-output-dir",
		"the refusal must teach the flag that fixes it")
}

// Adversarial: a file NAMED report.toml that does not parse as one must not
// count as a found report — a name is not evidence.
func TestAttest_MalformedReportRefused(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml": []byte("this is { not TOML ]["),
	})
	assert.Error(t, New().Attest(ctx))
}

// Adversarial: a parseable report.toml with an empty [image] section is a
// name wearing the right clothes — still refused.
func TestAttest_EmptyImageSectionRefused(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml": []byte("[image]\n"),
	})
	assert.Error(t, New().Attest(ctx))
}

// Daemon export: image-id only. Attested for context, but NO imagedigest
// subject — an image-id is daemon-local, not durable identity.
func TestAttest_DaemonExportGetsNoIdentitySubject(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml": []byte("[image]\n  tags = [\"demo-app\"]\n  image-id = \"abcdef123456\"\n"),
	})
	a := New()
	require.NoError(t, a.Attest(ctx))
	assert.Equal(t, "abcdef123456", a.ImageID)
	assert.Empty(t, a.ImageDigest)
	for key := range a.Subjects() {
		assert.False(t, strings.HasPrefix(key, "imagedigest:"),
			"daemon export must not mint an imagedigest subject, got %s", key)
	}
}

// Adversarial: a digest that is not sha256-prefixed must mint no identity.
func TestAttest_NonSha256DigestRefused(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml": []byte("[image]\n  tags = [\"t\"]\n  digest = \"md5:abcd\"\n"),
	})
	a := New()
	require.NoError(t, a.Attest(ctx))
	assert.Empty(t, a.ImageDigest)
	assert.NotContains(t, a.Subjects(), "imagedigest:abcd")
}

// Codex critical: sha256: with a value that is not exactly 64 hex chars is
// malformed and must mint no identity — the prefix alone is not enough.
func TestAttest_MalformedSha256DigestsRefused(t *testing.T) {
	cases := map[string]string{
		"too short":   "sha256:abc",
		"non-hex 64":  "sha256:" + strings.Repeat("z", 64),
		"too long":    "sha256:" + strings.Repeat("a", 65),
		"uppercase":   "sha256:" + strings.Repeat("A", 64),
		"empty after": "sha256:",
	}
	for name, digest := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := contextWithFiles(t, map[string][]byte{
				"out/report.toml": []byte("[image]\n  tags = [\"t\"]\n  digest = \"" + digest + "\"\n"),
			})
			a := New()
			require.NoError(t, a.Attest(ctx))
			assert.Empty(t, a.ImageDigest, "malformed digest %q must mint no identity", digest)
			for key := range a.Subjects() {
				assert.False(t, strings.HasPrefix(key, "imagedigest:"), "got %s from %q", key, digest)
			}
		})
	}
}

// The run-image reference's digest must also be a well-formed 64-hex sha256 to
// mint a runimagedigest subject — a short/non-hex value is not an identity.
func TestSubjects_MalformedRunImageDigestMintsNoSubject(t *testing.T) {
	for _, ref := range []string{
		"x@sha256:abc",
		"x@sha256:" + strings.Repeat("z", 64),
		"docker.io/heroku/heroku:24",
	} {
		a := New()
		a.RunImage = &RunImage{Reference: ref}
		for key := range a.Subjects() {
			assert.False(t, strings.HasPrefix(key, "runimagedigest:"), "ref %q minted %s", ref, key)
		}
	}
}

// Foreign JSON products (some other tool's output) are not ours to judge —
// ignored without error and without polluting the predicate.
func TestAttest_ForeignJSONIgnored(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml": fixtureBytes(t, "report.toml"),
		"other.json":      []byte(`{"totally":"unrelated"}`),
	})
	a := New()
	require.NoError(t, a.Attest(ctx))
	assert.Nil(t, a.RunImage)
	assert.Empty(t, a.Buildpacks)
}

// Adversarial: a config whose inner metadata JSON is corrupt must not fail the
// attestation — the outer facts stand, the broken field is absent.
func TestAttest_CorruptInnerLabelJSON(t *testing.T) {
	reportHex, manifest, config := ociChain(t, map[string]string{
		"io.buildpacks.build.metadata": "{not json",
		"io.buildpacks.stack.id":       "heroku-24",
	})
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml":   reportTOML(reportHex),
		"out/manifest.json": manifest,
		"out/config.json":   config,
	})
	a := New()
	require.NoError(t, a.Attest(ctx))
	assert.Empty(t, a.Buildpacks)
	assert.Equal(t, "heroku-24", a.StackID)
}

// A loose --sbom-output-dir file carries no image identity, so it is never read.
// The SBOM record is the image's OWN layer digest from its content-chained
// config. Here a foreign SBOM file is present alongside the real build: its
// digest and contents must appear nowhere, and SBOMLayer must be the config's.
func TestAttest_LooseSBOMFilesNotAttached(t *testing.T) {
	reportHex, manifest, config := ociChain(t, map[string]string{
		"io.buildpacks.lifecycle.metadata": `{"sbom":{"sha":"sha256:` + fixtureSBOMLayerHex + `"}}`,
	})
	foreignSBOM := []byte(`{"bomFormat":"CycloneDX","this-is":"a foreign build, not the reported image"}`)
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml":                           reportTOML(reportHex),
		"out/manifest.json":                         manifest,
		"out/config.json":                           config,
		"b/sbom/sbom/build/foreign/sbom.cdx.json":   foreignSBOM,
		"b/sbom/sbom/launch/foreign/sbom.spdx.json": []byte(`{"spdxVersion":"x"}`),
	})
	a := New()
	require.NoError(t, a.Attest(ctx))

	// SBOMLayer is the image's own layer digest, taken from the chained config.
	assert.Equal(t, fixtureSBOMLayerHex, a.SBOMLayer[cryptoutil.DigestValue{Hash: crypto.SHA256}],
		"SBOMLayer must be the reported image's own layer digest")

	// The foreign SBOM bytes must not have been read or recorded anywhere.
	foreignHex := sha256Hex(t, foreignSBOM)
	blob, err := json.Marshal(a)
	require.NoError(t, err)
	assert.NotContains(t, string(blob), foreignHex, "a loose SBOM digest must never enter the predicate")
	assert.NotContains(t, string(blob), "foreign build", "loose SBOM contents must never be read")
}

// When the SBOM sha in the lifecycle-metadata label is malformed it binds
// nothing — SBOMLayer stays empty rather than recording a non-digest value.
func TestAttest_MalformedSBOMLayerBindsNothing(t *testing.T) {
	for name, sha := range map[string]string{
		"too short": "sha256:abc",
		"no prefix": strings.Repeat("a", 64),
		"non-hex":   "sha256:" + strings.Repeat("z", 64),
	} {
		t.Run(name, func(t *testing.T) {
			reportHex, manifest, config := ociChain(t, map[string]string{
				"io.buildpacks.lifecycle.metadata": `{"sbom":{"sha":"` + sha + `"}}`,
			})
			ctx := contextWithFiles(t, map[string][]byte{
				"out/report.toml":   reportTOML(reportHex),
				"out/manifest.json": manifest,
				"out/config.json":   config,
			})
			a := New()
			require.NoError(t, a.Attest(ctx))
			assert.Empty(t, a.SBOMLayer, "malformed sbom sha %q must bind nothing", sha)
		})
	}
}

// Codex critical: two report.toml products are ambiguous (which image?) and
// must be refused rather than letting map order pick a winner.
func TestAttest_MultipleReportsRefused(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"a/report.toml": fixtureBytes(t, "report.toml"),
		"b/report.toml": fixtureBytes(t, "report.toml"),
	})
	err := New().Attest(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ambiguous")
}

// Codex critical: a report file modified after cilock hashed it as a product
// must be rejected — the parsed bytes are verified against product.Digest.
func TestAttest_TamperedReportBytesRefused(t *testing.T) {
	ctx := contextWithMistrustedProduct(t, "out/report.toml", fixtureBytes(t, "report.toml"))
	err := New().Attest(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "match the recorded product digest")
}

// Round-6 critical: labels are attributed only through the content chain. A
// manifest whose sha256 is NOT the report digest is a different image; its
// labels must not be attributed to the reported one.
func TestAttest_ManifestNotMatchingReportDigestIgnored(t *testing.T) {
	_, manifest, config := ociChain(t, map[string]string{
		"io.buildpacks.lifecycle.metadata": `{"runImage":{"reference":"evil@sha256:` + strings.Repeat("d", 64) + `"},"sbom":{"sha":"sha256:` + strings.Repeat("e", 64) + `"}}`,
		"io.buildpacks.stack.id":           "attacker",
	})
	// The report names a DIFFERENT image than the provided manifest (the real
	// fixture digest, which the synthesized manifest does not hash to).
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml":   reportTOML(fixtureImageDigestHex),
		"out/manifest.json": manifest,
		"out/config.json":   config,
	})
	a := New()
	require.NoError(t, a.Attest(ctx))
	assert.Nil(t, a.RunImage, "labels from a manifest that is not the reported image must be ignored")
	assert.Empty(t, a.StackID)
	assert.Empty(t, a.SBOMLayer)
	for key := range a.Subjects() {
		assert.False(t, strings.HasPrefix(key, "runimagedigest:"), "got %s", key)
	}
}

// Round-6 critical, the reviewer's exact case ("RepoDigests matches but the
// config does not"): the manifest DOES hash to the report digest, but the only
// config product present is a fabricated one whose sha256 is not the manifest's
// config.digest. It must not be read — the attacker's labels stay out.
func TestAttest_FabricatedConfigNotChainedIgnored(t *testing.T) {
	// Genuine chain; we keep its manifest (which names the genuine config's
	// digest) but do NOT provide that genuine config.
	reportHex, manifest, _ := ociChain(t, map[string]string{
		"io.buildpacks.stack.id": "real",
	})
	fabricated, err := json.Marshal(map[string]any{"config": map[string]any{"Labels": map[string]string{
		"io.buildpacks.lifecycle.metadata": `{"runImage":{"reference":"evil@sha256:` + strings.Repeat("e", 64) + `"}}`,
		"io.buildpacks.stack.id":           "attacker",
	}}})
	require.NoError(t, err)
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml":   reportTOML(reportHex),
		"out/manifest.json": manifest,   // hashes to reportHex, names the GENUINE config digest
		"out/config.json":   fabricated, // hashes to something else — not the named config
	})
	a := New()
	require.NoError(t, a.Attest(ctx))
	assert.Nil(t, a.RunImage, "a config not named by the manifest must not be read")
	assert.Empty(t, a.StackID, "attacker labels must not leak in")
	assert.Empty(t, a.SBOMLayer)
}

// An image index (multi-arch) report digest carries no single config; labels
// are not attested rather than guessed from one arbitrary child manifest.
func TestAttest_ImageIndexNoLabels(t *testing.T) {
	index, err := json.Marshal(map[string]any{
		"mediaType": "application/vnd.oci.image.index.v1+json",
		"manifests": []any{map[string]any{"digest": "sha256:" + strings.Repeat("a", 64)}},
	})
	require.NoError(t, err)
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml":   reportTOML(sha256Hex(t, index)),
		"out/manifest.json": index,
	})
	a := New()
	require.NoError(t, a.Attest(ctx))
	assert.Nil(t, a.RunImage, "an image index must not yield per-image labels")
	assert.Empty(t, a.StackID)
}

// A run-image reference WITHOUT a digest (tag-only) is a name, not an
// identity: recorded, but no runimagedigest subject.
func TestSubjects_TagOnlyRunImageMintsNoSubject(t *testing.T) {
	a := New()
	a.RunImage = &RunImage{Reference: "docker.io/heroku/heroku:24"}
	for key := range a.Subjects() {
		assert.False(t, strings.HasPrefix(key, "runimagedigest:"), "got %s", key)
	}
}

func TestSchemaIsReflectable(t *testing.T) {
	assert.NotNil(t, New().Schema())
}
