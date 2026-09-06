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

// The fixture digests below come from a REAL `pack build … --publish` run
// (heroku/builder:24, pack 0.40.9, 2026-09-06) whose outputs are committed
// under testdata/fixtures/pack-publish — the tests parse real bytes, not
// hand-typed samples.
const (
	fixtureImageDigestHex    = "0f067a8e564d23f4f8982ce47e3b1302b8ecba415bf433764b07b2eeb98576d3"
	fixtureRunImageDigestHex = "26197de1f4fcef5e57504d18a650c82fd74a976ba0de227e3bf7cfbf2583e5ff"
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

func TestAttest_RealFixture(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml": fixtureBytes(t, "report.toml"),
		"out/labels.json": fixtureBytes(t, "labels.json"),
		"out/sbom/sbom/launch/buildpacksio_lifecycle/launcher/sbom.cdx.json": []byte(`{"bomFormat":"CycloneDX"}`),
		"out/sbom/sbom/build/buildpacksio_lifecycle/sbom.spdx.json":          []byte(`{"spdxVersion":"SPDX-2.3"}`),
	})

	a := New()
	require.NoError(t, a.Attest(ctx))

	// Identity from report.toml.
	assert.Equal(t, fixtureImageDigestHex, a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}])
	assert.Equal(t, []string{"localhost:5001/demo-app"}, a.ImageTags)
	assert.Equal(t, int64(1538), a.ManifestSize)

	// Run image from the lifecycle metadata label — digest-resolved.
	require.NotNil(t, a.RunImage)
	assert.Contains(t, a.RunImage.Reference, "@sha256:"+fixtureRunImageDigestHex)
	assert.Equal(t, "docker.io/heroku/heroku:24", a.RunImage.Image)

	// Buildpack group + lifecycle provenance from the build metadata label.
	require.Len(t, a.Buildpacks, 1)
	assert.Equal(t, "heroku/go", a.Buildpacks[0].ID)
	assert.Equal(t, "4.1.0", a.Buildpacks[0].Version)
	require.NotNil(t, a.Launcher)
	assert.Equal(t, "github.com/buildpacks/lifecycle", a.Launcher.Repository)

	// Base distro labels.
	require.NotNil(t, a.BaseDistro)
	assert.Equal(t, "ubuntu", a.BaseDistro.Name)
	assert.Equal(t, "24.04", a.BaseDistro.Version)

	// SBOMs bound by product digest, never inlined.
	require.Len(t, a.SBOMs, 2)
	for _, s := range a.SBOMs {
		assert.NotEmpty(t, s.Digest, "SBOM %s must carry a digest", s.Path)
	}

	// Subjects: all three families present, digests exact.
	subj := a.Subjects()
	assert.Contains(t, subj, "imagedigest:"+fixtureImageDigestHex)
	assert.Contains(t, subj, "imagereference:localhost:5001/demo-app")
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

// Adversarial: a labels dump whose inner metadata JSON is corrupt must not
// fail the attestation — the outer facts stand, the broken field is absent.
func TestAttest_CorruptInnerLabelJSON(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml": fixtureBytes(t, "report.toml"),
		"out/labels.json": []byte(`{"io.buildpacks.build.metadata":"{not json","io.buildpacks.stack.id":"heroku-24"}`),
	})
	a := New()
	require.NoError(t, a.Attest(ctx))
	assert.Empty(t, a.Buildpacks)
	assert.Equal(t, "heroku-24", a.StackID)
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

// The lifecycle can write sbom.legacy.json as the literal string "null"
// (observed in the fixture build). Its CONTENT is never parsed — only bound
// by digest — so it must ride along without error.
func TestAttest_LegacyNullSBOM(t *testing.T) {
	ctx := contextWithFiles(t, map[string][]byte{
		"out/report.toml":                       fixtureBytes(t, "report.toml"),
		"out/sbom/sbom/launch/sbom.legacy.json": []byte("null"),
	})
	a := New()
	require.NoError(t, a.Attest(ctx))
	require.Len(t, a.SBOMs, 1)
	assert.Equal(t, "legacy", a.SBOMs[0].Format)
}

func TestSchemaIsReflectable(t *testing.T) {
	assert.NotNil(t, New().Schema())
}
