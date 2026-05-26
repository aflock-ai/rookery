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

package sbom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSBOMFile_ExplicitFile_SPDX validates the "I generated the SBOM
// in a previous step" workflow. The SBOM exists at attestation
// context start (so it's a *material*, not a *product*), which the
// blind-UX agent reported as the #1 friction point with `cilock run
// -a sbom`. With --attestor-sbom-file pointing at the file the
// attestor must produce the SPDX predicate without depending on
// product-set scanning.
func TestSBOMFile_ExplicitFile_SPDX(t *testing.T) {
	cwd := "./boms/spdx-2.3/"
	target := "alpine.spdx-2-3.json"

	sbom := NewSBOMAttestor()
	WithSBOMFile(target)(sbom)
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sbom},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	assert.Equal(t, SPDXPredicateType, sbom.predicateType)
	require.NotNil(t, sbom.SBOMDocument, "SBOMDocument must be populated from the explicit file")
	require.Contains(t, sbom.Subjects(), "file:"+target,
		"subjects must include the explicit file path")
}

func TestSBOMFile_ExplicitFile_CycloneDX(t *testing.T) {
	cwd := "./boms/cyclonedx-json/"
	target := "alpine.cyclonedx.json"

	sbom := NewSBOMAttestor()
	WithSBOMFile(target)(sbom)
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sbom},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	assert.Equal(t, CycloneDxPredicateType, sbom.predicateType)
	require.Contains(t, sbom.Subjects(), "file:"+target)
}

// TestSBOMFile_ExplicitFile_SPDX3 covers SPDX 3.0 documents, which
// drop the `spdxVersion` field used by 2.x and instead carry a
// JSON-LD `@context` plus `specVersion: "3.x.y"`. A red-team review
// of PR #187 caught that the original sniffer only matched 2.x +
// CycloneDX, silently rejecting any SPDX 3 SBOM the user pointed at.
func TestSBOMFile_ExplicitFile_SPDX3(t *testing.T) {
	cwd := t.TempDir()
	target := "doc.spdx3.json"
	// Minimal SPDX 3.0 fixture — only the fields the sniffer keys on.
	// Real 3.0 documents have a populated @graph; an empty array is
	// enough to prove detection works without forcing us to vendor a
	// full SPDX 3 example.
	body := []byte(`{"@context":"https://spdx.org/rdf/3.0.0/spdx-context.jsonld","@graph":[],"specVersion":"3.0.0"}`)
	require.NoError(t, os.WriteFile(filepath.Join(cwd, target), body, 0o600))

	sbom := NewSBOMAttestor()
	WithSBOMFile(target)(sbom)
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sbom},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	// SPDX 3 reuses the SPDX predicate URI — the URI names the
	// predicate, not the spec version. Document shape is what differs.
	assert.Equal(t, SPDXPredicateType, sbom.predicateType)
	require.NotNil(t, sbom.SBOMDocument, "SBOMDocument must be populated from the SPDX 3 file")
	require.Contains(t, sbom.Subjects(), "file:"+target,
		"file: subject must be present even though SPDX 3 subject extraction is deferred")
}

func TestSBOMFile_AbsolutePath(t *testing.T) {
	// Absolute paths should be honored as-is, NOT joined with cwd.
	cwd := t.TempDir()
	absPath, err := filepath.Abs("./boms/spdx-2.3/alpine.spdx-2-3.json")
	require.NoError(t, err)

	sbom := NewSBOMAttestor()
	WithSBOMFile(absPath)(sbom)
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sbom},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	assert.Equal(t, SPDXPredicateType, sbom.predicateType)
}

func TestSBOMFile_IgnoresProductSet(t *testing.T) {
	// Even when the cwd contains an SBOM that would be picked up by
	// the product attestor, --attestor-sbom-file's explicit path
	// wins. That's the contract: the flag is an escape hatch from
	// product-set scanning.
	cwd := t.TempDir()
	// Write a SPDX file at the cwd (would be picked up by products).
	productSPDX := filepath.Join(cwd, "would-be-product.spdx.json")
	require.NoError(t, os.WriteFile(productSPDX, []byte(`{"spdxVersion":"SPDX-2.3","name":"product-set-doc","SPDXID":"SPDXRef-DOCUMENT"}`), 0o600))
	// And a different one we'll point at explicitly.
	explicit := filepath.Join(cwd, "explicit.spdx.json")
	require.NoError(t, os.WriteFile(explicit, []byte(`{"spdxVersion":"SPDX-2.3","name":"explicit-doc","SPDXID":"SPDXRef-DOCUMENT"}`), 0o600))

	sbom := NewSBOMAttestor()
	WithSBOMFile("explicit.spdx.json")(sbom)
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sbom},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	// The explicit file's name should be the recorded subject — not
	// the would-be-product one.
	require.Contains(t, sbom.Subjects(), "file:explicit.spdx.json",
		"explicit file must override product-set scanning")
	assert.NotContains(t, sbom.Subjects(), "file:would-be-product.spdx.json")
	// The "name" subject should match the document inside the explicit file.
	assert.Contains(t, sbom.Subjects(), "name:explicit-doc")
}

func TestSBOMFile_MissingFileReturnsError(t *testing.T) {
	sbom := NewSBOMAttestor()
	WithSBOMFile("does-not-exist.json")(sbom)
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sbom},
		attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	// The wrapping context swallows the error, but the attestor's
	// own getCandidate doesn't get called — instead loadFromExplicitFile
	// runs and reports the missing file as an attestor error.
	completed := ctx.CompletedAttestors()
	var sbomResult *attestation.CompletedAttestor
	for i := range completed {
		if completed[i].Attestor.Name() == sbom.Name() {
			sbomResult = &completed[i]
			break
		}
	}
	require.NotNil(t, sbomResult, "sbom attestor must have run")
	require.Error(t, sbomResult.Error)
	assert.True(t,
		strings.Contains(sbomResult.Error.Error(), "does-not-exist.json"),
		"error must reference the missing file path, got: %v", sbomResult.Error)
}

func TestSBOMFile_RejectsNonSBOMJSON(t *testing.T) {
	cwd := t.TempDir()
	notSBOM := filepath.Join(cwd, "random.json")
	require.NoError(t, os.WriteFile(notSBOM, []byte(`{"foo":"bar","baz":42}`), 0o600))

	sbom := NewSBOMAttestor()
	WithSBOMFile("random.json")(sbom)
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sbom},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	completed := ctx.CompletedAttestors()
	var sbomResult *attestation.CompletedAttestor
	for i := range completed {
		if completed[i].Attestor.Name() == sbom.Name() {
			sbomResult = &completed[i]
			break
		}
	}
	require.NotNil(t, sbomResult)
	require.Error(t, sbomResult.Error)
	assert.Contains(t, sbomResult.Error.Error(), "not a recognized SBOM",
		"error must explain WHY the file was rejected, not just say 'failed'")
}

func TestSBOMFile_RejectsInvalidJSON(t *testing.T) {
	cwd := t.TempDir()
	bad := filepath.Join(cwd, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`{not valid json`), 0o600))

	sbom := NewSBOMAttestor()
	WithSBOMFile("bad.json")(sbom)
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sbom},
		attestation.WithWorkingDir(cwd))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	completed := ctx.CompletedAttestors()
	for _, c := range completed {
		if c.Attestor.Name() == sbom.Name() {
			require.Error(t, c.Error)
			assert.Contains(t, c.Error.Error(), "not valid JSON")
		}
	}
}
