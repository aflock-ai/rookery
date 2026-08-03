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

package sarif

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testsslNativeJSON is a hand-reduced copy of the shape `testssl.sh
// --jsonfile` actually writes: a FLAT ARRAY of findings, not a SARIF log.
// Four attestations carrying exactly this body reached production under the
// sarif predicate type and are permanently unparseable by every SARIF
// consumer. The values are trimmed to the two leading entries of a real
// report; nothing sensitive rides along.
const testsslNativeJSON = `[
  {"id":"engine_problem","ip":"/","port":"443","severity":"WARN","finding":"No engine or GOST support via engine"},
  {"id":"service","ip":"example.test/203.0.113.10","port":"443","severity":"INFO","finding":"HTTP"}
]`

// testsslConvertedSARIF is the shape `jade attest testssl-to-sarif` emits
// from the body above — a real SARIF 2.1.0 log.
const testsslConvertedSARIF = `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {"driver": {"name": "testssl.sh", "rules": [{"id": "engine_problem"}]}},
      "results": [
        {"ruleId": "engine_problem", "level": "warning", "message": {"text": "WARN: No engine or GOST support via engine"}}
      ]
    }
  ]
}`

// TestAttest_RejectsNonSARIFJSON is the core invariant: a sarif-typed
// attestation must be structurally incapable of carrying a document that is
// not a SARIF log. A valid-JSON, correct-MIME product that is a bare array
// must be REJECTED, not recorded. Before this was enforced the attestor
// happily embedded testssl's native report and every downstream SARIF reader
// hard-errored on it.
func TestAttest_RejectsNonSARIFJSON(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "testssl.json"), []byte(testsslNativeJSON), 0o644))

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{product.New(), a},
		attestation.WithWorkingDir(tmp))
	require.NoError(t, err)
	_ = ctx.RunAttestors()

	assert.Empty(t, a.Report, "a non-SARIF JSON document must never be recorded as a SARIF report")
	assert.Empty(t, a.ReportFile, "ReportFile must stay empty when no SARIF product is present")
}

// TestAttest_ErrorNamesTheRejection makes the failure diagnosable: when the
// only candidate is rejected for shape, the terminal error must say so rather
// than the bare "no sarif file found" that leaves an operator guessing.
func TestAttest_ErrorNamesTheRejection(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "testssl.json"), []byte(testsslNativeJSON), 0o644))

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{product.New(), a},
		attestation.WithWorkingDir(tmp))
	require.NoError(t, err)

	// RunAttestors does NOT surface a per-attestor failure as its own return
	// value — it captures each one on the attestor's CompletedAttestor leg
	// (attestation/context.go). So the LEG is what this asserts, not a second
	// direct Attest call: the leg is precisely what `cilock run` reads to
	// decide the process exit code, which is the behaviour under test.
	require.NoError(t, ctx.RunAttestors())

	var legErr error
	found := false
	for _, c := range ctx.CompletedAttestors() {
		if c.Attestor == attestation.Attestor(a) {
			legErr, found = c.Error, true
		}
	}
	require.True(t, found, "the sarif attestor must appear in the completed set")
	require.Error(t, legErr, "the attestor must fail loudly when no product is a SARIF log")
	assert.Contains(t, legErr.Error(), "testssl.json")

	// FATAL, not soft. `cilock run` demotes SoftError legs to warnings and
	// keeps exit 0; a step that produced a document claiming to be SARIF and
	// is not must turn the process red, not print a warning nobody reads.
	assert.False(t, attestation.IsSoftError(legErr), "a non-SARIF product must be a fatal attestor error")
}

// TestAttest_PrefersSARIFOverForeignJSON reproduces the production emission
// bug. The prod TLS lane leaves BOTH testssl.json (native) and
// testssl-results.sarif (converted) in the step workdir. Candidate selection
// walked ctx.Products(), a Go map, and took the first MIME-matching entry —
// so which file got attested was decided by randomized map iteration order.
// Recorded evidence: of five prod-platform-tls envelopes carrying a sarif
// attestation, four recorded testssl.json and one recorded
// testssl-results.sarif, with BOTH files present as products in every one.
//
// The vuln lane carries the same hazard from the other direction: it copies
// an OCI image-manifest.json in beside trivy-results.sarif, so it too has two
// MIME-matching JSON products and sorts the foreign one FIRST.
//
// Iterating enough times makes the old behavior fail essentially always.
func TestAttest_PrefersSARIFOverForeignJSON(t *testing.T) {
	const ociManifest = `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`

	for i := 0; i < 50; i++ {
		tmp := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(tmp, "testssl.json"), []byte(testsslNativeJSON), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(tmp, "image-manifest.json"), []byte(ociManifest), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(tmp, "testssl-results.sarif"), []byte(testsslConvertedSARIF), 0o644))

		a := New()
		ctx, err := attestation.NewContext("test", []attestation.Attestor{product.New(), a},
			attestation.WithWorkingDir(tmp))
		require.NoError(t, err)
		require.NoError(t, ctx.RunAttestors())

		require.Equal(t, "testssl-results.sarif", a.ReportFile,
			"iteration %d: the SARIF log must be selected over the foreign JSON product", i)
	}
}

// TestIsSARIFLog pins the discriminator itself. It keys on the structural
// invariant every SARIF consumer depends on — a top-level OBJECT carrying a
// `runs` ARRAY and a `version` — never on a file name, collection name or
// tool name, because foreign formats arrive under names we have never seen.
func TestIsSARIFLog(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"canonical", testsslConvertedSARIF, true},
		{"empty runs is a clean scan", `{"version":"2.1.0","runs":[]}`, true},
		// `results` is spec-OPTIONAL; a run that omits it must still pass.
		{"run without results", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}}}]}`, true},
		{"testssl native array", testsslNativeJSON, false},
		{"bare array", `[]`, false},
		{"scalar", `"sarif"`, false},
		{"top-level null", `null`, false},
		{"object without runs", `{"version":"2.1.0"}`, false},
		{"null runs", `{"version":"2.1.0","runs":null}`, false},
		{"runs not an array", `{"version":"2.1.0","runs":{}}`, false},
		{"missing version", `{"runs":[]}`, false},
		{"empty version", `{"version":"","runs":[]}`, false},
		{"not json", `not json`, false},
		// The two documents the review named: both parse as JSON and satisfy
		// a top-level-only check, yet carry no attributable scanner identity.
		{"garbage version with null run", `{"version":"garbage","runs":[null]}`, false},
		{"run is an empty object", `{"version":"2.1.0","runs":[{}]}`, false},
		// A non-2.1.0 version is rejected: the predicate type is the 2.1.0
		// contract, so a new SARIF major needs a new predicate version.
		{"future version", `{"version":"2.2.0","runs":[]}`, false},
		{"non-string version", `{"version":2.1,"runs":[]}`, false},
		{"run is a scalar", `{"version":"2.1.0","runs":[42]}`, false},
		{"run missing tool", `{"version":"2.1.0","runs":[{"results":[]}]}`, false},
		{"tool is null", `{"version":"2.1.0","runs":[{"tool":null}]}`, false},
		{"tool missing driver", `{"version":"2.1.0","runs":[{"tool":{}}]}`, false},
		{"driver is a scalar", `{"version":"2.1.0","runs":[{"tool":{"driver":"gosec"}}]}`, false},
		// The driver's `name` is what the evidence classifier keys on. An empty
		// or absent name yields an envelope with BLANK tool identity, which the
		// classifier reads as "no signal" rather than "unrecognized tool" — two
		// states the platform deliberately keeps distinct. Reject at the
		// producer so that distinction stays meaningful downstream.
		{"driver without name", `{"version":"2.1.0","runs":[{"tool":{"driver":{}}}]}`, false},
		{"driver name empty", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":""}}}]}`, false},
		{"driver name not a string", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":7}}}]}`, false},
		{"driver name null", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":null}}}]}`, false},
		{"second run is bad", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}}},{}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := isSARIFLog([]byte(tc.body))
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
