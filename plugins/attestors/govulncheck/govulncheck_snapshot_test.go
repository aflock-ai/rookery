// jade:ring local
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

package govulncheck

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttest_TwoCompletedScansAreRefused: products are a map, so when two
// completed govulncheck streams disagree, "keep the first one found" lets map
// iteration order decide which findings are signed, and a vulnerable report
// can be dropped silently. The attestor must refuse instead, naming both files.
// Each iteration builds a fresh context, so both iteration orders are exercised
// (the chance that 16 runs all see one order is 2^-15).
func TestAttest_TwoCompletedScansAreRefused(t *testing.T) {
	for i := 0; i < 16; i++ {
		tmp := t.TempDir()
		for name, fixture := range map[string]string{
			"a-vulns.json": "govulncheck-vuln-found.json",
			"b-clean.json": "govulncheck-no-vulns.json",
		} {
			src, err := os.ReadFile(filepath.Join("testdata", fixture))
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(tmp, name), src, 0o644))
		}
		gv := New()
		ctx, err := attestation.NewContext("test",
			[]attestation.Attestor{exits("0"), product.New(), gv},
			attestation.WithWorkingDir(tmp))
		require.NoError(t, err)
		require.NoError(t, ctx.RunAttestors())

		var gvErr error
		ran := false
		for _, c := range ctx.CompletedAttestors() {
			if c.Attestor.Name() == Name {
				gvErr, ran = c.Error, true
			}
		}
		require.True(t, ran, "govulncheck attestor did not run")
		require.Error(t, gvErr, "iteration %d: two completed scans with different findings must be refused, not resolved by map order (attested %q)", i, gv.ReportFile)
		assert.False(t, attestation.IsSoftError(gvErr), "the refusal must be fatal")
		assert.False(t, attestation.EvidenceIsRecordable(gvErr), "no summary may be signed")
		assert.Contains(t, gvErr.Error(), "a-vulns.json")
		assert.Contains(t, gvErr.Error(), "b-clean.json")
		assert.Empty(t, gv.ReportFile)
		assert.Empty(t, gv.Report)
		assert.Zero(t, gv.Summary.TotalFindings)
	}
}

// fixedProducts is a product attestor whose product set is supplied by the
// test, so the digest a product was recorded under can differ from the bytes
// now on disk.
type fixedProducts struct {
	products map[string]attestation.Product
}

func (f *fixedProducts) Name() string                                   { return "fixed-products" }
func (f *fixedProducts) Type() string                                   { return "https://aflock.ai/test/fixed-products/v0.1" }
func (f *fixedProducts) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (f *fixedProducts) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *fixedProducts) Schema() *jsonschema.Schema                     { return nil }
func (f *fixedProducts) Products() map[string]attestation.Product       { return f.products }

// TestAttest_DigestAndSummaryComeFromOneRead: the recorded ReportDigestSet
// and the signed Summary/Report must describe the same bytes. Hashing the path
// and then opening it again to parse reads two files if it is swapped in
// between.
//
// The product was recorded under the vulnerable report's digest; the first
// open serves those bytes, and the file now on disk (and every later open)
// holds a clean report, as after a swap. Hashing and parsing one read signs the
// vulnerable findings. Any second read, through openReport or around it (say
// cryptoutil.CalculateDigestSetFromFile on the path), sees the clean bytes and
// either signs the clean summary under the vulnerable digest or drops the scan
// on a digest mismatch; both fail here.
func TestAttest_DigestAndSummaryComeFromOneRead(t *testing.T) {
	tmp := t.TempDir()
	vuln, err := os.ReadFile(filepath.Join("testdata", "govulncheck-vuln-found.json"))
	require.NoError(t, err)
	served := filepath.Join(t.TempDir(), "hashed-vulns.json")
	require.NoError(t, os.WriteFile(served, vuln, 0o644))
	clean, err := os.ReadFile(filepath.Join("testdata", "govulncheck-no-vulns.json"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vulns.json"), clean, 0o644))

	cleanMsgs, err := parseStream(clean)
	require.NoError(t, err)
	vulnMsgs, err := parseStream(vuln)
	require.NoError(t, err)
	want := buildSummary(vulnMsgs)
	require.NotEqual(t, buildSummary(cleanMsgs).TotalFindings, want.TotalFindings,
		"fixtures must differ in findings or the swap proves nothing")

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	vulnDigest, err := cryptoutil.CalculateDigestSetFromBytes(vuln, hashes)
	require.NoError(t, err)

	opens := 0
	orig := openReport
	t.Cleanup(func() { openReport = orig })
	openReport = func(path string) (*os.File, error) {
		opens++
		if opens == 1 {
			return orig(served)
		}
		return orig(path)
	}

	gv := New()
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{exits("0"), &fixedProducts{products: map[string]attestation.Product{
			"vulns.json": {MimeType: "application/json", Digest: vulnDigest},
		}}, gv},
		attestation.WithWorkingDir(tmp),
		attestation.WithHashes(hashes))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	for _, c := range ctx.CompletedAttestors() {
		if c.Attestor.Name() == Name {
			require.NoError(t, c.Error)
		}
	}

	assert.Equal(t, 1, opens, "the report must be read once: hash and parse from one snapshot")
	require.Equal(t, "vulns.json", gv.ReportFile)
	assert.Equal(t, want.TotalFindings, gv.Summary.TotalFindings,
		"the signed summary must describe the bytes ReportDigestSet pins")
	assert.Equal(t, want.ReachableCount, gv.Summary.ReachableCount)
	assert.Len(t, gv.Report, len(vulnMsgs))
	assert.True(t, gv.ReportDigestSet.Equal(vulnDigest))
}
