// Copyright 2025 The Witness Contributors
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

package kubebench

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA256, GitOID: true},
		{Hash: crypto.SHA1, GitOID: true},
	}
}

// fakeProducer registers a single file as a product so the attestation context
// exposes it to PostProduct attestors such as kube-bench.
type fakeProducer struct {
	products map[string]attestation.Product
}

func (fp *fakeProducer) Name() string                                   { return "fake-producer" }
func (fp *fakeProducer) Type() string                                   { return "fake-type" }
func (fp *fakeProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (fp *fakeProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (fp *fakeProducer) Schema() *jsonschema.Schema                     { return nil }
func (fp *fakeProducer) Products() map[string]attestation.Product       { return fp.products }

// writeReportFile marshals report to a temp file and returns its absolute path.
func writeReportFile(t *testing.T, report KubeBenchReport) (dir, path string) {
	t.Helper()
	data, err := json.Marshal(report)
	require.NoError(t, err)
	dir = t.TempDir()
	path = filepath.Join(dir, "kube-bench.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return
}

// contextWithProduct creates an AttestationContext whose products include the
// file at path so that PostProduct attestors can discover it.
func contextWithProduct(t *testing.T, dir, path string, extraAttestors ...attestation.Attestor) *attestation.AttestationContext {
	t.Helper()
	hashes := defaultHashes()
	digest, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	require.NoError(t, err)

	prod := &fakeProducer{
		products: map[string]attestation.Product{
			path: {
				MimeType: "application/json",
				Digest:   digest,
			},
		},
	}

	attestors := append([]attestation.Attestor{prod}, extraAttestors...)
	ctx, err := attestation.NewContext("test", attestors,
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return ctx
}

// sampleReport returns a minimal but valid kube-bench JSON report.
func sampleReport() KubeBenchReport {
	return KubeBenchReport{
		Controls: []ControlSection{
			{
				ID:   "1",
				Text: "Control Plane Components",
				Tests: []ControlTest{
					{
						ID:   "1.1",
						Text: "Master Node Configuration Files",
						Results: []ControlResult{
							{
								TestNumber: "1.1.1",
								TestDesc:   "Ensure that the API server pod specification file permissions are set to 644 or more restrictive",
								Status:     "PASS",
								Scored:     true,
							},
							{
								TestNumber: "1.1.2",
								TestDesc:   "Ensure that the API server pod specification file ownership is set to root:root",
								Status:     "FAIL",
								Scored:     true,
							},
							{
								TestNumber: "1.1.3",
								TestDesc:   "Ensure that the controller manager pod specification file permissions are set to 644 or more restrictive",
								Status:     "WARN",
								Scored:     false,
							},
						},
					},
				},
			},
		},
		Totals: Totals{
			TotalPass: 1,
			TotalFail: 1,
			TotalWarn: 1,
		},
	}
}

// ── unit tests ────────────────────────────────────────────────────────────────

func TestNew(t *testing.T) {
	assert.NotNil(t, New())
}

func TestAttestorName(t *testing.T) {
	assert.Equal(t, Name, New().Name())
}

func TestAttestorType(t *testing.T) {
	assert.Equal(t, Type, New().Type())
}

func TestAttestorRunType(t *testing.T) {
	assert.Equal(t, RunType, New().RunType())
}

func TestAttestorSchema(t *testing.T) {
	assert.NotNil(t, New().Schema())
}

func TestAttest_NoProducts(t *testing.T) {
	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)

	err = a.Attest(ctx)
	assert.Error(t, err)
}

func TestAttest_ValidReport(t *testing.T) {
	report := sampleReport()
	dir, path := writeReportFile(t, report)

	a := New()
	a.ClusterName = "test-cluster"

	_ = contextWithProduct(t, dir, path, a)

	assert.Equal(t, path, a.ReportFile)
	assert.Equal(t, "1", a.Version)
	assert.Equal(t, 1, a.Summary.TotalPass)
	assert.Equal(t, 1, a.Summary.TotalFail)
	assert.Equal(t, 1, a.Summary.TotalWarn)
	require.Len(t, a.Summary.FailedChecks, 1)
	assert.Equal(t, "1.1.2", a.Summary.FailedChecks[0].ID)
	require.Len(t, a.Summary.WarnedChecks, 1)
	assert.Equal(t, "1.1.3", a.Summary.WarnedChecks[0].ID)
}

func TestAttest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json at all"), 0600))

	a := New()
	// contextWithProduct runs all attestors; errors are swallowed by the runner.
	// Instead call Attest directly with a context that has the bad product.
	hashes := defaultHashes()
	digest, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	require.NoError(t, err)

	prod := &fakeProducer{
		products: map[string]attestation.Product{
			path: {MimeType: "application/json", Digest: digest},
		},
	}
	ctx, err := attestation.NewContext("test", []attestation.Attestor{prod},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	err = a.Attest(ctx)
	assert.Error(t, err)
}

func TestAttest_NoControlsArray(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"Controls":[],"Totals":{}}`), 0600))

	hashes := defaultHashes()
	digest, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	require.NoError(t, err)

	prod := &fakeProducer{
		products: map[string]attestation.Product{
			path: {MimeType: "application/json", Digest: digest},
		},
	}
	ctx, err := attestation.NewContext("test", []attestation.Attestor{prod},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	a := New()
	err = a.Attest(ctx)
	assert.Error(t, err)
}

func TestSubjects_AllFields(t *testing.T) {
	a := New()
	a.Version = "1.8"
	a.ClusterName = "prod-cluster"
	a.NodeHostname = "node-1"

	subjects := a.Subjects()

	assert.Contains(t, subjects, "benchmark:cis-kubernetes-1.8")
	assert.Contains(t, subjects, "cluster:prod-cluster")
	assert.Contains(t, subjects, "node:node-1")
	// All subjects must have non-empty digest sets.
	for k, ds := range subjects {
		assert.NotEmpty(t, ds, "digest set for subject %q must not be empty", k)
	}
}

func TestSubjects_NoClusterName(t *testing.T) {
	a := New()
	a.Version = "1.8"
	a.ClusterName = ""
	a.NodeHostname = "node-1"

	subjects := a.Subjects()

	assert.Contains(t, subjects, "benchmark:cis-kubernetes-1.8")
	assert.Contains(t, subjects, "node:node-1")
	// No cluster subject when ClusterName is empty.
	for k := range subjects {
		assert.NotContains(t, k, "cluster:")
	}
}

func TestSubjects_NoVersion(t *testing.T) {
	a := New()
	a.ClusterName = "my-cluster"
	a.NodeHostname = "node-1"

	subjects := a.Subjects()

	// Falls back to unversioned benchmark key when Version is unset.
	assert.Contains(t, subjects, "benchmark:cis-kubernetes")
	assert.NotContains(t, subjects, "benchmark:cis-kubernetes-")
}

func TestClusterNameFromEnv(t *testing.T) {
	t.Setenv(envClusterName, "env-cluster")
	a := New()
	assert.Equal(t, "env-cluster", a.ClusterName)
}
