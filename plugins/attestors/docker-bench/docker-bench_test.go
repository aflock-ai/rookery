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

package dockerbench

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
// exposes it to PostProduct attestors.
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
func writeReportFile(t *testing.T, report DockerBenchReport) (dir, path string) {
	t.Helper()
	data, err := json.Marshal(report)
	require.NoError(t, err)
	dir = t.TempDir()
	path = filepath.Join(dir, "docker-bench.json")
	require.NoError(t, os.WriteFile(path, data, 0600))
	return
}

// contextWithProduct creates an AttestationContext whose products include the
// file at path so that PostProduct attestors can discover it, then runs all
// attestors so the product map is populated.
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

// sampleReport returns a minimal valid docker-bench-security JSON report.
func sampleReport() DockerBenchReport {
	return DockerBenchReport{
		ID:   "docker-bench-security",
		Desc: "CIS Docker Benchmark v1.6.0",
		Results: []CheckResult{
			{
				ID:     "1.1.1",
				Desc:   "Ensure a separate partition for containers has been created",
				Result: "WARN",
			},
			{
				ID:     "2.1",
				Desc:   "Run the Docker daemon as a non-root user, if possible",
				Result: "INFO",
			},
			{
				ID:     "4.1",
				Desc:   "Ensure that a user for the container has been created",
				Result: "PASS",
			},
			{
				ID:     "5.1",
				Desc:   "Ensure that, if applicable, an AppArmor Profile is enabled",
				Result: "WARN",
				Details: "abc123def456 xyz789abc012",
			},
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
	_ = contextWithProduct(t, dir, path, a)

	assert.Equal(t, path, a.ReportFile)
	assert.Equal(t, "docker-bench-security", a.BenchmarkID)
	assert.Equal(t, "v1.6.0", a.Version)
	assert.Equal(t, 4, a.Summary.TotalChecks)
	assert.Equal(t, 1, a.Summary.TotalPass)
	assert.Equal(t, 2, a.Summary.TotalWarn)
	assert.Equal(t, 1, a.Summary.TotalInfo)
	assert.Equal(t, 0, a.Summary.TotalNote)
	require.Len(t, a.Summary.FailedChecks, 2)
	assert.Equal(t, "1.1.1", a.Summary.FailedChecks[0].ID)
	assert.Equal(t, "5.1", a.Summary.FailedChecks[1].ID)
}

func TestAttest_ContainerIDExtraction(t *testing.T) {
	report := DockerBenchReport{
		ID:   "docker-bench-security",
		Desc: "CIS Docker Benchmark",
		Results: []CheckResult{
			{
				ID:      "5.2",
				Desc:    "Ensure SELinux security options are set if applicable",
				Result:  "WARN",
				Details: "abc123def456 deadbeefcafe Running containers without security profiles",
			},
		},
	}
	dir, path := writeReportFile(t, report)
	a := New()
	_ = contextWithProduct(t, dir, path, a)

	assert.Contains(t, a.ContainerIDs, "abc123def456")
	assert.Contains(t, a.ContainerIDs, "deadbeefcafe")
}

func TestAttest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(path, []byte("not json at all"), 0600))

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

func TestAttest_WrongDescFormat(t *testing.T) {
	// A valid JSON file that does not have the CIS Docker Benchmark Desc should
	// be rejected by the attestor.
	report := DockerBenchReport{
		ID:      "something-else",
		Desc:    "Not a Docker benchmark",
		Results: []CheckResult{{ID: "1.1", Desc: "foo", Result: "PASS"}},
	}
	dir, path := writeReportFile(t, report)

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

func TestAttest_EmptyResults(t *testing.T) {
	report := DockerBenchReport{
		ID:      "docker-bench-security",
		Desc:    "CIS Docker Benchmark",
		Results: []CheckResult{},
	}
	dir, path := writeReportFile(t, report)

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

func TestSubjects_WithVersion(t *testing.T) {
	a := New()
	a.Version = "v1.6.0"
	a.ContainerIDs = []string{"abc123def456"}

	subjects := a.Subjects()

	assert.Contains(t, subjects, "benchmark:cis-docker-1.6.0")
	assert.Contains(t, subjects, "container:abc123def456")
	for k, ds := range subjects {
		assert.NotEmpty(t, ds, "digest set for subject %q must not be empty", k)
	}
}

func TestSubjects_NoVersion(t *testing.T) {
	a := New()

	subjects := a.Subjects()

	assert.Contains(t, subjects, "benchmark:cis-docker")
	assert.NotContains(t, subjects, "benchmark:cis-docker-")
}

func TestSubjects_NoContainers(t *testing.T) {
	a := New()
	a.Version = "v1.6.0"

	subjects := a.Subjects()

	assert.Len(t, subjects, 1)
	assert.Contains(t, subjects, "benchmark:cis-docker-1.6.0")
}

func TestExtractContainerIDs(t *testing.T) {
	tests := []struct {
		name    string
		details string
		want    []string
	}{
		{
			name:    "two container IDs",
			details: "abc123def456 deadbeefcafe some other text",
			want:    []string{"abc123def456", "deadbeefcafe"},
		},
		{
			name:    "no container IDs",
			details: "no hex strings here at all",
			want:    nil,
		},
		{
			name:    "short token ignored",
			details: "abc123 too short",
			want:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContainerIDs(tt.details)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsHex(t *testing.T) {
	assert.True(t, isHex("abc123def456"))
	assert.True(t, isHex("DEADBEEFCAFE"))
	assert.False(t, isHex("not-hex-str!"))
	assert.False(t, isHex("abc123defXYZ"))
}

func TestUnique(t *testing.T) {
	input := []string{"a", "b", "a", "c", "b"}
	got := unique(input)
	assert.ElementsMatch(t, []string{"a", "b", "c"}, got)
}
