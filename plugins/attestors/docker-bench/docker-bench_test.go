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
	_ "embed"
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

// writeRawReport writes raw bytes (the REAL captured docker-bench-security JSON)
// to a temp file and returns its dir + path.
func writeRawReport(t *testing.T, raw []byte) (dir, path string) {
	t.Helper()
	dir = t.TempDir()
	path = filepath.Join(dir, "docker-bench.log.json")
	require.NoError(t, os.WriteFile(path, raw, 0600))
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

// sampleReport returns a minimal valid docker-bench-security JSON report in the
// REAL schema (version under "dockerbenchsecurity", sections under "tests").
func sampleReport() DockerBenchReport {
	return DockerBenchReport{
		DockerBenchSecurity: "1.6.0",
		Checks:              4,
		Score:               -1,
		Tests: []TestSection{
			{
				ID:   "1",
				Desc: "Host Configuration",
				Results: []CheckResult{
					{ID: "1.1.1", Desc: "Ensure a separate partition for containers has been created", Result: "WARN"},
					{ID: "2.1", Desc: "Run the Docker daemon as a non-root user, if possible", Result: "INFO"},
				},
			},
			{
				ID:   "5",
				Desc: "Container Runtime",
				Results: []CheckResult{
					{ID: "5.0", Desc: "Ensure that a user for the container has been created", Result: "PASS"},
					{
						ID:      "5.1",
						Desc:    "Ensure that, if applicable, an AppArmor Profile is enabled",
						Result:  "WARN",
						Details: "Containers with no AppArmorProfile:  app-1 app-2",
						Items:   []string{"app-1", "app-2"},
					},
				},
			},
		},
	}
}

// legacyReport returns a report in the LEGACY fallback shape (top-level
// "desc"/"results"), which the back-compat parser still accepts.
func legacyReport() DockerBenchReport {
	return DockerBenchReport{
		ID:   "docker-bench-security",
		Desc: "CIS Docker Benchmark v1.6.0",
		LegacyResults: []CheckResult{
			{ID: "1.1.1", Desc: "separate partition", Result: "WARN"},
			{ID: "2.1", Desc: "non-root daemon", Result: "INFO"},
			{ID: "4.1", Desc: "container user", Result: "PASS"},
			{ID: "5.1", Desc: "apparmor", Result: "WARN"},
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
	assert.Equal(t, "1.6.0", a.Version)
	assert.Equal(t, 4, a.Summary.TotalChecks)
	assert.Equal(t, 1, a.Summary.TotalPass)
	assert.Equal(t, 2, a.Summary.TotalWarn)
	assert.Equal(t, 1, a.Summary.TotalInfo)
	assert.Equal(t, 0, a.Summary.TotalNote)
	require.Len(t, a.Summary.FailedChecks, 2)
	assert.Equal(t, "1.1.1", a.Summary.FailedChecks[0].ID)
	assert.Equal(t, "5.1", a.Summary.FailedChecks[1].ID)
	// Container names come from the Container Runtime section (id "5") items.
	assert.Equal(t, []string{"app-1", "app-2"}, a.ContainerNames)
}

// TestAttest_LegacyFallback proves the back-compat parser still consumes the
// older top-level "desc"/"results" shape (so a pre-existing legacy report is not
// silently dropped), while the canonical fixture remains the REAL schema.
func TestAttest_LegacyFallback(t *testing.T) {
	report := legacyReport()
	dir, path := writeReportFile(t, report)

	a := New()
	_ = contextWithProduct(t, dir, path, a)

	assert.Equal(t, "docker-bench-security", a.BenchmarkID)
	assert.Equal(t, "v1.6.0", a.Version)
	assert.Equal(t, 4, a.Summary.TotalChecks)
	assert.Equal(t, 1, a.Summary.TotalPass)
	assert.Equal(t, 2, a.Summary.TotalWarn)
	assert.Equal(t, 1, a.Summary.TotalInfo)
}

//go:embed testdata/real-docker-bench.json
var realDockerBenchJSON []byte

// TestAttest_RealSchema drives the attestor against the REAL output of
// docker/docker-bench-security v1.3.4 (captured live and committed under
// testdata/). This is the ground-truth regression test for the parser bug: the
// real tool emits {"dockerbenchsecurity": "...", "tests": [{"results": [...]}]}
// with NO top-level desc/results and the literal "CIS Docker Benchmark" appears
// nowhere. The old top-level-DockerBenchReport parser rejects this with
// "no docker-bench report found in products"; the fixed parser must consume it.
func TestAttest_RealSchema(t *testing.T) {
	dir, path := writeRawReport(t, realDockerBenchJSON)

	a := New()
	_ = contextWithProduct(t, dir, path, a)

	assert.Equal(t, path, a.ReportFile)
	// Version derives from the top-level "dockerbenchsecurity" field.
	assert.Equal(t, "1.3.4", a.Version)
	assert.Equal(t, "docker-bench-security", a.BenchmarkID)

	// 105 checks across 7 sections: PASS=30 WARN=28 INFO=38 NOTE=9.
	assert.Equal(t, 105, a.Summary.TotalChecks)
	assert.Equal(t, 30, a.Summary.TotalPass)
	assert.Equal(t, 28, a.Summary.TotalWarn)
	assert.Equal(t, 38, a.Summary.TotalInfo)
	assert.Equal(t, 9, a.Summary.TotalNote)
	// Top-level rollup the tool itself reports.
	assert.Equal(t, 105, a.Summary.Checks)
	assert.Equal(t, 0, a.Summary.Score)
	// Every WARN is a failed check (28 WARN, 0 unknown statuses).
	assert.Len(t, a.Summary.FailedChecks, 28)

	// Container names are extracted from the Container Runtime section (id "5")
	// items — they are container NAMES, not 12-hex IDs. The throwaway
	// dbfix-sleep container plus the host's running containers must appear, and
	// the id:name / name:port forms must be normalized to the bare name.
	assert.Contains(t, a.ContainerNames, "dbfix-sleep")
	assert.Contains(t, a.ContainerNames, "k3d-lc-fixture-serverlb")
	assert.Contains(t, a.ContainerNames, "buildx_buildkit_multiarch0")
	// id:name form (5.29 docker0) must yield the name, not the 64-hex id.
	for _, n := range a.ContainerNames {
		assert.NotContains(t, n, ":", "container name %q must be normalized (no id:name / name:port)", n)
		assert.NotRegexp(t, "^[0-9a-f]{64}$", n, "container name %q must not be a raw container id", n)
	}
}

// TestSubjects_RealSchema proves both declared subject families are present on
// the real output: a benchmark: subject derived from the tool version, and a
// container: subject per running container.
func TestSubjects_RealSchema(t *testing.T) {
	dir, path := writeRawReport(t, realDockerBenchJSON)
	a := New()
	_ = contextWithProduct(t, dir, path, a)

	subjects := a.Subjects()
	assert.Contains(t, subjects, "benchmark:cis-docker@1.3.4")
	assert.Contains(t, subjects, "container:dbfix-sleep")
	for k, ds := range subjects {
		assert.NotEmpty(t, ds, "digest set for subject %q must not be empty", k)
	}
}

func TestAttest_ContainerNameExtraction(t *testing.T) {
	report := DockerBenchReport{
		DockerBenchSecurity: "1.3.4",
		Tests: []TestSection{
			{
				ID:   "4",
				Desc: "Container Images and Build File",
				Results: []CheckResult{
					// Section 4 items are IMAGE refs, not containers — must be ignored.
					{ID: "4.6", Desc: "healthcheck", Result: "WARN", Items: []string{"[alpine:3.20]", "[ubuntu:24.04]"}},
				},
			},
			{
				ID:   "5",
				Desc: "Container Runtime",
				Results: []CheckResult{
					{ID: "5.1", Desc: "apparmor", Result: "WARN", Items: []string{"web-app", "db"}},
					// id:name form must yield the name.
					{ID: "5.29", Desc: "docker0", Result: "INFO", Items: []string{"5e48fad4125ab8a2e64d35c8ede6ab91615279efc9e66523d6b8df40e85cd0f2:web-app"}},
					// name:port form must yield the name.
					{ID: "5.13", Desc: "wildcard bind", Result: "WARN", Items: []string{"db:0.0.0.0"}},
				},
			},
		},
	}
	dir, path := writeReportFile(t, report)
	a := New()
	_ = contextWithProduct(t, dir, path, a)

	// Only section-5 names, normalized and de-duped (web-app, db) — no image refs.
	assert.Equal(t, []string{"db", "web-app"}, a.ContainerNames)
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
	// A valid JSON file that is neither the real schema (no "dockerbenchsecurity"
	// + tests) nor the legacy CIS-Docker shape must be rejected.
	report := DockerBenchReport{
		ID:            "something-else",
		Desc:          "Not a Docker benchmark",
		LegacyResults: []CheckResult{{ID: "1.1", Desc: "foo", Result: "PASS"}},
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
	// Real schema with no sections, and a legacy desc with no results: neither
	// is a recognizable docker-bench report, so it must be rejected.
	report := DockerBenchReport{
		Desc:          "CIS Docker Benchmark",
		LegacyResults: []CheckResult{},
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
	a.Version = "1.6.0"
	a.ContainerNames = []string{"web-app"}

	subjects := a.Subjects()

	assert.Contains(t, subjects, "benchmark:cis-docker@1.6.0")
	assert.Contains(t, subjects, "container:web-app")
	for k, ds := range subjects {
		assert.NotEmpty(t, ds, "digest set for subject %q must not be empty", k)
	}
}

func TestSubjects_NoVersion(t *testing.T) {
	a := New()

	subjects := a.Subjects()

	assert.Contains(t, subjects, "benchmark:cis-docker")
	assert.NotContains(t, subjects, "benchmark:cis-docker@")
}

func TestSubjects_NoContainers(t *testing.T) {
	a := New()
	a.Version = "1.6.0"

	subjects := a.Subjects()

	assert.Len(t, subjects, 1)
	assert.Contains(t, subjects, "benchmark:cis-docker@1.6.0")
}

func TestNormalizeContainerName(t *testing.T) {
	tests := []struct {
		name string
		item string
		want string
	}{
		{"plain name", "dbfix-sleep", "dbfix-sleep"},
		{"underscore name", "buildx_buildkit_multiarch0", "buildx_buildkit_multiarch0"},
		{"id:name keeps name", "5e48fad4125ab8a2e64d35c8ede6ab91615279efc9e66523d6b8df40e85cd0f2:dbfix-sleep", "dbfix-sleep"},
		{"name:ip keeps name", "k3d-lc-fixture-serverlb:0.0.0.0", "k3d-lc-fixture-serverlb"},
		{"empty", "", ""},
		{"whitespace trimmed", "  app-1 ", "app-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, normalizeContainerName(tt.item))
		})
	}
}

func TestIsHex(t *testing.T) {
	assert.True(t, isHex("abc123def456"))
	assert.True(t, isHex("DEADBEEFCAFE"))
	assert.False(t, isHex("not-hex-str!"))
	assert.False(t, isHex("abc123defXYZ"))
	assert.False(t, isHex(""))
}
