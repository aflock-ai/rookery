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

package trivy

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetadata pins the registration surface — the strings here are what
// consumers pass to --attestations and what verifiers match on the
// predicate type. Don't change without a major version bump.
func TestMetadata(t *testing.T) {
	a := New()
	assert.Equal(t, "trivy", a.Name())
	assert.Equal(t, Name, a.Name())
	assert.Equal(t, "https://aflock.ai/attestations/trivy/v0.1", a.Type())
	assert.Equal(t, Type, a.Type())
	assert.Equal(t, attestation.PostProductRunType, a.RunType())
	assert.Equal(t, RunType, a.RunType())
}

// TestParse_FSVulnFixture verifies the npm-on-filesystem fixture parses
// and produces the expected summary. Generated from a real `trivy fs`
// scan of a package-lock.json containing axios 0.21.0 + lodash 4.17.4.
func TestParse_FSVulnFixture(t *testing.T) {
	report := loadReport(t, "testdata/trivy-fs-vuln.json")

	require.Equal(t, 2, report.SchemaVersion)
	assert.Equal(t, "filesystem", report.ArtifactType)
	assert.Equal(t, ".", report.ArtifactName)
	// Filesystem scans of pure source trees emit an empty Metadata
	// object — defend that this is harmless.
	assert.Empty(t, report.Metadata.OS.Family)
	assert.Empty(t, report.Metadata.ImageID)

	require.Len(t, report.Results, 1)
	r := report.Results[0]
	assert.Equal(t, "package-lock.json", r.Target)
	assert.Equal(t, "lang-pkgs", r.Class)
	assert.Equal(t, "npm", r.Type)
	require.NotEmpty(t, r.Vulnerabilities)

	summary := buildSummary(report)
	assert.Equal(t, ".", summary.ArtifactName)
	assert.Equal(t, "filesystem", summary.ArtifactType)
	assert.Equal(t, 2, summary.SchemaVersion)
	// All vulnerabilities are failures in Trivy's model.
	assert.Equal(t, len(r.Vulnerabilities), summary.VulnCount)
	assert.Equal(t, 0, summary.MisconfigCount)
	assert.Equal(t, 0, summary.SecretCount)
	assert.Len(t, summary.FailedFindings, summary.VulnCount)
	// PURL should round-trip into the resourceId of every failed finding.
	for _, ff := range summary.FailedFindings {
		assert.Equal(t, "lang-pkgs", ff.Class)
		assert.NotEmpty(t, ff.ID, "VulnerabilityID must be set")
		assert.NotEmpty(t, ff.ResourceID, "PURL should populate resourceId")
	}
	// Sanity-check that BySeverity sums match VulnCount.
	totalSeverityFail := 0
	for _, sc := range summary.BySeverity {
		totalSeverityFail += sc.Fail
	}
	assert.Equal(t, summary.VulnCount, totalSeverityFail)
}

// TestParse_ImageMultiFixture exercises the canonical container image
// scan fixture from the upstream Trivy integration tests (alpine 3.9
// with a known set of OS package CVEs).
func TestParse_ImageMultiFixture(t *testing.T) {
	report := loadReport(t, "testdata/trivy-image-multi.json")

	require.Equal(t, 2, report.SchemaVersion)
	assert.Equal(t, "container_image", report.ArtifactType)
	assert.Equal(t, "alpine", report.Metadata.OS.Family)
	assert.Equal(t, "3.9.4", report.Metadata.OS.Name)
	assert.NotEmpty(t, report.Metadata.ImageID)
	assert.NotEmpty(t, report.Metadata.RepoTags)

	require.Len(t, report.Results, 1)
	r := report.Results[0]
	assert.Equal(t, "os-pkgs", r.Class)
	assert.Equal(t, "alpine", r.Type)
	require.NotEmpty(t, r.Vulnerabilities)

	summary := buildSummary(report)
	assert.Equal(t, "alpine", summary.Metadata.OS.Family)
	assert.Equal(t, "3.9.4", summary.Metadata.OS.Name)
	assert.NotEmpty(t, summary.Metadata.ImageID)
	assert.Greater(t, summary.VulnCount, 0)
	// Every vuln in this fixture is at least MEDIUM severity.
	medFail := summary.BySeverity["medium"].Fail +
		summary.BySeverity["high"].Fail +
		summary.BySeverity["critical"].Fail
	assert.Greater(t, medFail, 0)
}

// TestParse_ConfigMisconfigFixture covers the Dockerfile-only misconfig
// path. This is the path where Status:"FAIL" matters — non-failing
// misconfigs shouldn't land in failedFindings.
func TestParse_ConfigMisconfigFixture(t *testing.T) {
	report := loadReport(t, "testdata/trivy-config-misconfig.json")

	require.Equal(t, 2, report.SchemaVersion)
	assert.Equal(t, "repository", report.ArtifactType)
	require.Len(t, report.Results, 1)
	r := report.Results[0]
	assert.Equal(t, "config", r.Class)
	assert.Equal(t, "dockerfile", r.Type)
	require.NotEmpty(t, r.Misconfigurations)

	summary := buildSummary(report)
	assert.Equal(t, len(r.Misconfigurations), summary.MisconfigCount)
	// The dockerfile fixture has one Status:"FAIL" misconfig → exactly
	// one failed finding.
	assert.Len(t, summary.FailedFindings, 1)
	ff := summary.FailedFindings[0]
	assert.Equal(t, "DS-0002", ff.ID)
	assert.Equal(t, "config", ff.Class)
	assert.Equal(t, "HIGH", ff.Severity)
	assert.Equal(t, "Dockerfile", ff.Target)
	// BySeverity rollup: this misconfig is HIGH and a failure.
	assert.Equal(t, 1, summary.BySeverity["high"].Fail)
}

// TestParse_SecretsFixture covers the secret-scanner output path.
func TestParse_SecretsFixture(t *testing.T) {
	report := loadReport(t, "testdata/trivy-secrets.json")

	require.Equal(t, 2, report.SchemaVersion)
	require.Len(t, report.Results, 1)
	r := report.Results[0]
	assert.Equal(t, "secret", r.Class)
	require.NotEmpty(t, r.Secrets)

	summary := buildSummary(report)
	assert.Equal(t, len(r.Secrets), summary.SecretCount)
	assert.Len(t, summary.FailedFindings, summary.SecretCount)
	for _, ff := range summary.FailedFindings {
		assert.Equal(t, "secret", ff.Class)
		assert.NotEmpty(t, ff.ID, "RuleID must populate failed finding ID")
		assert.Equal(t, ff.ID, ff.ResourceID, "secret ResourceID should mirror RuleID")
	}
	// AWS access key in the fixture is CRITICAL.
	assert.Greater(t, summary.BySeverity["critical"].Fail, 0)
}

// TestParse_RejectsBadInput surfaces the rejection criteria so callers
// know to expect specific errors rather than silent failures.
func TestParse_RejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "invalid-json", body: `{not json`},
		{name: "top-level-array", body: `[1,2,3]`},
		{name: "missing-schema-version", body: `{"ArtifactType": "filesystem"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseTrivyReport([]byte(tc.body))
			require.Error(t, err)
		})
	}
}

// TestValidate_RejectsUnsupportedSchema confirms that older Trivy v1
// reports are flagged rather than misparsed. Real-world v1 reports were
// arrays at the top level; this synthetic input covers the case where
// someone hand-rolls a Trivy report with the wrong schema number.
func TestValidate_RejectsUnsupportedSchema(t *testing.T) {
	r := &Report{SchemaVersion: 1, ArtifactType: "filesystem"}
	err := validateTrivyReport(r)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SchemaVersion")
}

// TestAttest_HappyPath runs the full Attestor lifecycle against the
// fs-vuln fixture: product attestor classifies the file, trivy attestor
// reads it, builds the summary, and stores the report. After Attest, the
// embedded Report bytes must round-trip cleanly (byte equality is the
// contract the json.RawMessage field promises).
func TestAttest_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	srcBytes, err := os.ReadFile("testdata/trivy-fs-vuln.json")
	require.NoError(t, err)
	dst := filepath.Join(tmp, "trivy-report.json")
	require.NoError(t, os.WriteFile(dst, srcBytes, 0o644))

	a := New()
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, a},
		attestation.WithWorkingDir(tmp))
	require.NoError(t, err)

	require.NoError(t, ctx.RunAttestors())

	// Summary populated from the report.
	assert.Equal(t, "filesystem", a.Summary.ArtifactType)
	assert.Equal(t, ".", a.Summary.ArtifactName)
	assert.Greater(t, a.Summary.VulnCount, 0)
	assert.Equal(t, "trivy-report.json", a.Summary.ReportFile)
	assert.NotEmpty(t, a.Summary.ReportDigestSet)

	// Embedded report is byte-equal to the input.
	assert.JSONEq(t, string(srcBytes), string(a.Report))

	// Subjects must include the artifact identifier and at least one CVE.
	subs := a.Subjects()
	assert.Contains(t, subs, "trivy:artifact:.")
	hasCVE := false
	for k := range subs {
		if len(k) > len("trivy:cve:") && k[:len("trivy:cve:")] == "trivy:cve:" {
			hasCVE = true
			break
		}
	}
	assert.True(t, hasCVE, "expected at least one trivy:cve:* subject")
}

// TestAttest_NoProducts surfaces the empty-context error to callers so
// misconfiguration fails loudly rather than producing an empty
// attestation.
func TestAttest_NoProducts(t *testing.T) {
	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a},
		attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	err = a.Attest(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no products")
}

// TestAttest_NonTrivyProduct verifies that a non-Trivy JSON file is
// skipped rather than mis-attested. RunAttestors doesn't propagate
// per-attestor errors, so the contract here is "Report stays empty."
func TestAttest_NonTrivyProduct(t *testing.T) {
	tmp := t.TempDir()
	// Valid JSON but missing SchemaVersion → not a Trivy report.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "other.json"),
		[]byte(`{"hello": "world"}`), 0o644))

	a := New()
	p := product.New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, a},
		attestation.WithWorkingDir(tmp))
	require.NoError(t, err)

	_ = ctx.RunAttestors()
	assert.Empty(t, a.Summary.ReportFile)
	assert.Empty(t, a.Report)
}

// TestSubjects_IncludesMisconfigResources confirms the resource-ID
// branch of Subjects() — misconfig findings with a CauseMetadata.Resource
// produce trivy:resource:* subjects. The dockerfile fixture has an empty
// Resource, so we hand-build a Summary to exercise this path.
func TestSubjects_IncludesMisconfigResources(t *testing.T) {
	a := New()
	a.Summary = Summary{
		ArtifactName: "kustomize-overlay",
		FailedFindings: []FailedFinding{
			{Class: "config", ID: "AVD-KSV-0001", ResourceID: "Deployment/web"},
			{Class: "config", ID: "AVD-KSV-0002", ResourceID: "Deployment/web"}, // dup → coalesced
			{Class: "vuln", ID: "CVE-2024-1234", ResourceID: "pkg:npm/foo@1"},
		},
	}
	subs := a.Subjects()
	assert.Contains(t, subs, "trivy:artifact:kustomize-overlay")
	assert.Contains(t, subs, "trivy:resource:Deployment/web")
	assert.Contains(t, subs, "trivy:cve:CVE-2024-1234")
}

// TestSubjects_ImageScanEmitsRepoDigest proves the container_image path:
// every well-formed Metadata.RepoDigests entry becomes an imagedigest:<hex>
// subject whose DigestSet carries the REAL manifest digest (oci convention)
// — not a sha256 of the name string like the trivy:* label subjects — so
// the verdict shares graph edges with the docker/oci attestors.
func TestSubjects_ImageScanEmitsRepoDigest(t *testing.T) {
	report := loadReport(t, "testdata/fixtures/image-repodigest/trivy-results.json")
	require.Equal(t, "container_image", report.ArtifactType)

	a := New()
	a.Summary = buildSummary(report)
	subs := a.Subjects()

	const manifestHex = "e2f2d2eb1c8b1c4e9c7a09a5b83d1e2f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d"
	key := "imagedigest:" + manifestHex
	require.Contains(t, subs, key)
	assert.Equal(t,
		cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: manifestHex},
		subs[key],
		"imagedigest subject must carry the raw manifest digest as its value")

	// ImageID is the image CONFIG digest, not the manifest digest — it must
	// never become an imagedigest subject.
	const configHex = "0d17b565c37bcbd895e9d92315a05c1c3c9a29f762b011a10c54a66cd53c9b31"
	assert.NotContains(t, subs, "imagedigest:"+configHex,
		"Metadata.ImageID (config digest) must not be emitted as an imagedigest subject")

	// The join-by-name label subjects are unchanged.
	assert.Contains(t, subs, "trivy:artifact:registry.example.com/acme/api:1.4.2")
	assert.Contains(t, subs, "trivy:cve:CVE-2024-6119")
}

// TestSubjects_NonImageScansEmitNoImageDigest: filesystem and repository
// scans have no image identity — they must not emit imagedigest subjects.
func TestSubjects_NonImageScansEmitNoImageDigest(t *testing.T) {
	for _, path := range []string{
		"testdata/trivy-fs-vuln.json",          // ArtifactType: filesystem
		"testdata/trivy-config-misconfig.json", // ArtifactType: repository
	} {
		report := loadReport(t, path)
		require.NotEqual(t, "container_image", report.ArtifactType)

		a := New()
		a.Summary = buildSummary(report)
		for k := range a.Subjects() {
			assert.False(t, strings.HasPrefix(k, "imagedigest:"),
				"%s: non-image scan must not emit imagedigest subject %q", path, k)
		}
	}
}

// TestSubjects_StrayRepoDigestsOnNonImageScanIgnored: even if a non-image
// report carries RepoDigests metadata, no imagedigest subjects are emitted —
// the gate is ArtifactType, not the mere presence of the field.
func TestSubjects_StrayRepoDigestsOnNonImageScanIgnored(t *testing.T) {
	a := New()
	a.Summary = Summary{
		ArtifactName: ".",
		ArtifactType: "filesystem",
		Metadata: MetadataSummary{
			RepoDigests: []string{"acme/api@sha256:" + strings.Repeat("ab", 32)},
		},
	}
	for k := range a.Subjects() {
		assert.False(t, strings.HasPrefix(k, "imagedigest:"),
			"filesystem scan must not emit imagedigest subject %q", k)
	}
}

// TestSubjects_RepoDigestStrictValidation: only entries whose payload is
// exactly 64 lowercase hex chars after "@sha256:" (the OCI digest grammar)
// become subjects; everything malformed is skipped, never mangled.
func TestSubjects_RepoDigestStrictValidation(t *testing.T) {
	valid := strings.Repeat("ab", 32) // 64 lowercase hex chars
	a := New()
	a.Summary = Summary{
		ArtifactName: "acme/api:1",
		ArtifactType: "container_image",
		Metadata: MetadataSummary{
			RepoDigests: []string{
				"acme/api@sha256:" + valid,                  // well-formed → kept
				"acme/api@sha256:" + valid[:63],             // too short → skipped
				"acme/api@sha256:" + valid + "ab",           // too long → skipped
				"acme/api@sha256:" + strings.ToUpper(valid), // uppercase → skipped (OCI is lowercase)
				"acme/api@sha256:" + valid[:63] + "g",       // non-hex char → skipped
				"acme/api@md5:abc",                          // wrong algorithm → skipped
				"@sha256:" + valid,                          // empty repo → skipped
				"noseparator",                               // no @sha256: → skipped
			},
		},
	}

	subs := a.Subjects()
	var digestKeys []string
	for k := range subs {
		if strings.HasPrefix(k, "imagedigest:") {
			digestKeys = append(digestKeys, k)
		}
	}
	require.Len(t, digestKeys, 1, "exactly one well-formed RepoDigests entry must survive")
	assert.Equal(t, "imagedigest:"+valid, digestKeys[0])
}

func loadReport(t *testing.T, path string) *Report {
	t.Helper()
	bytes, err := os.ReadFile(path) //nolint:gosec // fixed test fixture path
	require.NoError(t, err)
	r, err := parseTrivyReport(bytes)
	require.NoError(t, err)
	require.NoError(t, validateTrivyReport(r))
	return r
}

// TestSummary_JSONShape pins the wire format the predicate ends up in.
// Downstream rego policies key on these field names — renaming any of
// them is a breaking change requiring a predicate version bump.
func TestSummary_JSONShape(t *testing.T) {
	s := Summary{
		ArtifactName:  "alpine:3.18",
		ArtifactType:  "container_image",
		SchemaVersion: 2,
		BySeverity: map[string]SeverityCounts{
			"high": {Pass: 0, Fail: 3},
		},
		FailedFindings: []FailedFinding{
			{ID: "CVE-2024-1", Class: "os-pkgs", Severity: "HIGH"},
		},
	}
	out, err := json.Marshal(s)
	require.NoError(t, err)

	var roundtrip map[string]any
	require.NoError(t, json.Unmarshal(out, &roundtrip))
	for _, want := range []string{
		"artifactName", "artifactType", "schemaVersion", "metadata",
		"vulnCount", "misconfigCount", "secretCount", "licenseCount",
		"bySeverity", "failedFindings", "reportFile", "reportDigestSet",
	} {
		_, ok := roundtrip[want]
		assert.True(t, ok, "summary must serialize %q field", want)
	}
}
