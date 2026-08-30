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

package secretscan

import (
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// GitHub classic PAT shapes gitleaks flags with no entropy gate. Built by
// concatenation so this file itself doesn't carry the literals.
var (
	fakePAT  = "ghp_" + "1234567890abcdefghij" + "ABCDEFGHIJ123456"
	fakePAT2 = "ghp_" + "zyxwvutsrqponmlkjihg" + "ZYXWVUTSRQ987654"
)

func gitleaksReport(secret string) string {
	return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[{"ruleId":"github-pat","message":{"text":"` + secret + `"},"locations":[{"physicalLocation":{"region":{"snippet":{"text":"token = ` + secret + `"}}}}]}]}]}`
}

func runScan(t *testing.T, dir string, opts ...Option) *Attestor {
	t.Helper()
	prod := product.New()
	scan := New(opts...)
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{prod, scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return scan
}

func locations(a *Attestor) []string {
	out := make([]string, 0, len(a.Findings))
	for _, f := range a.Findings {
		out = append(out, f.Location+" ("+f.RuleID+")")
	}
	return out
}

func hasFindingIn(a *Attestor, file string) bool {
	for _, f := range a.Findings {
		if strings.Contains(f.Location, file) {
			return true
		}
	}
	return false
}

// TestScannerReportEchoesAreDeduplicated: a step like
//
//	cilock run -a sarif -a secretscan -- gitleaks detect --report-path gitleaks.sarif
//
// produces the scanner's own report as a product. That report QUOTES every
// secret it found, so scanning it naively "finds" each secret a second time,
// located in `product:gitleaks.sarif` — a cold-start user saw 7 findings that
// were all echoes of the report they had just generated.
//
// The report is still scanned (nothing in it is trusted); afterwards a
// finding inside it is dropped only if the report declares that rule AND the
// same (rule, secret sha256) was found elsewhere. The report stays a subject
// and the dedup is recorded, pinned to the sha256 of the bytes parsed.
func TestScannerReportEchoesAreDeduplicated(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gitleaks.sarif"), []byte(gitleaksReport(fakePAT)), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("github_token: "+fakePAT+"\n"), 0o600))

	scan := runScan(t, dir)

	require.True(t, hasFindingIn(scan, "config.yaml"), "control: the token in config.yaml must be detected (findings=%v)", locations(scan))
	require.False(t, hasFindingIn(scan, "gitleaks.sarif"), "the report's echo of config.yaml's secret was double-counted: %v", locations(scan))

	subjects := scan.Subjects()
	_, reportIsSubject := subjects["product:gitleaks.sarif"]
	require.True(t, reportIsSubject, "the report was scanned and must remain a subject")

	require.Len(t, scan.ConsumedReports, 1)
	rep := scan.ConsumedReports[0]
	require.Equal(t, "gitleaks.sarif", rep.Path)
	require.Equal(t, "gitleaks", rep.Driver)
	require.Equal(t, 1, rep.Results)
	require.Equal(t, 1, rep.Deduplicated)
	require.Equal(t, subjects["product:gitleaks.sarif"][cryptoutil.DigestValue{Hash: crypto.SHA256}], rep.SHA256,
		"recorded sha256 must be the digest of the bytes parsed, equal to the product digest")
}

// TestReportClaimingScannerDriverStillFires: driver.name is attacker
// controlled. A product that calls itself a gitleaks report and carries a
// secret found NOWHERE else is a leak, not an echo: the finding is recorded
// in product:fake.sarif and --fail-on-detection fires.
func TestReportClaimingScannerDriverStillFires(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fake.sarif"), []byte(gitleaksReport(fakePAT2)), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README.md"), []byte("nothing to see\n"), 0o600))

	prod := product.New()
	scan := New(WithFailOnDetection(true))
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{prod, scan},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors()) // per-attestor errors are recorded on the completed legs
	var scanErr error
	for _, c := range ctx.CompletedAttestors() {
		if c.Attestor.Name() == scan.Name() {
			scanErr = c.Error
		}
	}
	require.Error(t, scanErr, "--fail-on-detection must fire on a secret that only a self-described report carries")
	require.True(t, attestation.IsDetectionError(scanErr), "got %T: %v", scanErr, scanErr)

	require.True(t, hasFindingIn(scan, "fake.sarif"), "the secret inside the self-described report must be a finding: %v", locations(scan))
	require.Len(t, scan.ConsumedReports, 1)
	require.Equal(t, 0, scan.ConsumedReports[0].Deduplicated)
	_, isSubject := scan.Subjects()["product:fake.sarif"]
	require.True(t, isSubject)
}

// TestSecretBearingFileNamedSarifIsScanned: a leak wearing a .sarif name is
// not SARIF at all; it is scanned like any product and stays a subject.
func TestSecretBearingFileNamedSarifIsScanned(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "x.sarif"), []byte("export GITHUB_TOKEN="+fakePAT+"\n"), 0o600))

	scan := runScan(t, dir)
	require.True(t, hasFindingIn(scan, "x.sarif"), "findings=%v", locations(scan))
	require.Empty(t, scan.ConsumedReports)
	_, isSubject := scan.Subjects()["product:x.sarif"]
	require.True(t, isSubject)
}

// TestReportChangedBetweenSnapshotAndScanIsNotAReport: the product attestor
// digested one file; by the time secretscan reads it the bytes differ. The
// sha256 of the bytes PARSED must equal the recorded product digest or the
// product is treated as ordinary — scanned, nothing deduplicated — because
// nothing pins what was parsed. Same when no digest was recorded at all.
func TestReportChangedBetweenSnapshotAndScanIsNotAReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gitleaks.sarif")
	require.NoError(t, os.WriteFile(path, []byte(gitleaksReport(fakePAT)), 0o600))
	snapshot, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	require.NoError(t, err)

	// Replace the file between the digest and the parse.
	require.NoError(t, os.WriteFile(path, []byte(gitleaksReport(fakePAT)+"\n"), 0o600))

	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)

	t.Run("digest mismatch", func(t *testing.T) {
		scan := New()
		findings, err := scan.scanProductBytes("gitleaks.sarif", path, attestation.Product{MimeType: "application/json", Digest: snapshot}, detector)
		require.NoError(t, err)
		require.NotEmpty(t, findings, "the product is still scanned")
		require.Empty(t, scan.ConsumedReports, "a file whose parsed bytes do not match the recorded digest must not be treated as a report")
	})

	t.Run("digest missing", func(t *testing.T) {
		scan := New()
		findings, err := scan.scanProductBytes("gitleaks.sarif", path, attestation.Product{MimeType: "application/json"}, detector)
		require.NoError(t, err)
		require.NotEmpty(t, findings)
		require.Empty(t, scan.ConsumedReports, "without a recorded digest nothing pins the parsed bytes")
	})

	t.Run("digest matches", func(t *testing.T) {
		current, err := cryptoutil.CalculateDigestSetFromFile(path, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
		require.NoError(t, err)
		scan := New()
		_, err = scan.scanProductBytes("gitleaks.sarif", path, attestation.Product{MimeType: "application/json", Digest: current}, detector)
		require.NoError(t, err)
		require.Len(t, scan.ConsumedReports, 1)
		require.Equal(t, current[cryptoutil.DigestValue{Hash: crypto.SHA256}], scan.ConsumedReports[0].SHA256)
	})
}

// TestNonSecretScannerSarifIsStillScanned: a gosec SARIF quoting a credential
// that appears nowhere else is a real finding location.
func TestNonSecretScannerSarifIsStillScanned(t *testing.T) {
	dir := t.TempDir()
	sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[{"ruleId":"G101","message":{"text":"hardcoded: ` + fakePAT + `"}}]}]}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "gosec.sarif"), []byte(sarif), 0o600))

	scan := runScan(t, dir)
	require.True(t, hasFindingIn(scan, "gosec.sarif"), "findings=%v", locations(scan))
	require.Len(t, scan.ConsumedReports, 1)
	require.Equal(t, 0, scan.ConsumedReports[0].Deduplicated)
	_, isSubject := scan.Subjects()["product:gosec.sarif"]
	require.True(t, isSubject)
}
