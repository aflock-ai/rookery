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
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Stream records as golang.org/x/vuln emits them. The progress texts are the
// constants in x/vuln internal/vulncheck/vulncheck.go:20-22, unchanged from
// v1.1.1 through v1.8.0; the SBOM record exists from v1.1.4
// (internal/govulncheck/govulncheck.go:42).
func cfgRecord(version, mode string) string {
	return fmt.Sprintf(`{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck",`+
		`"scanner_version":%q,"db":"https://vuln.go.dev","go_version":"go1.26.3","scan_level":"symbol","scan_mode":%q}}`,
		version, mode)
}

const (
	sbomWithRoot    = `{"SBOM":{"go_version":"go1.26.3","modules":[{"path":"example.com/app"},{"path":"stdlib","version":"v1.26.3"}],"roots":["example.com/app"]}}`
	sbomNoRoot      = `{"SBOM":{"go_version":"go1.26.3","modules":[{"path":"golang.org/x/text","version":"v0.3.7"},{"path":"stdlib","version":"v1.26.3"}]}}`
	progFetching    = `{"progress":{"message":"Fetching vulnerabilities from the database..."}}`
	progCheckSource = `{"progress":{"message":"Checking the code against the vulnerabilities..."}}`
	progCheckBinary = `{"progress":{"message":"Checking the binary against the vulnerabilities..."}}`
	progScanBinary  = `{"progress":{"message":"Scanning your binary for known vulnerabilities..."}}`
	osvRecord       = `{"osv":{"id":"GO-2022-1059","summary":"Denial of service via crafted Accept-Language header in golang.org/x/text/language"}}`
)

func attestStream(t *testing.T, records ...string) (*Attestor, error) {
	t.Helper()
	tmp := t.TempDir()
	// govulncheck indents every record (x/vuln internal/govulncheck/jsonhandler.go:22).
	// One record per line would sniff as NDJSON, which the product attestor
	// never offers this attestor, and every case would pass for the wrong reason.
	var stream bytes.Buffer
	for _, r := range records {
		require.NoError(t, json.Indent(&stream, []byte(r), "", "  "))
		stream.WriteByte('\n')
	}
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vulns.json"), stream.Bytes(), 0o644))
	gv := New()
	// The scanner exited 0: this test is about what the stream shows, and the
	// exit status half of completion is TestAttest_CompletionNeedsTheScannersExitStatus.
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{exits("0"), product.New(), gv},
		attestation.WithWorkingDir(tmp))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	for _, c := range ctx.CompletedAttestors() {
		if c.Attestor.Name() == Name {
			return gv, c.Error
		}
	}
	t.Fatalf("govulncheck attestor did not run")
	return nil, nil
}

// TestAttest_ScanCompletionIsReadFromTheCheckingRecord pins how the attestor
// tells a completed govulncheck scan from a failed one. govulncheck emits its
// SBOM record BEFORE it fetches the vulnerability database
// (x/vuln internal/vulncheck/source.go:60 then :64-68; binary.go:59 then
// :63-67), so SBOM roots do not prove the scan ran: a database fetch failure,
// the most common CI failure, leaves roots in the stream and used to be signed
// as totalFindings 0. The record that proves the check phase was reached is
// the post-fetch "Checking the code/binary against the vulnerabilities..."
// progress record (source.go:78, binary.go:77; line numbers at v1.1.4 and v1.8.0).
//
// The same record also fixes the two false refusals a roots rule causes: a
// completed v1.1.1-v1.1.3 scan (no SBOM record exists before v1.1.4) and a
// completed binary scan of a binary with no main module (bin.SBOM() sets Roots
// only when bin.Main is set, binary.go:212).
func TestAttest_ScanCompletionIsReadFromTheCheckingRecord(t *testing.T) {
	cases := []struct {
		name    string
		records []string
		// wantErr empty means the stream must be attested.
		wantErr []string
	}{
		{
			name:    "v1.1.4 source scan whose vulnerability fetch failed",
			records: []string{cfgRecord("v1.1.4", "source"), sbomWithRoot, progFetching},
			wantErr: []string{"did not complete", "vulns.json", "vulnerability database"},
		},
		{
			name:    "v1.8.0 binary scan whose vulnerability fetch failed",
			records: []string{cfgRecord("v1.8.0", "binary"), progScanBinary, sbomWithRoot, progFetching},
			wantErr: []string{"did not complete", "vulns.json", "vulnerability database"},
		},
		{
			name:    "v1.1.4 source scan that failed loading packages",
			records: []string{cfgRecord("v1.1.4", "source")},
			wantErr: []string{"did not complete", "vulns.json", "SBOM"},
		},
		{
			name:    "v1.1.3 completed source scan with no SBOM record",
			records: []string{cfgRecord("v1.1.3", "source"), progFetching, osvRecord, progCheckSource},
		},
		{
			name:    "v1.1.3 source scan whose vulnerability fetch failed",
			records: []string{cfgRecord("v1.1.3", "source"), progFetching},
			wantErr: []string{"did not complete", "vulnerability database"},
		},
		{
			name:    "v1.1.4 completed binary scan of a binary with no main module",
			records: []string{cfgRecord("v1.1.4", "binary"), progScanBinary, sbomNoRoot, progFetching, osvRecord, progCheckBinary},
		},
		{
			name:    "development build that reached the checking record",
			records: []string{cfgRecord("v0.0.0-709015412431-20260908135242", "source"), sbomWithRoot, progFetching, progCheckSource},
		},
		{
			name:    "v1.0.4 stream carries no completion record",
			records: []string{cfgRecord("v1.0.4", "source"), osvRecord},
			wantErr: []string{"v1.0.4", "v1.1.1", "cannot tell a completed scan from a failed one", "upgrade govulncheck"},
		},
		{
			name:    "unversioned stream carries no completion record",
			records: []string{cfgRecord("", "source"), sbomWithRoot},
			wantErr: []string{"cannot tell a completed scan from a failed one", "upgrade govulncheck"},
		},
		{
			name:    "binary scan must carry the binary checking record, not the source one",
			records: []string{cfgRecord("v1.1.4", "binary"), sbomWithRoot, progFetching, progCheckSource},
			wantErr: []string{"did not complete"},
		},
		{
			name:    "query mode looks up ids and scans no code",
			records: []string{cfgRecord("v1.1.4", "query"), osvRecord},
			wantErr: []string{`scan_mode "query"`, "scans no code"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gv, err := attestStream(t, tc.records...)
			if len(tc.wantErr) == 0 {
				require.NoError(t, err)
				assert.Equal(t, "vulns.json", gv.ReportFile)
				assert.Len(t, gv.Report, len(tc.records))
				return
			}
			require.Error(t, err, "an incomplete scan must not be attested as zero findings")
			assert.False(t, attestation.IsSoftError(err), "a failed scan must be fatal, not a soft skip")
			assert.False(t, attestation.EvidenceIsRecordable(err), "the failed scan's payload must be dropped")
			for _, want := range tc.wantErr {
				assert.Contains(t, err.Error(), want)
			}
			assert.Empty(t, gv.ReportFile, "no report may be recorded from an incomplete scan")
		})
	}
}
