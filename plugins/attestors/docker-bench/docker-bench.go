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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "docker-bench"
	Type    = "https://aflock.ai/attestations/docker-bench/v0.1"
	RunType = attestation.PostProductRunType

	// cisDockerDesc is the expected description prefix for a docker-bench report.
	cisDockerDesc = "CIS Docker Benchmark"
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}

	mimeTypes = []string{"text/plain", "application/json"}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// CheckResult is a single result entry produced by docker-bench-security --json.
type CheckResult struct {
	ID      string `json:"id"`
	Desc    string `json:"desc"`
	Result  string `json:"result"`  // PASS | WARN | INFO | NOTE
	Details string `json:"details,omitempty"`
}

// DockerBenchReport is the top-level structure produced by docker-bench-security
// when invoked with the --json flag.
type DockerBenchReport struct {
	ID      string        `json:"id"`
	Desc    string        `json:"desc"`
	Results []CheckResult `json:"results"`
}

// FailedCheck records a single non-passing check in the attestation summary.
type FailedCheck struct {
	ID     string `json:"id"`
	Desc   string `json:"desc"`
	Result string `json:"result"`
}

// Summary contains the roll-up data stored in the attestation.
type Summary struct {
	TotalChecks  int           `json:"total_checks"`
	TotalPass    int           `json:"total_pass"`
	TotalWarn    int           `json:"total_warn"`
	TotalInfo    int           `json:"total_info"`
	TotalNote    int           `json:"total_note"`
	FailedChecks []FailedCheck `json:"failed_checks,omitempty"`
}

// Attestor captures docker-bench-security CIS Docker Benchmark results.
type Attestor struct {
	// ReportFile is the path of the docker-bench JSON output file.
	ReportFile string `json:"report_file"`
	// ReportDigestSet is the cryptographic digest of the report file.
	ReportDigestSet cryptoutil.DigestSet `json:"report_digest_set"`
	// BenchmarkID is the top-level ID field from the report (e.g. "docker-bench-security").
	BenchmarkID string `json:"benchmark_id,omitempty"`
	// Version is derived from the Desc field by stripping the common prefix.
	// docker-bench does not always emit an explicit version field; when present
	// it appears in the Desc as "CIS Docker Benchmark v1.6.0".
	Version string `json:"version,omitempty"`
	// ContainerIDs lists container IDs found in failing check details.
	ContainerIDs []string `json:"container_ids,omitempty"`
	// Summary contains aggregated pass/warn/info/note counts and failed check details.
	Summary Summary `json:"summary"`

	hashes []cryptoutil.DigestValue
	report *DockerBenchReport
}

// New creates a new docker-bench Attestor.
func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

// Attest scans the attestation context products for a valid docker-bench JSON
// report, parses it, and populates the attestor fields.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	a.hashes = ctx.Hashes()
	return a.getCandidate(ctx)
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	for path, product := range products {
		if product.MimeType != "" {
			mimeMatch := false
			for _, mt := range mimeTypes {
				if product.MimeType == mt {
					mimeMatch = true
					break
				}
			}
			if !mimeMatch {
				continue
			}
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/docker-bench) error calculating digest set from file %s: %v", path, err)
			continue
		}

		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/docker-bench) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path sourced from attestation context products
		if err != nil {
			log.Debugf("(attestation/docker-bench) error opening file %s: %v", path, err)
			continue
		}

		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/docker-bench) error reading file %s: %v", path, err)
			continue
		}

		var report DockerBenchReport
		if err := json.Unmarshal(reportBytes, &report); err != nil {
			log.Debugf("(attestation/docker-bench) error unmarshaling report: %v", err)
			continue
		}

		// Validate that this is a docker-bench report: the Desc field must
		// contain the CIS Docker Benchmark string, and Results must be non-empty.
		if !strings.Contains(report.Desc, cisDockerDesc) {
			log.Debugf("(attestation/docker-bench) file %s desc %q does not match expected docker-bench format, skipping", path, report.Desc)
			continue
		}
		if len(report.Results) == 0 {
			log.Debugf("(attestation/docker-bench) file %s has no results, skipping", path)
			continue
		}

		a.report = &report
		a.ReportFile = path
		a.ReportDigestSet = product.Digest
		a.populateSummary()
		return nil
	}

	return fmt.Errorf("no docker-bench report found in products")
}

// populateSummary fills in the Summary fields and derives metadata from the report.
func (a *Attestor) populateSummary() {
	if a.report == nil {
		return
	}

	a.BenchmarkID = a.report.ID

	// Extract version from the Desc if present, e.g.
	// "CIS Docker Benchmark v1.6.0" → "v1.6.0".
	if idx := strings.Index(a.report.Desc, cisDockerDesc); idx >= 0 {
		rest := strings.TrimSpace(a.report.Desc[idx+len(cisDockerDesc):])
		if rest != "" {
			a.Version = rest
		}
	}

	a.Summary.TotalChecks = len(a.report.Results)

	for _, r := range a.report.Results {
		switch strings.ToUpper(r.Result) {
		case "PASS":
			a.Summary.TotalPass++
		case "WARN":
			a.Summary.TotalWarn++
			a.Summary.FailedChecks = append(a.Summary.FailedChecks, FailedCheck{
				ID:     r.ID,
				Desc:   r.Desc,
				Result: r.Result,
			})
		case "INFO":
			a.Summary.TotalInfo++
		case "NOTE":
			a.Summary.TotalNote++
		default:
			// Unknown status — treat as a failed check.
			a.Summary.FailedChecks = append(a.Summary.FailedChecks, FailedCheck{
				ID:     r.ID,
				Desc:   r.Desc,
				Result: r.Result,
			})
		}

		// Extract container IDs from details. docker-bench often embeds the
		// container ID (12-char hex prefix) in the details string.
		if r.Details != "" {
			a.ContainerIDs = append(a.ContainerIDs, extractContainerIDs(r.Details)...)
		}
	}

	// De-duplicate container IDs.
	a.ContainerIDs = unique(a.ContainerIDs)
}

// extractContainerIDs finds space-separated 12-hex-char tokens that look like
// short Docker container IDs within a details string.
func extractContainerIDs(details string) []string {
	var ids []string
	for _, token := range strings.Fields(details) {
		if len(token) >= 12 && isHex(token[:12]) {
			ids = append(ids, token[:12])
		}
	}
	return ids
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func unique(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := ss[:0]
	for _, s := range ss {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// Subjects returns the in-toto subjects for this attestation. Each subject
// creates a node in the supply chain graph:
//
//   - benchmark:<benchmark-id>     — identifies the CIS Docker Benchmark version
//   - container:<container-id>     — each container ID found in failing check details
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	// Benchmark identity subject.
	benchmarkID := "cis-docker"
	if a.Version != "" {
		// Strip leading whitespace/v prefix for a clean ID, e.g. "v1.6.0" → "1.6.0".
		ver := strings.TrimSpace(a.Version)
		ver = strings.TrimPrefix(ver, "v")
		if ver != "" {
			benchmarkID = fmt.Sprintf("cis-docker-%s", ver)
		}
	}
	benchmarkKey := fmt.Sprintf("benchmark:%s", benchmarkID)
	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(benchmarkKey), hashes); err == nil {
		subjects[benchmarkKey] = ds
	} else {
		log.Debugf("(attestation/docker-bench) failed to record benchmark subject: %v", err)
	}

	// Container identity subjects — tie the attestation to specific running containers.
	for _, cid := range a.ContainerIDs {
		containerKey := fmt.Sprintf("container:%s", cid)
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(containerKey), hashes); err == nil {
			subjects[containerKey] = ds
		} else {
			log.Debugf("(attestation/docker-bench) failed to record container subject %s: %v", cid, err)
		}
	}

	return subjects
}
