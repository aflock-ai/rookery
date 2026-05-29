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
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "docker-bench"
	Type    = "https://aflock.ai/attestations/docker-bench/v0.1"
	RunType = attestation.PostProductRunType

	// benchmarkID is the stable identity of the benchmark this tool runs.
	benchmarkID = "docker-bench-security"

	// containerRuntimeSectionID is the docker-bench section ("5" / "Container
	// Runtime") whose per-check items list running container names. Image-build
	// sections (e.g. "4") also carry items, but those are image references, not
	// container identifiers, so only this section's items yield container:
	// subjects.
	containerRuntimeSectionID = "5"

	// cisDockerDesc is the description prefix some hypothetical/older report
	// shapes use. The real docker/docker-bench-security tool does NOT emit this;
	// it is retained only for the back-compat fallback parser.
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
	detection.Register(Name, detectorYAML)
}

// CheckResult is a single result entry produced by docker-bench-security. In the
// real tool output it lives under tests[].results[]; the legacy fallback shape
// places it at the top level under "results".
type CheckResult struct {
	ID      string   `json:"id"`
	Desc    string   `json:"desc"`
	Result  string   `json:"result"` // PASS | WARN | INFO | NOTE
	Details string   `json:"details,omitempty"`
	Items   []string `json:"items,omitempty"`
}

// TestSection is one numbered docker-bench section (e.g. "5" / "Container
// Runtime") holding its individual check results.
type TestSection struct {
	ID      string        `json:"id"`
	Desc    string        `json:"desc"`
	Results []CheckResult `json:"results"`
}

// DockerBenchReport is the REAL top-level structure produced by
// docker/docker-bench-security (v1.3.4 confirmed). It carries the tool version
// under "dockerbenchsecurity", the sections under "tests", and the tool's own
// rollup under "checks"/"score". There is NO top-level "desc" or "results".
type DockerBenchReport struct {
	DockerBenchSecurity string        `json:"dockerbenchsecurity"`
	Start               int64         `json:"start,omitempty"`
	End                 int64         `json:"end,omitempty"`
	Tests               []TestSection `json:"tests"`
	Checks              int           `json:"checks"`
	Score               int           `json:"score"`

	// Legacy fallback shape: some older/hypothetical reports emit the checks at
	// the top level under "desc"/"results" instead of under "tests". These are
	// only consulted when "tests" is empty (see allResults).
	ID            string        `json:"id,omitempty"`
	Desc          string        `json:"desc,omitempty"`
	LegacyResults []CheckResult `json:"results,omitempty"`
}

// isDockerBench reports whether the decoded report is recognizably
// docker-bench-security output: either the real schema (a tool version under
// "dockerbenchsecurity" plus sections) or the legacy fallback shape (a
// CIS-Docker desc with top-level results).
func (r *DockerBenchReport) isDockerBench() bool {
	if r.DockerBenchSecurity != "" && len(r.Tests) > 0 {
		return true
	}
	// Legacy fallback: top-level CIS Docker Benchmark report with results.
	return strings.Contains(r.Desc, cisDockerDesc) && len(r.LegacyResults) > 0
}

// version returns the benchmark/tool version. The real tool reports it in the
// "dockerbenchsecurity" field; the legacy shape embeds it in the Desc string
// ("CIS Docker Benchmark v1.6.0" -> "v1.6.0").
func (r *DockerBenchReport) version() string {
	if r.DockerBenchSecurity != "" {
		return r.DockerBenchSecurity
	}
	if idx := strings.Index(r.Desc, cisDockerDesc); idx >= 0 {
		if rest := strings.TrimSpace(r.Desc[idx+len(cisDockerDesc):]); rest != "" {
			return rest
		}
	}
	return ""
}

// allResults flattens the per-check results across every section. For the real
// schema it walks tests[].results[]; for the legacy fallback it returns the
// top-level results. Section order and within-section order are preserved so
// the derived predicate is deterministic.
func (r *DockerBenchReport) allResults() []CheckResult {
	if len(r.Tests) > 0 {
		var out []CheckResult
		for _, s := range r.Tests {
			out = append(out, s.Results...)
		}
		return out
	}
	return r.LegacyResults
}

// FailedCheck records a single non-passing check in the attestation summary.
type FailedCheck struct {
	ID     string `json:"id"`
	Desc   string `json:"desc"`
	Result string `json:"result"`
}

// Summary contains the roll-up data stored in the attestation.
type Summary struct {
	// TotalChecks is the count of individual checks the attestor tallied.
	TotalChecks int `json:"total_checks"`
	TotalPass   int `json:"total_pass"`
	TotalWarn   int `json:"total_warn"`
	TotalInfo   int `json:"total_info"`
	TotalNote   int `json:"total_note"`
	// Checks is the tool's own top-level check count ("checks" field).
	Checks int `json:"checks"`
	// Score is the tool's own top-level score ("score" field).
	Score        int           `json:"score"`
	FailedChecks []FailedCheck `json:"failed_checks,omitempty"`
}

// Attestor captures docker-bench-security CIS Docker Benchmark results.
type Attestor struct {
	// ReportFile is the path of the docker-bench JSON output file.
	ReportFile string `json:"report_file"`
	// ReportDigestSet is the cryptographic digest of the report file.
	ReportDigestSet cryptoutil.DigestSet `json:"report_digest_set"`
	// BenchmarkID is the stable benchmark identity ("docker-bench-security").
	BenchmarkID string `json:"benchmark_id,omitempty"`
	// Version is the tool/benchmark version, from the "dockerbenchsecurity"
	// field (real schema) or the Desc suffix (legacy fallback).
	Version string `json:"version,omitempty"`
	// ContainerNames lists the running container names docker-bench audited in
	// its Container Runtime section.
	ContainerNames []string `json:"container_names,omitempty"`
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

//nolint:gocognit // sequential candidate scan: iterate products → open → decode → validate
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

		// Validate that this is a docker-bench report: the real schema is
		// recognized by the top-level "dockerbenchsecurity" version field plus
		// sections; the legacy fallback by a CIS-Docker desc + top-level results.
		if !report.isDockerBench() {
			log.Debugf("(attestation/docker-bench) file %s is not docker-bench-security output, skipping", path)
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

	a.BenchmarkID = benchmarkID
	a.Version = a.report.version()
	a.Summary.Checks = a.report.Checks
	a.Summary.Score = a.report.Score

	results := a.report.allResults()
	a.Summary.TotalChecks = len(results)

	for _, r := range results {
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
	}

	a.ContainerNames = a.extractContainerNames()
}

// extractContainerNames collects the running container names docker-bench
// reports in its Container Runtime section (id "5"). The tool lists them in the
// per-check items array in three shapes that this normalizes to the bare name:
//
//   - "name"                     → "name"
//   - "<64-hex-id>:name"  (5.29) → "name"
//   - "name:<ip-or-port>" (5.13) → "name"
//
// Results are sorted + de-duplicated so the predicate is deterministic.
func (a *Attestor) extractContainerNames() []string {
	if a.report == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var names []string
	for _, s := range a.report.Tests {
		if s.ID != containerRuntimeSectionID {
			continue
		}
		for _, r := range s.Results {
			for _, item := range r.Items {
				name := normalizeContainerName(item)
				if name == "" {
					continue
				}
				if _, ok := seen[name]; ok {
					continue
				}
				seen[name] = struct{}{}
				names = append(names, name)
			}
		}
	}
	sort.Strings(names)
	return names
}

// normalizeContainerName reduces a docker-bench Container Runtime item to a bare
// container name. docker-bench reports either a plain name, an "<id>:<name>"
// pair (long-hex id, take the name) or a "<name>:<port-or-ip>" pair (take the
// name). Returns "" if nothing usable remains.
func normalizeContainerName(item string) string {
	item = strings.TrimSpace(item)
	if item == "" {
		return ""
	}
	if idx := strings.Index(item, ":"); idx >= 0 {
		left, right := item[:idx], item[idx+1:]
		// "<id>:<name>" — a long-hex container id prefix: keep the name.
		if len(left) >= 12 && isHex(left) {
			return strings.TrimSpace(right)
		}
		// "<name>:<port-or-ip>" — keep the name.
		return strings.TrimSpace(left)
	}
	return item
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// Subjects returns the in-toto subjects for this attestation. Each subject
// creates a node in the supply chain graph:
//
//   - benchmark:cis-docker[@<version>]  — the CIS Docker Benchmark identity,
//     derived from the tool version (e.g. benchmark:cis-docker@1.3.4)
//   - container:<name>                  — each running container docker-bench
//     audited in its Container Runtime section
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	// Benchmark identity subject — honestly derived from the tool's reported
	// version (no fabricated "v1.6.0").
	benchmarkKey := "benchmark:cis-docker"
	if ver := strings.TrimSpace(a.Version); ver != "" {
		benchmarkKey = fmt.Sprintf("benchmark:cis-docker@%s", ver)
	}
	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(benchmarkKey), hashes); err == nil {
		subjects[benchmarkKey] = ds
	} else {
		log.Debugf("(attestation/docker-bench) failed to record benchmark subject: %v", err)
	}

	// Container identity subjects — tie the attestation to the specific running
	// containers docker-bench audited.
	for _, name := range a.ContainerNames {
		containerKey := fmt.Sprintf("container:%s", name)
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(containerKey), hashes); err == nil {
			subjects[containerKey] = ds
		} else {
			log.Debugf("(attestation/docker-bench) failed to record container subject %s: %v", name, err)
		}
	}

	return subjects
}
