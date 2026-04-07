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
	"fmt"
	"io"
	"os"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "kube-bench"
	Type    = "https://aflock.ai/attestations/kube-bench/v0.1"
	RunType = attestation.PostProductRunType

	// envClusterName is the environment variable used to identify the cluster.
	envClusterName = "KUBE_BENCH_CLUSTER_NAME"
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

// ControlResult represents a single test result from kube-bench.
type ControlResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Status      string `json:"status"`
	Scored      bool   `json:"scored"`
	ActualValue string `json:"actual_value,omitempty"`
	ExpectedResult string `json:"expected_result,omitempty"`
}

// ControlTest represents a group of results within a control section.
type ControlTest struct {
	ID      string          `json:"id"`
	Text    string          `json:"text"`
	Results []ControlResult `json:"results"`
}

// ControlSection represents a top-level CIS benchmark section.
type ControlSection struct {
	ID    string        `json:"id"`
	Text  string        `json:"text"`
	Tests []ControlTest `json:"tests"`
}

// Totals summarises pass/fail/warn counts across all controls.
type Totals struct {
	TotalPass int `json:"total_pass"`
	TotalFail int `json:"total_fail"`
	TotalWarn int `json:"total_warn"`
	TotalInfo int `json:"total_info,omitempty"`
}

// KubeBenchReport is the top-level structure produced by `kube-bench --json`.
type KubeBenchReport struct {
	Controls []ControlSection `json:"Controls"`
	Totals   Totals           `json:"Totals"`
}

// FailedCheck records a single failing check for inclusion in the attestation summary.
type FailedCheck struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

// Summary contains the roll-up data stored in the attestation.
type Summary struct {
	TotalPass    int           `json:"total_pass"`
	TotalFail    int           `json:"total_fail"`
	TotalWarn    int           `json:"total_warn"`
	FailedChecks []FailedCheck `json:"failed_checks,omitempty"`
	WarnedChecks []FailedCheck `json:"warned_checks,omitempty"`
}

// Attestor captures kube-bench CIS Kubernetes Benchmark results.
type Attestor struct {
	// ReportFile is the path of the kube-bench JSON output file.
	ReportFile string `json:"report_file"`
	// ReportDigestSet is the cryptographic digest of the report file.
	ReportDigestSet cryptoutil.DigestSet `json:"report_digest_set"`
	// ClusterName identifies the Kubernetes cluster that was scanned.
	ClusterName string `json:"cluster_name,omitempty"`
	// Version is the CIS benchmark version reported by kube-bench (derived from the
	// first control section ID prefix, e.g. "1" → "1").
	Version string `json:"version,omitempty"`
	// NodeHostname is the hostname of the node on which kube-bench ran.
	NodeHostname string `json:"node_hostname,omitempty"`
	// Summary contains the aggregated pass/fail/warn counts and failed check details.
	Summary Summary `json:"summary"`

	hashes []cryptoutil.DigestValue
	report *KubeBenchReport
}

// New creates a new kube-bench Attestor. The cluster name is pre-populated from
// the KUBE_BENCH_CLUSTER_NAME environment variable if set; it can also be
// overridden via WithClusterName.
func New() *Attestor {
	hostname, _ := os.Hostname()
	return &Attestor{
		ClusterName:  os.Getenv(envClusterName),
		NodeHostname: hostname,
	}
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

// Attest scans the attestation context products for a valid kube-bench JSON
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
			log.Debugf("(attestation/kube-bench) error calculating digest set from file %s: %v", path, err)
			continue
		}

		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/kube-bench) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path sourced from attestation context products
		if err != nil {
			log.Debugf("(attestation/kube-bench) error opening file %s: %v", path, err)
			continue
		}

		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/kube-bench) error reading file %s: %v", path, err)
			continue
		}

		var report KubeBenchReport
		if err := json.Unmarshal(reportBytes, &report); err != nil {
			log.Debugf("(attestation/kube-bench) error unmarshaling report: %v", err)
			continue
		}

		// Validate this is actually a kube-bench report: it must have a non-empty
		// Controls array.
		if len(report.Controls) == 0 {
			log.Debugf("(attestation/kube-bench) file %s has no Controls array, skipping", path)
			continue
		}

		a.report = &report
		a.ReportFile = path
		a.ReportDigestSet = product.Digest
		a.populateSummary()
		return nil
	}

	return fmt.Errorf("no kube-bench report found in products")
}

// populateSummary fills in the Summary fields and extracts the benchmark version
// from the control section IDs.
func (a *Attestor) populateSummary() {
	if a.report == nil {
		return
	}

	a.Summary.TotalPass = a.report.Totals.TotalPass
	a.Summary.TotalFail = a.report.Totals.TotalFail
	a.Summary.TotalWarn = a.report.Totals.TotalWarn

	// Derive the benchmark version from the first section ID (the major version
	// component, e.g. section "1.1" → version "1").
	if len(a.report.Controls) > 0 {
		firstID := a.report.Controls[0].ID
		if len(firstID) > 0 {
			a.Version = firstID
		}
	}

	for _, section := range a.report.Controls {
		for _, test := range section.Tests {
			for _, result := range test.Results {
				switch result.Status {
				case "FAIL":
					a.Summary.FailedChecks = append(a.Summary.FailedChecks, FailedCheck{
						ID:   result.TestNumber,
						Text: result.TestDesc,
					})
				case "WARN":
					a.Summary.WarnedChecks = append(a.Summary.WarnedChecks, FailedCheck{
						ID:   result.TestNumber,
						Text: result.TestDesc,
					})
				}
			}
		}
	}
}

// Subjects returns the in-toto subjects for this attestation. Each subject
// creates a node in the supply chain graph:
//
//   - benchmark:<benchmark-id> — identifies the CIS Kubernetes Benchmark version
//   - cluster:<cluster-name>  — identifies the target cluster (when known)
//   - node:<hostname>         — identifies the specific node that was scanned
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := make(map[string]cryptoutil.DigestSet)

	// Benchmark identity subject — ties this attestation to a specific CIS version.
	benchmarkID := "cis-kubernetes"
	if a.Version != "" {
		benchmarkID = fmt.Sprintf("cis-kubernetes-%s", a.Version)
	}
	benchmarkKey := fmt.Sprintf("benchmark:%s", benchmarkID)
	if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(benchmarkKey), hashes); err == nil {
		subjects[benchmarkKey] = ds
	} else {
		log.Debugf("(attestation/kube-bench) failed to record benchmark subject: %v", err)
	}

	// Cluster identity subject — ties this benchmark run to a specific cluster.
	if a.ClusterName != "" {
		clusterKey := fmt.Sprintf("cluster:%s", a.ClusterName)
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(clusterKey), hashes); err == nil {
			subjects[clusterKey] = ds
		} else {
			log.Debugf("(attestation/kube-bench) failed to record cluster subject: %v", err)
		}
	}

	// Node identity subject — ties this benchmark run to a specific node.
	if a.NodeHostname != "" {
		nodeKey := fmt.Sprintf("node:%s", a.NodeHostname)
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(nodeKey), hashes); err == nil {
			subjects[nodeKey] = ds
		} else {
			log.Debugf("(attestation/kube-bench) failed to record node subject: %v", err)
		}
	}

	return subjects
}
