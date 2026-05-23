// Copyright 2026 The Aflock Authors
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

// Package linkerdcheck parses `linkerd check -o json` output and optionally
// `linkerd viz edges -o json`, emitting a signed attestation that captures
// Linkerd service-mesh health + the meshed service graph with per-edge
// mTLS status.
//
// Linkerd (https://linkerd.io) is the CNCF-graduated service mesh. Its
// `linkerd check` CLI runs a battery of structured validations against the
// control plane, data plane, extensions, and trust chain, then emits one of
// success | warning | error per check. The viz extension adds `linkerd viz
// edges`, which returns the meshed service graph with mTLS client_id /
// server_id identities per src→dst pair.
//
// This attestor consumes the JSON output of both commands (the edges file
// is optional) and emits a structured predicate that policy Rego can gate
// on:
//
//   - per-category check rollup (pass/warn/error counts + warning details)
//   - flat summary across categories
//   - optional service graph with mTLS-secured booleans per edge
//   - optional cluster name from $LINKERD_CLUSTER_NAME
//
// The shape mirrors the `falco` attestor (postproduct, MIME-filtered
// product candidate scan, integrity-checked digest before parsing).
//
// Tracking: rookery#146 follow-up (linkerd attestor).
package linkerdcheck

import (
	"bytes"
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
	Name    = "linkerd-check"
	Type    = "https://aflock.ai/attestations/linkerd-check/v0.1"
	RunType = attestation.PostProductRunType

	envClusterName = "LINKERD_CLUSTER_NAME"

	// File-name hints used to disambiguate which product file is the
	// check report vs. the edges report when both are present. We also
	// fall back to JSON-shape detection if neither matches.
	checkFileHint = "linkerd-check"
	edgesFileHint = "linkerd-edges"

	resultSuccess = "success"
	resultWarning = "warning"
	resultError   = "error"
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}

	// linkerd CLIs emit application/json; some pipelines may strip the
	// MIME hint and end up as text/plain on disk.
	mimeTypes = []string{"application/json", "text/plain"}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// CheckReport is the top-level shape of `linkerd check -o json`. See
// linkerd/linkerd2 healthcheck package for the upstream definition.
type CheckReport struct {
	Success    bool            `json:"success"`
	Categories []CheckCategory `json:"categories"`
}

// CheckCategory groups the checks fired for a single area (e.g.
// "linkerd-existence", "linkerd-identity", "linkerd-control-plane-proxy").
type CheckCategory struct {
	CategoryName string  `json:"categoryName"`
	Checks       []Check `json:"checks"`
}

// Check is a single Linkerd validation outcome.
type Check struct {
	Description string `json:"description"`
	Hint        string `json:"hint,omitempty"`
	Error       string `json:"error,omitempty"`
	Result      string `json:"result"` // "success" | "warning" | "error"
}

// EdgeReport is the top-level shape of `linkerd viz edges -o json`.
// Linkerd emits a flat array of Edge objects.
type EdgeReport []Edge

// Edge captures a single src→dst flow as Linkerd's data-plane proxies see
// it. The mTLS status is encoded by the presence of client_id + server_id
// and the no_tls_reason free-form field.
type Edge struct {
	Src          string `json:"src"`
	SrcNamespace string `json:"src_namespace"`
	Dst          string `json:"dst"`
	DstNamespace string `json:"dst_namespace"`
	ClientID     string `json:"client_id,omitempty"`
	ServerID     string `json:"server_id,omitempty"`
	NoTLSReason  string `json:"no_tls_reason,omitempty"`
}

// Secured returns true when the edge is mTLS-secured: both peer identities
// are present AND no_tls_reason is empty.
func (e Edge) Secured() bool {
	return e.ClientID != "" && e.ServerID != "" && e.NoTLSReason == ""
}

// CategoryRollup is a per-category aggregation of check results.
type CategoryRollup struct {
	Category string   `json:"category"`
	Pass     int      `json:"pass"`
	Warn     int      `json:"warn"`
	Error    int      `json:"error"`
	Warnings []string `json:"warnings,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

// CheckSummary is the flat roll-up across every category.
type CheckSummary struct {
	Pass             int              `json:"pass"`
	Warn             int              `json:"warn"`
	Error            int              `json:"error"`
	DistinctCategory int              `json:"distinct_categories"`
	OverallSuccess   bool             `json:"overall_success"`
	Categories       []CategoryRollup `json:"categories,omitempty"`
}

// EdgesSummary is the optional roll-up over `linkerd viz edges`.
type EdgesSummary struct {
	TotalEdges    int      `json:"total_edges"`
	Secured       int      `json:"secured"`
	Insecure      int      `json:"insecure"`
	DistinctSrcNS []string `json:"distinct_src_namespaces,omitempty"`
	DistinctDstNS []string `json:"distinct_dst_namespaces,omitempty"`
}

// Attestor captures Linkerd check results plus optional viz edges.
type Attestor struct {
	// CheckFile is the path of the linkerd check JSON file in the product set.
	CheckFile string `json:"check_file"`
	// CheckDigestSet is the cryptographic digest of the check report file.
	CheckDigestSet cryptoutil.DigestSet `json:"check_digest_set"`
	// EdgesFile, if present, is the path of the linkerd viz edges JSON.
	EdgesFile string `json:"edges_file,omitempty"`
	// EdgesDigestSet is the digest of the edges file (only set when EdgesFile is).
	EdgesDigestSet cryptoutil.DigestSet `json:"edges_digest_set,omitempty"`

	// ClusterName from $LINKERD_CLUSTER_NAME. Optional.
	ClusterName string `json:"cluster_name,omitempty"`
	// Hostname of the cilock host that ran the captures.
	Hostname string `json:"hostname,omitempty"`

	// CheckSummary is the structured roll-up across check categories.
	CheckSummary CheckSummary `json:"check_summary"`
	// CheckReport is the raw parsed check report. Embedded for Rego that
	// wants to walk individual checks.
	CheckReport CheckReport `json:"check_report"`

	// EdgesSummary is the optional roll-up across viz edges.
	EdgesSummary *EdgesSummary `json:"edges_summary,omitempty"`
	// EdgeReport is the raw parsed edges output, when an edges file is present.
	EdgeReport EdgeReport `json:"edge_report,omitempty"`
}

// New creates a new Attestor. ClusterName is pre-populated from the
// LINKERD_CLUSTER_NAME environment variable if set.
func New() *Attestor {
	hostname, _ := os.Hostname()
	return &Attestor{
		ClusterName: os.Getenv(envClusterName),
		Hostname:    hostname,
	}
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(a) }

// Attest scans the product set for one or two Linkerd JSON files: a
// `linkerd check -o json` report (required) and an optional `linkerd viz
// edges -o json` report. Both are MIME-filtered + integrity-checked before
// parsing.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	return a.getCandidates(ctx)
}

//nolint:gocognit // sequential candidate scan: iterate products → open → decode → validate
func (a *Attestor) getCandidates(ctx *attestation.AttestationContext) error {
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
			log.Debugf("(attestation/linkerd-check) error calculating digest set from file %s: %v", path, err)
			continue
		}
		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/linkerd-check) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path sourced from attestation context products
		if err != nil {
			log.Debugf("(attestation/linkerd-check) error opening file %s: %v", path, err)
			continue
		}
		body, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/linkerd-check) error reading file %s: %v", path, err)
			continue
		}

		// Try check report first — its shape has a top-level object with
		// `categories[]`, distinct from edges (top-level array).
		if a.CheckFile == "" {
			if rep, ok := parseCheckReport(body, path); ok {
				a.CheckFile = path
				a.CheckDigestSet = product.Digest
				a.CheckReport = rep
				a.populateCheckSummary()
				continue
			}
		}

		// Try edges next — top-level array of edge objects.
		if a.EdgesFile == "" {
			if er, ok := parseEdgeReport(body, path); ok {
				a.EdgesFile = path
				a.EdgesDigestSet = product.Digest
				a.EdgeReport = er
				a.populateEdgesSummary()
				continue
			}
		}
	}

	if a.CheckFile == "" {
		return fmt.Errorf("no linkerd check report (linkerd check -o json) found in products")
	}
	return nil
}

// parseCheckReport returns (report, true) iff body parses as one or more
// concatenated CheckReports AND the merged report's shape is recognisably a
// linkerd-check output (has categories and each category has checks).
//
// Linkerd's `linkerd check -o json` emits one JSON object for the core
// checks and one per installed extension (viz, jaeger, multicluster,
// etc.), with NO delimiter between objects — see linkerd/linkerd2#5837.
// We use a streaming decoder to read every object and merge their
// categories into a single CheckReport. `success` is the logical AND
// of all sub-reports' success flags (any extension failing fails the
// whole report).
func parseCheckReport(body []byte, path string) (CheckReport, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	merged := CheckReport{Success: true}
	count := 0
	for {
		var sub CheckReport
		if err := dec.Decode(&sub); err != nil {
			if err == io.EOF {
				break
			}
			if count == 0 {
				return merged, false
			}
			// One sub-report failed to decode after others succeeded;
			// surface the partial merge but log the tail.
			log.Debugf("(attestation/linkerd-check) %s: trailing decode error: %v", path, err)
			break
		}
		count++
		merged.Success = merged.Success && sub.Success
		merged.Categories = append(merged.Categories, sub.Categories...)
	}
	if count == 0 || len(merged.Categories) == 0 {
		return merged, false
	}
	// Sanity: every category must look like one (have a name + checks).
	for _, c := range merged.Categories {
		if c.CategoryName == "" && len(c.Checks) == 0 {
			log.Debugf("(attestation/linkerd-check) %s: category missing name and checks", path)
			return merged, false
		}
	}
	return merged, true
}

// parseEdgeReport returns (edges, true) iff body parses as a top-level
// array of Edge objects with the expected fields populated.
func parseEdgeReport(body []byte, path string) (EdgeReport, bool) {
	var er EdgeReport
	if err := json.Unmarshal(body, &er); err != nil {
		return nil, false
	}
	if len(er) == 0 {
		// An empty edges report (cluster has no meshed traffic) is valid,
		// but we can't disambiguate it from an empty array that isn't an
		// edges file. Use a filename hint as a tiebreaker.
		return er, strings.Contains(path, edgesFileHint)
	}
	// Every edge must have at least src + dst.
	for _, e := range er {
		if e.Src == "" || e.Dst == "" {
			log.Debugf("(attestation/linkerd-check) %s: edge missing src/dst", path)
			return nil, false
		}
	}
	return er, true
}

// populateCheckSummary fills in CheckSummary from a.CheckReport.
func (a *Attestor) populateCheckSummary() {
	a.CheckSummary.OverallSuccess = a.CheckReport.Success
	a.CheckSummary.DistinctCategory = len(a.CheckReport.Categories)

	for _, cat := range a.CheckReport.Categories {
		roll := CategoryRollup{Category: cat.CategoryName}
		for _, chk := range cat.Checks {
			switch chk.Result {
			case resultSuccess:
				roll.Pass++
				a.CheckSummary.Pass++
			case resultWarning:
				roll.Warn++
				a.CheckSummary.Warn++
				roll.Warnings = append(roll.Warnings, chk.Description)
			case resultError:
				roll.Error++
				a.CheckSummary.Error++
				roll.Errors = append(roll.Errors, chk.Description)
			}
		}
		a.CheckSummary.Categories = append(a.CheckSummary.Categories, roll)
	}
}

// populateEdgesSummary fills in EdgesSummary from a.EdgeReport.
func (a *Attestor) populateEdgesSummary() {
	if len(a.EdgeReport) == 0 {
		a.EdgesSummary = &EdgesSummary{}
		return
	}
	summary := &EdgesSummary{TotalEdges: len(a.EdgeReport)}
	srcNS := map[string]struct{}{}
	dstNS := map[string]struct{}{}
	for _, e := range a.EdgeReport {
		if e.Secured() {
			summary.Secured++
		} else {
			summary.Insecure++
		}
		if e.SrcNamespace != "" {
			srcNS[e.SrcNamespace] = struct{}{}
		}
		if e.DstNamespace != "" {
			dstNS[e.DstNamespace] = struct{}{}
		}
	}
	for ns := range srcNS {
		summary.DistinctSrcNS = append(summary.DistinctSrcNS, ns)
	}
	for ns := range dstNS {
		summary.DistinctDstNS = append(summary.DistinctDstNS, ns)
	}
	a.EdgesSummary = summary
}

// Subjects returns the in-toto subjects for this attestation so the verify-
// time BFS can chain back to the wrapped step that produced the JSON files:
//
//   - check_file:<path>          — the check report, digested by product set
//   - edges_file:<path>          — the edges report (when present)
//   - cluster:<cluster-name>     — when LINKERD_CLUSTER_NAME is set
//   - linkerd-overall:success|fail — top-level pass/fail signal for fast Rego
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := map[string]cryptoutil.DigestSet{}

	add := func(key, digest string) {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(digest), hashes); err == nil {
			subjects[key] = ds
		}
	}

	if a.CheckFile != "" && len(a.CheckDigestSet) > 0 {
		subjects[fmt.Sprintf("check_file:%s", a.CheckFile)] = a.CheckDigestSet
	}
	if a.EdgesFile != "" && len(a.EdgesDigestSet) > 0 {
		subjects[fmt.Sprintf("edges_file:%s", a.EdgesFile)] = a.EdgesDigestSet
	}
	if a.ClusterName != "" {
		add(fmt.Sprintf("cluster:%s", a.ClusterName), a.ClusterName)
	}
	overall := "fail"
	if a.CheckSummary.OverallSuccess {
		overall = "success"
	}
	add(fmt.Sprintf("linkerd-overall:%s", overall), overall)

	return subjects
}
