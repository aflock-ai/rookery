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

// Package falco parses Falco JSON event output and emits a signed
// attestation summarising runtime security events.
//
// Falco (https://falco.org) is a CNCF runtime security tool that uses
// eBPF (or the legacy kernel module) to detect abnormal process exec,
// file access, network connections, container escapes, and other policy
// violations defined as Falco rules. It writes events as line-delimited
// JSON (`--json --output-fields-include-pid`) when configured for
// machine-readable output.
//
// This attestor wraps a window of Falco events captured to a file —
// typically by running `falco --json --duration <window>` or by tailing
// `/var/log/falco.log` and copying a windowed slice into a product file —
// then parses the line-delimited JSON and emits a structured predicate
// that policy Rego can gate on:
//
//   - per-event records (rule, priority, hostname, time, output, output_fields)
//   - aggregate priority counts (Critical / Error / Warning / Notice / Info / Debug)
//   - the source file digest as a subject so the BFS can chain back to
//     the wrapped `cilock run -- sh -c '... > falco-events.jsonl'` step
//
// Tracking: rookery#139.
package falco

import (
	"bufio"
	"bytes"
	"crypto"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
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
	Name    = "falco"
	Type    = "https://aflock.ai/attestations/falco/v0.1"
	RunType = attestation.PostProductRunType

	// envClusterName is the environment variable used to identify the
	// Kubernetes cluster the events were captured from. Optional.
	envClusterName = "FALCO_CLUSTER_NAME"
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}

	// mimeTypes accepted from the product set. Falco emits line-delimited
	// JSON; that's a text/plain or application/json file on disk, depending
	// on the user's pipeline.
	mimeTypes = []string{"text/plain", "application/json", "application/x-ndjson"}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

// Event is a single Falco-emitted JSON event line.
//
// Falco's JSON format (output_format=json) is documented at
// https://falco.org/docs/concepts/outputs/formatting/ and the
// canonical key set is `time, rule, priority, source, hostname, output,
// output_fields, tags`.
type Event struct {
	Time         string         `json:"time,omitempty"`
	Rule         string         `json:"rule,omitempty"`
	Priority     string         `json:"priority,omitempty"`
	Source       string         `json:"source,omitempty"`
	Hostname     string         `json:"hostname,omitempty"`
	Output       string         `json:"output,omitempty"`
	OutputFields map[string]any `json:"output_fields,omitempty"`
	Tags         []string       `json:"tags,omitempty"`
	// K8s carries the convenience accessor for kubernetes pod/ns/container
	// metadata if the operator enabled `json_include_output_property` for
	// the K8s fields. Always nil when running outside a K8s cluster.
	K8s *K8sContext `json:"k8s,omitempty"`
}

// K8sContext is the subset of Kubernetes metadata Falco attaches to events
// when running inside a cluster with the k8s metadata source enabled.
type K8sContext struct {
	PodName        string `json:"pod_name,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	ContainerID    string `json:"container_id,omitempty"`
	ContainerName  string `json:"container_name,omitempty"`
	ContainerImage string `json:"container_image,omitempty"`
}

// PriorityCounts roll-up of how many events fell into each Falco priority
// bucket. Mirrors the canonical Falco priority levels in descending
// severity: Emergency, Alert, Critical, Error, Warning, Notice,
// Informational, Debug.
type PriorityCounts struct {
	Emergency     int `json:"emergency,omitempty"`
	Alert         int `json:"alert,omitempty"`
	Critical      int `json:"critical,omitempty"`
	Error         int `json:"error,omitempty"`
	Warning       int `json:"warning,omitempty"`
	Notice        int `json:"notice,omitempty"`
	Informational int `json:"informational,omitempty"`
	Debug         int `json:"debug,omitempty"`
}

// Total returns the total number of events across all priorities.
func (p PriorityCounts) Total() int {
	return p.Emergency + p.Alert + p.Critical + p.Error +
		p.Warning + p.Notice + p.Informational + p.Debug
}

// RuleHit captures a per-rule aggregation: which rule fired, how many
// times, and the highest priority observed for it. Useful for policy
// Rego that wants to deny when, say, the `Terminal shell in container`
// rule fires more than zero times — without having to walk every event.
type RuleHit struct {
	Rule            string `json:"rule"`
	Count           int    `json:"count"`
	HighestPriority string `json:"highest_priority,omitempty"`
}

// Summary is the roll-up the attestor publishes alongside the raw events.
type Summary struct {
	TotalEvents   int            `json:"total_events"`
	Priorities    PriorityCounts `json:"priorities"`
	RuleHits      []RuleHit      `json:"rule_hits,omitempty"`
	DistinctRules int            `json:"distinct_rules,omitempty"`
	DistinctHosts int            `json:"distinct_hosts,omitempty"`
	WindowStart   string         `json:"window_start,omitempty"`
	WindowEnd     string         `json:"window_end,omitempty"`
}

// Attestor captures Falco runtime-security events from the product set.
type Attestor struct {
	// ReportFile is the path of the Falco JSON event file in the product set.
	ReportFile string `json:"report_file"`
	// ReportDigestSet is the cryptographic digest of the report file.
	ReportDigestSet cryptoutil.DigestSet `json:"report_digest_set"`
	// ClusterName identifies the Kubernetes cluster Falco watched. Populated
	// from $FALCO_CLUSTER_NAME or left blank for non-K8s deployments.
	ClusterName string `json:"cluster_name,omitempty"`
	// Hostname is the cilock host's hostname (the node where Falco ran).
	Hostname string `json:"hostname,omitempty"`
	// Summary is the aggregate roll-up.
	Summary Summary `json:"summary"`
	// Events is the parsed list of Falco event records.
	Events []Event `json:"events,omitempty"`

	hashes []cryptoutil.DigestValue
}

// New creates a new Falco Attestor. The cluster name is pre-populated from
// the FALCO_CLUSTER_NAME environment variable if set.
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

// Attest scans the attestation context products for a Falco line-delimited
// JSON event file, parses it, and populates the attestor fields.
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
			log.Debugf("(attestation/falco) error calculating digest set from file %s: %v", path, err)
			continue
		}
		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/falco) integrity error for %s: product digest does not match", path)
			continue
		}

		f, err := os.Open(path) //nolint:gosec // G304: path sourced from attestation context products
		if err != nil {
			log.Debugf("(attestation/falco) error opening file %s: %v", path, err)
			continue
		}
		reportBytes, err := io.ReadAll(f)
		_ = f.Close()
		if err != nil {
			log.Debugf("(attestation/falco) error reading file %s: %v", path, err)
			continue
		}

		events, err := parseEvents(reportBytes)
		if err != nil {
			log.Debugf("(attestation/falco) error parsing events in %s: %v", path, err)
			continue
		}
		if len(events) == 0 {
			// Empty event file is a valid Falco capture (the window had no
			// rule hits), but skip files that don't shape-match — they're
			// some other JSON document the user happened to put in products.
			if !looksLikeFalco(reportBytes) {
				continue
			}
		}

		a.ReportFile = path
		a.ReportDigestSet = product.Digest
		a.Events = events
		a.populateSummary()
		return nil
	}

	return fmt.Errorf("no falco event file found in products")
}

// parseEvents parses Falco's line-delimited JSON output. Each non-empty
// non-whitespace line is decoded as one Event. Malformed lines are
// skipped with a debug log; this matches Falco's own pipe-tolerant
// consumer behaviour where partial logs from a crash still parse.
func parseEvents(b []byte) ([]Event, error) {
	var out []Event
	scanner := bufio.NewScanner(bytes.NewReader(b))
	// Falco event lines can exceed the default 64 KB scanner buffer when
	// output_fields is verbose. Bump to 1 MB.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev Event
		if err := json.Unmarshal(line, &ev); err != nil {
			log.Debugf("(attestation/falco) skipping malformed event line: %v", err)
			continue
		}
		// Only count something as an event when it has a rule name —
		// Falco's startup banner lines and shutdown messages don't have one.
		if ev.Rule == "" {
			continue
		}
		out = append(out, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// looksLikeFalco heuristically validates a file is Falco-shaped even when
// zero rule events occurred. Used so we don't claim an empty CycloneDX
// SBOM or empty SARIF file as a Falco event file.
func looksLikeFalco(b []byte) bool {
	// Any line that has both a "rule" and "priority" key is Falco-shaped.
	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if bytes.Contains(line, []byte(`"rule"`)) && bytes.Contains(line, []byte(`"priority"`)) {
			return true
		}
	}
	return false
}

// priorityField returns a pointer into PriorityCounts for the given
// Falco priority string (case-insensitive). Returns nil for unknown
// priority strings.
func priorityField(p *PriorityCounts, priority string) *int {
	switch strings.ToLower(priority) {
	case "emergency":
		return &p.Emergency
	case "alert":
		return &p.Alert
	case "critical":
		return &p.Critical
	case "error":
		return &p.Error
	case "warning":
		return &p.Warning
	case "notice":
		return &p.Notice
	case "informational", "info":
		return &p.Informational
	case "debug":
		return &p.Debug
	}
	return nil
}

// priorityRank maps priority strings to integer ranks (higher = more
// severe) so we can compare "highest priority observed for rule X".
func priorityRank(priority string) int {
	switch strings.ToLower(priority) {
	case "emergency":
		return 8
	case "alert":
		return 7
	case "critical":
		return 6
	case "error":
		return 5
	case "warning":
		return 4
	case "notice":
		return 3
	case "informational", "info":
		return 2
	case "debug":
		return 1
	}
	return 0
}

// upsertRuleHit increments the count for ev.Rule in ruleHits, creating
// the entry on first sight and bumping HighestPriority when the new
// event is more severe than what we've seen for this rule before.
func upsertRuleHit(ruleHits map[string]*RuleHit, ev Event) {
	hit, ok := ruleHits[ev.Rule]
	if !ok {
		ruleHits[ev.Rule] = &RuleHit{Rule: ev.Rule, Count: 1, HighestPriority: ev.Priority}
		return
	}
	hit.Count++
	if priorityRank(ev.Priority) > priorityRank(hit.HighestPriority) {
		hit.HighestPriority = ev.Priority
	}
}

// updateTimeWindow widens earliest/latest to cover ev.Time. Returns the
// new bounds; the caller threads them through the loop.
func updateTimeWindow(earliest, latest, t string) (string, string) {
	if t == "" {
		return earliest, latest
	}
	if earliest == "" || t < earliest {
		earliest = t
	}
	if latest == "" || t > latest {
		latest = t
	}
	return earliest, latest
}

// populateSummary fills in the Summary fields from a.Events.
func (a *Attestor) populateSummary() {
	a.Summary.TotalEvents = len(a.Events)
	if len(a.Events) == 0 {
		return
	}

	hostSeen := map[string]struct{}{}
	ruleHits := map[string]*RuleHit{}
	var earliest, latest string

	for _, ev := range a.Events {
		if f := priorityField(&a.Summary.Priorities, ev.Priority); f != nil {
			*f++
		}
		if ev.Hostname != "" {
			hostSeen[ev.Hostname] = struct{}{}
		}
		if ev.Rule != "" {
			upsertRuleHit(ruleHits, ev)
		}
		earliest, latest = updateTimeWindow(earliest, latest, ev.Time)
	}

	a.Summary.DistinctHosts = len(hostSeen)
	a.Summary.DistinctRules = len(ruleHits)
	a.Summary.WindowStart = earliest
	a.Summary.WindowEnd = latest

	a.Summary.RuleHits = make([]RuleHit, 0, len(ruleHits))
	for _, hit := range ruleHits {
		a.Summary.RuleHits = append(a.Summary.RuleHits, *hit)
	}
}

// Subjects returns the in-toto subjects for this attestation. Each subject
// creates a node in the supply chain graph so a verify-time BFS can chain
// back to the wrapped step that captured the events:
//
//   - falco-events:<host>          — the host whose events were captured
//   - cluster:<cluster-name>       — when running in a K8s cluster
//   - rule:<rule-name>            — one subject per distinct rule that fired
//   - report_file:<path>          — the captured events file
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subjects := map[string]cryptoutil.DigestSet{}

	add := func(key, digest string) {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(digest), hashes); err == nil {
			subjects[key] = ds
		}
	}

	if a.Hostname != "" {
		add(fmt.Sprintf("falco-events:%s", a.Hostname), a.Hostname)
	}
	if a.ClusterName != "" {
		add(fmt.Sprintf("cluster:%s", a.ClusterName), a.ClusterName)
	}
	for _, hit := range a.Summary.RuleHits {
		add(fmt.Sprintf("rule:%s", hit.Rule), hit.Rule)
	}
	if a.ReportFile != "" {
		// Report-file subject uses the file's actual digest from the product
		// set, not a hash-of-the-path, so the BFS can chain to product/v0.3.
		if len(a.ReportDigestSet) > 0 {
			subjects[fmt.Sprintf("report_file:%s", a.ReportFile)] = a.ReportDigestSet
		}
	}
	return subjects
}
