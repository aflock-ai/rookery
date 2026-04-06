// Copyright 2026 The Witness Contributors
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

// Package sinkholeflows is a rookery attestor that attaches HTTP(S) flow
// data captured by a mitmproxy sidecar to a signed attestation collection.
//
// Intended use: when a pip-witness scan runs against the `pipw_sinkhole`
// Docker network, all outbound HTTPS traffic from the scan container is
// routed through a mitmproxy sidecar that logs each request+response as
// a JSON line to /flows/out.jsonl (bind-mounted into the scan container).
//
// This attestor runs in the PostProductRunType phase, reads that file,
// filters by the PIPW_SCAN_ID env var so flows from parallel scans stay
// attributable, and emits a structured predicate the scanner's policies
// can reason about.
//
// Predicate type: https://aflock.ai/attestations/sinkhole-flows/v0.1
package sinkholeflows

import (
	"bufio"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	Name    = "sinkhole-flows"
	Type    = "https://aflock.ai/attestations/sinkhole-flows/v0.1"
	RunType = attestation.PostProductRunType

	// FlowsPath is where the mitmproxy sidecar addon writes captured flows.
	// It is a bind mount from the host-side sinkhole/flows directory.
	FlowsPath = "/flows/out.jsonl"

	// ScanIDEnv identifies which scan's flows to include. The pip-witness
	// wrapper sets this before invoking cilock so concurrent scans on the
	// same sidecar don't intermix.
	ScanIDEnv = "PIPW_SCAN_ID"

	// PackageNameEnv and PackageVersionEnv let the attestor emit a
	// `pip://NAME@VERSION` subject that is byte-identical to the one the
	// pip-install attestor emits for the same package, giving Archivista
	// a clean subject-digest join between install and sinkhole attestations.
	PackageNameEnv    = "PIPW_PACKAGE_NAME"
	PackageVersionEnv = "PIPW_PACKAGE_VERSION"
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType,
		func() attestation.Attestor { return New() })
}

// FlowBody holds either decoded utf-8 text or base64-encoded bytes from
// the mitmproxy addon. Matches the structure the Python addon writes.
type FlowBody struct {
	Encoding  string `json:"encoding,omitempty"`
	Length    int    `json:"length,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Text      string `json:"text,omitempty"`
	B64       string `json:"b64,omitempty"`
	Empty     bool   `json:"empty,omitempty"`
}

// Flow is one HTTP request/response pair or a TLS ClientHello event.
type Flow struct {
	ScanID          string     `json:"scanId"`
	Timestamp       string     `json:"timestamp"`
	Event           string     `json:"event"` // "http" or "tls_clienthello"
	SNI             string     `json:"sni,omitempty"`
	AlpnProtocols   []string   `json:"alpnProtocols,omitempty"`
	Method          string     `json:"method,omitempty"`
	Scheme          string     `json:"scheme,omitempty"`
	Host            string     `json:"host,omitempty"`
	Port            int        `json:"port,omitempty"`
	Path            string     `json:"path,omitempty"`
	HTTPVersion     string     `json:"httpVersion,omitempty"`
	RequestHeaders  [][]string `json:"requestHeaders,omitempty"`
	RequestBody     *FlowBody  `json:"requestBody,omitempty"`
	ResponseStatus  int        `json:"responseStatus,omitempty"`
	ResponseReason  string     `json:"responseReason,omitempty"`
	ResponseHeaders [][]string `json:"responseHeaders,omitempty"`
	ResponseBody    *FlowBody  `json:"responseBody,omitempty"`
}

// Summary gives policies a cheap set of fields to match against without
// iterating every raw flow entry.
type Summary struct {
	ScanID         string         `json:"scanId"`
	TotalFlows     int            `json:"totalFlows"`
	UniqueHosts    []string       `json:"uniqueHosts"`
	UniqueSNIs     []string       `json:"uniqueSnis"`
	SchemeCounts   map[string]int `json:"schemeCounts"`
	StatusCounts   map[int]int    `json:"statusCounts,omitempty"`
	TotalBytesOut  int            `json:"totalBytesOut"`
	TotalBytesIn   int            `json:"totalBytesIn"`
	FlowsPath      string         `json:"flowsPath"`
	FlowsFileSHA256 string        `json:"flowsFileSha256,omitempty"`
}

// Attestor is the concrete attestor implementation whose fields become
// the signed predicate.
type Attestor struct {
	ScanID         string  `json:"scanId"`
	PackageName    string  `json:"packageName,omitempty"`
	PackageVersion string  `json:"packageVersion,omitempty"`
	Summary        Summary `json:"summary"`
	Flows          []Flow  `json:"flows"`
}

func New() *Attestor {
	return &Attestor{Flows: []Flow{}}
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(a) }

func (a *Attestor) Attest(_ *attestation.AttestationContext) error {
	scanID := strings.TrimSpace(os.Getenv(ScanIDEnv))
	a.ScanID = scanID
	a.PackageName = strings.TrimSpace(os.Getenv(PackageNameEnv))
	a.PackageVersion = strings.TrimSpace(os.Getenv(PackageVersionEnv))
	a.Summary = Summary{
		ScanID:       scanID,
		UniqueHosts:  []string{},
		UniqueSNIs:   []string{},
		SchemeCounts: map[string]int{},
		StatusCounts: map[int]int{},
		FlowsPath:    FlowsPath,
	}

	// Missing flows file is not fatal — attestor is designed to run in both
	// sinkhole-enabled and sinkhole-disabled container configurations. An
	// empty attestation is still a valid signed statement ("no flows seen").
	f, err := os.Open(FlowsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("opening %s: %w", FlowsPath, err)
	}
	defer f.Close()

	// Also hash the raw file so the attestation references the exact bytes
	// the sidecar produced.
	if sum, err := hashFile(FlowsPath); err == nil {
		a.Summary.FlowsFileSHA256 = sum
	}

	hostSet := map[string]struct{}{}
	sniSet := map[string]struct{}{}

	scanner := bufio.NewScanner(f)
	// The addon caps body size at 4 MB, but a single captured body
	// base64-encodes to ~5.4 MB and sits inside a larger JSON envelope
	// carrying headers and metadata, so one flow entry can comfortably
	// exceed 8 MB on disk. Size the scanner buffer to 32 MB per line so
	// cumulative out.jsonl files with large bodies from prior scans
	// don't trip Scanner's default "token too long" error mid-read.
	scanner.Buffer(make([]byte, 0, 1024*1024), 32*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var raw struct {
			ScanID string `json:"scan_id"`
		}
		if err := json.Unmarshal(line, &raw); err != nil {
			continue
		}
		// Filter: only flows tagged with this scan's id.
		if scanID != "" && raw.ScanID != scanID {
			continue
		}

		flow := Flow{}
		if err := decodeFlow(line, &flow); err != nil {
			continue
		}
		a.Flows = append(a.Flows, flow)
		a.Summary.TotalFlows++

		if flow.Host != "" {
			hostSet[flow.Host] = struct{}{}
		}
		if flow.SNI != "" {
			sniSet[flow.SNI] = struct{}{}
		}
		if flow.Scheme != "" {
			a.Summary.SchemeCounts[flow.Scheme]++
		}
		if flow.ResponseStatus != 0 {
			a.Summary.StatusCounts[flow.ResponseStatus]++
		}
		if flow.RequestBody != nil {
			a.Summary.TotalBytesOut += flow.RequestBody.Length
		}
		if flow.ResponseBody != nil {
			a.Summary.TotalBytesIn += flow.ResponseBody.Length
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading %s: %w", FlowsPath, err)
	}

	a.Summary.UniqueHosts = sortedKeys(hostSet)
	a.Summary.UniqueSNIs = sortedKeys(sniSet)
	return nil
}

// Subjects emits a `pip://NAME@VERSION` subject that is byte-identical
// to the one the pip-install attestor produces for the same package, so
// Archivista can join this sinkhole attestation to the install attestation
// by subject digest. The scan id and flows file sha256 are emitted as
// additional subjects for ad-hoc joins.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)

	if a.PackageName != "" && a.PackageVersion != "" {
		// Must mirror pip-install attestor's Subjects() exactly:
		//   name:   "pip://NAME@VERSION"
		//   digest: sha256("NAME==VERSION")
		if ds, err := cryptoutil.CalculateDigestSetFromBytes(
			[]byte(fmt.Sprintf("%s==%s", a.PackageName, a.PackageVersion)),
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		); err == nil {
			subjects[fmt.Sprintf("pip://%s@%s", a.PackageName, a.PackageVersion)] = ds
		}
	}

	if a.ScanID != "" {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes(
			[]byte(a.ScanID),
			[]cryptoutil.DigestValue{{Hash: crypto.SHA256}},
		); err == nil {
			subjects[fmt.Sprintf("pipw-sinkhole-scan://%s", a.ScanID)] = ds
		}
	}
	if a.Summary.FlowsFileSHA256 != "" {
		ds := cryptoutil.DigestSet{
			cryptoutil.DigestValue{Hash: crypto.SHA256}: a.Summary.FlowsFileSHA256,
		}
		subjects[fmt.Sprintf("pipw-sinkhole-flows-file://%s", a.ScanID)] = ds
	}
	return subjects
}

// decodeFlow unmarshals a JSONL line into our Flow struct. The mitmproxy
// addon writes snake_case field names; this mirrors them to camelCase.
func decodeFlow(line []byte, flow *Flow) error {
	var raw struct {
		ScanID          string          `json:"scan_id"`
		Timestamp       string          `json:"timestamp"`
		Event           string          `json:"event"`
		SNI             string          `json:"sni"`
		AlpnProtocols   []string        `json:"alpn_protocols"`
		Method          string          `json:"method"`
		Scheme          string          `json:"scheme"`
		Host            string          `json:"host"`
		Port            int             `json:"port"`
		Path            string          `json:"path"`
		HTTPVersion     string          `json:"http_version"`
		RequestHeaders  [][]string      `json:"request_headers"`
		RequestBody     json.RawMessage `json:"request_body"`
		ResponseStatus  int             `json:"response_status"`
		ResponseReason  string          `json:"response_reason"`
		ResponseHeaders [][]string      `json:"response_headers"`
		ResponseBody    json.RawMessage `json:"response_body"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return err
	}
	flow.ScanID = raw.ScanID
	flow.Timestamp = raw.Timestamp
	flow.Event = raw.Event
	flow.SNI = raw.SNI
	flow.AlpnProtocols = raw.AlpnProtocols
	flow.Method = raw.Method
	flow.Scheme = raw.Scheme
	flow.Host = raw.Host
	flow.Port = raw.Port
	flow.Path = raw.Path
	flow.HTTPVersion = raw.HTTPVersion
	flow.RequestHeaders = raw.RequestHeaders
	flow.ResponseStatus = raw.ResponseStatus
	flow.ResponseReason = raw.ResponseReason
	flow.ResponseHeaders = raw.ResponseHeaders
	if len(raw.RequestBody) > 0 && string(raw.RequestBody) != "null" {
		var body FlowBody
		if err := json.Unmarshal(raw.RequestBody, &body); err == nil {
			flow.RequestBody = &body
		}
	}
	if len(raw.ResponseBody) > 0 && string(raw.ResponseBody) != "null" {
		var body FlowBody
		if err := json.Unmarshal(raw.ResponseBody, &body); err == nil {
			flow.ResponseBody = &body
		}
	}
	return nil
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
