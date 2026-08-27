// Copyright 2025 The Aflock Authors
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

package options

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sampleSummary() *RunSummary {
	return &RunSummary{
		Step:               "build",
		WorkingDir:         "/work/repo",
		PlatformURL:        "https://platform.example.com",
		Tenant:             "acme",
		Signer:             "fulcio",
		SignerEmail:        "alice@acme.com",
		TimestampAuthority: []string{"https://platform.example.com/api/v1/timestamp"},
		FulcioURL:          "https://platform.example.com",
		ArchivistaURL:      "https://platform.example.com/archivista",
		Uploaded:           true,
		Gitoid:             "gitoid:blob:sha256:abc123",
		OutFile:            "build.att.json",
		Subjects: []RunSubject{
			// Fully-qualified predicate-URI names, as the git attestor emits them.
			{Name: "https://aflock.ai/attestations/git/v0.1/remote:git@github.com:acme/repo.git", Digests: map[string]string{"sha256": "deadbeef"}},
			{Name: "https://aflock.ai/attestations/git/v0.1/commithash:1234", Digests: map[string]string{"sha1": "1234"}},
		},
		Attestors: []AttestorOutcome{
			{Name: "git", Status: AttestorStatusRan},
			{Name: "sbom", Status: AttestorStatusSkipped, Detail: "no SBOM file found"},
			{Name: "secretscan", Status: AttestorStatusFailed, Detail: "secret detected"},
		},
		WrappedCommand: &WrappedCommand{Args: []string{"go", "build"}, ExitCode: 0},
	}
}

// TestRunSummary_JSONFields proves the structured result serializes every
// field the agent-DX spec calls for, with stable JSON keys.
func TestRunSummary_JSONFields(t *testing.T) {
	var buf bytes.Buffer
	if err := sampleSummary().WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Must be a single well-formed JSON object.
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}

	for _, key := range []string{
		"step", "gitoid", "archivista_url", "tenant", "signer",
		"timestamp_authority", "subjects", "attestors", "wrapped_command",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("JSON missing required key %q\n%s", key, buf.String())
		}
	}

	// wrapped_command.exit_code must be present and machine-readable.
	wc, ok := got["wrapped_command"].(map[string]any)
	if !ok {
		t.Fatalf("wrapped_command is not an object: %T", got["wrapped_command"])
	}
	if _, ok := wc["exit_code"]; !ok {
		t.Errorf("wrapped_command missing exit_code")
	}

	// attestors carry the ran|skipped|failed vocabulary.
	atts, ok := got["attestors"].([]any)
	if !ok || len(atts) != 3 {
		t.Fatalf("expected 3 attestors, got %#v", got["attestors"])
	}
}

// TestRunSummary_JSONIsSingleObject ensures stdout output is exactly one JSON
// object terminated by a newline — an agent can read it directly.
func TestRunSummary_JSONIsSingleObject(t *testing.T) {
	var buf bytes.Buffer
	if err := sampleSummary().WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	out := buf.String()
	if !strings.HasSuffix(out, "}\n") {
		t.Errorf("JSON output should end with }\\n, got tail %q", out[max(0, len(out)-5):])
	}
	dec := json.NewDecoder(strings.NewReader(out))
	var first map[string]any
	if err := dec.Decode(&first); err != nil {
		t.Fatalf("decode first object: %v", err)
	}
	// There must be no trailing second object.
	var second map[string]any
	if err := dec.Decode(&second); err == nil {
		t.Errorf("expected exactly one JSON object on stdout, found a second")
	}
}

// TestRunSummary_HumanAnchorLine proves the single most valuable line — the
// git remote correlation anchor — is surfaced in the human summary.
func TestRunSummary_HumanAnchorLine(t *testing.T) {
	var buf bytes.Buffer
	sampleSummary().WriteHuman(&buf)
	out := buf.String()
	if !strings.Contains(out, "anchor:     git remote git@github.com:acme/repo.git") {
		t.Errorf("human summary missing git remote anchor line:\n%s", out)
	}
	if !strings.Contains(out, "tenant:     acme") {
		t.Errorf("human summary missing tenant line:\n%s", out)
	}
	if !strings.Contains(out, "gitoid:     gitoid:blob:sha256:abc123") {
		t.Errorf("human summary missing gitoid line:\n%s", out)
	}
}

// TestRunSummary_HumanNoAnchorWarns proves that when no git remote subject is
// present, the human summary LOUDLY says correlation will not happen rather
// than staying silent (the silent-correlation-failure footgun from the spec).
func TestRunSummary_HumanNoAnchorWarns(t *testing.T) {
	s := sampleSummary()
	s.Subjects = []RunSubject{{Name: "https://aflock.ai/attestations/git/v0.1/commithash:1234"}}
	var buf bytes.Buffer
	s.WriteHuman(&buf)
	out := buf.String()
	if !strings.Contains(out, "no git remote subject") {
		t.Errorf("expected a loud no-anchor warning, got:\n%s", out)
	}
}

// TestRunSummary_AnchorIgnoresNonSegmentSubstring proves the anchor matcher
// only fires on a genuine `remote:` path segment, never an arbitrary substring
// (e.g. a subject that merely contains the bytes "remote:" mid-token).
func TestRunSummary_AnchorIgnoresNonSegmentSubstring(t *testing.T) {
	s := sampleSummary()
	s.Subjects = []RunSubject{{Name: "https://aflock.ai/attestations/foo/v0.1/notaremote:value"}}
	var buf bytes.Buffer
	s.WriteHuman(&buf)
	if !strings.Contains(buf.String(), "no git remote subject") {
		t.Errorf("matcher should not treat 'notaremote:' as the remote anchor:\n%s", buf.String())
	}
}

// TestRunSummary_ProducerDoesNotSelfAssignStandardsLevels pins the core trust
// boundary: signer kind, workflow OIDC, and a no-egress trace are useful facts,
// but they do not let the producer assess its own SLSA Build or ALPS level.
func TestRunSummary_ProducerDoesNotSelfAssignStandardsLevels(t *testing.T) {
	s := sampleSummary()
	s.WorkflowIdentity = true
	s.Tracing = "ebpf"
	s.NoExternalNetworkEgressObserved = true
	s.ComputeStandardsAssessment(false)

	if s.SLSABuildLevel != 0 {
		t.Fatalf("producer must not self-assign a SLSA Build level, got L%d", s.SLSABuildLevel)
	}
	if s.SLSABuildAssessment != "not_assessed" || s.ALPSAssessment != "not_assessed" {
		t.Fatalf("standards must remain not_assessed, got SLSA=%q ALPS=%q",
			s.SLSABuildAssessment, s.ALPSAssessment)
	}
	if s.ALPSSpecVersion != "0.1" {
		t.Fatalf("ALPS spec version = %q, want 0.1", s.ALPSSpecVersion)
	}

	var buf bytes.Buffer
	s.WriteHuman(&buf)
	out := buf.String()
	if strings.Contains(out, "SLSA Build L1") || strings.Contains(out, "SLSA Build L2") ||
		strings.Contains(out, "SLSA Build L3") || strings.Contains(out, "ALPS-1") ||
		strings.Contains(out, "ALPS-2") || strings.Contains(out, "ALPS-3") {
		t.Errorf("producer summary self-assigned a standards level:\n%s", out)
	}
	if !strings.Contains(out, "SLSA Build: not assessed") ||
		!strings.Contains(out, "ALPS 0.1: not assessed") {
		t.Errorf("human summary missing explicit not-assessed results:\n%s", out)
	}
}

// TestRunSummary_NetworkTraceIsNotHermeticity proves that zero observed network
// egress remains a narrow observation instead of being inflated into SLSA L3,
// ALPS H-Complete, or a generic hermeticity claim.
func TestRunSummary_NetworkTraceIsNotHermeticity(t *testing.T) {
	s := sampleSummary()
	s.Tracing = "ebpf"
	s.NoExternalNetworkEgressObserved = true
	s.ComputeStandardsAssessment(false)

	var buf bytes.Buffer
	s.WriteHuman(&buf)
	out := buf.String()
	if !strings.Contains(out, "no external egress observed (ebpf trace); hermeticity not assessed") {
		t.Errorf("human summary should report the narrow network observation:\n%s", out)
	}
	if strings.Contains(out, "H-Complete") || strings.Contains(out, "build is hermetic") {
		t.Errorf("network trace must not become a hermeticity modifier:\n%s", out)
	}
}

func TestRunSummary_ObservedEgressNamesEndpointsWithoutAssigningHermeticity(t *testing.T) {
	s := sampleSummary()
	s.Tracing = "ebpf"
	s.NetworkEgress = []string{"proxy.golang.org:443"}
	s.ComputeStandardsAssessment(false)

	var buf bytes.Buffer
	s.WriteHuman(&buf)
	out := buf.String()
	if !strings.Contains(out, "external egress observed (ebpf trace: proxy.golang.org:443)") {
		t.Errorf("human summary missing observed endpoint:\n%s", out)
	}
	if !strings.Contains(out, "hermeticity not assessed") {
		t.Errorf("human summary must keep hermeticity unassigned:\n%s", out)
	}
}

func TestRunSummary_FailedRunStandardsNotAssessed(t *testing.T) {
	s := sampleSummary()
	s.WorkflowIdentity = true
	s.Tracing = "ebpf"
	s.NoExternalNetworkEgressObserved = true
	s.ComputeStandardsAssessment(true)

	if s.SLSABuildLevel != 0 || s.SLSABuildAssessment != "not_assessed" || s.ALPSAssessment != "not_assessed" {
		t.Fatalf("failed run must remain unassessed: %#v", s)
	}
	if !strings.Contains(s.SLSAVerdict, "did not complete") ||
		!strings.Contains(s.ALPSVerdict, "did not produce complete evidence") {
		t.Fatalf("failed-run reasons missing: SLSA=%q ALPS=%q", s.SLSAVerdict, s.ALPSVerdict)
	}
}

// TestRunSummary_StandardsInJSON proves machine consumers get explicit status
// fields and observations, while the obsolete numeric SLSA level and ambiguous
// `hermetic` boolean are omitted.
func TestRunSummary_StandardsInJSON(t *testing.T) {
	s := sampleSummary()
	s.WorkflowIdentity = true
	s.Tracing = "ebpf"
	s.NoExternalNetworkEgressObserved = true
	s.ComputeStandardsAssessment(false)
	s.AssuranceLevel = "aal2"

	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if _, ok := got["slsa_build_level"]; ok {
		t.Errorf("unassessed summary must omit slsa_build_level, got %#v", got["slsa_build_level"])
	}
	if got["slsa_build_assessment"] != "not_assessed" || got["alps_assessment"] != "not_assessed" {
		t.Errorf("explicit assessment statuses missing: %s", buf.String())
	}
	if got["alps_spec_version"] != "0.1" {
		t.Errorf("alps_spec_version should be 0.1, got %#v", got["alps_spec_version"])
	}
	if got["workflow_identity"] != true || got["no_external_network_egress_observed"] != true {
		t.Errorf("signed-path/network observations missing: %s", buf.String())
	}
	if _, ok := got["hermetic"]; ok {
		t.Errorf("ambiguous legacy hermetic field must be omitted: %s", buf.String())
	}
	if got["assurance_level"] != "aal2" {
		t.Errorf("assurance_level should echo aal2, got %#v", got["assurance_level"])
	}
}
