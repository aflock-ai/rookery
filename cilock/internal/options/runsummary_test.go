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

// TestRunSummary_SLSALocalKeyIsL1 proves a local file-key run is reported as
// SLSA Build L1 (forgeable provenance) with an explicit upgrade hint naming the
// platform — so a user who ran the slsa attestor does NOT assume a higher level.
func TestRunSummary_SLSALocalKeyIsL1(t *testing.T) {
	s := sampleSummary()
	s.Signer = "file"
	s.ComputeSLSA("https://platform.example.com", false)
	if s.SLSABuildLevel != 1 {
		t.Fatalf("local file key should be SLSA Build L1, got L%d", s.SLSABuildLevel)
	}
	var buf bytes.Buffer
	s.WriteHuman(&buf)
	out := buf.String()
	if !strings.Contains(out, "SLSA Build L1") {
		t.Errorf("human summary missing SLSA Build L1 verdict:\n%s", out)
	}
	if !strings.Contains(out, "cilock login --workflow-identity --platform-url https://platform.example.com") {
		t.Errorf("human summary missing the upgrade hint with the platform URL:\n%s", out)
	}
}

// TestRunSummary_SLSAFulcioKindAloneIsNotL3 is the regression guard for the
// over-claim a code review caught: the achieved level must derive from the
// actual trusted workflow signing path, NOT the signer-kind string. A run whose
// Signer contains "fulcio" but that did NOT take cilock's platform
// workflow-identity path (e.g. an explicit --signer-fulcio-token, or an offline
// run pointed at a Fulcio URL) is not attestable as isolated ⇒ stays at L1, even
// if the build happened to be hermetic.
func TestRunSummary_SLSAFulcioKindAloneIsNotL3(t *testing.T) {
	s := sampleSummary()
	s.Signer = "fulcio"        // signer KIND says fulcio …
	s.WorkflowIdentity = false // … but cilock did NOT mint a platform workflow identity
	s.Tracing = "ebpf"
	s.Hermetic = true // a hermetic build cannot rescue a non-isolated identity
	s.ComputeSLSA("https://platform.example.com", false)
	if s.SLSABuildLevel != 1 {
		t.Fatalf("fulcio signer kind WITHOUT the workflow-identity path must be L1, got L%d", s.SLSABuildLevel)
	}
}

// TestRunSummary_SLSAWorkflowIdentityNoTraceIsL2 proves an isolated platform
// workflow identity reaches L2 (non-forgeable provenance) but NOT L3 without
// hermeticity evidence — an untraced build's hermeticity is unknown.
func TestRunSummary_SLSAWorkflowIdentityNoTraceIsL2(t *testing.T) {
	s := sampleSummary()
	s.Signer = "fulcio"
	s.WorkflowIdentity = true
	s.Tracing = "" // not traced ⇒ hermeticity unknown
	s.ComputeSLSA("https://platform.example.com", false)
	if s.SLSABuildLevel != 2 {
		t.Fatalf("workflow identity without tracing should be L2, got L%d", s.SLSABuildLevel)
	}
	if !strings.Contains(s.SLSAVerdict, "--trace") {
		t.Errorf("L2 verdict should steer to --trace for L3, got: %q", s.SLSAVerdict)
	}
}

// TestRunSummary_SLSAWorkflowIdentityWithEgressIsL2 proves a traced build that
// reached the network is reported NOT hermetic and held at L2, with the egress
// endpoint named as the evidence.
func TestRunSummary_SLSAWorkflowIdentityWithEgressIsL2(t *testing.T) {
	s := sampleSummary()
	s.Signer = "fulcio"
	s.WorkflowIdentity = true
	s.Tracing = "ebpf"
	s.Hermetic = false
	s.NetworkEgress = []string{"proxy.golang.org:443"}
	s.ComputeSLSA("https://platform.example.com", false)
	if s.SLSABuildLevel != 2 {
		t.Fatalf("traced build WITH network egress should be L2, got L%d", s.SLSABuildLevel)
	}
	if !strings.Contains(s.SLSAVerdict, "proxy.golang.org:443") {
		t.Errorf("non-hermetic verdict should name the egress endpoint, got: %q", s.SLSAVerdict)
	}
}

// TestRunSummary_SLSAWorkflowIdentityHermeticIsL3 proves the full L3 path:
// isolated workflow identity + a traced build with zero external network egress.
func TestRunSummary_SLSAWorkflowIdentityHermeticIsL3(t *testing.T) {
	s := sampleSummary()
	s.Signer = "fulcio"
	s.WorkflowIdentity = true
	s.Tracing = "ebpf"
	s.Hermetic = true
	s.ComputeSLSA("https://platform.example.com", false)
	if s.SLSABuildLevel != 3 {
		t.Fatalf("workflow identity + hermetic trace should be L3, got L%d", s.SLSABuildLevel)
	}
	var buf bytes.Buffer
	s.WriteHuman(&buf)
	out := buf.String()
	if !strings.Contains(out, "SLSA Build L3") {
		t.Errorf("human summary missing SLSA Build L3 verdict:\n%s", out)
	}
	if !strings.Contains(out, "hermetic") {
		t.Errorf("human summary missing the hermetic build evidence line:\n%s", out)
	}
}

// TestRunSummary_SLSAOfflineHintHasPlaceholder proves an offline run (no
// platform) still emits an actionable upgrade hint, with a placeholder for the
// platform the operator must supply.
func TestRunSummary_SLSAOfflineHintHasPlaceholder(t *testing.T) {
	s := sampleSummary()
	s.Signer = "file"
	s.ComputeSLSA("", false)
	if !strings.Contains(s.SLSAVerdict, "<platform>") {
		t.Errorf("offline verdict should carry a <platform> placeholder, got: %q", s.SLSAVerdict)
	}
}

// TestRunSummary_SLSAFailedRunNotAssessed is the regression guard for the
// overclaim a code review caught: ComputeSLSA must NOT hand back an L1+ floor
// when the run failed to produce signed provenance (fatal signer/attestor error
// or a non-zero wrapped command). The L1 floor is "a signed attestation EXISTS";
// a failed run has none, so it is held at level 0 with an explicit not-assessed
// verdict — even on the strongest would-be evidence (workflow identity + hermetic
// trace). Without this, a release gate keying on slsa_build_level could trust
// provenance the run never emitted.
func TestRunSummary_SLSAFailedRunNotAssessed(t *testing.T) {
	s := sampleSummary()
	s.Signer = "fulcio"
	s.WorkflowIdentity = true // would otherwise reach L3 …
	s.Tracing = "ebpf"
	s.Hermetic = true
	s.ComputeSLSA("https://platform.example.com", true) // … but the run FAILED
	if s.SLSABuildLevel != 0 {
		t.Fatalf("a failed run must be SLSA level 0 (not assessed), got L%d", s.SLSABuildLevel)
	}
	if !strings.Contains(s.SLSAVerdict, "not assessed") {
		t.Errorf("failed-run verdict should say 'not assessed', got: %q", s.SLSAVerdict)
	}
	var buf bytes.Buffer
	s.WriteHuman(&buf)
	if out := buf.String(); strings.Contains(out, "SLSA Build L") {
		t.Errorf("failed run must not print any 'SLSA Build L<n>' claim:\n%s", out)
	}
}

// TestRunSummary_SLSAInJSON proves the achieved level + verdict + the evidence
// fields are serialized so an agent can branch on slsa_build_level (and audit
// WHY) without parsing prose.
func TestRunSummary_SLSAInJSON(t *testing.T) {
	s := sampleSummary()
	s.Signer = "fulcio"
	s.WorkflowIdentity = true
	s.Tracing = "ebpf"
	s.Hermetic = true
	s.ComputeSLSA("https://platform.example.com", false)
	s.AssuranceLevel = "aal2"
	var buf bytes.Buffer
	if err := s.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	lvl, ok := got["slsa_build_level"].(float64)
	if !ok || int(lvl) != 3 {
		t.Errorf("slsa_build_level should be 3, got %#v", got["slsa_build_level"])
	}
	if got["workflow_identity"] != true {
		t.Errorf("JSON should carry workflow_identity=true, got %#v", got["workflow_identity"])
	}
	if got["hermetic"] != true {
		t.Errorf("JSON should carry hermetic=true, got %#v", got["hermetic"])
	}
	if _, ok := got["slsa_verdict"]; !ok {
		t.Errorf("JSON missing slsa_verdict:\n%s", buf.String())
	}
	if got["assurance_level"] != "aal2" {
		t.Errorf("assurance_level should echo aal2, got %#v", got["assurance_level"])
	}
}
