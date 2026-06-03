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
