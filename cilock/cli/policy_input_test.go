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

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeStepEnvelope writes an unsigned DSSE envelope for one step carrying a
// command-run and a secretscan attestation.
func writeStepEnvelope(t *testing.T) string {
	t.Helper()
	stmt := map[string]any{
		"subject": []any{map[string]any{"name": "git/v0.1/commithash:abc", "digest": map[string]string{"sha1": "abc"}}},
		"predicate": map[string]any{"name": "tests", "attestations": []any{
			map[string]any{"type": "https://aflock.ai/attestations/command-run/v0.2", "attestation": map[string]any{"cmd": []string{"go", "test", "./..."}, "exitcode": 0}},
			map[string]any{"type": "https://aflock.ai/attestations/secretscan/v0.1", "attestation": map[string]any{"findings": []any{}}},
		}},
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": payload, "signatures": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "tests.json")
	if err := os.WriteFile(path, env, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func execPolicyInput(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := PolicyInputCmd()
	cmd.SetArgs(args)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err := cmd.Execute()
	return out.String(), err
}

// Onbsim 2026-09-25: agents decoded their own envelopes with
// `jq '.payload | @base64d | fromjson | .predicate.attestations[] | select(.type==...)'`
// to learn the fields a rego rule reads, and jq was not installed (34 failures
// in 17 runs). cilock shows it directly.
func TestPolicyInputSummarizesAStep(t *testing.T) {
	out, err := execPolicyInput(t, writeStepEnvelope(t))
	if err != nil {
		t.Fatalf("summary: %v\n%s", err, out)
	}
	for _, want := range []string{"step: tests", "command-run", "https://aflock.ai/attestations/command-run/v0.2", "cmd", "exitcode", "secretscan", "findings", "--attestor"} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
	}
}

func TestPolicyInputPrintsTheRegoInputForOneAttestor(t *testing.T) {
	path := writeStepEnvelope(t)
	for _, name := range []string{"command-run", "https://aflock.ai/attestations/command-run/v0.2"} {
		out, err := execPolicyInput(t, path, "--attestor", name)
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		var input map[string]any
		if err := json.Unmarshal([]byte(out), &input); err != nil {
			t.Fatalf("%s: stdout must be exactly the JSON rego sees as input: %v\n%s", name, err, out)
		}
		if input["exitcode"] != float64(0) {
			t.Errorf("%s: wrong attestation: %v", name, input)
		}
	}
}

func TestPolicyInputNamesWhatTheEnvelopeCarriesForAnUnknownAttestor(t *testing.T) {
	out, err := execPolicyInput(t, writeStepEnvelope(t), "--attestor", "sarif")
	if err == nil {
		t.Fatal("an attestor the envelope does not carry is an error")
	}
	msg := err.Error() + out
	for _, want := range []string{"sarif", "command-run", "secretscan"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should name %q: %s", want, msg)
		}
	}
}

func TestPolicyInputRefusesAFileThatIsNotAnEnvelope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"steps":{},"expires":"2027-01-01T00:00:00Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := execPolicyInput(t, path)
	if err == nil || !strings.Contains(err.Error(), "not a DSSE envelope") {
		t.Fatalf("want a clear refusal naming what the file is not, got %v", err)
	}
}

// The verifier wraps an attestation as input.attestation whenever the step has
// cross-step or timestamp context (attestation/policy buildRegoInput), which a
// platform-timestamped step always has. A rule written against bare input
// fields would never match there, so the summary and help say how to read it.
func TestPolicyInputSaysWhereARuleReadsTheAttestation(t *testing.T) {
	out, err := execPolicyInput(t, writeStepEnvelope(t))
	if err != nil {
		t.Fatalf("summary: %v\n%s", err, out)
	}
	for _, want := range []string{"input.attestation", `object.get(input, "attestation", input)`} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q:\n%s", want, out)
		}
		if !strings.Contains(PolicyInputCmd().Long, want) {
			t.Errorf("help missing %q", want)
		}
	}
}
