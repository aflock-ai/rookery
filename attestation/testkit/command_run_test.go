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

package testkit

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/invopop/jsonschema"
)

// recordedCollection writes a minimal signed-shaped DSSE collection holding one
// command-run predicate (the given body; nil means no command-run at all).
func recordedCollection(t *testing.T, dir string, commandRunBody map[string]any) {
	t.Helper()
	var atts []map[string]any
	if commandRunBody != nil {
		atts = append(atts, map[string]any{"type": "https://aflock.ai/attestations/command-run/v0.1", "attestation": commandRunBody})
	}
	atts = append(atts, map[string]any{"type": "https://example.test/other/v0.1", "attestation": map[string]any{}})
	stmt, err := json.Marshal(map[string]any{
		"subject":   []map[string]any{{"name": "x"}},
		"predicate": map[string]any{"attestations": atts},
	})
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(map[string]any{
		"payload":     base64.StdEncoding.EncodeToString(stmt),
		"payloadType": "application/vnd.in-toto+json",
		"signatures":  []map[string]any{{"sig": "c2ln", "keyid": "k"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "attestation.json"), env)
}

func commandRunManifest(mode, commandRun string, recorded bool) string {
	m := "schema_version: '0.1'\nattestor: example\nsetup:\n  mode: " + mode + "\n  input: out.json\n"
	if commandRun != "" {
		m += "  command_run: " + commandRun + "\n"
	}
	if recorded {
		m += "recording:\n  attestation: attestation.json\n"
	}
	return m + "expect:\n  predicate_type: example\n"
}

// TestLoadFixtureReadsTheRecordedCommandRun pins setup.command_run: the argv
// and exit status come from the recorded collection, and every way the
// fixture cannot have them is a load error, never a replay without one.
func TestLoadFixtureReadsTheRecordedCommandRun(t *testing.T) {
	argv := []string{"sh", "-c", "tool > out.json"}
	for _, tc := range []struct {
		name       string
		mode       string
		commandRun string
		recorded   bool
		body       map[string]any
		want       *CommandRun
		wantErr    string
	}{
		{name: "recorded-exit-zero", mode: ModeProduct, commandRun: "recorded", recorded: true,
			body: map[string]any{"cmd": argv, "exitcode": 0}, want: &CommandRun{Argv: argv, ExitCode: 0}},
		{name: "recorded-exit-nonzero", mode: ModeProduct, commandRun: "recorded", recorded: true,
			body: map[string]any{"cmd": argv, "exitcode": 3}, want: &CommandRun{Argv: argv, ExitCode: 3}},
		{name: "not-declared", mode: ModeProduct, recorded: true,
			body: map[string]any{"cmd": argv, "exitcode": 0}, want: nil},
		{name: "exitcode-missing", mode: ModeProduct, commandRun: "recorded", recorded: true,
			body: map[string]any{"cmd": argv}, wantErr: "has no command-run with a cmd and an exitcode"},
		{name: "no-command-run-recorded", mode: ModeProduct, commandRun: "recorded", recorded: true,
			wantErr: "has no command-run with a cmd and an exitcode"},
		{name: "no-recording", mode: ModeProduct, commandRun: "recorded",
			wantErr: "needs recording.attestation"},
		{name: "not-product-mode", mode: ModeWorkdir, commandRun: "recorded", recorded: true,
			body: map[string]any{"cmd": argv, "exitcode": 0}, wantErr: "only product mode"},
		{name: "unknown-value", mode: ModeProduct, commandRun: "exit-0", recorded: true,
			body: map[string]any{"cmd": argv, "exitcode": 0}, wantErr: `"exit-0" is not supported`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mustWrite(t, filepath.Join(dir, "out.json"), []byte(`{}`))
			recordedCollection(t, dir, tc.body)
			mustWrite(t, filepath.Join(dir, ManifestFile), []byte(commandRunManifest(tc.mode, tc.commandRun, tc.recorded)))
			fx, err := LoadFixture(dir)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadFixture error = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFixture: %v", err)
			}
			if !reflect.DeepEqual(fx.CommandRun, tc.want) {
				t.Fatalf("CommandRun = %+v, want %+v", fx.CommandRun, tc.want)
			}
		})
	}
}

// fakeCommandRun stands in for the command-run plugin, which this package
// cannot import.
type fakeCommandRun struct{}

func (f *fakeCommandRun) Name() string                                   { return "command-run" }
func (f *fakeCommandRun) Type() string                                   { return "https://example.test/command-run/v0.1" }
func (f *fakeCommandRun) RunType() attestation.RunType                   { return attestation.ExecuteRunType }
func (f *fakeCommandRun) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(f) }
func (f *fakeCommandRun) Attest(_ *attestation.AttestationContext) error { return nil }

// completedNames is a post-product target that records which attestors had
// completed when it ran.
type completedNames struct {
	Seen []string `json:"seen"`
}

func (c *completedNames) Name() string                 { return "completed-names" }
func (c *completedNames) Type() string                 { return "https://example.test/completed-names/v0.1" }
func (c *completedNames) RunType() attestation.RunType { return attestation.PostProductRunType }
func (c *completedNames) Schema() *jsonschema.Schema   { return jsonschema.Reflect(c) }
func (c *completedNames) Attest(ctx *attestation.AttestationContext) error {
	c.Seen = nil
	for _, a := range ctx.CompletedAttestors() {
		c.Seen = append(c.Seen, a.Attestor.Name())
	}
	return nil
}

// TestProductReplayPlacesTheDeclaredCommandRun pins the driver side: a fixture
// that declares a command-run gets the builder's attestor, built from the
// fixture's argv and exit status and completed before the post-product
// target; a fixture that does not gets no command-run even when the caller
// passes a builder.
func TestProductReplayPlacesTheDeclaredCommandRun(t *testing.T) {
	var built []CommandRun
	builder := WithCommandRun(func(cr CommandRun) attestation.Attestor {
		built = append(built, cr)
		return &fakeCommandRun{}
	})
	input := filepath.Join(t.TempDir(), "out.json")
	mustWrite(t, input, []byte(`{}`))

	declared := &CommandRun{Argv: []string{"sh", "-c", "exit 4"}, ExitCode: 4}
	for _, tc := range []struct {
		name       string
		commandRun *CommandRun
		wantSeen   bool
	}{
		{name: "declared", commandRun: declared, wantSeen: true},
		{name: "not-declared", commandRun: nil, wantSeen: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			built = nil
			target := &completedNames{}
			fx := &Fixture{Name: tc.name, Attestor: "completed-names", Mode: ModeProduct, InputPath: input,
				MimeType: "application/json", CommandRun: tc.commandRun}
			res := RunAttestorWithFixture(t, fx, WithAttestor(target), builder)
			if res.RunErr != nil {
				t.Fatalf("run: %v", res.RunErr)
			}
			seen := false
			for _, n := range target.Seen {
				if n == "command-run" {
					seen = true
				}
			}
			if seen != tc.wantSeen {
				t.Fatalf("target saw completed attestors %v; command-run present = %v, want %v", target.Seen, seen, tc.wantSeen)
			}
			if tc.wantSeen && (len(built) != 1 || !reflect.DeepEqual(built[0], *declared)) {
				t.Fatalf("builder called with %+v, want exactly %+v", built, *declared)
			}
			if !tc.wantSeen && len(built) != 0 {
				t.Fatalf("builder called %d time(s) for a fixture that declares no command-run", len(built))
			}
		})
	}
}
