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

// jade:ring local

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/stretchr/testify/require"
)

// #9308: a wrapped command that exits non-zero must leave a signed command-run
// record behind, because every exit-code deny rule in a shipped policy reads
// `input.exitcode` from that record. When the record is dropped the verifier
// reports "0 candidate envelopes" and the remediation text the policy author
// wrote is unreachable. These tests drive the real `cilock run` → `cilock sign`
// → `cilock verify` commands in-process, offline, with a local key.

const commandRunV02 = "https://aflock.ai/attestations/command-run/v0.2"

// errorCaptureLogger keeps error-level lines. The deny reason a policy produces
// is LOGGED by verify (the returned error is the generic "policy verification
// failed"), so a test that wants to prove the rule fired has to read the log.
type errorCaptureLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *errorCaptureLogger) record(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *errorCaptureLogger) Errorf(format string, args ...interface{}) { l.record(format, args...) }
func (l *errorCaptureLogger) Error(args ...interface{})                 { l.record("%s", fmt.Sprint(args...)) }
func (l *errorCaptureLogger) Warnf(format string, args ...interface{})  {}
func (l *errorCaptureLogger) Warn(args ...interface{})                  {}
func (l *errorCaptureLogger) Debugf(format string, args ...interface{}) {}
func (l *errorCaptureLogger) Debug(args ...interface{})                 {}
func (l *errorCaptureLogger) Infof(format string, args ...interface{})  {}
func (l *errorCaptureLogger) Info(args ...interface{})                  {}
func (l *errorCaptureLogger) joined() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

// signedCollection is the decoded in-toto statement a `cilock run -o` envelope
// carries, reduced to what these tests read.
type signedCollection struct {
	Subjects []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		Attestations []struct {
			Type        string          `json:"type"`
			Attestation json.RawMessage `json:"attestation"`
		} `json:"attestations"`
	} `json:"predicate"`
}

func readSignedCollection(t *testing.T, path string) signedCollection {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "the signed envelope must be written even when the command fails")
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	require.NotEmpty(t, env.Signatures, "envelope must be signed")
	var stmt signedCollection
	require.NoError(t, json.Unmarshal(env.Payload, &stmt))
	return stmt
}

func (c signedCollection) attestationTypes() []string {
	types := make([]string, 0, len(c.Predicate.Attestations))
	for _, a := range c.Predicate.Attestations {
		types = append(types, a.Type)
	}
	return types
}

// commandRunExitCode returns the signed exit code and whether a command-run
// record is present at all.
func (c signedCollection) commandRunExitCode(t *testing.T) (int, bool) {
	t.Helper()
	for _, a := range c.Predicate.Attestations {
		if a.Type != commandRunV02 {
			continue
		}
		var cr struct {
			ExitCode *int `json:"exitcode"`
		}
		require.NoError(t, json.Unmarshal(a.Attestation, &cr))
		require.NotNil(t, cr.ExitCode, "command-run must carry a numeric exitcode (the shipped regos refuse a missing one)")
		return *cr.ExitCode, true
	}
	return 0, false
}

// materialSubject is the digest verify is pointed at. The collection's own
// subjects are the entry point into the attestation graph; the material tree
// root is one every run carries.
func (c signedCollection) materialSubject(t *testing.T) string {
	t.Helper()
	for _, s := range c.Subjects {
		if strings.HasSuffix(s.Name, "tree:materials") {
			return "sha256:" + s.Digest["sha256"]
		}
	}
	t.Fatalf("no material tree subject among %d subjects", len(c.Subjects))
	return ""
}

// runOffline mints one step with a local key and no platform. workdir is both
// the wrapped command's cwd and the material/product capture root, so the walk
// stays inside the test's temp dir.
func runOffline(t *testing.T, keyPath, workdir, outfile string, extra []string, argv ...string) error {
	t.Helper()
	args := make([]string, 0, 14+len(extra)+len(argv))
	args = append(args, "run", "--offline", "--enable-archivista=false", "-k", keyPath,
		"--step", "push-tests", "-a", "environment", "--workingdir", workdir, "-o", outfile)
	args = append(args, extra...)
	args = append(args, "--")
	args = append(args, argv...)
	return executeCmd(args...)
}

// writeExitCodePolicy writes and signs a one-step policy whose only rule is the
// shape every shipped exit-code gate uses: deny when input.exitcode != 0, with
// remediation text in the message. Returns the signed policy path.
func writeExitCodePolicy(t *testing.T, dir, keyPath, pubPath string) string {
	t.Helper()
	pubPEM, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	verifier, err := cryptoutil.NewVerifierFromReader(bytes.NewReader(pubPEM))
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	rego := `package pushtests

deny[msg] {
	input.exitcode != 0
	msg := sprintf("push-tests exited %d: fix the failure it printed, then re-mint", [input.exitcode])
}
`
	policy := map[string]any{
		"expires": "2099-01-01T00:00:00Z",
		"steps": map[string]any{
			"push-tests": map[string]any{
				"name":          "push-tests",
				"functionaries": []map[string]any{{"type": "publickey", "publickeyid": keyID}},
				"attestations": []map[string]any{{
					"type": commandRunV02,
					"regopolicies": []map[string]any{{
						"name":   "exit",
						"module": base64.StdEncoding.EncodeToString([]byte(rego)),
					}},
				}},
			},
		},
		"publickeys": map[string]any{
			keyID: map[string]any{"keyid": keyID, "key": base64.StdEncoding.EncodeToString(pubPEM)},
		},
	}
	raw, err := json.Marshal(policy)
	require.NoError(t, err)
	unsigned := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(unsigned, raw, 0o600))
	signed := filepath.Join(dir, "policy.signed.json")
	require.NoError(t, executeCmd("sign", "--platform-url", "", "-k", keyPath, "-f", unsigned, "-o", signed))
	return signed
}

// TestRunHelpShowsIgnoreCommandExitCode: the flag that turns a non-zero exit
// into a recorded-but-non-fatal outcome is a gate-shaping decision, so it must
// be on the concise `cilock run --help` page, not one of 80-odd flags behind
// --help-advanced. The issue's "has no CLI flag" report was exactly this: the
// flag existed and nobody could find it.
func TestRunHelpShowsIgnoreCommandExitCode(t *testing.T) {
	stdout, _, err := executeCmdOutput("run", "--help")
	require.NoError(t, err)
	require.Contains(t, stdout, "--ignore-command-exit-code",
		"cilock run --help must list --ignore-command-exit-code in the concise flag set")
	flag := RunCmd().Flags().Lookup("ignore-command-exit-code")
	require.NotNil(t, flag)
	require.NotContains(t, flag.Usage, "v0.1", "the help text must name the predicate cilock actually emits (command-run/v0.2)")
	require.Contains(t, flag.Usage, "recorded", "the help text must say the exit code is recorded either way; the flag only changes cilock's own exit status")
}

// TestFailingCommandEnvelopeReachesExitCodeDenyRule is the end-to-end claim of
// #9308: a failing command still produces a signed collection with a
// command-run record carrying the real exit code, `cilock run` itself still
// exits non-zero, and a policy deny rule on input.exitcode reaches that record
// and prints its remediation text. A passing run attests exactly the same
// attestation types and passes the same policy.
func TestFailingCommandEnvelopeReachesExitCodeDenyRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	work := filepath.Join(dir, "work")
	require.NoError(t, os.MkdirAll(work, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(work, "input.txt"), []byte("material\n"), 0o600))

	failing := filepath.Join(dir, "failing.json")
	err := runOffline(t, keyPath, work, failing, nil, "sh", "-c", "exit 3")
	require.Error(t, err, "cilock run must still fail when the wrapped command fails")
	require.Contains(t, err.Error(), "exited with status 3")

	failed := readSignedCollection(t, failing)
	code, present := failed.commandRunExitCode(t)
	require.True(t, present, "command-run/v0.2 must be in the signed collection of a failing run; got %v", failed.attestationTypes())
	require.Equal(t, 3, code)

	passing := filepath.Join(dir, "passing.json")
	require.NoError(t, runOffline(t, keyPath, work, passing, nil, "sh", "-c", "exit 0"))
	passed := readSignedCollection(t, passing)
	code, present = passed.commandRunExitCode(t)
	require.True(t, present)
	require.Equal(t, 0, code)
	require.ElementsMatch(t, passed.attestationTypes(), failed.attestationTypes(),
		"a failing run must attest the same attestation types as a passing one — only the recorded exit code differs")

	signedPolicy := writeExitCodePolicy(t, dir, keyPath, pubPath)

	logs, err := verifyOffline(signedPolicy, pubPath, failing, failed.materialSubject(t))
	require.Error(t, err, "the exit-code deny rule must fail verification of the failing run")
	require.Contains(t, logs, "push-tests exited 3: fix the failure it printed, then re-mint",
		"the deny rule's remediation text must reach the operator; a dropped command-run record yields 'no collection passed verification' instead")
	require.NotContains(t, logs, "verifying 0 candidate envelope", "the failing run's envelope must be a verify candidate")

	_, err = verifyOffline(signedPolicy, pubPath, passing, passed.materialSubject(t))
	require.NoError(t, err, "the passing run must satisfy the same policy")
}

// verifyOffline drives `cilock verify` against one local envelope and returns
// the error-level log lines with the verdict. The root command installs its
// own stderr logger when built, so the verify subcommand is driven directly
// under a capturing logger instead of through New().
func verifyOffline(signedPolicy, pubPath, envelope, subject string) (string, error) {
	logs := &errorCaptureLogger{}
	log.SetLogger(logs)
	defer log.SetLogger(log.SilentLogger{})
	cmd := VerifyCmd()
	cmd.SetArgs([]string{"--offline", "-p", signedPolicy, "-k", pubPath, "-a", envelope, "-s", subject})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	return logs.joined(), err
}

// TestIgnoreCommandExitCodeRecordsTheCodeAndExitsZero pins the flag's contract
// end to end: with --ignore-command-exit-code the run exits 0, and the signed
// command-run record still carries the real exit code for a policy to deny on.
func TestIgnoreCommandExitCodeRecordsTheCodeAndExitsZero(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	work := filepath.Join(dir, "work")
	require.NoError(t, os.MkdirAll(work, 0o750))

	out := filepath.Join(dir, "ignored.json")
	require.NoError(t, runOffline(t, keyPath, work, out, []string{"--ignore-command-exit-code"}, "sh", "-c", "exit 5"),
		"--ignore-command-exit-code must make cilock run exit 0 on a non-zero command exit")
	code, present := readSignedCollection(t, out).commandRunExitCode(t)
	require.True(t, present)
	require.Equal(t, 5, code, "ignoring the exit code for cilock's own status must not rewrite the recorded one")
}

// TestNonZeroExitIsRecordableEvidenceForTheCollection is the unit-level
// invariant the end-to-end test rests on, stated against the real predicate the
// workflow applies (attestation.EvidenceIsRecordable): the error a non-zero
// exit produces keeps the payload in the collection.
func TestNonZeroExitIsRecordableEvidenceForTheCollection(t *testing.T) {
	err := attestation.NewDetectionError("command exited with status 1")
	require.True(t, attestation.EvidenceIsRecordable(err))
	require.False(t, attestation.EvidenceIsRecordable(fmt.Errorf("exit status 1")),
		"a raw exec error is 'could not observe' and drops the payload — the pre-#8541 defect")
}
