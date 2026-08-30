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

package commandrun

import (
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

// TestNonZeroExitIsRecordedEvidence: a wrapped command that exits non-zero
// used to make Attest return the raw *exec.ExitError. The workflow treats a
// plain error as "could not observe" and DROPS the attestor's payload from
// the signed collection — so the one run a policy most wants to read ("did
// the tests pass? what was the exit code?") had no command-run attestation
// at all. A cold-start user found their `exitcode == 0` rule could never
// fire because the field was never signed.
//
// The command DID run and WAS observed: the exit code is the observation.
// Attest must still return an error (cilock run keeps exiting non-zero), but
// one the workflow recognises as a verdict on good evidence, so the predicate
// — exitcode, stdout, stderr — is kept and signed.
func TestNonZeroExitIsRecordedEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	actx, err := attestation.NewContext("nonzero-exit", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(
		WithCommand([]string{"sh", "-c", "echo OUT; echo ERR 1>&2; exit 3"}),
		WithSilent(true),
	)
	err = rc.Attest(actx)
	if err == nil {
		t.Fatal("Attest returned nil for a command that exited 3 — cilock run would exit 0 and hide the failure")
	}
	if !attestation.IsDetectionError(err) {
		t.Fatalf("Attest error must be a DetectionError so the workflow keeps the payload in the signed collection; got %T: %v", err, err)
	}
	if attestation.IsSoftError(err) {
		t.Fatalf("a non-zero exit is not a soft 'nothing to do' outcome: %v", err)
	}
	if !strings.Contains(err.Error(), "3") {
		t.Errorf("error should name the exit status: %v", err)
	}
	if rc.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", rc.ExitCode)
	}
	if got := strings.TrimSpace(rc.Stdout); got != "OUT" {
		t.Errorf("Stdout = %q, want OUT", got)
	}
	if got := strings.TrimSpace(rc.Stderr); got != "ERR" {
		t.Errorf("Stderr = %q, want ERR", got)
	}
}

// TestIgnoreExitCodeStillSuppressesTheError pins the existing
// --ignore-command-exit-code contract: opting in turns the non-zero exit into
// a clean nil so postproduct attestors run and cilock run exits 0.
func TestIgnoreExitCodeStillSuppressesTheError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	actx, err := attestation.NewContext("nonzero-exit-ignored", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(
		WithCommand([]string{"sh", "-c", "exit 3"}),
		WithSilent(true),
		WithIgnoreExitCode(true),
	)
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if rc.ExitCode != 3 {
		t.Errorf("ExitCode = %d, want 3", rc.ExitCode)
	}
}
