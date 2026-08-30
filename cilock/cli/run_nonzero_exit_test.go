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
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	githubreview "github.com/aflock-ai/rookery/plugins/attestors/github-review"
)

// mustBeFatal asserts that an attestor error survives classifyAttestorRunError
// as a fatal leg — what drives `cilock run`'s own non-zero exit.
func mustBeFatal(t *testing.T, name string, attestErr error) {
	t.Helper()
	if attestErr == nil {
		t.Fatalf("%s: Attest returned nil", name)
	}
	agg := &workflow.AttestorRunErrors{Legs: []workflow.AttestorErrorLeg{{Attestor: name, Err: attestErr}}}
	if got := classifyAttestorRunError(agg); got == nil {
		t.Fatalf("%s: classified as non-fatal — cilock run would exit 0", name)
	}
	if len(agg.FatalLegs()) != 1 {
		t.Fatalf("%s: fatal legs = %d, want 1", name, len(agg.FatalLegs()))
	}
}

// mustBeFatalAndRecorded: the run fails AND the payload stays in the signed
// collection. Correct for an operator-configured verdict on a SUCCESSFUL
// observation — the observation happened, so deleting its evidence would make
// a positive finding indistinguishable from a scan that never ran.
func mustBeFatalAndRecorded(t *testing.T, name string, attestErr error) {
	t.Helper()
	mustBeFatal(t, name, attestErr)
	if !attestation.EvidenceIsRecordable(attestErr) {
		t.Fatalf("%s: payload would be dropped from the collection, losing the finding: %v", name, attestErr)
	}
}

// mustBeFatalAndDropped: the run fails AND the payload is kept OUT of the
// signed collection. Correct when the attestor COULD NOT OBSERVE — recording
// a partial payload would assert a clean result that was never established.
func mustBeFatalAndDropped(t *testing.T, name string, attestErr error) {
	t.Helper()
	mustBeFatal(t, name, attestErr)
	if attestation.EvidenceIsRecordable(attestErr) {
		t.Fatalf("%s: payload would be RECORDED as signed evidence even though nothing was observed: %v", name, attestErr)
	}
}

// TestRunStillFailsWhenTheWrappedCommandExitsNonZero: keeping the command-run
// predicate in the collection on non-zero exit (see
// commandrun.TestNonZeroExitIsRecordedEvidence) must NOT turn the run green.
func TestRunStillFailsWhenTheWrappedCommandExitsNonZero(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell")
	}
	actx, err := attestation.NewContext("nonzero-exit", []attestation.Attestor{}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := commandrun.New(commandrun.WithCommand([]string{"sh", "-c", "exit 3"}), commandrun.WithSilent(true))
	mustBeFatalAndRecorded(t, rc.Name(), rc.Attest(actx))
}

// TestRunFailsAndRecordsNothingWhenGitHubHasNotSeenTheCommit: github-review at
// push time (422 "No commit found for SHA") has no review state to observe.
// The run must exit non-zero AND emit no github-review attestation at all — a
// signed payload with an empty `prs` would pass an "all PRs approved" rule
// vacuously at verify time, long after this exit code is gone.
func TestRunFailsAndRecordsNothingWhenGitHubHasNotSeenTheCommit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"message":"No commit found for SHA: abc123"}`))
	}))
	defer srv.Close()

	a := githubreview.New(githubreview.WithRepo("o/r"), githubreview.WithSHA("abc123"), githubreview.WithAPIBaseURL(srv.URL), githubreview.WithToken("stub-not-a-real-token"))
	actx, err := attestation.NewContext("push-time-review", []attestation.Attestor{a}, attestation.WithWorkingDir(t.TempDir()))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	mustBeFatalAndDropped(t, a.Name(), a.Attest(actx))
}
