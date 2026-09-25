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

package policy

// #9820 E8: a Rego evaluation that runs out of its deadline produced no
// verdict, yet it was recorded as an ordinary rejection and signed FAILED,
// which warn mode admits and a human can override. The Pushgate contract says
// a timeout is unsigned: it is a refusal to answer, like an unanswered AI
// question. These tests mutate the package-level deadline: no t.Parallel().

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// slowRego takes far longer than a millisecond on any machine.
const slowRego = "package slow\n\ndeny[msg] {\n\tcount([x | x := numbers.range(1, 20000000)[_]; x < 0]) > 0\n\tmsg := \"never\"\n}\n"

func withRegoDeadline(t *testing.T, d time.Duration) {
	t.Helper()
	prev := regoEvalTimeout
	regoEvalTimeout = d
	t.Cleanup(func() { regoEvalTimeout = prev })
}

func TestRegoTimeout_IsARefusalNotADeny(t *testing.T) {
	withRegoDeadline(t, time.Millisecond)
	err := EvaluateRegoPolicy(&lintAttestor{}, []RegoPolicy{{Name: "slow.rego", Module: []byte(slowRego)}})

	var refusal ErrRegoEvaluationRefused
	require.ErrorAs(t, err, &refusal, "a timed-out evaluation produced no verdict")
	require.Equal(t, "timeout", refusal.Code)
	var denied ErrPolicyDenied
	require.False(t, errors.As(err, &denied), "a timeout is not the policy denying")
}

func TestRefusedResults_RegoTimeoutIsARefusal(t *testing.T) {
	steps := map[string]StepResult{
		"build": {
			Step: "build",
			Rejected: []RejectedCollection{{Reason: ErrCollectionValidationFailed{Reasons: []error{
				ErrRegoEvaluationRefused{Code: "timeout", cause: context.DeadlineExceeded},
			}}}},
		},
	}
	var refusal ErrRegoEvaluationRefused
	require.ErrorAs(t, refusedAIResults(steps, nil), &refusal)

	// Beside a passing witness the step is satisfied, as for an AI refusal.
	steps["build"] = StepResult{Step: "build", Passed: []PassedCollection{{}}, Rejected: steps["build"].Rejected}
	require.NoError(t, refusedAIResults(steps, nil))
}

// End to end: Verify returns the refusal as an error instead of a signed
// FAILED verdict.
func TestRegoTimeout_VerifyReturnsARefusal(t *testing.T) {
	withRegoDeadline(t, time.Millisecond)
	f := newFanoutFixture(t)
	p := aiPolicyWithGuard(f)
	step := p.Steps[fanoutStepName]
	step.Attestations[0].AiPolicies = nil
	step.Attestations[0].RegoPolicies = []RegoPolicy{{Name: "slow.rego", Module: []byte(slowRego)}}
	p.Steps[fanoutStepName] = step

	mem := source.NewMemorySource()
	for _, env := range fanoutCorpus(t, f, 0) {
		require.NoError(t, mem.LoadEnvelope(env.Reference, env.Envelope))
	}
	accepted, _, err := p.Verify(context.Background(),
		WithVerifiedSource(source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))),
		WithSubjectDigests([]string{fanoutCommitDigest, fanoutHubDigest}))
	require.False(t, accepted)
	var refusal ErrRegoEvaluationRefused
	require.ErrorAs(t, err, &refusal, "a timeout must surface as a refusal to answer, not a signed FAILED")
}
