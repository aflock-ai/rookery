// Copyright 2026 The Archivista Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// countingAIServer is a fake AI policy server that counts evaluation
// requests and always returns PASS.
func countingAIServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		inner, err := json.Marshal(AiResponse{Status: AiStatusPass, Reason: "ok"})
		require.NoError(t, err)
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{"response": string(inner)}))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

// aiPolicyWithGuard is the fan-out fixture policy with one AI policy added
// to the required attestation, so gate evaluation makes an external call.
func aiPolicyWithGuard(f *fanoutFixture) Policy {
	return Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: map[string]PublicKey{
			f.keyID: {KeyID: f.keyID, Key: []byte(f.pubPEM)},
		},
		Steps: map[string]Step{
			fanoutStepName: {
				Name: fanoutStepName,
				Attestations: []Attestation{{
					Type:       fanoutAttestorType,
					AiPolicies: []AiPolicy{{Name: "ai-gate", Prompt: "evaluate", Model: "test-model"}},
				}},
				Functionaries: []Functionary{{Type: "publickey", PublicKeyID: f.keyID}},
			},
		},
	}
}

// TestInterleave_HubRejectedCandidatesMakeNoAICalls pins the side-effect
// contract of the streamed pipeline under the subject fan-out guard: gate
// evaluation calls an external AI server, and the batch path only ever gates
// GUARD-ADMITTED candidates — so a hub-flooded corpus must produce exactly
// one AI request per admitted candidate per policy, and ZERO for hub-rejected
// candidates. Without gate deferral the streamed path would provisionally
// evaluate every not-yet-provably-rejected hub candidate (at least the first
// maxFanout arrivals), so this test fails mechanically if the deferral is
// removed.
func TestInterleave_HubRejectedCandidatesMakeNoAICalls(t *testing.T) {
	f := newFanoutFixture(t)
	const hubOnly = 12
	corpus := fanoutCorpus(t, f, hubOnly)

	run := func(src source.VerifiedSourcer) (int64, map[string]StepResult) {
		srv, calls := countingAIServer(t)
		accepted, results, err := aiPolicyWithGuard(f).Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{fanoutCommitDigest, fanoutHubDigest}),
			WithMaxSubjectFanout(4),
			WithAiServerURL(srv.URL),
		)
		require.NoError(t, err)
		require.True(t, accepted, "commit A's own evidence must still pass")
		return calls.Load(), results
	}

	newSource := func() *source.VerifiedSource {
		mem := source.NewMemorySource()
		for _, e := range corpus {
			require.NoError(t, mem.LoadEnvelope(e.Reference, e.Envelope))
		}
		return source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))
	}

	// Streamed (interleaved) path.
	streamCalls, streamResults := run(newSource())
	sr := streamResults[fanoutStepName]
	require.Len(t, sr.Passed, 2, "only the commit closure evidence is admitted")
	assert.EqualValues(t, 2, streamCalls,
		"admitted candidates make exactly one AI call each; any more means hub-rejected candidates were AI-evaluated (gate deferral reverted?)")

	// Batch path: same corpus, same count — the parity the deferral exists
	// to preserve.
	batchCalls, batchResults := run(batchOnlyVerifiedSourcer{inner: newSource()})
	require.Len(t, batchResults[fanoutStepName].Passed, 2)
	assert.Equal(t, batchCalls, streamCalls, "streamed path AI request count must match the batch path")

	// Hub rejections are still fully reported.
	hubRejections := 0
	for _, rc := range sr.Rejected {
		if rc.Reason != nil && len(rc.Reason.Error()) > 0 {
			hubRejections++
		}
	}
	assert.GreaterOrEqual(t, hubRejections, hubOnly, "hub-rejected candidates must remain visible in step results")
}
