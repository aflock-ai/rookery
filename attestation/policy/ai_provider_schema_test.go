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

// Item 5: an injected AI provider that returned no responses, or a
// status other than exactly "PASS" or "FAIL" (for example "pass"), passed the
// gate, because the gate only rejected on an exact "FAIL". An empty or
// out-of-schema provider response is a FAIL.

import (
	"context"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// schemaProvider answers every policy with status, naming the policy's model.
type schemaProvider struct{ status string }

func (p schemaProvider) Evaluate(_ context.Context, _ attestation.Attestor, pol AiPolicy, _ string) (AiResponse, error) {
	return AiResponse{Status: p.status, Reason: "scripted", Model: pol.Model}, nil
}

// schemaBatchProvider returns a fixed batch whatever it is asked.
type schemaBatchProvider struct {
	schemaProvider
	batch []AiResponse
}

func (p schemaBatchProvider) EvaluateBatch(context.Context, attestation.Attestor, []AiPolicy, string) ([]AiResponse, error) {
	return p.batch, nil
}

func TestAiProvider_OutOfSchemaStatusIsAFail(t *testing.T) {
	pols := []AiPolicy{{Name: "p", Prompt: "x", Model: "m"}}
	for _, status := range []string{"pass", "Pass", "", "MAYBE", "PASS "} {
		_, err := EvaluateAIPolicyWithProvider(context.Background(), &charAttestor{}, pols, "http://127.0.0.1:1", schemaProvider{status})
		require.Error(t, err, "status %q must fail the policy", status)
	}
	resp, err := EvaluateAIPolicyWithProvider(context.Background(), &charAttestor{}, pols, "http://127.0.0.1:1", schemaProvider{AiStatusPass})
	require.NoError(t, err)
	require.Len(t, resp, 1)
}

func TestAiBatchProvider_MissingOrMalformedResponsesAreAFail(t *testing.T) {
	pols := []AiPolicy{{Name: "a", Prompt: "x", Model: "m"}, {Name: "b", Prompt: "y", Model: "m"}}
	for name, batch := range map[string][]AiResponse{
		"no responses":      nil,
		"one of two":        {{Status: AiStatusPass, Model: "m"}},
		"three for two":     {{Status: AiStatusPass, Model: "m"}, {Status: AiStatusPass, Model: "m"}, {Status: AiStatusPass, Model: "m"}},
		"lower-case status": {{Status: AiStatusPass, Model: "m"}, {Status: "pass", Model: "m"}},
		"empty status":      {{Status: AiStatusPass, Model: "m"}, {Model: "m"}},
	} {
		_, err := EvaluateAIPolicyWithProvider(context.Background(), &charAttestor{}, pols, "http://127.0.0.1:1",
			schemaBatchProvider{batch: batch})
		require.Error(t, err, name)
	}
	_, err := EvaluateAIPolicyWithProvider(context.Background(), &charAttestor{}, pols, "http://127.0.0.1:1",
		schemaBatchProvider{batch: []AiResponse{{Status: AiStatusPass, Model: "m"}, {Status: AiStatusFail, Model: "m"}}})
	require.NoError(t, err, "a well-formed batch is returned; the FAIL is the gate's to act on")
}

// End to end: a provider that answers "pass" does not let the step pass.
func TestAiProvider_OutOfSchemaStatusFailsTheStep(t *testing.T) {
	f := newFanoutFixture(t)
	p := aiPolicyWithGuard(f)
	mem := source.NewMemorySource()
	for _, env := range fanoutCorpus(t, f, 0) {
		require.NoError(t, mem.LoadEnvelope(env.Reference, env.Envelope))
	}
	verify := func(provider AiProvider) bool {
		accepted, _, err := p.Verify(context.Background(),
			WithVerifiedSource(source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))),
			WithSubjectDigests([]string{fanoutCommitDigest, fanoutHubDigest}),
			WithAiServerURL("http://127.0.0.1:1"),
			WithAiProvider(provider))
		require.NoError(t, err)
		return accepted
	}
	require.True(t, verify(schemaProvider{AiStatusPass}), "sanity: an exact PASS passes the fixture")
	require.False(t, verify(schemaProvider{"pass"}), "an out-of-schema status must not pass the step")
	require.False(t, verify(schemaBatchProvider{batch: nil}), "no responses must not pass the step")
}
