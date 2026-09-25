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

// #9820 E5: typed Jev policies refuse a resolved model other than the one the
// policy pins, but the generative (Ollama) path and injected providers never
// checked which model answered. Every provider's resolved model must equal the
// policy's, or the evaluation is refused (no verdict), the same as Jev.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

func requireModelRefusal(t *testing.T, err error) {
	t.Helper()
	var refusal ErrAIEvaluationRefused
	require.True(t, errors.As(err, &refusal), "want a refusal, got %v", err)
	require.Equal(t, "model_mismatch", refusal.Code)
}

// ollamaEnvelope serves a raw /api/generate envelope whose model the test
// chooses; "" omits the member.
func ollamaEnvelope(t *testing.T, model, inner string) string {
	t.Helper()
	env := map[string]string{"response": inner}
	if model != "" {
		env["model"] = model
	}
	srv, _ := newAiServer(t, func(w http.ResponseWriter, _ *http.Request) {
		body, err := json.Marshal(env)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	return srv.URL
}

func TestOllama_ResolvedModelIsPinned(t *testing.T) {
	pol := AiPolicy{Name: "p", Prompt: "x", Model: "llama3"}
	pass := `{"status":"PASS","reason":"ok"}`

	_, err := ExecuteAiPolicy(&charAttestor{}, pol, ollamaEnvelope(t, "llama3-uncensored", pass))
	requireModelRefusal(t, err)

	_, err = ExecuteAiPolicy(&charAttestor{}, pol, ollamaEnvelope(t, "", pass))
	requireModelRefusal(t, err)

	resp, err := ExecuteAiPolicy(&charAttestor{}, pol, ollamaEnvelope(t, "llama3", pass))
	require.NoError(t, err)
	require.Equal(t, AiStatusPass, resp.Status)
	require.Equal(t, "llama3", resp.Model, "the resolved model is recorded")
}

// A FAIL from the wrong model is not a verdict either.
func TestOllama_FailFromTheWrongModelIsRefused(t *testing.T) {
	pol := AiPolicy{Name: "p", Prompt: "x", Model: "llama3"}
	_, err := ExecuteAiPolicy(&charAttestor{}, pol, ollamaEnvelope(t, "other", `{"status":"FAIL","reason":"no"}`))
	requireModelRefusal(t, err)
}

type fixedProvider struct{ responses []AiResponse }

func (p fixedProvider) Evaluate(context.Context, attestation.Attestor, AiPolicy, string) (AiResponse, error) {
	return p.responses[0], nil
}

type fixedBatchProvider struct{ fixedProvider }

func (p fixedBatchProvider) EvaluateBatch(context.Context, attestation.Attestor, []AiPolicy, string) ([]AiResponse, error) {
	return p.responses, nil
}

func TestProvider_ResolvedModelIsPinned(t *testing.T) {
	pol := []AiPolicy{{Name: "p", Prompt: "x", Model: "m"}}
	for _, model := range []string{"evil", ""} {
		_, err := EvaluateAIPolicyWithProvider(context.Background(), &charAttestor{}, pol, "http://127.0.0.1:1",
			fixedProvider{[]AiResponse{{Status: AiStatusPass, Reason: "ok", Model: model}}})
		requireModelRefusal(t, err)
	}
	resp, err := EvaluateAIPolicyWithProvider(context.Background(), &charAttestor{}, pol, "http://127.0.0.1:1",
		fixedProvider{[]AiResponse{{Status: AiStatusPass, Reason: "ok", Model: "m"}}})
	require.NoError(t, err)
	require.Len(t, resp, 1)

	// The single-question entry point is held to the same rule.
	_, err = ExecuteAiPolicyWithProvider(context.Background(), &charAttestor{}, pol[0], "http://127.0.0.1:1",
		fixedProvider{[]AiResponse{{Status: AiStatusPass, Reason: "ok", Model: "evil"}}})
	requireModelRefusal(t, err)
}

// A surplus response has no policy to pin it against, so a batch carrying
// one is not returned as a set of verdicts.
func TestBatchProvider_SurplusResponseIsRejected(t *testing.T) {
	pols := []AiPolicy{{Name: "a", Prompt: "x", Model: "m"}}
	_, err := EvaluateAIPolicyWithProvider(context.Background(), &charAttestor{}, pols, "http://127.0.0.1:1",
		fixedBatchProvider{fixedProvider{[]AiResponse{
			{Status: AiStatusPass, Reason: "ok", Model: "m"},
			{Status: AiStatusPass, Reason: "ok", Model: "other"},
		}}})
	require.Error(t, err)
}

func TestBatchProvider_EveryResolvedModelIsPinned(t *testing.T) {
	pols := []AiPolicy{{Name: "a", Prompt: "x", Model: "m"}, {Name: "b", Prompt: "y", Model: "m"}}
	_, err := EvaluateAIPolicyWithProvider(context.Background(), &charAttestor{}, pols, "http://127.0.0.1:1",
		fixedBatchProvider{fixedProvider{[]AiResponse{
			{Status: AiStatusPass, Reason: "ok", Model: "m"},
			{Status: AiStatusPass, Reason: "ok", Model: "swapped"},
		}}})
	requireModelRefusal(t, err)
}
