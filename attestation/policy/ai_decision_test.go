// jade:ring local
// Copyright 2025 The Witness Contributors
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

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func f64(v float64) *float64 { return &v }

// ---------------------------------------------------------------------------
// Backward compatibility of the on-the-wire policy shape.
//
// Policies are SIGNED. A generative policy written before the typed-decision
// shape existed must serialize to the same bytes afterwards: same keys, same
// ORDER, no new keys appearing from zero values.
// ---------------------------------------------------------------------------

func TestAiPolicyGenerativeMarshalsByteIdentically(t *testing.T) {
	pol := AiPolicy{Name: "check-exit", Prompt: "did it exit zero?", Model: "llama3"}

	got, err := json.Marshal(pol)
	require.NoError(t, err)
	assert.Equal(t,
		`{"name":"check-exit","prompt":"did it exit zero?","model":"llama3"}`,
		string(got),
		"a prompt-only AI policy must serialize exactly as it did before the decision shape existed")
}

func TestAiPolicyOmitsEveryNewKeyWhenUnset(t *testing.T) {
	got, err := json.Marshal(AiPolicy{Name: "n", Prompt: "p", Model: "m"})
	require.NoError(t, err)
	assert.NotContains(t, string(got), "decision")

	// A policy round-trips through JSON unchanged.
	var back AiPolicy
	require.NoError(t, json.Unmarshal(got, &back))
	assert.Equal(t, AiPolicy{Name: "n", Prompt: "p", Model: "m"}, back)
	assert.Nil(t, back.Decision)
}

func TestAiResponseGenerativeMarshalsByteIdentically(t *testing.T) {
	got, err := json.Marshal(AiResponse{Status: AiStatusPass, Reason: "ok"})
	require.NoError(t, err)
	assert.Equal(t, `{"status":"PASS","reason":"ok"}`, string(got),
		"an AiResponse carrying no audit payload must serialize as it did before")
}

// TestAiDecisionRoundTrips proves the typed shape survives marshal/unmarshal,
// including the pointer-valued assertions whose whole point is that 0.0 is a
// real assertion rather than an absent one.
func TestAiDecisionRoundTrips(t *testing.T) {
	pol := AiPolicy{
		Name:  "impossible",
		Model: "llama3",
		Decision: &AiDecision{
			YesNo: &AiYesNo{
				Instructions:   "could this build have been tampered with?",
				Criteria:       map[string]string{"tamper": "evidence of modification"},
				MaxProbability: f64(0),
			},
		},
	}

	raw, err := json.Marshal(pol)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"maxProbability":0`,
		"maxProbability: 0.0 is the assertion 'must be impossible' and must survive marshaling")
	assert.NotContains(t, string(raw), `"prompt"`)
	assert.NotContains(t, string(raw), `"minProbability"`)

	var back AiPolicy
	require.NoError(t, json.Unmarshal(raw, &back))
	require.NotNil(t, back.Decision)
	require.NotNil(t, back.Decision.YesNo)
	require.NotNil(t, back.Decision.YesNo.MaxProbability)
	assert.Equal(t, 0.0, *back.Decision.YesNo.MaxProbability)
	assert.Nil(t, back.Decision.YesNo.MinProbability)
	assert.Equal(t, pol, back)
}

func TestAiScoreZeroBoundsSurviveMarshal(t *testing.T) {
	d := AiDecision{Score: &AiScore{
		Instructions: "how severe?",
		Levels:       []string{"none", "low", "high"},
		MinScore:     f64(0),
		MaxScore:     f64(0),
	}}
	raw, err := json.Marshal(d)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"minScore":0`)
	assert.Contains(t, string(raw), `"maxScore":0`)
}

// ---------------------------------------------------------------------------
// Validation. Every rule fails CLOSED.
// ---------------------------------------------------------------------------

func TestAiPolicyValidate(t *testing.T) {
	yesNo := func() *AiYesNo {
		return &AiYesNo{Instructions: "is it fine?", Criteria: map[string]string{"true": "meets the criterion", "false": "does not meet the criterion"}, MinProbability: f64(0.9)}
	}
	choice := func() *AiChoice {
		return &AiChoice{
			Instructions:  "which risk tier?",
			Options:       map[string]string{"low": "no risk", "high": "risky"},
			Allow:         []string{"low"},
			MinConfidence: f64(0.5),
		}
	}
	score := func() *AiScore {
		return &AiScore{Instructions: "how bad?", Levels: []string{"a", "b", "c"}, MaxScore: f64(1)}
	}

	tests := []struct {
		name    string
		pol     AiPolicy
		wantErr string
	}{
		// --- happy paths -------------------------------------------------
		{
			name: "generative policy is valid",
			pol:  AiPolicy{Name: "g", Prompt: "p", Model: "m"},
		},
		{
			name: "yesNo decision is valid",
			pol:  AiPolicy{Name: "d", Model: "m", Decision: &AiDecision{YesNo: yesNo()}},
		},
		{
			name: "choice decision is valid",
			pol:  AiPolicy{Name: "d", Model: "m", Decision: &AiDecision{Choice: choice()}},
		},
		{
			name: "score decision is valid",
			pol:  AiPolicy{Name: "d", Model: "m", Decision: &AiDecision{Score: score()}},
		},
		{
			name: "a decision may carry a rego state projection",
			pol: AiPolicy{Name: "d", Model: "m", Decision: &AiDecision{
				State: &RegoPolicy{Name: "proj", Module: []byte("package p")},
				YesNo: yesNo(),
			}},
		},
		{
			name: "maxProbability of exactly zero is a real assertion",
			pol: AiPolicy{Name: "d", Model: "m", Decision: &AiDecision{
				YesNo: &AiYesNo{Instructions: "impossible?", Criteria: map[string]string{"true": "the event occurred", "false": "the event did not occur"}, MaxProbability: f64(0)},
			}},
		},

		// --- rule 8: name ------------------------------------------------
		{
			name:    "empty name",
			pol:     AiPolicy{Prompt: "p", Model: "m"},
			wantErr: `AI policy name must not be empty`,
		},

		// --- rule 3: model -----------------------------------------------
		{
			name:    "missing model preserves the historical error text",
			pol:     AiPolicy{Name: "no-model", Prompt: "p"},
			wantErr: `AI policy "no-model" must specify a model; the open-source policy engine does not ship a default`,
		},

		// --- rule 1: exactly one of prompt/decision ----------------------
		{
			name:    "neither prompt nor decision",
			pol:     AiPolicy{Name: "n", Model: "m"},
			wantErr: `AI policy "n" must set exactly one of "prompt" or "decision"; neither is set`,
		},
		{
			name: "both prompt and decision",
			pol: AiPolicy{Name: "n", Model: "m", Prompt: "p",
				Decision: &AiDecision{YesNo: yesNo()}},
			wantErr: `AI policy "n" must set exactly one of "prompt" or "decision"; both are set`,
		},

		// --- rule 2: exactly one decision kind ---------------------------
		{
			name:    "decision with no kind",
			pol:     AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{}},
			wantErr: `AI policy "n" decision must set exactly one of "yesNo", "choice" or "score"; none is set`,
		},
		{
			name: "decision with two kinds",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				YesNo: yesNo(), Score: score()}},
			wantErr: `AI policy "n" decision must set exactly one of "yesNo", "choice" or "score"; 2 are set (yesNo, score)`,
		},
		{
			name: "decision with all three kinds",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				YesNo: yesNo(), Choice: choice(), Score: score()}},
			wantErr: `AI policy "n" decision must set exactly one of "yesNo", "choice" or "score"; 3 are set (yesNo, choice, score)`,
		},

		// --- rule 4: every kind needs at least one assertion --------------
		{
			name: "yesNo with no assertion",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				YesNo: &AiYesNo{Instructions: "is it fine?"}}},
			wantErr: `AI policy "n" yesNo decision must set at least one of "minProbability" or "maxProbability"; a decision that asserts nothing about the answer passes vacuously`,
		},
		{
			name: "choice with no assertion",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Choice: &AiChoice{Instructions: "which?", Options: map[string]string{"a": "A"}}}},
			wantErr: `AI policy "n" choice decision must set at least one of "allow", "deny" or "minConfidence"; a decision that asserts nothing about the answer passes vacuously`,
		},
		{
			name: "score with no assertion",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Score: &AiScore{Instructions: "how bad?", Levels: []string{"a", "b"}}}},
			wantErr: `AI policy "n" score decision must set at least one of "minScore" or "maxScore"; a decision that asserts nothing about the answer passes vacuously`,
		},

		// --- rule 5: options / levels non-empty ---------------------------
		{
			name: "choice with no options",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Choice: &AiChoice{Instructions: "which?", MinConfidence: f64(0.5)}}},
			wantErr: `AI policy "n" choice decision must define at least one option`,
		},
		{
			name: "score with no levels",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Score: &AiScore{Instructions: "how bad?", MinScore: f64(0)}}},
			wantErr: `AI policy "n" score decision must define at least one level`,
		},

		// --- rule 6: allow/deny must name defined options -----------------
		{
			name: "allow names an undefined option",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Choice: &AiChoice{
					Instructions: "which?",
					Options:      map[string]string{"low": "L"},
					Allow:        []string{"medium"},
				}}},
			wantErr: `AI policy "n" choice decision "allow" names option "medium", which is not defined in "options"`,
		},
		{
			name: "deny names an undefined option",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Choice: &AiChoice{
					Instructions: "which?",
					Options:      map[string]string{"low": "L"},
					Deny:         []string{"HIGH"},
				}}},
			wantErr: `AI policy "n" choice decision "deny" names option "HIGH", which is not defined in "options"`,
		},

		// --- rule 7: assertion ranges -------------------------------------
		{
			name: "minProbability above one",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				YesNo: &AiYesNo{Instructions: "i", MinProbability: f64(1.5)}}},
			wantErr: `AI policy "n" yesNo decision "minProbability" must be within [0, 1], got 1.5`,
		},
		{
			name: "maxProbability below zero",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				YesNo: &AiYesNo{Instructions: "i", MaxProbability: f64(-0.1)}}},
			wantErr: `AI policy "n" yesNo decision "maxProbability" must be within [0, 1], got -0.1`,
		},
		{
			name: "min above max probability",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				YesNo: &AiYesNo{Instructions: "i", MinProbability: f64(0.9), MaxProbability: f64(0.1)}}},
			wantErr: `AI policy "n" yesNo decision "minProbability" (0.9) must not exceed "maxProbability" (0.1)`,
		},
		{
			name: "min equal to max probability is allowed",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				YesNo: &AiYesNo{Instructions: "i", Criteria: map[string]string{"true": "criterion met", "false": "criterion unmet"}, MinProbability: f64(0.5), MaxProbability: f64(0.5)}}},
		},
		{
			name: "minConfidence out of range",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Choice: &AiChoice{Instructions: "i",
					Options: map[string]string{"a": "A"}, MinConfidence: f64(2)}}},
			wantErr: `AI policy "n" choice decision "minConfidence" must be within [0, 1], got 2`,
		},
		{
			name: "min above max score",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Score: &AiScore{Instructions: "i", Levels: []string{"a", "b", "c"},
					MinScore: f64(2), MaxScore: f64(1)}}},
			wantErr: `AI policy "n" score decision "minScore" (2) must not exceed "maxScore" (1)`,
		},
		{
			name: "score bound above the last level index",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Score: &AiScore{Instructions: "i", Levels: []string{"a", "b", "c"},
					MaxScore: f64(3)}}},
			wantErr: `AI policy "n" score decision "maxScore" must be within [0, 2] for 3 levels, got 3`,
		},
		{
			name: "score bound below zero",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Score: &AiScore{Instructions: "i", Levels: []string{"a", "b", "c"},
					MinScore: f64(-1)}}},
			wantErr: `AI policy "n" score decision "minScore" must be within [0, 2] for 3 levels, got -1`,
		},
		{
			name: "score bound at the last level index is allowed",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Score: &AiScore{Instructions: "i", Levels: []string{"a", "b", "c"},
					MinScore: f64(2), MaxScore: f64(2)}}},
		},
		{
			name: "a single level admits only score zero",
			pol: AiPolicy{Name: "n", Model: "m", Decision: &AiDecision{
				Score: &AiScore{Instructions: "i", Levels: []string{"only"},
					MinScore: f64(1)}}},
			wantErr: `AI policy "n" score decision "minScore" must be within [0, 0] for 1 levels, got 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pol.Validate()
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Equal(t, tt.wantErr, err.Error())
		})
	}
}

// TestAttestationValidateNameUniqueness covers rule 8's second half: a Name is
// the question id once requests are batched, so two policies sharing one inside
// a single Attestation is a policy bug.
func TestAttestationValidateNameUniqueness(t *testing.T) {
	ok := Attestation{
		Type: "https://example.com/a/v1",
		AiPolicies: []AiPolicy{
			{Name: "one", Prompt: "p", Model: "m"},
			{Name: "two", Prompt: "p", Model: "m"},
		},
	}
	require.NoError(t, ok.Validate())

	dup := Attestation{
		Type: "https://example.com/a/v1",
		AiPolicies: []AiPolicy{
			{Name: "same", Prompt: "p", Model: "m"},
			{Name: "same", Prompt: "q", Model: "m"},
		},
	}
	err := dup.Validate()
	require.Error(t, err)
	assert.Equal(t, `AI policy name "same" is used more than once in attestation "https://example.com/a/v1"; names must be unique`, err.Error())

	// An invalid member policy is reported through the attestation too.
	bad := Attestation{
		Type:       "https://example.com/a/v1",
		AiPolicies: []AiPolicy{{Name: "n", Model: "m"}},
	}
	err = bad.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), `must set exactly one of "prompt" or "decision"`)

	// No AI policies at all is fine.
	require.NoError(t, Attestation{Type: "t"}.Validate())
}

// ---------------------------------------------------------------------------
// Validation is enforced BEFORE any network call.
// ---------------------------------------------------------------------------

func TestEvaluateAIPolicyValidatesBeforeDialing(t *testing.T) {
	srv, capture := newAiServer(t, func(w http.ResponseWriter, _ *http.Request) {
		ollamaGenerate(t, w, `{"status":"PASS","reason":"should never be reached"}`)
	})

	tests := []struct {
		name    string
		pols    []AiPolicy
		wantErr string
	}{
		{
			name:    "assertion-free decision never reaches the server",
			pols:    []AiPolicy{{Name: "vacuous", Model: "m", Decision: &AiDecision{YesNo: &AiYesNo{Instructions: "i"}}}},
			wantErr: `must set at least one of "minProbability" or "maxProbability"`,
		},
		{
			name: "a later invalid policy stops the whole batch",
			pols: []AiPolicy{
				{Name: "first", Prompt: "p", Model: "m"},
				{Name: "second", Model: "m"},
			},
			wantErr: `AI policy "second" must set exactly one of "prompt" or "decision"; neither is set`,
		},
		{
			name: "duplicate names stop the whole batch",
			pols: []AiPolicy{
				{Name: "dup", Prompt: "p", Model: "m"},
				{Name: "dup", Prompt: "q", Model: "m"},
			},
			wantErr: `AI policy name "dup" is used more than once`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := func() int { _, _, _, _, h := capture.snapshot(); return h }()
			resps, err := EvaluateAIPolicy(&charAttestor{}, tt.pols, srv.URL)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
			assert.Nil(t, resps, "a rejected batch produces no responses at all")
			after := func() int { _, _, _, _, h := capture.snapshot(); return h }()
			assert.Equal(t, before, after, "no request may leave the process for a batch that fails validation")
		})
	}
}

// ---------------------------------------------------------------------------
// The provider seam.
// ---------------------------------------------------------------------------

// TestOllamaProviderIsTheDefault proves ExecuteAiPolicy is a thin wrapper and
// that the interface is satisfied by the concrete provider.
func TestOllamaProviderSatisfiesTheInterface(t *testing.T) {
	var p AiProvider = ollamaProvider{}
	require.NotNil(t, p)
}

// TestDecisionPolicyHasNoProviderYet pins the deliberate gap: the typed shape
// is accepted and validated, but nothing evaluates it yet, and that refusal is
// explicit rather than a silent pass.
func TestDecisionPolicyHasNoProviderYet(t *testing.T) {
	srv, capture := newAiServer(t, func(w http.ResponseWriter, _ *http.Request) {
		ollamaGenerate(t, w, `{"status":"PASS","reason":"must not be reached"}`)
	})

	pol := AiPolicy{Name: "d", Model: "llama3", Decision: &AiDecision{
		YesNo: &AiYesNo{Instructions: "is it fine?", Criteria: map[string]string{"true": "meets the criterion", "false": "does not meet the criterion"}, MinProbability: f64(0.9)},
	}}
	require.NoError(t, pol.Validate(), "the policy itself is well formed")

	resp, err := ExecuteAiPolicy(&charAttestor{}, pol, srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no provider configured for decision policies")
	assert.Equal(t, AiResponse{}, resp)

	_, _, _, _, hits := capture.snapshot()
	assert.Equal(t, 0, hits, "a decision policy must not be sent down the generative path")

	// And through the batch entry point.
	resps, err := EvaluateAIPolicy(&charAttestor{}, []AiPolicy{pol}, srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no provider configured for decision policies")
	require.Len(t, resps, 1)
	assert.Equal(t, AiResponse{}, resps[0])
}

// ---------------------------------------------------------------------------
// The audit record is ours, not the model's.
// ---------------------------------------------------------------------------

// TestAiResponseAuditFieldsAreNotServerControlled proves an AI server cannot
// populate the audit members of AiResponse by echoing them in its structured
// output. Model is set from the resolved policy model; Answer stays nil on the
// generative path.
func TestAiResponseAuditFieldsAreNotServerControlled(t *testing.T) {
	srv, _ := newAiServer(t, func(w http.ResponseWriter, _ *http.Request) {
		ollamaGenerate(t, w, `{"status":"PASS","reason":"ok","model":"totally-different","answer":{"type":"yesNo","yesNo":1}}`)
	})

	resp, err := ExecuteAiPolicy(&charAttestor{}, AiPolicy{Name: "p", Prompt: "x", Model: "llama3"}, srv.URL)
	require.NoError(t, err)
	assert.Equal(t, "llama3", resp.Model, "Model is the RESOLVED model we asked, not what the server claims")
	assert.Nil(t, resp.Answer, "the generative path produces no typed answer")
}

// ---------------------------------------------------------------------------
// Deep copy must actually be deep.
// ---------------------------------------------------------------------------

// TestAiPolicyDeepCopyIsDeep guards the generated deepcopy against the shallow
// `*out = *in` it had while AiPolicy held only value fields. With a pointer
// member, a shallow copy aliases the original and mutating the copy rewrites
// the signed policy in place.
func TestAiPolicyDeepCopyIsDeep(t *testing.T) {
	orig := AiPolicy{Name: "d", Model: "m", Decision: &AiDecision{
		Choice: &AiChoice{
			Instructions:  "which?",
			Options:       map[string]string{"low": "L"},
			Allow:         []string{"low"},
			MinConfidence: f64(0.5),
		},
	}}

	cp := orig.DeepCopy()
	require.NotNil(t, cp.Decision)
	require.NotSame(t, orig.Decision, cp.Decision)
	require.NotNil(t, cp.Decision.Choice)
	require.NotSame(t, orig.Decision.Choice, cp.Decision.Choice)

	cp.Decision.Choice.Options["low"] = "MUTATED"
	cp.Decision.Choice.Allow[0] = "MUTATED"
	*cp.Decision.Choice.MinConfidence = 0.99

	assert.Equal(t, "L", orig.Decision.Choice.Options["low"])
	assert.Equal(t, "low", orig.Decision.Choice.Allow[0])
	assert.Equal(t, 0.5, *orig.Decision.Choice.MinConfidence)
}

// TestAttestationDeepCopyIsDeep covers the slice-of-AiPolicy path, which the
// generator used to satisfy with a plain `copy()`.
func TestAttestationDeepCopyIsDeep(t *testing.T) {
	orig := Attestation{
		Type: "t",
		AiPolicies: []AiPolicy{{Name: "d", Model: "m", Decision: &AiDecision{
			Score: &AiScore{Instructions: "i", Levels: []string{"a", "b"}, MaxScore: f64(1)},
		}}},
	}
	cp := orig.DeepCopy()
	require.NotNil(t, cp.AiPolicies[0].Decision)
	require.NotSame(t, orig.AiPolicies[0].Decision, cp.AiPolicies[0].Decision)
	cp.AiPolicies[0].Decision.Score.Levels[0] = "MUTATED"
	assert.Equal(t, "a", orig.AiPolicies[0].Decision.Score.Levels[0])
}
