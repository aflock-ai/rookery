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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A decision body's members are ASSERTIONS. Go's default JSON decoding drops
// a member it does not recognise, which turns "the author asserted something"
// into "the engine asserted nothing" with no diagnostic — the same vacuous-pass
// failure the assertion-free rule exists to prevent, arriving through the
// decoder instead of the validator.
//
// The motivating case: `minConfidence` on a yesNo. The model returns a
// confidence only for choice and score answers, never for a yes/no, so the
// field cannot exist on AiYesNo. Without strict decoding, a policy author who
// writes it gets a gate that asserts nothing and reads as if it asserts a
// confidence floor.

func TestAiYesNoRejectsMinConfidence(t *testing.T) {
	raw := []byte(`{
		"instructions": "is it fine?",
		"minConfidence": 0.9
	}`)

	var y AiYesNo
	err := json.Unmarshal(raw, &y)
	require.Error(t, err, "minConfidence on a yesNo must be a policy error, not a silently dropped field")
	assert.Contains(t, err.Error(), "minConfidence")
	assert.Contains(t, err.Error(), "choice")
}

// TestAiYesNoRejectsMinConfidenceThroughAWholePolicy proves the refusal
// survives decoding at the level a real signed policy is decoded at, not only
// when the leaf struct is unmarshaled directly.
func TestAiYesNoRejectsMinConfidenceThroughAWholePolicy(t *testing.T) {
	raw := []byte(`{
		"name": "tamper",
		"model": "llama3",
		"decision": {"yesNo": {"instructions": "q", "minConfidence": 0.9}}
	}`)

	var pol AiPolicy
	err := json.Unmarshal(raw, &pol)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "minConfidence")
}

// TestDecisionBodiesRejectUnknownFields covers the mechanism rather than the
// one field that exposed it: every decision body refuses a member it cannot
// act on. A silently dropped assertion is indistinguishable from no assertion.
func TestDecisionBodiesRejectUnknownFields(t *testing.T) {
	tests := []struct {
		name   string
		raw    string
		target func() interface{}
	}{
		{
			name:   "yesNo",
			raw:    `{"instructions":"q","maxProbabilty":0.1}`, // typo'd assertion
			target: func() interface{} { return &AiYesNo{} },
		},
		{
			name:   "choice",
			raw:    `{"instructions":"q","options":{"a":"A"},"minProbability":0.5}`,
			target: func() interface{} { return &AiChoice{} },
		},
		{
			name:   "score",
			raw:    `{"instructions":"q","levels":["a"],"minConfidence":0.5}`,
			target: func() interface{} { return &AiScore{} },
		},
		{
			name:   "decision",
			raw:    `{"yesNo":{"instructions":"q"},"minScore":0.5}`, // an assertion at the wrong level
			target: func() interface{} { return &AiDecision{} },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := json.Unmarshal([]byte(tt.raw), tt.target())
			require.Error(t, err, "an unrecognised member of a %s body must be refused, never dropped", tt.name)
		})
	}
}

// TestDecisionBodiesStillRoundTrip guards the strict decoding against being
// so strict it rejects its own output.
func TestDecisionBodiesStillRoundTrip(t *testing.T) {
	original := AiDecision{
		State: &RegoPolicy{Name: "proj", Module: []byte("package p")},
		Choice: &AiChoice{
			Instructions:  "which?",
			Options:       map[string]string{"low": "L", "high": "H"},
			Allow:         []string{"low"},
			Deny:          []string{"high"},
			MinConfidence: f64(0.75),
		},
	}
	raw, err := json.Marshal(original)
	require.NoError(t, err)

	var back AiDecision
	require.NoError(t, json.Unmarshal(raw, &back))
	assert.Equal(t, original, back)

	for _, d := range []AiDecision{
		{YesNo: &AiYesNo{Instructions: "q", Criteria: map[string]string{"k": "v"}, MinProbability: f64(0), MaxProbability: f64(1)}},
		{Score: &AiScore{Instructions: "q", Levels: []string{"a", "b"}, MinScore: f64(0), MaxScore: f64(1)}},
	} {
		raw, err := json.Marshal(d)
		require.NoError(t, err)
		var rt AiDecision
		require.NoError(t, json.Unmarshal(raw, &rt))
		assert.Equal(t, d, rt)
	}
}
