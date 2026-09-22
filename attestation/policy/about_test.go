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

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicyPredicateV02IsTheWireString(t *testing.T) {
	require.Equal(t, "https://aflock.ai/policy/v0.2", PolicyPredicateV02)
	require.Equal(t, "source", StepAboutSource)
	require.True(t, IsPolicyV01Type(PolicyPredicate))
	require.True(t, IsPolicyV01Type(LegacyPolicyPredicate))
	require.False(t, IsPolicyV01Type(PolicyPredicateV02))
	require.False(t, IsPolicyV01Type(""))
}

// A v0.1 policy round-trips through Step byte for byte: About is omitted
// when empty, so adding the field writes no new key into any v0.1 document.
func TestStepAbout_V01RoundTripIsByteIdentical(t *testing.T) {
	v01 := Policy{Steps: map[string]Step{"build": {
		Name:          "build",
		Functionaries: []Functionary{{Type: "publickey", PublicKeyID: "k"}},
		Attestations:  []Attestation{{Type: "t"}},
		ArtifactsFrom: []string{"checkout"},
	}}}
	out, err := json.Marshal(v01)
	require.NoError(t, err)
	require.NotContains(t, string(out), `"about"`, "an empty About writes no key")

	var again Policy
	require.NoError(t, json.Unmarshal(out, &again))
	require.Empty(t, again.Steps["build"].About)
	out2, err := json.Marshal(again)
	require.NoError(t, err)
	require.Equal(t, string(out), string(out2))
}

func TestStepAbout_DecodesAndEncodes(t *testing.T) {
	var s Step
	require.NoError(t, json.Unmarshal([]byte(`{"name":"secrets","about":"source"}`), &s))
	require.Equal(t, StepAboutSource, s.About)
	out, err := json.Marshal(s)
	require.NoError(t, err)
	require.Contains(t, string(out), `"about":"source"`)
}

func TestStepsDeclaringAbout(t *testing.T) {
	cases := []struct {
		name string
		doc  string
		want []string
	}{
		{"none", `{"steps":{"build":{"name":"build"}}}`, nil},
		{"empty value", `{"steps":{"build":{"name":"build","about":""}}}`, nil},
		{"one", `{"steps":{"build":{"name":"build"},"secrets":{"name":"secrets","about":"source"}}}`, []string{"secrets"}},
		{"unknown value still declares", `{"steps":{"b":{"about":"seed"},"a":{"about":"source"}}}`, []string{"a", "b"}},
		{"not json", `not json`, nil},
		{"steps not an object", `{"steps":[]}`, nil},
		{"hand-authored source, partial step", `{"expires":"2030-01-01T00:00:00Z","steps":{"s":{"about":"source"}}}`, []string{"s"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, StepsDeclaringAbout([]byte(tc.doc)))
		})
	}
}
