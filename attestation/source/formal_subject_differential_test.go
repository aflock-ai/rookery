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

package source

// formal:differential
//
// Binds the engine half of the subject-match model (formal/security-backlog,
// SecBacklog/Subject.lean, #9816) to the code. Each vector subject is signed
// into its own bare statement; for every seed string the engine can receive,
// the set of statements that answer it must equal the model's, at both
// layers that decide it:
//
//   - the MemorySource index pre-filter (SearchByPredicateTypeWithOptions),
//   - the signed-payload guard (MatchExternalSubjects).
//
// formalSubjectModel names the model server the code is held to: `required`
// since #9863 (matching on algorithm and value). Before it, main was
// `asbuilt`, and this test with `required` failed 14 of 20 seeds there.
//
// The vectors live in the Judge monorepo, so this test skips when rookery is
// built on its own, unless JADE_FORMAL_DIFFERENTIAL=1.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/stretchr/testify/require"
)

const (
	formalSubjectVectors   = "../../../../formal/security-backlog/vectors/subject.json"
	formalSubjectModel     = "required"
	formalSubjectPredicate = "https://example.com/security-backlog/subject/v1"
	formalSubjectPrefix    = "https://example.com/security-backlog/commithash:"
)

type formalSubjectFile struct {
	Values   map[string]string `json:"values"`
	Subjects []struct {
		Alg       string `json:"alg"`
		Val       string `json:"val"`
		CommitArm bool   `json:"commit_arm"`
	} `json:"subjects"`
	Engine []struct {
		Seed     string `json:"seed"`
		AsBuilt  []int  `json:"asbuilt"`
		Required []int  `json:"required"`
	} `json:"engine"`
}

func loadFormalSubjectVectors(t *testing.T) formalSubjectFile {
	t.Helper()
	raw, err := os.ReadFile(formalSubjectVectors)
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") == "1" {
			t.Fatalf("formal:differential: JADE_FORMAL_DIFFERENTIAL=1 but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal:differential: vectors not on disk (%v); set JADE_FORMAL_DIFFERENTIAL=1 to make this fatal", err)
	}
	var f formalSubjectFile
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Subjects)
	require.NotEmpty(t, f.Engine)
	return f
}

func TestFormalSubjectDifferential(t *testing.T) {
	f := loadFormalSubjectVectors(t)

	mem := NewMemorySource()
	payloads := make([][]byte, len(f.Subjects))
	for i, s := range f.Subjects {
		value, ok := f.Values[s.Val]
		require.True(t, ok, "vector value %q", s.Val)
		// The commit arm is the policy-declared one: a subject named exactly
		// <prefix><value>, which only a sha1 40-hex digest can use.
		name := "artifact"
		if s.CommitArm {
			name = formalSubjectPrefix + value
		}
		payload, err := json.Marshal(intoto.Statement{
			Type:          intoto.StatementType,
			PredicateType: formalSubjectPredicate,
			Subject:       []intoto.Subject{{Name: name, Digest: map[string]string{s.Alg: value}}},
			Predicate:     json.RawMessage(`{}`),
		})
		require.NoError(t, err)
		payloads[i] = payload
		require.NoError(t, mem.LoadEnvelope(fmt.Sprint(i), dsse.Envelope{PayloadType: intoto.PayloadType, Payload: payload}))
	}
	opts := PredicateSearchOptions{CommitSubjects: map[string][]string{formalSubjectPredicate: {formalSubjectPrefix}}}

	for _, e := range f.Engine {
		want := e.AsBuilt
		if formalSubjectModel == "required" {
			want = e.Required
		}
		t.Run(e.Seed, func(t *testing.T) {
			var guard []int
			for i, p := range payloads {
				if MatchExternalSubjects(p, []string{e.Seed}, formalSubjectPredicate, formalSubjectPrefix) == nil {
					guard = append(guard, i)
				}
			}
			require.Equal(t, want, nilIfEmpty(guard), "signed-payload guard disagrees with the %s model", formalSubjectModel)

			found, err := mem.SearchByPredicateTypeWithOptions(context.Background(), []string{formalSubjectPredicate}, []string{e.Seed}, opts)
			require.NoError(t, err)
			var prefilter []int
			for _, se := range found {
				var i int
				_, err := fmt.Sscan(se.Reference, &i)
				require.NoError(t, err)
				prefilter = append(prefilter, i)
			}
			slices.Sort(prefilter)
			require.Equal(t, want, nilIfEmpty(prefilter), "memory pre-filter disagrees with the %s model", formalSubjectModel)
		})
	}
}

func nilIfEmpty(xs []int) []int {
	if len(xs) == 0 {
		return []int{}
	}
	return xs
}
