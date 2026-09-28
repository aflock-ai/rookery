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

package policyverify

// formal:differential
//
// Binds the seed half of the subject-match model (formal/security-backlog,
// SecBacklog/Subject.lean, `asbuiltP` / `requiredP`, #9816) to
// seedDigestStrings: each typed seed must become exactly the string the model
// hands the engine, or be refused where the model refuses.
//
// formalSubjectModel names the model server the code is held to. Main is
// `asbuilt` (every seed flattened to its bare value); #9863 flips it to
// `required`.
//
// The vectors live in the Judge monorepo, so this test skips when rookery is
// built on its own, unless JADE_FORMAL_DIFFERENTIAL=1.

import (
	"crypto"
	"encoding/json"
	"os"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

const (
	formalSubjectVectors = "../../../../../formal/security-backlog/vectors/subject.json"
	formalSubjectModel   = "asbuilt"
)

// formalSubjectDigestValues maps the model's typed-seed algorithms to the
// DigestValue a caller would put in a seed DigestSet. "unnamed" is one with
// no wire name.
var formalSubjectDigestValues = map[string]cryptoutil.DigestValue{
	"sha256":        {Hash: crypto.SHA256},
	"sha1":          {Hash: crypto.SHA1},
	"gitoid:sha256": {Hash: crypto.SHA256, GitOID: true},
	"dirHash":       {Hash: crypto.SHA256, DirHash: true},
	"unnamed":       {Hash: crypto.SHA512},
}

func TestFormalSubjectSeedDifferential(t *testing.T) {
	raw, err := os.ReadFile(formalSubjectVectors)
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") == "1" {
			t.Fatalf("formal:differential: JADE_FORMAL_DIFFERENTIAL=1 but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal:differential: vectors not on disk (%v); set JADE_FORMAL_DIFFERENTIAL=1 to make this fatal", err)
	}
	var f struct {
		Values map[string]string `json:"values"`
		Typed  []struct {
			Alg      string `json:"alg"`
			Val      string `json:"val"`
			AsBuilt  string `json:"asbuilt"`
			Required string `json:"required"`
		} `json:"typed"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Typed)

	for _, c := range f.Typed {
		want := c.AsBuilt
		if formalSubjectModel == "required" {
			want = c.Required
		}
		t.Run(c.Alg+"/"+c.Val, func(t *testing.T) {
			dv, ok := formalSubjectDigestValues[c.Alg]
			require.True(t, ok, "vector algorithm %q", c.Alg)
			value, ok := f.Values[c.Val]
			require.True(t, ok, "vector value %q", c.Val)

			a := New()
			a.SetSubjectDigests([]cryptoutil.DigestSet{{dv: value}})
			got := a.seedDigestStrings()
			if want == "refuse" {
				t.Fatalf("the %s model refuses this seed; seedDigestStrings returned %v", formalSubjectModel, got)
			}
			require.Equal(t, []string{want}, got)
		})
	}
}
