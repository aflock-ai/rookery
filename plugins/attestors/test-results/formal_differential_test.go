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

package testresults

import (
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// The Lean model's vectors (formal/test-results/vectors/junit.json, rookery
// root) are replayed through parseJUnit. Design:
// docs/design/fix-security.md#test-results-verdict (Judge monorepo).
const junitVectors = "../../../formal/test-results/vectors/junit.json"

// knownDivergences are the vectors the parser summarizes differently from the
// model. The verdict fix closed every hole, so it is empty: the test fails when
// the parser disagrees on any vector (a regression), and when a listed vector
// starts to agree (shrink the list).
var knownDivergences = map[string]bool{}

func TestFormalDifferentialJUnit(t *testing.T) {
	raw, err := os.ReadFile(junitVectors)
	if err != nil {
		if os.Getenv("JADE_FORMAL_DIFFERENTIAL") == "1" {
			t.Fatalf("formal:differential: JADE_FORMAL_DIFFERENTIAL=1 but the model's vectors are unreadable: %v", err)
		}
		t.Skipf("formal:differential: vectors not on disk (%v); set JADE_FORMAL_DIFFERENTIAL=1 to make this fatal", err)
	}
	var v struct {
		Cases []struct {
			Name    string `json:"name"`
			XML     string `json:"xml"`
			Summary struct {
				Total   int `json:"total"`
				Passed  int `json:"passed"`
				Failed  int `json:"failed"`
				Skipped int `json:"skipped"`
				Errors  int `json:"errors"`
			} `json:"summary"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Cases)

	var disagree []string
	for _, c := range v.Cases {
		pred, _, err := parseJUnit([]byte(c.XML))
		if err != nil {
			disagree = append(disagree, c.Name)
			if !knownDivergences[c.Name] {
				t.Errorf("%s: parser refused a document the model summarizes: %v", c.Name, err)
			}
			continue
		}
		got := pred.Summary
		want := Summary{Total: c.Summary.Total, Passed: c.Summary.Passed, Failed: c.Summary.Failed,
			Skipped: c.Summary.Skipped, Errors: c.Summary.Errors, DurationSeconds: got.DurationSeconds}
		if got != want {
			disagree = append(disagree, c.Name)
			if !knownDivergences[c.Name] {
				t.Errorf("%s: parser %+v, model %+v", c.Name, got, want)
			}
		}
	}
	seen := map[string]bool{}
	for _, n := range disagree {
		seen[n] = true
	}
	var fixed []string
	for n := range knownDivergences {
		if !seen[n] {
			fixed = append(fixed, n)
		}
	}
	sort.Strings(fixed)
	require.Empty(t, fixed, "listed as divergent but the parser now agrees with the model: remove from knownDivergences")
}
