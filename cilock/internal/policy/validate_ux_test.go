// Copyright 2025 The Aflock Authors
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
	"context"
	"strings"
	"testing"
)

// These tests pin the AUTHORING-TIME UX of `cilock policy validate`: an invalid
// policy must be rejected with a message that names the problem AND the fix, so
// an author finds out at authoring time instead of at verify time. Cases marked
// "GAP" encode behavior the validator does NOT yet have — they fail until the
// validator learns to catch root-functionary trust-root mistakes.

func validateRaw(t *testing.T, policyJSON string) *ValidationResult {
	t.Helper()
	res := ValidateRawPolicy(context.Background(), []byte(policyJSON))
	if res == nil {
		t.Fatal("ValidateRawPolicy returned nil")
	}
	return res
}

// validRootPolicy is a minimal policy that MUST validate: one step, one root
// functionary whose certConstraint references a defined root and an identity.
const validRootPolicy = `{
  "expires": "2030-01-01T00:00:00Z",
  "roots": { "rootA": { "certificate": "Zm9v" } },
  "steps": {
    "build": {
      "name": "build",
      "functionaries": [
        { "type": "root", "certConstraint": { "roots": ["rootA"], "emails": ["dev@example.com"] } }
      ],
      "attestations": [ { "type": "https://aflock.ai/attestations/product/v0.3" } ]
    }
  }
}`

func TestValidateUX_BaselineValid(t *testing.T) {
	res := validateRaw(t, validRootPolicy)
	if !res.Valid {
		t.Fatalf("baseline policy must validate, got errors: %v", res.Errors)
	}
}

// TestValidateUX_WellHandledCases locks the messages that are already good — a
// regression guard so they keep naming the problem clearly.
func TestValidateUX_WellHandledCases(t *testing.T) {
	cases := []struct {
		name       string
		policyJSON string
		wantSubstr string
	}{
		{
			name:       "missing steps",
			policyJSON: `{"expires":"2030-01-01T00:00:00Z","roots":{"rootA":{"certificate":"Zm9v"}}}`,
			wantSubstr: "at least one step",
		},
		{
			name: "step with no functionaries",
			policyJSON: `{"expires":"2030-01-01T00:00:00Z","roots":{"rootA":{"certificate":"Zm9v"}},
				"steps":{"build":{"name":"build","functionaries":[],"attestations":[{"type":"t"}]}}}`,
			wantSubstr: "at least one functionary",
		},
		{
			name: "functionary with invalid type",
			policyJSON: `{"expires":"2030-01-01T00:00:00Z","roots":{"rootA":{"certificate":"Zm9v"}},
				"steps":{"build":{"name":"build","functionaries":[{"type":"bogus"}],"attestations":[{"type":"t"}]}}}`,
			wantSubstr: "invalid type",
		},
		{
			name: "artifactsFrom references undefined step",
			policyJSON: `{"expires":"2030-01-01T00:00:00Z","roots":{"rootA":{"certificate":"Zm9v"}},
				"steps":{"build":{"name":"build","artifactsFrom":["ghost"],"functionaries":[{"type":"root","certConstraint":{"roots":["rootA"]}}],"attestations":[{"type":"t"}]}}}`,
			wantSubstr: "undefined step",
		},
		{
			name: "artifactsFrom self-reference",
			policyJSON: `{"expires":"2030-01-01T00:00:00Z","roots":{"rootA":{"certificate":"Zm9v"}},
				"steps":{"build":{"name":"build","artifactsFrom":["build"],"functionaries":[{"type":"root","certConstraint":{"roots":["rootA"]}}],"attestations":[{"type":"t"}]}}}`,
			wantSubstr: "cannot reference itself",
		},
		{
			name:       "invalid expires format",
			policyJSON: `{"expires":"not-a-date","roots":{"rootA":{"certificate":"Zm9v"}},"steps":{"build":{"name":"build","functionaries":[{"type":"root","certConstraint":{"roots":["rootA"]}}],"attestations":[{"type":"t"}]}}}`,
			wantSubstr: "expires",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := validateRaw(t, tc.policyJSON)
			if res.Valid {
				t.Fatalf("expected INVALID, got valid")
			}
			joined := strings.Join(res.Errors, " | ")
			if !strings.Contains(joined, tc.wantSubstr) {
				t.Fatalf("error message should contain %q, got: %s", tc.wantSubstr, joined)
			}
		})
	}
}

// ── GAPS: a root functionary's certConstraint trust-roots are never validated.
// These currently PASS validate but are dead or wrong policies; the author only
// finds out at verify time with a "cert doesn't belong to any root" / "no trusted
// roots provided in functionary" failure. validate must catch them up front. ──

// GAP 1: a root functionary with an empty roots list can NEVER match any cert
// (Functionary.Validate rejects with "no trusted roots provided in functionary"),
// so it is a dead policy that must not pass authoring validation.
func TestValidateUX_Gap_RootFunctionaryEmptyRoots(t *testing.T) {
	policyJSON := `{
		"expires":"2030-01-01T00:00:00Z",
		"roots":{"rootA":{"certificate":"Zm9v"}},
		"steps":{"build":{"name":"build",
			"functionaries":[{"type":"root","certConstraint":{"roots":[],"emails":["dev@example.com"]}}],
			"attestations":[{"type":"t"}]}}}`
	res := validateRaw(t, policyJSON)
	if res.Valid {
		t.Fatalf("a root functionary with empty certConstraint.roots is a dead policy and must FAIL validation, but it passed")
	}
	joined := strings.Join(res.Errors, " | ")
	if !strings.Contains(joined, "root") {
		t.Fatalf("error should explain the missing trusted root(s); got: %s", joined)
	}
}

// GAP 2: a root functionary with no certConstraint at all is equivalent to empty
// roots — dead, and must fail authoring validation.
func TestValidateUX_Gap_RootFunctionaryNoCertConstraint(t *testing.T) {
	policyJSON := `{
		"expires":"2030-01-01T00:00:00Z",
		"roots":{"rootA":{"certificate":"Zm9v"}},
		"steps":{"build":{"name":"build",
			"functionaries":[{"type":"root"}],
			"attestations":[{"type":"t"}]}}}`
	res := validateRaw(t, policyJSON)
	if res.Valid {
		t.Fatalf("a root functionary with no certConstraint must FAIL validation, but it passed")
	}
}

// GAP 3: a certConstraint.roots that references a root id NOT present in the
// policy's roots map is almost always a typo; it can never match and must be
// caught at authoring time (mirrors the existing publickeyid cross-check).
func TestValidateUX_Gap_CertConstraintUndefinedRoot(t *testing.T) {
	policyJSON := `{
		"expires":"2030-01-01T00:00:00Z",
		"roots":{"rootA":{"certificate":"Zm9v"}},
		"steps":{"build":{"name":"build",
			"functionaries":[{"type":"root","certConstraint":{"roots":["rootTYPO"],"emails":["dev@example.com"]}}],
			"attestations":[{"type":"t"}]}}}`
	res := validateRaw(t, policyJSON)
	if res.Valid {
		t.Fatalf("certConstraint.roots referencing an undefined root id must FAIL validation, but it passed")
	}
	joined := strings.Join(res.Errors, " | ")
	if !strings.Contains(joined, "rootTYPO") {
		t.Fatalf("error should name the undefined root id 'rootTYPO'; got: %s", joined)
	}
}
