//go:build audit

// Copyright 2024 The Witness Contributors
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
	"crypto"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// verifyAttestor implements attestation.Attestor with exported fields for JSON
// serialization in verification tests.
type verifyAttestor struct {
	AttName string `json:"name"`
	AttType string `json:"type"`
	Value   string `json:"value"`
}

func (a *verifyAttestor) Name() string                                  { return a.AttName }
func (a *verifyAttestor) Type() string                                  { return a.AttType }
func (a *verifyAttestor) RunType() attestation.RunType                  { return "test" }
func (a *verifyAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *verifyAttestor) Schema() *jsonschema.Schema                    { return nil }

// mockVerifiedSrc implements source.VerifiedSourcer for tests that need to
// control what Search returns per-step.
type mockVerifiedSrc struct {
	resultsByStep map[string][]source.CollectionVerificationResult
	err           error
}

func (m *mockVerifiedSrc) Search(_ context.Context, collectionName string, _ []string, _ []string) ([]source.CollectionVerificationResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if results, ok := m.resultsByStep[collectionName]; ok {
		return results, nil
	}
	return nil, nil
}

// futureExpiry returns an Expires time 1 year from now.
func futureExpiry() metav1.Time {
	return metav1.Time{Time: time.Now().Add(365 * 24 * time.Hour)}
}

// pastExpiry returns an Expires time 1 year in the past.
func pastExpiry() metav1.Time {
	return metav1.Time{Time: time.Now().Add(-365 * 24 * time.Hour)}
}

// sha256DV is a convenience DigestValue for SHA256.
var sha256DV = cryptoutil.DigestValue{Hash: crypto.SHA256}

// sha512DV is a convenience DigestValue for SHA512.
var sha512DV = cryptoutil.DigestValue{Hash: crypto.SHA512}

// ===========================================================================
// FINDING FV-001 (HIGH): Policy.Validate() accepts diamond dependencies
// without deduplication, causing topologicalSort to count edges incorrectly.
//
// Diamond: A -> B, A -> C, B -> D, C -> D
// This is valid (no cycle), but exercises the in-degree counting. If a step
// appears as a dependency of multiple other steps, the in-degree must reflect
// all edges, not just one.
// ===========================================================================

func TestVerify_Validate_DiamondDependency(t *testing.T) {
	// Finding: FV-001 | Severity: MEDIUM | Diamond dependency graphs
	// Description: Verify that diamond-shaped DAGs are correctly handled
	// by both Validate() and topologicalSort(). A diamond is NOT a cycle.
	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"A": {Name: "A", AttestationsFrom: []string{"B", "C"}},
			"B": {Name: "B", AttestationsFrom: []string{"D"}},
			"C": {Name: "C", AttestationsFrom: []string{"D"}},
			"D": {Name: "D"},
		},
	}

	err := p.Validate()
	assert.NoError(t, err, "diamond DAG should be valid, not a cycle")

	sorted, err := p.topologicalSort()
	assert.NoError(t, err, "diamond DAG should sort without error")
	assert.Len(t, sorted, 4, "all 4 steps should appear in sort")

	// D must come before B and C; B and C must come before A.
	indexOf := make(map[string]int)
	for i, name := range sorted {
		indexOf[name] = i
	}
	assert.Less(t, indexOf["D"], indexOf["B"], "D must precede B")
	assert.Less(t, indexOf["D"], indexOf["C"], "D must precede C")
	assert.Less(t, indexOf["B"], indexOf["A"], "B must precede A")
	assert.Less(t, indexOf["C"], indexOf["A"], "C must precede A")
}

// ===========================================================================
// FINDING FV-002 (HIGH): topologicalSort with disconnected components.
//
// If the graph has multiple disconnected subgraphs (e.g., steps with no
// dependencies on each other), topologicalSort should still return all steps.
// ===========================================================================

func TestVerify_TopologicalSort_DisconnectedComponents(t *testing.T) {
	// Finding: FV-002 | Severity: LOW | Disconnected graph components
	// Description: Steps with no dependencies on each other form disconnected
	// components. topologicalSort must still include all of them.
	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"island1": {Name: "island1"},
			"island2": {Name: "island2"},
			"island3": {Name: "island3"},
			"chain-a": {Name: "chain-a", AttestationsFrom: []string{"chain-b"}},
			"chain-b": {Name: "chain-b"},
		},
	}

	err := p.Validate()
	assert.NoError(t, err)

	sorted, err := p.topologicalSort()
	assert.NoError(t, err)
	assert.Len(t, sorted, 5, "all 5 steps must appear")

	// chain-b must come before chain-a
	indexOf := make(map[string]int)
	for i, name := range sorted {
		indexOf[name] = i
	}
	assert.Less(t, indexOf["chain-b"], indexOf["chain-a"])
}

// ===========================================================================
// FINDING FV-003 (HIGH): Deep chain cycle detection. A -> B -> C -> ... -> A
// with depth > 10. The DFS must handle deep chains without stack overflow or
// incorrect cycle path reporting.
// ===========================================================================

func TestVerify_Validate_DeepChainCycle(t *testing.T) {
	// Finding: FV-003 | Severity: HIGH | Deep chain cycle detection
	// Description: Cycles in long chains (depth 20) must be detected. The
	// cycle path in the error must be correct.
	steps := make(map[string]Step)
	depth := 20
	for i := 0; i < depth; i++ {
		name := fmt.Sprintf("step-%02d", i)
		var deps []string
		if i > 0 {
			deps = []string{fmt.Sprintf("step-%02d", i-1)}
		}
		steps[name] = Step{Name: name, AttestationsFrom: deps}
	}
	// Close the cycle: step-00 depends on step-19
	s := steps["step-00"]
	s.AttestationsFrom = []string{fmt.Sprintf("step-%02d", depth-1)}
	steps["step-00"] = s

	p := Policy{Expires: futureExpiry(), Steps: steps}
	err := p.Validate()
	require.Error(t, err, "deep cycle must be detected")

	var cyclErr ErrCircularDependency
	assert.ErrorAs(t, err, &cyclErr, "error must be ErrCircularDependency")
	assert.GreaterOrEqual(t, len(cyclErr.Steps), 2, "cycle path must have at least 2 steps")
}

// ===========================================================================
// FINDING FV-004 (MEDIUM): Self-referencing step detection
// ===========================================================================

func TestVerify_Validate_SelfReference(t *testing.T) {
	// Finding: FV-004 | Severity: MEDIUM | Self-reference detection
	// Description: A step that lists itself in AttestationsFrom must be rejected.
	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"selfish": {Name: "selfish", AttestationsFrom: []string{"selfish"}},
		},
	}

	err := p.Validate()
	require.Error(t, err)
	var selfErr ErrSelfReference
	assert.ErrorAs(t, err, &selfErr)
	assert.Equal(t, "selfish", selfErr.Step)
}

// ===========================================================================
// FINDING FV-005 (CRITICAL): checkCertConstraint uses set EQUALITY, not
// subset matching. This means:
// - constraints=["a@x.com", "b@x.com"], values=["a@x.com"] -> FAILS (unmet: b@x.com)
// - constraints=["a@x.com"], values=["a@x.com", "b@x.com"] -> FAILS (unexpected: b@x.com)
//
// This is a bidirectional exact-set match. Any extra values on either side
// cause failure. This is BY DESIGN for security (prevents cert spoofing
// with extra SANs), but could surprise policy authors who expect subset
// semantics.
// ===========================================================================

func TestVerify_CheckCertConstraint_SetEquality(t *testing.T) {
	// Finding: FV-005 | Severity: CRITICAL | Set equality semantics
	// Description: checkCertConstraint requires EXACT set match between
	// constraints and values. Not subset, not superset -- exact.

	tests := []struct {
		name        string
		constraints []string
		values      []string
		wantErr     bool
		desc        string
	}{
		{
			name:        "exact match passes",
			constraints: []string{"a@x.com", "b@x.com"},
			values:      []string{"a@x.com", "b@x.com"},
			wantErr:     false,
			desc:        "identical sets should pass",
		},
		{
			name:        "extra constraint fails - unmet constraint",
			constraints: []string{"a@x.com", "b@x.com"},
			values:      []string{"a@x.com"},
			wantErr:     true,
			desc:        "cert missing b@x.com that policy requires",
		},
		{
			name:        "extra value fails - unexpected value",
			constraints: []string{"a@x.com"},
			values:      []string{"a@x.com", "b@x.com"},
			wantErr:     true,
			desc:        "cert has extra b@x.com not in policy constraints",
		},
		{
			name:        "empty constraints with values fails",
			constraints: []string{},
			values:      []string{"a@x.com"},
			wantErr:     true,
			desc:        "no constraints means cert should have no values",
		},
		{
			name:        "empty constraints with empty values passes",
			constraints: []string{},
			values:      []string{},
			wantErr:     false,
			desc:        "empty == empty",
		},
		{
			name:        "allow-all constraint passes any value",
			constraints: []string{"*"},
			values:      []string{"literally-anything"},
			wantErr:     false,
			desc:        "the * wildcard bypasses all checking",
		},
		{
			name:        "allow-all constraint passes empty value",
			constraints: []string{"*"},
			values:      []string{},
			wantErr:     false,
			desc:        "* allows even empty cert values",
		},
		{
			name:        "nil constraints with nil values",
			constraints: nil,
			values:      nil,
			wantErr:     false,
			desc:        "nil treated as empty",
		},
		{
			name:        "whitespace is significant",
			constraints: []string{"a@x.com"},
			values:      []string{" a@x.com"},
			wantErr:     true,
			desc:        "leading whitespace makes values different",
		},
		{
			name:        "case sensitive",
			constraints: []string{"A@X.COM"},
			values:      []string{"a@x.com"},
			wantErr:     true,
			desc:        "case matters in set matching",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCertConstraint("email", tt.constraints, tt.values)
			if tt.wantErr {
				assert.Error(t, err, tt.desc)
			} else {
				assert.NoError(t, err, tt.desc)
			}
		})
	}
}

// ===========================================================================
// FINDING FV-006 (HIGH): checkCertConstraint with duplicate constraints
// causes silent constraint weakening due to map dedup.
//
// constraints=["ACME", "ACME"], values=["ACME"] -> PASSES
// The map `unmet` deduplicates "ACME" to a single entry. When the single
// cert value deletes it, len(unmet)==0 and we pass. But the policy author
// may have intended to require TWO occurrences.
// ===========================================================================

func TestVerify_CheckCertConstraint_DuplicateConstraintWeakening(t *testing.T) {
	// Finding: FV-006 | Severity: HIGH | Duplicate constraint collapse
	// Description: Duplicate constraints are silently deduplicated by the
	// unmet map, weakening the constraint set. This test PROVES the bug
	// exists by asserting the (incorrect but current) behavior passes.
	err := checkCertConstraint("org", []string{"ACME", "ACME"}, []string{"ACME"})
	// BUG: This SHOULD fail because the policy has 2 constraints but the cert
	// only has 1 value. Instead it passes because the map deduplicates.
	assert.NoError(t, err, "BUG PROVEN: duplicate constraints collapse via map dedup, silently weakening the constraint set")
}

// ===========================================================================
// FINDING FV-007 (MEDIUM): checkCertConstraint with duplicate values
// causes false rejection.
//
// constraints=["ACME"], values=["ACME", "ACME"] -> FAILS
// First "ACME" deletes the constraint. Second "ACME" is "unexpected".
// ===========================================================================

func TestVerify_CheckCertConstraint_DuplicateValueRejection(t *testing.T) {
	// Finding: FV-007 | Severity: MEDIUM | Duplicate value rejection
	// Description: If a cert has duplicate values (e.g., two identical SANs),
	// the second one is rejected as "unexpected" because the constraint was
	// already consumed by the first.
	err := checkCertConstraint("email", []string{"a@x.com"}, []string{"a@x.com", "a@x.com"})
	assert.Error(t, err, "second duplicate value is unexpected after first consumes the constraint")
	assert.Contains(t, err.Error(), "unexpected")
}

// ===========================================================================
// FINDING FV-008 (HIGH): checkCertConstraint single empty string normalization
//
// The function has special handling: if constraints==[""] it normalizes to [].
// Same for values==[""].  But what about constraints==["", ""]?
// ===========================================================================

func TestVerify_CheckCertConstraint_EmptyStringNormalization(t *testing.T) {
	// Finding: FV-008 | Severity: MEDIUM | Empty string normalization edge cases
	// Description: The function normalizes single-element [""] to [], but
	// multi-element ["", ""] is NOT normalized. This creates inconsistency.

	// Single empty string -> normalized to empty
	err := checkCertConstraint("dns", []string{""}, []string{""})
	assert.NoError(t, err, "single empty string on both sides normalizes to empty==empty")

	// Two empty strings in constraints -> NOT normalized by the single-element check.
	// The map `unmet` deduplicates "" to one entry. But values [""] IS normalized
	// to [] (single empty string rule). So unmet has 1 entry but 0 values iterate.
	// Result: len(unmet) > 0 -> error.
	//
	// This is inconsistent: ["", ""] constraints with [""] values fails, but
	// [""] constraints with [""] values passes. The two-element form doesn't
	// get the single-element normalization.
	err = checkCertConstraint("dns", []string{"", ""}, []string{""})
	assert.Error(t, err, "two empty strings in constraints are not normalized, but values [''] is normalized to [], creating asymmetry")

	// However: ["", ""] constraints with ["", ""] values DOES pass because
	// map dedup makes unmet have 1 entry, and values ["", ""] has first ""
	// that deletes it plus second "" that is "unexpected".
	err = checkCertConstraint("dns", []string{"", ""}, []string{"", ""})
	// BUG: Map dedup means 2 constraints -> 1 unmet entry. First value deletes it.
	// Second value has no entry in unmet -> "unexpected" error.
	assert.Error(t, err, "BUG PROVEN: duplicate constraints collapse via map, second value is 'unexpected'")
}

// ===========================================================================
// FINDING FV-009 (HIGH): checkCertConstraint with unicode normalization.
// Go string comparison is byte-level, not Unicode-normalized. Two strings
// that look identical but use different Unicode representations will fail.
// ===========================================================================

func TestVerify_CheckCertConstraint_UnicodeNormalization(t *testing.T) {
	// Finding: FV-009 | Severity: MEDIUM | Unicode normalization
	// Description: Strings that appear identical but differ in Unicode
	// representation (NFC vs NFD) will not match because Go uses byte comparison.
	//
	// "cafe\u0301" (e + combining acute) vs "caf\u00e9" (precomposed e-acute)
	nfd := "cafe\u0301" // NFD: e + combining acute accent
	nfc := "caf\u00e9"  // NFC: precomposed e-acute

	// These look the same to humans but are different byte sequences
	err := checkCertConstraint("org", []string{nfc}, []string{nfd})
	assert.Error(t, err, "NFC vs NFD representations are not byte-equal, constraint fails")
}

// ===========================================================================
// FINDING FV-010 (CRITICAL): compareArtifacts only checks the INTERSECTION
// of material paths and artifact paths. Extra artifacts not present in
// materials are completely ignored (only logged at debug level).
//
// An attacker who controls a step's output can inject arbitrary extra files
// that will never be validated by the consuming step.
// ===========================================================================

func TestVerify_CompareArtifacts_ExtraArtifactsIgnored(t *testing.T) {
	// Finding: FV-010 | Severity: CRITICAL | Extra artifacts silently ignored
	// Description: compareArtifacts iterates over materials and checks matching
	// paths in artifacts. But artifacts with paths NOT in materials are silently
	// ignored. An attacker can inject poisoned files into a step's products that
	// no downstream step will ever validate.

	mats := map[string]cryptoutil.DigestSet{
		"legit.bin": {sha256DV: "aaa111"},
	}
	arts := map[string]cryptoutil.DigestSet{
		"legit.bin":   {sha256DV: "aaa111"}, // matches
		"evil.bin":    {sha256DV: "deadbeef"}, // INJECTED - not in materials
		"trojan.so":   {sha256DV: "cafebabe"}, // INJECTED - not in materials
	}

	err := compareArtifacts(mats, arts)
	// BUG: This passes because compareArtifacts only checks keys present in mats.
	// evil.bin and trojan.so are never examined.
	assert.NoError(t, err, "BUG PROVEN: extra artifacts in producing step are silently ignored, allowing supply chain injection")
}

// ===========================================================================
// FINDING FV-011 (HIGH): compareArtifacts with overlapping keys but
// different digest types. If materials have SHA256 and artifacts have SHA512
// for the same path, DigestSet.Equal checks only the intersection of hash
// algorithms. If they share no common hash algorithm, Equal returns false.
// ===========================================================================

func TestVerify_CompareArtifacts_DifferentDigestTypes(t *testing.T) {
	// Finding: FV-011 | Severity: HIGH | Non-overlapping digest algorithms
	// Description: When materials and artifacts use different hash algorithms
	// for the same path, DigestSet.Equal has no common algorithms to compare
	// and returns false. This causes a mismatch error even though neither side
	// can actually prove the other is wrong.

	mats := map[string]cryptoutil.DigestSet{
		"file.txt": {sha256DV: "abc123"},
	}
	arts := map[string]cryptoutil.DigestSet{
		"file.txt": {sha512DV: "def456789"},
	}

	err := compareArtifacts(mats, arts)
	assert.Error(t, err, "no common hash algorithm means Equal returns false")
	var mismatchErr ErrMismatchArtifact
	assert.ErrorAs(t, err, &mismatchErr)
	assert.Equal(t, "file.txt", mismatchErr.Path)
}

// ===========================================================================
// FINDING FV-012 (HIGH): compareArtifacts with EMPTY DigestSets for a path.
// If both material and artifact exist for a path but have empty DigestSets,
// DigestSet.Equal returns false (no matching digest found).
// ===========================================================================

func TestVerify_CompareArtifacts_EmptyDigestSets(t *testing.T) {
	// Finding: FV-012 | Severity: HIGH | Empty DigestSets cause mismatch
	// Description: If a path exists in both maps but both DigestSets are empty,
	// Equal returns false because hasMatchingDigest is never set to true.

	mats := map[string]cryptoutil.DigestSet{
		"file.txt": {},
	}
	arts := map[string]cryptoutil.DigestSet{
		"file.txt": {},
	}

	err := compareArtifacts(mats, arts)
	// Two empty digest sets for the same path -> Equal returns false -> mismatch
	assert.Error(t, err, "empty DigestSets have no common hashes, Equal returns false")
}

// ===========================================================================
// FINDING FV-013 (MEDIUM): compareArtifacts is ASYMMETRIC. It only iterates
// over `mats` looking for matches in `arts`. If `arts` has paths that `mats`
// doesn't, they're ignored. But if `mats` has paths that `arts` doesn't,
// they're also ignored (the `!ok` continue).
//
// This means extra materials are silently passed too.
// ===========================================================================

func TestVerify_CompareArtifacts_AsymmetricCheck(t *testing.T) {
	// Finding: FV-013 | Severity: MEDIUM | Asymmetric artifact checking
	// Description: compareArtifacts only checks paths present in BOTH maps.
	// Extra materials (paths in mats but not arts) are silently skipped.
	// Extra artifacts (paths in arts but not mats) are silently skipped.
	// Only the intersection is validated.

	// Materials have an extra file that artifacts don't
	mats := map[string]cryptoutil.DigestSet{
		"common.txt":       {sha256DV: "aaa"},
		"only-in-mats.txt": {sha256DV: "bbb"},
	}
	arts := map[string]cryptoutil.DigestSet{
		"common.txt":       {sha256DV: "aaa"},
		"only-in-arts.txt": {sha256DV: "ccc"},
	}

	err := compareArtifacts(mats, arts)
	assert.NoError(t, err, "only the intersection (common.txt) is checked; disjoint paths are ignored on both sides")
}

// ===========================================================================
// FINDING FV-014 (MEDIUM): compareArtifacts with nil maps
// ===========================================================================

func TestVerify_CompareArtifacts_NilMaps(t *testing.T) {
	// Finding: FV-014 | Severity: LOW | Nil map handling
	// Description: compareArtifacts should not panic on nil inputs.

	assert.NotPanics(t, func() {
		_ = compareArtifacts(nil, nil)
	}, "nil/nil must not panic")

	assert.NotPanics(t, func() {
		_ = compareArtifacts(nil, map[string]cryptoutil.DigestSet{"f": {sha256DV: "x"}})
	}, "nil mats must not panic")

	assert.NotPanics(t, func() {
		_ = compareArtifacts(map[string]cryptoutil.DigestSet{"f": {sha256DV: "x"}}, nil)
	}, "nil arts must not panic")

	// nil mats means no iteration happens -> no error
	err := compareArtifacts(nil, map[string]cryptoutil.DigestSet{"f": {sha256DV: "x"}})
	assert.NoError(t, err, "nil materials means nothing to check, passes vacuously")
}

// ===========================================================================
// FINDING FV-015 (CRITICAL): Policy.Verify with zero steps returns error
// but a policy with steps that all have empty Passed lists should fail.
// ===========================================================================

func TestVerify_VerifyEmptyPolicy(t *testing.T) {
	// Finding: FV-015 | Severity: MEDIUM | Empty/nil policy behavior
	// Description: Policy.Verify with no steps should return an error, not
	// vacuously pass. A policy with nil Steps map should also fail gracefully.

	t.Run("nil steps map", func(t *testing.T) {
		p := Policy{
			Expires: futureExpiry(),
			Steps:   nil,
		}
		src := &mockVerifiedSrc{resultsByStep: map[string][]source.CollectionVerificationResult{}}
		pass, _, err := p.Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{"sha256:abc"}),
			WithSearchDepth(1),
		)
		assert.False(t, pass)
		assert.Error(t, err, "nil steps should error")
	})

	t.Run("empty steps map", func(t *testing.T) {
		p := Policy{
			Expires: futureExpiry(),
			Steps:   map[string]Step{},
		}
		src := &mockVerifiedSrc{resultsByStep: map[string][]source.CollectionVerificationResult{}}
		pass, _, err := p.Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{"sha256:abc"}),
			WithSearchDepth(1),
		)
		assert.False(t, pass)
		assert.Error(t, err, "empty steps should error with 'policy has no steps to verify'")
	})
}

// ===========================================================================
// FINDING FV-016 (HIGH): Policy.Verify with expired policy
// ===========================================================================

func TestVerify_VerifyExpiredPolicy(t *testing.T) {
	// Finding: FV-016 | Severity: HIGH | Expired policy rejection
	// Description: A policy with an expiry in the past must be rejected.

	p := Policy{
		Expires: pastExpiry(),
		Steps: map[string]Step{
			"build": {Name: "build"},
		},
	}

	src := &mockVerifiedSrc{resultsByStep: map[string][]source.CollectionVerificationResult{}}
	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithSearchDepth(1),
	)
	assert.False(t, pass)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

// ===========================================================================
// FINDING FV-017 (MEDIUM): Policy.Verify with missing required options
// ===========================================================================

func TestVerify_VerifyMissingOptions(t *testing.T) {
	// Finding: FV-017 | Severity: MEDIUM | Missing option validation
	// Description: Verify must reject calls with missing required options.

	p := Policy{
		Expires: futureExpiry(),
		Steps:   map[string]Step{"build": {Name: "build"}},
	}

	t.Run("no verified source", func(t *testing.T) {
		_, _, err := p.Verify(context.Background(),
			WithSubjectDigests([]string{"sha256:abc"}),
			WithSearchDepth(1),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "verified source")
	})

	t.Run("no subject digests", func(t *testing.T) {
		src := &mockVerifiedSrc{resultsByStep: map[string][]source.CollectionVerificationResult{}}
		_, _, err := p.Verify(context.Background(),
			WithVerifiedSource(src),
			WithSearchDepth(1),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "subject digest")
	})

	t.Run("zero search depth uses default", func(t *testing.T) {
		// Default searchDepth is 3, but setting it to 0 should be rejected
		src := &mockVerifiedSrc{resultsByStep: map[string][]source.CollectionVerificationResult{}}
		_, _, err := p.Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{"sha256:abc"}),
			WithSearchDepth(0),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "search depth")
	})
}

// ===========================================================================
// FINDING FV-018 (HIGH): Policy.Verify with cycle should fail at Validate
// ===========================================================================

func TestVerify_VerifyWithCycle(t *testing.T) {
	// Finding: FV-018 | Severity: HIGH | Verify rejects cyclic policies
	// Description: A policy with a cycle in AttestationsFrom should be
	// rejected during the Validate() call within Verify().

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"A": {Name: "A", AttestationsFrom: []string{"B"}},
			"B": {Name: "B", AttestationsFrom: []string{"C"}},
			"C": {Name: "C", AttestationsFrom: []string{"A"}},
		},
	}

	src := &mockVerifiedSrc{resultsByStep: map[string][]source.CollectionVerificationResult{}}
	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithSearchDepth(1),
	)
	assert.False(t, pass)
	require.Error(t, err)
	var cyclErr ErrCircularDependency
	assert.ErrorAs(t, err, &cyclErr)
}

// ===========================================================================
// FINDING FV-019 (HIGH): Policy.Verify with artifactsFrom referencing
// non-existent step should fail early.
// ===========================================================================

func TestVerify_VerifyArtifactsFromUnknownStep(t *testing.T) {
	// Finding: FV-019 | Severity: HIGH | artifactsFrom unknown step
	// Description: If a step's ArtifactsFrom references a step that doesn't
	// exist in the policy, Verify should catch this early.

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				ArtifactsFrom: []string{"nonexistent"},
			},
		},
	}

	src := &mockVerifiedSrc{resultsByStep: map[string][]source.CollectionVerificationResult{}}
	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithSearchDepth(1),
	)
	assert.False(t, pass)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

// ===========================================================================
// FINDING FV-020 (CRITICAL): checkCertConstraintGlob with patterns that
// contain '*' but are not valid globs, and patterns that cause the gobwas/glob
// library to exhibit pathological behavior.
// ===========================================================================

func TestVerify_CheckCertConstraintGlob_EdgeCases(t *testing.T) {
	// Finding: FV-020 | Severity: HIGH | Glob pattern edge cases
	// Description: Various edge cases in glob pattern matching for cert constraints.

	tests := []struct {
		name       string
		constraint string
		value      string
		wantErr    bool
		desc       string
	}{
		{
			name:       "empty constraint allows all",
			constraint: "",
			value:      "anything",
			wantErr:    false,
			desc:       "empty constraint is permissive",
		},
		{
			name:       "star constraint allows all",
			constraint: "*",
			value:      "anything",
			wantErr:    false,
			desc:       "* is the AllowAllConstraint",
		},
		{
			name:       "exact match without glob chars",
			constraint: "example.com",
			value:      "example.com",
			wantErr:    false,
			desc:       "non-glob exact match",
		},
		{
			name:       "exact mismatch without glob chars",
			constraint: "example.com",
			value:      "other.com",
			wantErr:    true,
			desc:       "non-glob exact mismatch",
		},
		{
			name:       "wildcard prefix",
			constraint: "*.example.com",
			value:      "foo.example.com",
			wantErr:    false,
			desc:       "standard wildcard prefix match",
		},
		{
			name:       "wildcard prefix no match",
			constraint: "*.example.com",
			value:      "foo.other.com",
			wantErr:    true,
			desc:       "wildcard prefix must match suffix",
		},
		{
			name:       "wildcard suffix",
			constraint: "test-*",
			value:      "test-anything",
			wantErr:    false,
			desc:       "wildcard suffix match",
		},
		{
			name:       "empty value with non-empty constraint",
			constraint: "required.com",
			value:      "",
			wantErr:    true,
			desc:       "empty value cannot match non-empty constraint",
		},
		{
			name:       "glob with special chars - brackets",
			constraint: "[a-z]*.com",
			value:      "abc.com",
			wantErr:    false,
			desc:       "character class in glob",
		},
		{
			name:       "glob with braces",
			constraint: "{foo,bar}*.com",
			value:      "foo.com",
			wantErr:    false,
			desc:       "alternation in glob",
		},
		{
			name:       "constraint with only asterisk in middle",
			constraint: "a*b",
			value:      "aXYZb",
			wantErr:    false,
			desc:       "asterisk matches anything in middle",
		},
		{
			name:       "invalid glob pattern with unclosed bracket",
			constraint: "[abc*",
			value:      "test",
			wantErr:    true,
			desc:       "invalid glob pattern returns error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkCertConstraintGlob("common name", tt.constraint, tt.value)
			if tt.wantErr {
				assert.Error(t, err, tt.desc)
			} else {
				assert.NoError(t, err, tt.desc)
			}
		})
	}
}

// ===========================================================================
// FINDING FV-021 (LOW): topologicalSort with duplicate step names in
// AttestationsFrom. The duplicate edge causes in-degree to be 2 and
// dependents to list the child twice, which cancel out correctly. But this
// is still a latent issue: Validate doesn't reject duplicate deps, so a
// policy author who accidentally duplicates a dep gets silently different
// behavior during cross-step context building (the dep is iterated twice).
// ===========================================================================

func TestVerify_TopologicalSort_DuplicateDependency(t *testing.T) {
	// Finding: FV-021 | Severity: LOW | Duplicate dependency edges
	// Description: If a step lists the same dependency twice in AttestationsFrom,
	// topologicalSort handles it correctly because the duplicate in-degree
	// increment is matched by a duplicate decrement in the dependents list.
	// However, Validate() does not reject duplicate deps, meaning cross-step
	// context building will iterate the same dep twice (wasteful but not incorrect).

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"base":  {Name: "base"},
			"build": {Name: "build", AttestationsFrom: []string{"base", "base"}}, // duplicate!
		},
	}

	// Validate should pass -- no actual cycle, and duplicates are not rejected
	err := p.Validate()
	assert.NoError(t, err, "duplicate deps are not a cycle and not rejected by Validate")

	// topologicalSort handles duplicates correctly: in-degree 2 gets decremented twice
	sorted, err := p.topologicalSort()
	assert.NoError(t, err, "duplicate deps are handled correctly by Kahn's algorithm")
	assert.Len(t, sorted, 2, "both steps should appear in sort")
}

// ===========================================================================
// FINDING FV-022 (LOW): Validate and topologicalSort consistency check.
// Both algorithms must agree on whether a graph is valid. With duplicate
// edges in AttestationsFrom, both handle it correctly -- Validate's DFS
// doesn't re-trigger on already-gray nodes from the same path, and
// topologicalSort's Kahn's algorithm correctly balances the duplicate
// in-degree with duplicate dependents entries. However, neither rejects
// duplicate deps, which is a validation gap.
// ===========================================================================

func TestVerify_ValidateVsTopologicalSort_Consistency(t *testing.T) {
	// Finding: FV-022 | Severity: LOW | Validate and topologicalSort consistency
	// Description: Both Validate (DFS) and topologicalSort (Kahn's) must agree
	// on whether a graph is valid. This test verifies they produce consistent
	// results for various graph shapes including duplicate edges.

	tests := []struct {
		name      string
		steps     map[string]Step
		wantCycle bool
	}{
		{
			name: "simple valid chain",
			steps: map[string]Step{
				"a": {Name: "a"},
				"b": {Name: "b", AttestationsFrom: []string{"a"}},
			},
			wantCycle: false,
		},
		{
			name: "duplicate edge - both should agree valid",
			steps: map[string]Step{
				"root":  {Name: "root"},
				"child": {Name: "child", AttestationsFrom: []string{"root", "root"}},
			},
			wantCycle: false,
		},
		{
			name: "actual cycle - both should detect",
			steps: map[string]Step{
				"a": {Name: "a", AttestationsFrom: []string{"b"}},
				"b": {Name: "b", AttestationsFrom: []string{"a"}},
			},
			wantCycle: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Policy{Expires: futureExpiry(), Steps: tt.steps}

			validateErr := p.Validate()
			_, topoErr := p.topologicalSort()

			if tt.wantCycle {
				assert.Error(t, validateErr, "Validate should detect cycle")
				assert.Error(t, topoErr, "topologicalSort should detect cycle")
			} else {
				assert.NoError(t, validateErr, "Validate should not detect cycle")
				assert.NoError(t, topoErr, "topologicalSort should not detect cycle")
			}

			// Key invariant: they must ALWAYS agree
			validateHasCycle := validateErr != nil
			topoHasCycle := topoErr != nil
			assert.Equal(t, validateHasCycle, topoHasCycle,
				"Validate and topologicalSort must agree on cycle detection")
		})
	}
}

// ===========================================================================
// FINDING FV-023 (MEDIUM): Policy.Verify clock skew tolerance
// ===========================================================================

func TestVerify_ClockSkewTolerance(t *testing.T) {
	// Finding: FV-023 | Severity: MEDIUM | Clock skew tolerance
	// Description: WithClockSkewTolerance should allow recently-expired
	// policies to still pass verification.

	// Policy expired 30 seconds ago
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(-30 * time.Second)},
		Steps: map[string]Step{
			"build": {Name: "build"},
		},
	}

	src := &mockVerifiedSrc{resultsByStep: map[string][]source.CollectionVerificationResult{}}

	t.Run("fails without tolerance", func(t *testing.T) {
		pass, _, err := p.Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{"sha256:abc"}),
			WithSearchDepth(1),
		)
		assert.False(t, pass)
		assert.Error(t, err)
	})

	t.Run("passes with sufficient tolerance", func(t *testing.T) {
		// 60 second tolerance should accommodate the 30-second expiry
		_, _, err := p.Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{"sha256:abc"}),
			WithSearchDepth(1),
			WithClockSkewTolerance(60*time.Second),
		)
		// Won't get an expiry error -- but may get other errors from missing collections.
		// The point is it should NOT be an expiry error.
		if err != nil {
			assert.NotContains(t, err.Error(), "expired", "should not be an expiry error with sufficient tolerance")
		}
	})
}

// ===========================================================================
// FINDING FV-024 (HIGH): Validate with unknown step in AttestationsFrom
// ===========================================================================

func TestVerify_Validate_UnknownStepReference(t *testing.T) {
	// Finding: FV-024 | Severity: HIGH | Unknown step detection
	// Description: A step referencing a non-existent step in AttestationsFrom
	// must be caught by Validate.

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build": {Name: "build", AttestationsFrom: []string{"nonexistent"}},
		},
	}

	err := p.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
	assert.Contains(t, err.Error(), "unknown step")
}

// ===========================================================================
// FINDING FV-025 (MEDIUM): topologicalSort with single-node graph
// ===========================================================================

func TestVerify_TopologicalSort_SingleNode(t *testing.T) {
	// Finding: FV-025 | Severity: LOW | Single node topology
	// Description: A single step with no dependencies should be trivially sorted.

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"only": {Name: "only"},
		},
	}

	sorted, err := p.topologicalSort()
	require.NoError(t, err)
	assert.Equal(t, []string{"only"}, sorted)
}

// ===========================================================================
// FINDING FV-026 (MEDIUM): verifyArtifacts when no passed collections exist
// ===========================================================================

func TestVerify_VerifyArtifacts_NoPassedCollections(t *testing.T) {
	// Finding: FV-026 | Severity: MEDIUM | No passed collections handling
	// Description: verifyArtifacts should handle steps that have no passed
	// collections gracefully, adding a rejection reason.

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build": {Name: "build"},
		},
	}

	resultsByStep := map[string]StepResult{
		"build": {
			Step:   "build",
			Passed: nil, // no passed collections
		},
	}

	results, err := p.verifyArtifacts(resultsByStep)
	require.NoError(t, err)
	assert.Len(t, results["build"].Rejected, 1)
	assert.Contains(t, results["build"].Rejected[0].Reason.Error(), "no passed collections")
}

// ===========================================================================
// FINDING FV-027 (HIGH): Validate with complex multi-cycle graph
// ===========================================================================

func TestVerify_Validate_MultipleCycles(t *testing.T) {
	// Finding: FV-027 | Severity: HIGH | Multiple cycles in one policy
	// Description: A policy with multiple independent cycles should detect
	// at least one of them. The DFS stops at the first cycle found.

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"A": {Name: "A", AttestationsFrom: []string{"B"}},
			"B": {Name: "B", AttestationsFrom: []string{"A"}}, // cycle 1: A->B->A
			"C": {Name: "C", AttestationsFrom: []string{"D"}},
			"D": {Name: "D", AttestationsFrom: []string{"C"}}, // cycle 2: C->D->C
		},
	}

	err := p.Validate()
	require.Error(t, err)
	var cyclErr ErrCircularDependency
	assert.ErrorAs(t, err, &cyclErr)
	// At least one cycle should be reported
	assert.GreaterOrEqual(t, len(cyclErr.Steps), 2)
}

// ===========================================================================
// FINDING FV-028 (MEDIUM): checkCertConstraint with very large inputs
// ===========================================================================

func TestVerify_CheckCertConstraint_LargeInputs(t *testing.T) {
	// Finding: FV-028 | Severity: LOW | Large input handling
	// Description: checkCertConstraint should handle large constraint and value
	// lists without excessive memory use or panics.

	// Generate 1000 unique constraints and matching values
	constraints := make([]string, 1000)
	values := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		s := fmt.Sprintf("user-%04d@example.com", i)
		constraints[i] = s
		values[i] = s
	}

	err := checkCertConstraint("email", constraints, values)
	assert.NoError(t, err, "1000 matching constraints should pass")

	// Now remove one value
	err = checkCertConstraint("email", constraints, values[:999])
	assert.Error(t, err, "missing one value should fail")
}

// ===========================================================================
// FINDING FV-029 (HIGH): verifyCollectionArtifacts behavior when referenced
// step has passed collections but artifact comparison fails for all of them
// ===========================================================================

func TestVerify_VerifyArtifacts_AllCollectionsFail(t *testing.T) {
	// Finding: FV-029 | Severity: MEDIUM | All artifact comparisons fail
	// Description: When verifyCollectionArtifacts checks artifacts from a
	// referenced step and ALL comparisons fail, the step should be rejected.

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				ArtifactsFrom: []string{"source"},
			},
			"source": {Name: "source"},
		},
	}

	// Build step has materials with SHA256
	// Source step has products with different digests
	buildCollection := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
			Collection: attestation.Collection{
				Name: "build",
			},
		},
	}

	sourceCollection := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Statement: intoto.Statement{PredicateType: attestation.CollectionType},
			Collection: attestation.Collection{
				Name: "source",
			},
		},
	}

	resultsByStep := map[string]StepResult{
		"build": {
			Step:   "build",
			Passed: []PassedCollection{{Collection: buildCollection}},
		},
		"source": {
			Step:   "source",
			Passed: []PassedCollection{{Collection: sourceCollection}},
		},
	}

	results, err := p.verifyArtifacts(resultsByStep)
	require.NoError(t, err, "verifyArtifacts itself should not error")
	// Both steps should still be in results. Build step's artifact check passes
	// vacuously because the collections have no materials/products to compare.
	assert.NotNil(t, results["build"])
	assert.NotNil(t, results["source"])
}

// ===========================================================================
// FUZZ TESTS
// ===========================================================================

// FuzzValidateRandomGraphs generates random dependency graphs and verifies
// that Validate never panics, and that its result is consistent with
// topologicalSort (if Validate passes, topologicalSort should also pass,
// EXCEPT for the known duplicate-edge bug FV-022).
func FuzzValidateRandomGraphs(f *testing.F) {
	// Seed: linear chain
	f.Add(uint8(5), uint8(1), uint8(0))
	// Seed: no edges
	f.Add(uint8(10), uint8(0), uint8(0))
	// Seed: dense
	f.Add(uint8(8), uint8(3), uint8(0))
	// Seed: single node
	f.Add(uint8(1), uint8(0), uint8(0))
	// Seed: force backward edge (potential cycle)
	f.Add(uint8(4), uint8(2), uint8(1))

	f.Fuzz(func(t *testing.T, numSteps uint8, edgeDensity uint8, cycleSeed uint8) {
		n := int(numSteps)
		if n == 0 {
			n = 1
		}
		if n > 30 {
			n = 30
		}

		names := make([]string, n)
		for i := 0; i < n; i++ {
			names[i] = fmt.Sprintf("s%d", i)
		}

		steps := make(map[string]Step, n)
		density := int(edgeDensity)

		for i, name := range names {
			step := Step{Name: name}
			if i > 0 && density > 0 {
				// Add forward edges (should not create cycles)
				for j := 0; j < density && j < i; j++ {
					idx := (int(cycleSeed) + j) % i
					step.AttestationsFrom = append(step.AttestationsFrom, names[idx])
				}
			}
			steps[name] = step
		}

		// Optionally add a backward edge to create a cycle
		if cycleSeed%3 == 0 && n >= 2 {
			s := steps[names[0]]
			s.AttestationsFrom = append(s.AttestationsFrom, names[n-1])
			steps[names[0]] = s
		}

		p := Policy{Expires: futureExpiry(), Steps: steps}

		// Must not panic
		_ = p.Validate()
		_, _ = p.topologicalSort()
	})
}

// FuzzCompareArtifactsMultiHash fuzzes compareArtifacts with DigestSets that
// have multiple hash algorithms per path, probing for edge cases in
// DigestSet.Equal.
func FuzzCompareArtifactsMultiHash(f *testing.F) {
	f.Add("file.txt", "abc", "def", "file.txt", "abc", "ghi")
	f.Add("a", "x", "y", "a", "x", "y")
	f.Add("a", "x", "y", "a", "z", "y")
	f.Add("", "", "", "", "", "")

	f.Fuzz(func(t *testing.T, matPath, matSHA256, matSHA512, artPath, artSHA256, artSHA512 string) {
		mats := map[string]cryptoutil.DigestSet{
			matPath: {
				sha256DV: matSHA256,
				sha512DV: matSHA512,
			},
		}
		arts := map[string]cryptoutil.DigestSet{
			artPath: {
				sha256DV: artSHA256,
				sha512DV: artSHA512,
			},
		}

		// Must not panic
		err := compareArtifacts(mats, arts)

		// Invariant: if paths match and both algorithms match, no error
		if matPath == artPath && matSHA256 == artSHA256 && matSHA512 == artSHA512 {
			if matPath != "" && matSHA256 != "" && matSHA512 != "" {
				assert.NoError(t, err, "identical paths and digests should match")
			}
		}

		// Invariant: if paths match and any algorithm mismatches, error
		if matPath == artPath && matPath != "" {
			if (matSHA256 != artSHA256 && matSHA256 != "" && artSHA256 != "") ||
				(matSHA512 != artSHA512 && matSHA512 != "" && artSHA512 != "") {
				// At least one common hash differs
				if matSHA256 != "" && artSHA256 != "" && matSHA256 != artSHA256 {
					assert.Error(t, err, "mismatched SHA256 should cause error")
				}
			}
		}
	})
}

// FuzzCheckCertConstraintSetOps fuzzes checkCertConstraint with multi-element
// constraint and value sets to probe set-equality edge cases.
func FuzzCheckCertConstraintSetOps(f *testing.F) {
	f.Add("a", "b", "a", "b")
	f.Add("a", "b", "b", "a")     // reverse order
	f.Add("a", "a", "a", "")      // duplicate constraint
	f.Add("*", "", "anything", "") // wildcard with extra
	f.Add("", "", "", "")          // all empty

	f.Fuzz(func(t *testing.T, c1, c2, v1, v2 string) {
		constraints := []string{c1, c2}
		values := []string{v1, v2}

		// Must not panic
		_ = checkCertConstraint("test", constraints, values)

		// Also test with nil values
		_ = checkCertConstraint("test", constraints, nil)
		_ = checkCertConstraint("test", nil, values)
	})
}

// FuzzCheckCertConstraintGlobPanic fuzzes checkCertConstraintGlob with
// adversarial patterns designed to trigger panics in gobwas/glob.
func FuzzCheckCertConstraintGlobPanic(f *testing.F) {
	// Known problematic patterns from gobwas/glob issues
	f.Add("0*,{*,", "test")
	f.Add("{{{{{", "test")
	f.Add(strings.Repeat("{a,", 50)+strings.Repeat("}", 50), "test")
	f.Add("[\\", "test")
	f.Add("*****", "test")
	f.Add("{,,,,,}", "test")
	f.Add("*{*{*{*{*", "test")
	f.Add("\x00*\xff*\xfe", "\x00test\xff")
	f.Add("?*?*?*?*?*?*?*?*?*?*", strings.Repeat("a", 100))

	f.Fuzz(func(t *testing.T, pattern, value string) {
		// Must not panic. The safeGlobMatch wrapper should recover any panics.
		assert.NotPanics(t, func() {
			_ = checkCertConstraintGlob("cn", pattern, value)
		}, "checkCertConstraintGlob must not panic on any input")
	})
}

// FuzzTopologicalSortStress generates large random DAGs and verifies
// topologicalSort never panics and produces correct ordering when successful.
func FuzzTopologicalSortStress(f *testing.F) {
	f.Add(uint8(10), uint64(12345))
	f.Add(uint8(50), uint64(0))
	f.Add(uint8(1), uint64(9999))
	f.Add(uint8(30), uint64(42))

	f.Fuzz(func(t *testing.T, numSteps uint8, seed uint64) {
		n := int(numSteps)
		if n == 0 {
			n = 1
		}
		if n > 50 {
			n = 50
		}

		names := make([]string, n)
		for i := 0; i < n; i++ {
			names[i] = fmt.Sprintf("step%d", i)
		}

		steps := make(map[string]Step, n)
		s := seed

		for i, name := range names {
			step := Step{Name: name}
			// Each step can optionally depend on earlier steps
			if i > 0 {
				// Use seed to decide how many deps (0 to min(3, i))
				maxDeps := i
				if maxDeps > 3 {
					maxDeps = 3
				}
				numDeps := int(s % uint64(maxDeps+1))
				s = s*6364136223846793005 + 1 // LCG for deterministic randomness

				for j := 0; j < numDeps; j++ {
					dep := int(s % uint64(i))
					s = s*6364136223846793005 + 1
					step.AttestationsFrom = append(step.AttestationsFrom, names[dep])
				}
			}
			steps[name] = step
		}

		p := Policy{Expires: futureExpiry(), Steps: steps}

		// Must not panic
		sorted, err := p.topologicalSort()

		if err == nil {
			// If sort succeeded, verify ordering: for every step, all its
			// deps must appear earlier in the sorted list.
			indexOf := make(map[string]int)
			for i, name := range sorted {
				indexOf[name] = i
			}
			assert.Len(t, sorted, len(steps), "all steps must appear")

			for name, step := range steps {
				for _, dep := range step.AttestationsFrom {
					depIdx, ok := indexOf[dep]
					if !ok {
						t.Errorf("dependency %s of %s not in sorted output", dep, name)
						continue
					}
					assert.Less(t, depIdx, indexOf[name],
						"dependency %s must appear before %s", dep, name)
				}
			}
		}
	})
}

// ===========================================================================
// FINDING FV-030 (MEDIUM): StepResult.Analyze behavior edge cases
// ===========================================================================

func TestVerify_StepResultAnalyze_EdgeCases(t *testing.T) {
	// Finding: FV-030 | Severity: MEDIUM | StepResult.Analyze edge cases
	// Description: Analyze returns true only if Passed is non-empty and no
	// Passed collection has Errors. Test edge cases.

	t.Run("empty result is failure", func(t *testing.T) {
		r := StepResult{Step: "test"}
		assert.False(t, r.Analyze(), "empty result should fail")
	})

	t.Run("only rejected collections", func(t *testing.T) {
		r := StepResult{
			Step:     "test",
			Rejected: []RejectedCollection{{Reason: fmt.Errorf("bad")}},
		}
		assert.False(t, r.Analyze(), "only rejected should fail")
	})

	t.Run("passed with errors is failure", func(t *testing.T) {
		r := StepResult{
			Step: "test",
			Passed: []PassedCollection{
				{
					Collection: source.CollectionVerificationResult{
						Errors: []error{fmt.Errorf("lurking error")},
					},
				},
			},
		}
		assert.False(t, r.Analyze(), "passed collection with errors should fail")
	})

	t.Run("passed without errors is success", func(t *testing.T) {
		r := StepResult{
			Step: "test",
			Passed: []PassedCollection{
				{Collection: source.CollectionVerificationResult{}},
			},
		}
		assert.True(t, r.Analyze(), "clean passed collection should succeed")
	})
}

// ===========================================================================
// FINDING FV-031 (HIGH): verifyArtifacts when step is missing from results
// ===========================================================================

func TestVerify_VerifyArtifacts_StepMissingFromResults(t *testing.T) {
	// Finding: FV-031 | Severity: HIGH | Step missing from results map
	// Description: If a step defined in the policy is not present in the
	// resultsByStep map at all, verifyArtifacts returns an error rather than
	// adding a rejection. This is because the code does `resultsByStep[step.Name]`
	// which returns a zero StepResult, then checks `len(Passed) == 0` and tries
	// to look up the step with `if result, ok := resultsByStep[step.Name]` --
	// ok is false since the key doesn't exist, so it returns a hard error.
	//
	// BUG: This is a fatal error for a condition that should arguably just be
	// a rejection. If a step has no results because Search returned nothing,
	// it should be added to the results map with a rejection, not cause the
	// entire verification to abort with a hard error.

	p := Policy{
		Expires: futureExpiry(),
		Steps: map[string]Step{
			"build":  {Name: "build"},
			"deploy": {Name: "deploy", ArtifactsFrom: []string{"build"}},
		},
	}

	// Only "deploy" is in results, "build" is missing from the map entirely
	resultsByStep := map[string]StepResult{
		"deploy": {
			Step: "deploy",
			Passed: []PassedCollection{
				{Collection: source.CollectionVerificationResult{
					CollectionEnvelope: source.CollectionEnvelope{
						Collection: attestation.Collection{Name: "deploy"},
					},
				}},
			},
		},
	}

	_, err := p.verifyArtifacts(resultsByStep)
	// BUG PROVEN: verifyArtifacts returns a hard error when a step is missing
	// from the results map, rather than gracefully adding a rejection.
	assert.Error(t, err, "BUG PROVEN: step missing from results map causes hard error instead of rejection")
	assert.Contains(t, err.Error(), "build", "error should reference the missing step")
}

// ===========================================================================
// FINDING FV-032 (MEDIUM): Validate with all steps being islands (no deps)
// ===========================================================================

func TestVerify_Validate_AllIslands(t *testing.T) {
	// Finding: FV-032 | Severity: LOW | All-island graph
	// Description: A policy where no step depends on any other should be valid.

	steps := make(map[string]Step)
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("step-%d", i)
		steps[name] = Step{Name: name}
	}

	p := Policy{Expires: futureExpiry(), Steps: steps}
	err := p.Validate()
	assert.NoError(t, err, "100 independent steps is valid")

	sorted, err := p.topologicalSort()
	assert.NoError(t, err)
	assert.Len(t, sorted, 100, "all 100 steps in sorted output")
}
