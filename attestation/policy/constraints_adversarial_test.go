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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ===========================================================================
// FINDING 1 (HIGH) — FIXED (#5746): Duplicate constraints in checkCertConstraint
// no longer collapse via map deduplication. Occurrences are counted, so a
// duplicate constraint requires that many matching cert values. These tests
// previously pinned the buggy fail-open behavior (assert.NoError); they now
// document the fail-closed fix (assert.Error). See failclosed_constraints_test.go
// TestRed_F1.
// ===========================================================================

func TestAdversarial_CheckCertConstraint_DuplicateConstraintsCollapse(t *testing.T) {
	// The constraint list has "ACME" twice, so the cert must present two "ACME"
	// values. A cert with only one "ACME" no longer collapses to a single map
	// entry — occurrences are counted, so this fails closed.
	err := checkCertConstraint("org",
		[]string{"ACME", "ACME"}, // Two constraints — require TWO matching values
		[]string{"ACME"},         // Cert has only one value
	)
	// FIXED: duplicate constraints are NOT deduplicated; one cert value cannot
	// satisfy two required occurrences.
	assert.Error(t, err,
		"FIXED (#5746): duplicate constraints [ACME, ACME] are no longer collapsed; "+
			"a cert with only one ACME value must fail closed.")
}

func TestAdversarial_CheckCertConstraint_DuplicateConstraintsDifferentCounts(t *testing.T) {
	// Policy requires ["A", "A", "B"] — three required occurrences (two A, one B).
	// A cert with ["A", "B"] presents only one A, so it can no longer satisfy the
	// two required A occurrences.
	err := checkCertConstraint("org",
		[]string{"A", "A", "B"}, // 3 required occurrences (2x A, 1x B)
		[]string{"A", "B"},      // 2 cert values — only one A
	)
	// FIXED: the duplicate A constraint is honored, not silently dropped.
	assert.Error(t, err,
		"FIXED (#5746): constraints=[A, A, B] require two A values; a cert with "+
			"values=[A, B] must fail closed (the duplicate A is no longer dropped).")
}

// ===========================================================================
// FINDING 2 (HIGH) — FIXED (#5746): checkCertConstraint now GLOB-matches
// multi-value fields (DNSNames, Emails, Organizations, URIs) whenever a
// constraint value carries a glob metacharacter (* ? { [), matching
// checkCertConstraintGlob's behavior for CommonName. A constraint with NO glob
// char still exact-matches (no behavior change for existing exact policies).
// These tests previously pinned the exact-only behavior (assert.Error); they now
// document the glob-match fix (assert.NoError).
// ===========================================================================

func TestAdversarial_CheckCertConstraint_NoGlobSupportForDNSNames(t *testing.T) {
	// "*.example.com" now matches "foo.example.com" for DNS names via glob
	// expansion, the same way CommonName glob matching works.
	err := checkCertConstraint("dns name",
		[]string{"*.example.com"},   // glob constraint
		[]string{"foo.example.com"}, // Cert has a matching DNS name
	)
	// FIXED (#5746, F2): the glob metachar '*' triggers glob matching for the
	// multi-value DNS field, so "*.example.com" matches "foo.example.com".
	assert.NoError(t, err,
		"FIXED (#5746, F2): checkCertConstraint glob-matches multi-value SAN fields; "+
			"'*.example.com' now matches 'foo.example.com', consistent with CommonName.")
}

func TestAdversarial_CheckCertConstraint_GlobInEmailConstraint(t *testing.T) {
	// An email constraint with a glob pattern now matches via glob expansion.
	err := checkCertConstraint("email",
		[]string{"*@example.com"},     // glob constraint: any @example.com address
		[]string{"alice@example.com"}, // Cert has a matching email
	)
	assert.NoError(t, err,
		"FIXED (#5746, F2): email constraints support glob patterns; "+
			"'*@example.com' matches 'alice@example.com'.")
}

// ===========================================================================
// FINDING 3 (MEDIUM): checkCertConstraint with nil constraints vs empty
// constraints has different semantics that could confuse callers.
//
// nil constraints: len(nil)==0, falls through to unmet-map logic with
//   empty map, then len(unmet)==0, returns nil (pass).
// []string{} constraints: same behavior, len([]string{})==0.
// BUT: if len(values) > 0, the check at line 189 catches both cases
//   and returns an error. So nil and empty are equivalent.
//
// The subtle issue: constraints=nil and values=nil both pass (correct),
// but this means a nil CertConstraint field is equivalent to "allow any",
// which may not be the intended default for a security-critical field.
// ===========================================================================

func TestAdversarial_CheckCertConstraint_NilConstraintsWithValues(t *testing.T) {
	// nil constraints with a cert that has values
	err := checkCertConstraint("org", nil, []string{"EvilCorp"})
	// This correctly fails -- nil constraints means "expect no values"
	assert.Error(t, err,
		"nil constraints with cert values should fail")
}

func TestAdversarial_CheckCertConstraint_NilConstraintsNilValues(t *testing.T) {
	// nil constraints with nil values
	err := checkCertConstraint("org", nil, nil)
	// This passes -- nil constraints + nil values is acceptable
	assert.NoError(t, err,
		"nil constraints + nil values should pass")
}

func TestAdversarial_CheckCertConstraint_NilVsEmptySliceSemantically(t *testing.T) {
	// Verify nil and empty slice behave identically for constraints
	errNil := checkCertConstraint("org", nil, []string{"Val"})
	errEmpty := checkCertConstraint("org", []string{}, []string{"Val"})

	// Both should fail
	assert.Error(t, errNil)
	assert.Error(t, errEmpty)

	// And for values
	errNilVal := checkCertConstraint("org", []string{"C"}, nil)
	errEmptyVal := checkCertConstraint("org", []string{"C"}, []string{})

	// Both should fail (constraint requires "C" but cert has nothing)
	assert.Error(t, errNilVal)
	assert.Error(t, errEmptyVal)
}

// ===========================================================================
// FINDING 4 (HIGH): checkCertConstraint allows subset matches in a
// security-sensitive direction.
//
// If constraints=["A"] and values=["A", "B"], the function correctly
// rejects because "B" is unexpected. Good.
//
// But if constraints=["A", "B"] and values=["A"], it also correctly
// rejects because "B" is unmet. Good.
//
// However, the duplicate constraint collapse (Finding 1) means that
// constraints=["A", "A"] and values=["A"] silently passes. This is the
// vector.
// ===========================================================================

func TestAdversarial_CheckCertConstraint_SubsetChecksCorrect(t *testing.T) {
	// Constraints require more values than cert has -- should fail
	err := checkCertConstraint("org", []string{"A", "B"}, []string{"A"})
	assert.Error(t, err, "should fail when cert is missing required constraint value")

	// Cert has more values than constraints allow -- should fail
	err = checkCertConstraint("org", []string{"A"}, []string{"A", "B"})
	assert.Error(t, err, "should fail when cert has unexpected extra value")

	// Exact match -- should pass
	err = checkCertConstraint("org", []string{"A", "B"}, []string{"A", "B"})
	assert.NoError(t, err, "exact match should pass")

	err = checkCertConstraint("org", []string{"A", "B"}, []string{"B", "A"})
	assert.NoError(t, err, "order should not matter")
}

// ===========================================================================
// FINDING 5 (HIGH) — FIXED (#5746): checkCertConstraintGlob with an EMPTY
// constraint now fails closed instead of defaulting to "allow all". A policy
// author who forgets/empties CommonName must set the explicit AllowAllConstraint
// ("*") to allow any value. This test previously pinned the dangerous fail-open
// default (assert.NoError); it now documents the fail-closed fix (assert.Error).
// See failclosed_constraints_test.go TestRed_F5.
// ===========================================================================

func TestAdversarial_CheckCertConstraintGlob_EmptyConstraintAllowsAnything(t *testing.T) {
	// Empty constraint now fails closed -- a forgotten CommonName no longer
	// silently accepts an attacker-controlled CN; the author must opt in with "*".
	err := checkCertConstraintGlob("common name", "", "evil-cn.attacker.com")
	assert.Error(t, err,
		"FIXED (#5746): an empty CommonName constraint fails closed; "+
			"require the explicit '*' (AllowAllConstraint) to allow any value.")
}

func TestAdversarial_CheckCertConstraintGlob_EmptyValueWithConstraint(t *testing.T) {
	// Non-empty constraint with empty value -- should fail
	err := checkCertConstraintGlob("common name", "expected.com", "")
	assert.Error(t, err, "non-empty constraint should not match empty value")
}

func TestAdversarial_CheckCertConstraintGlob_DoubleStarAllowsAll(t *testing.T) {
	// "**" is NOT caught by the AllowAllConstraint check (which is "*" exactly),
	// so it goes through the glob compilation path. "**" in gobwas/glob matches
	// everything (including path separators), so it's effectively another
	// way to spell AllowAllConstraint.
	err := checkCertConstraintGlob("common name", "**", "literally-anything")
	assert.NoError(t, err,
		"'**' pattern matches everything, acting as an undocumented AllowAllConstraint")
}

func TestAdversarial_CheckCertConstraintGlob_NonStarGlobCharsNotSupported(t *testing.T) {
	// FIXED (#5746, F2): checkCertConstraintGlob now triggers glob mode on ANY
	// glob metacharacter (globMetaChars = "*?{["), not only "*". So patterns
	// using "?", "[...]", or "{...}" WITHOUT any "*" are glob-matched, not
	// treated as literal strings.

	// "?" matches any single character in glob semantics.
	err := checkCertConstraintGlob("common name", "?.example.com", "a.example.com")
	assert.NoError(t, err,
		"FIXED (#5746, F2): '?' triggers glob mode; '?.example.com' matches 'a.example.com'.")

	// Character classes are honored.
	err = checkCertConstraintGlob("common name", "[abc].example.com", "a.example.com")
	assert.NoError(t, err,
		"FIXED (#5746, F2): '[abc]' character class glob-matches 'a.example.com'.")

	// Alternation is honored.
	err = checkCertConstraintGlob("common name", "{foo,bar}.example.com", "foo.example.com")
	assert.NoError(t, err,
		"FIXED (#5746, F2): '{foo,bar}' alternation glob-matches 'foo.example.com'.")

	// Combining non-star globs with * also works (glob mode either way).
	err = checkCertConstraintGlob("common name", "{foo,bar}*", "foo")
	assert.NoError(t, err,
		"A '*' also activates glob mode, making other glob chars work")
}

// ===========================================================================
// FINDING 6 (MEDIUM): checkTrustBundles with AllowAllConstraint and empty
// trustBundles always fails. This is correct (fail-closed), but it means
// a policy with Roots=["*"] is useless without trust bundles.
// ===========================================================================

func TestAdversarial_CheckTrustBundles_WildcardWithEmptyBundles(t *testing.T) {
	cc := CertConstraint{
		Roots: []string{AllowAllConstraint},
	}

	// With empty trust bundles, the wildcard loop has nothing to iterate.
	// No bundle matches, so it falls through to the error.
	// We need a real X509Verifier to test this.
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "leaf", []string{"TestOrg"}, nil, nil)

	verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	err = cc.checkTrustBundles(verifier, map[string]TrustBundle{})
	assert.Error(t, err,
		"Roots=[*] with empty trust bundles should fail (no roots to match against)")
}

func TestAdversarial_CheckTrustBundles_NilBundles(t *testing.T) {
	cc := CertConstraint{
		Roots: []string{AllowAllConstraint},
	}

	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "leaf", []string{"TestOrg"}, nil, nil)

	verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	err = cc.checkTrustBundles(verifier, nil)
	assert.Error(t, err,
		"Roots=[*] with nil trust bundles should fail (no roots to match against)")
}

// ===========================================================================
// FINDING 7 (HIGH): compareArtifacts only checks one direction.
//
// Materials from the consuming step are checked against artifacts from the
// producing step. But artifacts from the producing step that do NOT appear
// as materials in the consuming step are silently ignored (only logged).
//
// This means an attacker who compromises a build step can inject arbitrary
// extra files into the output that no downstream step validates.
// ===========================================================================

func TestAdversarial_CompareArtifacts_InjectedArtifactsIgnored(t *testing.T) {
	sha256 := cryptoutil.DigestValue{Hash: crypto.SHA256}

	// Consuming step expects file.txt
	materials := map[string]cryptoutil.DigestSet{
		"file.txt": {sha256: "legitimate_hash"},
	}

	// Producing step has file.txt (matching) PLUS a malicious backdoor
	artifacts := map[string]cryptoutil.DigestSet{
		"file.txt":    {sha256: "legitimate_hash"},
		"backdoor.sh": {sha256: "evil_hash"},
	}

	// DEFAULT (warn-only, backward-compatible): compareArtifacts still passes —
	// the injected backdoor.sh is logged, not rejected. Existing policies that
	// under-declare materials must keep verifying.
	err := compareArtifacts(materials, artifacts)
	assert.NoError(t, err,
		"DEFAULT: compareArtifacts logs (does not reject) extra producing-step artifacts for backward compat")

	// STRICT (F7, opt-in via WithRequireAllArtifacts): the unconsumed
	// backdoor.sh is detected and would fail the artifactsFrom edge closed.
	// extraArtifacts is the exact predicate the strict path keys off.
	extra := extraArtifacts(materials, artifacts)
	assert.Equal(t, []string{"backdoor.sh"}, extra,
		"STRICT (F7): the injected backdoor.sh must be flagged as an unconsumed artifact and fail closed under strict mode")
}

func TestAdversarial_CompareArtifacts_EmptyMaterialsIgnoresEverything(t *testing.T) {
	sha256 := cryptoutil.DigestValue{Hash: crypto.SHA256}

	// Consuming step has no materials (empty)
	materials := map[string]cryptoutil.DigestSet{}

	// Producing step has tons of artifacts
	artifacts := map[string]cryptoutil.DigestSet{
		"backdoor.sh":  {sha256: "evil1"},
		"rootkit.so":   {sha256: "evil2"},
		"keylogger.py": {sha256: "evil3"},
	}

	// DEFAULT (warn-only): empty materials still pass — preserved for backward
	// compatibility (a leaf-less empty set is already rejected upstream in
	// verifyCollectionArtifacts; an authoritative empty set is a valid "consumed
	// nothing" claim).
	err := compareArtifacts(materials, artifacts)
	assert.NoError(t, err,
		"DEFAULT: empty materials pass artifacts through (logged only)")

	// STRICT (F7, opt-in): with empty materials, EVERY producing-step artifact
	// is unconsumed, so strict mode flags all of them and fails closed.
	extra := extraArtifacts(materials, artifacts)
	assert.ElementsMatch(t, []string{"backdoor.sh", "rootkit.so", "keylogger.py"}, extra,
		"STRICT (F7): every unconsumed artifact must be flagged when materials are empty")
}

// ===========================================================================
// FINDING 8 (MEDIUM): Functionary.Validate with empty PublicKeyID falls
// through to X509 verification. If the verifier is not an X509Verifier,
// the error message says "not a public key verifier or a x509 verifier"
// but the actual issue is that PublicKeyID didn't match (it was empty).
// ===========================================================================

func TestAdversarial_FunctionaryValidate_EmptyPublicKeyID(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)

	// Functionary with empty PublicKeyID -- the check at line 168
	// "f.PublicKeyID != "" && f.PublicKeyID == verifierID" is false because
	// f.PublicKeyID is "". Falls through to X509 check.
	f := Functionary{PublicKeyID: ""}
	err = f.Validate(verifier, nil)
	assert.Error(t, err,
		"Empty PublicKeyID should not match any verifier")
	// The error message is misleading -- it says "not a public key verifier
	// or x509 verifier" when the real issue is the empty PublicKeyID.
}

func TestAdversarial_FunctionaryValidate_EmptyPublicKeyIDWithX509(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "leaf", []string{"TestOrg"}, nil, nil)

	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	// Functionary with empty PublicKeyID but X509 verifier -- falls through
	// to CertConstraint.Roots check, which fails because Roots is empty.
	f := Functionary{PublicKeyID: ""}
	err = f.Validate(x509Verifier, nil)
	assert.Error(t, err,
		"Empty PublicKeyID + empty CertConstraint.Roots should fail")
	assert.Contains(t, err.Error(), "no trusted roots",
		"Should fail on missing roots, not on key ID mismatch")
}

// ===========================================================================
// FINDING 9 (HIGH): Step.validateAttestations with empty Attestations list
// and a valid collection silently passes. A step with no required
// attestations is effectively a no-op -- any collection passes.
//
// This means a policy step that forgets to specify required attestations
// will accept any collection without checking anything.
// ===========================================================================

func TestAdversarial_ValidateAttestations_EmptyAttestationsPassesAnything(t *testing.T) {
	s := Step{
		Name:         "build",
		Attestations: []Attestation{}, // No required attestations!
	}

	// A collection with no errors passes through
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{Name: "build"},
		},
	}

	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	// FIXED (#5746, F9): a step with no required attestations is a misconfigured
	// no-op gate and now fails CLOSED — the collection is rejected, not passed.
	assert.Empty(t, result.Passed,
		"FIXED (#5746, F9): a step with no required attestations rejects (fail closed) "+
			"instead of rubber-stamping any collection.")
	assert.Len(t, result.Rejected, 1,
		"the no-requirements collection is rejected with a fail-closed reason")
}

// ===========================================================================
// FINDING 10 (MEDIUM) — FIXED (#5746): validateAttestations now requires EXACT
// step-name equality. An empty collection name no longer acts as a wildcard —
// only a collection explicitly named for the step is considered (fail closed).
// This test previously pinned the empty-name-matches-any bypass (Passed len 1);
// it now documents the fix (no passed collections for a name-less collection).
// ===========================================================================

func TestAdversarial_ValidateAttestations_EmptyCollectionNameMatchesAnyStep(t *testing.T) {
	attType := "https://example.com/att/v1"
	s := Step{
		Name: "build",
		Attestations: []Attestation{
			{Type: attType},
		},
	}

	// Collection with empty name -- should it match "build" step?
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: attestation.Collection{
				Name: "", // Empty name!
				Attestations: []attestation.CollectionAttestation{
					{
						Type:        attType,
						Attestation: &dummyAttestor{name: "test", typeStr: attType},
					},
				},
			},
		},
	}

	result := s.validateAttestations([]source.CollectionVerificationResult{cvr}, "", nil)
	// FIXED (#5746, F10): the empty-name collection does NOT match the "build"
	// step (exact name equality required), so it is skipped — not passed.
	assert.Empty(t, result.Passed,
		"FIXED (#5746, F10): a collection with an empty name no longer matches every "+
			"step; only an exact step-name match is considered (fail closed).")
}

// ===========================================================================
// FINDING 11 (MEDIUM) — FIXED (#5746): checkCertConstraint single-empty-string
// normalization now applies at ALL positions, not just index 0.
//
// constraints=["", "real"] now normalizes the empty string away (it carries no
// SAN identity), so it means "require real" — the cert is NOT forced to present
// a literal empty value. The second assertion previously pinned the buggy
// behavior (assert.Error, "must have an empty value"); it now documents the
// fail-closed-but-correct normalization (assert.NoError). See
// failclosed_constraints_test.go TestRed_F11.
// ===========================================================================

func TestAdversarial_CheckCertConstraint_EmptyStringInMultipleConstraints(t *testing.T) {
	// constraints=["", "real"] -- the empty string normalizes away at any
	// position, so this means "require real". A cert presenting "real" passes.
	err := checkCertConstraint("org",
		[]string{"", "real"}, // empty element normalized away -> require "real"
		[]string{"", "real"}, // cert's empty element also normalized away
	)
	assert.NoError(t, err)

	// The cert presenting only "real" (no empty value) now PASSES: the empty
	// constraint element no longer forces the cert to carry an empty value.
	err = checkCertConstraint("org",
		[]string{"", "real"}, // empty element normalized away -> require "real"
		[]string{"real"},     // cert has "real" only
	)
	assert.NoError(t, err,
		"FIXED (#5746): an embedded empty-string constraint normalizes away at any "+
			"position; the cert is not required to present a literal empty value.")
}

// ===========================================================================
// FINDING 12 (HIGH) — FIXED (#5746): Policy.Verify must NOT accumulate duplicate
// passed collections across depth iterations.
//
// Previously the cross-depth merge appended stepResult.Passed each iteration,
// so a collection re-discovered via back-reference expansion (or returned by
// the source on every iteration) was appended once per depth — inflating the
// passing-collection count in trust signals and the step_results UI. The merge
// now de-duplicates by content key (mergePassedCollections / passedCollectionKey
// in policy.go), so the same collection seen across N depths yields exactly ONE
// Passed entry. This test was inverted from documenting the bug (a non-asserting
// t.Logf) to ASSERTING the fixed, fail-closed behavior.
// ===========================================================================

func TestAdversarial_Verify_DuplicatePassedAcrossDepthIterations(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	stepName := "build"
	attType := "https://example.com/att/v1"
	// The step declares a required attestation (post-#5746 F9: a step with no
	// required attestations fails closed), so the dedup behavior under test is
	// isolated from the empty-attestations fail-closed path.
	coll := attestation.Collection{
		Name: stepName,
		Attestations: []attestation.CollectionAttestation{{
			Type:        attType,
			Attestation: &marshalableAttestor{AttName: "att", AttType: attType},
		}},
	}

	cvr := source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Collection: coll,
			Statement:  intoto.Statement{PredicateType: attestation.CollectionType},
		},
	}

	// The mock source always returns the same collection regardless of subject digests
	ms := &mockVerifiedSource{results: []source.CollectionVerificationResult{cvr}}

	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps: map[string]Step{
			stepName: {
				Name:         stepName,
				Attestations: []Attestation{{Type: attType}},
				Functionaries: []Functionary{
					{PublicKeyID: keyID},
				},
			},
		},
	}

	// Use searchDepth=3 to trigger multiple iterations
	pass, results, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithSearchDepth(3),
	)
	require.NoError(t, err)
	assert.True(t, pass)

	// Fixed behavior (#5746, F12): the same collection seen across all 3 depth
	// iterations must be de-duplicated to a SINGLE Passed entry, not accumulated
	// once per iteration. (Was a non-asserting t.Logf documenting the bug.)
	assert.Len(t, results[stepName].Passed, 1,
		"step %q must have exactly 1 passed collection; the cross-depth merge must "+
			"de-duplicate the same collection, not accumulate it once per depth iteration", stepName)
}

// ===========================================================================
// FINDING 13 (HIGH) — FIXED (#5746): checkCertConstraint honors the AllowAll
// wildcard ("*") at ANY position in the constraint list, not only index 0. A
// list like ["specific-root", "*"] means "allow any value". This test previously
// pinned the position-0-only bug (assert.Error); it now documents the fix
// (assert.NoError). See hasAllowAll in constraints.go (F13/F18).
// ===========================================================================

func TestAdversarial_CheckCertConstraint_WildcardNotAtIndex0(t *testing.T) {
	// AllowAllConstraint at index 1 now acts as a wildcard (F13/F18).
	err := checkCertConstraint("org",
		[]string{"specific", AllowAllConstraint},
		[]string{"anything"},
	)
	// FIXED (#5746, F13/F18): hasAllowAll scans every position, so a "*" anywhere
	// in the list means "allow any value".
	assert.NoError(t, err,
		"FIXED (#5746, F13/F18): '*' at any position is honored as a wildcard; "+
			"constraints=['specific', '*'] allows all values.")
}

// ===========================================================================
// FINDING 14 (HIGH) — FIXED (#5746): CertConstraint.Check now short-circuits on
// the FIRST failing constraint instead of accumulating every check's error. This
// avoids needless work (the trust-bundle check can be expensive) and stops the
// error fan from enumerating certificate details to callers. This test
// previously pinned the accumulation behavior (errs >= 3); it now documents the
// short-circuit fix (errs <= 1). See failclosed_constraints_test.go TestRed_F14.
// ===========================================================================

func TestAdversarial_CertConstraintCheck_ErrorAccumulation(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf, _ := generateLeafCert(t, ca, caKey, "wrong-cn", []string{"WrongOrg"}, []string{"wrong@email.com"}, []string{"wrong.dns"})

	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)

	trustBundles := map[string]TrustBundle{
		"root1": {Root: ca},
	}

	cc := CertConstraint{
		CommonName:    "expected-cn",
		Organizations: []string{"ExpectedOrg"},
		Emails:        []string{"expected@email.com"},
		DNSNames:      []string{"expected.dns"},
		Roots:         []string{"root1"},
	}

	err = cc.Check(x509Verifier, trustBundles)
	assert.Error(t, err)

	// FIXED: Check short-circuits on the first failing constraint, so exactly one
	// underlying error is surfaced (no cert-detail enumeration via accumulated errs).
	var constraintErr ErrConstraintCheckFailed
	if assert.ErrorAs(t, err, &constraintErr) {
		assert.LessOrEqual(t, len(constraintErr.errs), 1,
			"FIXED (#5746): Check short-circuits on the first failing constraint "+
				"and surfaces a single error, not one per failed check.")
	}
}

// ===========================================================================
// FINDING 15 (MEDIUM): The Verify function's empty-steps check at line 507
// occurs AFTER all the expensive verification work. A policy with no steps
// should be rejected early in Validate(), not after searching/verifying.
//
// While Validate() is called and would succeed (an empty steps map is
// technically valid), the check "if len(resultsByStep) == 0" at line 507
// is a correctness issue: resultsByStep will be empty because the
// stepOrder loop has nothing to iterate.
// ===========================================================================

func TestAdversarial_Verify_EmptyPolicyNoSteps(t *testing.T) {
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(1 * time.Hour)},
		Steps:   map[string]Step{}, // No steps!
	}

	ms := &mockVerifiedSource{}
	pass, _, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
	)
	assert.False(t, pass)
	assert.Error(t, err, "policy with no steps should fail")
	assert.Contains(t, err.Error(), "no steps",
		"Should clearly indicate the policy has no steps")
}

// ===========================================================================
// FINDING 16 (MEDIUM): RESOLVED post-#5766. checkCertConstraintGlob now
// case-folds the CommonName value (via normalizeGlobValue) before
// comparison, so case differences no longer cause spurious mismatches.
// Whitespace is still NOT trimmed (see _WhitespaceInValue below), which is
// intentional: a SAN value carries no leading/trailing whitespace.
// ===========================================================================

func TestAdversarial_CheckCertConstraintGlob_CaseSensitivity(t *testing.T) {
	// Post-#5766 F16: CommonName matching case-folds.
	err := checkCertConstraintGlob("common name", "Example.COM", "example.com")
	assert.NoError(t, err,
		"post-#5766 F16: CommonName matching case-folds, so 'Example.COM' matches "+
			"'example.com'. Legitimate certs are no longer rejected on CN case alone.")
}

func TestAdversarial_CheckCertConstraintGlob_WhitespaceInValue(t *testing.T) {
	// Whitespace in CN value
	err := checkCertConstraintGlob("common name", "example.com", " example.com ")
	assert.Error(t, err,
		"Whitespace in CN value causes mismatch. No trimming is performed.")
}

// ===========================================================================
// FINDING 17 (MEDIUM) — FIXED (#5746): buildStepContext is now FIRST-writer-wins
// for duplicate attestation types across multiple passed collections. A second
// passed collection presenting the same attestation type must NOT overwrite the
// first (legitimate) one in the cross-step Rego context — that was a shadowing
// vector. This test previously pinned last-writer-wins ("second-scan"); it now
// documents the first-writer-wins fix ("first-scan").
// ===========================================================================

func TestAdversarial_BuildStepContext_LastWriterWins(t *testing.T) {
	attType := "https://example.com/scan/v1"

	results := map[string]StepResult{
		"scan": {
			Step: "scan",
			Passed: []PassedCollection{
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "scan",
								Attestations: []attestation.CollectionAttestation{{
									Type: attType,
									Attestation: &marshalableAttestor{
										AttName: "first-scan",
										AttType: attType,
									},
								}},
							},
						},
					},
				},
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "scan",
								Attestations: []attestation.CollectionAttestation{{
									Type: attType,
									Attestation: &marshalableAttestor{
										AttName: "second-scan",
										AttType: attType,
									},
								}},
							},
						},
					},
				},
			},
		},
	}

	ctx := buildStepContext([]string{"scan"}, results)
	require.NotNil(t, ctx)

	scanCtx, ok := ctx["scan"].(map[string]interface{})
	require.True(t, ok)

	attData, ok := scanCtx[attType].(map[string]interface{})
	require.True(t, ok)

	// FIXED (#5746, F17): the FIRST passed collection wins; the second collection
	// with the same attestation type does NOT overwrite it.
	assert.Equal(t, "first-scan", attData["name"],
		"FIXED (#5746, F17): buildStepContext is first-writer-wins. A second signed "+
			"collection for the same step and attestation type can no longer shadow the "+
			"first (legitimate) collection's data in the cross-step Rego context.")
}

// ===========================================================================
// FINDING 18 (MEDIUM) — FIXED (#5746): checkCertConstraint honors the AllowAll
// wildcard ("*") for multi-value fields at ANY position, not only constraints[0].
// A list like ["A", "*"] means "allow any value". This test previously pinned the
// position-0-only bug (assert.Error); it now documents the fix (assert.NoError).
// ===========================================================================

func TestAdversarial_CheckCertConstraint_AllowAllNotFirstElement(t *testing.T) {
	// AllowAllConstraint mixed with other constraints now allows all values.
	err := checkCertConstraint("email",
		[]string{"admin@example.com", AllowAllConstraint},
		[]string{"admin@example.com", "other@example.com"},
	)
	// FIXED (#5746, F13/F18): hasAllowAll honors "*" at any position, so the list
	// ["admin@example.com", "*"] allows any email value.
	assert.NoError(t, err,
		"FIXED (#5746, F13/F18): '*' mixed with other constraints is honored as a "+
			"wildcard at any position, allowing all values.")
}

// ===========================================================================
// FINDING 19 (LOW): checkCertConstraintGlob compiles a new glob on every
// call. No caching. For cert constraint checking this is called once per
// verification so it's not a performance issue, but in a hot loop it could
// be.
// ===========================================================================

// (No test needed -- this is a code quality observation.)

// ===========================================================================
// FINDING 20 (MEDIUM): Policy Verify with clock skew tolerance is
// unidirectional -- it only extends the expiry window forward.
//
// If a policy was set to expire in the future but the verifier's clock is
// ahead, the tolerance helps. But if the verifier's clock is behind, the
// policy appears to not have expired yet and no tolerance is needed.
//
// The concern: a negative clockSkewTolerance could be used to make an
// already-expired policy fail even harder, but there's no validation that
// clockSkewTolerance is non-negative.
// ===========================================================================

func TestAdversarial_Verify_NegativeClockSkewTolerance(t *testing.T) {
	// Policy that expires 5 minutes from now
	p := Policy{
		Expires: metav1.Time{Time: time.Now().Add(5 * time.Minute)},
		Steps: map[string]Step{
			"build": {Name: "build"},
		},
	}

	ms := &mockVerifiedSource{}

	// Negative tolerance SHRINKS the expiry window — left unchecked it would
	// make a non-expired policy (5 min remaining) appear expired.
	_, _, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithClockSkewTolerance(-10*time.Minute), // would expire it 10 min EARLIER
	)
	// FIXED (F20, #5746): checkVerifyOpts now rejects a negative tolerance up
	// front, so Verify fails with an option-validation error rather than
	// silently treating the still-valid policy as expired.
	require.Error(t, err, "F20: negative clock-skew tolerance must be rejected")
	assert.Contains(t, err.Error(), "must be non-negative",
		"F20: negative clockSkewTolerance must be rejected with a non-negative validation error, not silently applied")
	assert.NotContains(t, err.Error(), "expired",
		"F20: a still-valid policy must not be reported as expired due to negative tolerance")
}
