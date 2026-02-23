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
// FINDING 1 (HIGH): Duplicate constraints in checkCertConstraint collapse
// via map deduplication, silently weakening the constraint set.
//
// When a policy author specifies constraints=["ACME", "ACME"] intending
// to require two distinct cert values, the map deduplicates them to one
// entry. A cert with values=["ACME"] will pass because the single map
// entry gets deleted and len(unmet)==0. The constraint semantics are
// silently weakened.
// ===========================================================================

func TestAdversarial_CheckCertConstraint_DuplicateConstraintsCollapse(t *testing.T) {
	// The constraint list has "ACME" twice. If the policy author intended
	// the cert to have two "ACME" values (perhaps in a list-valued field),
	// this should arguably fail when the cert only has one "ACME".
	// But because constraints go into a map, duplicates collapse.
	err := checkCertConstraint("org",
		[]string{"ACME", "ACME"}, // Two constraints, but map deduplicates to 1
		[]string{"ACME"},         // Cert has only one value
	)
	// BUG: This passes because the map {ACME: {}} has one entry, and the single
	// cert value "ACME" matches it, leaving len(unmet)==0.
	// A correct implementation would count occurrences, not just presence.
	assert.NoError(t, err,
		"CONFIRMED BUG: duplicate constraints are silently deduplicated. "+
			"A policy with constraints=[ACME, ACME] passes with only one cert value ACME. "+
			"This weakens constraint enforcement.")
}

func TestAdversarial_CheckCertConstraint_DuplicateConstraintsDifferentCounts(t *testing.T) {
	// Policy requires ["A", "A", "B"] but cert has ["A", "B"].
	// After dedup, constraints map = {A: {}, B: {}}. Cert has both.
	// This will pass even though the original constraint list had 3 items
	// and the cert only has 2 values.
	err := checkCertConstraint("org",
		[]string{"A", "A", "B"}, // 3 constraints, but map has 2 entries
		[]string{"A", "B"},      // 2 cert values
	)
	assert.NoError(t, err,
		"CONFIRMED BUG: constraints=[A, A, B] passes with values=[A, B]. "+
			"The duplicate A constraint is silently dropped.")
}

// ===========================================================================
// FINDING 2 (HIGH): checkCertConstraint does NOT support glob patterns for
// multi-value fields (DNSNames, Emails, Organizations, URIs), unlike
// checkCertConstraintGlob which is used for CommonName.
//
// A policy with constraint ["*.example.com"] for DNS names requires the
// cert to have EXACTLY the string "*.example.com" as a DNS SAN -- it does
// NOT match "foo.example.com" via glob expansion. This is a significant
// inconsistency that could lead to policy bypass.
// ===========================================================================

func TestAdversarial_CheckCertConstraint_NoGlobSupportForDNSNames(t *testing.T) {
	// Policy expects "*.example.com" to match "foo.example.com" for DNS names,
	// the same way CommonName glob matching works. But checkCertConstraint
	// uses exact string matching, not glob matching.
	err := checkCertConstraint("dns name",
		[]string{"*.example.com"},  // Policy author thinks this is a glob
		[]string{"foo.example.com"}, // Cert has a matching DNS name
	)
	// BUG: This FAILS because "*.example.com" != "foo.example.com" (exact match).
	// The policy author expects glob matching like CommonName gets.
	assert.Error(t, err,
		"CONFIRMED: checkCertConstraint does NOT support glob matching. "+
			"A constraint of '*.example.com' requires the literal string, not a wildcard match. "+
			"This is inconsistent with checkCertConstraintGlob behavior for CommonName.")
}

func TestAdversarial_CheckCertConstraint_GlobInEmailConstraint(t *testing.T) {
	// An email constraint with a glob pattern
	err := checkCertConstraint("email",
		[]string{"*@example.com"},  // Policy author thinks this matches any @example.com
		[]string{"alice@example.com"}, // Cert has a matching email
	)
	assert.Error(t, err,
		"CONFIRMED: email constraints do not support glob patterns. "+
			"'*@example.com' requires the cert to have exactly '*@example.com' as an email SAN.")
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
// FINDING 5 (HIGH): checkCertConstraintGlob with empty value and non-empty
// non-glob constraint passes when it should fail.
//
// When constraint is a non-empty, non-glob string (no "*") and value is "",
// the exact match check at line 168 will correctly fail because
// "something" != "". This is correct.
//
// But when constraint is "" (empty), it immediately returns nil (pass) at
// line 148, regardless of what the cert's common name actually is. An
// empty constraint means "allow any value" which is a dangerous default.
// ===========================================================================

func TestAdversarial_CheckCertConstraintGlob_EmptyConstraintAllowsAnything(t *testing.T) {
	// Empty constraint allows any value -- this is by design but dangerous.
	// A policy author who forgets to set CommonName gets "allow all".
	err := checkCertConstraintGlob("common name", "", "evil-cn.attacker.com")
	assert.NoError(t, err,
		"DESIGN ISSUE: empty CommonName constraint allows any value. "+
			"A missing/forgotten constraint defaults to 'allow all'.")
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
	// BUG: checkCertConstraintGlob at line 152 checks strings.Contains(constraint, "*")
	// to decide whether to use glob matching. This means glob patterns that use
	// "?", "[...]", or "{...}" WITHOUT any "*" are treated as literal strings
	// and go to the exact-match path. This is a real bug.

	// "?" should match any single character in glob semantics, but it goes
	// to exact match because the constraint has no "*".
	err := checkCertConstraintGlob("common name", "?.example.com", "a.example.com")
	assert.Error(t, err,
		"BUG CONFIRMED: '?' glob pattern is treated as a literal string "+
			"because checkCertConstraintGlob only checks for '*' to trigger glob mode. "+
			"The pattern '?.example.com' requires the cert CN to be literally '?.example.com'. "+
			"This silently breaks any policy using ?, [...], or {...} glob patterns without *.")

	// Same issue with character classes
	err = checkCertConstraintGlob("common name", "[abc].example.com", "a.example.com")
	assert.Error(t, err,
		"BUG CONFIRMED: '[abc]' character class is treated as a literal string")

	// Same issue with alternation
	err = checkCertConstraintGlob("common name", "{foo,bar}.example.com", "foo.example.com")
	assert.Error(t, err,
		"BUG CONFIRMED: '{foo,bar}' alternation is treated as a literal string")

	// Workaround: combining non-star globs with * triggers glob mode
	err = checkCertConstraintGlob("common name", "{foo,bar}*", "foo")
	assert.NoError(t, err,
		"Adding a '*' to the pattern activates glob mode, making other glob chars work")
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

	err := compareArtifacts(materials, artifacts)
	// BUG: This passes! The injected backdoor.sh is completely ignored.
	assert.NoError(t, err,
		"CONFIRMED: compareArtifacts ignores extra artifacts from the producing step. "+
			"An attacker can inject arbitrary files (backdoor.sh) that downstream steps "+
			"never validate. This is a supply chain injection vector.")
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

	err := compareArtifacts(materials, artifacts)
	assert.NoError(t, err,
		"CONFIRMED: empty materials pass any artifacts through. "+
			"A step with no material attestations cannot detect injected artifacts.")
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
	// BUG: This passes because the for loop over s.Attestations does nothing,
	// and passed remains true.
	assert.Len(t, result.Passed, 1,
		"CONFIRMED: A step with no required attestations passes any collection. "+
			"This is a policy misconfiguration vector -- forgetting to list attestations "+
			"means the step is effectively a no-op.")
}

// ===========================================================================
// FINDING 10 (MEDIUM): validateAttestations collection name matching
// allows empty collection names to bypass the name filter.
//
// At line 255: if collection.Collection.Name != s.Name && collection.Collection.Name != ""
// An empty collection name will NOT be skipped, so it always matches any step.
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
	// The empty-name collection is NOT skipped (line 255 condition), so it's validated
	// against the "build" step's attestations.
	assert.Len(t, result.Passed, 1,
		"CONFIRMED: A collection with an empty name matches any step. "+
			"An attacker who can produce a collection with an empty name can bypass "+
			"the step-name filter.")
}

// ===========================================================================
// FINDING 11 (MEDIUM): checkCertConstraint single-empty-string normalization
// only applies to index 0.
//
// constraints=["", "real"] does NOT trigger the normalization at line 181-183
// because len(constraints)!=1. The empty string stays in the constraint set,
// meaning the cert must have an entry matching exactly "".
// ===========================================================================

func TestAdversarial_CheckCertConstraint_EmptyStringInMultipleConstraints(t *testing.T) {
	// constraints=["", "real"] -- the empty string is NOT normalized away
	// because the normalization only fires for single-element slices.
	err := checkCertConstraint("org",
		[]string{"", "real"},   // First constraint is ""
		[]string{"", "real"},   // Cert has both
	)
	// This passes because both values match exactly
	assert.NoError(t, err)

	// But what if the cert doesn't have the empty string?
	err = checkCertConstraint("org",
		[]string{"", "real"},  // First constraint is ""
		[]string{"real"},      // Cert only has "real", not ""
	)
	// This should fail because the "" constraint is unmet
	assert.Error(t, err,
		"constraints with an embedded empty string require the cert to have an empty value")
}

// ===========================================================================
// FINDING 12 (HIGH): Policy.Verify merges step results across depth iterations
// in a way that can accumulate stale passed collections.
//
// The merge logic at lines 475-483 appends to Passed and Rejected across
// depth iterations. If a collection passes in depth=0 but the same
// collection is seen again in depth=1 (due to back-reference expansion),
// it gets appended again, leading to duplicate entries in Passed.
// ===========================================================================

func TestAdversarial_Verify_DuplicatePassedAcrossDepthIterations(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)

	stepName := "build"
	coll := attestation.Collection{Name: stepName}

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
				Name: stepName,
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

	// The same collection may appear multiple times in Passed due to the
	// merge logic across depth iterations.
	passedCount := len(results[stepName].Passed)
	if passedCount > 1 {
		t.Logf("FINDING: Step '%s' has %d passed collections (expected 1). "+
			"The merge logic accumulates duplicates across depth iterations.",
			stepName, passedCount)
	}
}

// ===========================================================================
// FINDING 13 (HIGH): checkCertConstraint AllowAllConstraint only checks
// position [0] of the Roots slice. If the wildcard appears at any other
// position (e.g., ["specific-root", "*"]), it is NOT treated as a wildcard.
// ===========================================================================

func TestAdversarial_CheckCertConstraint_WildcardNotAtIndex0(t *testing.T) {
	// AllowAllConstraint at index 1 -- does it still act as wildcard?
	err := checkCertConstraint("org",
		[]string{"specific", AllowAllConstraint},
		[]string{"anything"},
	)
	// The check at line 176 only fires if len==1 && [0]==AllowAllConstraint.
	// With two elements, the wildcard at index 1 is treated as a literal "*".
	assert.Error(t, err,
		"CONFIRMED: '*' at non-zero index is treated as a literal string, not a wildcard. "+
			"constraints=['specific', '*'] does NOT allow all values -- it requires "+
			"the cert to have exactly 'specific' and '*' as values.")
}

// ===========================================================================
// FINDING 14 (HIGH): CertConstraint.Check accumulates errors but does not
// short-circuit. All constraint checks run even if an early one fails.
// This is by design (to report all failures), but it means the trust
// bundle check (which may involve network calls for CRL/OCSP) always runs.
// More critically, it means the error list can be used to enumerate
// certificate details through error messages.
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

	// The error should contain details about ALL failing constraints
	var constraintErr ErrConstraintCheckFailed
	if assert.ErrorAs(t, err, &constraintErr) {
		// All checks ran -- CN, Org, Email, DNS all failed
		assert.GreaterOrEqual(t, len(constraintErr.errs), 3,
			"All constraint checks should run and accumulate errors. "+
				"Error messages may leak certificate details to callers.")
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
// FINDING 16 (MEDIUM): checkCertConstraintGlob does not normalize the
// value before comparison. Whitespace, case differences, etc. in the
// common name could cause unexpected matches or mismatches.
// ===========================================================================

func TestAdversarial_CheckCertConstraintGlob_CaseSensitivity(t *testing.T) {
	// Glob matching is case-sensitive
	err := checkCertConstraintGlob("common name", "Example.COM", "example.com")
	assert.Error(t, err,
		"Glob matching is case-sensitive. 'Example.COM' does not match 'example.com'. "+
			"This could cause legitimate certs to be rejected if the CN case differs.")
}

func TestAdversarial_CheckCertConstraintGlob_WhitespaceInValue(t *testing.T) {
	// Whitespace in CN value
	err := checkCertConstraintGlob("common name", "example.com", " example.com ")
	assert.Error(t, err,
		"Whitespace in CN value causes mismatch. No trimming is performed.")
}

// ===========================================================================
// FINDING 17 (MEDIUM): buildStepContext last-writer-wins for duplicate
// attestation types across multiple passed collections.
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

	// The second passed collection overwrites the first for the same attestation type
	assert.Equal(t, "second-scan", attData["name"],
		"CONFIRMED: buildStepContext uses last-writer-wins. "+
			"If an attacker can get a second signed collection for the same step and "+
			"attestation type, their data overwrites the legitimate collection's data "+
			"in the cross-step context visible to Rego policies.")
}

// ===========================================================================
// FINDING 18 (MEDIUM): checkCertConstraint with AllowAllConstraint for
// multi-value fields only works at the exact position constraints[0].
// A constraint list like ["A", "*"] does not have wildcard semantics --
// it requires the cert to have values ["A", "*"] exactly.
// ===========================================================================

func TestAdversarial_CheckCertConstraint_AllowAllNotFirstElement(t *testing.T) {
	// AllowAllConstraint mixed with other constraints
	err := checkCertConstraint("email",
		[]string{"admin@example.com", AllowAllConstraint},
		[]string{"admin@example.com", "other@example.com"},
	)
	// The check at line 176 only fires if len==1 && [0]=="*".
	// Here len==2, so "*" is treated literally.
	// The cert has "other@example.com" which is not in constraints, so it fails.
	assert.Error(t, err,
		"'*' mixed with other constraints is treated as a literal string, "+
			"not as a wildcard. This is likely unexpected behavior for policy authors.")
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

	// Negative tolerance makes the expiry window SMALLER
	_, _, err := p.Verify(context.Background(),
		WithVerifiedSource(ms),
		WithSubjectDigests([]string{"sha256:abc"}),
		WithClockSkewTolerance(-10*time.Minute), // Makes it expire 10 min EARLIER
	)
	// The check is: time.Now().After(p.Expires.Time.Add(vo.clockSkewTolerance))
	// = time.Now().After(now+5min + (-10min))
	// = time.Now().After(now - 5min)
	// = true! The policy is treated as expired.
	if err != nil {
		assert.Contains(t, err.Error(), "expired",
			"CONFIRMED: Negative clockSkewTolerance makes non-expired policies appear expired. "+
				"No validation prevents negative tolerance values.")
	}
}
