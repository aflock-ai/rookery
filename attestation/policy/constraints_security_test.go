//go:build audit

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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// R3-270: checkCertConstraint exact matching vs glob matching consistency
//
// Post-#5766 (F2), glob patterns are honored consistently: checkCertConstraintGlob
// (CommonName) AND checkCertConstraint (DNSNames, Emails, Organizations, URIs)
// both interpret a constraint containing a glob metacharacter (*, ?, {, [) as a
// glob. A policy author who writes "*.example.com" as a DNS constraint now gets
// glob semantics on every SAN field, resolving the earlier inconsistency.
// ===========================================================================

// TestSecurity_R3_270_ExactVsGlobInconsistency proves that "*.example.com"
// now has the SAME glob semantics on both the single-value CommonName path
// and the multi-value SAN path (post-#5766 F2).
func TestSecurity_R3_270_ExactVsGlobInconsistency(t *testing.T) {
	// CommonName: glob matching - "*.example.com" matches "foo.example.com"
	err := checkCertConstraintGlob("common name", "*.example.com", "foo.example.com")
	require.NoError(t, err, "checkCertConstraintGlob should match *.example.com against foo.example.com via glob")

	// DNSNames: glob matching too (post-#5766) - "*.example.com" matches "foo.example.com"
	err = checkCertConstraint("dns name", []string{"*.example.com"}, []string{"foo.example.com"})
	require.NoError(t, err, "post-#5766 F2: checkCertConstraint honors glob patterns, so "+
		"'*.example.com' matches the DNS SAN 'foo.example.com' via the glob engine. "+
		"The exact-vs-glob inconsistency is resolved.")
}

// TestSecurity_R3_270_GlobEmailConstraintSilentlyFails proves that email
// constraints with glob patterns are now honored (post-#5766 F2).
func TestSecurity_R3_270_GlobEmailConstraintSilentlyFails(t *testing.T) {
	err := checkCertConstraint("email", []string{"*@example.com"}, []string{"alice@example.com"})
	require.NoError(t, err, "post-#5766 F2: email constraint '*@example.com' is matched as a "+
		"glob, so 'alice@example.com' matches via the glob engine.")
}

// TestSecurity_R3_270_GlobOrgConstraintSilentlyFails proves that organization
// constraints with glob patterns are now honored (post-#5766 F2).
func TestSecurity_R3_270_GlobOrgConstraintSilentlyFails(t *testing.T) {
	err := checkCertConstraint("organization", []string{"Acme*"}, []string{"AcmeCorp"})
	require.NoError(t, err, "post-#5766 F2: organization constraint 'Acme*' is matched as a "+
		"glob (case-folded), so 'AcmeCorp' matches via the glob engine.")
}

// ===========================================================================
// R3-270: checkCertConstraintGlob triggers glob mode on ANY glob
// metacharacter (*, ?, {, [), not only "*" (post-#5766). Patterns using
// ?, [...], or {...} without a "*" are now interpreted as globs.
// ===========================================================================

// TestSecurity_R3_270_NonStarGlobCharsAreNotInterpreted proves that
// "?", "[...]", and "{...}" are interpreted as globs even with no "*"
// present (post-#5766: containsGlobMeta covers "*?{[").
func TestSecurity_R3_270_NonStarGlobCharsAreNotInterpreted(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		value      string
	}{
		{
			name:       "question_mark_without_star",
			constraint: "?.example.com",
			value:      "a.example.com",
		},
		{
			name:       "character_class_without_star",
			constraint: "[abc].example.com",
			value:      "a.example.com",
		},
		{
			name:       "alternation_without_star",
			constraint: "{foo,bar}.example.com",
			value:      "foo.example.com",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkCertConstraintGlob("common name", tc.constraint, tc.value)
			require.NoError(t, err, "post-#5766: glob pattern %q is compiled as a glob "+
				"because containsGlobMeta detects any of *?{[ (not only '*'), so "+
				"?, [...], and {...} match as expected.", tc.constraint)
		})
	}
}

// TestSecurity_R3_270_NonStarGlobCharsWorkWithStar proves that adding
// a "*" to the pattern enables glob mode for all glob characters.
func TestSecurity_R3_270_NonStarGlobCharsWorkWithStar(t *testing.T) {
	// Once a "*" is present, the entire pattern is compiled as a glob,
	// so other glob characters work correctly.
	err := checkCertConstraintGlob("common name", "{foo,bar}*", "foo")
	require.NoError(t, err, "adding '*' enables full glob mode, so {foo,bar} works")

	err = checkCertConstraintGlob("common name", "?*.example.com", "ab.example.com")
	require.NoError(t, err, "adding '*' enables full glob mode, so ? works")
}

// ===========================================================================
// R3-270: checkExtensions uses reflect.VisibleFields to iterate over
// the certificate.Extensions struct. If the upstream sigstore/fulcio
// library adds new fields, they are automatically iterated and an empty
// constraint value causes log.Debugf + continue, meaning the new field
// is auto-allowed without the policy author explicitly opting in.
// ===========================================================================

// TestSecurity_R3_270_ExtensionsEmptyConstraintAllowsAllValues proves
// that empty constraint fields in Extensions are auto-allowed.
func TestSecurity_R3_270_ExtensionsEmptyConstraintAllowsAllValues(t *testing.T) {
	// CertConstraint with all extension fields empty. Every extension
	// field will be skipped via the constraintField.String() == "" check,
	// meaning any extension value on the certificate is allowed.
	cc := CertConstraint{
		// Extensions: all zero values (empty strings)
	}

	// We can't easily test this without a real cert with Fulcio extensions,
	// but we can verify the behavior of checkExtensions with an empty
	// pkix.Extension list (which parses to empty Extensions, all matching).
	err := cc.checkExtensions([]pkix.Extension{})
	require.NoError(t, err, "empty constraints on extensions means all values are "+
		"auto-allowed. If the upstream sigstore/fulcio library adds new fields, "+
		"they will also be auto-allowed without explicit policy author opt-in.")
}

// ===========================================================================
// R3-270: checkTrustBundles "allow all" logic
//
// When Roots is ["*"], checkTrustBundles iterates ALL bundles to find a
// match. This is intentional, but the concern is that Roots=["*"] with
// all empty constraint fields (CN, Org, Email, DNS, URI) creates a
// completely open CertConstraint that matches any certificate from any
// trusted root.
// ===========================================================================

func helperCreateCAAndLeaf(t *testing.T, caCN string, leafCN string, leafOrgs []string) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: caCN},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leafPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   leafCN,
			Organization: leafOrgs,
		},
		NotBefore:   time.Now().Add(-1 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafPriv.PublicKey, caPriv)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return caCert, leafCert, leafPriv
}

// TestSecurity_R3_270_AllowAllRootsWithEmptyFieldsMatchesAnyCert proves
// that an EMPTY CommonName now fails closed (post-#5766 F5): a CertConstraint
// that forgets to set CommonName no longer silently accepts any cert.
func TestSecurity_R3_270_AllowAllRootsWithEmptyFieldsMatchesAnyCert(t *testing.T) {
	caCert, leafCert, _ := helperCreateCAAndLeaf(t, "EvilCA", "evil-attacker.com", nil)

	x509Verifier, err := cryptoutil.NewX509Verifier(leafCert, nil, []*x509.Certificate{caCert}, time.Now())
	require.NoError(t, err)

	trustBundles := map[string]TrustBundle{
		"evil-root": {Root: caCert},
	}

	// CertConstraint where ALL fields are empty/default, and Roots is ["*"].
	cc := CertConstraint{
		CommonName:    "",                           // Empty CommonName now FAILS CLOSED (F5)
		Organizations: nil,                          // nil = allow (since cert also has none)
		Emails:        nil,                          // nil = allow
		DNSNames:      nil,                          // nil = allow
		URIs:          nil,                          // nil = allow
		Roots:         []string{AllowAllConstraint}, // Match any root
	}

	err = cc.Check(x509Verifier, trustBundles)
	require.Error(t, err, "post-#5766 F5: an empty CommonName constraint fails closed, so a "+
		"CertConstraint that forgets to set CommonName no longer accepts ANY cert. The author "+
		"must opt in to 'allow any' explicitly with '*'. Zero-identity-assurance config is rejected.")
}

// TestSecurity_R3_270_AllowAllRootsWithEmptyBundlesFailsClosed proves
// that Roots=["*"] with an empty trust bundles map correctly fails.
func TestSecurity_R3_270_AllowAllRootsWithEmptyBundlesFailsClosed(t *testing.T) {
	caCert, leafCert, _ := helperCreateCAAndLeaf(t, "TestCA", "leaf", nil)

	x509Verifier, err := cryptoutil.NewX509Verifier(leafCert, nil, []*x509.Certificate{caCert}, time.Now())
	require.NoError(t, err)

	cc := CertConstraint{
		Roots: []string{AllowAllConstraint},
	}

	err = cc.checkTrustBundles(x509Verifier, map[string]TrustBundle{})
	require.Error(t, err, "Roots=[*] with empty trust bundles should fail-closed (correct)")
}

// TestSecurity_R3_270_AllowAllRootsWithNilBundlesFailsClosed proves
// that Roots=["*"] with nil trust bundles correctly fails.
func TestSecurity_R3_270_AllowAllRootsWithNilBundlesFailsClosed(t *testing.T) {
	caCert, leafCert, _ := helperCreateCAAndLeaf(t, "TestCA", "leaf", nil)

	x509Verifier, err := cryptoutil.NewX509Verifier(leafCert, nil, []*x509.Certificate{caCert}, time.Now())
	require.NoError(t, err)

	cc := CertConstraint{
		Roots: []string{AllowAllConstraint},
	}

	err = cc.checkTrustBundles(x509Verifier, nil)
	require.Error(t, err, "Roots=[*] with nil trust bundles should fail-closed (correct)")
}

// ===========================================================================
// R3-270: Case sensitivity in constraint matching (post-#5766 F16)
//
// The single-value CommonName path (checkCertConstraintGlob) is now
// case-INsensitive: both its glob and exact branches case-fold via
// normalizeGlobValue, because the CommonName identity field is
// case-insensitive per RFC. The multi-value EXACT phase of checkCertConstraint
// deliberately stays BYTE-EXACT (case-sensitive) to preserve existing
// multi-value policy behavior; only its glob branch case-folds.
// ===========================================================================

// TestSecurity_R3_270_CaseSensitiveGlobMatching proves that
// checkCertConstraintGlob now case-folds (post-#5766 F16).
func TestSecurity_R3_270_CaseSensitiveGlobMatching(t *testing.T) {
	err := checkCertConstraintGlob("common name", "Example.COM", "example.com")
	require.NoError(t, err, "post-#5766 F16: CommonName matching case-folds, so a constraint "+
		"of 'Example.COM' accepts a cert with CN='example.com'. Legitimate certs are no "+
		"longer rejected on CN case alone.")
}

// TestSecurity_R3_270_CaseSensitiveExactMatching proves that
// checkCertConstraint's multi-value EXACT phase stays case-sensitive
// (byte-exact) by design — F16 case-folding applies only to the
// single-value CommonName path and the multi-value glob branch.
func TestSecurity_R3_270_CaseSensitiveExactMatching(t *testing.T) {
	err := checkCertConstraint("organization", []string{"ACME Corp"}, []string{"acme corp"})
	require.Error(t, err, "the multi-value exact phase stays byte-exact (no case-fold) to "+
		"preserve existing policy behavior. A constraint of 'ACME Corp' rejects a cert with "+
		"Org='acme corp'.")
}

// TestSecurity_R3_270_CaseSensitiveGlobWildcardStillCaseSensitive proves
// that glob patterns with wildcards on the CommonName path now case-fold
// (post-#5766 F16).
func TestSecurity_R3_270_CaseSensitiveGlobWildcardStillCaseSensitive(t *testing.T) {
	err := checkCertConstraintGlob("common name", "*.EXAMPLE.com", "foo.example.com")
	require.NoError(t, err, "post-#5766 F16: CommonName glob matching case-folds, so "+
		"'*.EXAMPLE.com' matches 'foo.example.com'")
}

// ===========================================================================
// R3-270: checkCertConstraint preserves duplicate-constraint counts
// (post-#5766 F1). Duplicates are no longer collapsed via a set; the
// exact phase uses a count map, so a multiset constraint is enforced.
// ===========================================================================

// TestSecurity_R3_270_DuplicateConstraintsSilentlyDedup proves that
// duplicate constraints are NO LONGER silently collapsed (post-#5766 F1).
func TestSecurity_R3_270_DuplicateConstraintsSilentlyDedup(t *testing.T) {
	// Policy author specifies ["ACME", "ACME"] - the count map requires TWO
	// matching cert values. A cert with only one "ACME" no longer passes.
	err := checkCertConstraint("org", []string{"ACME", "ACME"}, []string{"ACME"})
	require.Error(t, err, "post-#5766 F1: duplicate constraints are count-preserving. "+
		"constraints=['ACME','ACME'] requires two 'ACME' values and FAILS with values=['ACME']. "+
		"A multiset constraint is now enforceable.")
}

// TestSecurity_R3_270_DuplicateConstraintsDifferentCounts demonstrates
// the count-based semantics with mixed duplicates (post-#5766 F1).
func TestSecurity_R3_270_DuplicateConstraintsDifferentCounts(t *testing.T) {
	// constraints=["A", "A", "B"] requires 2x"A" + 1x"B".
	// Cert values=["A", "B"] provides only one "A", so it FAILS.
	err := checkCertConstraint("org", []string{"A", "A", "B"}, []string{"A", "B"})
	require.Error(t, err, "post-#5766 F1: constraints=['A','A','B'] requires two 'A's and one "+
		"'B'; values=['A','B'] is missing one 'A', so it fails. The extra 'A' is NOT dropped.")
}

// ===========================================================================
// R3-270: checkCertConstraint with duplicate values in the cert now
// matches correctly against count-preserving constraints (post-#5766 F1).
// ===========================================================================

// TestSecurity_R3_270_DuplicateCertValuesRejected proves that duplicate
// values in a certificate now match a duplicate-count constraint
// (post-#5766 F1: the count map consumes one value per constraint entry).
func TestSecurity_R3_270_DuplicateCertValuesRejected(t *testing.T) {
	// Cert has ["A", "A"] and constraint is ["A", "A"] (count map {A:2}).
	// Each cert "A" is consumed by one constraint entry; the constraint is met.
	err := checkCertConstraint("org", []string{"A", "A"}, []string{"A", "A"})
	require.NoError(t, err, "post-#5766 F1: duplicate cert values match a count-preserving "+
		"constraint. constraints=['A','A'] (count {A:2}) matches values=['A','A'] (2 values).")
}

// ===========================================================================
// R3-270: AllowAllConstraint ("*") in multi-value fields is now honored at
// ANY position, not only as the sole element at index 0 (post-#5766 F13/F18).
// ===========================================================================

// TestSecurity_R3_270_AllowAllConstraintOnlyWorksAlone proves that "*"
// mixed with other constraints is now honored as AllowAllConstraint
// (post-#5766 F13/F18: hasAllowAll scans every position).
func TestSecurity_R3_270_AllowAllConstraintOnlyWorksAlone(t *testing.T) {
	err := checkCertConstraint("org",
		[]string{"specific", AllowAllConstraint},
		[]string{"anything"},
	)
	require.NoError(t, err, "post-#5766 F13/F18: '*' at any position is honored as "+
		"AllowAllConstraint. constraints=['specific','*'] allows any value, so 'anything' passes.")
}

// TestSecurity_R3_270_AllowAllConstraintAloneWorks proves the intended use.
func TestSecurity_R3_270_AllowAllConstraintAloneWorks(t *testing.T) {
	err := checkCertConstraint("org", []string{AllowAllConstraint}, []string{"anything"})
	require.NoError(t, err, "single '*' constraint should match any values")
}

// ===========================================================================
// R3-270: checkCertConstraintGlob empty constraint now fails closed
// (post-#5766 F5); the author must opt in to "allow any" with "*".
// ===========================================================================

// TestSecurity_R3_270_EmptyGlobConstraintAllowsAnything proves that an
// empty CommonName constraint now fails closed (post-#5766 F5).
func TestSecurity_R3_270_EmptyGlobConstraintAllowsAnything(t *testing.T) {
	err := checkCertConstraintGlob("common name", "", "evil-cn.attacker.com")
	require.Error(t, err, "post-#5766 F5: an empty constraint fails closed. A policy author "+
		"who forgets to set CommonName gets a rejection, not silent 'allow all'; '*' is "+
		"required to allow any value.")
}

// TestSecurity_R3_270_AllowAllConstraintInGlob proves that the explicit
// AllowAllConstraint "*" in checkCertConstraintGlob also allows everything.
func TestSecurity_R3_270_AllowAllConstraintInGlob(t *testing.T) {
	err := checkCertConstraintGlob("common name", AllowAllConstraint, "anything.com")
	require.NoError(t, err, "explicit '*' constraint should allow any CN")
}

// TestSecurity_R3_270_DoubleStarActsAsUndocumentedWildcard proves that
// "**" also matches everything, acting as an undocumented AllowAllConstraint.
func TestSecurity_R3_270_DoubleStarActsAsUndocumentedWildcard(t *testing.T) {
	err := checkCertConstraintGlob("common name", "**", "literally-anything")
	require.NoError(t, err, "SECURITY FINDING: '**' pattern matches everything "+
		"via gobwas/glob, acting as an undocumented AllowAllConstraint bypass")
}

// ===========================================================================
// R3-270: checkCertConstraint drops empty-string elements at ALL positions
// (post-#5766 F11), not only in a single-element slice.
// ===========================================================================

// TestSecurity_R3_270_EmptyStringNormalizationOnlySingleElement proves
// that empty-string elements are dropped at every position (post-#5766 F11:
// dropEmpty normalizes both constraint and value lists).
func TestSecurity_R3_270_EmptyStringNormalizationOnlySingleElement(t *testing.T) {
	// Single element [""] is normalized to []
	err := checkCertConstraint("org", []string{""}, []string{})
	require.NoError(t, err, "single empty string constraint is normalized to empty")

	// ["", "real"] now drops the "" too, leaving ["real"] which matches ["real"]
	err = checkCertConstraint("org", []string{"", "real"}, []string{"real"})
	require.NoError(t, err, "post-#5766 F11: a multi-element constraint with '' has the empty "+
		"string dropped at any position, so constraints=['','real'] reduces to ['real'] and "+
		"matches values=['real']. The cert need not present a literal empty organization entry.")
}

// ===========================================================================
// R3-270: CertConstraint.Check now short-circuits on the FIRST failing
// constraint (post-#5766 F14), surfacing exactly one error instead of
// accumulating a fan of errors that leaked certificate field values.
// ===========================================================================

// TestSecurity_R3_270_ErrorAccumulationLeaksCertDetails proves that
// CertConstraint.Check stops at the first failing constraint and returns a
// single wrapped error (post-#5766 F14), rather than accumulating all checks.
func TestSecurity_R3_270_ErrorAccumulationLeaksCertDetails(t *testing.T) {
	caCert, leafCert, _ := helperCreateCAAndLeaf(t, "TestCA", "wrong-cn", []string{"WrongOrg"})

	x509Verifier, err := cryptoutil.NewX509Verifier(leafCert, nil, []*x509.Certificate{caCert}, time.Now())
	require.NoError(t, err)

	trustBundles := map[string]TrustBundle{
		"root1": {Root: caCert},
	}

	cc := CertConstraint{
		CommonName:    "expected-cn",
		Organizations: []string{"ExpectedOrg"},
		Roots:         []string{"root1"},
	}

	err = cc.Check(x509Verifier, trustBundles)
	require.Error(t, err, "should fail on mismatched CN and Org")

	var constraintErr ErrConstraintCheckFailed
	require.ErrorAs(t, err, &constraintErr, "should be ErrConstraintCheckFailed")
	require.Len(t, constraintErr.errs, 1,
		"post-#5766 F14: Check short-circuits on the first failing constraint (CN), so exactly "+
			"one error is surfaced instead of a fan that leaked both CN='wrong-cn' and Org='WrongOrg'.")
}

// ===========================================================================
// R3-270: Whitespace in constraint or value is not trimmed.
// ===========================================================================

// TestSecurity_R3_270_WhitespaceNotTrimmed proves that leading/trailing
// whitespace in constraint values causes mismatches.
func TestSecurity_R3_270_WhitespaceNotTrimmed(t *testing.T) {
	err := checkCertConstraintGlob("common name", "example.com", " example.com ")
	require.Error(t, err, "whitespace in CN value causes mismatch; no trimming is performed")

	err = checkCertConstraint("org", []string{"ACME"}, []string{" ACME "})
	require.Error(t, err, "whitespace in org value causes mismatch; no trimming is performed")
}
