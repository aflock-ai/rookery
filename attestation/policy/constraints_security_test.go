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
// R3-270: checkCertConstraint exact matching vs glob matching inconsistency
//
// checkCertConstraintGlob (used for CommonName) supports glob patterns
// when the constraint contains "*", but checkCertConstraint (used for
// DNSNames, Emails, Organizations, URIs) uses only exact string matching.
// A policy author who writes "*.example.com" as a DNS constraint expects
// glob semantics but gets literal string matching instead.
// ===========================================================================

// TestSecurity_R3_270_ExactVsGlobInconsistency proves that the same
// pattern "*.example.com" has different semantics depending on which
// function evaluates it. CommonName gets glob matching; DNSNames does not.
func TestSecurity_R3_270_ExactVsGlobInconsistency(t *testing.T) {
	// CommonName: glob matching - "*.example.com" matches "foo.example.com"
	err := checkCertConstraintGlob("common name", "*.example.com", "foo.example.com")
	require.NoError(t, err, "checkCertConstraintGlob should match *.example.com against foo.example.com via glob")

	// DNSNames: exact matching - "*.example.com" does NOT match "foo.example.com"
	err = checkCertConstraint("dns name", []string{"*.example.com"}, []string{"foo.example.com"})
	require.Error(t, err, "SECURITY FINDING: checkCertConstraint uses exact matching, so "+
		"'*.example.com' requires the literal string '*.example.com' as a DNS SAN. "+
		"A policy author expecting glob semantics will be silently misconfigured.")
}

// TestSecurity_R3_270_GlobEmailConstraintSilentlyFails proves that email
// constraints with glob patterns fail silently because checkCertConstraint
// does not support globs.
func TestSecurity_R3_270_GlobEmailConstraintSilentlyFails(t *testing.T) {
	err := checkCertConstraint("email", []string{"*@example.com"}, []string{"alice@example.com"})
	require.Error(t, err, "SECURITY FINDING: email constraint '*@example.com' is treated as "+
		"literal, not as a glob. 'alice@example.com' does not match the literal '*@example.com'.")
}

// TestSecurity_R3_270_GlobOrgConstraintSilentlyFails proves that organization
// constraints with glob patterns fail silently.
func TestSecurity_R3_270_GlobOrgConstraintSilentlyFails(t *testing.T) {
	err := checkCertConstraint("organization", []string{"Acme*"}, []string{"AcmeCorp"})
	require.Error(t, err, "SECURITY FINDING: organization constraint 'Acme*' is literal, "+
		"not a glob. 'AcmeCorp' does not match the literal string 'Acme*'.")
}

// ===========================================================================
// R3-270: checkCertConstraintGlob only triggers glob mode when "*" is
// present. Other valid glob characters (?, [...], {...}) are treated as
// literal strings, breaking policy author expectations.
// ===========================================================================

// TestSecurity_R3_270_NonStarGlobCharsAreNotInterpreted proves that
// "?", "[...]", and "{...}" are treated as literals when no "*" is present.
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
			require.Error(t, err, "SECURITY FINDING: glob pattern %q without '*' is "+
				"treated as a literal string. The check at strings.Contains(constraint, "+
				"\"*\") only triggers glob compilation for '*'. Policy authors using "+
				"?, [...], or {...} will get unexpected exact-match behavior.", tc.constraint)
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
// that Roots=["*"] combined with empty CN/Org/Email/DNS/URI fields
// creates a CertConstraint that accepts any certificate from any root.
func TestSecurity_R3_270_AllowAllRootsWithEmptyFieldsMatchesAnyCert(t *testing.T) {
	caCert, leafCert, _ := helperCreateCAAndLeaf(t, "EvilCA", "evil-attacker.com", nil)

	x509Verifier, err := cryptoutil.NewX509Verifier(leafCert, nil, []*x509.Certificate{caCert}, time.Now())
	require.NoError(t, err)

	trustBundles := map[string]TrustBundle{
		"evil-root": {Root: caCert},
	}

	// CertConstraint where ALL fields are empty/default, and Roots is ["*"].
	cc := CertConstraint{
		CommonName:    "",                           // Empty = allow any CN
		Organizations: nil,                          // nil = allow (since cert also has none)
		Emails:        nil,                          // nil = allow
		DNSNames:      nil,                          // nil = allow
		URIs:          nil,                          // nil = allow
		Roots:         []string{AllowAllConstraint}, // Match any root
	}

	err = cc.Check(x509Verifier, trustBundles)
	require.NoError(t, err, "SECURITY FINDING: CertConstraint with all empty fields and "+
		"Roots=[\"*\"] matches ANY certificate from ANY trusted root. The certificate "+
		"CN='evil-attacker.com' passed all checks. A functionary configured this way "+
		"provides zero identity assurance.")
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
// R3-270: Case sensitivity in constraint matching
//
// Both checkCertConstraint and checkCertConstraintGlob are case-sensitive.
// Certificate CNs, Orgs, emails, etc. are compared as-is with no
// normalization. This means a policy that specifies "Example.COM" will
// not match a cert with "example.com" as its CN.
// ===========================================================================

// TestSecurity_R3_270_CaseSensitiveGlobMatching proves that
// checkCertConstraintGlob is case-sensitive.
func TestSecurity_R3_270_CaseSensitiveGlobMatching(t *testing.T) {
	err := checkCertConstraintGlob("common name", "Example.COM", "example.com")
	require.Error(t, err, "SECURITY FINDING: glob matching is case-sensitive. "+
		"A constraint of 'Example.COM' will reject a cert with CN='example.com'. "+
		"This could cause legitimate certificates to be rejected.")
}

// TestSecurity_R3_270_CaseSensitiveExactMatching proves that
// checkCertConstraint is case-sensitive for multi-value fields.
func TestSecurity_R3_270_CaseSensitiveExactMatching(t *testing.T) {
	err := checkCertConstraint("organization", []string{"ACME Corp"}, []string{"acme corp"})
	require.Error(t, err, "SECURITY FINDING: exact matching is case-sensitive. "+
		"A constraint of 'ACME Corp' will reject a cert with Org='acme corp'.")
}

// TestSecurity_R3_270_CaseSensitiveGlobWildcardStillCaseSensitive proves
// that even glob patterns with wildcards are case-sensitive.
func TestSecurity_R3_270_CaseSensitiveGlobWildcardStillCaseSensitive(t *testing.T) {
	err := checkCertConstraintGlob("common name", "*.EXAMPLE.com", "foo.example.com")
	require.Error(t, err, "glob wildcard matching is case-sensitive: "+
		"'*.EXAMPLE.com' does not match 'foo.example.com'")
}

// ===========================================================================
// R3-270: checkCertConstraint duplicate constraint values are silently
// deduplicated via map, weakening the constraint set.
// ===========================================================================

// TestSecurity_R3_270_DuplicateConstraintsSilentlyDedup proves that
// duplicate constraints in the input are silently collapsed.
func TestSecurity_R3_270_DuplicateConstraintsSilentlyDedup(t *testing.T) {
	// Policy author specifies ["ACME", "ACME"] - map deduplicates to one entry.
	// A cert with only one "ACME" passes even though the author listed it twice.
	err := checkCertConstraint("org", []string{"ACME", "ACME"}, []string{"ACME"})
	require.NoError(t, err, "SECURITY FINDING: duplicate constraints are silently "+
		"deduplicated via map. constraints=['ACME','ACME'] passes with values=['ACME']. "+
		"A multiset constraint cannot be expressed.")
}

// TestSecurity_R3_270_DuplicateConstraintsDifferentCounts demonstrates
// the dedup with mixed duplicates.
func TestSecurity_R3_270_DuplicateConstraintsDifferentCounts(t *testing.T) {
	// constraints=["A", "A", "B"] deduplicates to map{A:{}, B:{}}.
	// Cert values=["A", "B"] matches the deduplicated map.
	err := checkCertConstraint("org", []string{"A", "A", "B"}, []string{"A", "B"})
	require.NoError(t, err, "SECURITY FINDING: constraints=['A','A','B'] passes "+
		"with values=['A','B']. The extra 'A' is silently dropped during map dedup.")
}

// ===========================================================================
// R3-270: checkCertConstraint with duplicate values in the cert
// interacts badly with map-based dedup.
// ===========================================================================

// TestSecurity_R3_270_DuplicateCertValuesRejected proves that duplicate
// values in a certificate cause rejection when the constraint map has
// already consumed the single matching entry.
func TestSecurity_R3_270_DuplicateCertValuesRejected(t *testing.T) {
	// Cert has ["A", "A"] but constraint is ["A", "A"] (deduped to {A:{}}).
	// First cert "A" matches and deletes. Second cert "A" has no match.
	err := checkCertConstraint("org", []string{"A", "A"}, []string{"A", "A"})
	require.Error(t, err, "SECURITY FINDING: duplicate cert values interact badly "+
		"with map-based constraint dedup. constraints=['A','A'] (deduped to 1 entry) "+
		"cannot match values=['A','A'] (2 values). The second 'A' is 'unexpected'.")
}

// ===========================================================================
// R3-270: AllowAllConstraint ("*") in multi-value fields only works when
// it is the sole element at index 0.
// ===========================================================================

// TestSecurity_R3_270_AllowAllConstraintOnlyWorksAlone proves that "*"
// mixed with other constraints is treated as a literal string, not a wildcard.
func TestSecurity_R3_270_AllowAllConstraintOnlyWorksAlone(t *testing.T) {
	err := checkCertConstraint("org",
		[]string{"specific", AllowAllConstraint},
		[]string{"anything"},
	)
	require.Error(t, err, "SECURITY FINDING: '*' at non-zero index or in a multi-element "+
		"slice is treated as a literal string, not as AllowAllConstraint. "+
		"constraints=['specific','*'] requires the cert to have values 'specific' and '*'.")
}

// TestSecurity_R3_270_AllowAllConstraintAloneWorks proves the intended use.
func TestSecurity_R3_270_AllowAllConstraintAloneWorks(t *testing.T) {
	err := checkCertConstraint("org", []string{AllowAllConstraint}, []string{"anything"})
	require.NoError(t, err, "single '*' constraint should match any values")
}

// ===========================================================================
// R3-270: checkCertConstraintGlob empty constraint allows everything.
// ===========================================================================

// TestSecurity_R3_270_EmptyGlobConstraintAllowsAnything proves that an
// empty CommonName constraint is treated as "allow any value".
func TestSecurity_R3_270_EmptyGlobConstraintAllowsAnything(t *testing.T) {
	err := checkCertConstraintGlob("common name", "", "evil-cn.attacker.com")
	require.NoError(t, err, "SECURITY FINDING: empty constraint means 'allow all'. "+
		"A policy author who forgets to set CommonName gets no CN enforcement.")
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
// R3-270: checkCertConstraint single-empty-string normalization only
// applies when constraints has exactly one element.
// ===========================================================================

// TestSecurity_R3_270_EmptyStringNormalizationOnlySingleElement proves
// that the empty-string normalization at line 181-183 only fires for
// single-element slices.
func TestSecurity_R3_270_EmptyStringNormalizationOnlySingleElement(t *testing.T) {
	// Single element [""] is normalized to []
	err := checkCertConstraint("org", []string{""}, []string{})
	require.NoError(t, err, "single empty string constraint is normalized to empty")

	// But ["", "real"] is NOT normalized - the empty string stays
	err = checkCertConstraint("org", []string{"", "real"}, []string{"real"})
	require.Error(t, err, "SECURITY FINDING: multi-element constraint with '' is "+
		"not normalized. The empty string is treated as a required value, so the "+
		"cert must literally have an empty organization entry to match.")
}

// ===========================================================================
// R3-270: CertConstraint.Check error accumulation leaks certificate
// details through error messages.
// ===========================================================================

// TestSecurity_R3_270_ErrorAccumulationLeaksCertDetails proves that
// CertConstraint.Check runs ALL checks even if early ones fail,
// and the accumulated errors reveal certificate field values.
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
	require.GreaterOrEqual(t, len(constraintErr.errs), 2,
		"SECURITY FINDING: all constraint checks run and accumulate. "+
			"Error messages contain cert CN='wrong-cn' and Org='WrongOrg', "+
			"leaking certificate details to callers.")
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
