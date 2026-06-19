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
//
// ============================================================================
// Fail-closed acceptance tests for RequiredPolicyOIDs (certificatePolicies,
// OID 2.5.29.32) enforcement on CertConstraint.
//
// These assert the CORRECT, fail-closed behavior and run in the DEFAULT suite
// (no build tag) so the CI/merge-queue gate enforces them. Synthetic certs are
// built with x509.CreateCertificate carrying a Policies extension — no hardware.
//
//   (a) cert carries the required OID + constraint requires it      -> PASS
//   (b) cert MISSING a required OID                                  -> FAIL closed
//   (c) cert has EXTRA OIDs beyond the required set (subset match)   -> PASS
//   (d) empty RequiredPolicyOIDs                                     -> NO-OP PASS
//   (e) multiple required OIDs, cert has only some                   -> FAIL closed
// ============================================================================

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Platform-shaped example OIDs. The first mimics a "hardware-backed AAL3
// release-approval" policy OID under the sigstore/Fulcio private arc
// (1.3.6.1.4.1.57264). The exact values are arbitrary for the test — only their
// presence/absence on the cert matters.
const (
	oidAAL3ReleaseApproval = "1.3.6.1.4.1.57264.1.99"
	oidHardwareBacked      = "1.3.6.1.4.1.57264.1.100"
	oidUnrelated           = "1.3.6.1.4.1.57264.1.7"
)

// generateLeafCertWithPolicyOIDs creates a leaf cert signed by the given CA that
// carries the supplied certificatePolicies OIDs (dotted-decimal). It mirrors
// generateLeafCert but populates the Policies extension.
func generateLeafCertWithPolicyOIDs(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, policyOIDs []string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	oids := make([]x509.OID, 0, len(policyOIDs))
	for _, s := range policyOIDs {
		oid, err := x509.ParseOID(s)
		require.NoError(t, err, "test OID %q must parse", s)
		oids = append(oids, oid)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Policies:     oids,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca, &priv.PublicKey, caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}

// newVerifierForLeaf wraps a leaf cert in an X509Verifier chained to ca, the way
// the policy engine receives it at verification time.
func newVerifierForLeaf(t *testing.T, leaf, ca *x509.Certificate) *cryptoutil.X509Verifier {
	t.Helper()
	v, err := cryptoutil.NewX509Verifier(leaf, nil, []*x509.Certificate{ca}, time.Now())
	require.NoError(t, err)
	return v
}

// (a) cert carries the required OID + a constraint requiring it -> PASS.
func TestRequiredPolicyOIDs_Present_Passes(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver", []string{oidAAL3ReleaseApproval})

	cc := CertConstraint{
		CommonName:         AllowAllConstraint,
		Roots:              []string{"root1"},
		RequiredPolicyOIDs: []string{oidAAL3ReleaseApproval},
	}
	err := cc.Check(newVerifierForLeaf(t, leaf, ca), map[string]TrustBundle{"root1": {Root: ca}})
	assert.NoError(t, err, "cert carrying the required policy OID must pass")
}

// Direct-pass form so the assertion targets checkPolicyOIDs alone, independent of
// the trust-bundle/SAN checks (defense against a future Check() reordering).
func TestRequiredPolicyOIDs_Present_DirectPass(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver", []string{oidAAL3ReleaseApproval})

	cc := CertConstraint{RequiredPolicyOIDs: []string{oidAAL3ReleaseApproval}}
	assert.NoError(t, cc.checkPolicyOIDs(leaf))
}

// (b) cert MISSING a required OID -> fail closed.
func TestRequiredPolicyOIDs_Missing_FailsClosed(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	// Cert carries only an UNRELATED policy OID, not the required one.
	leaf := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver", []string{oidUnrelated})

	cc := CertConstraint{
		CommonName:         AllowAllConstraint,
		Roots:              []string{"root1"},
		RequiredPolicyOIDs: []string{oidAAL3ReleaseApproval},
	}
	err := cc.Check(newVerifierForLeaf(t, leaf, ca), map[string]TrustBundle{"root1": {Root: ca}})
	require.Error(t, err, "cert missing the required policy OID must fail closed")
	assert.ErrorAs(t, err, &ErrConstraintCheckFailed{})
}

// A cert carrying NO policy OIDs at all must also fail closed when one is required.
func TestRequiredPolicyOIDs_NoneOnCert_FailsClosed(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver", nil)

	cc := CertConstraint{RequiredPolicyOIDs: []string{oidAAL3ReleaseApproval}}
	err := cc.checkPolicyOIDs(leaf)
	assert.Error(t, err, "a cert with no certificatePolicies must fail a non-empty RequiredPolicyOIDs")
}

// (c) cert with EXTRA OIDs beyond the required set -> PASS (subset match).
func TestRequiredPolicyOIDs_ExtraOIDs_SubsetPasses(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	// Cert carries the required OID PLUS two extra ones.
	leaf := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver",
		[]string{oidAAL3ReleaseApproval, oidHardwareBacked, oidUnrelated})

	cc := CertConstraint{
		CommonName:         AllowAllConstraint,
		Roots:              []string{"root1"},
		RequiredPolicyOIDs: []string{oidAAL3ReleaseApproval},
	}
	err := cc.Check(newVerifierForLeaf(t, leaf, ca), map[string]TrustBundle{"root1": {Root: ca}})
	assert.NoError(t, err, "extra policy OIDs beyond the required set must still pass (subset match)")
}

// (d) empty RequiredPolicyOIDs -> NO-OP pass (backward compatible).
func TestRequiredPolicyOIDs_Empty_NoOp(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})

	// Even a cert with NO policy OIDs at all must pass when the field is unset —
	// existing policies that never set RequiredPolicyOIDs must be unaffected.
	leaf := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver", nil)

	for _, tc := range []struct {
		name  string
		field []string
	}{
		{"nil", nil},
		{"emptySlice", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc := CertConstraint{
				CommonName:         AllowAllConstraint,
				Roots:              []string{"root1"},
				RequiredPolicyOIDs: tc.field,
			}
			err := cc.Check(newVerifierForLeaf(t, leaf, ca), map[string]TrustBundle{"root1": {Root: ca}})
			assert.NoError(t, err, "empty RequiredPolicyOIDs must be a no-op (backward compatible)")
			// And the unit-level pass is a clean no-op too.
			assert.NoError(t, cc.checkPolicyOIDs(leaf))
		})
	}
}

// (e) multiple required OIDs, cert has only SOME -> fail closed.
func TestRequiredPolicyOIDs_PartialMatch_FailsClosed(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	// Cert carries only the FIRST of two required OIDs.
	leaf := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver", []string{oidAAL3ReleaseApproval})

	cc := CertConstraint{
		CommonName:         AllowAllConstraint,
		Roots:              []string{"root1"},
		RequiredPolicyOIDs: []string{oidAAL3ReleaseApproval, oidHardwareBacked},
	}
	err := cc.Check(newVerifierForLeaf(t, leaf, ca), map[string]TrustBundle{"root1": {Root: ca}})
	require.Error(t, err, "a cert satisfying only some required OIDs must fail closed")

	// And when ALL required OIDs are present, it passes (the positive control for
	// the multi-OID path).
	leafAll := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver",
		[]string{oidAAL3ReleaseApproval, oidHardwareBacked})
	err = cc.Check(newVerifierForLeaf(t, leafAll, ca), map[string]TrustBundle{"root1": {Root: ca}})
	assert.NoError(t, err, "a cert carrying ALL required OIDs must pass")
}

// An unparseable / malformed required OID in the policy must fail closed rather
// than silently treating it as "not present" or "matched".
func TestRequiredPolicyOIDs_MalformedConstraint_FailsClosed(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver", []string{oidAAL3ReleaseApproval})

	for _, bad := range []string{"not-an-oid", "1.2.x.4", "", "  "} {
		cc := CertConstraint{RequiredPolicyOIDs: []string{bad}}
		assert.Error(t, cc.checkPolicyOIDs(leaf),
			"malformed required OID %q must fail closed", bad)
	}
}

// A required OID with surrounding whitespace must still match a cert that carries
// the canonical OID (normalization through the OID parser).
func TestRequiredPolicyOIDs_WhitespaceNormalized(t *testing.T) {
	ca, caKey, _ := generateSelfSignedCert(t, "TestCA", []string{"TestOrg"})
	leaf := generateLeafCertWithPolicyOIDs(t, ca, caKey, "approver", []string{oidAAL3ReleaseApproval})

	cc := CertConstraint{RequiredPolicyOIDs: []string{"  " + oidAAL3ReleaseApproval + "  "}}
	assert.NoError(t, cc.checkPolicyOIDs(leaf),
		"a required OID with surrounding whitespace must normalize and match")
}
