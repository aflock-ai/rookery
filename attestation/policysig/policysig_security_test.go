//go:build audit

package policysig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
)

// ==========================================================================
// Test helpers — standalone, no testify dependency
// ==========================================================================

func secGenRSAKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return priv, &priv.PublicKey
}

func secCreateKeyPair(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	priv, pub := secGenRSAKey(t)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(pub, crypto.SHA256)
	return signer, verifier
}

func secCreateCert(t *testing.T, signerKey interface{}, pubKey interface{}, tmpl, parent *x509.Certificate) *x509.Certificate {
	t.Helper()
	sn, err := rand.Int(rand.Reader, big.NewInt(4294967295))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	tmpl.SerialNumber = sn
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pubKey, signerKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func secCreateRootCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := secGenRSAKey(t)
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SecurityTest"},
			CommonName:   "Security Test Root CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	cert := secCreateCert(t, priv, pub, tmpl, tmpl)
	return cert, priv
}

func secCreateIntermediateCA(t *testing.T, parent *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := secGenRSAKey(t)
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"SecurityTest"},
			CommonName:   "Security Test Intermediate CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	cert := secCreateCert(t, parentKey, pub, tmpl, parent)
	return cert, priv
}

type secLeafOpts struct {
	cn           string
	orgs         []string
	dnsNames     []string
	emails       []string
	uris         []*url.URL
}

func secCreateLeafCert(t *testing.T, parent *x509.Certificate, parentKey *rsa.PrivateKey, opts secLeafOpts) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := secGenRSAKey(t)
	cn := opts.cn
	if cn == "" {
		cn = "Security Test Leaf"
	}
	orgs := opts.orgs
	if orgs == nil {
		orgs = []string{"SecurityTest"}
	}
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: orgs,
			CommonName:   cn,
		},
		DNSNames:              opts.dnsNames,
		EmailAddresses:        opts.emails,
		URIs:                  opts.uris,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert := secCreateCert(t, parentKey, pub, tmpl, parent)
	return cert, priv
}

func secSignEnvelope(t *testing.T, signer cryptoutil.Signer) dsse.Envelope {
	t.Helper()
	env, err := dsse.Sign("application/vnd.test+json", bytes.NewReader([]byte(`{"test":"payload"}`)), dsse.SignWithSigners(signer))
	if err != nil {
		t.Fatalf("sign envelope: %v", err)
	}
	return env
}

func secSignEnvelopeX509(t *testing.T, leafKey *rsa.PrivateKey, leaf *x509.Certificate, inter *x509.Certificate, root *x509.Certificate) dsse.Envelope {
	t.Helper()
	signer, err := cryptoutil.NewSigner(leafKey,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
		cryptoutil.SignWithRoots([]*x509.Certificate{root}),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return secSignEnvelope(t, signer)
}

// ==========================================================================
// R3-260: Empty signature list / no-verifier bypass
//
// Verify that an envelope with zero signatures is always rejected, and that
// providing zero verifiers also results in rejection. This exercises the
// boundary where VerifyPolicySignature could vacuously pass.
// ==========================================================================

func TestSecurity_R3_260_EmptySignatureListRejected(t *testing.T) {
	_, verifier := secCreateKeyPair(t)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)

	// Envelope with no signatures at all.
	env := dsse.Envelope{
		Payload:     []byte("some payload"),
		PayloadType: "test/type",
		Signatures:  []dsse.Signature{},
	}

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected error for envelope with empty signature list, got nil")
	}
	if !strings.Contains(err.Error(), "could not verify policy") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSecurity_R3_260_NilSignatureSliceRejected(t *testing.T) {
	_, verifier := secCreateKeyPair(t)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)

	// Envelope with nil signature slice.
	env := dsse.Envelope{
		Payload:     []byte("payload"),
		PayloadType: "test/type",
		Signatures:  nil,
	}

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected error for envelope with nil signatures, got nil")
	}
}

func TestSecurity_R3_260_ZeroVerifiersRejectsValidEnvelope(t *testing.T) {
	signer, _ := secCreateKeyPair(t)
	env := secSignEnvelope(t, signer)

	// Options with no verifiers at all — the DSSE layer should reject.
	vo := NewVerifyPolicySignatureOptions()

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected error when no verifiers supplied, got nil")
	}
}

// ==========================================================================
// R3-261: Failed DSSE verifiers still checked against constraints
//
// BUG: VerifyPolicySignature iterates ALL CheckedVerifiers returned by
// Envelope.Verify, including those with Error != nil (failed DSSE signature
// verification). It calls Functionary.Validate on each without checking
// the Error field. A CheckedVerifier that failed signature verification
// can still pass Functionary.Validate if its Verifier matches the
// constraint (e.g., matching KeyID for key-based verifiers).
//
// Attack scenario: An attacker adds a second, invalid signature to the
// envelope. The DSSE threshold is met by the legitimate signature. But
// the attacker's verifier (which failed DSSE) is also returned and
// checked against constraints. If the attacker's key matches a trusted
// constraint that the legitimate signer's key does not, the policy passes.
//
// In practice, Envelope.Verify returns all CheckedVerifiers (pass AND fail)
// when threshold is met. The policysig loop should filter out those with
// Error != nil before calling f.Validate.
// ==========================================================================

func TestSecurity_R3_261_FailedDSSEVerifierNotUsedForConstraints(t *testing.T) {
	// Create two key pairs. signerA signs the envelope. signerB does not.
	signerA, _ := secCreateKeyPair(t)
	_, verifierB := secCreateKeyPair(t)

	env := secSignEnvelope(t, signerA)

	// Supply both verifiers. VerifierA will pass DSSE (signature matches),
	// verifierB will fail DSSE. Both are returned in CheckedVerifiers.
	//
	// Critically: we set up the verify options with ONLY verifierB as the
	// "trusted" verifier. If the code incorrectly checks failed verifiers
	// against constraints, verifierB would pass Functionary.Validate
	// (key type, matching KeyID) despite never having produced a valid signature.
	//
	// The correct behavior: this should FAIL because signerA's key doesn't
	// match verifierB's KeyID constraint.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifierB}),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("BUG: envelope signed by keyA passed verification with only keyB trusted; " +
			"this indicates failed DSSE verifiers are being used for constraint checks")
	}
}

// ==========================================================================
// R3-262: Wildcard constraint bypass via multi-element slice
//
// The allWildcard() function checks for exactly {"*"} in each slice.
// If a caller sets ["*", "anything"], allWildcard returns false (suppressing
// the warning), but the constraint check in checkCertConstraint handles
// it differently — it does exact set matching, not glob matching.
//
// This test verifies that ["*", "extra"] does NOT match a cert that only
// has ["SecurityTest"] — it should fail because checkCertConstraint
// requires exact bidirectional set equality (not glob matching).
// ==========================================================================

func TestSecurity_R3_262_WildcardInMultiElementSliceNotTreatedAsGlob(t *testing.T) {
	root, rootKey := secCreateRootCA(t)
	inter, interKey := secCreateIntermediateCA(t, root, rootKey)
	leaf, leafKey := secCreateLeafCert(t, inter, interKey, secLeafOpts{
		cn:   "Leaf",
		orgs: []string{"MyOrg"},
	})

	env := secSignEnvelopeX509(t, leafKey, leaf, inter, root)

	// Set organizations to ["*", "ExtraOrg"]. This suppresses the wildcard
	// warning but should still fail because checkCertConstraint does exact
	// set matching: it expects the cert to have BOTH "*" and "ExtraOrg".
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyCertConstraints(
			"*",                      // CN wildcard - passes
			[]string{"*"},            // DNS - passes
			[]string{"*"},            // emails - passes
			[]string{"*", "ExtraOrg"}, // orgs - should fail: cert has ["MyOrg"] not ["*","ExtraOrg"]
			[]string{"*"},            // URIs - passes
		),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected failure: multi-element org constraint ['*','ExtraOrg'] should not match cert with org ['MyOrg']")
	}
}

// ==========================================================================
// R3-263: Cert constraint CN mismatch rejects policy signature
//
// When using X509 verification, the CN constraint must actually be checked
// against the leaf certificate's CN. This confirms that a mismatched CN
// causes VerifyPolicySignature to fail.
// ==========================================================================

func TestSecurity_R3_263_CertConstraintCNMismatchRejects(t *testing.T) {
	root, rootKey := secCreateRootCA(t)
	inter, interKey := secCreateIntermediateCA(t, root, rootKey)
	leaf, leafKey := secCreateLeafCert(t, inter, interKey, secLeafOpts{
		cn: "Actual Leaf CN",
	})

	env := secSignEnvelopeX509(t, leafKey, leaf, inter, root)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyCertConstraints(
			"Wrong CN",    // does not match "Actual Leaf CN"
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
		),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected rejection for CN mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "no policy verifiers passed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestSecurity_R3_263_CertConstraintCNMatchPasses(t *testing.T) {
	root, rootKey := secCreateRootCA(t)
	inter, interKey := secCreateIntermediateCA(t, root, rootKey)
	leaf, leafKey := secCreateLeafCert(t, inter, interKey, secLeafOpts{
		cn: "Expected CN",
	})

	env := secSignEnvelopeX509(t, leafKey, leaf, inter, root)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyCertConstraints(
			"Expected CN",
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
		),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err != nil {
		t.Fatalf("expected success for matching CN, got: %v", err)
	}
}

// ==========================================================================
// R3-264: Cert organization constraint enforcement
//
// Verify that organization constraints are properly checked and that
// a certificate with a different organization is rejected.
// ==========================================================================

func TestSecurity_R3_264_CertOrgConstraintMismatchRejects(t *testing.T) {
	root, rootKey := secCreateRootCA(t)
	inter, interKey := secCreateIntermediateCA(t, root, rootKey)
	leaf, leafKey := secCreateLeafCert(t, inter, interKey, secLeafOpts{
		cn:   "Leaf",
		orgs: []string{"ActualOrg"},
	})

	env := secSignEnvelopeX509(t, leafKey, leaf, inter, root)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyCertConstraints(
			"*",
			[]string{"*"},
			[]string{"*"},
			[]string{"WrongOrg"}, // does not match "ActualOrg"
			[]string{"*"},
		),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected rejection for org mismatch")
	}
}

func TestSecurity_R3_264_CertOrgConstraintMatchPasses(t *testing.T) {
	root, rootKey := secCreateRootCA(t)
	inter, interKey := secCreateIntermediateCA(t, root, rootKey)
	leaf, leafKey := secCreateLeafCert(t, inter, interKey, secLeafOpts{
		cn:   "Leaf",
		orgs: []string{"CorrectOrg"},
	})

	env := secSignEnvelopeX509(t, leafKey, leaf, inter, root)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyCertConstraints(
			"*",
			[]string{"*"},
			[]string{"*"},
			[]string{"CorrectOrg"},
			[]string{"*"},
		),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err != nil {
		t.Fatalf("expected success with matching org, got: %v", err)
	}
}

// ==========================================================================
// R3-265: Key-based verifier ignores all certificate constraints
//
// By design, when the DSSE verifier is an RSAVerifier (not X509Verifier),
// the policysig code creates a "key" type Functionary with PublicKeyID.
// The Functionary.Validate method returns success solely on KeyID match,
// completely ignoring any CertConstraint fields. This test confirms that
// behavior and documents it as a security-relevant design choice.
// ==========================================================================

func TestSecurity_R3_265_KeyVerifierIgnoresCertConstraints(t *testing.T) {
	signer, verifier := secCreateKeyPair(t)
	env := secSignEnvelope(t, signer)

	// Set very restrictive cert constraints — they should be irrelevant
	// for key-based verification.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
		VerifyWithPolicyCertConstraints(
			"very-specific-cn",
			[]string{"specific.dns.example.com"},
			[]string{"specific@example.com"},
			[]string{"VerySpecificOrg"},
			[]string{"https://specific.example.com"},
		),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err != nil {
		t.Fatalf("key verifier should pass regardless of cert constraints, got: %v", err)
	}
}

// ==========================================================================
// R3-266: Tampered payload with valid signatures is rejected
//
// Even if the signature bytes are untouched, modifying the payload
// should invalidate all signatures because DSSE signs PAE(type, payload).
// ==========================================================================

func TestSecurity_R3_266_TamperedPayloadRejected(t *testing.T) {
	signer, verifier := secCreateKeyPair(t)
	env := secSignEnvelope(t, signer)

	// Tamper the payload after signing.
	env.Payload = []byte("TAMPERED PAYLOAD")

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected rejection for tampered payload, got nil")
	}
}

func TestSecurity_R3_266_TamperedPayloadTypeRejected(t *testing.T) {
	signer, verifier := secCreateKeyPair(t)
	env := secSignEnvelope(t, signer)

	// Change the payload type — PAE includes the type, so signature is invalid.
	env.PayloadType = "tampered/type"

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected rejection for tampered payload type, got nil")
	}
}

// ==========================================================================
// R3-267: Corrupted signature bytes are rejected
//
// Bit-flip in signature bytes should cause DSSE verification failure.
// ==========================================================================

func TestSecurity_R3_267_CorruptedSignatureBytesRejected(t *testing.T) {
	signer, verifier := secCreateKeyPair(t)
	env := secSignEnvelope(t, signer)

	if len(env.Signatures) == 0 {
		t.Fatal("expected at least one signature")
	}

	// Corrupt a byte in the middle of the signature.
	sig := make([]byte, len(env.Signatures[0].Signature))
	copy(sig, env.Signatures[0].Signature)
	sig[len(sig)/2] ^= 0xFF
	env.Signatures[0].Signature = sig

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected rejection for corrupted signature")
	}
}

// ==========================================================================
// R3-268: X509 wrong root CA is rejected
//
// Policy signatures signed by a cert from CA-A should be rejected if only
// CA-B's root is trusted. This verifies the trust chain validation.
// ==========================================================================

func TestSecurity_R3_268_WrongRootCARejected(t *testing.T) {
	// Create chain A.
	rootA, rootKeyA := secCreateRootCA(t)
	interA, interKeyA := secCreateIntermediateCA(t, rootA, rootKeyA)
	leafA, leafKeyA := secCreateLeafCert(t, interA, interKeyA, secLeafOpts{cn: "LeafA"})

	// Sign the envelope with chain A.
	env := secSignEnvelopeX509(t, leafKeyA, leafA, interA, rootA)

	// Create an entirely separate chain B.
	rootB, _ := secCreateRootCA(t)

	// Trust only chain B's root. Chain A's signature should be rejected.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{rootB}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{interA}), // still provide interA but root mismatch
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err == nil {
		t.Fatal("expected rejection: envelope signed by CA-A, only CA-B trusted")
	}
}

func TestSecurity_R3_268_CorrectRootCAPasses(t *testing.T) {
	root, rootKey := secCreateRootCA(t)
	inter, interKey := secCreateIntermediateCA(t, root, rootKey)
	leaf, leafKey := secCreateLeafCert(t, inter, interKey, secLeafOpts{cn: "Leaf"})

	env := secSignEnvelopeX509(t, leafKey, leaf, inter, root)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	if err != nil {
		t.Fatalf("expected success with correct root CA, got: %v", err)
	}
}

// ==========================================================================
// R3-269: Functionary.Validate direct checks
//
// Test the Functionary.Validate method directly for edge cases:
// - Key type functionary with mismatched KeyID
// - Root type functionary with empty roots (should error)
// - CertConstraint.Check with root trust bundle validation
//
// These are internal to the policy package but exercised indirectly
// through VerifyPolicySignature. We test the integration path.
// ==========================================================================

func TestSecurity_R3_269_FunctionaryValidateKeyIDMismatch(t *testing.T) {
	// Create a key verifier.
	_, verifier := secCreateKeyPair(t)
	verifierKID, err := verifier.KeyID()
	if err != nil {
		t.Fatalf("get key id: %v", err)
	}

	// Create a functionary with a different public key ID.
	f := policy.Functionary{
		Type:        "key",
		PublicKeyID: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}

	trustBundle := make(map[string]policy.TrustBundle)
	err = f.Validate(verifier, trustBundle)
	if err == nil {
		t.Fatalf("expected error for mismatched key ID (%s vs %s)", f.PublicKeyID, verifierKID)
	}
}

func TestSecurity_R3_269_FunctionaryValidateKeyIDMatch(t *testing.T) {
	_, verifier := secCreateKeyPair(t)
	kid, err := verifier.KeyID()
	if err != nil {
		t.Fatalf("get key id: %v", err)
	}

	f := policy.Functionary{
		Type:        "key",
		PublicKeyID: kid,
	}

	trustBundle := make(map[string]policy.TrustBundle)
	err = f.Validate(verifier, trustBundle)
	if err != nil {
		t.Fatalf("expected success for matching key ID, got: %v", err)
	}
}

func TestSecurity_R3_269_FunctionaryValidateX509NoRootsRejects(t *testing.T) {
	// Create an X509Verifier directly.
	root, rootKey := secCreateRootCA(t)
	inter, interKey := secCreateIntermediateCA(t, root, rootKey)
	leaf, _ := secCreateLeafCert(t, inter, interKey, secLeafOpts{cn: "Leaf"})

	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, []*x509.Certificate{inter}, []*x509.Certificate{root}, time.Now())
	if err != nil {
		t.Fatalf("create x509 verifier: %v", err)
	}

	// Functionary with no Roots in CertConstraint — should be rejected by Validate
	// which checks len(f.CertConstraint.Roots) == 0.
	f := policy.Functionary{
		Type: "root",
		CertConstraint: policy.CertConstraint{
			CommonName: "*",
			// Roots is empty - this should cause rejection.
		},
	}

	trustBundle := make(map[string]policy.TrustBundle)
	err = f.Validate(x509Verifier, trustBundle)
	if err == nil {
		t.Fatal("expected error for X509 verifier with no roots in functionary")
	}
	if !strings.Contains(err.Error(), "no trusted roots") {
		t.Logf("note: error message was: %v", err)
		// The error might have different wording, just ensure it's an error.
	}
}

func TestSecurity_R3_269_FunctionaryValidateX509WithRootsAndConstraintsPasses(t *testing.T) {
	root, rootKey := secCreateRootCA(t)
	inter, interKey := secCreateIntermediateCA(t, root, rootKey)
	leaf, _ := secCreateLeafCert(t, inter, interKey, secLeafOpts{
		cn:   "Expected Leaf",
		orgs: []string{"ExpectedOrg"},
	})

	x509Verifier, err := cryptoutil.NewX509Verifier(leaf, []*x509.Certificate{inter}, []*x509.Certificate{root}, time.Now())
	if err != nil {
		t.Fatalf("create x509 verifier: %v", err)
	}

	rootID := base64.StdEncoding.EncodeToString(root.Raw)
	trustBundle := map[string]policy.TrustBundle{
		rootID: {Root: root},
	}

	f := policy.Functionary{
		Type: "root",
		CertConstraint: policy.CertConstraint{
			Roots:         []string{rootID},
			CommonName:    "Expected Leaf",
			Organizations: []string{"ExpectedOrg"},
			DNSNames:      []string{},
			Emails:        []string{},
			URIs:          []string{},
		},
	}

	err = f.Validate(x509Verifier, trustBundle)
	if err != nil {
		t.Fatalf("expected success with matching constraints, got: %v", err)
	}
}

func TestSecurity_R3_269_FunctionaryValidateX509WrongTrustBundleRootRejects(t *testing.T) {
	rootA, rootKeyA := secCreateRootCA(t)
	interA, interKeyA := secCreateIntermediateCA(t, rootA, rootKeyA)
	leafA, _ := secCreateLeafCert(t, interA, interKeyA, secLeafOpts{cn: "Leaf"})

	// The verifier was built with rootA chain.
	x509Verifier, err := cryptoutil.NewX509Verifier(leafA, []*x509.Certificate{interA}, []*x509.Certificate{rootA}, time.Now())
	if err != nil {
		t.Fatalf("create x509 verifier: %v", err)
	}

	// But the trust bundle references rootB.
	rootB, _ := secCreateRootCA(t)
	rootBID := base64.StdEncoding.EncodeToString(rootB.Raw)
	trustBundle := map[string]policy.TrustBundle{
		rootBID: {Root: rootB},
	}

	f := policy.Functionary{
		Type: "root",
		CertConstraint: policy.CertConstraint{
			Roots:         []string{rootBID},
			CommonName:    "*",
			Organizations: []string{"*"},
			DNSNames:      []string{"*"},
			Emails:        []string{"*"},
			URIs:          []string{"*"},
		},
	}

	err = f.Validate(x509Verifier, trustBundle)
	if err == nil {
		t.Fatal("expected rejection: leaf cert from rootA should not belong to rootB trust bundle")
	}
}
