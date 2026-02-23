//go:build audit

package dsse

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// ==========================================================================
// Test helpers (stdlib only, no testify)
// ==========================================================================

func secCreateRSAKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	return priv, &priv.PublicKey
}

func secCreateSignerVerifier(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	priv, pub := secCreateRSAKey(t)
	return cryptoutil.NewRSASigner(priv, crypto.SHA256), cryptoutil.NewRSAVerifier(pub, crypto.SHA256)
}

func secSignEnvelope(t *testing.T, signers ...cryptoutil.Signer) Envelope {
	t.Helper()
	env, err := Sign("application/vnd.security-test+json",
		bytes.NewReader([]byte(`{"security":"test"}`)),
		SignWithSigners(signers...))
	if err != nil {
		t.Fatalf("failed to sign envelope: %v", err)
	}
	return env
}

func secCreateCACertChain(t *testing.T) (root *x509.Certificate, rootPriv *rsa.PrivateKey,
	intermediate *x509.Certificate, intermediatePriv *rsa.PrivateKey,
	leaf *x509.Certificate, leafPriv *rsa.PrivateKey) {
	t.Helper()

	// Root CA
	rootPriv, rootPub := secCreateRSAKey(t)
	rootSerial, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	rootTmpl := &x509.Certificate{
		SerialNumber: rootSerial,
		Subject: pkix.Name{
			CommonName:   "Security Test Root CA",
			Organization: []string{"Security Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, rootPub, rootPriv)
	if err != nil {
		t.Fatalf("failed to create root cert: %v", err)
	}
	root, err = x509.ParseCertificate(rootCertBytes)
	if err != nil {
		t.Fatalf("failed to parse root cert: %v", err)
	}

	// Intermediate CA
	intermediatePriv, intermediatePub := secCreateRSAKey(t)
	intSerial, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	intTmpl := &x509.Certificate{
		SerialNumber: intSerial,
		Subject: pkix.Name{
			CommonName:   "Security Test Intermediate CA",
			Organization: []string{"Security Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	intCertBytes, err := x509.CreateCertificate(rand.Reader, intTmpl, root, intermediatePub, rootPriv)
	if err != nil {
		t.Fatalf("failed to create intermediate cert: %v", err)
	}
	intermediate, err = x509.ParseCertificate(intCertBytes)
	if err != nil {
		t.Fatalf("failed to parse intermediate cert: %v", err)
	}

	// Leaf
	leafPriv, leafPub := secCreateRSAKey(t)
	leafSerial, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	leafTmpl := &x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			CommonName:   "Security Test Leaf",
			Organization: []string{"Security Test"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	leafCertBytes, err := x509.CreateCertificate(rand.Reader, leafTmpl, intermediate, leafPub, intermediatePriv)
	if err != nil {
		t.Fatalf("failed to create leaf cert: %v", err)
	}
	leaf, err = x509.ParseCertificate(leafCertBytes)
	if err != nil {
		t.Fatalf("failed to parse leaf cert: %v", err)
	}

	return
}

// mockVerifier is a test verifier with controllable KeyID and verification.
type mockVerifier struct {
	keyID      string
	verifyFunc func(io.Reader, []byte) error
}

func (m *mockVerifier) KeyID() (string, error) { return m.keyID, nil }
func (m *mockVerifier) Verify(body io.Reader, sig []byte) error {
	if m.verifyFunc != nil {
		return m.verifyFunc(body, sig)
	}
	return nil
}
func (m *mockVerifier) Bytes() ([]byte, error) { return []byte(m.keyID), nil }

// ==========================================================================
// R3_130: PAE uses fmt.Sprintf %s for binary body -- null byte behavior
//
// The preauthEncode function constructs the PAE string using:
//   fmt.Sprintf("%s %d %s %d %s", "DSSEv1", len(type), type, len(body), body)
//
// The %s verb treats body as a string. In Go, strings and []byte can contain
// null bytes and %s passes them through correctly. However, this test proves
// that the PAE correctly handles payloads with embedded null bytes and that
// the length prefix in the PAE reflects the actual byte length (including
// nulls), not a C-style strlen.
//
// If PAE ever switches to a C-compatible string function or the length
// calculation is based on string length after null truncation, this test
// will catch the mismatch.
// ==========================================================================

func TestSecurity_R3_130_PAE_NullByteInPayload(t *testing.T) {
	// Two payloads: one with nulls, one with the non-null prefix.
	bodyWithNull := []byte("hello\x00world\x00end")
	bodyTruncated := []byte("hello")

	paeWithNull := preauthEncode("test", bodyWithNull)
	paeTruncated := preauthEncode("test", bodyTruncated)

	// The PAEs MUST differ because the payloads are different lengths.
	if bytes.Equal(paeWithNull, paeTruncated) {
		t.Fatalf("SECURITY BUG: PAE with null bytes in body matches truncated body PAE. "+
			"This means preauthEncode truncates at null bytes, which would allow "+
			"an attacker to sign 'hello\\x00<malicious>' and have it verify as 'hello'")
	}

	// Verify the length field in PAE is correct.
	expectedPrefix := fmt.Sprintf("DSSEv1 4 test %d ", len(bodyWithNull))
	if !bytes.HasPrefix(paeWithNull, []byte(expectedPrefix)) {
		t.Errorf("PAE length prefix mismatch. Expected prefix %q but got PAE starting with %q",
			expectedPrefix, paeWithNull[:min(len(paeWithNull), len(expectedPrefix)+10)])
	}

	// Now verify sign/verify round-trip with null-containing payload.
	signer, verifier := secCreateSignerVerifier(t)
	env, err := Sign("test", bytes.NewReader(bodyWithNull), SignWithSigners(signer))
	if err != nil {
		t.Fatalf("signing with null-byte payload failed: %v", err)
	}

	// Payload must be preserved exactly.
	if !bytes.Equal(env.Payload, bodyWithNull) {
		t.Fatalf("payload not preserved: got %q want %q", env.Payload, bodyWithNull)
	}

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	if err != nil {
		t.Fatalf("verification of null-byte payload failed: %v", err)
	}

	// Tamper: replace payload with truncated version. Must fail.
	env.Payload = bodyTruncated
	_, err = env.Verify(VerifyWithVerifiers(verifier))
	if err == nil {
		t.Fatalf("SECURITY BUG: null-truncated payload verified with original signature. "+
			"An attacker could sign 'hello\\x00<anything>' and it would verify as 'hello'")
	}
}

// ==========================================================================
// R3_131: Cert + Raw verifier double-counting inflates threshold
//
// When a signature carries a valid certificate AND a matching raw verifier
// is provided, both verification paths succeed independently. Each creates
// a verifier with a potentially different KeyID (the X509Verifier gets its
// KeyID from the cert's public key, while the raw RSAVerifier also gets
// its KeyID from the same public key -- but they may or may not match
// depending on the X509Verifier wrapper).
//
// This test documents and detects whether a single physical key can meet
// threshold=2 by being counted once via the cert path and once via the
// raw verifier path.
// ==========================================================================

func TestSecurity_R3_131_CertPlusRawVerifierDoubleCount(t *testing.T) {
	root, _, intermediate, _, leaf, leafPriv := secCreateCACertChain(t)

	// Create a cert-based signer.
	certSigner, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
	if err != nil {
		t.Fatalf("failed to create cert signer: %v", err)
	}

	// Create a raw RSA verifier from the same public key.
	rawVerifier := cryptoutil.NewRSAVerifier(leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("double-count-test")), SignWithSigners(certSigner))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Attempt verification with threshold=2 using cert path + raw verifier.
	// Only ONE physical key signed this envelope. Threshold=2 should NOT pass.
	_, err = env.Verify(
		VerifyWithVerifiers(rawVerifier),
		VerifyWithRoots(root),
		VerifyWithIntermediates(intermediate),
		VerifyWithThreshold(2),
	)

	if err == nil {
		// Get the KeyIDs to document the double-counting.
		rawKID, _ := rawVerifier.KeyID()

		t.Errorf("SECURITY BUG: Single physical key met threshold=2 via cert+raw double-counting. "+
			"Raw verifier KeyID: %s. "+
			"An attacker who compromises ONE signing key can satisfy any threshold by "+
			"providing the key as both a certificate-based signer and a raw verifier.",
			rawKID)
	}
}

// ==========================================================================
// R3_132: VerifyWithVerifiers replaces rather than accumulates
//
// Calling VerifyWithVerifiers(v1) then VerifyWithVerifiers(v2) results in
// only v2 being used. The first call's verifiers are silently dropped.
// This is an API footgun: a caller who chains options might expect both
// v1 and v2 to be checked, but only v2 will be.
//
// Impact: If a caller splits verifier options (e.g., from different config
// sources), they could accidentally drop verifiers, reducing security.
// ==========================================================================

func TestSecurity_R3_132_VerifyWithVerifiersReplacesInsteadOfAccumulating(t *testing.T) {
	priv1, _ := secCreateRSAKey(t)
	priv2, _ := secCreateRSAKey(t)

	signer1 := cryptoutil.NewRSASigner(priv1, crypto.SHA256)
	signer2 := cryptoutil.NewRSASigner(priv2, crypto.SHA256)
	verifier1 := cryptoutil.NewRSAVerifier(&priv1.PublicKey, crypto.SHA256)
	verifier2 := cryptoutil.NewRSAVerifier(&priv2.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("multi-verifier")),
		SignWithSigners(signer1, signer2))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Use two separate VerifyWithVerifiers calls.
	_, err = env.Verify(
		VerifyWithVerifiers(verifier1),
		VerifyWithVerifiers(verifier2),
		VerifyWithThreshold(2),
	)

	if err == nil {
		t.Log("Multiple VerifyWithVerifiers calls accumulate (no bug here)")
		return
	}

	// If we get here, the second call replaced the first.
	// Verify this is the case by checking that only verifier2 was used.
	_, errSingleCall := env.Verify(
		VerifyWithVerifiers(verifier1, verifier2),
		VerifyWithThreshold(2),
	)
	if errSingleCall != nil {
		t.Fatalf("single VerifyWithVerifiers call with both verifiers also failed: %v", errSingleCall)
	}

	t.Errorf("SECURITY FOOTGUN: VerifyWithVerifiers replaces instead of accumulating. "+
		"Calling VerifyWithVerifiers(v1) then VerifyWithVerifiers(v2) silently drops v1. "+
		"Only the last call's verifiers are used. This is dangerous when verifier options "+
		"are assembled from multiple configuration sources. "+
		"Two-call error: %v", err)
}

// ==========================================================================
// R3_133: Attacker-supplied intermediates in signature can chain to
//         alternate root
//
// The verify code appends sig.Intermediates to options.intermediates:
//   sigIntermediates = append(sigIntermediates, options.intermediates...)
//
// This means an attacker who can modify the envelope JSON can inject
// intermediate certificates into the signature that build a chain to
// a different (attacker-controlled) root. If the verifier's root pool
// inadvertently trusts the attacker's root, or if the root pool is
// empty (which on some platforms falls back to system roots), the
// attacker's cert chain could verify.
//
// This test verifies that intermediates from the signature CANNOT cause
// verification to succeed against a root that wasn't explicitly provided
// in the VerifyWithRoots option.
// ==========================================================================

func TestSecurity_R3_133_AttackerIntermediatesDoNotChainToUnauthorizedRoot(t *testing.T) {
	// Create the legitimate CA chain.
	legitimateRoot, _, legitimateInt, _, legitimateLeaf, legitimateLeafPriv := secCreateCACertChain(t)

	// Create an attacker CA chain.
	attackerRoot, attackerRootPriv, _, _, _, _ := secCreateCACertChain(t)

	// Create an attacker intermediate that chains to the attacker root.
	attackerIntPriv, attackerIntPub := secCreateRSAKey(t)
	_ = attackerIntPriv // not used further
	attackerIntSerial, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	attackerIntTmpl := &x509.Certificate{
		SerialNumber: attackerIntSerial,
		Subject: pkix.Name{
			CommonName:   "Attacker Intermediate",
			Organization: []string{"Attacker"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	attackerIntCertBytes, err := x509.CreateCertificate(rand.Reader, attackerIntTmpl, attackerRoot, attackerIntPub, attackerRootPriv)
	if err != nil {
		t.Fatalf("failed to create attacker intermediate: %v", err)
	}
	attackerIntCert, err := x509.ParseCertificate(attackerIntCertBytes)
	if err != nil {
		t.Fatalf("failed to parse attacker intermediate: %v", err)
	}

	// Sign with the legitimate leaf.
	certSigner, err := cryptoutil.NewSigner(legitimateLeafPriv,
		cryptoutil.SignWithCertificate(legitimateLeaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{legitimateInt}))
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	env, err := Sign("test", bytes.NewReader([]byte("intermediate-injection")), SignWithSigners(certSigner))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Inject attacker's intermediate into the envelope's signature.
	attackerIntPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: attackerIntCert.Raw})
	env.Signatures[0].Intermediates = append(env.Signatures[0].Intermediates, attackerIntPEM)

	// Verify with ONLY the legitimate root. The attacker's intermediate
	// should not affect the outcome.
	_, err = env.Verify(
		VerifyWithRoots(legitimateRoot),
		VerifyWithThreshold(1),
	)
	if err != nil {
		t.Logf("Correctly: verification with injected attacker intermediate still works "+
			"with legitimate root (attacker intermediate is ignored): no error")
	}

	// Now verify with ONLY the attacker root. This MUST fail because
	// the leaf was signed by the legitimate CA, not the attacker CA.
	_, err = env.Verify(
		VerifyWithRoots(attackerRoot),
		VerifyWithThreshold(1),
	)
	if err == nil {
		t.Fatalf("SECURITY BUG: Attacker-injected intermediate allowed verification "+
			"against attacker root even though the leaf cert was issued by the "+
			"legitimate CA. The attacker's intermediate in sig.Intermediates created "+
			"a cross-chain trust path.")
	}
}

// ==========================================================================
// R3_134: Empty signatures array after initial check
//
// The verify function checks len(e.Signatures) == 0 early and returns
// ErrNoSignatures. But what about an envelope where Signatures is non-nil
// but all signature entries have nil/empty Signature bytes? The loop will
// iterate but no verifier will succeed, and the function should return
// ErrNoMatchingSigs.
//
// A subtler variant: what if ALL signature entries have Certificate data
// that fails to parse? Does verification still try raw verifiers?
// ==========================================================================

func TestSecurity_R3_134_AllSignaturesHaveEmptyBytesStillFails(t *testing.T) {
	_, verifier := secCreateSignerVerifier(t)

	env := Envelope{
		Payload:     []byte("test payload"),
		PayloadType: "test",
		Signatures: []Signature{
			{KeyID: "k1", Signature: nil},
			{KeyID: "k2", Signature: []byte{}},
			{KeyID: "k3", Signature: []byte{0x00}},
		},
	}

	_, err := env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(1))
	if err == nil {
		t.Fatal("SECURITY BUG: envelope with all nil/empty signature bytes passed verification")
	}
}

// ==========================================================================
// R3_135: Duplicate verifiers with different KeyIDs bypass threshold
//
// If an attacker can influence the verifier list (e.g., through a config
// injection), they can wrap the same underlying key in multiple verifiers
// with distinct KeyIDs. The dedup is KeyID-based, so N wrappers of the
// same key with different KeyIDs meet threshold=N.
//
// This proves the vulnerability: one compromised key can satisfy any
// threshold by appearing multiple times with different KeyIDs.
// ==========================================================================

func TestSecurity_R3_135_SameKeyDifferentKeyIDsBypassesThreshold(t *testing.T) {
	priv, _ := secCreateRSAKey(t)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	env := secSignEnvelope(t, signer)

	// Create 3 wrappers around the same verifier with different KeyIDs.
	wrapper1 := &mockVerifier{
		keyID: "key-alpha",
		verifyFunc: func(body io.Reader, sig []byte) error {
			return realVerifier.Verify(body, sig)
		},
	}
	wrapper2 := &mockVerifier{
		keyID: "key-beta",
		verifyFunc: func(body io.Reader, sig []byte) error {
			return realVerifier.Verify(body, sig)
		},
	}
	wrapper3 := &mockVerifier{
		keyID: "key-gamma",
		verifyFunc: func(body io.Reader, sig []byte) error {
			return realVerifier.Verify(body, sig)
		},
	}

	_, err := env.Verify(
		VerifyWithVerifiers(wrapper1, wrapper2, wrapper3),
		VerifyWithThreshold(3),
	)

	if err == nil {
		t.Errorf("SECURITY BUG: Single key with 3 different KeyID wrappers met threshold=3. "+
			"The threshold deduplication is KeyID-based, not cryptographic-key-based. "+
			"An attacker who compromises one key can wrap it in N verifier objects with "+
			"distinct KeyIDs to satisfy any threshold. This completely undermines "+
			"multi-party signing guarantees.")
	}
}

// ==========================================================================
// R3_136: Signature with forged Certificate field and valid raw signature
//
// If an attacker injects a valid-looking but unrelated certificate into
// the signature's Certificate field, and the verifier has both roots and
// raw verifiers configured, verify how the two paths interact.
//
// Specifically: if the cert path fails (because the cert doesn't match
// the signature), does the raw verifier path still work correctly?
// ==========================================================================

func TestSecurity_R3_136_ForgedCertificateFieldDoesNotBlockRawVerifier(t *testing.T) {
	signer, verifier := secCreateSignerVerifier(t)
	env := secSignEnvelope(t, signer)

	// Create an unrelated certificate.
	unrelatedRoot, unrelatedRootPriv, _, _, _, _ := secCreateCACertChain(t)
	_ = unrelatedRoot

	// Create a leaf from the unrelated CA.
	unrelatedLeafPriv, unrelatedLeafPub := secCreateRSAKey(t)
	_ = unrelatedLeafPriv
	unrelatedLeafSerial, _ := rand.Int(rand.Reader, big.NewInt(1<<32))
	unrelatedLeafTmpl := &x509.Certificate{
		SerialNumber: unrelatedLeafSerial,
		Subject:      pkix.Name{CommonName: "Unrelated Leaf"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	unrelatedLeafBytes, err := x509.CreateCertificate(rand.Reader, unrelatedLeafTmpl, unrelatedRoot, unrelatedLeafPub, unrelatedRootPriv)
	if err != nil {
		t.Fatalf("failed to create unrelated leaf cert: %v", err)
	}

	// Inject the unrelated certificate into the envelope's signature.
	unrelatedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: unrelatedLeafBytes})
	env.Signatures[0].Certificate = unrelatedPEM

	// Verify with the raw verifier. The cert path will attempt to verify
	// the unrelated cert (which will fail because there are no matching
	// roots), but the raw verifier should still work.
	_, err = env.Verify(
		VerifyWithVerifiers(verifier),
		VerifyWithThreshold(1),
	)

	if err != nil {
		t.Errorf("Raw verifier blocked by forged Certificate field: %v. "+
			"The presence of a Certificate field that fails cert verification "+
			"should NOT prevent the raw verifier path from running.", err)
	}
}

// ==========================================================================
// R3_137: Payload mutation between sign and verify (TOCTOU)
//
// The Envelope struct uses a []byte slice for Payload. If the caller
// retains a reference to the original byte slice, they can mutate it
// after signing but before verification. Since Envelope.Verify uses a
// value receiver (copy of the struct), the Payload field is copied --
// but the underlying byte array is shared. This test verifies whether
// mutation of the original byte slice after signing can cause verification
// to succeed on altered data.
// ==========================================================================

func TestSecurity_R3_137_PayloadMutationAfterSigning(t *testing.T) {
	signer, verifier := secCreateSignerVerifier(t)

	original := []byte("this is the original payload that was signed")
	env, err := Sign("test", bytes.NewReader(original), SignWithSigners(signer))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// The Sign function reads all bytes from the reader and stores them.
	// The returned env.Payload is a separate slice from original (because
	// io.ReadAll allocates a new slice). But let's verify this property.

	// Mutate the Payload directly in the envelope.
	savedPayload := make([]byte, len(env.Payload))
	copy(savedPayload, env.Payload)

	env.Payload[0] = 'X' // mutate first byte

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	if err == nil {
		t.Errorf("SECURITY BUG: Mutated payload verified with original signature. "+
			"Payload[0] was changed from %c to X but verification still passed. "+
			"This is a TOCTOU vulnerability: the PAE is computed from the (mutated) "+
			"Payload at verify time, but the signature was computed from the original.",
			savedPayload[0])
	}

	// Restore and verify the original works.
	env.Payload = savedPayload
	_, err = env.Verify(VerifyWithVerifiers(verifier))
	if err != nil {
		t.Errorf("restored payload should verify: %v", err)
	}
}

// ==========================================================================
// R3_138: PAE length-extension attack
//
// The PAE format is:
//   "DSSEv1 <len(type)> <type> <len(body)> <body>"
//
// Can an attacker craft a (type, body) pair that produces the same PAE
// as a different (type, body) pair? For instance:
//   type="a"  body="b 3 xyz"   -> "DSSEv1 1 a 7 b 3 xyz"
//   type="a"  body="b"         -> "DSSEv1 1 a 1 b"
//
// The length prefix should prevent this, but the fact that the separator
// is a space (which can appear in both type and body) means we need to
// verify that the length fields create unambiguous boundaries.
// ==========================================================================

func TestSecurity_R3_138_PAELengthExtensionAttack(t *testing.T) {
	// Attempt collision: pad body to include what looks like a PAE trailer.
	type1 := "type"
	body1 := []byte("data")
	body2 := []byte("data 10 extra-data")

	pae1 := preauthEncode(type1, body1)
	pae2 := preauthEncode(type1, body2)

	if bytes.Equal(pae1, pae2) {
		t.Fatal("SECURITY BUG: two different bodies produced the same PAE")
	}

	// Attempt: can we find a body whose PAE matches a different (type, body)?
	// "DSSEv1 4 type 4 data" is pae1.
	// Can we craft type2/body2 to produce the same string?
	// type2="type 4 data" body2="" -> "DSSEv1 11 type 4 data 0 "
	// Different because len(type2)=11 != len(type1)=4.
	paeCandidate := preauthEncode("type 4 data", []byte(""))
	if bytes.Equal(pae1, paeCandidate) {
		t.Fatal("SECURITY BUG: PAE collision via type containing body content")
	}

	// Attempt: same total length but rearranged.
	// pae1 = "DSSEv1 4 type 4 data"
	// Craft: type="typ" body="e 4 data" -> "DSSEv1 3 typ 8 e 4 data"
	// Different because type length is 3 not 4.
	paeRearranged := preauthEncode("typ", []byte("e 4 data"))
	if bytes.Equal(pae1, paeRearranged) {
		t.Fatal("SECURITY BUG: PAE collision via rearranging type/body boundary")
	}

	// Now verify through actual sign/verify.
	signer, verifier := secCreateSignerVerifier(t)
	env, err := Sign(type1, bytes.NewReader(body1), SignWithSigners(signer))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	// Attempt to verify with body2 (different body, same type).
	env.Payload = body2
	_, err = env.Verify(VerifyWithVerifiers(verifier))
	if err == nil {
		t.Fatal("SECURITY BUG: length-extended body verified with original signature")
	}
}

// ==========================================================================
// R3_139: Threshold=1 with no valid signatures but non-empty envelope
//
// An envelope with signatures that all fail verification should return
// ErrNoMatchingSigs, not silently pass. This tests the boundary between
// "signatures exist but none verify" and "no signatures at all".
// ==========================================================================

func TestSecurity_R3_139_AllSignaturesFailStillReturnsError(t *testing.T) {
	signer, _ := secCreateSignerVerifier(t)
	_, wrongVerifier := secCreateSignerVerifier(t) // different key

	env := secSignEnvelope(t, signer)

	_, err := env.Verify(VerifyWithVerifiers(wrongVerifier), VerifyWithThreshold(1))
	if err == nil {
		t.Fatal("SECURITY BUG: verification passed with wrong verifier")
	}

	var noMatch ErrNoMatchingSigs
	if !errors.As(err, &noMatch) {
		t.Errorf("expected ErrNoMatchingSigs, got %T: %v", err, err)
	}
}

// ==========================================================================
// R3_140: Mixed algorithm confusion -- ECDSA signature verified by RSA
//
// Verify that cross-algorithm verification never accidentally succeeds.
// The DSSE verify loop tries every verifier against every signature.
// If a verifier's Verify method doesn't properly reject signatures from
// a different algorithm, a cross-algorithm bypass could occur.
// ==========================================================================

func TestSecurity_R3_140_CrossAlgorithmVerificationNeverSucceeds(t *testing.T) {
	// Sign with ECDSA.
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	ecSigner := cryptoutil.NewECDSASigner(ecPriv, crypto.SHA256)

	// Sign with RSA.
	rsaPriv, _ := secCreateRSAKey(t)
	rsaSigner := cryptoutil.NewRSASigner(rsaPriv, crypto.SHA256)

	// Create verifiers for the opposite keys.
	rsaVerifierForECKey := cryptoutil.NewRSAVerifier(&rsaPriv.PublicKey, crypto.SHA256)
	ecVerifierForRSAKey := cryptoutil.NewECDSAVerifier(&ecPriv.PublicKey, crypto.SHA256)

	// ECDSA-signed envelope verified with RSA verifier.
	ecEnv, err := Sign("test", bytes.NewReader([]byte("ecdsa-payload")), SignWithSigners(ecSigner))
	if err != nil {
		t.Fatalf("ECDSA sign failed: %v", err)
	}

	_, err = ecEnv.Verify(VerifyWithVerifiers(rsaVerifierForECKey))
	if err == nil {
		t.Fatal("SECURITY BUG: ECDSA signature verified with RSA verifier")
	}

	// RSA-signed envelope verified with ECDSA verifier.
	rsaEnv, err := Sign("test", bytes.NewReader([]byte("rsa-payload")), SignWithSigners(rsaSigner))
	if err != nil {
		t.Fatalf("RSA sign failed: %v", err)
	}

	_, err = rsaEnv.Verify(VerifyWithVerifiers(ecVerifierForRSAKey))
	if err == nil {
		t.Fatal("SECURITY BUG: RSA signature verified with ECDSA verifier")
	}
}

// ==========================================================================
// R3_141: Verify with zero-value Envelope
//
// A zero-value Envelope has nil Payload, empty PayloadType, and nil
// Signatures. Verify should handle this gracefully without panicking.
// ==========================================================================

func TestSecurity_R3_141_ZeroValueEnvelopeDoesNotPanic(t *testing.T) {
	_, verifier := secCreateSignerVerifier(t)

	env := Envelope{} // zero value

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SECURITY BUG: zero-value Envelope caused panic in Verify: %v", r)
		}
	}()

	_, err := env.Verify(VerifyWithVerifiers(verifier))
	if err == nil {
		t.Fatal("SECURITY BUG: zero-value Envelope passed verification")
	}

	// Should be ErrNoSignatures.
	var noSigs ErrNoSignatures
	if !errors.As(err, &noSigs) {
		t.Logf("got error type %T: %v (expected ErrNoSignatures)", err, err)
	}
}

// ==========================================================================
// R3_142: Verify that preauthEncode is injection-safe for all byte values
//
// Exhaustively test that for any single-byte difference in the body, the
// PAE output differs. This confirms that no byte value has special
// handling that could create ambiguity.
// ==========================================================================

func TestSecurity_R3_142_PAEByteSafety(t *testing.T) {
	baseType := "test"
	baseBody := []byte{0x41} // "A"
	basePAE := preauthEncode(baseType, baseBody)

	for b := 0; b < 256; b++ {
		if byte(b) == 0x41 {
			continue // skip identical
		}
		altBody := []byte{byte(b)}
		altPAE := preauthEncode(baseType, altBody)

		if bytes.Equal(basePAE, altPAE) {
			t.Errorf("SECURITY BUG: byte 0x%02x produces same PAE as 0x41", b)
		}
	}
}

// ==========================================================================
// R3_143: Envelope Signatures slice can be mutated between Verify calls
//
// Since Envelope.Verify takes the Envelope by value, mutations to the
// Signatures slice between calls should not affect an ongoing Verify.
// But what about mutations DURING a call? Envelope is copied by value,
// but the Signatures slice header is copied -- the underlying array is
// shared. If someone mutates env.Signatures[i] concurrently with Verify,
// the Verify call sees inconsistent data.
// ==========================================================================

func TestSecurity_R3_143_SignatureSliceMutationBetweenVerifyCalls(t *testing.T) {
	signer, verifier := secCreateSignerVerifier(t)
	env := secSignEnvelope(t, signer)

	// First verify should succeed.
	_, err := env.Verify(VerifyWithVerifiers(verifier))
	if err != nil {
		t.Fatalf("initial verify failed: %v", err)
	}

	// Save the valid signature.
	validSig := make([]byte, len(env.Signatures[0].Signature))
	copy(validSig, env.Signatures[0].Signature)

	// Mutate the Signatures slice between calls.
	env.Signatures[0].Signature = []byte("corrupted")

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	if err == nil {
		t.Fatal("SECURITY BUG: corrupted signature still verified after mutation")
	}

	// Restore and verify again.
	env.Signatures[0].Signature = validSig
	_, err = env.Verify(VerifyWithVerifiers(verifier))
	if err != nil {
		t.Errorf("restored signature should verify: %v", err)
	}
}

// ==========================================================================
// R3_144: Large number of verifiers amplification DoS
//
// The verification loop is O(signatures * verifiers). An attacker who
// can influence the verifier list size can cause CPU exhaustion. This test
// measures the amplification factor.
// ==========================================================================

func TestSecurity_R3_144_VerifierAmplificationFactor(t *testing.T) {
	signer, _ := secCreateSignerVerifier(t)
	env := secSignEnvelope(t, signer)

	// Duplicate the signature to have 10 entries.
	origSig := env.Signatures[0]
	env.Signatures = make([]Signature, 10)
	for i := range env.Signatures {
		env.Signatures[i] = origSig
	}

	// Create 10 verifiers (all wrong except potentially one).
	verifiers := make([]cryptoutil.Verifier, 10)
	for i := range verifiers {
		_, v := secCreateSignerVerifier(t)
		verifiers[i] = v
	}

	callCount := 0
	// Wrap verifiers in a counter.
	countingVerifiers := make([]cryptoutil.Verifier, len(verifiers))
	for i, v := range verifiers {
		vCopy := v
		countingVerifiers[i] = &mockVerifier{
			keyID: fmt.Sprintf("counting-%d", i),
			verifyFunc: func(body io.Reader, sig []byte) error {
				callCount++
				return vCopy.Verify(body, sig)
			},
		}
	}

	_, _ = env.Verify(
		VerifyWithVerifiers(countingVerifiers...),
		VerifyWithThreshold(1),
	)

	// Expected: 10 sigs * 10 verifiers = 100 calls.
	expectedCalls := 10 * 10
	if callCount != expectedCalls {
		t.Errorf("expected %d verification calls (O(sigs*verifiers)), got %d", expectedCalls, callCount)
	}

	t.Logf("SECURITY NOTE: Verification performs O(sigs * verifiers) = %d cryptographic "+
		"operations. With attacker-controlled signature count, this is a DoS vector. "+
		"Consider adding a max signatures limit.", callCount)
}

// ==========================================================================
// R3_145: Envelope with PayloadType containing format string specifiers
//
// preauthEncode uses fmt.Sprintf. If the PayloadType contains format
// specifiers like %s, %d, %x, etc., they should be treated as literal
// text, not as format directives, because they appear as arguments to
// Sprintf, not as the format string.
// ==========================================================================

func TestSecurity_R3_145_PayloadTypeWithFormatSpecifiers(t *testing.T) {
	signer, verifier := secCreateSignerVerifier(t)

	dangerousTypes := []string{
		"%s%s%s%s%s",
		"%d%x%v%p",
		"%n%n%n", // C format string attack (not applicable in Go but worth testing)
		"%(EXTRA)s",
		"type\x00embedded",
	}

	for _, dtype := range dangerousTypes {
		t.Run(fmt.Sprintf("type=%q", dtype), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("SECURITY BUG: payloadType %q caused panic: %v", dtype, r)
				}
			}()

			env, err := Sign(dtype, bytes.NewReader([]byte("payload")), SignWithSigners(signer))
			if err != nil {
				t.Fatalf("sign with type %q failed: %v", dtype, err)
			}

			_, err = env.Verify(VerifyWithVerifiers(verifier))
			if err != nil {
				t.Fatalf("verify with type %q failed: %v", dtype, err)
			}

			// Tamper and verify it fails.
			env.PayloadType = dtype + "x"
			_, err = env.Verify(VerifyWithVerifiers(verifier))
			if err == nil {
				t.Fatalf("tampered type %q should fail verification", dtype+"x")
			}
		})
	}
}

// ==========================================================================
// R3_146: Envelope with extremely large PayloadType length field
//
// The PAE format includes len(type) as a decimal integer. If a type string
// is very long, len() will be a large number. Verify this doesn't cause
// integer overflow or memory issues in the PAE construction.
// ==========================================================================

func TestSecurity_R3_146_PAEWithMaxIntLengthField(t *testing.T) {
	// We can't actually allocate a string of MaxInt length, but we can
	// test that the PAE format correctly represents large lengths.
	bigType := strings.Repeat("A", 1<<16) // 64KB
	body := []byte("small body")

	pae := preauthEncode(bigType, body)

	expectedPrefix := fmt.Sprintf("DSSEv1 %d ", len(bigType))
	if !bytes.HasPrefix(pae, []byte(expectedPrefix)) {
		t.Errorf("PAE does not start with expected prefix for 64KB type. "+
			"Got prefix: %q", pae[:min(len(pae), 30)])
	}

	// Verify the full PAE is correct.
	expectedPAE := fmt.Sprintf("DSSEv1 %d %s %d %s", len(bigType), bigType, len(body), body)
	if !bytes.Equal(pae, []byte(expectedPAE)) {
		t.Error("PAE with large type string does not match expected format")
	}
}

// ==========================================================================
// R3_147: ErrThresholdNotMet leaks verified count to attacker
//
// The ErrThresholdNotMet error includes the Actual verified count. This
// is an information leak: an attacker probing threshold values can learn
// exactly how many verifiers passed, which reveals information about
// which keys are compromised or which signatures are valid.
// ==========================================================================

func TestSecurity_R3_147_ThresholdErrorLeaksVerifiedCount(t *testing.T) {
	priv1, _ := secCreateRSAKey(t)
	priv2, _ := secCreateRSAKey(t)

	signer1 := cryptoutil.NewRSASigner(priv1, crypto.SHA256)
	signer2 := cryptoutil.NewRSASigner(priv2, crypto.SHA256)
	verifier1 := cryptoutil.NewRSAVerifier(&priv1.PublicKey, crypto.SHA256)
	verifier2 := cryptoutil.NewRSAVerifier(&priv2.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("leak-test")),
		SignWithSigners(signer1, signer2))
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	_, err = env.Verify(
		VerifyWithVerifiers(verifier1, verifier2),
		VerifyWithThreshold(100), // unreachable threshold
	)
	if err == nil {
		t.Fatal("threshold=100 should not pass")
	}

	var threshErr ErrThresholdNotMet
	if !errors.As(err, &threshErr) {
		t.Fatalf("expected ErrThresholdNotMet, got %T: %v", err, err)
	}

	// The Actual field reveals exactly how many verifiers passed.
	if threshErr.Actual != 2 {
		t.Errorf("expected Actual=2, got %d", threshErr.Actual)
	}

	// This is an information leak. Document it.
	errMsg := threshErr.Error()
	if !strings.Contains(errMsg, "2") {
		t.Errorf("error message should contain the actual count: %s", errMsg)
	}

	t.Logf("SECURITY NOTE: ErrThresholdNotMet.Error() reveals verified count: %q. "+
		"An attacker who can trigger verification with different thresholds can learn "+
		"exactly how many signatures verified, revealing which keys are valid. "+
		"Consider returning only 'threshold not met' without the actual count.", errMsg)
}

// ==========================================================================
// R3_148: Verify returns CheckedVerifier with nil Verifier
//
// The verify loop can potentially add CheckedVerifier entries with nil
// Verifier fields if the cert verification path creates a nil verifier.
// Consumers iterating the returned slice and calling methods on Verifier
// would panic. Verify this doesn't happen.
// ==========================================================================

func TestSecurity_R3_148_NoNilVerifiersInCheckedVerifiersOutput(t *testing.T) {
	signer, verifier := secCreateSignerVerifier(t)
	env := secSignEnvelope(t, signer)

	// Add some garbage signatures to exercise error paths.
	env.Signatures = append(env.Signatures, Signature{
		KeyID:       "garbage",
		Signature:   []byte("not-valid"),
		Certificate: []byte("not-a-cert"),
	})

	checked, err := env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(1))
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	for i, cv := range checked {
		if cv.Verifier == nil {
			t.Errorf("SECURITY BUG: CheckedVerifier[%d] has nil Verifier. "+
				"Consumers iterating this slice and calling cv.Verifier.KeyID() will panic.", i)
		}
	}
}

// ==========================================================================
// R3_149: Signature replay across payload types of different lengths
//
// The PAE includes both len(type) and the type itself. If two types have
// the same length, could a signature from one type verify under the other?
// The answer should be no (the type content differs), but let's prove it.
// ==========================================================================

func TestSecurity_R3_149_SameLengthPayloadTypeReplayFails(t *testing.T) {
	signer, verifier := secCreateSignerVerifier(t)
	payload := []byte("shared payload")

	typeA := "application/aaa" // len=15
	typeB := "application/bbb" // len=15

	if len(typeA) != len(typeB) {
		t.Fatal("test setup error: types must have same length")
	}

	envA, err := Sign(typeA, bytes.NewReader(payload), SignWithSigners(signer))
	if err != nil {
		t.Fatalf("sign A failed: %v", err)
	}

	// Transplant A's signature to an envelope with type B.
	envB := Envelope{
		Payload:     payload,
		PayloadType: typeB,
		Signatures:  envA.Signatures,
	}

	_, err = envB.Verify(VerifyWithVerifiers(verifier))
	if err == nil {
		t.Fatal("SECURITY BUG: signature from typeA verified under typeB with same length. " +
			"The PAE type content is not being verified, only the length.")
	}
}

// Note: uses builtin min() from Go 1.21+
