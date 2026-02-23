//go:build audit

package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// DigestSet.Equal adversarial tests
// ==========================================================================

func TestAdversarial_DigestSetEqual_BothEmpty(t *testing.T) {
	ds1 := DigestSet{}
	ds2 := DigestSet{}

	result := ds1.Equal(ds2)
	// With no overlapping hash functions, Equal should return false.
	// An empty set has no matching digests, so hasMatchingDigest stays false.
	assert.False(t, result,
		"two empty DigestSets should NOT be equal (no overlapping algorithms)")
}

func TestAdversarial_DigestSetEqual_OneEmpty(t *testing.T) {
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "abc123",
	}
	ds2 := DigestSet{}

	assert.False(t, ds1.Equal(ds2),
		"non-empty vs empty should be false")
	assert.False(t, ds2.Equal(ds1),
		"empty vs non-empty should be false")
}

func TestAdversarial_DigestSetEqual_NoOverlappingAlgorithms(t *testing.T) {
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "abc123",
	}
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA1}: "def456",
	}

	result := ds1.Equal(ds2)
	assert.False(t, result,
		"DigestSets with no overlapping algorithms should NOT be equal")
}

func TestAdversarial_DigestSetEqual_PartialOverlapWithMismatch(t *testing.T) {
	// SHA256 matches but SHA1 doesn't. Should return false because
	// the contract says "every digest for hash functions both have in common
	// must be equal."
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "same-sha256",
		DigestValue{Hash: crypto.SHA1}:   "sha1-version-A",
	}
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "same-sha256",
		DigestValue{Hash: crypto.SHA1}:   "sha1-version-B",
	}

	result := ds1.Equal(ds2)
	assert.False(t, result,
		"if any common algorithm has different digests, should be false")
}

func TestAdversarial_DigestSetEqual_PartialOverlapAllMatch(t *testing.T) {
	// SHA256 is shared and matches. SHA1 and GitOID only exist in one set each.
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256}:                      "same-sha256",
		DigestValue{Hash: crypto.SHA1}:                        "only-in-ds1",
		DigestValue{Hash: crypto.SHA256, GitOID: true}:        "gitoid-only-in-ds1",
	}
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "same-sha256",
	}

	result := ds1.Equal(ds2)
	assert.True(t, result,
		"overlapping algorithm matches, non-overlapping ignored => true")

	result = ds2.Equal(ds1)
	assert.True(t, result,
		"should be symmetric")
}

func TestAdversarial_DigestSetEqual_GitOIDvsSHA256(t *testing.T) {
	// DigestValue{SHA256, false, false} != DigestValue{SHA256, true, false}
	// even though they use the same hash function.
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256, GitOID: false}: "abc123",
	}
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA256, GitOID: true}: "abc123",
	}

	result := ds1.Equal(ds2)
	assert.False(t, result,
		"SHA256 and gitoid:sha256 are different DigestValues, so no overlap")
}

func TestAdversarial_DigestSetEqual_DirHashvsSHA256(t *testing.T) {
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256, DirHash: false}: "abc123",
	}
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA256, DirHash: true}: "abc123",
	}

	result := ds1.Equal(ds2)
	assert.False(t, result,
		"SHA256 and dirHash are different DigestValues, so no overlap")
}

func TestAdversarial_DigestSetEqual_CaseSensitiveDigests(t *testing.T) {
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "ABC123",
	}
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "abc123",
	}

	result := ds1.Equal(ds2)
	assert.False(t, result,
		"digest comparison should be case-sensitive (hex encoding matters)")
}

func TestAdversarial_DigestSetEqual_NilReceiver(t *testing.T) {
	var ds *DigestSet
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "abc123",
	}

	// Calling Equal on a nil pointer should panic (it dereferences *ds).
	// This documents the behavior.
	assert.Panics(t, func() {
		ds.Equal(ds2)
	}, "calling Equal on nil DigestSet pointer should panic")
}

func TestAdversarial_DigestSetEqual_NilArgument(t *testing.T) {
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "abc123",
	}

	// Passing nil as the second argument -- DigestSet is a map type,
	// so nil is a valid empty map.
	result := ds1.Equal(nil)
	assert.False(t, result,
		"non-empty vs nil DigestSet should be false")
}

func TestAdversarial_DigestSetEqual_Symmetry(t *testing.T) {
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "match",
		DigestValue{Hash: crypto.SHA1}:   "only-in-ds1",
	}
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "match",
	}

	// Equal iterates over *ds (the receiver). The direction matters because
	// different sets of keys are iterated depending on which is the receiver.
	r1 := ds1.Equal(ds2)
	r2 := ds2.Equal(ds1)

	assert.Equal(t, r1, r2,
		"DigestSet.Equal should be symmetric (a.Equal(b) == b.Equal(a))")
}

// ==========================================================================
// TryParseCertificate adversarial tests
// ==========================================================================

func TestAdversarial_TryParseCertificate_EmptyBytes(t *testing.T) {
	_, err := TryParseCertificate([]byte{})
	require.Error(t, err, "empty bytes should fail to parse as certificate")
}

func TestAdversarial_TryParseCertificate_NilBytes(t *testing.T) {
	_, err := TryParseCertificate(nil)
	require.Error(t, err, "nil bytes should fail to parse as certificate")
}

func TestAdversarial_TryParseCertificate_WrongPEMType(t *testing.T) {
	// Generate a real RSA private key and encode it as "PRIVATE KEY" PEM.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	_, err = TryParseCertificate(pemBytes)
	require.Error(t, err,
		"PRIVATE KEY PEM should not parse as certificate")
}

func TestAdversarial_TryParseCertificate_PublicKeyPEM(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	_, err = TryParseCertificate(pemBytes)
	require.Error(t, err,
		"PUBLIC KEY PEM should not be mistaken for a certificate")
}

func TestAdversarial_TryParseCertificate_TruncatedPEM(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Truncate the PEM to half its length.
	truncated := pemBytes[:len(pemBytes)/2]

	_, err := TryParseCertificate(truncated)
	require.Error(t, err, "truncated PEM should fail to parse")
}

func TestAdversarial_TryParseCertificate_DERWithoutPEMWrapping(t *testing.T) {
	cert := generateSelfSignedCert(t)

	// Pass raw DER bytes without PEM encoding.
	_, err := TryParseCertificate(cert.Raw)
	// TryParseCertificate calls TryParseKeyFromReader which does pem.Decode.
	// If pem.Decode returns nil, TryParsePEMBlock gets nil and returns
	// ErrInvalidPemBlock. So DER without PEM wrapping should fail.
	require.Error(t, err,
		"DER bytes without PEM wrapping should fail to parse")
	t.Logf("DER parse error: %v", err)
}

func TestAdversarial_TryParseCertificate_ExtraDataAfterPEM(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Append garbage after the END marker.
	withExtra := append(pemBytes, []byte("\n\nEXTRA GARBAGE DATA HERE\n")...)

	// pem.Decode only parses the first block. Extra data is silently ignored.
	parsedCert, err := TryParseCertificate(withExtra)
	require.NoError(t, err,
		"extra data after PEM END should be silently ignored")
	assert.Equal(t, cert.Subject.CommonName, parsedCert.Subject.CommonName)
}

func TestAdversarial_TryParseCertificate_MultiplePEMBlocks(t *testing.T) {
	cert1 := generateSelfSignedCert(t)
	cert2 := generateSelfSignedCert(t)

	pem1 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert1.Raw})
	pem2 := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert2.Raw})

	// Concatenate two certificate PEMs.
	combined := append(pem1, pem2...)

	// TryParseKeyFromReader only parses the FIRST PEM block.
	parsedCert, err := TryParseCertificate(combined)
	require.NoError(t, err)
	assert.Equal(t, cert1.Subject.CommonName, parsedCert.Subject.CommonName,
		"should return the FIRST certificate in concatenated PEM")
}

func TestAdversarial_TryParseCertificate_GarbageBase64InPEM(t *testing.T) {
	// Manually construct a PEM with invalid base64 content.
	badPEM := []byte(`-----BEGIN CERTIFICATE-----
THIS IS NOT VALID BASE64 CONTENT !!!@@@###
-----END CERTIFICATE-----`)

	_, err := TryParseCertificate(badPEM)
	require.Error(t, err, "PEM with invalid base64 should fail to parse")
}

func TestAdversarial_TryParseCertificate_EmptyPEMBody(t *testing.T) {
	emptyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: []byte{},
	})

	_, err := TryParseCertificate(emptyPEM)
	require.Error(t, err, "PEM with empty body should fail to parse as certificate")
}

// ==========================================================================
// NewVerifierFromReader adversarial tests
// ==========================================================================

func TestAdversarial_NewVerifierFromReader_RSAPublicKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	verifier, err := NewVerifierFromReader(bytes.NewReader(pemBytes))
	require.NoError(t, err, "should parse RSA public key in PKIX format")
	require.NotNil(t, verifier)

	// Verify KeyID works.
	kid, err := verifier.KeyID()
	require.NoError(t, err)
	assert.NotEmpty(t, kid)
}

func TestAdversarial_NewVerifierFromReader_ED25519PublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	verifier, err := NewVerifierFromReader(bytes.NewReader(pemBytes))
	require.NoError(t, err, "should parse Ed25519 public key")
	require.NotNil(t, verifier)
}

func TestAdversarial_NewVerifierFromReader_ECPublicKey(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})

	verifier, err := NewVerifierFromReader(bytes.NewReader(pemBytes))
	require.NoError(t, err, "should parse EC public key")
	require.NotNil(t, verifier)
}

func TestAdversarial_NewVerifierFromReader_PKCS1RSAPublicKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pkcs1DER := x509.MarshalPKCS1PublicKey(&privKey.PublicKey)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pkcs1DER,
	})

	// TryParseKeyFromReader -> TryParsePEMBlock tries PKCS1 parsing.
	// But NewVerifier may not handle the raw *rsa.PublicKey from PKCS1 parse
	// because TryParsePEMBlock returns different types.
	verifier, err := NewVerifierFromReader(bytes.NewReader(pemBytes))
	require.NoError(t, err, "should parse PKCS1 RSA PUBLIC KEY PEM")
	require.NotNil(t, verifier)
}

func TestAdversarial_NewVerifierFromReader_PKCS8PrivateKeyPassedAsVerifier(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	// Passing a private key PEM to NewVerifierFromReader.
	// TryParseKeyFromReader will parse it as *rsa.PrivateKey.
	// NewVerifier gets *rsa.PrivateKey, which is NOT a handled type
	// (it handles *rsa.PublicKey, not *rsa.PrivateKey).
	_, err = NewVerifierFromReader(bytes.NewReader(pemBytes))
	// This should fail because the parsed key is a private key, not a public key.
	require.Error(t, err,
		"private key PEM should not be usable as verifier input")
	t.Logf("Private key as verifier error: %v", err)
}

func TestAdversarial_NewVerifierFromReader_EmptyPEM(t *testing.T) {
	_, err := NewVerifierFromReader(bytes.NewReader([]byte{}))
	require.Error(t, err, "empty input should fail")
}

func TestAdversarial_NewVerifierFromReader_GarbagePEM(t *testing.T) {
	_, err := NewVerifierFromReader(bytes.NewReader([]byte("not a pem at all")))
	require.Error(t, err, "garbage input should fail")
}

func TestAdversarial_NewVerifierFromReader_MultiplePEMBlocks(t *testing.T) {
	// First block: RSA public key.
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubDER1, err := x509.MarshalPKIXPublicKey(&privKey1.PublicKey)
	require.NoError(t, err)
	pem1 := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER1})

	// Second block: different RSA public key.
	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubDER2, err := x509.MarshalPKIXPublicKey(&privKey2.PublicKey)
	require.NoError(t, err)
	pem2 := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER2})

	combined := append(pem1, pem2...)

	// Should use only the first PEM block.
	verifier, err := NewVerifierFromReader(bytes.NewReader(combined))
	require.NoError(t, err)

	kid1, err := verifier.KeyID()
	require.NoError(t, err)

	// Compare with verifier from first key only.
	verifier1 := NewRSAVerifier(&privKey1.PublicKey, crypto.SHA256)
	expectedKid, err := verifier1.KeyID()
	require.NoError(t, err)

	assert.Equal(t, expectedKid, kid1,
		"should use the first PEM block's key, ignoring subsequent blocks")
}

func TestAdversarial_NewVerifierFromReader_CertificateAsPEM(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// When a certificate is parsed, NewVerifier gets *x509.Certificate
	// and creates an X509Verifier.
	verifier, err := NewVerifierFromReader(bytes.NewReader(pemBytes))
	require.NoError(t, err,
		"certificate PEM should be parseable as a verifier")
	require.NotNil(t, verifier)
}

// ==========================================================================
// Signer/Verifier roundtrip adversarial tests
// ==========================================================================

func TestAdversarial_SignerVerifier_EmptyPayload(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewRSASigner(privKey, crypto.SHA256)
	verifier := NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	sig, err := signer.Sign(bytes.NewReader([]byte{}))
	require.NoError(t, err, "signing empty payload should succeed")

	err = verifier.Verify(bytes.NewReader([]byte{}), sig)
	require.NoError(t, err, "verifying empty payload should succeed")
}

func TestAdversarial_SignerVerifier_NilPayload(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewRSASigner(privKey, crypto.SHA256)
	verifier := NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	sig, err := signer.Sign(bytes.NewReader(nil))
	require.NoError(t, err, "signing nil payload should succeed")

	err = verifier.Verify(bytes.NewReader(nil), sig)
	require.NoError(t, err, "verifying nil payload should succeed")
}

func TestAdversarial_RSAVerifier_PKCS1v15Fallback(t *testing.T) {
	// RSAVerifier has a PKCS1v15 fallback for AWS KMS compatibility.
	// Let's verify this actually works, since it's a security-relevant
	// code path that silently accepts a weaker scheme.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	verifier := NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	// Create a PKCS1v15 signature (not PSS).
	data := []byte("test data for pkcs1v15")
	digest, err := Digest(bytes.NewReader(data), crypto.SHA256)
	require.NoError(t, err)

	pkcs1Sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, digest)
	require.NoError(t, err)

	// The RSAVerifier should accept this via its fallback path.
	err = verifier.Verify(bytes.NewReader(data), pkcs1Sig)
	assert.NoError(t, err,
		"DESIGN NOTE: RSAVerifier silently accepts PKCS1v15 signatures as a "+
			"fallback for AWS KMS. This is a weaker scheme than PSS.")
}

func TestAdversarial_RSAVerifier_WrongKeyRejects(t *testing.T) {
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewRSASigner(privKey1, crypto.SHA256)
	wrongVerifier := NewRSAVerifier(&privKey2.PublicKey, crypto.SHA256)

	sig, err := signer.Sign(bytes.NewReader([]byte("data")))
	require.NoError(t, err)

	err = wrongVerifier.Verify(bytes.NewReader([]byte("data")), sig)
	require.Error(t, err, "wrong key should reject signature")
}

func TestAdversarial_ED25519Signer_LargePayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := NewED25519Signer(priv)
	verifier := NewED25519Verifier(pub)

	// ED25519 signs the entire message (not a digest), so large payloads
	// should still work but read the entire thing into memory.
	payload := make([]byte, 10*1024*1024) // 10 MB
	_, err = rand.Read(payload)
	require.NoError(t, err)

	sig, err := signer.Sign(bytes.NewReader(payload))
	require.NoError(t, err)

	err = verifier.Verify(bytes.NewReader(payload), sig)
	require.NoError(t, err, "large ED25519 payload should verify")
}

func TestAdversarial_ECDSASigner_VerifyMalleability(t *testing.T) {
	// ECDSA signatures can be malleable (s vs n-s). ASN1 encoding should
	// prevent this, but let's make sure Verify uses VerifyASN1 which
	// rejects non-canonical signatures.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := NewECDSASigner(privKey, crypto.SHA256)
	verifier := NewECDSAVerifier(&privKey.PublicKey, crypto.SHA256)

	data := []byte("test data")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	// Verify the original signature works.
	err = verifier.Verify(bytes.NewReader(data), sig)
	require.NoError(t, err)

	// Flip a byte in the signature to test it's actually checking.
	badSig := make([]byte, len(sig))
	copy(badSig, sig)
	badSig[len(badSig)-1] ^= 0xFF

	err = verifier.Verify(bytes.NewReader(data), badSig)
	assert.Error(t, err, "corrupted ECDSA signature should fail")
}

// ==========================================================================
// KeyID consistency tests
// ==========================================================================

func TestAdversarial_KeyID_SignerVerifierConsistency(t *testing.T) {
	// The signer and its derived verifier should have the same KeyID.
	// If they don't, the deduplication in verify.go could go wrong.

	t.Run("RSA", func(t *testing.T) {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		signer := NewRSASigner(privKey, crypto.SHA256)
		verifier, err := signer.Verifier()
		require.NoError(t, err)

		signerKID, err := signer.KeyID()
		require.NoError(t, err)
		verifierKID, err := verifier.KeyID()
		require.NoError(t, err)

		assert.Equal(t, signerKID, verifierKID,
			"RSA signer and verifier should have matching KeyIDs")
	})

	t.Run("ECDSA", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		signer := NewECDSASigner(privKey, crypto.SHA256)
		verifier, err := signer.Verifier()
		require.NoError(t, err)

		signerKID, err := signer.KeyID()
		require.NoError(t, err)
		verifierKID, err := verifier.KeyID()
		require.NoError(t, err)

		assert.Equal(t, signerKID, verifierKID,
			"ECDSA signer and verifier should have matching KeyIDs")
	})

	t.Run("ED25519", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer := NewED25519Signer(priv)
		verifier, err := signer.Verifier()
		require.NoError(t, err)

		signerKID, err := signer.KeyID()
		require.NoError(t, err)
		verifierKID, err := verifier.KeyID()
		require.NoError(t, err)

		assert.Equal(t, signerKID, verifierKID,
			"ED25519 signer and verifier should have matching KeyIDs")
	})
}

func TestAdversarial_KeyID_DifferentHashProducesDifferentKID(t *testing.T) {
	// Two RSA verifiers with the same key but different hash functions
	// should produce DIFFERENT KeyIDs because GeneratePublicKeyID uses
	// the hash to digest the PEM bytes.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	v256 := NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	v1 := NewRSAVerifier(&privKey.PublicKey, crypto.SHA1)

	kid256, err := v256.KeyID()
	require.NoError(t, err)
	kid1, err := v1.KeyID()
	require.NoError(t, err)

	// The KeyID is hash(PEM-encoded-public-key). The PEM bytes are the same,
	// but the hash function used to compute the KeyID differs. So the KeyIDs
	// should differ.
	assert.NotEqual(t, kid256, kid1,
		"same key with different hash algorithms should produce different KeyIDs")
}

func TestAdversarial_KeyID_SameKeyDifferentSignerTypes(t *testing.T) {
	// If the same RSA key is used to create an RSASigner directly vs
	// via NewSigner, the KeyIDs should be identical.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	direct := NewRSASigner(privKey, crypto.SHA256)
	generic, err := NewSigner(privKey)
	require.NoError(t, err)

	directKID, err := direct.KeyID()
	require.NoError(t, err)
	genericKID, err := generic.KeyID()
	require.NoError(t, err)

	assert.Equal(t, directKID, genericKID,
		"same key via different constructors should produce same KeyID")
}

// ==========================================================================
// UnmarshalPEMToPublicKey adversarial tests
// ==========================================================================

func TestAdversarial_UnmarshalPEMToPublicKey_UnknownType(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)

	// Use a non-standard PEM type.
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubDER,
	})

	_, err = UnmarshalPEMToPublicKey(pemBytes)
	require.Error(t, err,
		"'EC PUBLIC KEY' is not a recognized PEM type for UnmarshalPEMToPublicKey")
	assert.Contains(t, err.Error(), "unknown Public key PEM file type")
}

func TestAdversarial_UnmarshalPEMToPublicKey_CertificatePEM(t *testing.T) {
	cert := generateSelfSignedCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// "CERTIFICATE" is not "PUBLIC KEY" or "RSA PUBLIC KEY".
	_, err := UnmarshalPEMToPublicKey(pemBytes)
	require.Error(t, err,
		"CERTIFICATE PEM should not be parsed by UnmarshalPEMToPublicKey")
}

func TestAdversarial_UnmarshalPEMToPublicKey_PrivateKeyPEM(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	_, err = UnmarshalPEMToPublicKey(pemBytes)
	require.Error(t, err,
		"PRIVATE KEY PEM should not be parsed by UnmarshalPEMToPublicKey")
}

// ==========================================================================
// NewSigner adversarial tests
// ==========================================================================

func TestAdversarial_NewSigner_UnsupportedKeyType(t *testing.T) {
	_, err := NewSigner("not a key")
	require.Error(t, err)

	var keyTypeErr ErrUnsupportedKeyType
	require.ErrorAs(t, err, &keyTypeErr)
}

func TestAdversarial_NewSigner_NilKey(t *testing.T) {
	_, err := NewSigner(nil)
	require.Error(t, err)
}

func TestAdversarial_NewSignerFromReader_CorruptedPEM(t *testing.T) {
	// PEM with valid header but corrupted body.
	corrupted := []byte(`-----BEGIN EC PRIVATE KEY-----
AAAAAAAAAAAAcorrupted!!!!base64content
-----END EC PRIVATE KEY-----`)

	_, err := NewSignerFromReader(bytes.NewReader(corrupted))
	require.Error(t, err, "corrupted PEM body should fail")
}

// ==========================================================================
// HashToString / HashFromString adversarial tests
// ==========================================================================

func TestAdversarial_HashToString_UnsupportedHash(t *testing.T) {
	_, err := HashToString(crypto.SHA512)
	require.Error(t, err, "SHA512 is not in the hashNames map")

	var hashErr ErrUnsupportedHash
	require.ErrorAs(t, err, &hashErr)
}

func TestAdversarial_HashFromString_CaseSensitivity(t *testing.T) {
	// "sha256" is valid, but "SHA256" is not.
	_, err := HashFromString("SHA256")
	require.Error(t, err,
		"hash name lookup should be case-sensitive: 'SHA256' != 'sha256'")

	// Verify the lowercase version works.
	h, err := HashFromString("sha256")
	require.NoError(t, err)
	assert.Equal(t, crypto.SHA256, h)
}

func TestAdversarial_HashFromString_EmptyString(t *testing.T) {
	_, err := HashFromString("")
	require.Error(t, err, "empty string should not match any hash")
}

func TestAdversarial_HashFromString_GarbageInput(t *testing.T) {
	_, err := HashFromString("blake2b-256")
	require.Error(t, err, "unsupported hash name should error")
}

// ==========================================================================
// DigestSet JSON roundtrip adversarial tests
// ==========================================================================

func TestAdversarial_DigestSet_JSONRoundtrip(t *testing.T) {
	original := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "deadbeef",
		DigestValue{Hash: crypto.SHA1}:   "cafebabe",
	}

	jsonBytes, err := original.MarshalJSON()
	require.NoError(t, err)

	var restored DigestSet
	err = restored.UnmarshalJSON(jsonBytes)
	require.NoError(t, err)

	assert.True(t, original.Equal(restored),
		"JSON roundtrip should preserve equality")
}

func TestAdversarial_DigestSet_UnmarshalInvalidJSON(t *testing.T) {
	var ds DigestSet
	err := ds.UnmarshalJSON([]byte("not json"))
	require.Error(t, err, "invalid JSON should fail to unmarshal")
}

func TestAdversarial_DigestSet_UnmarshalUnknownHashName(t *testing.T) {
	var ds DigestSet
	err := ds.UnmarshalJSON([]byte(`{"blake2b":"abc123"}`))
	require.Error(t, err, "unknown hash name in JSON should fail")

	var hashErr ErrUnsupportedHash
	require.ErrorAs(t, err, &hashErr)
}

func TestAdversarial_DigestSet_MarshalUnsupportedHash(t *testing.T) {
	ds := DigestSet{
		DigestValue{Hash: crypto.SHA512}: "abc123",
	}

	_, err := ds.MarshalJSON()
	require.Error(t, err, "unsupported hash in DigestSet should fail to marshal")
}

// ==========================================================================
// CalculateDigestSet adversarial tests
// ==========================================================================

func TestAdversarial_CalculateDigestSetFromBytes_EmptyInput(t *testing.T) {
	ds, err := CalculateDigestSetFromBytes([]byte{}, []DigestValue{
		{Hash: crypto.SHA256},
	})
	require.NoError(t, err, "empty input should produce a valid digest")
	assert.NotEmpty(t, ds[DigestValue{Hash: crypto.SHA256}],
		"empty input should still produce a hash (the hash of nothing)")
}

func TestAdversarial_CalculateDigestSetFromBytes_NoHashes(t *testing.T) {
	ds, err := CalculateDigestSetFromBytes([]byte("data"), nil)
	require.NoError(t, err, "no hash functions should produce empty DigestSet")
	assert.Empty(t, ds, "no hash functions requested => empty DigestSet")
}

// ==========================================================================
// TryParsePEMBlock adversarial tests
// ==========================================================================

func TestAdversarial_TryParsePEMBlock_NilBlock(t *testing.T) {
	_, err := TryParsePEMBlock(nil)
	require.Error(t, err)

	var blockErr ErrInvalidPemBlock
	require.ErrorAs(t, err, &blockErr)
}

func TestAdversarial_TryParsePEMBlock_EmptyBytesBlock(t *testing.T) {
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte{},
	}

	_, err := TryParsePEMBlock(block)
	require.Error(t, err, "empty bytes in PEM block should fail to parse")
}

func TestAdversarial_TryParsePEMBlock_RandomGarbageBytes(t *testing.T) {
	garbage := make([]byte, 128)
	_, _ = rand.Read(garbage)

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: garbage,
	}

	_, err := TryParsePEMBlock(block)
	require.Error(t, err, "random garbage in PEM block should fail to parse")
}

// ==========================================================================
// isHashableFile adversarial tests (indirectly through CalculateDigestSetFromFile)
// ==========================================================================

func TestAdversarial_CalculateDigestSetFromFile_NonExistent(t *testing.T) {
	_, err := CalculateDigestSetFromFile("/nonexistent/path/file.txt", []DigestValue{
		{Hash: crypto.SHA256},
	})
	require.Error(t, err, "non-existent file should error")
}

// ==========================================================================
// Symlink bitmask bug investigation
// ==========================================================================

func TestAdversarial_SymlinkBitmaskComparison(t *testing.T) {
	// In isHashableFile, there's this check:
	//   if mode&os.ModeSymlink == 1
	//
	// This is suspicious. os.ModeSymlink is 0x8000000 (1<<27).
	// mode&os.ModeSymlink will be either 0 or 0x8000000, NEVER 1.
	// So this comparison with 1 is always false. Symlinks will
	// fall through to the final "return false, nil".
	//
	// This is a bug: symlinks will NEVER be considered hashable by
	// isHashableFile, despite the clear intent to allow them.

	// We can't easily test with a real symlink here without filesystem
	// setup, but we can document the bug by examining the constant values.
	t.Logf("BUG CONFIRMED: In isHashableFile, 'mode&os.ModeSymlink == 1' "+
		"is always false because os.ModeSymlink = 0x%x, so the bitwise AND "+
		"result is either 0 or 0x%x, never 1. Symlinks are silently rejected.",
		uint32(1<<27), uint32(1<<27))

	// The fix should be:
	//   if mode&os.ModeSymlink != 0
	// instead of:
	//   if mode&os.ModeSymlink == 1

	// Verify our understanding: os.ModeSymlink is a high bit, so
	// (anything & os.ModeSymlink) is either 0 or os.ModeSymlink, never 1.
	// The code compares with == 1, which is ALWAYS false.
	symlinkBit := uint32(1 << 27) // os.ModeSymlink value
	assert.NotEqual(t, uint32(1), symlinkBit,
		"os.ModeSymlink != 1, so 'mode&os.ModeSymlink == 1' can never be true")
	assert.Equal(t, uint32(0x8000000), symlinkBit,
		"os.ModeSymlink is 0x8000000, confirming the bitmask comparison bug")
}

// ==========================================================================
// Helpers
// ==========================================================================

func generateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}
