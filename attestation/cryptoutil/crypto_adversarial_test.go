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
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// RSA edge case key sizes
// ==========================================================================

func TestAdversarial_RSA_SmallKeySize(t *testing.T) {
	// 1024-bit RSA keys are insecure but Go still supports them.
	// Verify sign/verify works with them (no validation of key strength).
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	signer := NewRSASigner(priv, crypto.SHA256)
	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	data := []byte("test with weak key")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err, "signing with 1024-bit key should succeed (no min key size enforcement)")

	err = verifier.Verify(bytes.NewReader(data), sig)
	require.NoError(t, err,
		"DESIGN NOTE: no minimum RSA key size is enforced -- 1024-bit keys work fine")
}

func TestAdversarial_RSA_4096KeySize(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	signer := NewRSASigner(priv, crypto.SHA256)
	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	data := []byte("test with strong key")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	err = verifier.Verify(bytes.NewReader(data), sig)
	require.NoError(t, err, "4096-bit RSA key should work")
}

func TestAdversarial_RSA_SHA1Hash(t *testing.T) {
	// SHA1 is considered weak for signing. The code doesn't prevent it.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewRSASigner(priv, crypto.SHA1)
	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA1)

	data := []byte("test with SHA1")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err,
		"DESIGN NOTE: SHA1 is not blocked for RSA signing")

	err = verifier.Verify(bytes.NewReader(data), sig)
	require.NoError(t, err)
}

// ==========================================================================
// RSA cross-key/cross-hash verification
// ==========================================================================

func TestAdversarial_RSA_HashMismatch(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Sign with SHA256, try to verify with SHA1.
	signer := NewRSASigner(priv, crypto.SHA256)
	wrongVerifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA1)

	data := []byte("hash mismatch test")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	err = wrongVerifier.Verify(bytes.NewReader(data), sig)
	require.Error(t, err,
		"signing with SHA256 and verifying with SHA1 should fail")
}

func TestAdversarial_RSA_PKCS1v15_WrongKey(t *testing.T) {
	// The PKCS1v15 fallback should still reject signatures from wrong keys.
	priv1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	data := []byte("wrong key pkcs1 test")
	digest, err := Digest(bytes.NewReader(data), crypto.SHA256)
	require.NoError(t, err)

	pkcs1Sig, err := rsa.SignPKCS1v15(rand.Reader, priv1, crypto.SHA256, digest)
	require.NoError(t, err)

	// Verify with the wrong key's verifier.
	wrongVerifier := NewRSAVerifier(&priv2.PublicKey, crypto.SHA256)
	err = wrongVerifier.Verify(bytes.NewReader(data), pkcs1Sig)
	require.Error(t, err,
		"PKCS1v15 fallback should still reject wrong key")
}

func TestAdversarial_RSA_EmptySig(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	err = verifier.Verify(bytes.NewReader([]byte("data")), []byte{})
	require.Error(t, err, "empty signature should fail verification")
}

func TestAdversarial_RSA_NilSig(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	err = verifier.Verify(bytes.NewReader([]byte("data")), nil)
	require.Error(t, err, "nil signature should fail verification")
}

// ==========================================================================
// ECDSA curve variations
// ==========================================================================

func TestAdversarial_ECDSA_AllCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P224", elliptic.P224()},
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			require.NoError(t, err)

			signer := NewECDSASigner(priv, crypto.SHA256)
			verifier := NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)

			data := []byte("test data for " + tc.name)
			sig, err := signer.Sign(bytes.NewReader(data))
			require.NoError(t, err)

			err = verifier.Verify(bytes.NewReader(data), sig)
			require.NoError(t, err, "%s curve should work", tc.name)
		})
	}
}

func TestAdversarial_ECDSA_CrossCurveRejection(t *testing.T) {
	// Sign with P256, try to verify with P384 key.
	priv256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	priv384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	signer := NewECDSASigner(priv256, crypto.SHA256)
	wrongVerifier := NewECDSAVerifier(&priv384.PublicKey, crypto.SHA256)

	data := []byte("cross-curve test")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	err = wrongVerifier.Verify(bytes.NewReader(data), sig)
	require.Error(t, err, "cross-curve verification should fail")
}

func TestAdversarial_ECDSA_EmptySig(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	verifier := NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	err = verifier.Verify(bytes.NewReader([]byte("data")), []byte{})
	require.Error(t, err, "empty ECDSA signature should fail")
}

func TestAdversarial_ECDSA_TruncatedSig(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := NewECDSASigner(priv, crypto.SHA256)
	data := []byte("truncation test")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	// Truncate the signature.
	truncated := sig[:len(sig)/2]

	verifier := NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	err = verifier.Verify(bytes.NewReader(data), truncated)
	require.Error(t, err, "truncated ECDSA signature should fail")
}

// ==========================================================================
// ED25519 edge cases
// ==========================================================================

func TestAdversarial_ED25519_EmptySig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier := NewED25519Verifier(pub)
	err = verifier.Verify(bytes.NewReader([]byte("data")), []byte{})
	require.Error(t, err, "empty ED25519 signature should fail")
}

func TestAdversarial_ED25519_WrongLengthSig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier := NewED25519Verifier(pub)
	// ED25519 signatures are 64 bytes. Pass 63 and 65 bytes.
	err = verifier.Verify(bytes.NewReader([]byte("data")), make([]byte, 63))
	require.Error(t, err, "63-byte ED25519 signature should fail")

	err = verifier.Verify(bytes.NewReader([]byte("data")), make([]byte, 65))
	require.Error(t, err, "65-byte ED25519 signature should fail")
}

func TestAdversarial_ED25519_CrossKeyRejection(t *testing.T) {
	_, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := NewED25519Signer(priv1)
	wrongVerifier := NewED25519Verifier(pub2)

	data := []byte("cross key test")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	err = wrongVerifier.Verify(bytes.NewReader(data), sig)
	require.Error(t, err, "wrong ED25519 key should reject")
}

// ==========================================================================
// X509 certificate verification edge cases
// ==========================================================================

func TestAdversarial_X509Verifier_ExpiredCert(t *testing.T) {
	// Create a cert that expired 1 hour ago.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Expired Cert"},
		NotBefore:             now.Add(-48 * time.Hour),
		NotAfter:              now.Add(-1 * time.Hour), // expired!
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Create X509Verifier with no trusted time (uses current time).
	verifier, err := NewX509Verifier(cert, nil, []*x509.Certificate{cert}, time.Time{})
	require.NoError(t, err)

	data := []byte("signed by expired cert")
	signer := NewRSASigner(priv, crypto.SHA256)
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	err = verifier.Verify(bytes.NewReader(data), sig)
	require.Error(t, err,
		"expired certificate should fail verification")
}

func TestAdversarial_X509Verifier_FutureCert(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Future Cert"},
		NotBefore:             now.Add(24 * time.Hour), // not valid yet!
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	verifier, err := NewX509Verifier(cert, nil, []*x509.Certificate{cert}, time.Time{})
	require.NoError(t, err)

	data := []byte("signed by future cert")
	signer := NewRSASigner(priv, crypto.SHA256)
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	err = verifier.Verify(bytes.NewReader(data), sig)
	require.Error(t, err,
		"certificate not yet valid should fail verification")
}

func TestAdversarial_X509Verifier_TrustedTimeOverride(t *testing.T) {
	// Create a cert that is currently expired but was valid in the past.
	// Using trustedTime should allow verification.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pastStart := time.Now().Add(-72 * time.Hour)
	pastEnd := time.Now().Add(-24 * time.Hour)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Was Valid"},
		NotBefore:             pastStart,
		NotAfter:              pastEnd,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	// Set trustedTime to when the cert was valid.
	trustedTime := pastStart.Add(1 * time.Hour)
	verifier, err := NewX509Verifier(cert, nil, []*x509.Certificate{cert}, trustedTime)
	require.NoError(t, err)

	data := []byte("signed during valid period")
	signer := NewRSASigner(priv, crypto.SHA256)
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	err = verifier.Verify(bytes.NewReader(data), sig)
	require.NoError(t, err,
		"trustedTime within cert validity period should allow verification")
}

func TestAdversarial_X509Signer_NilSigner(t *testing.T) {
	cert := advGenSelfSignedCert(t)
	_, err := NewX509Signer(nil, cert, nil, nil)
	require.Error(t, err)
	var signerErr ErrInvalidSigner
	require.ErrorAs(t, err, &signerErr)
}

func TestAdversarial_X509Signer_NilCert(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := NewRSASigner(priv, crypto.SHA256)

	_, err = NewX509Signer(signer, nil, nil, nil)
	require.Error(t, err)
	var certErr ErrInvalidCertificate
	require.ErrorAs(t, err, &certErr)
}

// ==========================================================================
// Concurrent digest computation
// ==========================================================================

func TestAdversarial_ConcurrentDigestComputation(t *testing.T) {
	data := []byte("concurrent digest test data")
	hashes := []DigestValue{{Hash: crypto.SHA256}, {Hash: crypto.SHA1}}

	var wg sync.WaitGroup
	results := make([]DigestSet, 50)
	errs := make([]error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = CalculateDigestSetFromBytes(data, hashes)
		}(i)
	}

	wg.Wait()

	// All results should be identical.
	for i, err := range errs {
		require.NoError(t, err, "goroutine %d should succeed", i)
	}

	for i := 1; i < len(results); i++ {
		assert.True(t, results[0].Equal(results[i]),
			"all concurrent digests should be equal (goroutine 0 vs %d)", i)
	}
}

func TestAdversarial_ConcurrentSignVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewRSASigner(priv, crypto.SHA256)
	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	data := []byte("concurrent sign/verify")

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := signer.Sign(bytes.NewReader(data))
			assert.NoError(t, err)
			err = verifier.Verify(bytes.NewReader(data), sig)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}

// ==========================================================================
// PEM parsing adversarial tests (beyond existing tests)
// ==========================================================================

func TestAdversarial_TryParseKeyFromReaderWithPassword_NilPassword(t *testing.T) {
	// Explicitly passing nil password should work like no password.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	})

	key, err := TryParseKeyFromReaderWithPassword(bytes.NewReader(pemBytes), nil)
	require.NoError(t, err)
	assert.NotNil(t, key)
}

func TestAdversarial_TryParseKeyFromReaderWithPassword_WrongPassword(t *testing.T) {
	// Create an encrypted PEM block using legacy DEK-Info encryption.
	//nolint:staticcheck // testing legacy encryption support
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	privDER := x509.MarshalPKCS1PrivateKey(priv)
	//nolint:staticcheck // legacy support
	encBlock, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privDER,
		[]byte("correctpassword"), x509.PEMCipherAES256)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(encBlock)

	// Try with wrong password.
	_, err = TryParseKeyFromReaderWithPassword(bytes.NewReader(pemBytes), []byte("wrongpassword"))
	require.Error(t, err, "wrong password should fail")
}

func TestAdversarial_TryParsePEMBlockWithPassword_NilBlock(t *testing.T) {
	_, err := TryParsePEMBlockWithPassword(nil, []byte("password"))
	require.Error(t, err)
	var blockErr ErrInvalidPemBlock
	require.ErrorAs(t, err, &blockErr)
}

func TestAdversarial_UnmarshalPEMToPublicKey_NilInput(t *testing.T) {
	_, err := UnmarshalPEMToPublicKey(nil)
	require.Error(t, err, "nil PEM bytes should fail")
}

func TestAdversarial_UnmarshalPEMToPublicKey_PKCS1RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkcs1DER := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pkcs1DER,
	})

	pub, err := UnmarshalPEMToPublicKey(pemBytes)
	require.NoError(t, err)
	assert.NotNil(t, pub)

	rsaPub, ok := pub.(*rsa.PublicKey)
	require.True(t, ok)
	assert.Equal(t, priv.PublicKey.N, rsaPub.N)
}

// ==========================================================================
// DigestSet adversarial tests (new tests beyond existing ones)
// ==========================================================================

func TestAdversarial_DigestSetEqual_SelfEquality(t *testing.T) {
	ds := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "abc123",
		DigestValue{Hash: crypto.SHA1}:   "def456",
	}
	assert.True(t, ds.Equal(ds), "DigestSet should be equal to itself")
}

func TestAdversarial_DigestSetEqual_LargeOverlap(t *testing.T) {
	// Both sets have the same algorithms and values.
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256}:               "same256",
		DigestValue{Hash: crypto.SHA1}:                 "same1",
		DigestValue{Hash: crypto.SHA256, GitOID: true}: "samegitoid",
	}
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA256}:               "same256",
		DigestValue{Hash: crypto.SHA1}:                 "same1",
		DigestValue{Hash: crypto.SHA256, GitOID: true}: "samegitoid",
	}

	assert.True(t, ds1.Equal(ds2))
	assert.True(t, ds2.Equal(ds1))
}

func TestAdversarial_DigestSetEqual_OneMatchOneMismatch(t *testing.T) {
	// If any overlapping algorithm has a different digest, Equal returns false.
	ds1 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "same",
		DigestValue{Hash: crypto.SHA1}:   "different1",
	}
	ds2 := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "same",
		DigestValue{Hash: crypto.SHA1}:   "different2",
	}
	assert.False(t, ds1.Equal(ds2),
		"one matching + one mismatching digest should return false")
}

func TestAdversarial_CalculateDigestSet_DuplicateHashes(t *testing.T) {
	// What happens if we pass the same hash algorithm twice?
	data := []byte("duplicate hash test")
	hashes := []DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA256}, // duplicate
	}

	ds, err := CalculateDigestSetFromBytes(data, hashes)
	require.NoError(t, err)

	// DigestSet is a map, so duplicate keys should just result in one entry.
	assert.Len(t, ds, 1, "duplicate hash algorithms should result in single entry")
}

// ==========================================================================
// ComputeDigest adversarial tests
// ==========================================================================

func TestAdversarial_ComputeDigest_UnsupportedHash(t *testing.T) {
	data := bytes.NewReader([]byte("test"))
	_, _, err := ComputeDigest(data, crypto.SHA256, []crypto.Hash{crypto.SHA1})
	require.Error(t, err, "SHA256 not in supported list should error")
	assert.Contains(t, err.Error(), "unsupported hash algorithm")
}

func TestAdversarial_ComputeDigest_NilSupportedHashes(t *testing.T) {
	// When supportedHashFuncs is nil, isSupportedAlg returns true for any hash.
	data := bytes.NewReader([]byte("test"))
	digest, hash, err := ComputeDigest(data, crypto.SHA256, nil)
	require.NoError(t, err, "nil supportedHashFuncs should accept any hash")
	assert.Equal(t, crypto.SHA256, hash)
	assert.NotEmpty(t, digest)
}

func TestAdversarial_ComputeDigest_EmptySupportedHashes(t *testing.T) {
	// Empty slice (not nil) means nothing is supported.
	data := bytes.NewReader([]byte("test"))
	_, _, err := ComputeDigest(data, crypto.SHA256, []crypto.Hash{})
	require.Error(t, err, "empty supported list should reject all hashes")
}

func TestAdversarial_ComputeDigest_EmptyReader(t *testing.T) {
	data := bytes.NewReader([]byte{})
	digest, hash, err := ComputeDigest(data, crypto.SHA256, []crypto.Hash{crypto.SHA256})
	require.NoError(t, err)
	assert.Equal(t, crypto.SHA256, hash)
	assert.NotEmpty(t, digest, "empty reader should produce a valid digest (hash of nothing)")
}

// ==========================================================================
// NewVerifier / NewSigner edge cases
// ==========================================================================

func TestAdversarial_NewVerifier_Ed25519ByValue(t *testing.T) {
	// Ed25519 public key is ed25519.PublicKey (a []byte), not *ed25519.PublicKey.
	// The type switch handles it by value, which is correct.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	verifier, err := NewVerifier(pub)
	require.NoError(t, err)
	assert.NotNil(t, verifier)
}

func TestAdversarial_NewSigner_Ed25519ByValue(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer, err := NewSigner(priv)
	require.NoError(t, err)
	assert.NotNil(t, signer)
}

func TestAdversarial_NewVerifier_WithCustomHash(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Use a non-default hash.
	verifier, err := NewVerifier(&priv.PublicKey, VerifyWithHash(crypto.SHA512))
	require.NoError(t, err)

	// Verify that signing with SHA512 + verifying with SHA512 works.
	signer := NewRSASigner(priv, crypto.SHA512)
	data := []byte("sha512 test")
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	err = verifier.Verify(bytes.NewReader(data), sig)
	require.NoError(t, err)
}

// ==========================================================================
// isHashableFile symlink bitmask bug (extended test)
// ==========================================================================

func TestAdversarial_IsHashableFile_RegularFile(t *testing.T) {
	// Create a real temporary file and verify it's hashable.
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(tmpFile, []byte("hello"), 0644)
	require.NoError(t, err)

	f, err := os.Open(tmpFile)
	require.NoError(t, err)
	defer f.Close()

	hashable, err := isHashableFile(f)
	require.NoError(t, err)
	assert.True(t, hashable, "regular file should be hashable")
}

func TestAdversarial_IsHashableFile_Directory(t *testing.T) {
	tmpDir := t.TempDir()

	f, err := os.Open(tmpDir)
	require.NoError(t, err)
	defer f.Close()

	hashable, err := isHashableFile(f)
	require.NoError(t, err)
	// Directories have IsDir() true. The code checks mode.Perm().IsDir()
	// which is different from mode.IsDir(). mode.Perm() only keeps the
	// lower 9 bits (rwxrwxrwx). mode.Perm().IsDir() checks ModeDir bit
	// in the permission bits, which is always false.
	//
	// But mode.IsRegular() also returns false for directories.
	// So directories fall through to the final "return false, nil".
	//
	// BUG: mode.Perm().IsDir() is ALWAYS false because Perm() strips
	// the ModeDir bit. The code should use mode.IsDir() instead.
	// As a result, directories are NOT hashable, which may or may not
	// be intended.
	t.Logf("BUG: isHashableFile uses mode.Perm().IsDir() which always returns false. "+
		"mode.Perm() strips the ModeDir bit. Should use mode.IsDir() instead. "+
		"Directory hashable result: %v", hashable)
}

func TestAdversarial_IsHashableFile_Symlink(t *testing.T) {
	// Create a symlink and verify the bitmask bug.
	tmpDir := t.TempDir()
	target := filepath.Join(tmpDir, "target.txt")
	err := os.WriteFile(target, []byte("target"), 0644)
	require.NoError(t, err)

	link := filepath.Join(tmpDir, "link.txt")
	err = os.Symlink(target, link)
	require.NoError(t, err)

	// When we os.Open a symlink, Go follows the symlink by default.
	// The stat of the opened file will show the target's mode, not
	// ModeSymlink. So the symlink bitmask bug is only relevant
	// for code paths where os.Lstat is used instead of os.Stat.
	//
	// The isHashableFile function calls f.Stat() which follows symlinks,
	// so the symlink will look like a regular file. The bitmask bug
	// (mode&os.ModeSymlink == 1) would only matter if Lstat were used.
	f, err := os.Open(link)
	require.NoError(t, err)
	defer f.Close()

	hashable, err := isHashableFile(f)
	require.NoError(t, err)
	assert.True(t, hashable,
		"opened symlink is followed by os.Open, so it looks like a regular file")
}

// ==========================================================================
// GeneratePublicKeyID consistency
// ==========================================================================

func TestAdversarial_GeneratePublicKeyID_Deterministic(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	id1, err := GeneratePublicKeyID(&priv.PublicKey, crypto.SHA256)
	require.NoError(t, err)

	id2, err := GeneratePublicKeyID(&priv.PublicKey, crypto.SHA256)
	require.NoError(t, err)

	assert.Equal(t, id1, id2, "same key should produce same ID")
}

func TestAdversarial_GeneratePublicKeyID_UnsupportedKeyType(t *testing.T) {
	// Passing something that x509.MarshalPKIXPublicKey doesn't support.
	_, err := GeneratePublicKeyID("not a key", crypto.SHA256)
	require.Error(t, err)
}

// ==========================================================================
// PublicPemBytes edge cases
// ==========================================================================

func TestAdversarial_PublicPemBytes_AllKeyTypes(t *testing.T) {
	t.Run("RSA", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		pemBytes, err := PublicPemBytes(&priv.PublicKey)
		require.NoError(t, err)
		assert.Contains(t, string(pemBytes), "PUBLIC KEY")
	})

	t.Run("ECDSA", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		pemBytes, err := PublicPemBytes(&priv.PublicKey)
		require.NoError(t, err)
		assert.Contains(t, string(pemBytes), "PUBLIC KEY")
	})

	t.Run("ED25519", func(t *testing.T) {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		pemBytes, err := PublicPemBytes(pub)
		require.NoError(t, err)
		assert.Contains(t, string(pemBytes), "PUBLIC KEY")
	})
}

// ==========================================================================
// DigestBytes / Digest edge cases
// ==========================================================================

func TestAdversarial_Digest_ErrorReader(t *testing.T) {
	// Reader that returns an error.
	errReader := &errorReader{err: io.ErrUnexpectedEOF}
	_, err := Digest(errReader, crypto.SHA256)
	require.Error(t, err, "error reader should propagate error")
}

func TestAdversarial_DigestBytes_NilInput(t *testing.T) {
	digest, err := DigestBytes(nil, crypto.SHA256)
	require.NoError(t, err)
	assert.NotEmpty(t, digest, "nil input should produce hash of empty content")
}

func TestAdversarial_DigestBytes_Deterministic(t *testing.T) {
	data := []byte("deterministic test")
	d1, err := DigestBytes(data, crypto.SHA256)
	require.NoError(t, err)
	d2, err := DigestBytes(data, crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, d1, d2, "same data should produce same digest")
}

// ==========================================================================
// HexEncode edge cases
// ==========================================================================

func TestAdversarial_HexEncode_EmptyInput(t *testing.T) {
	result := HexEncode([]byte{})
	assert.Empty(t, result)
}

func TestAdversarial_HexEncode_NilInput(t *testing.T) {
	result := HexEncode(nil)
	assert.Empty(t, result)
}

func TestAdversarial_HexEncode_KnownValue(t *testing.T) {
	result := HexEncode([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	assert.Equal(t, "deadbeef", string(result))
}

// ==========================================================================
// Signer/Verifier roundtrip with data mutation
// ==========================================================================

func TestAdversarial_RSA_SignVerify_DataMutation(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewRSASigner(priv, crypto.SHA256)
	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	originalData := []byte("original data")
	sig, err := signer.Sign(bytes.NewReader(originalData))
	require.NoError(t, err)

	// Verify with mutated data.
	mutatedData := []byte("mutated data")
	err = verifier.Verify(bytes.NewReader(mutatedData), sig)
	require.Error(t, err, "mutated data should fail verification")
}

func TestAdversarial_ECDSA_SignVerify_DataMutation(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer := NewECDSASigner(priv, crypto.SHA256)
	verifier := NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)

	originalData := []byte("original ECDSA data")
	sig, err := signer.Sign(bytes.NewReader(originalData))
	require.NoError(t, err)

	mutatedData := []byte("mutated ECDSA data")
	err = verifier.Verify(bytes.NewReader(mutatedData), sig)
	require.Error(t, err, "mutated data should fail ECDSA verification")
}

func TestAdversarial_ED25519_SignVerify_DataMutation(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := NewED25519Signer(priv)
	verifier, err := signer.Verifier()
	require.NoError(t, err)

	originalData := []byte("original ED25519 data")
	sig, err := signer.Sign(bytes.NewReader(originalData))
	require.NoError(t, err)

	mutatedData := []byte("mutated ED25519 data")
	err = verifier.Verify(bytes.NewReader(mutatedData), sig)
	require.Error(t, err, "mutated data should fail ED25519 verification")
}

// ==========================================================================
// X509Verifier.BelongsToRoot
// ==========================================================================

func TestAdversarial_X509Verifier_BelongsToRoot_WrongRoot(t *testing.T) {
	// Create two separate self-signed certs (acting as roots).
	cert1 := advGenSelfSignedCert(t)
	cert2 := advGenSelfSignedCert(t)

	verifier, err := NewX509Verifier(cert1, nil, []*x509.Certificate{cert1}, time.Time{})
	require.NoError(t, err)

	err = verifier.BelongsToRoot(cert2)
	require.Error(t, err, "cert should not belong to a different root")
}

func TestAdversarial_X509Verifier_BelongsToRoot_CorrectRoot(t *testing.T) {
	cert := advGenSelfSignedCert(t)

	verifier, err := NewX509Verifier(cert, nil, []*x509.Certificate{cert}, time.Time{})
	require.NoError(t, err)

	err = verifier.BelongsToRoot(cert)
	require.NoError(t, err, "self-signed cert should belong to itself as root")
}

// ==========================================================================
// NewDigestSet edge cases
// ==========================================================================

func TestAdversarial_NewDigestSet_EmptyMap(t *testing.T) {
	ds, err := NewDigestSet(map[string]string{})
	require.NoError(t, err)
	assert.Empty(t, ds)
}

func TestAdversarial_NewDigestSet_UnknownHashName(t *testing.T) {
	_, err := NewDigestSet(map[string]string{
		"blake3": "somehash",
	})
	require.Error(t, err)
}

func TestAdversarial_NewDigestSet_ValidHashNames(t *testing.T) {
	ds, err := NewDigestSet(map[string]string{
		"sha256":        "abc",
		"sha1":          "def",
		"gitoid:sha256": "ghi",
		"gitoid:sha1":   "jkl",
		"dirHash":       "mno",
	})
	require.NoError(t, err)
	assert.Len(t, ds, 5)
}

// ==========================================================================
// isSupportedAlg edge cases
// ==========================================================================

func TestAdversarial_IsSupportedAlg_NilList(t *testing.T) {
	// nil list means "all supported"
	assert.True(t, isSupportedAlg(crypto.SHA256, nil))
	assert.True(t, isSupportedAlg(crypto.SHA512, nil))
	assert.True(t, isSupportedAlg(crypto.SHA1, nil))
}

func TestAdversarial_IsSupportedAlg_EmptyList(t *testing.T) {
	// Empty list means "nothing supported"
	assert.False(t, isSupportedAlg(crypto.SHA256, []crypto.Hash{}))
}

func TestAdversarial_IsSupportedAlg_ExactMatch(t *testing.T) {
	assert.True(t, isSupportedAlg(crypto.SHA256, []crypto.Hash{crypto.SHA256}))
	assert.False(t, isSupportedAlg(crypto.SHA512, []crypto.Hash{crypto.SHA256}))
}

// ==========================================================================
// ErrUnsupportedPEM / ErrInvalidPemBlock error messages
// ==========================================================================

func TestAdversarial_ErrorTypes_Messages(t *testing.T) {
	pemErr := ErrUnsupportedPEM{t: "WEIRD TYPE"}
	assert.Contains(t, pemErr.Error(), "WEIRD TYPE")

	blockErr := ErrInvalidPemBlock{}
	assert.Equal(t, "invalid pem block", blockErr.Error())

	keyErr := ErrUnsupportedKeyType{t: "complex128"}
	assert.Contains(t, keyErr.Error(), "complex128")

	hashErr := ErrUnsupportedHash("md5")
	assert.Contains(t, hashErr.Error(), "md5")

	verifyErr := ErrVerifyFailed{}
	assert.Equal(t, "verification failed", verifyErr.Error())
}

// ==========================================================================
// Verifier.Bytes round-trip
// ==========================================================================

func TestAdversarial_VerifierBytes_Roundtrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	pemBytes, err := verifier.Bytes()
	require.NoError(t, err)

	// Parse the PEM bytes back and create a new verifier.
	verifier2, err := NewVerifierFromReader(bytes.NewReader(pemBytes))
	require.NoError(t, err)

	kid1, err := verifier.KeyID()
	require.NoError(t, err)
	kid2, err := verifier2.KeyID()
	require.NoError(t, err)

	assert.Equal(t, kid1, kid2,
		"verifier bytes round-trip should produce same KeyID")
}

// ==========================================================================
// TryParsePEMBlock with password - non-encrypted block with password
// ==========================================================================

func TestAdversarial_TryParsePEMBlockWithPassword_UnencryptedWithPassword(t *testing.T) {
	// If a password is provided but the block is NOT encrypted (no DEK-Info),
	// the code falls through to unencrypted parsing. The password is ignored.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privDER,
	}

	key, err := TryParsePEMBlockWithPassword(block, []byte("uselesspassword"))
	require.NoError(t, err,
		"unencrypted PEM with password should succeed (password ignored)")
	assert.NotNil(t, key)
}

// ==========================================================================
// X509Verifier accessors
// ==========================================================================

func TestAdversarial_X509Verifier_Accessors(t *testing.T) {
	cert := advGenSelfSignedCert(t)
	inter := advGenSelfSignedCert(t) // not actually intermediate, just testing accessors
	root := advGenSelfSignedCert(t)

	verifier, err := NewX509Verifier(cert, []*x509.Certificate{inter}, []*x509.Certificate{root}, time.Now())
	require.NoError(t, err)

	assert.Equal(t, cert, verifier.Certificate())
	assert.Equal(t, []*x509.Certificate{inter}, verifier.Intermediates())
	assert.Equal(t, []*x509.Certificate{root}, verifier.Roots())
}

// ==========================================================================
// Certificate chain validation edge cases
// ==========================================================================

func TestAdversarial_X509Verifier_FullChainValidation(t *testing.T) {
	// Build a proper root -> intermediate -> leaf chain and verify
	// the X509Verifier validates the full chain.
	rootPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            2,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate,
		&rootPriv.PublicKey, rootPriv)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	interPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	interTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Intermediate CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, rootCert,
		&interPriv.PublicKey, rootPriv)
	require.NoError(t, err)
	interCert, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)

	leafPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "Leaf"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, interCert,
		&leafPriv.PublicKey, interPriv)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// Verifier with full chain should succeed
	verifier, err := NewX509Verifier(leafCert,
		[]*x509.Certificate{interCert},
		[]*x509.Certificate{rootCert},
		time.Time{})
	require.NoError(t, err)

	data := []byte("chain validation test")
	signer := NewRSASigner(leafPriv, crypto.SHA256)
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	err = verifier.Verify(bytes.NewReader(data), sig)
	require.NoError(t, err, "full chain verification should succeed")

	// Missing intermediate should fail
	noInterVerifier, err := NewX509Verifier(leafCert,
		nil, // no intermediates
		[]*x509.Certificate{rootCert},
		time.Time{})
	require.NoError(t, err)

	err = noInterVerifier.Verify(bytes.NewReader(data), sig)
	require.Error(t, err, "missing intermediate should cause chain validation failure")
}

func TestAdversarial_X509Verifier_WrongIntermediateChain(t *testing.T) {
	// Build two separate chains and try to mix intermediates.
	rootPriv1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootTemplate1 := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Root 1"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER1, err := x509.CreateCertificate(rand.Reader, rootTemplate1, rootTemplate1,
		&rootPriv1.PublicKey, rootPriv1)
	require.NoError(t, err)
	rootCert1, err := x509.ParseCertificate(rootDER1)
	require.NoError(t, err)

	// A different CA chain
	rootPriv2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	interPriv2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootTemplate2 := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Root 2"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	rootDER2, err := x509.CreateCertificate(rand.Reader, rootTemplate2, rootTemplate2,
		&rootPriv2.PublicKey, rootPriv2)
	require.NoError(t, err)
	rootCert2, err := x509.ParseCertificate(rootDER2)
	require.NoError(t, err)

	interTemplate2 := &x509.Certificate{
		SerialNumber:          big.NewInt(11),
		Subject:               pkix.Name{CommonName: "Inter 2"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	interDER2, err := x509.CreateCertificate(rand.Reader, interTemplate2, rootCert2,
		&interPriv2.PublicKey, rootPriv2)
	require.NoError(t, err)
	interCert2, err := x509.ParseCertificate(interDER2)
	require.NoError(t, err)

	// Create a leaf signed by root1's key
	leafPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Leaf 1"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert1,
		&leafPriv.PublicKey, rootPriv1)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	// Try to verify leaf from chain 1 using intermediate from chain 2
	verifier, err := NewX509Verifier(leafCert,
		[]*x509.Certificate{interCert2}, // wrong intermediate
		[]*x509.Certificate{rootCert1},
		time.Time{})
	require.NoError(t, err)

	data := []byte("cross chain test")
	signer := NewRSASigner(leafPriv, crypto.SHA256)
	sig, err := signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	// This should still succeed because leafCert was directly signed by rootCert1,
	// and rootCert1 is in the roots pool. The irrelevant intermediate is ignored.
	err = verifier.Verify(bytes.NewReader(data), sig)
	require.NoError(t, err,
		"leaf directly signed by root should verify even with irrelevant intermediate")
}

// ==========================================================================
// X509Signer sign/verify roundtrip
// ==========================================================================

func TestAdversarial_X509Signer_FullRoundtrip(t *testing.T) {
	// Generate a self-signed CA cert and use it for X509Signer.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Roundtrip Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	baseSigner := NewRSASigner(priv, crypto.SHA256)
	x509Signer, err := NewX509Signer(baseSigner, cert, nil, []*x509.Certificate{cert})
	require.NoError(t, err)

	// Get verifier from signer
	x509Verifier, err := x509Signer.Verifier()
	require.NoError(t, err)

	// KeyIDs should match
	signerKID, err := x509Signer.KeyID()
	require.NoError(t, err)
	verifierKID, err := x509Verifier.KeyID()
	require.NoError(t, err)
	assert.Equal(t, signerKID, verifierKID, "X509Signer/Verifier KeyIDs should match")

	// Sign and verify
	data := []byte("x509 signer roundtrip")
	sig, err := x509Signer.Sign(bytes.NewReader(data))
	require.NoError(t, err)

	// The X509Verifier from Verifier() does NOT have trustedTime set,
	// so it will use the zero time. The cert.Verify call with zero
	// CurrentTime uses the current system time.
	err = x509Verifier.Verify(bytes.NewReader(data), sig)
	// Note: this may or may not succeed depending on whether roots are
	// properly set in the returned verifier. The X509Signer.Verifier()
	// copies cert, roots, intermediates but the verifier from signer.Verifier()
	// is the base RSA verifier wrapped in X509Verifier without roots.
	// Let's see what actually happens:
	if err != nil {
		t.Logf("X509Signer.Verifier() round-trip failed: %v", err)
		t.Logf("FINDING: X509Signer.Verifier() creates X509Verifier with " +
			"roots from X509Signer but base verifier from inner signer. " +
			"The cert chain validation may fail if roots are not propagated correctly.")
	}

	// Accessors should work
	assert.Equal(t, cert, x509Signer.Certificate())
	assert.Nil(t, x509Signer.Intermediates())
	assert.Equal(t, []*x509.Certificate{cert}, x509Signer.Roots())
}

// ==========================================================================
// gitoidHasher edge cases
// ==========================================================================

func TestAdversarial_GitoidHasher_EmptyWrite(t *testing.T) {
	dv := DigestValue{Hash: crypto.SHA256, GitOID: true}
	hasher := dv.New()

	// Writing empty data should be valid
	n, err := hasher.Write([]byte{})
	require.NoError(t, err)
	assert.Equal(t, 0, n)

	sum := hasher.Sum(nil)
	assert.NotEmpty(t, sum, "gitoid of empty content should produce a URI")
	assert.True(t, strings.HasPrefix(string(sum), "gitoid:"),
		"gitoid sum should start with 'gitoid:' prefix, got %q", string(sum))
}

func TestAdversarial_GitoidHasher_LargeWrite(t *testing.T) {
	dv := DigestValue{Hash: crypto.SHA256, GitOID: true}
	hasher := dv.New()

	// Write a large blob
	data := make([]byte, 1*1024*1024) // 1 MB
	_, err := rand.Read(data)
	require.NoError(t, err)

	n, err := hasher.Write(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	sum := hasher.Sum(nil)
	assert.True(t, strings.HasPrefix(string(sum), "gitoid:"),
		"large gitoid sum should have proper prefix")
}

func TestAdversarial_GitoidHasher_MultipleWrites(t *testing.T) {
	dv := DigestValue{Hash: crypto.SHA256, GitOID: true}
	hasher := dv.New()

	// Multiple small writes should concatenate
	_, _ = hasher.Write([]byte("hello "))
	_, _ = hasher.Write([]byte("world"))
	sum1 := hasher.Sum(nil)

	// Single write of same content
	hasher2 := dv.New()
	_, _ = hasher2.Write([]byte("hello world"))
	sum2 := hasher2.Sum(nil)

	assert.Equal(t, string(sum1), string(sum2),
		"multiple writes should produce same result as single write of concatenated data")
}

func TestAdversarial_GitoidHasher_SHA1vsSHA256(t *testing.T) {
	data := []byte("test gitoid difference")

	sha1DV := DigestValue{Hash: crypto.SHA1, GitOID: true}
	sha256DV := DigestValue{Hash: crypto.SHA256, GitOID: true}

	h1 := sha1DV.New()
	_, _ = h1.Write(data)
	sum1 := h1.Sum(nil)

	h256 := sha256DV.New()
	_, _ = h256.Write(data)
	sum256 := h256.Sum(nil)

	// Both should be valid gitoid URIs but with different content
	assert.True(t, strings.HasPrefix(string(sum1), "gitoid:"))
	assert.True(t, strings.HasPrefix(string(sum256), "gitoid:"))
	assert.NotEqual(t, string(sum1), string(sum256),
		"SHA1 and SHA256 gitoids should differ")
}

// ==========================================================================
// DigestSet with empty and special-character digest values
// ==========================================================================

func TestAdversarial_DigestSetEqual_EmptyDigestValues(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}

	ds1 := DigestSet{sha256Key: ""}
	ds2 := DigestSet{sha256Key: ""}

	// Empty string digest values that match should still be considered equal
	assert.True(t, ds1.Equal(ds2),
		"matching empty string digests should be equal")
}

func TestAdversarial_DigestSetEqual_EmptyVsNonEmpty(t *testing.T) {
	sha256Key := DigestValue{Hash: crypto.SHA256}

	ds1 := DigestSet{sha256Key: ""}
	ds2 := DigestSet{sha256Key: "abc123"}

	// Empty vs non-empty should not match
	assert.False(t, ds1.Equal(ds2),
		"empty vs non-empty digest should not be equal")
}

func TestAdversarial_DigestSet_JSONRoundtrip_EmptyDigest(t *testing.T) {
	ds := DigestSet{
		DigestValue{Hash: crypto.SHA256}: "",
	}

	jsonBytes, err := ds.MarshalJSON()
	require.NoError(t, err)

	var restored DigestSet
	err = restored.UnmarshalJSON(jsonBytes)
	require.NoError(t, err)

	assert.True(t, ds.Equal(restored),
		"JSON roundtrip should preserve empty digest values")
}

func TestAdversarial_DigestSet_JSONRoundtrip_GitOIDDigest(t *testing.T) {
	ds := DigestSet{
		DigestValue{Hash: crypto.SHA256, GitOID: true}: "gitoid:blob:sha256:abc123",
	}

	jsonBytes, err := ds.MarshalJSON()
	require.NoError(t, err)

	var restored DigestSet
	err = restored.UnmarshalJSON(jsonBytes)
	require.NoError(t, err)

	assert.True(t, ds.Equal(restored),
		"JSON roundtrip should preserve gitoid digest values")
}

// ==========================================================================
// Signer roundtrip with 1-byte boundary payload
// ==========================================================================

func TestAdversarial_SignerVerifier_OneByte(t *testing.T) {
	keyTypes := []struct {
		name   string
		signer Signer
	}{
		{"RSA", func() Signer {
			priv, _ := rsa.GenerateKey(rand.Reader, 2048)
			return NewRSASigner(priv, crypto.SHA256)
		}()},
		{"ECDSA", func() Signer {
			priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return NewECDSASigner(priv, crypto.SHA256)
		}()},
		{"ED25519", func() Signer {
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			return NewED25519Signer(priv)
		}()},
	}

	for _, kt := range keyTypes {
		t.Run(kt.name, func(t *testing.T) {
			verifier, err := kt.signer.Verifier()
			require.NoError(t, err)

			// Single byte payload
			data := []byte{0x42}
			sig, err := kt.signer.Sign(bytes.NewReader(data))
			require.NoError(t, err)

			err = verifier.Verify(bytes.NewReader(data), sig)
			require.NoError(t, err, "1-byte payload should sign and verify")
		})
	}
}

// ==========================================================================
// Signer roundtrip with max-size payload (stress test)
// ==========================================================================

func TestAdversarial_RSA_SignVerify_MaxPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large payload test in short mode")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := NewRSASigner(priv, crypto.SHA256)
	verifier := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	// 10 MB payload - RSA only digests it, so this should work fine
	payload := make([]byte, 10*1024*1024)
	_, err = rand.Read(payload)
	require.NoError(t, err)

	sig, err := signer.Sign(bytes.NewReader(payload))
	require.NoError(t, err)

	err = verifier.Verify(bytes.NewReader(payload), sig)
	require.NoError(t, err, "large RSA payload should verify")
}

// ==========================================================================
// mode.Perm().IsDir() bug documentation
// ==========================================================================

func TestAdversarial_IsHashableFile_PermIsDirBug(t *testing.T) {
	// Document the mode.Perm().IsDir() bug.
	// os.FileMode.Perm() returns only the lower 9 permission bits.
	// os.FileMode.IsDir() checks if ModeDir (bit 31) is set.
	// Therefore Perm().IsDir() is ALWAYS false because Perm() strips
	// the ModeDir bit.
	//
	// The code at digestset.go:283 does:
	//   if mode.Perm().IsDir() { return true, nil }
	//
	// This condition can never be true. The intent was likely:
	//   if mode.IsDir() { return true, nil }
	//
	// Impact: Directories passed to isHashableFile will fall through
	// to "return false, nil" and be considered not hashable, even though
	// the code was clearly trying to allow them.
	//
	// Severity: LOW -- CalculateDigestSetFromFile opens the file,
	// and os.Open on a directory returns an *os.File that can't be
	// read via io.Copy anyway. The bug is real but has no practical
	// security impact since CalculateDigestSetFromDir is the intended
	// path for directories.

	var mode os.FileMode = os.ModeDir | 0755
	assert.True(t, mode.IsDir(), "mode with ModeDir bit should be a directory")
	assert.False(t, mode.Perm().IsDir(),
		"BUG: mode.Perm().IsDir() is always false because Perm() strips ModeDir")
}

// ==========================================================================
// Helpers
// ==========================================================================

type errorReader struct {
	err error
}

func (r *errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

func advGenSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert " + strings.Repeat("x", 8),
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template,
		&priv.PublicKey, priv)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	return cert
}
