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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Additional mock verifiers for deep adversarial testing
// ==========================================================================

// delayedUnstableKeyIDVerifier returns a different KeyID each time and also
// introduces a small delay, exposing any timing-dependent dedup bugs.
type delayedUnstableKeyIDVerifier struct {
	inner   cryptoutil.Verifier
	counter atomic.Int64
}

func (v *delayedUnstableKeyIDVerifier) KeyID() (string, error) {
	n := v.counter.Add(1)
	return fmt.Sprintf("delayed-unstable-%d", n), nil
}

func (v *delayedUnstableKeyIDVerifier) Verify(body io.Reader, sig []byte) error {
	return v.inner.Verify(body, sig)
}

func (v *delayedUnstableKeyIDVerifier) Bytes() ([]byte, error) {
	return v.inner.Bytes()
}

// conditionalPassVerifier passes on even-numbered calls, fails on odd.
// This tests whether the verified count is stable when a verifier is
// non-deterministic in its pass/fail behavior.
type conditionalPassVerifier struct {
	inner   cryptoutil.Verifier
	counter atomic.Int64
	keyID   string
}

func (v *conditionalPassVerifier) KeyID() (string, error) {
	return v.keyID, nil
}

func (v *conditionalPassVerifier) Verify(body io.Reader, sig []byte) error {
	n := v.counter.Add(1)
	if n%2 == 0 {
		return v.inner.Verify(body, sig)
	}
	return fmt.Errorf("conditionally failing on call %d", n)
}

func (v *conditionalPassVerifier) Bytes() ([]byte, error) {
	return v.inner.Bytes()
}

// ==========================================================================
// Deep DSSE Adversarial Tests
// ==========================================================================

// TestDeepAdversarial_StableKeyIDPrecomputation verifies that the stableKeyIDs
// map in Verify() is computed ONCE before the signature loop, so that a
// verifier with a non-deterministic KeyID cannot produce different IDs
// across different signatures.
func TestDeepAdversarial_StableKeyIDPrecomputation(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("precompute-test")), SignWithSigners(signer))
	require.NoError(t, err)

	// Create 5 duplicate signatures to give the unstable verifier multiple
	// chances to produce different KeyIDs.
	origSig := env.Signatures[0]
	env.Signatures = make([]Signature, 5)
	for i := range env.Signatures {
		env.Signatures[i] = origSig
	}

	unstable := &delayedUnstableKeyIDVerifier{inner: realVerifier}

	// With threshold=2 and only 1 actual key, this MUST fail.
	// The stableKeyIDs map should pin the KeyID at construction time.
	_, err = env.Verify(
		VerifyWithVerifiers(unstable),
		VerifyWithThreshold(2),
	)

	require.Error(t, err, "unstable KeyID should NOT inflate threshold due to precomputation")
	var threshErr ErrThresholdNotMet
	if errors.As(err, &threshErr) {
		assert.Equal(t, 1, threshErr.Actual,
			"precomputed stable KeyID should count exactly 1 verifier")
	}
}

// TestDeepAdversarial_MultipleUnstableVerifiersSameKey tests what happens when
// the SAME underlying key is wrapped in multiple unstable-keyid verifiers.
// Each wrapper is a distinct object so stableKeyIDs will give each a different
// precomputed ID. This means one key wrapped N times could meet threshold=N.
func TestDeepAdversarial_MultipleUnstableVerifiersSameKey(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("multi-wrapper")), SignWithSigners(signer))
	require.NoError(t, err)

	// Create 3 distinct wrapper objects around the same underlying verifier.
	// Each will get a different precomputed stable KeyID (because they are
	// different pointers), and each will successfully verify.
	wrappers := make([]cryptoutil.Verifier, 3)
	for i := range wrappers {
		wrappers[i] = &delayedUnstableKeyIDVerifier{inner: realVerifier}
	}

	_, err = env.Verify(
		VerifyWithVerifiers(wrappers...),
		VerifyWithThreshold(3),
	)

	// DESIGN CONCERN: This WILL pass because the dedup is based on the
	// precomputed KeyID, which is different for each wrapper object.
	// One compromised key wrapped in N distinct objects meets threshold=N.
	if err == nil {
		t.Logf("DESIGN CONCERN: Same key wrapped in 3 distinct unstable-KeyID objects " +
			"met threshold=3. The dedup map uses precomputed stable IDs per verifier " +
			"object, not per underlying cryptographic key. An attacker who compromises " +
			"one key can wrap it in N objects to meet any threshold.")
	}
}

// TestDeepAdversarial_CertPlusRawKeyMixedVerification tests that when a
// signature has BOTH a certificate field AND matches a raw-key verifier,
// both paths contribute to the verified count but share the same dedup map.
func TestDeepAdversarial_CertPlusRawKeyMixedVerification(t *testing.T) {
	// Create a CA chain.
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)

	// Create a signer that includes the certificate.
	s, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
	require.NoError(t, err)

	// Also create a raw verifier from the same public key.
	rawVerifier := cryptoutil.NewRSAVerifier(leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("mixed-cert-raw")),
		SignWithSigners(s))
	require.NoError(t, err)

	// Verify with BOTH cert roots AND the raw verifier.
	// The cert path should verify via X509, and the raw verifier should also verify.
	// Both should contribute to the verified count, but they might have different KeyIDs.
	checked, err := env.Verify(
		VerifyWithVerifiers(rawVerifier),
		VerifyWithRoots(root),
		VerifyWithIntermediates(intermediate),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err, "mixed cert + raw key should pass threshold=1")

	passed := 0
	for _, cv := range checked {
		if cv.Error == nil {
			passed++
		}
	}

	// Both the cert verifier and the raw verifier should pass.
	assert.GreaterOrEqual(t, passed, 2,
		"both cert and raw-key verification paths should succeed")
}

// TestDeepAdversarial_CertPlusRawKeyThresholdCounting tests whether the cert
// verifier and raw verifier from the same key are counted as 1 or 2 distinct
// verifiers in the threshold check.
func TestDeepAdversarial_CertPlusRawKeyThresholdCounting(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)

	s, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
	require.NoError(t, err)

	rawVerifier := cryptoutil.NewRSAVerifier(leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("threshold-counting")),
		SignWithSigners(s))
	require.NoError(t, err)

	// Try threshold=2 with cert verification + raw verifier.
	// If they produce different KeyIDs, both count separately.
	_, err = env.Verify(
		VerifyWithVerifiers(rawVerifier),
		VerifyWithRoots(root),
		VerifyWithIntermediates(intermediate),
		VerifyWithThreshold(2),
	)

	// This reveals whether the same underlying key can count as 2 verifiers
	// through the cert path and the raw path.
	if err == nil {
		t.Logf("DESIGN NOTE: Cert verifier and raw verifier for the same key are " +
			"counted as 2 distinct verifiers (different KeyIDs). This means " +
			"threshold=2 can be met with a single key if both cert and raw " +
			"verification paths are available.")
	} else {
		t.Logf("Cert and raw verifier for same key treated as 1 verifier: %v", err)
	}
}

// TestDeepAdversarial_UnparseableCertDoesNotBlockRawVerifier is a regression
// test for the fixed bug where an unparseable Certificate field in a signature
// would skip the raw verifier loop.
func TestDeepAdversarial_UnparseableCertDoesNotBlockRawVerifier(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	testCases := []struct {
		name string
		cert []byte
	}{
		{"garbage bytes", []byte("not-a-certificate")},
		{"truncated PEM", []byte("-----BEGIN CERTIFICATE-----\ntruncated\n-----END CERTIFICATE-----")},
		{"empty PEM block", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{}})},
		{"wrong PEM type", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("fake")})},
		{"binary garbage", func() []byte {
			b := make([]byte, 256)
			rand.Read(b)
			return b
		}()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set the certificate field to something unparseable.
			env.Signatures[0].Certificate = tc.cert

			_, err := env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(1))
			require.NoError(t, err,
				"REGRESSION: unparseable cert field should NOT block raw verifier. "+
					"The fix replaced 'continue' with a log+fallthrough on cert parse failure.")
		})
	}
}

// TestDeepAdversarial_CertWithUnparseableIntermediates tests that unparseable
// intermediate certificates are skipped without blocking the cert verification
// path, and the raw verifier path still works.
func TestDeepAdversarial_CertWithUnparseableIntermediates(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)

	s, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
	require.NoError(t, err)

	env, err := Sign("test", bytes.NewReader([]byte("bad-intermediates")), SignWithSigners(s))
	require.NoError(t, err)

	// Inject garbage intermediate alongside the real one.
	env.Signatures[0].Intermediates = append(
		env.Signatures[0].Intermediates,
		[]byte("garbage-intermediate"),
	)

	rawVerifier := cryptoutil.NewRSAVerifier(leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256)

	_, err = env.Verify(
		VerifyWithVerifiers(rawVerifier),
		VerifyWithRoots(root),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err,
		"garbage intermediate should be skipped; raw verifier should still work")
}

// TestDeepAdversarial_TimestampVerifierWithNoTimestamps tests the branch
// where timestamp verifiers are provided but the signature has no timestamps.
// In this case, passedTimestampVerifiers is empty and the cert verification
// records all as failed.
func TestDeepAdversarial_TimestampVerifierWithNoTimestamps(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)

	s, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
	require.NoError(t, err)

	// Sign WITHOUT timestampers so no timestamps are in the envelope.
	env, err := Sign("test", bytes.NewReader([]byte("no-timestamps")),
		SignWithSigners(s))
	require.NoError(t, err)

	// Verify WITH timestamp verifiers. Since no timestamps exist in the sig,
	// the inner loop over sig.Timestamps never executes, so
	// passedTimestampVerifiers stays empty.
	fakeTV := timestamp.FakeTimestamper{T: time.Now()}
	_, err = env.Verify(
		VerifyWithRoots(root),
		VerifyWithIntermediates(intermediate),
		VerifyWithTimestampVerifiers(fakeTV),
		VerifyWithThreshold(1),
	)

	// This should fail because the timestamp path found no valid timestamps,
	// and there are no raw verifiers to fall back on.
	require.Error(t, err,
		"cert sig with timestamp verifiers but no timestamps should fail")
}

// TestDeepAdversarial_TimestampVerifierPartialMatch tests the case where
// some timestamp verifiers pass and some fail for a cert-based signature.
func TestDeepAdversarial_TimestampVerifierPartialMatch(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)

	s, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
	require.NoError(t, err)

	now := time.Now()
	goodTS := timestamp.FakeTimestamper{T: now}
	badTS := timestamp.FakeTimestamper{T: now.Add(48 * time.Hour)} // outside cert validity

	env, err := Sign("test", bytes.NewReader([]byte("partial-ts")),
		SignWithSigners(s),
		SignWithTimestampers(goodTS, badTS))
	require.NoError(t, err)

	checked, err := env.Verify(
		VerifyWithRoots(root),
		VerifyWithIntermediates(intermediate),
		VerifyWithTimestampVerifiers(goodTS, badTS),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err,
		"at least one timestamp should pass, meeting threshold")

	// Find the passed verifier.
	for _, cv := range checked {
		if cv.Error == nil {
			assert.NotEmpty(t, cv.TimestampVerifiers,
				"passed cert verifier should have timestamp verifiers attached")
		}
	}
}

// TestDeepAdversarial_ConditionallyPassingVerifier tests a verifier that
// alternates between passing and failing. With multiple signatures from
// the same key, on some signatures it will pass and on others it will fail.
// Since the dedup is by KeyID, it should still only count as 1.
func TestDeepAdversarial_ConditionallyPassingVerifier(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("conditional")), SignWithSigners(signer))
	require.NoError(t, err)

	// Duplicate the signature 4 times.
	origSig := env.Signatures[0]
	env.Signatures = []Signature{origSig, origSig, origSig, origSig}

	cv := &conditionalPassVerifier{
		inner: realVerifier,
		keyID: "conditional-key",
	}

	// With 4 sigs, the conditional verifier passes on calls 2 and 4
	// (even-numbered), fails on 1 and 3. But the dedup map should only
	// count "conditional-key" once.
	_, err = env.Verify(
		VerifyWithVerifiers(cv),
		VerifyWithThreshold(2),
	)
	require.Error(t, err, "conditionally passing verifier should only count as 1 unique key")
}

// TestDeepAdversarial_SignatureWithBothCertAndRawVerifierOrder tests that
// the cert verification path runs BEFORE the raw verifier path for each
// signature, and that the raw verifier is ALWAYS attempted regardless of
// cert verification outcome.
func TestDeepAdversarial_SignatureWithBothCertAndRawVerifierOrder(t *testing.T) {
	// Create a valid cert chain and leaf.
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)

	s, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
	require.NoError(t, err)

	rawVerifier := cryptoutil.NewRSAVerifier(leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("order-test")), SignWithSigners(s))
	require.NoError(t, err)

	// Provide a DIFFERENT root (not the one that signed the chain) so cert
	// verification fails, but pass the correct raw verifier.
	wrongRoot, _, err := createRoot()
	require.NoError(t, err)

	_, err = env.Verify(
		VerifyWithVerifiers(rawVerifier),
		VerifyWithRoots(wrongRoot), // wrong root -> cert path fails
		VerifyWithThreshold(1),
	)
	require.NoError(t, err,
		"raw verifier should succeed even when cert verification fails with wrong root")
}

// TestDeepAdversarial_ConcurrentVerifyWithCertAndRawMixed tests concurrent
// verification where some goroutines use cert verification and others use
// raw key verification on the same envelope.
func TestDeepAdversarial_ConcurrentVerifyWithCertAndRawMixed(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)

	s, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
	require.NoError(t, err)

	rawVerifier := cryptoutil.NewRSAVerifier(leaf.PublicKey.(*rsa.PublicKey), crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("concurrent-mixed")), SignWithSigners(s))
	require.NoError(t, err)

	const goroutines = 30
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				// Cert path.
				_, err := env.Verify(
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithThreshold(1),
				)
				errs[idx] = err
			} else {
				// Raw verifier path.
				_, err := env.Verify(
					VerifyWithVerifiers(rawVerifier),
					VerifyWithThreshold(1),
				)
				errs[idx] = err
			}
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d should succeed (cert=%v, raw=%v)", i, i%2 == 0, i%2 != 0)
	}
}

// TestDeepAdversarial_ECDSASignerRSAVerifier tests that an ECDSA-signed
// envelope does not accidentally verify with an RSA verifier (cross-algorithm).
func TestDeepAdversarial_ECDSASignerRSAVerifier(t *testing.T) {
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecSigner := cryptoutil.NewECDSASigner(ecPriv, crypto.SHA256)

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaVerifier := cryptoutil.NewRSAVerifier(&rsaPriv.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("cross-algo")), SignWithSigners(ecSigner))
	require.NoError(t, err)

	_, err = env.Verify(VerifyWithVerifiers(rsaVerifier))
	require.Error(t, err, "ECDSA signature should not verify with RSA verifier")
}

// TestDeepAdversarial_VerifyWithZeroThreshold confirms that threshold=0
// always returns ErrInvalidThreshold regardless of whether signatures exist.
func TestDeepAdversarial_VerifyWithZeroThreshold(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	_, err := env.Verify(
		VerifyWithVerifiers(verifier),
		VerifyWithThreshold(0),
	)
	require.Error(t, err)
	assert.ErrorAs(t, err, new(ErrInvalidThreshold),
		"threshold=0 must always return ErrInvalidThreshold")
}

// TestDeepAdversarial_VerifyThresholdGreaterThanVerifiers tests threshold
// higher than the number of verifiers. Even if all verifiers pass, we
// should still fail because len(verifiedKeyIDs) < threshold.
func TestDeepAdversarial_VerifyThresholdGreaterThanVerifiers(t *testing.T) {
	s1, v1 := mustCreateTestKey(t)
	s2, v2 := mustCreateTestKey(t)

	env := signEnvelope(t, s1, s2)

	_, err := env.Verify(
		VerifyWithVerifiers(v1, v2),
		VerifyWithThreshold(10),
	)
	require.Error(t, err)
	var threshErr ErrThresholdNotMet
	require.ErrorAs(t, err, &threshErr)
	assert.Equal(t, 2, threshErr.Actual)
	assert.Equal(t, 10, threshErr.Theshold)
}

// TestDeepAdversarial_SignatureTimestampDataCorruption tests that corrupted
// timestamp data in a signature does not prevent raw verifier verification.
func TestDeepAdversarial_SignatureTimestampDataCorruption(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	// Inject corrupted timestamp data.
	env.Signatures[0].Timestamps = []SignatureTimestamp{
		{Type: TimestampRFC3161, Data: []byte("corrupted-timestamp-data")},
		{Type: "unknown-type", Data: nil},
	}

	// Raw verifier should still work.
	_, err := env.Verify(
		VerifyWithVerifiers(verifier),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err,
		"corrupted timestamps should not affect raw-key verification")
}

// TestDeepAdversarial_MassiveConcurrentVerification stress-tests the
// concurrent verification path with many goroutines, mixed key types,
// and varying thresholds.
func TestDeepAdversarial_MassiveConcurrentVerification(t *testing.T) {
	// Create keys of different types.
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaSigner := cryptoutil.NewRSASigner(rsaPriv, crypto.SHA256)
	rsaVerifier := cryptoutil.NewRSAVerifier(&rsaPriv.PublicKey, crypto.SHA256)

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecSigner := cryptoutil.NewECDSASigner(ecPriv, crypto.SHA256)
	ecVerifier := cryptoutil.NewECDSAVerifier(&ecPriv.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("massive-concurrent")),
		SignWithSigners(rsaSigner, ecSigner))
	require.NoError(t, err)

	const goroutines = 100
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			threshold := (idx % 2) + 1 // alternates between 1 and 2
			_, err := env.Verify(
				VerifyWithVerifiers(rsaVerifier, ecVerifier),
				VerifyWithThreshold(threshold),
			)
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d (threshold=%d) should pass", i, (i%2)+1)
	}
}

// TestDeepAdversarial_EnvelopeWithNoPayload tests an envelope with nil payload.
func TestDeepAdversarial_EnvelopeWithNoPayload(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)

	// Sign with an empty reader (produces empty payload).
	env, err := Sign("test", bytes.NewReader(nil), SignWithSigners(signer))
	require.NoError(t, err)

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err, "nil/empty payload should verify")
}

// TestDeepAdversarial_ExpiredCertNotValidWithCurrentTime tests that a cert
// signed envelope fails when the cert has expired and no timestamp verifier
// is provided (so the default time.Now() is used).
func TestDeepAdversarial_ExpiredCertNotValidWithCurrentTime(t *testing.T) {
	// Create a root and leaf with a very short validity window that's already expired.
	rootPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootPub := &rootPriv.PublicKey

	rootTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Expired Test Root",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // expired
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootTemplate.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(4294967295))
	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPub, rootPriv)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootCertBytes)
	require.NoError(t, err)

	leafPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafPub := &leafPriv.PublicKey

	leafTemplate := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: "Expired Leaf",
		},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour), // expired
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafTemplate.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(4294967295))
	leafCertBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootTemplate, leafPub, rootPriv)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(leafCertBytes)
	require.NoError(t, err)

	s, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leafCert))
	require.NoError(t, err)

	env, err := Sign("test", bytes.NewReader([]byte("expired-cert")), SignWithSigners(s))
	require.NoError(t, err)

	// Without a raw verifier, only cert path is available. With an expired cert
	// and no timestamp verifier, verification should fail.
	_, err = env.Verify(
		VerifyWithRoots(rootCert),
		VerifyWithThreshold(1),
	)
	require.Error(t, err,
		"expired cert should fail when using time.Now() for verification")
}

// TestDeepAdversarial_VerifyWithEmptyVerifierSlice tests that explicitly
// passing an empty verifier slice (not nil) behaves the same as nil.
func TestDeepAdversarial_VerifyWithEmptyVerifierSlice(t *testing.T) {
	signer, _ := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	_, err := env.Verify(
		VerifyWithVerifiers([]cryptoutil.Verifier{}...),
		VerifyWithThreshold(1),
	)
	require.Error(t, err)
	var noMatchErr ErrNoMatchingSigs
	require.ErrorAs(t, err, &noMatchErr,
		"empty verifier slice should produce ErrNoMatchingSigs")
}

// TestDeepAdversarial_VerifyWithOnlyNilsInVerifiers tests that a verifier
// slice containing only nils does not count toward the threshold.
func TestDeepAdversarial_VerifyWithOnlyNilsInVerifiers(t *testing.T) {
	signer, _ := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	_, err := env.Verify(
		VerifyWithVerifiers(nil, nil, nil),
		VerifyWithThreshold(1),
	)
	require.Error(t, err,
		"nil-only verifiers should not pass any threshold")
}

// TestDeepAdversarial_DuplicateSignaturesDifferentIntermediates tests that
// duplicate signatures with different intermediate certificate data are
// still deduplicated by KeyID.
func TestDeepAdversarial_DuplicateSignaturesDifferentIntermediates(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	origSig := env.Signatures[0]

	// Create copies with different intermediate data.
	sig1 := origSig
	sig1.Intermediates = [][]byte{[]byte("intermediate-A")}

	sig2 := origSig
	sig2.Intermediates = [][]byte{[]byte("intermediate-B")}

	env.Signatures = []Signature{sig1, sig2, origSig}

	_, err := env.Verify(
		VerifyWithVerifiers(verifier),
		VerifyWithThreshold(2),
	)
	require.Error(t, err,
		"same key with different intermediates should still count as 1 unique verifier")
}
