//go:build audit

package dsse

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Mock verifiers for adversarial testing
// ==========================================================================

// unstableKeyIDVerifier returns a different KeyID on every call.
// This tests whether the verifiedKeyIDs deduplication is stable when
// a verifier's KeyID is non-deterministic.
type unstableKeyIDVerifier struct {
	inner   cryptoutil.Verifier
	counter atomic.Int64
}

func (v *unstableKeyIDVerifier) KeyID() (string, error) {
	n := v.counter.Add(1)
	return fmt.Sprintf("unstable-key-%d", n), nil
}

func (v *unstableKeyIDVerifier) Verify(body io.Reader, sig []byte) error {
	return v.inner.Verify(body, sig)
}

func (v *unstableKeyIDVerifier) Bytes() ([]byte, error) {
	return v.inner.Bytes()
}

// errorKeyIDVerifier always returns an error from KeyID().
// This tests the verifierKeyID fallback path.
type errorKeyIDVerifier struct {
	inner cryptoutil.Verifier
}

func (v *errorKeyIDVerifier) KeyID() (string, error) {
	return "", errors.New("KeyID unavailable")
}

func (v *errorKeyIDVerifier) Verify(body io.Reader, sig []byte) error {
	return v.inner.Verify(body, sig)
}

func (v *errorKeyIDVerifier) Bytes() ([]byte, error) {
	return v.inner.Bytes()
}

// fixedKeyIDVerifier returns a fixed KeyID regardless of the underlying key.
// This is the classic attack: two different keys that report the same KeyID
// to trick deduplication into counting only one when both are valid.
type fixedKeyIDVerifier struct {
	inner cryptoutil.Verifier
	keyID string
}

func (v *fixedKeyIDVerifier) KeyID() (string, error) {
	return v.keyID, nil
}

func (v *fixedKeyIDVerifier) Verify(body io.Reader, sig []byte) error {
	return v.inner.Verify(body, sig)
}

func (v *fixedKeyIDVerifier) Bytes() ([]byte, error) {
	return v.inner.Bytes()
}

// alwaysPassVerifier always reports verification success. Used to test
// whether threshold logic can be fooled by a verifier that lies.
type alwaysPassVerifier struct {
	keyID string
}

func (v *alwaysPassVerifier) KeyID() (string, error) {
	return v.keyID, nil
}

func (v *alwaysPassVerifier) Verify(_ io.Reader, _ []byte) error {
	return nil // always "verifies"
}

func (v *alwaysPassVerifier) Bytes() ([]byte, error) {
	return []byte("fake"), nil
}

// ==========================================================================
// DSSE Threshold Inflation Attacks
// ==========================================================================

// TestAdversarial_UnstableKeyIDInflatesThreshold tests whether a verifier
// whose KeyID() changes on every call can inflate the verified count.
//
// BUG HYPOTHESIS: If verifierKeyID(v) returns "key-1" for the first signature
// check and "key-2" for the second, the verifiedKeyIDs map will have two
// entries even though it's the same verifier, inflating the threshold count.
func TestAdversarial_UnstableKeyIDInflatesThreshold(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	// Sign with one key, then duplicate the signature.
	env, err := Sign("test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
	require.NoError(t, err)

	// Duplicate the signature 3 times to give the unstable verifier
	// multiple chances to produce different KeyIDs.
	origSig := env.Signatures[0]
	env.Signatures = []Signature{origSig, origSig, origSig}

	unstable := &unstableKeyIDVerifier{inner: realVerifier}

	// With threshold=2 and only 1 actual key, this SHOULD fail.
	// But if the unstable KeyID causes multiple map entries, it might pass.
	_, err = env.Verify(
		VerifyWithVerifiers(unstable),
		VerifyWithThreshold(2),
	)

	// BUG: If err is nil here, the unstable KeyID inflated the threshold.
	if err == nil {
		t.Errorf("BUG: Unstable KeyID inflated threshold! A single verifier with "+
			"non-deterministic KeyID() passed threshold=2 with duplicated signatures. "+
			"verifierKeyID is called once per signature check, and each call to the "+
			"unstable verifier produces a different KeyID, creating separate entries in "+
			"the verifiedKeyIDs map. Counter reached: %d", unstable.counter.Load())
	} else {
		// This is the correct behavior.
		var threshErr ErrThresholdNotMet
		if errors.As(err, &threshErr) {
			t.Logf("Correctly rejected: actual=%d, threshold=%d", threshErr.Actual, threshErr.Theshold)
		}
	}
}

// TestAdversarial_ErrorKeyIDFallbackDeduplication tests that when KeyID()
// returns an error, the fallback (pointer-based hash) correctly deduplicates
// a single verifier across multiple signature checks.
func TestAdversarial_ErrorKeyIDFallbackDeduplication(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
	require.NoError(t, err)

	// Duplicate signatures.
	origSig := env.Signatures[0]
	env.Signatures = []Signature{origSig, origSig, origSig}

	errVerifier := &errorKeyIDVerifier{inner: realVerifier}

	// The fallback uses fmt.Sprintf("%p", v) which should be stable for the
	// same pointer. So threshold=2 should fail with only 1 unique verifier.
	_, err = env.Verify(
		VerifyWithVerifiers(errVerifier),
		VerifyWithThreshold(2),
	)

	if err == nil {
		t.Errorf("BUG: Error KeyID fallback failed to deduplicate! Threshold=2 should " +
			"not be met with a single verifier, even when KeyID() returns errors")
	} else {
		var threshErr ErrThresholdNotMet
		if errors.As(err, &threshErr) {
			assert.Equal(t, 1, threshErr.Actual,
				"fallback dedup should count exactly 1 unique verifier")
		}
	}
}

// TestAdversarial_KeyIDCollisionReducesThreshold tests what happens when
// two DIFFERENT keys that legitimately signed an envelope report the SAME
// KeyID. The verifiedKeyIDs map will only have one entry, reducing the
// effective verified count.
func TestAdversarial_KeyIDCollisionReducesThreshold(t *testing.T) {
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer1 := cryptoutil.NewRSASigner(privKey1, crypto.SHA256)
	signer2 := cryptoutil.NewRSASigner(privKey2, crypto.SHA256)

	realVerifier1 := cryptoutil.NewRSAVerifier(&privKey1.PublicKey, crypto.SHA256)
	realVerifier2 := cryptoutil.NewRSAVerifier(&privKey2.PublicKey, crypto.SHA256)

	// Sign with both keys.
	env, err := Sign("test", bytes.NewReader([]byte("payload")), SignWithSigners(signer1, signer2))
	require.NoError(t, err)
	require.Len(t, env.Signatures, 2)

	// Wrap both verifiers to return the same KeyID.
	collisionID := "colliding-key-id"
	wrapped1 := &fixedKeyIDVerifier{inner: realVerifier1, keyID: collisionID}
	wrapped2 := &fixedKeyIDVerifier{inner: realVerifier2, keyID: collisionID}

	// Both verifiers successfully verify their respective signatures,
	// but they report the same KeyID. The dedup map will only count 1.
	_, err = env.Verify(
		VerifyWithVerifiers(wrapped1, wrapped2),
		VerifyWithThreshold(2),
	)

	// This SHOULD fail because the dedup map sees "colliding-key-id" twice
	// and only counts it once.
	if err == nil {
		t.Errorf("KeyID collision unexpectedly passed threshold=2. Two distinct keys " +
			"with colliding KeyIDs should still be counted as 1 (by design? or bug?)")
	} else {
		// Documenting this as a design concern: if two legitimately different
		// keys happen to have the same KeyID (e.g., a malicious CA reissues),
		// the threshold count is reduced. This may or may not be desired behavior.
		t.Logf("DESIGN NOTE: KeyID collision reduced verified count from 2 to 1. "+
			"Error: %v", err)
	}
}

// TestAdversarial_AlwaysPassVerifierMeetsThreshold tests that a verifier
// that always returns nil from Verify() is counted as a valid verification.
// This is less about DSSE and more about documenting that the trust model
// depends on the verifier implementations being honest.
func TestAdversarial_AlwaysPassVerifierMeetsThreshold(t *testing.T) {
	signer, _ := mustCreateTestKey(t)

	env, err := Sign("test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
	require.NoError(t, err)

	// Create 3 fake verifiers that always pass.
	fakes := []cryptoutil.Verifier{
		&alwaysPassVerifier{keyID: "fake-1"},
		&alwaysPassVerifier{keyID: "fake-2"},
		&alwaysPassVerifier{keyID: "fake-3"},
	}

	_, err = env.Verify(
		VerifyWithVerifiers(fakes...),
		VerifyWithThreshold(3),
	)

	// This WILL pass -- documenting the trust model limitation.
	if err == nil {
		t.Logf("DESIGN NOTE: 3 always-pass fake verifiers met threshold=3. " +
			"The DSSE verify loop trusts the Verifier.Verify() return value unconditionally. " +
			"Security depends on the caller providing honest verifier implementations.")
	}
}

// TestAdversarial_SameVerifierAsEnvelopeAndPassedVerifier tests what happens
// when the same underlying key appears in both the envelope's certificate
// chain AND the passed verifiers list. Could this double-count?
func TestAdversarial_SameKeyRegisteredTwiceAsVerifier(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
	require.NoError(t, err)

	// Pass the SAME verifier twice in the verifiers list.
	_, err = env.Verify(
		VerifyWithVerifiers(verifier, verifier),
		VerifyWithThreshold(2),
	)

	// The same verifier object will have the same KeyID, and the loop iterates
	// over options.verifiers for EACH signature. With 1 signature and 2 copies
	// of the same verifier, verifier[0] succeeds (adds KeyID to map),
	// verifier[1] also succeeds (same KeyID already in map).
	// So verifiedKeyIDs should have only 1 entry.
	if err == nil {
		t.Errorf("BUG: Same verifier passed twice met threshold=2! " +
			"The dedup map should prevent this.")
	} else {
		var threshErr ErrThresholdNotMet
		if errors.As(err, &threshErr) {
			assert.Equal(t, 1, threshErr.Actual,
				"same verifier passed twice should only count as 1")
		}
	}
}

// TestAdversarial_NilVerifierInList tests that nil verifiers in the list
// don't cause panics.
func TestAdversarial_NilVerifierInList(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	// nil verifier mixed in with valid ones.
	_, err := env.Verify(
		VerifyWithVerifiers(nil, verifier, nil),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err, "nil verifiers should be skipped without panic")
}

// TestAdversarial_AllNilVerifiers tests that all-nil verifier list doesn't panic.
func TestAdversarial_AllNilVerifiers(t *testing.T) {
	signer, _ := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	assert.NotPanics(t, func() {
		_, _ = env.Verify(
			VerifyWithVerifiers(nil, nil, nil),
			VerifyWithThreshold(1),
		)
	}, "all-nil verifiers should not panic")
}

// TestAdversarial_CrossSignatureVerifierMatching tests that a verifier
// is tried against EVERY signature in the envelope, not just the one
// with a matching KeyID. This is correct behavior (the envelope KeyID
// field is informational, not authoritative), but worth validating.
func TestAdversarial_CrossSignatureVerifierMatching(t *testing.T) {
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer1 := cryptoutil.NewRSASigner(privKey1, crypto.SHA256)
	signer2 := cryptoutil.NewRSASigner(privKey2, crypto.SHA256)
	verifier1 := cryptoutil.NewRSAVerifier(&privKey1.PublicKey, crypto.SHA256)

	// Sign with both keys.
	env, err := Sign("test", bytes.NewReader([]byte("payload")),
		SignWithSigners(signer1, signer2))
	require.NoError(t, err)

	// Swap the KeyID fields in the signatures to mismatch.
	env.Signatures[0].KeyID, env.Signatures[1].KeyID =
		env.Signatures[1].KeyID, env.Signatures[0].KeyID

	// verifier1 should still work because Verify() tries all verifiers
	// against all signatures, ignoring the KeyID field.
	_, err = env.Verify(
		VerifyWithVerifiers(verifier1),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err,
		"verifier should match its signature regardless of envelope KeyID field")
}

// TestAdversarial_MixedKeyTypesThreshold tests threshold with mixed key types
// where each key type signs separately.
func TestAdversarial_MixedKeyTypesThreshold(t *testing.T) {
	// RSA signer/verifier
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaSigner := cryptoutil.NewRSASigner(rsaPriv, crypto.SHA256)
	rsaVerifier := cryptoutil.NewRSAVerifier(&rsaPriv.PublicKey, crypto.SHA256)

	// ECDSA signer/verifier
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecSigner := cryptoutil.NewECDSASigner(ecPriv, crypto.SHA256)
	ecVerifier := cryptoutil.NewECDSAVerifier(&ecPriv.PublicKey, crypto.SHA256)

	// ED25519 signer/verifier
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edSigner := cryptoutil.NewED25519Signer(edPriv)
	edVerifier := cryptoutil.NewED25519Verifier(edPub)

	// Sign with all three.
	env, err := Sign("test", bytes.NewReader([]byte("multi-key-type")),
		SignWithSigners(rsaSigner, ecSigner, edSigner))
	require.NoError(t, err)
	require.Len(t, env.Signatures, 3)

	// Verify with threshold=3.
	checked, err := env.Verify(
		VerifyWithVerifiers(rsaVerifier, ecVerifier, edVerifier),
		VerifyWithThreshold(3),
	)
	require.NoError(t, err, "3 distinct key types should meet threshold=3")

	passed := 0
	for _, cv := range checked {
		if cv.Error == nil {
			passed++
		}
	}
	assert.Equal(t, 3, passed)
}

// TestAdversarial_ConcurrentUnstableKeyIDVerification tests the unstable KeyID
// scenario under concurrent access to ensure no data races in the dedup map.
func TestAdversarial_ConcurrentUnstableKeyIDVerification(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("concurrent-unstable")),
		SignWithSigners(signer))
	require.NoError(t, err)

	origSig := env.Signatures[0]
	env.Signatures = []Signature{origSig, origSig, origSig}

	const goroutines = 20
	var wg sync.WaitGroup
	results := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Each goroutine gets its own unstable verifier to avoid counter races.
			unstable := &unstableKeyIDVerifier{inner: realVerifier}
			_, err := env.Verify(
				VerifyWithVerifiers(unstable),
				VerifyWithThreshold(1),
			)
			results[idx] = err
		}(i)
	}
	wg.Wait()

	// With threshold=1, at least the first match should count.
	// But the unstable KeyID means each iteration adds a new entry.
	// With threshold=1 this should still pass because we only need 1.
	for i, err := range results {
		assert.NoError(t, err, "goroutine %d: threshold=1 should pass even with unstable KeyID", i)
	}
}

// TestAdversarial_VerifierKeyIDFallbackStability tests that the pointer-based
// fallback in verifierKeyID produces stable results for the same verifier
// across multiple calls.
func TestAdversarial_VerifierKeyIDFallbackStability(t *testing.T) {
	privKeyForFallback, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	realVerifier := cryptoutil.NewRSAVerifier(&privKeyForFallback.PublicKey, crypto.SHA256)

	errVerifier := &errorKeyIDVerifier{inner: realVerifier}

	// Call verifierKeyID multiple times on the same pointer.
	kid1 := verifierKeyID(errVerifier)
	kid2 := verifierKeyID(errVerifier)
	kid3 := verifierKeyID(errVerifier)

	assert.Equal(t, kid1, kid2, "fallback KeyID should be stable across calls")
	assert.Equal(t, kid2, kid3, "fallback KeyID should be stable across calls")
	assert.Contains(t, kid1, "fallback:", "should use fallback prefix")
}

// TestAdversarial_VerifierKeyIDFallbackUniqueness tests that different verifier
// pointers produce different fallback KeyIDs.
func TestAdversarial_VerifierKeyIDFallbackUniqueness(t *testing.T) {
	makeErrVerifier := func() *errorKeyIDVerifier {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		v := cryptoutil.NewRSAVerifier(&k.PublicKey, crypto.SHA256)
		return &errorKeyIDVerifier{inner: v}
	}

	v1 := makeErrVerifier()
	v2 := makeErrVerifier()

	kid1 := verifierKeyID(v1)
	kid2 := verifierKeyID(v2)

	assert.NotEqual(t, kid1, kid2,
		"different verifier pointers should produce different fallback KeyIDs")
}

// TestAdversarial_EmptySignatureSlotSkipped tests that an envelope entry with
// empty/nil certificate and empty signature data doesn't cause a panic
// when there's also a valid signature.
func TestAdversarial_EmptySignatureSlotSkipped(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	// Inject empty signature entries.
	env.Signatures = append([]Signature{
		{KeyID: "", Signature: nil, Certificate: nil},
		{KeyID: "garbage", Signature: []byte{}, Certificate: []byte("not-a-cert")},
	}, env.Signatures...)

	assert.NotPanics(t, func() {
		_, err := env.Verify(
			VerifyWithVerifiers(verifier),
			VerifyWithThreshold(1),
		)
		require.NoError(t, err, "should still verify the valid signature")
	})
}

// TestAdversarial_HugeNumberOfSignatures tests memory/time behavior with
// a large number of duplicate signatures. This is a DoS vector: an attacker
// could stuff an envelope with thousands of signatures.
func TestAdversarial_HugeNumberOfSignatures(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	origSig := env.Signatures[0]
	env.Signatures = make([]Signature, 1000)
	for i := range env.Signatures {
		env.Signatures[i] = origSig
	}

	// This should still work but only count 1 unique verifier.
	_, err := env.Verify(
		VerifyWithVerifiers(verifier),
		VerifyWithThreshold(2),
	)

	require.Error(t, err, "1000 duplicates of 1 key should not meet threshold=2")
	var threshErr ErrThresholdNotMet
	require.ErrorAs(t, err, &threshErr)
	assert.Equal(t, 1, threshErr.Actual)

	// But threshold=1 should pass.
	_, err = env.Verify(
		VerifyWithVerifiers(verifier),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err)
}

// TestAdversarial_VerifyStatementUnsafePresence checks whether the package
// exports a VerifyStatementUnsafe function, which would be a thread-safety
// and correctness concern.
func TestAdversarial_EnvelopeVerifyIsValueReceiver(t *testing.T) {
	// Envelope.Verify takes (e Envelope), not (e *Envelope).
	// This means every call gets a copy of the envelope, which is safe
	// for concurrent use BUT means the Signatures slice header is copied
	// (still pointing to same underlying array). Verify only reads, so
	// this should be fine. Let's validate.
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	// Store original state.
	origPayload := make([]byte, len(env.Payload))
	copy(origPayload, env.Payload)
	origSigCount := len(env.Signatures)

	_, err := env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err)

	// Verify didn't mutate the envelope.
	assert.Equal(t, origPayload, env.Payload, "Verify should not mutate Payload")
	assert.Len(t, env.Signatures, origSigCount, "Verify should not mutate Signatures")
}

// TestAdversarial_ThresholdExactlyEqualToVerifiedCount tests the boundary
// condition where verified == threshold exactly.
func TestAdversarial_ThresholdExactlyEqualToVerifiedCount(t *testing.T) {
	const n = 5
	signers := make([]cryptoutil.Signer, n)
	verifiers := make([]cryptoutil.Verifier, n)
	for i := range n {
		s, v := mustCreateTestKey(t)
		signers[i] = s
		verifiers[i] = v
	}

	env := signEnvelope(t, signers...)

	// threshold == verified count: should pass.
	_, err := env.Verify(
		VerifyWithVerifiers(verifiers...),
		VerifyWithThreshold(n),
	)
	require.NoError(t, err, "threshold exactly equal to verified count should pass")

	// threshold == verified + 1: should fail.
	_, err = env.Verify(
		VerifyWithVerifiers(verifiers...),
		VerifyWithThreshold(n+1),
	)
	require.Error(t, err, "threshold one above verified count should fail")
}

// ==========================================================================
// NEW ADVERSARIAL TESTS: Envelope manipulation, stateful verifiers,
// PAE injection, replay attacks, option accumulation, error paths
// ==========================================================================

// bodyConsumingVerifier reads the entire body during Verify(), which could
// cause issues if the verification loop passes the same io.Reader to
// multiple verifiers. In practice, verify.go creates a new bytes.NewReader
// for each call, but this test validates that assumption.
type bodyConsumingVerifier struct {
	inner    cryptoutil.Verifier
	consumed atomic.Int64
}

func (v *bodyConsumingVerifier) KeyID() (string, error) {
	return v.inner.KeyID()
}

func (v *bodyConsumingVerifier) Verify(body io.Reader, sig []byte) error {
	// Drain the entire reader first, then try to verify.
	data, err := io.ReadAll(body)
	v.consumed.Add(int64(len(data)))
	if err != nil {
		return err
	}
	// Re-wrap and delegate.
	return v.inner.Verify(bytes.NewReader(data), sig)
}

func (v *bodyConsumingVerifier) Bytes() ([]byte, error) {
	return v.inner.Bytes()
}

// panicVerifier panics during Verify(). Tests whether the DSSE framework
// recovers from panicking verifiers or propagates the panic.
type panicVerifier struct {
	keyID string
}

func (v *panicVerifier) KeyID() (string, error) {
	return v.keyID, nil
}

func (v *panicVerifier) Verify(_ io.Reader, _ []byte) error {
	panic("verifier intentionally panicked")
}

func (v *panicVerifier) Bytes() ([]byte, error) {
	return []byte("panic"), nil
}

// slowVerifier counts how many times Verify is called. Used to measure
// the total number of verifier invocations for DoS analysis.
type countingVerifier struct {
	inner cryptoutil.Verifier
	calls atomic.Int64
}

func (v *countingVerifier) KeyID() (string, error) {
	return v.inner.KeyID()
}

func (v *countingVerifier) Verify(body io.Reader, sig []byte) error {
	v.calls.Add(1)
	return v.inner.Verify(body, sig)
}

func (v *countingVerifier) Bytes() ([]byte, error) {
	return v.inner.Bytes()
}

// --------------------------------------------------------------------------
// Test: Body-consuming verifier does not corrupt subsequent verification
// --------------------------------------------------------------------------

// TestAdversarial_BodyConsumingVerifierDoesNotCorrupt tests that a verifier
// which fully reads the io.Reader body does not corrupt the body for
// subsequent verifiers operating on the same signature. This validates
// that verify.go creates a fresh Reader for each verifier call.
func TestAdversarial_BodyConsumingVerifierDoesNotCorrupt(t *testing.T) {
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer1 := cryptoutil.NewRSASigner(privKey1, crypto.SHA256)
	signer2 := cryptoutil.NewRSASigner(privKey2, crypto.SHA256)
	realVerifier1 := cryptoutil.NewRSAVerifier(&privKey1.PublicKey, crypto.SHA256)
	realVerifier2 := cryptoutil.NewRSAVerifier(&privKey2.PublicKey, crypto.SHA256)

	// Sign with both keys.
	env, err := Sign("test", bytes.NewReader([]byte("body-consume-test")),
		SignWithSigners(signer1, signer2))
	require.NoError(t, err)

	consuming1 := &bodyConsumingVerifier{inner: realVerifier1}
	consuming2 := &bodyConsumingVerifier{inner: realVerifier2}

	// Both verifiers consume the body. If the reader is shared, the second
	// verifier would get an empty body and fail.
	checked, err := env.Verify(
		VerifyWithVerifiers(consuming1, consuming2),
		VerifyWithThreshold(2),
	)
	require.NoError(t, err, "body-consuming verifiers should both succeed "+
		"because verify.go creates a new Reader per call")

	passed := 0
	for _, cv := range checked {
		if cv.Error == nil {
			passed++
		}
	}
	assert.GreaterOrEqual(t, passed, 2,
		"both body-consuming verifiers should have passed")
	assert.Greater(t, consuming1.consumed.Load(), int64(0), "verifier1 should have consumed bytes")
	assert.Greater(t, consuming2.consumed.Load(), int64(0), "verifier2 should have consumed bytes")
}

// --------------------------------------------------------------------------
// Test: Empty PayloadType handling
// --------------------------------------------------------------------------

// TestAdversarial_EmptyPayloadType tests that an envelope with empty
// payloadType can still be signed and verified. This documents whether
// the implementation enforces any constraints on payloadType.
func TestAdversarial_EmptyPayloadType(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)

	// Empty payloadType.
	env, err := Sign("", bytes.NewReader([]byte("payload with empty type")),
		SignWithSigners(signer))
	require.NoError(t, err, "signing with empty payloadType should succeed")
	assert.Equal(t, "", env.PayloadType)

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err, "verification with empty payloadType should succeed")
}

// --------------------------------------------------------------------------
// Test: PayloadType mismatch between signing and verification
// --------------------------------------------------------------------------

// TestAdversarial_PayloadTypeTamperedAfterSigning tests that changing
// the payloadType after signing causes verification to fail, because
// preauthEncode includes the payloadType in the signed data.
func TestAdversarial_PayloadTypeTamperedAfterSigning(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)

	env, err := Sign("application/json", bytes.NewReader([]byte(`{"data":"value"}`)),
		SignWithSigners(signer))
	require.NoError(t, err)

	// Tamper with the payloadType after signing.
	env.PayloadType = "application/xml"

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err, "changing payloadType after signing should invalidate the signature "+
		"because PAE includes the type")
}

// --------------------------------------------------------------------------
// Test: PAE injection via crafted payloadType
// --------------------------------------------------------------------------

// TestAdversarial_PAEInjectionViaPayloadType tests whether a specially
// crafted payloadType string can create a PAE collision. The PAE format is:
//
//	"DSSEv1 <len(type)> <type> <len(body)> <body>"
//
// If an attacker can craft a type that includes spaces and length fields,
// they might be able to make two different (type, body) pairs produce
// the same PAE. This test verifies that the length-prefix scheme prevents it.
func TestAdversarial_PAEInjectionViaPayloadType(t *testing.T) {
	// Legitimate PAE for type="a 1 X" body="Y" would be:
	//   "DSSEv1 5 a 1 X 1 Y"
	// Could this collide with type="a" body="X 1 Y"?
	//   "DSSEv1 1 a 5 X 1 Y"
	// No, because the lengths differ. But let's verify programmatically.

	pae1 := preauthEncode("a 1 X", []byte("Y"))
	pae2 := preauthEncode("a", []byte("X 1 Y"))

	assert.NotEqual(t, pae1, pae2,
		"PAE with embedded spaces in payloadType must not collide with different decomposition")

	// Additional injection attempt: type contains a digit that looks like a length.
	pae3 := preauthEncode("5 hello", []byte("world"))
	pae4 := preauthEncode("5", []byte("hello 5 world"))

	assert.NotEqual(t, pae3, pae4,
		"PAE should resist injection via numeric prefix in type")

	// Verify that the actual signing/verification catches this.
	signer, verifier := mustCreateTestKey(t)

	env, err := Sign("a 1 X", bytes.NewReader([]byte("Y")),
		SignWithSigners(signer))
	require.NoError(t, err)

	// Change to what would be the "collision" type/body.
	env.PayloadType = "a"
	env.Payload = []byte("X 1 Y")

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err, "PAE injection via payloadType tampering should fail verification")
}

// --------------------------------------------------------------------------
// Test: Signature replay across envelopes with different payloads
// --------------------------------------------------------------------------

// TestAdversarial_CrossEnvelopeSignatureReplay tests that a valid signature
// from one envelope cannot be transplanted to another envelope with different
// content. Even though both envelopes use the same key, the PAE binding to
// the payload should prevent this.
func TestAdversarial_CrossEnvelopeSignatureReplay(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)

	env1, err := Sign("test", bytes.NewReader([]byte("legitimate payload")),
		SignWithSigners(signer))
	require.NoError(t, err)

	env2, err := Sign("test", bytes.NewReader([]byte("different payload")),
		SignWithSigners(signer))
	require.NoError(t, err)

	// Transplant env1's signature onto env2's payload.
	env2.Signatures = env1.Signatures

	_, err = env2.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err, "replayed signature from a different payload must fail")
}

// TestAdversarial_CrossEnvelopePayloadTypeReplay tests replaying a signature
// from an envelope with type "A" onto an envelope with type "B" but same payload.
func TestAdversarial_CrossEnvelopePayloadTypeReplay(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)

	payload := []byte("same payload for both")

	env1, err := Sign("type-A", bytes.NewReader(payload), SignWithSigners(signer))
	require.NoError(t, err)

	env2, err := Sign("type-B", bytes.NewReader(payload), SignWithSigners(signer))
	require.NoError(t, err)

	// Transplant env1's signature onto env2 (different type, same payload).
	env2.Signatures = env1.Signatures

	_, err = env2.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err, "signature for type-A should not verify under type-B")
}

// --------------------------------------------------------------------------
// Test: Multiple VerifyWithVerifiers options accumulate
// --------------------------------------------------------------------------

// TestAdversarial_MultipleVerifyWithVerifiersAccumulate tests whether calling
// VerifyWithVerifiers multiple times in the options accumulates verifiers
// or replaces them. This is an API semantics concern.
func TestAdversarial_MultipleVerifyWithVerifiersAccumulate(t *testing.T) {
	privKey1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privKey2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer1 := cryptoutil.NewRSASigner(privKey1, crypto.SHA256)
	signer2 := cryptoutil.NewRSASigner(privKey2, crypto.SHA256)
	verifier1 := cryptoutil.NewRSAVerifier(&privKey1.PublicKey, crypto.SHA256)
	verifier2 := cryptoutil.NewRSAVerifier(&privKey2.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("two-signers")),
		SignWithSigners(signer1, signer2))
	require.NoError(t, err)

	// Call VerifyWithVerifiers twice with one verifier each.
	// If they accumulate, threshold=2 should pass.
	// If the second replaces the first, only verifier2 is active and threshold=2 fails.
	_, err = env.Verify(
		VerifyWithVerifiers(verifier1),
		VerifyWithVerifiers(verifier2),
		VerifyWithThreshold(2),
	)

	// The implementation sets vo.verifiers = verifiers each time (line 67-69 of verify.go),
	// meaning the SECOND call replaces the first. This is a potential foot-gun.
	// Let's document the actual behavior.
	if err != nil {
		t.Logf("DESIGN NOTE: Multiple VerifyWithVerifiers calls do NOT accumulate. "+
			"The last call wins, replacing previous verifiers. This is a potential API "+
			"foot-gun where callers might expect accumulation. Error: %v", err)

		// Verify that using a single call with both verifiers works.
		_, err = env.Verify(
			VerifyWithVerifiers(verifier1, verifier2),
			VerifyWithThreshold(2),
		)
		require.NoError(t, err, "single VerifyWithVerifiers call with both verifiers should work")
	} else {
		t.Logf("Multiple VerifyWithVerifiers calls accumulate verifiers")
	}
}

// --------------------------------------------------------------------------
// Test: Panicking verifier propagates or is handled
// --------------------------------------------------------------------------

// TestAdversarial_PanickingVerifierPropagatesPanic tests that a verifier
// which panics during Verify() causes the verification to panic (it is
// NOT recovered). This documents that the caller must trust their verifiers.
func TestAdversarial_PanickingVerifierPropagatesPanic(t *testing.T) {
	signer, _ := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	pv := &panicVerifier{keyID: "panic-key"}

	// DSSE Verify does NOT have a recover() call. A panicking verifier
	// will propagate to the caller.
	assert.Panics(t, func() {
		_, _ = env.Verify(VerifyWithVerifiers(pv))
	}, "panicking verifier should propagate panic to caller; DSSE does not recover()")
}

// --------------------------------------------------------------------------
// Test: Verifier count amplification (O(sigs * verifiers) behavior)
// --------------------------------------------------------------------------

// TestAdversarial_VerifierCallCountAmplification tests that the verification
// loop tries every verifier against every signature, creating O(S*V) calls.
// With many signatures and many verifiers, this can be expensive.
func TestAdversarial_VerifierCallCountAmplification(t *testing.T) {
	const numSigners = 3
	const numExtraVerifiers = 7

	signers := make([]cryptoutil.Signer, numSigners)
	countingVerifiers := make([]*countingVerifier, numSigners+numExtraVerifiers)

	for i := range numSigners {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		signers[i] = cryptoutil.NewRSASigner(priv, crypto.SHA256)
		countingVerifiers[i] = &countingVerifier{
			inner: cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256),
		}
	}

	// Create extra verifiers that won't match any signature.
	for i := numSigners; i < numSigners+numExtraVerifiers; i++ {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		countingVerifiers[i] = &countingVerifier{
			inner: cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256),
		}
	}

	env, err := Sign("test", bytes.NewReader([]byte("amplification test")),
		SignWithSigners(signers...))
	require.NoError(t, err)

	verifiers := make([]cryptoutil.Verifier, len(countingVerifiers))
	for i, cv := range countingVerifiers {
		verifiers[i] = cv
	}

	_, err = env.Verify(
		VerifyWithVerifiers(verifiers...),
		VerifyWithThreshold(numSigners),
	)
	require.NoError(t, err)

	totalCalls := int64(0)
	for _, cv := range countingVerifiers {
		totalCalls += cv.calls.Load()
	}

	// Expected: numSigners * len(verifiers) = 3 * 10 = 30
	expectedCalls := int64(numSigners) * int64(numSigners+numExtraVerifiers)
	assert.Equal(t, expectedCalls, totalCalls,
		"verification should make O(sigs * verifiers) calls. "+
			"With %d sigs and %d verifiers, expected %d calls but got %d. "+
			"This is the expected (but potentially DoS-exploitable) behavior.",
		numSigners, numSigners+numExtraVerifiers, expectedCalls, totalCalls)
}

// --------------------------------------------------------------------------
// Test: checkedVerifiers accumulates entries for all verifier-signature pairs
// --------------------------------------------------------------------------

// TestAdversarial_CheckedVerifiersSliceGrowth tests that the returned
// checkedVerifiers slice contains entries for EVERY verifier attempted
// against EVERY signature, including failures. This means the slice can
// grow to O(sigs * verifiers) size.
func TestAdversarial_CheckedVerifiersSliceGrowth(t *testing.T) {
	const numSigners = 2
	const numVerifiers = 5

	signers := make([]cryptoutil.Signer, numSigners)
	verifiers := make([]cryptoutil.Verifier, numVerifiers)

	for i := range numSigners {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		signers[i] = cryptoutil.NewRSASigner(priv, crypto.SHA256)
		verifiers[i] = cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	}
	// Extra wrong verifiers.
	for i := numSigners; i < numVerifiers; i++ {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		verifiers[i] = cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	}

	env, err := Sign("test", bytes.NewReader([]byte("slice growth")),
		SignWithSigners(signers...))
	require.NoError(t, err)

	checked, err := env.Verify(
		VerifyWithVerifiers(verifiers...),
		VerifyWithThreshold(numSigners),
	)
	require.NoError(t, err)

	// checkedVerifiers should have numSigners * numVerifiers entries.
	expectedEntries := numSigners * numVerifiers
	assert.Equal(t, expectedEntries, len(checked),
		"checkedVerifiers should contain one entry per (signature, verifier) pair. "+
			"Got %d entries for %d sigs * %d verifiers = %d expected",
		len(checked), numSigners, numVerifiers, expectedEntries)

	// Count passes vs failures.
	passed, failed := 0, 0
	for _, cv := range checked {
		if cv.Error == nil {
			passed++
		} else {
			failed++
		}
	}

	// Each correct verifier matches exactly 1 of the 2 signatures.
	// Each wrong verifier matches 0.
	// So: 2 signers match their own sigs = 2 passes.
	// Plus: each correct verifier fails on the other sig = 2 fails from correct verifiers.
	// Plus: 3 wrong verifiers * 2 sigs = 6 fails.
	// Total fails = 2 + 6 = 8. Total passes = 2.
	assert.Equal(t, numSigners, passed,
		"only %d verifiers should pass (one per signing key)", numSigners)
	assert.Equal(t, expectedEntries-numSigners, failed)
}

// --------------------------------------------------------------------------
// Test: Same key, different hash algorithm (SHA256 sign, SHA512 verify)
// --------------------------------------------------------------------------

// TestAdversarial_HashMismatchBetweenSignerAndVerifier tests that using
// different hash algorithms for signing vs verification causes failure.
// RSA-PSS binds the hash into the signature, so a mismatch should fail.
func TestAdversarial_HashMismatchBetweenSignerAndVerifier(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	wrongHashVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA512)

	env, err := Sign("test", bytes.NewReader([]byte("hash mismatch")),
		SignWithSigners(signer))
	require.NoError(t, err)

	_, err = env.Verify(VerifyWithVerifiers(wrongHashVerifier))
	require.Error(t, err, "SHA256-signed envelope should not verify with SHA512 verifier")
}

// --------------------------------------------------------------------------
// Test: Very long payloadType string
// --------------------------------------------------------------------------

// TestAdversarial_VeryLongPayloadType tests behavior with an extremely long
// payloadType string. The PAE format encodes len(type), so this should work
// but tests for any buffer/overflow issues.
func TestAdversarial_VeryLongPayloadType(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)

	// 100KB payloadType string.
	longType := make([]byte, 100*1024)
	for i := range longType {
		longType[i] = 'a' + byte(i%26)
	}

	env, err := Sign(string(longType), bytes.NewReader([]byte("payload")),
		SignWithSigners(signer))
	require.NoError(t, err)
	assert.Len(t, env.PayloadType, 100*1024)

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err, "very long payloadType should still sign and verify correctly")
}

// --------------------------------------------------------------------------
// Test: Unicode and special characters in payloadType
// --------------------------------------------------------------------------

// TestAdversarial_UnicodePayloadType tests that unicode characters in
// payloadType are handled correctly through PAE encoding and verification.
func TestAdversarial_UnicodePayloadType(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)

	unicodeTypes := []string{
		"application/\u00e9ncoded",          // accented e
		"type/\u0000null\u0000embedded",     // null bytes
		"type/\U0001F4A9",                   // emoji (pile of poo)
		"type/\xff\xfe",                     // invalid UTF-8
		"type with\ttabs\nand\nnewlines",    // whitespace
		"type/with spaces and\t\tmixed\nws", // mixed whitespace
	}

	for _, utype := range unicodeTypes {
		t.Run(fmt.Sprintf("type=%q", utype), func(t *testing.T) {
			env, err := Sign(utype, bytes.NewReader([]byte("payload")),
				SignWithSigners(signer))
			require.NoError(t, err)

			_, err = env.Verify(VerifyWithVerifiers(verifier))
			require.NoError(t, err, "unicode/special payloadType should round-trip correctly")

			// Verify that tampering any byte still fails.
			env.PayloadType = utype + "x"
			_, err = env.Verify(VerifyWithVerifiers(verifier))
			require.Error(t, err, "tampered unicode payloadType should fail")
		})
	}
}

// --------------------------------------------------------------------------
// Test: No verifiers option provided at all
// --------------------------------------------------------------------------

// TestAdversarial_NoVerifiersOptionProvided tests what happens when Verify
// is called without any VerifyWithVerifiers option. The default verifiers
// slice is nil/empty, so no verifiers will match.
func TestAdversarial_NoVerifiersOptionProvided(t *testing.T) {
	signer, _ := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	// Call Verify with only a threshold, no verifiers.
	_, err := env.Verify(VerifyWithThreshold(1))
	require.Error(t, err, "verify with no verifiers should fail")

	var noMatchErr ErrNoMatchingSigs
	require.ErrorAs(t, err, &noMatchErr,
		"should be ErrNoMatchingSigs when no verifiers are provided")
}

// --------------------------------------------------------------------------
// Test: Envelope KeyID field is purely informational
// --------------------------------------------------------------------------

// TestAdversarial_EnvelopeKeyIDFieldIgnored tests that the KeyID field in
// the Signature struct is completely ignored during verification. An attacker
// could set it to anything without affecting verification outcome.
func TestAdversarial_EnvelopeKeyIDFieldIgnored(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	// Set the envelope's KeyID to something completely wrong.
	env.Signatures[0].KeyID = "totally-wrong-key-id-that-matches-nothing"

	_, err := env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err,
		"envelope KeyID field should be ignored; verification should succeed "+
			"based on cryptographic verification alone")

	// Also test with empty KeyID.
	env.Signatures[0].KeyID = ""
	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err,
		"empty envelope KeyID should not prevent verification")
}

// --------------------------------------------------------------------------
// Test: Payload is nil vs empty
// --------------------------------------------------------------------------

// TestAdversarial_NilVsEmptyPayload tests whether nil and empty payloads
// produce the same PAE and therefore the same signature.
func TestAdversarial_NilVsEmptyPayload(t *testing.T) {
	paeNil := preauthEncode("test", nil)
	paeEmpty := preauthEncode("test", []byte{})

	assert.Equal(t, paeNil, paeEmpty,
		"nil and empty payloads should produce identical PAE")

	// Verify they cross-verify.
	signer, verifier := mustCreateTestKey(t)

	envEmpty, err := Sign("test", bytes.NewReader([]byte{}), SignWithSigners(signer))
	require.NoError(t, err)

	// Manually set payload to nil and verify.
	envEmpty.Payload = nil
	_, err = envEmpty.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err,
		"nil payload should verify the same as empty payload")
}

// --------------------------------------------------------------------------
// Test: Two verifiers wrapping the same key with different wrappers
// --------------------------------------------------------------------------

// TestAdversarial_TwoWrappersOfSameKeyDifferentKeyIDs tests that two
// different wrapper types around the same underlying key, each producing
// a different KeyID, are counted as two distinct verifiers in the threshold.
// This could be a security concern: one compromised key inflates the count.
func TestAdversarial_TwoWrappersOfSameKeyDifferentKeyIDs(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("wrapper test")),
		SignWithSigners(signer))
	require.NoError(t, err)

	// Two wrappers around the same key, different KeyIDs.
	wrapper1 := &fixedKeyIDVerifier{inner: realVerifier, keyID: "wrapper-A"}
	wrapper2 := &fixedKeyIDVerifier{inner: realVerifier, keyID: "wrapper-B"}

	_, err = env.Verify(
		VerifyWithVerifiers(wrapper1, wrapper2),
		VerifyWithThreshold(2),
	)

	// BUG/DESIGN CONCERN: Both wrappers wrap the same key and will both
	// successfully verify. Since they have different KeyIDs, the dedup map
	// will count 2 distinct keys. This means a single compromised key can
	// be wrapped with different KeyIDs to inflate the threshold.
	if err == nil {
		t.Logf("DESIGN CONCERN: Two wrappers of the same cryptographic key with " +
			"different KeyIDs met threshold=2. The dedup is based on KeyID, not on " +
			"the actual cryptographic key material. A single compromised key can inflate " +
			"the threshold by using multiple KeyID aliases.")
	} else {
		t.Logf("Correctly rejected same-key wrappers with different KeyIDs: %v", err)
	}
}

// --------------------------------------------------------------------------
// Test: Concurrent threshold verification with stateful counting verifier
// --------------------------------------------------------------------------

// TestAdversarial_ConcurrentCountingVerifiers tests that counting verifiers
// under concurrent access show the expected call counts without races.
func TestAdversarial_ConcurrentCountingVerifiers(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	env, err := Sign("test", bytes.NewReader([]byte("concurrent counting")),
		SignWithSigners(signer))
	require.NoError(t, err)

	// Each goroutine uses the same counting verifier.
	cv := &countingVerifier{inner: realVerifier}

	const goroutines = 50
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, err := env.Verify(VerifyWithVerifiers(cv))
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d should succeed", i)
	}

	// Each goroutine calls Verify once, with 1 signature and 1 verifier = 1 call per goroutine.
	assert.Equal(t, int64(goroutines), cv.calls.Load(),
		"counting verifier should have been called exactly once per goroutine")
}

// --------------------------------------------------------------------------
// Test: Signature from a different DSSE version (tampered PAE prefix)
// --------------------------------------------------------------------------

// TestAdversarial_TamperedPAEPrefix tests that modifying the PAE version
// prefix does not result in a valid verification. This isn't directly
// testable through the public API (since Sign hardcodes "DSSEv1"), but
// we can verify the PAE function itself.
func TestAdversarial_TamperedPAEPrefix(t *testing.T) {
	paeV1 := preauthEncode("test", []byte("data"))
	assert.True(t, bytes.HasPrefix(paeV1, []byte("DSSEv1 ")),
		"PAE should start with 'DSSEv1 '")

	// If someone changed the version, the PAE would differ.
	paeManual := []byte(fmt.Sprintf("DSSEv2 %d %s %d %s", len("test"), "test", len("data"), "data"))
	assert.NotEqual(t, paeV1, paeManual,
		"different DSSE version string should produce different PAE")
}

// --------------------------------------------------------------------------
// Test: Single byte payload difference
// --------------------------------------------------------------------------

// TestAdversarial_SingleByteDifference tests that a single byte difference
// in the payload causes verification to fail, confirming the signature
// covers every byte of the payload.
func TestAdversarial_SingleByteDifference(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)

	original := []byte("The quick brown fox jumps over the lazy dog")
	env, err := Sign("test", bytes.NewReader(original), SignWithSigners(signer))
	require.NoError(t, err)

	// Verify original works.
	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err)

	// Test flipping each byte position.
	for i := range original {
		tampered := make([]byte, len(original))
		copy(tampered, original)
		tampered[i] ^= 0x01

		tamperedEnv := Envelope{
			Payload:     tampered,
			PayloadType: env.PayloadType,
			Signatures:  env.Signatures,
		}

		_, err := tamperedEnv.Verify(VerifyWithVerifiers(verifier))
		assert.Error(t, err,
			"flipping byte at position %d should fail verification", i)
	}
}

// --------------------------------------------------------------------------
// Test: VerifyWithThreshold called multiple times (last wins)
// --------------------------------------------------------------------------

// TestAdversarial_MultipleThresholdOptionsLastWins tests that calling
// VerifyWithThreshold multiple times uses the last value.
func TestAdversarial_MultipleThresholdOptionsLastWins(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	// Set threshold to 100 first, then override to 1.
	_, err := env.Verify(
		VerifyWithVerifiers(verifier),
		VerifyWithThreshold(100),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err,
		"last VerifyWithThreshold should win; threshold=1 should pass with 1 signer")

	// Set threshold to 1 first, then override to 100.
	_, err = env.Verify(
		VerifyWithVerifiers(verifier),
		VerifyWithThreshold(1),
		VerifyWithThreshold(100),
	)
	require.Error(t, err,
		"last VerifyWithThreshold should win; threshold=100 should fail with 1 signer")
}

// --------------------------------------------------------------------------
// Test: Envelope with certificate data but no roots (error path)
// --------------------------------------------------------------------------

// TestAdversarial_CertificateFieldBlocksRawVerifier documents a real bug in
// the verification logic: when a signature has a non-empty Certificate field
// that fails to parse, the code `continue`s to the next signature, SKIPPING
// the raw verifier loop entirely for that signature.
//
// BUG: An attacker can inject a non-parseable Certificate field into a
// legitimate raw-key signature to prevent it from being verified by the
// raw verifier path. The `continue` on line ~128 of verify.go exits the
// entire signature iteration, bypassing the `for _, verifier := range
// options.verifiers` loop.
//
// Impact: If the attacker can modify envelope JSON after signing (e.g.,
// MITM or storage corruption), they can add Certificate: "garbage" to
// each signature, causing all raw-key verifiers to be skipped, resulting
// in verification failure even though the signatures are cryptographically
// valid.
func TestAdversarial_CertificateFieldBlocksRawVerifier(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	// Verify works without the Certificate field.
	_, err := env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err, "baseline: verification should work without Certificate field")

	// Inject a non-parseable certificate PEM into the signature.
	env.Signatures[0].Certificate = []byte("not-a-real-pem-certificate")

	// Should not panic, and raw verifiers should still work even when
	// Certificate field is unparseable.
	assert.NotPanics(t, func() {
		_, err := env.Verify(VerifyWithVerifiers(verifier))

		// FIXED: The cert parse failure now falls through to the raw verifier
		// loop instead of using 'continue' to skip the entire signature.
		require.NoError(t, err,
			"FIXED: raw-key verification should succeed even when Certificate "+
				"field is unparseable — cert parse failure no longer skips raw verifiers")
	})
}

// --------------------------------------------------------------------------
// Test: Zero-length signature bytes in one slot, valid in another
// --------------------------------------------------------------------------

// TestAdversarial_ZeroLengthSigWithValidSig tests that an envelope with one
// zero-length signature and one valid signature still passes threshold=1.
func TestAdversarial_ZeroLengthSigWithValidSig(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)
	env := signEnvelope(t, signer)

	// Prepend a zero-length signature.
	env.Signatures = append([]Signature{
		{KeyID: "empty-sig", Signature: []byte{}},
	}, env.Signatures...)

	_, err := env.Verify(
		VerifyWithVerifiers(verifier),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err,
		"valid signature should be found despite zero-length signature in envelope")
}
