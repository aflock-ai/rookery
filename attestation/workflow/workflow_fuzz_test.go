//go:build audit

package workflow

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// Shared test helpers for this file
// ==========================================================================

func fuzzMakeRSASignerVerifier(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)
	return signer, verifier
}

// fuzzAttestor is a minimal attestor for testing.
type fuzzAttestor struct {
	name       string
	typeName   string
	runType    attestation.RunType
	attestFunc func(*attestation.AttestationContext) error
	subjects   map[string]cryptoutil.DigestSet
	export     bool
}

func (a *fuzzAttestor) Name() string                 { return a.name }
func (a *fuzzAttestor) Type() string                 { return a.typeName }
func (a *fuzzAttestor) RunType() attestation.RunType { return a.runType }
func (a *fuzzAttestor) Schema() *jsonschema.Schema   { return nil }
func (a *fuzzAttestor) Attest(ctx *attestation.AttestationContext) error {
	if a.attestFunc != nil {
		return a.attestFunc(ctx)
	}
	return nil
}
func (a *fuzzAttestor) Subjects() map[string]cryptoutil.DigestSet {
	if a.subjects != nil {
		return a.subjects
	}
	return map[string]cryptoutil.DigestSet{}
}
func (a *fuzzAttestor) Export() bool { return a.export }

// fuzzFixedKeyIDVerifier wraps a real verifier but returns a fixed KeyID.
type fuzzFixedKeyIDVerifier struct {
	inner cryptoutil.Verifier
	keyID string
}

func (v *fuzzFixedKeyIDVerifier) KeyID() (string, error) { return v.keyID, nil }
func (v *fuzzFixedKeyIDVerifier) Verify(body io.Reader, sig []byte) error {
	return v.inner.Verify(body, sig)
}
func (v *fuzzFixedKeyIDVerifier) Bytes() ([]byte, error) { return v.inner.Bytes() }

// ==========================================================================
// FINDING FUZZ-01: RunWithExports with empty step name is rejected (MEDIUM)
//
// The validateRunOpts function correctly rejects empty step names. But what
// about various boundary inputs -- whitespace, path traversal characters,
// null bytes, extremely long names? This tests that the boundary is
// correctly enforced and documents edge cases that pass validation.
// ==========================================================================

func TestFuzz_StepNameBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		stepName  string
		expectErr bool
		finding   string
	}{
		{
			name:      "empty string rejected",
			stepName:  "",
			expectErr: true,
			finding:   "Correctly rejects empty step name",
		},
		{
			name:      "whitespace-only accepted",
			stepName:  "   \t\n",
			expectErr: false,
			finding: "FUZZ-01a: Whitespace-only step name passes validation. " +
				"Severity: LOW. The step name becomes the collection name, " +
				"which is used as an identifier in policy matching. A whitespace-only " +
				"name could silently break policy evaluation or be confused with " +
				"an empty name in downstream systems.",
		},
		{
			name:      "path traversal chars accepted",
			stepName:  "../../../etc/passwd",
			expectErr: false,
			finding: "FUZZ-01b: Path traversal characters in step name pass validation. " +
				"Severity: LOW. The step name is used in Collection.Name and may be " +
				"used to construct file paths by callers (e.g., output filenames). " +
				"If unsanitized, this could enable directory traversal in callers.",
		},
		{
			name:      "null bytes accepted",
			stepName:  "step\x00name",
			expectErr: false,
			finding: "FUZZ-01c: Null bytes in step name pass validation. " +
				"Severity: LOW. Null bytes could cause truncation in C-backed " +
				"storage systems (e.g., some databases, filesystem operations).",
		},
		{
			name:      "very long name accepted",
			stepName:  strings.Repeat("a", 100000),
			expectErr: false,
			finding: "FUZZ-01d: 100KB step name passes validation. " +
				"Severity: LOW. No length limit on step names. This becomes " +
				"part of the JSON-serialized collection and signed envelope, " +
				"contributing to memory and storage consumption.",
		},
		{
			name:      "JSON injection accepted",
			stepName:  `"},{malicious: true, "name": "`,
			expectErr: false,
			finding: "FUZZ-01e: JSON special characters in step name pass validation. " +
				"Severity: INFO. JSON marshaling handles escaping correctly, but " +
				"the name is passed through to the collection without sanitization.",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RunWithExports(tc.stepName, RunWithInsecure(true))
			if tc.expectErr {
				require.Error(t, err, "expected error for step name: %q", tc.stepName)
			} else {
				require.NoError(t, err, "step name %q should be accepted", tc.stepName)
				t.Log(tc.finding)
			}
		})
	}
}

// ==========================================================================
// FINDING FUZZ-02: RunWithExports with conflicting options (MEDIUM)
//
// Multiple RunWithSigners calls append signers. Two calls with different
// signers accumulate both. The envelope will have signatures from all of
// them. This is arguably correct but not documented and could surprise
// callers who expect the last call to win.
// ==========================================================================

func TestFuzz_ConflictingSigners(t *testing.T) {
	signer1, verifier1 := fuzzMakeRSASignerVerifier(t)
	signer2, verifier2 := fuzzMakeRSASignerVerifier(t)

	att := &fuzzAttestor{
		name:     "test",
		typeName: "https://test/fuzz-02",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {{Hash: crypto.SHA256}: "deadbeef01"},
		},
	}

	results, err := RunWithExports("conflict-test",
		RunWithSigners(signer1),
		RunWithSigners(signer2), // Second call -- does it replace or append?
		RunWithAttestors([]attestation.Attestor{att}),
	)
	require.NoError(t, err)

	// Find the collection result (last one)
	collection := results[len(results)-1]

	sigCount := len(collection.SignedEnvelope.Signatures)
	assert.Equal(t, 2, sigCount,
		"FUZZ-02: Multiple RunWithSigners calls ACCUMULATE signers (append, not replace). "+
			"Severity: MEDIUM. Two signers produce 2 signatures. This is inconsistent with "+
			"VerifyWithVerifiers which REPLACES on each call. API inconsistency between "+
			"run options (append) and verify options (replace) is a footgun.")

	// Verify both signatures are valid
	_, err = collection.SignedEnvelope.Verify(
		dsse.VerifyWithVerifiers(verifier1, verifier2),
		dsse.VerifyWithThreshold(2),
	)
	assert.NoError(t, err, "both signers should have produced valid signatures")
}

// ==========================================================================
// FINDING FUZZ-03: DSSE Sign with empty payload (LOW)
//
// Signing an empty payload succeeds. The PAE encoding handles empty
// payloads correctly (len=0). This is valid per the DSSE spec but worth
// documenting.
// ==========================================================================

func TestFuzz_DSSESignEmptyPayload(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	env, err := dsse.Sign("application/json",
		bytes.NewReader([]byte{}),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err,
		"FUZZ-03: Empty payload is accepted by dsse.Sign. Severity: LOW. "+
			"An empty payload produces a valid signed envelope. "+
			"The DSSE spec does not prohibit empty payloads, but this means "+
			"a caller can accidentally sign nothing and get a valid envelope.")

	assert.Empty(t, env.Payload, "payload should be empty")
	assert.NotEmpty(t, env.Signatures, "should still have a signature")

	// Verify the empty payload envelope is valid
	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.NoError(t, err, "empty payload envelope should verify correctly")
}

// ==========================================================================
// FINDING FUZZ-04: DSSE Sign with binary data containing null bytes (INFO)
//
// Binary payloads with null bytes are handled correctly. The PAE encoding
// uses length-prefix, so null bytes don't cause truncation.
// ==========================================================================

func TestFuzz_DSSESignBinaryPayloadWithNulls(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	// Binary data with null bytes at various positions
	payload := make([]byte, 256)
	for i := range payload {
		payload[i] = byte(i) // includes 0x00 at position 0
	}

	env, err := dsse.Sign("application/octet-stream",
		bytes.NewReader(payload),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err, "binary payload with null bytes should sign successfully")

	assert.Equal(t, payload, env.Payload,
		"payload should be preserved byte-for-byte including null bytes")

	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.NoError(t, err, "binary payload with null bytes should verify correctly")

	t.Log("FUZZ-04: Binary payload with null bytes (0x00) at every byte position " +
		"signs and verifies correctly. Severity: INFO. The PAE length-prefix " +
		"encoding correctly handles binary data without C-string truncation.")
}

// ==========================================================================
// FINDING FUZZ-05: DSSE Verify with duplicate signatures from the same key
// should only count once toward threshold (HIGH)
//
// An attacker could duplicate a valid signature in the envelope to try to
// meet a threshold requirement with a single key. The deduplication logic
// in verify.go (verifiedKeyIDs map) should prevent this.
// ==========================================================================

func TestFuzz_DSSEVerifyDuplicateSigsCountOnce(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	env, err := dsse.Sign("test",
		bytes.NewReader([]byte("payload")),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err)

	// Duplicate the single signature 10 times
	origSig := env.Signatures[0]
	env.Signatures = make([]dsse.Signature, 10)
	for i := range env.Signatures {
		env.Signatures[i] = origSig
	}

	// With threshold=2, this should FAIL because all 10 signatures
	// are from the same key, counting as only 1 unique verifier.
	_, err = env.Verify(
		dsse.VerifyWithVerifiers(verifier),
		dsse.VerifyWithThreshold(2),
	)

	require.Error(t, err,
		"FUZZ-05: Duplicate signatures from the same key should only count once "+
			"toward the threshold. Severity: HIGH (security). If this passes, an "+
			"attacker can inflate threshold count by duplicating signatures.")

	var threshErr dsse.ErrThresholdNotMet
	require.ErrorAs(t, err, &threshErr)
	assert.Equal(t, 1, threshErr.Actual,
		"should count only 1 unique verifier despite 10 duplicate signatures")
	assert.Equal(t, 2, threshErr.Theshold,
		"threshold should be 2 as requested")

	// But threshold=1 should pass
	_, err = env.Verify(
		dsse.VerifyWithVerifiers(verifier),
		dsse.VerifyWithThreshold(1),
	)
	require.NoError(t, err, "threshold=1 should pass with 1 unique key")
}

// ==========================================================================
// FINDING FUZZ-06: DSSE Verify with threshold=0 is rejected (HIGH)
//
// threshold=0 means "no signatures needed" which would defeat the purpose
// of signing. The verify code checks for threshold <= 0 and returns
// ErrInvalidThreshold. This test confirms the guard is in place.
// ==========================================================================

func TestFuzz_DSSEVerifyThresholdZero(t *testing.T) {
	signer, _ := fuzzMakeRSASignerVerifier(t)

	env, err := dsse.Sign("test",
		bytes.NewReader([]byte("payload")),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err)

	_, err = env.Verify(dsse.VerifyWithThreshold(0))

	require.Error(t, err,
		"FUZZ-06: threshold=0 should be rejected. Severity: HIGH (security). "+
			"A threshold of 0 would mean no signatures are needed to pass verification.")

	var invalidThresh dsse.ErrInvalidThreshold
	require.ErrorAs(t, err, &invalidThresh,
		"should return ErrInvalidThreshold for threshold=0")

	// Also test negative threshold
	_, err = env.Verify(dsse.VerifyWithThreshold(-1))
	require.Error(t, err, "negative threshold should also be rejected")
	require.ErrorAs(t, err, &invalidThresh)
}

// ==========================================================================
// FINDING FUZZ-07: DSSE Verify with tampered payload after signing (HIGH)
//
// After signing, if the payload is modified, verification should fail.
// This is the fundamental integrity property of DSSE.
// ==========================================================================

func TestFuzz_DSSEVerifyPayloadTamperedAfterSigning(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	originalPayload := []byte(`{"action":"transfer","amount":100}`)
	env, err := dsse.Sign("application/json",
		bytes.NewReader(originalPayload),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err)

	// Verify the untampered envelope works
	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.NoError(t, err, "untampered envelope should verify")

	// Now tamper with the payload -- simulate an attacker changing the amount
	tamperedPayload := []byte(`{"action":"transfer","amount":999999}`)
	env.Payload = tamperedPayload

	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.Error(t, err,
		"FUZZ-07: Tampered payload must be detected by verification. "+
			"Severity: HIGH (security). If this passes, the signature does not "+
			"protect the payload integrity.")
}

// ==========================================================================
// FINDING FUZZ-08: Race condition -- multiple goroutines calling Sign()
// with the same signer (MEDIUM)
//
// The RSA signer's Sign method is stateless (only reads the private key),
// so concurrent calls should be safe. This test runs with -race flag to
// detect any data races.
// ==========================================================================

func TestFuzz_ConcurrentSignWithSameSigner(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	const goroutines = 50
	var wg sync.WaitGroup
	envelopes := make([]dsse.Envelope, goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf(`{"goroutine":%d}`, idx))
			env, err := dsse.Sign("application/json",
				bytes.NewReader(payload),
				dsse.SignWithSigners(signer),
			)
			envelopes[idx] = env
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	for i := 0; i < goroutines; i++ {
		require.NoError(t, errs[i], "goroutine %d should sign without error", i)
		require.Len(t, envelopes[i].Signatures, 1,
			"goroutine %d should produce exactly 1 signature", i)

		// Verify each envelope
		_, err := envelopes[i].Verify(dsse.VerifyWithVerifiers(verifier))
		assert.NoError(t, err,
			"goroutine %d: envelope should verify correctly", i)
	}

	t.Log("FUZZ-08: 50 concurrent dsse.Sign calls with the same RSA signer " +
		"completed without errors or data races. Severity: MEDIUM. " +
		"RSA signers are safe for concurrent use, but KMS or HSM-backed " +
		"signers with connection pools or rate limits may not be. " +
		"Run with -race flag to detect subtle races.")
}

// ==========================================================================
// FINDING FUZZ-09: Attestor that panics during Attest() is recovered
// by the workflow runtime (HIGH)
//
// The AttestationContext.runAttestor method has a defer/recover that wraps
// panics into errors. This test proves the recovery works and the panic
// does not crash the process.
// ==========================================================================

func TestFuzz_AttestorPanicRecovery(t *testing.T) {
	panicAttestor := &fuzzAttestor{
		name:     "panicker",
		typeName: "https://test/panicker",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			panic("deliberate panic: simulating a crasher bug in an attestor")
		},
	}

	normalAttestor := &fuzzAttestor{
		name:     "normal",
		typeName: "https://test/normal",
		runType:  attestation.ExecuteRunType,
	}

	// Test 1: Panic attestor alone, errors not ignored
	_, err := RunWithExports("panic-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{panicAttestor}),
	)
	require.Error(t, err,
		"FUZZ-09a: Panicking attestor should produce an error, not crash the process")
	assert.Contains(t, err.Error(), "panicked",
		"error message should indicate a panic occurred")

	// Test 2: Panic attestor with ignoreErrors=true
	results, err := RunWithExports("panic-ignore-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{panicAttestor}),
		RunWithIgnoreErrors(true),
	)
	require.NoError(t, err,
		"FUZZ-09b: Panicking attestor with ignoreErrors=true should not propagate error")
	collection := results[len(results)-1]
	assert.Empty(t, collection.Collection.Attestations,
		"panicking attestor should not appear in collection")

	// Test 3: Panic attestor alongside normal attestor
	// Both run in the same phase (ExecuteRunType), so they run concurrently.
	// The panic in one should not kill the other.
	_, err = RunWithExports("panic-with-normal",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{panicAttestor, normalAttestor}),
		RunWithIgnoreErrors(true),
	)
	require.NoError(t, err,
		"FUZZ-09c: Panic in one attestor should not kill concurrent attestors")

	t.Log("FUZZ-09: Attestor panic recovery is working correctly. " +
		"Severity: HIGH. The defer/recover in context.go:runAttestor wraps " +
		"panics into errors. Without this, a single buggy attestor plugin " +
		"would crash the entire workflow process.")
}

// ==========================================================================
// FINDING FUZZ-10: Attestor panic with runtime-level panic (nil pointer)
// ensures the recovery handles non-string panic values (MEDIUM)
// ==========================================================================

func TestFuzz_AttestorNilPointerPanicRecovery(t *testing.T) {
	nilPanicAttestor := &fuzzAttestor{
		name:     "nil-panicker",
		typeName: "https://test/nil-panicker",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			// This will panic with a runtime error, not a string
			var p *int
			_ = *p //nolint:govet // deliberate nil dereference
			return nil
		},
	}

	_, err := RunWithExports("nil-panic-test",
		RunWithInsecure(true),
		RunWithAttestors([]attestation.Attestor{nilPanicAttestor}),
	)
	require.Error(t, err,
		"FUZZ-10: Runtime nil pointer panic should be recovered, not crash the process")
	assert.Contains(t, err.Error(), "panicked",
		"error should contain 'panicked' for runtime panics too")

	t.Log("FUZZ-10: Runtime nil pointer panic is correctly recovered. " +
		"Severity: MEDIUM. The recover() in runAttestor handles both string " +
		"panics and runtime errors (nil deref, index out of bounds, etc). " +
		"This is critical for plugin safety.")
}

// ==========================================================================
// FINDING FUZZ-11: RunWithExports in insecure mode produces envelope with
// no signatures -- the Collection result has a zero-value envelope (MEDIUM)
//
// In insecure mode, the SignedEnvelope field is a zero-value dsse.Envelope.
// Callers who blindly use SignedEnvelope without checking insecure mode
// will operate on an empty envelope.
// ==========================================================================

func TestFuzz_InsecureModeProducesEmptyEnvelope(t *testing.T) {
	results, err := RunWithExports("insecure-test", RunWithInsecure(true))
	require.NoError(t, err)

	collection := results[len(results)-1]
	assert.Empty(t, collection.SignedEnvelope.Signatures,
		"FUZZ-11: Insecure mode produces an envelope with no signatures")
	assert.Empty(t, collection.SignedEnvelope.Payload,
		"insecure mode envelope has empty payload")
	assert.Empty(t, collection.SignedEnvelope.PayloadType,
		"insecure mode envelope has empty payload type")

	// This means the envelope is indistinguishable from an uninitialized value.
	// A caller cannot tell if the envelope was intentionally unsigned or if
	// something went wrong.
	emptyEnv := dsse.Envelope{}
	assert.Equal(t, emptyEnv, collection.SignedEnvelope,
		"FUZZ-11: The SignedEnvelope in insecure mode is a zero-value struct. "+
			"Severity: MEDIUM. Callers cannot distinguish 'insecure mode' from "+
			"'something went wrong and the envelope was never populated'. "+
			"Consider adding a sentinel value or flag.")
}

// ==========================================================================
// FINDING FUZZ-12: DSSE Sign with nil signer in the list (MEDIUM)
//
// dsse.Sign skips nil signers in the loop. If ALL signers are nil, it now
// returns an error after the R3-155 fix. But if a MIX of nil and real
// signers are provided, only the real ones produce signatures.
// ==========================================================================

func TestFuzz_DSSESignNilSignerMixed(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	// Mix of nil and real signers
	env, err := dsse.Sign("test",
		bytes.NewReader([]byte("payload")),
		dsse.SignWithSigners(nil, signer, nil),
	)
	require.NoError(t, err,
		"mixed nil and real signers should succeed")
	assert.Len(t, env.Signatures, 1,
		"FUZZ-12a: Only the non-nil signer should produce a signature. "+
			"Severity: LOW. Nil signers are silently skipped. There is no warning "+
			"that 2 of 3 provided signers were nil.")

	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	assert.NoError(t, err, "the one real signature should verify")

	// All nil signers -- should fail with the R3-155 fix
	_, err = dsse.Sign("test",
		bytes.NewReader([]byte("payload")),
		dsse.SignWithSigners(nil, nil, nil),
	)
	require.Error(t, err,
		"FUZZ-12b: All-nil signers should be rejected. "+
			"The R3-155 fix ensures at least one signature is produced.")
	assert.Contains(t, err.Error(), "no signatures produced")
}

// ==========================================================================
// FINDING FUZZ-13: DSSE Verify with two different keys where both sign
// the same payload -- threshold correctly counts distinct keys (INFO)
// ==========================================================================

func TestFuzz_DSSEVerifyTwoDistinctKeysThreshold(t *testing.T) {
	signer1, verifier1 := fuzzMakeRSASignerVerifier(t)
	signer2, verifier2 := fuzzMakeRSASignerVerifier(t)

	env, err := dsse.Sign("test",
		bytes.NewReader([]byte("multi-signer-payload")),
		dsse.SignWithSigners(signer1, signer2),
	)
	require.NoError(t, err)
	require.Len(t, env.Signatures, 2)

	// threshold=2 with both verifiers should pass
	_, err = env.Verify(
		dsse.VerifyWithVerifiers(verifier1, verifier2),
		dsse.VerifyWithThreshold(2),
	)
	require.NoError(t, err,
		"2 distinct keys should meet threshold=2")

	// threshold=2 with only one verifier should fail
	_, err = env.Verify(
		dsse.VerifyWithVerifiers(verifier1),
		dsse.VerifyWithThreshold(2),
	)
	require.Error(t, err,
		"1 verifier should not meet threshold=2 even with 2 signatures")

	t.Log("FUZZ-13: Threshold counting correctly differentiates distinct keys. " +
		"Severity: INFO. The verifiedKeyIDs map correctly tracks unique keys.")
}

// ==========================================================================
// FINDING FUZZ-14: Duplicate signatures from same key with different
// KeyID field values -- deduplication is based on the VERIFIER's KeyID,
// not the ENVELOPE's KeyID field (HIGH)
//
// An attacker might modify the KeyID field in duplicated signatures
// hoping that the dedup logic uses the envelope's KeyID rather than
// the verifier's KeyID. This test proves the dedup is based on the
// verifier, not the envelope.
// ==========================================================================

func TestFuzz_DuplicateSigsWithDifferentEnvelopeKeyIDs(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	env, err := dsse.Sign("test",
		bytes.NewReader([]byte("payload")),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err)

	// Duplicate the signature but give each copy a different KeyID in the envelope
	origSig := env.Signatures[0]
	env.Signatures = make([]dsse.Signature, 5)
	for i := range env.Signatures {
		sig := origSig
		sig.KeyID = fmt.Sprintf("fake-key-%d", i)
		env.Signatures[i] = sig
	}

	// Even though each signature has a different envelope KeyID,
	// the VERIFIER's KeyID is what's used for deduplication.
	_, err = env.Verify(
		dsse.VerifyWithVerifiers(verifier),
		dsse.VerifyWithThreshold(2),
	)
	require.Error(t, err,
		"FUZZ-14: Duplicate sigs with different envelope KeyIDs should still "+
			"count as 1 unique key. Severity: HIGH (security). The dedup is based on "+
			"the verifier's KeyID(), not the envelope's KeyID field.")

	var threshErr dsse.ErrThresholdNotMet
	require.ErrorAs(t, err, &threshErr)
	assert.Equal(t, 1, threshErr.Actual,
		"should count only 1 unique verifier regardless of envelope KeyID values")
}

// ==========================================================================
// FINDING FUZZ-15: Same verifier object passed twice with same KeyID
// should only count once (HIGH)
//
// If the same verifier object is passed twice in VerifyWithVerifiers,
// it should still only count once because both have the same KeyID.
// ==========================================================================

func TestFuzz_SameVerifierPassedTwice(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	env, err := dsse.Sign("test",
		bytes.NewReader([]byte("payload")),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err)

	_, err = env.Verify(
		dsse.VerifyWithVerifiers(verifier, verifier, verifier),
		dsse.VerifyWithThreshold(2),
	)
	require.Error(t, err,
		"FUZZ-15: Same verifier passed 3 times should count as 1 unique key. "+
			"Severity: HIGH (security). The stableKeyIDs pre-computation ensures "+
			"the same verifier object always produces the same KeyID.")

	var threshErr dsse.ErrThresholdNotMet
	require.ErrorAs(t, err, &threshErr)
	assert.Equal(t, 1, threshErr.Actual,
		"same verifier object passed 3 times should count as 1")
}

// ==========================================================================
// FINDING FUZZ-16: Two wrappers of the same cryptographic key with
// different KeyIDs can inflate the threshold (DESIGN CONCERN)
//
// The deduplication is based on KeyID, not on the underlying key material.
// Two verifier wrappers around the same private key, reporting different
// KeyIDs, will be counted as two distinct keys. A single compromised
// key can thus appear to be multiple keys.
// ==========================================================================

func TestFuzz_SameKeyDifferentKeyIDsInflatesThreshold(t *testing.T) {
	signer, _ := fuzzMakeRSASignerVerifier(t)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer = cryptoutil.NewRSASigner(privKey, crypto.SHA256)
	realVerifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

	env, err := dsse.Sign("test",
		bytes.NewReader([]byte("payload")),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err)

	wrapper1 := &fuzzFixedKeyIDVerifier{inner: realVerifier, keyID: "alias-A"}
	wrapper2 := &fuzzFixedKeyIDVerifier{inner: realVerifier, keyID: "alias-B"}

	_, err = env.Verify(
		dsse.VerifyWithVerifiers(wrapper1, wrapper2),
		dsse.VerifyWithThreshold(2),
	)

	// This WILL pass because the dedup map sees two different KeyIDs.
	// This is the expected (but dangerous) behavior.
	if err == nil {
		t.Log("FUZZ-16: DESIGN CONCERN - Two wrappers of the same cryptographic key " +
			"with different KeyIDs met threshold=2. Severity: MEDIUM. " +
			"The deduplication is KeyID-based, not key-material-based. " +
			"A single compromised key can be wrapped with multiple KeyIDs to " +
			"inflate the threshold count. The security model assumes callers " +
			"provide honest verifier implementations with unique, accurate KeyIDs.")
	} else {
		// If this branch is hit, the implementation has been strengthened
		// to detect same-key wrappers -- that would be a positive change.
		t.Logf("Same-key wrappers correctly rejected: %v", err)
	}
}

// ==========================================================================
// FINDING FUZZ-17: RunWithExports with signed mode and no attestors
// produces an empty collection that still gets signed (MEDIUM)
//
// An empty collection with no subjects will fail intoto.NewStatement.
// This is arguably correct (why sign an empty collection?) but the
// error message may be confusing.
// ==========================================================================

func TestFuzz_SignedModeNoAttestorsSucceeds(t *testing.T) {
	signer, _ := fuzzMakeRSASignerVerifier(t)

	results, err := RunWithExports("empty-signed",
		RunWithSigners(signer),
	)
	// Empty subjects are now allowed (matching upstream witness behavior).
	// An empty collection with no attestors can still be signed.
	require.NoError(t, err,
		"FUZZ-17: Signed mode with no attestors should succeed because "+
			"intoto.NewStatement allows empty subjects (matching witness).")
	require.NotEmpty(t, results, "should produce at least one result (the collection)")
}

// ==========================================================================
// FINDING FUZZ-18: Envelope.Verify with no signatures returns
// ErrNoSignatures -- even if verifiers are provided (INFO)
// ==========================================================================

func TestFuzz_VerifyEnvelopeWithNoSignatures(t *testing.T) {
	_, verifier := fuzzMakeRSASignerVerifier(t)

	env := dsse.Envelope{
		Payload:     []byte("some payload"),
		PayloadType: "test",
		Signatures:  []dsse.Signature{},
	}

	_, err := env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.Error(t, err)

	var noSigs dsse.ErrNoSignatures
	require.ErrorAs(t, err, &noSigs,
		"FUZZ-18: Empty signatures array returns ErrNoSignatures. "+
			"Severity: INFO. The check happens before verifier iteration.")

	// Also test nil signatures
	env.Signatures = nil
	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.Error(t, err)
	require.ErrorAs(t, err, &noSigs,
		"nil signatures should also return ErrNoSignatures")
}

// ==========================================================================
// FINDING FUZZ-19: RunWithExports error is not returned when attestor
// fails but ignoreErrors is true AND the attestor is not an Exporter
// (INFO -- verifying correct behavior)
// ==========================================================================

func TestFuzz_FailingAttestorWithIgnoreErrors(t *testing.T) {
	failAtt := &fuzzAttestor{
		name:     "fail",
		typeName: "https://test/fail",
		runType:  attestation.ExecuteRunType,
		attestFunc: func(_ *attestation.AttestationContext) error {
			return errors.New("attestor-failure")
		},
	}

	goodAtt := &fuzzAttestor{
		name:     "good",
		typeName: "https://test/good",
		runType:  attestation.ExecuteRunType,
		subjects: map[string]cryptoutil.DigestSet{
			"artifact": {{Hash: crypto.SHA256}: "abc123"},
		},
	}

	signer, _ := fuzzMakeRSASignerVerifier(t)

	results, err := RunWithExports("ignore-fail",
		RunWithSigners(signer),
		RunWithAttestors([]attestation.Attestor{failAtt, goodAtt}),
		RunWithIgnoreErrors(true),
	)
	require.NoError(t, err,
		"FUZZ-19: ignoreErrors=true should suppress attestor failures")

	collection := results[len(results)-1]
	// The failing attestor should NOT appear in the collection
	for _, a := range collection.Collection.Attestations {
		assert.NotEqual(t, "https://test/fail", a.Type,
			"failing attestor should be excluded from collection")
	}

	t.Log("FUZZ-19: Correctly excludes failed attestors from collection when " +
		"ignoreErrors=true, while still including successful attestors.")
}

// ==========================================================================
// FINDING FUZZ-20: DSSE envelope JSON roundtrip preserves all fields (INFO)
//
// Signing, marshaling to JSON, unmarshaling, and verifying should work.
// This tests the full serialization roundtrip.
// ==========================================================================

func TestFuzz_DSSEEnvelopeJSONRoundtrip(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	payload := []byte(`{"test":"roundtrip","number":42,"nested":{"key":"value"}}`)
	env, err := dsse.Sign("application/json",
		bytes.NewReader(payload),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err)

	// Marshal to JSON
	jsonBytes, err := json.Marshal(env)
	require.NoError(t, err)

	// Unmarshal back
	var env2 dsse.Envelope
	require.NoError(t, json.Unmarshal(jsonBytes, &env2))

	// Verify the deserialized envelope
	_, err = env2.Verify(dsse.VerifyWithVerifiers(verifier))
	require.NoError(t, err,
		"FUZZ-20: Envelope should verify after JSON roundtrip")

	assert.Equal(t, env.PayloadType, env2.PayloadType)
	assert.Equal(t, env.Payload, env2.Payload)
	assert.Len(t, env2.Signatures, len(env.Signatures))
}

// ==========================================================================
// FINDING FUZZ-21: Multiple attestors across different phases execute
// in phase order (INFO -- verifying correctness)
//
// Attestors in different RunType phases should execute in the order:
// PreMaterial -> Material -> Execute -> Product -> PostProduct
// ==========================================================================

func TestFuzz_AttestorPhaseOrdering(t *testing.T) {
	var mu sync.Mutex
	var order []string

	makeAtt := func(name string, rt attestation.RunType) attestation.Attestor {
		return &fuzzAttestor{
			name:     name,
			typeName: "https://test/" + name,
			runType:  rt,
			attestFunc: func(_ *attestation.AttestationContext) error {
				mu.Lock()
				order = append(order, name)
				mu.Unlock()
				return nil
			},
		}
	}

	attestors := []attestation.Attestor{
		makeAtt("post", attestation.PostProductRunType),
		makeAtt("exec", attestation.ExecuteRunType),
		makeAtt("pre", attestation.PreMaterialRunType),
		makeAtt("mat", attestation.MaterialRunType),
		makeAtt("prod", attestation.ProductRunType),
	}

	_, err := RunWithExports("phase-order",
		RunWithInsecure(true),
		RunWithAttestors(attestors),
	)
	require.NoError(t, err)

	// Within each phase there's only one attestor, so the order should be deterministic
	require.Len(t, order, 5)
	assert.Equal(t, "pre", order[0], "PreMaterial should run first")
	assert.Equal(t, "mat", order[1], "Material should run second")
	assert.Equal(t, "exec", order[2], "Execute should run third")
	assert.Equal(t, "prod", order[3], "Product should run fourth")
	assert.Equal(t, "post", order[4], "PostProduct should run last")

	t.Log("FUZZ-21: Attestor phases execute in the correct order: " +
		"PreMaterial -> Material -> Execute -> Product -> PostProduct. " +
		"Severity: INFO. Ordering is critical for correct attestation " +
		"(materials must be captured before products).")
}

// ==========================================================================
// FINDING FUZZ-22: DSSE Sign stores the raw payload bytes, not a copy,
// which means the caller's buffer mutation after signing could potentially
// affect the envelope (LOW)
//
// This tests whether Sign takes ownership of the bytes or copies them.
// ==========================================================================

func TestFuzz_DSSESignPayloadOwnership(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	payload := []byte("original payload data")
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)

	env, err := dsse.Sign("test",
		bytes.NewReader(payload),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err)

	// The envelope's Payload is set from io.ReadAll(body), which creates
	// a new byte slice. So mutating the original should NOT affect the envelope.
	payload[0] = 'X'

	assert.Equal(t, payloadCopy, env.Payload,
		"FUZZ-22: Envelope payload should be independent of caller's buffer. "+
			"Severity: LOW. io.ReadAll creates a new allocation, so the caller's "+
			"buffer and the envelope's payload are independent.")

	// Verify the envelope is still valid
	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.NoError(t, err, "envelope should still verify after caller mutates their buffer")
}

// ==========================================================================
// FINDING FUZZ-23: Large payload signing does not corrupt data (INFO)
//
// Test with a 1MB payload to ensure no truncation or corruption occurs
// during the sign/verify roundtrip.
// ==========================================================================

func TestFuzz_LargePayloadIntegrity(t *testing.T) {
	signer, verifier := fuzzMakeRSASignerVerifier(t)

	// 1MB payload
	payload := make([]byte, 1*1024*1024)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	env, err := dsse.Sign("application/octet-stream",
		bytes.NewReader(payload),
		dsse.SignWithSigners(signer),
	)
	require.NoError(t, err)

	assert.Len(t, env.Payload, len(payload),
		"payload length should be preserved")
	assert.Equal(t, payload, env.Payload,
		"payload content should be byte-identical")

	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.NoError(t, err,
		"FUZZ-23: 1MB payload signs and verifies correctly. Severity: INFO. "+
			"No truncation or corruption observed.")
}

// ==========================================================================
// FINDING FUZZ-24: Nil signer bypass in validateRunOpts -- the validation
// checks len(signers) > 0 but does not check for nil entries (MEDIUM)
//
// This is a known bug from the adversarial tests but we verify it here
// in the context of the full RunWithExports flow.
// ==========================================================================

func TestFuzz_NilSignerBypassFullFlow(t *testing.T) {
	// validateRunOpts passes because len(signers) == 2
	ro := runOptions{
		stepName: "test",
		signers:  []cryptoutil.Signer{nil, nil},
	}
	err := validateRunOpts(ro)
	assert.NoError(t, err,
		"FUZZ-24: validateRunOpts accepts a slice of all-nil signers. "+
			"Severity: MEDIUM. len(signers)==2 passes the check.")

	// But the actual RunWithExports flow will fail because dsse.Sign
	// now rejects all-nil signers (R3-155 fix).
	_, err = RunWithExports("nil-signer-test",
		RunWithSigners(nil, nil),
		RunWithAttestors([]attestation.Attestor{
			&fuzzAttestor{
				name: "test", typeName: "https://test/a",
				runType: attestation.ExecuteRunType,
				subjects: map[string]cryptoutil.DigestSet{
					"x": {{Hash: crypto.SHA256}: "abc"},
				},
				export: true,
			},
		}),
	)
	require.Error(t, err,
		"FUZZ-24: Full flow with all-nil signers should fail at dsse.Sign level. "+
			"The validation gap in validateRunOpts is caught by dsse.Sign's R3-155 check.")
}

// ==========================================================================
// FINDING FUZZ-25: VerifyWithVerifiers replaces rather than appends
// (verify the actual behavior)
// ==========================================================================

func TestFuzz_VerifyWithVerifiersReplaces(t *testing.T) {
	signer1, verifier1 := fuzzMakeRSASignerVerifier(t)
	signer2, verifier2 := fuzzMakeRSASignerVerifier(t)

	env, err := dsse.Sign("test",
		bytes.NewReader([]byte("two-signer-test")),
		dsse.SignWithSigners(signer1, signer2),
	)
	require.NoError(t, err)

	// Two separate VerifyWithVerifiers calls -- does the second replace the first?
	_, err = env.Verify(
		dsse.VerifyWithVerifiers(verifier1),
		dsse.VerifyWithVerifiers(verifier2),
		dsse.VerifyWithThreshold(2),
	)

	// If they accumulate, this passes (2 verifiers meet threshold=2).
	// If the second replaces the first, only verifier2 is active (threshold=2 fails).
	if err != nil {
		t.Log("FUZZ-25: VerifyWithVerifiers REPLACES on each call (last wins). " +
			"Severity: LOW. This is inconsistent with RunWithSigners which " +
			"APPENDS on each call. API inconsistency.")

		// Verify it works with a single call
		_, err = env.Verify(
			dsse.VerifyWithVerifiers(verifier1, verifier2),
			dsse.VerifyWithThreshold(2),
		)
		require.NoError(t, err, "single call with both verifiers should work")
	} else {
		t.Log("FUZZ-25: VerifyWithVerifiers accumulates (both verifiers counted)")
	}
}
