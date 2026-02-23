//go:build audit

package dsse

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signEnvelope is a test helper that creates a signed envelope using the given signers.
func signEnvelope(t *testing.T, signers ...cryptoutil.Signer) Envelope {
	t.Helper()
	env, err := Sign("application/vnd.test+json", bytes.NewReader([]byte(`{"test":"data"}`)), SignWithSigners(signers...))
	require.NoError(t, err)
	return env
}

// mustCreateTestKey generates an RSA signer/verifier pair.
func mustCreateTestKey(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	signer, verifier, err := createTestKey()
	require.NoError(t, err)
	return signer, verifier
}

// ---------------------------------------------------------------------------
// TestVerifyThresholdEdgeCases
// ---------------------------------------------------------------------------

func TestVerifyThresholdEdgeCases(t *testing.T) {
	// Pre-create keys used across multiple test cases.
	signer1, verifier1 := mustCreateTestKey(t)
	signer2, verifier2 := mustCreateTestKey(t)
	_, wrongVerifier := mustCreateTestKey(t)

	// Envelope signed by signer1 only.
	envSingle := signEnvelope(t, signer1)
	// Envelope signed by both signer1 and signer2.
	envDouble := signEnvelope(t, signer1, signer2)

	// Build an envelope with one valid and one invalid signature.
	envMixed := signEnvelope(t, signer1)
	// Append a bogus signature to envMixed.
	envMixed.Signatures = append(envMixed.Signatures, Signature{
		KeyID:     "bogus-key",
		Signature: []byte("definitely-not-a-valid-signature"),
	})

	// Envelope with empty payload.
	envEmpty, err := Sign("empty", bytes.NewReader([]byte{}), SignWithSigners(signer1))
	require.NoError(t, err)

	// Envelope with duplicated signatures from the same key.
	envDuplicated := signEnvelope(t, signer1)
	origSig := envDuplicated.Signatures[0]
	envDuplicated.Signatures = []Signature{origSig, origSig, origSig}

	tests := []struct {
		name      string
		envelope  Envelope
		threshold int
		verifiers []cryptoutil.Verifier
		wantErr   bool
		errCheck  func(t *testing.T, err error)
		passCheck func(t *testing.T, checked []CheckedVerifier)
	}{
		{
			name:      "threshold=0 should error as invalid",
			envelope:  envSingle,
			threshold: 0,
			verifiers: []cryptoutil.Verifier{verifier1},
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				assert.ErrorAs(t, err, new(ErrInvalidThreshold),
					"threshold=0 should return ErrInvalidThreshold")
			},
		},
		{
			name:      "threshold=-1 should error as invalid",
			envelope:  envSingle,
			threshold: -1,
			verifiers: []cryptoutil.Verifier{verifier1},
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				assert.ErrorAs(t, err, new(ErrInvalidThreshold),
					"negative threshold should return ErrInvalidThreshold")
			},
		},
		{
			name:      "threshold=1 with 0 verifiers and no cert should fail",
			envelope:  envSingle,
			threshold: 1,
			verifiers: nil,
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				// No verifiers means no signatures can be matched.
				assert.ErrorAs(t, err, new(ErrNoMatchingSigs),
					"no verifiers should produce ErrNoMatchingSigs")
			},
		},
		{
			name:      "threshold=1 with 1 valid signature should pass",
			envelope:  envSingle,
			threshold: 1,
			verifiers: []cryptoutil.Verifier{verifier1},
			wantErr:   false,
			passCheck: func(t *testing.T, checked []CheckedVerifier) {
				passed := 0
				for _, cv := range checked {
					if cv.Error == nil {
						passed++
					}
				}
				assert.GreaterOrEqual(t, passed, 1, "at least 1 verifier should pass")
			},
		},
		{
			name:      "threshold=2 with 1 valid signature should fail threshold",
			envelope:  envSingle,
			threshold: 2,
			verifiers: []cryptoutil.Verifier{verifier1},
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				var threshErr ErrThresholdNotMet
				require.ErrorAs(t, err, &threshErr,
					"should be ErrThresholdNotMet")
				assert.Equal(t, 2, threshErr.Theshold)
				assert.Equal(t, 1, threshErr.Actual)
			},
		},
		{
			name:      "threshold=1 with 1 invalid signature should error",
			envelope:  envSingle,
			threshold: 1,
			verifiers: []cryptoutil.Verifier{wrongVerifier},
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				assert.ErrorAs(t, err, new(ErrNoMatchingSigs),
					"wrong verifier should produce ErrNoMatchingSigs")
			},
		},
		{
			name:      "threshold=1 with 2 sigs, 1 valid 1 bogus should pass",
			envelope:  envMixed,
			threshold: 1,
			verifiers: []cryptoutil.Verifier{verifier1},
			wantErr:   false,
			passCheck: func(t *testing.T, checked []CheckedVerifier) {
				passed := 0
				for _, cv := range checked {
					if cv.Error == nil {
						passed++
					}
				}
				assert.GreaterOrEqual(t, passed, 1)
			},
		},
		{
			name:      "threshold=2 with 3 duplicate sigs from same key should fail (only 1 unique)",
			envelope:  envDuplicated,
			threshold: 2,
			verifiers: []cryptoutil.Verifier{verifier1},
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				var threshErr ErrThresholdNotMet
				require.ErrorAs(t, err, &threshErr)
				assert.Equal(t, 1, threshErr.Actual,
					"duplicate key should only count as 1 unique verifier")
			},
		},
		{
			name:      "threshold=1 with empty payload should still verify if signature is valid",
			envelope:  envEmpty,
			threshold: 1,
			verifiers: []cryptoutil.Verifier{verifier1},
			wantErr:   false,
		},
		{
			name:      "threshold=1 with nil verifiers and no cert should fail",
			envelope:  envSingle,
			threshold: 1,
			verifiers: nil,
			wantErr:   true,
		},
		{
			name:      "threshold=MaxInt32 should fail gracefully without panic",
			envelope:  envDouble,
			threshold: math.MaxInt32,
			verifiers: []cryptoutil.Verifier{verifier1, verifier2},
			wantErr:   true,
			errCheck: func(t *testing.T, err error) {
				var threshErr ErrThresholdNotMet
				require.ErrorAs(t, err, &threshErr,
					"max threshold should return ErrThresholdNotMet, not panic")
				assert.Equal(t, math.MaxInt32, threshErr.Theshold)
				assert.Equal(t, 2, threshErr.Actual)
			},
		},
		{
			name:      "threshold=2 with 2 distinct valid signatures should pass",
			envelope:  envDouble,
			threshold: 2,
			verifiers: []cryptoutil.Verifier{verifier1, verifier2},
			wantErr:   false,
			passCheck: func(t *testing.T, checked []CheckedVerifier) {
				passed := 0
				for _, cv := range checked {
					if cv.Error == nil {
						passed++
					}
				}
				assert.Equal(t, 2, passed,
					"2 distinct valid signatures should yield 2 passed verifiers")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := []VerificationOption{
				VerifyWithThreshold(tc.threshold),
			}
			if tc.verifiers != nil {
				opts = append(opts, VerifyWithVerifiers(tc.verifiers...))
			}

			checked, err := tc.envelope.Verify(opts...)

			if tc.wantErr {
				require.Error(t, err)
				if tc.errCheck != nil {
					tc.errCheck(t, err)
				}
			} else {
				require.NoError(t, err)
				if tc.passCheck != nil {
					tc.passCheck(t, checked)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestVerifySignatureManipulation
// ---------------------------------------------------------------------------

func TestVerifySignatureManipulation(t *testing.T) {
	signer1, verifier1 := mustCreateTestKey(t)
	signer2, _ := mustCreateTestKey(t)

	// A legitimate envelope to use as a baseline.
	goodEnv := signEnvelope(t, signer1)
	require.Len(t, goodEnv.Signatures, 1)
	goodSig := goodEnv.Signatures[0].Signature

	// Another envelope signed by a different key with different payload.
	otherEnv, err := Sign("other-type", bytes.NewReader([]byte("other payload")), SignWithSigners(signer2))
	require.NoError(t, err)

	tests := []struct {
		name     string
		mutate   func(t *testing.T, env Envelope) Envelope
		wantErr  bool
		errCheck func(t *testing.T, err error)
	}{
		{
			name: "truncated signature fails",
			mutate: func(t *testing.T, env Envelope) Envelope {
				sig := make([]byte, len(goodSig)/2)
				copy(sig, goodSig[:len(goodSig)/2])
				env.Signatures[0].Signature = sig
				return env
			},
			wantErr: true,
		},
		{
			name: "single bit-flipped signature fails",
			mutate: func(t *testing.T, env Envelope) Envelope {
				sig := make([]byte, len(goodSig))
				copy(sig, goodSig)
				sig[len(sig)/2] ^= 0x01
				env.Signatures[0].Signature = sig
				return env
			},
			wantErr: true,
		},
		{
			name: "all bits flipped signature fails",
			mutate: func(t *testing.T, env Envelope) Envelope {
				sig := make([]byte, len(goodSig))
				for i := range sig {
					sig[i] = goodSig[i] ^ 0xFF
				}
				env.Signatures[0].Signature = sig
				return env
			},
			wantErr: true,
		},
		{
			name: "signature from different payload fails",
			mutate: func(t *testing.T, env Envelope) Envelope {
				env.Signatures[0].Signature = otherEnv.Signatures[0].Signature
				return env
			},
			wantErr: true,
		},
		{
			name: "tampered payload with original signature fails",
			mutate: func(t *testing.T, env Envelope) Envelope {
				env.Payload = []byte("tampered payload content")
				return env
			},
			wantErr: true,
		},
		{
			name: "changed payloadType with original signature fails",
			mutate: func(t *testing.T, env Envelope) Envelope {
				env.PayloadType = "application/tampered"
				return env
			},
			wantErr: true,
		},
		{
			name: "empty signature bytes fail",
			mutate: func(t *testing.T, env Envelope) Envelope {
				env.Signatures[0].Signature = []byte{}
				return env
			},
			wantErr: true,
		},
		{
			name: "nil signature bytes fail",
			mutate: func(t *testing.T, env Envelope) Envelope {
				env.Signatures[0].Signature = nil
				return env
			},
			wantErr: true,
		},
		{
			name: "random garbage signature fails",
			mutate: func(t *testing.T, env Envelope) Envelope {
				garbage := make([]byte, 256)
				_, err := rand.Read(garbage)
				require.NoError(t, err)
				env.Signatures[0].Signature = garbage
				return env
			},
			wantErr: true,
		},
		{
			name: "signature with extra trailing bytes fails",
			mutate: func(t *testing.T, env Envelope) Envelope {
				sig := make([]byte, len(goodSig)+32)
				copy(sig, goodSig)
				_, err := rand.Read(sig[len(goodSig):])
				require.NoError(t, err)
				env.Signatures[0].Signature = sig
				return env
			},
			wantErr: true,
		},
		{
			name: "signature with prepended bytes fails",
			mutate: func(t *testing.T, env Envelope) Envelope {
				prefix := make([]byte, 16)
				_, err := rand.Read(prefix)
				require.NoError(t, err)
				sig := append(prefix, goodSig...)
				env.Signatures[0].Signature = sig
				return env
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Start from a deep copy of the good envelope each time.
			env := Envelope{
				Payload:     make([]byte, len(goodEnv.Payload)),
				PayloadType: goodEnv.PayloadType,
				Signatures: []Signature{
					{
						KeyID:     goodEnv.Signatures[0].KeyID,
						Signature: make([]byte, len(goodEnv.Signatures[0].Signature)),
					},
				},
			}
			copy(env.Payload, goodEnv.Payload)
			copy(env.Signatures[0].Signature, goodEnv.Signatures[0].Signature)

			env = tc.mutate(t, env)

			_, err := env.Verify(
				VerifyWithVerifiers(verifier1),
				VerifyWithThreshold(1),
			)

			if tc.wantErr {
				require.Error(t, err, "manipulated signature should fail verification")
				if tc.errCheck != nil {
					tc.errCheck(t, err)
				}
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestVerifyNoSignatures
// ---------------------------------------------------------------------------

func TestVerifyNoSignatures(t *testing.T) {
	_, verifier := mustCreateTestKey(t)

	env := Envelope{
		Payload:     []byte("some data"),
		PayloadType: "test",
		Signatures:  []Signature{},
	}

	_, err := env.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err)
	assert.ErrorAs(t, err, new(ErrNoSignatures),
		"envelope with no signatures should return ErrNoSignatures")
}

// ---------------------------------------------------------------------------
// TestVerifyWithNilSignatureSlice
// ---------------------------------------------------------------------------

func TestVerifyWithNilSignatureSlice(t *testing.T) {
	_, verifier := mustCreateTestKey(t)

	env := Envelope{
		Payload:     []byte("some data"),
		PayloadType: "test",
		Signatures:  nil,
	}

	_, err := env.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err)
	assert.ErrorAs(t, err, new(ErrNoSignatures))
}

// ---------------------------------------------------------------------------
// TestPreauthEncodeConsistency
// ---------------------------------------------------------------------------

func TestPreauthEncodeConsistency(t *testing.T) {
	// preauthEncode must be deterministic.
	pae1 := preauthEncode("type1", []byte("body1"))
	pae2 := preauthEncode("type1", []byte("body1"))
	assert.Equal(t, pae1, pae2, "preauthEncode must be deterministic")

	// Different types produce different PAE.
	pae3 := preauthEncode("type2", []byte("body1"))
	assert.NotEqual(t, pae1, pae3, "different types should produce different PAE")

	// Different bodies produce different PAE.
	pae4 := preauthEncode("type1", []byte("body2"))
	assert.NotEqual(t, pae1, pae4, "different bodies should produce different PAE")

	// Empty body.
	pae5 := preauthEncode("type1", []byte{})
	pae6 := preauthEncode("type1", nil)
	assert.Equal(t, pae5, pae6, "empty and nil body should produce same PAE")
}

// ---------------------------------------------------------------------------
// TestVerifyMultipleVerifiersSameEnvelope
// ---------------------------------------------------------------------------

func TestVerifyMultipleVerifiersSameEnvelope(t *testing.T) {
	signer1, verifier1 := mustCreateTestKey(t)
	_, wrongVerifier1 := mustCreateTestKey(t)
	_, wrongVerifier2 := mustCreateTestKey(t)

	env := signEnvelope(t, signer1)

	checked, err := env.Verify(
		VerifyWithVerifiers(wrongVerifier1, verifier1, wrongVerifier2),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err)

	passed := 0
	failed := 0
	for _, cv := range checked {
		if cv.Error == nil {
			passed++
		} else {
			failed++
		}
	}
	assert.Equal(t, 1, passed, "only the correct verifier should pass")
	assert.Equal(t, 2, failed, "wrong verifiers should be recorded as failed")
}

// ---------------------------------------------------------------------------
// TestVerifyRSAKeyLengths
// ---------------------------------------------------------------------------

func TestVerifyRSAKeyLengths(t *testing.T) {
	keySizes := []int{2048, 3072, 4096}
	for _, bits := range keySizes {
		t.Run(fmt.Sprintf("RSA_%d", bits), func(t *testing.T) {
			privKey, err := rsa.GenerateKey(rand.Reader, bits)
			require.NoError(t, err)

			signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
			verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

			env, err := Sign("test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
			require.NoError(t, err)

			_, err = env.Verify(VerifyWithVerifiers(verifier))
			require.NoError(t, err)
		})
	}
}

// ---------------------------------------------------------------------------
// TestVerifyLargePayload
// ---------------------------------------------------------------------------

func TestVerifyLargePayload(t *testing.T) {
	signer, verifier := mustCreateTestKey(t)

	// 1 MB payload.
	payload := make([]byte, 1024*1024)
	_, err := rand.Read(payload)
	require.NoError(t, err)

	env, err := Sign("application/octet-stream", bytes.NewReader(payload), SignWithSigners(signer))
	require.NoError(t, err)

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err, "large payload should verify successfully")
}
