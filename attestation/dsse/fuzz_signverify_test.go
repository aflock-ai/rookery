//go:build audit

// Copyright 2025 The Witness Contributors
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

package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Helper: fast ed25519 key generation for fuzz targets
// ---------------------------------------------------------------------------

// fuzzED25519KeyPair generates an ed25519 key pair optimized for fuzz throughput.
// Ed25519 keygen is ~100x faster than RSA-2048, which matters when the fuzzer
// calls this on every iteration.
func fuzzED25519KeyPair(t *testing.T) (*cryptoutil.ED25519Signer, *cryptoutil.ED25519Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Skip("ed25519 key generation failed")
	}
	return cryptoutil.NewED25519Signer(priv), cryptoutil.NewED25519Verifier(pub)
}

// ---------------------------------------------------------------------------
// Fuzz 1: FuzzDSSESignVerifyRoundTrip
//
// Generate random payloads and payload types, sign with a generated key,
// then verify. The round trip MUST always succeed for any (payloadType, payload)
// pair. If it doesn't, that is a bug.
// ---------------------------------------------------------------------------

func FuzzDSSESignVerifyRoundTrip(f *testing.F) {
	// Seed corpus: diverse payload types and bodies
	f.Add("application/vnd.in-toto+json", []byte(`{"_type":"https://in-toto.io/Statement/v0.1"}`))
	f.Add("application/json", []byte("{}"))
	f.Add("", []byte(""))
	f.Add("", []byte(nil))
	f.Add("text/plain", []byte("hello world"))
	f.Add("application/octet-stream", []byte{0x00, 0x01, 0x02, 0xff, 0xfe})
	f.Add("\x00", []byte{0x00})
	f.Add("type\x00with\x00nulls", []byte("payload\x00with\x00nulls"))
	f.Add("application/json\nX-Injected: header", []byte("body"))
	f.Add(strings.Repeat("A", 65536), []byte("short"))
	f.Add("short", bytes.Repeat([]byte("B"), 65536))
	f.Add("\xff\xfe\xfd", []byte("\xff\xfe\xfd"))              // invalid UTF-8
	f.Add("type/\U0001F512", []byte("\U0001F4A9"))             // emoji
	f.Add("\u4e16\u754c", []byte("\u4e16\u754c"))              // CJK
	f.Add("cafe\u0301", []byte("latte\u0301"))                 // combining accent
	f.Add("DSSEv1 5 fake 3 pae", []byte("nested PAE attempt")) // PAE-in-type
	f.Add("5 injected", []byte("body"))                        // digit-prefix type
	f.Add(" ", []byte(" "))                                    // spaces only
	f.Add("\t\n\r", []byte("\t\n\r"))                          // whitespace

	f.Fuzz(func(t *testing.T, payloadType string, payload []byte) {
		signer, verifier := fuzzED25519KeyPair(t)

		// Sign
		env, err := Sign(payloadType, bytes.NewReader(payload), SignWithSigners(signer))
		if err != nil {
			// Sign returning an error is acceptable (e.g. reader failures).
			// But it must not panic.
			return
		}

		// Verify structural invariants of the envelope
		if env.PayloadType != payloadType {
			t.Fatalf("envelope PayloadType mismatch: got %q, want %q", env.PayloadType, payloadType)
		}
		if !bytes.Equal(env.Payload, payload) {
			t.Fatalf("envelope Payload mismatch: got %d bytes, want %d bytes", len(env.Payload), len(payload))
		}
		if len(env.Signatures) != 1 {
			t.Fatalf("expected 1 signature, got %d", len(env.Signatures))
		}
		if len(env.Signatures[0].Signature) == 0 {
			t.Fatal("signature bytes are empty after successful sign")
		}

		// Verify round trip: this MUST succeed for every input
		checkedVerifiers, err := env.Verify(VerifyWithVerifiers(verifier))
		if err != nil {
			t.Fatalf("round-trip verification failed for payloadType=%q payload_len=%d: %v",
				payloadType, len(payload), err)
		}

		// At least one verifier must have passed without error
		passed := 0
		for _, cv := range checkedVerifiers {
			if cv.Error == nil {
				passed++
			}
		}
		if passed == 0 {
			t.Fatal("no verifiers passed despite Verify returning nil error")
		}

		// Verify that the payload survives a JSON round trip and still verifies.
		// This catches issues where JSON encoding corrupts base64 or string fields.
		jsonData, err := json.Marshal(env)
		if err != nil {
			// JSON marshal can fail for non-UTF-8 strings in PayloadType.
			// That is a known limitation, not a panic.
			return
		}
		var env2 Envelope
		if err := json.Unmarshal(jsonData, &env2); err != nil {
			return
		}
		// Payload ([]byte) is base64-encoded in JSON, so it survives intact.
		// PayloadType (string) may be corrupted by JSON marshal if it contains
		// non-UTF-8 bytes. Only verify if PayloadType survived.
		if env2.PayloadType == payloadType && bytes.Equal(env2.Payload, payload) {
			_, err = env2.Verify(VerifyWithVerifiers(verifier))
			if err != nil {
				t.Fatalf("round-trip verification failed after JSON round-trip: %v", err)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// Fuzz 2: FuzzDSSEVerifyMalformedEnvelope
//
// Generate random JSON that looks like a DSSE envelope (random signatures,
// payload, payloadType) and try to verify. Should NEVER panic.
// ---------------------------------------------------------------------------

func FuzzDSSEVerifyMalformedEnvelope(f *testing.F) {
	// Seed: valid-ish JSON shapes
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"payload":"","payloadType":"","signatures":[]}`))
	f.Add([]byte(`{"payload":"aGVsbG8=","payloadType":"text/plain","signatures":[{"keyid":"k","sig":"AAAA"}]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`"string"`))
	f.Add([]byte{0xff, 0xfe, 0x00})
	f.Add([]byte(`{"payload":0,"payloadType":false,"signatures":"bad"}`))
	f.Add([]byte(`{"signatures":[{"keyid":"","sig":"","certificate":"not-pem"}]}`))
	f.Add([]byte(`{"signatures":[{"certificate":"-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----"}]}`))
	f.Add([]byte(`{"payload":"aGVsbG8=","payloadType":"test","signatures":[{"keyid":"k","sig":"AAAA"},{"keyid":"k","sig":"AAAA"}]}`))
	// Extremely nested JSON
	f.Add([]byte(`{"payload":"","payloadType":"","signatures":[{"keyid":"","sig":"","timestamps":[{"type":"tsp","data":"AAAA"}]}]}`))
	// Large signature count
	f.Add(func() []byte {
		sigs := make([]Signature, 50)
		for i := range sigs {
			sigs[i] = Signature{KeyID: fmt.Sprintf("key-%d", i), Signature: []byte("garbage")}
		}
		env := Envelope{Payload: []byte("p"), PayloadType: "t", Signatures: sigs}
		data, _ := json.Marshal(env)
		return data
	}())
	// Unicode in fields
	f.Add([]byte(`{"payload":"","payloadType":"\u0000\uffff","signatures":[{"keyid":"\u202e","sig":"AA=="}]}`))
	// Huge payload
	f.Add([]byte(`{"payload":"` + string(bytes.Repeat([]byte("QUFB"), 5000)) + `","payloadType":"t","signatures":[{"keyid":"k","sig":"AA=="}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			// Invalid JSON or type mismatch: no panic is the invariant.
			return
		}

		// Create a real verifier for code paths that check signatures
		_, verifier := fuzzED25519KeyPair(t)

		// All of these must not panic. We don't care about the error.
		_, _ = env.Verify()
		_, _ = env.Verify(VerifyWithVerifiers(verifier))
		_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(1))
		_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(2))
		_, _ = env.Verify(VerifyWithThreshold(0))
		_, _ = env.Verify(VerifyWithThreshold(-1))

		// Re-marshal and unmarshal for stability (no panic on round-trip)
		remarshaled, err := json.Marshal(env)
		if err != nil {
			return
		}
		var env2 Envelope
		if err := json.Unmarshal(remarshaled, &env2); err != nil {
			return
		}
		_, _ = env2.Verify(VerifyWithVerifiers(verifier))
	})
}

// ---------------------------------------------------------------------------
// Fuzz 3: FuzzPAEEncoding
//
// Fuzz the PAE encoding function with random strings. Should never panic
// and should always produce valid, deterministic, structurally correct output.
// ---------------------------------------------------------------------------

func FuzzPAEEncoding(f *testing.F) {
	// Seed corpus: diverse edge cases
	f.Add("application/vnd.in-toto+json", []byte(`{"_type":"statement"}`))
	f.Add("", []byte(""))
	f.Add("", []byte(nil))
	f.Add("\x00", []byte{0x00})
	f.Add("a\x00b", []byte("c\x00d"))
	f.Add("type with spaces", []byte("body with spaces"))
	f.Add(strings.Repeat("X", 100000), []byte("short"))
	f.Add("short", bytes.Repeat([]byte{0xff}, 100000))
	f.Add("DSSEv1 0 DSSEv1 0 ", []byte("nested PAE"))
	f.Add("42 fake", []byte("injection"))
	f.Add("0", []byte(""))
	f.Add("-1", []byte("negative"))
	f.Add("\n\r\t", []byte("\n\r\t"))
	f.Add("\u202e\u0041\u0042", []byte("RTL override"))
	f.Add("\xef\xbb\xbf", []byte("\xef\xbb\xbf")) // BOM

	f.Fuzz(func(t *testing.T, bodyType string, body []byte) {
		// Must not panic
		result := preauthEncode(bodyType, body)
		if result == nil {
			t.Fatal("preauthEncode returned nil")
		}

		// 1. Determinism: same input -> same output
		result2 := preauthEncode(bodyType, body)
		if !bytes.Equal(result, result2) {
			t.Fatal("preauthEncode is not deterministic")
		}

		// 2. Must start with "DSSEv1 "
		const prefix = "DSSEv1 "
		if !bytes.HasPrefix(result, []byte(prefix)) {
			t.Fatalf("result does not start with 'DSSEv1 ', got: %q", result[:min(len(result), 20)])
		}

		// 3. Structural validation: parse the PAE format
		s := string(result)
		rest := s[len(prefix):]

		// Parse type length
		spaceIdx := strings.Index(rest, " ")
		if spaceIdx < 0 {
			t.Fatal("missing space after type length")
		}
		typeLenStr := rest[:spaceIdx]
		typeLen, err := strconv.Atoi(typeLenStr)
		if err != nil {
			t.Fatalf("type length not a valid integer: %q", typeLenStr)
		}
		if typeLen != len(bodyType) {
			t.Fatalf("type length mismatch: encoded=%d, actual=%d", typeLen, len(bodyType))
		}
		rest = rest[spaceIdx+1:]

		// Extract the type
		if len(rest) < typeLen {
			t.Fatalf("truncated: need %d bytes for type, have %d", typeLen, len(rest))
		}
		extractedType := rest[:typeLen]
		if extractedType != bodyType {
			t.Fatalf("type mismatch: extracted=%q, expected=%q", extractedType, bodyType)
		}
		rest = rest[typeLen:]

		// Space separator
		if len(rest) == 0 || rest[0] != ' ' {
			t.Fatalf("missing space after type field")
		}
		rest = rest[1:]

		// Parse body length
		spaceIdx = strings.Index(rest, " ")
		if spaceIdx < 0 {
			t.Fatal("missing space after body length")
		}
		bodyLenStr := rest[:spaceIdx]
		bodyLen, err := strconv.Atoi(bodyLenStr)
		if err != nil {
			t.Fatalf("body length not a valid integer: %q", bodyLenStr)
		}
		if bodyLen != len(body) {
			t.Fatalf("body length mismatch: encoded=%d, actual=%d", bodyLen, len(body))
		}
		rest = rest[spaceIdx+1:]

		// Extract and validate the body
		extractedBody := []byte(rest)
		if !bytes.Equal(extractedBody, body) {
			t.Fatalf("body mismatch: extracted %d bytes, expected %d bytes",
				len(extractedBody), len(body))
		}

		// 4. Total length consistency
		expectedLen := len(prefix) + len(typeLenStr) + 1 + len(bodyType) + 1 + len(bodyLenStr) + 1 + len(body)
		if len(result) != expectedLen {
			t.Fatalf("total length mismatch: got=%d, expected=%d", len(result), expectedLen)
		}
	})
}

// ---------------------------------------------------------------------------
// Fuzz 4: FuzzDSSESignEmptyPayload
//
// Sign empty/nil payloads with various payload types. Should handle gracefully:
// either succeed (and verify) or return a clean error, never panic.
// ---------------------------------------------------------------------------

func FuzzDSSESignEmptyPayload(f *testing.F) {
	// The payload dimension is fixed as empty/nil; we fuzz the payload type
	// and whether the payload is nil vs empty []byte.
	f.Add("application/json", true)
	f.Add("", true)
	f.Add("", false)
	f.Add("\x00", true)
	f.Add("\x00", false)
	f.Add("application/vnd.in-toto+json", false)
	f.Add(strings.Repeat("X", 65536), true)
	f.Add("\xff\xfe", true)
	f.Add("DSSEv1 0  0 ", false)
	f.Add("type\nwith\nnewlines", true)
	f.Add("type with spaces", false)
	f.Add("42 injection", true)

	f.Fuzz(func(t *testing.T, payloadType string, useNil bool) {
		signer, verifier := fuzzED25519KeyPair(t)

		var payload []byte
		if !useNil {
			payload = []byte{}
		}
		// When useNil is true, payload remains nil

		var reader *bytes.Reader
		if payload == nil {
			reader = bytes.NewReader(nil)
		} else {
			reader = bytes.NewReader(payload)
		}

		// Sign must not panic
		env, err := Sign(payloadType, reader, SignWithSigners(signer))
		if err != nil {
			// Error is acceptable, panic is not
			return
		}

		// Envelope payload should be empty (not nil, since io.ReadAll returns []byte{} for empty reader)
		if len(env.Payload) != 0 {
			t.Fatalf("expected empty payload, got %d bytes", len(env.Payload))
		}

		// Payload type should be preserved
		if env.PayloadType != payloadType {
			t.Fatalf("payloadType mismatch: got %q, want %q", env.PayloadType, payloadType)
		}

		// Must have exactly one signature
		if len(env.Signatures) != 1 {
			t.Fatalf("expected 1 signature for empty payload, got %d", len(env.Signatures))
		}

		// Verify must succeed: an empty payload is valid, not an error
		_, err = env.Verify(VerifyWithVerifiers(verifier))
		if err != nil {
			t.Fatalf("verification failed for empty payload with payloadType=%q: %v",
				payloadType, err)
		}
	})
}

// ---------------------------------------------------------------------------
// Fuzz 5: FuzzDSSEVerifyCorruptedSignature
//
// Sign a valid payload, then corrupt the signature bytes. Verify should
// fail (not panic). If the corruption is a no-op (mutated byte == original),
// verify may pass, which is fine.
// ---------------------------------------------------------------------------

func FuzzDSSEVerifyCorruptedSignature(f *testing.F) {
	f.Add([]byte("hello world"), "application/json", uint16(0), byte(0xff), uint8(1))
	f.Add([]byte(""), "", uint16(5), byte(0x00), uint8(0))
	f.Add([]byte("test payload"), "text/plain", uint16(10), byte(0x41), uint8(5))
	f.Add([]byte{0x00, 0xff, 0xfe}, "binary/octet-stream", uint16(32), byte(0xfe), uint8(3))
	f.Add([]byte("\U0001F512"), "emoji", uint16(0), byte(0x01), uint8(1))
	f.Add(bytes.Repeat([]byte("A"), 10000), "large", uint16(100), byte(0xab), uint8(10))
	f.Add([]byte("x"), "t", uint16(0), byte(0x00), uint8(255))
	f.Add([]byte("a"), "b", uint16(65535), byte(0x80), uint8(128))

	f.Fuzz(func(t *testing.T, payload []byte, payloadType string, mutPos uint16, mutByte byte, numMutations uint8) {
		signer, verifier := fuzzED25519KeyPair(t)

		env, err := Sign(payloadType, bytes.NewReader(payload), SignWithSigners(signer))
		if err != nil {
			return
		}

		if len(env.Signatures) == 0 || len(env.Signatures[0].Signature) == 0 {
			return
		}

		originalSig := make([]byte, len(env.Signatures[0].Signature))
		copy(originalSig, env.Signatures[0].Signature)

		// Apply mutations to the signature
		mutatedSig := make([]byte, len(originalSig))
		copy(mutatedSig, originalSig)

		mutations := int(numMutations)
		if mutations == 0 {
			mutations = 1
		}
		if mutations > len(mutatedSig) {
			mutations = len(mutatedSig)
		}

		for i := 0; i < mutations; i++ {
			idx := (int(mutPos) + i) % len(mutatedSig)
			mutatedSig[idx] = mutByte ^ byte(i)
		}

		env.Signatures[0].Signature = mutatedSig

		// Must NEVER panic, regardless of signature corruption
		checkedVerifiers, err := env.Verify(VerifyWithVerifiers(verifier))

		// If verification succeeded, the mutation must have been a no-op
		if err == nil {
			if !bytes.Equal(mutatedSig, originalSig) {
				t.Fatalf("SECURITY: verification passed after non-trivial signature corruption. "+
					"sig_len=%d, mutPos=%d, mutByte=0x%02x, numMutations=%d",
					len(originalSig), mutPos, mutByte, numMutations)
			}
		}

		// CheckedVerifiers should never contain nil Verifier with nil Error
		for i, cv := range checkedVerifiers {
			if cv.Verifier == nil && cv.Error == nil {
				t.Fatalf("checkedVerifiers[%d] has nil Verifier with nil Error", i)
			}
		}

		// Also try with various thresholds to exercise error paths
		_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(2))
		_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(0))
		_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(-1))
	})
}

// ===========================================================================
// Table-driven edge case tests discovered while reading the code
// ===========================================================================

// TestSignVerifyEdgeCases_NilBodyReader tests that Sign handles a nil body
// reader without panicking. The io.ReadAll call in Sign will dereference the
// reader, so nil should either return an error or panic (which we catch).
func TestSignVerifyEdgeCases_NilBodyReader(t *testing.T) {
	signer, _ := fuzzED25519KeyPair(t)

	// Catch panic — Sign calls io.ReadAll(body) which will panic on nil.
	// We document this behavior rather than fixing it.
	defer func() {
		if r := recover(); r != nil {
			t.Logf("Sign panics on nil body reader: %v (known behavior)", r)
		}
	}()

	_, err := Sign("test", nil, SignWithSigners(signer))
	if err == nil {
		t.Log("Sign accepted nil body reader without error (unexpected)")
	}
}

// TestSignVerifyEdgeCases_AllNilSigners tests that Sign rejects a signer
// slice containing only nil entries (R3-155 fix).
func TestSignVerifyEdgeCases_AllNilSigners(t *testing.T) {
	_, err := Sign("test", bytes.NewReader([]byte("data")),
		SignWithSigners(nil, nil, nil))
	require.Error(t, err, "all-nil signers should produce an error")
	assert.Contains(t, err.Error(), "no signatures produced")
}

// TestSignVerifyEdgeCases_ZeroLengthSignatureInEnvelope tests that an
// envelope with a zero-length signature value is handled without panic.
func TestSignVerifyEdgeCases_ZeroLengthSignatureInEnvelope(t *testing.T) {
	_, verifier := fuzzED25519KeyPair(t)

	env := Envelope{
		Payload:     []byte("data"),
		PayloadType: "test",
		Signatures: []Signature{
			{KeyID: "k", Signature: []byte{}},
		},
	}

	assert.NotPanics(t, func() {
		_, _ = env.Verify(VerifyWithVerifiers(verifier))
	})
}

// TestSignVerifyEdgeCases_PayloadTypeAffectsPAE verifies that changing
// only the payloadType invalidates the signature. This is critical because
// the PAE encoding includes the payloadType — if it were ignored, an
// attacker could reinterpret the payload under a different type.
func TestSignVerifyEdgeCases_PayloadTypeAffectsPAE(t *testing.T) {
	signer, verifier := fuzzED25519KeyPair(t)
	payload := []byte(`{"step":"build"}`)

	env, err := Sign("application/vnd.in-toto+json", bytes.NewReader(payload),
		SignWithSigners(signer))
	require.NoError(t, err)

	// Tamper the payload type
	env.PayloadType = "text/plain"

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err, "changing payloadType must invalidate the signature")
}

// TestSignVerifyEdgeCases_SingleBitFlipInPayload verifies that a single
// bit flip in the payload invalidates the signature.
func TestSignVerifyEdgeCases_SingleBitFlipInPayload(t *testing.T) {
	signer, verifier := fuzzED25519KeyPair(t)
	payload := []byte("the quick brown fox jumps over the lazy dog")

	env, err := Sign("text/plain", bytes.NewReader(payload), SignWithSigners(signer))
	require.NoError(t, err)

	// Sanity: verify passes before tampering
	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err)

	// Flip a single bit in the payload
	env.Payload[len(env.Payload)/2] ^= 0x01

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err, "single bit flip in payload must invalidate signature")
}

// TestSignVerifyEdgeCases_SignatureBytesTruncated tests that truncating
// the signature to various lengths is handled gracefully.
func TestSignVerifyEdgeCases_SignatureBytesTruncated(t *testing.T) {
	signer, verifier := fuzzED25519KeyPair(t)

	env, err := Sign("test", bytes.NewReader([]byte("data")), SignWithSigners(signer))
	require.NoError(t, err)

	originalSig := env.Signatures[0].Signature
	truncations := []int{0, 1, len(originalSig) / 2, len(originalSig) - 1}

	for _, truncLen := range truncations {
		t.Run(fmt.Sprintf("truncate_to_%d", truncLen), func(t *testing.T) {
			truncated := make([]byte, truncLen)
			copy(truncated, originalSig[:truncLen])
			env.Signatures[0].Signature = truncated

			assert.NotPanics(t, func() {
				_, err := env.Verify(VerifyWithVerifiers(verifier))
				assert.Error(t, err, "truncated signature should fail verification")
			})
		})
	}
}

// TestSignVerifyEdgeCases_SignatureExtended tests that appending random
// bytes to the signature is handled gracefully.
func TestSignVerifyEdgeCases_SignatureExtended(t *testing.T) {
	signer, verifier := fuzzED25519KeyPair(t)

	env, err := Sign("test", bytes.NewReader([]byte("data")), SignWithSigners(signer))
	require.NoError(t, err)

	originalSig := env.Signatures[0].Signature
	extensions := []int{1, 64, 256, 1024}

	for _, extLen := range extensions {
		t.Run(fmt.Sprintf("extend_by_%d", extLen), func(t *testing.T) {
			extended := make([]byte, len(originalSig)+extLen)
			copy(extended, originalSig)
			// Fill the extension with random bytes
			_, _ = rand.Read(extended[len(originalSig):])
			env.Signatures[0].Signature = extended

			assert.NotPanics(t, func() {
				_, err := env.Verify(VerifyWithVerifiers(verifier))
				// Ed25519 has a fixed signature length (64 bytes). An extended
				// signature should fail verification.
				assert.Error(t, err, "extended signature should fail verification")
			})
		})
	}
}

// TestSignVerifyEdgeCases_VerifyWithNoOptions tests that calling Verify()
// with absolutely no options does not panic. The default threshold is 1
// and there are no verifiers, so it should return an error.
func TestSignVerifyEdgeCases_VerifyWithNoOptions(t *testing.T) {
	signer, _ := fuzzED25519KeyPair(t)

	env, err := Sign("test", bytes.NewReader([]byte("data")), SignWithSigners(signer))
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		_, err = env.Verify()
		assert.Error(t, err, "verify with no verifiers should fail")
	})
}

// TestSignVerifyEdgeCases_LargeThresholdWithSingleSigner tests that a
// threshold much larger than the number of verifiers fails cleanly.
func TestSignVerifyEdgeCases_LargeThresholdWithSingleSigner(t *testing.T) {
	signer, verifier := fuzzED25519KeyPair(t)

	env, err := Sign("test", bytes.NewReader([]byte("data")), SignWithSigners(signer))
	require.NoError(t, err)

	thresholds := []int{2, 10, 100, 1000, 1<<31 - 1}
	for _, th := range thresholds {
		t.Run(fmt.Sprintf("threshold_%d", th), func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, err := env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(th))
				assert.Error(t, err, "threshold=%d with 1 signer should fail", th)
			})
		})
	}
}

// TestSignVerifyEdgeCases_HugePayload tests sign/verify with a large
// payload to catch any size-related issues (e.g. integer overflow in PAE
// length encoding, excessive memory allocation).
func TestSignVerifyEdgeCases_HugePayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping huge payload test in short mode")
	}

	signer, verifier := fuzzED25519KeyPair(t)

	// 4MB payload
	payload := make([]byte, 4*1024*1024)
	_, _ = rand.Read(payload)

	env, err := Sign("application/octet-stream", bytes.NewReader(payload),
		SignWithSigners(signer))
	require.NoError(t, err)

	_, err = env.Verify(VerifyWithVerifiers(verifier))
	require.NoError(t, err, "4MB payload should sign and verify successfully")
}

// TestSignVerifyEdgeCases_PAEWithMaxLenPayloadType checks that PAE
// correctly handles a payload type at the boundary where its decimal
// length representation changes digit count (e.g. 9->10, 99->100).
func TestSignVerifyEdgeCases_PAEWithMaxLenPayloadType(t *testing.T) {
	// Sizes at power-of-10 boundaries
	sizes := []int{9, 10, 99, 100, 999, 1000}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("type_len_%d", size), func(t *testing.T) {
			bodyType := strings.Repeat("a", size)
			body := []byte("test")

			pae := preauthEncode(bodyType, body)
			require.NotNil(t, pae)

			// Verify the length field matches
			s := string(pae)
			afterPrefix := s[len("DSSEv1 "):]
			spaceIdx := strings.Index(afterPrefix, " ")
			require.NotEqual(t, -1, spaceIdx)

			encodedLen, err := strconv.Atoi(afterPrefix[:spaceIdx])
			require.NoError(t, err)
			assert.Equal(t, size, encodedLen, "PAE type length must match for size=%d", size)
		})
	}
}

// TestSignVerifyEdgeCases_MultipleVerifiersSameKey tests that providing
// the same verifier multiple times does not inflate the threshold count.
func TestSignVerifyEdgeCases_MultipleVerifiersSameKey(t *testing.T) {
	signer, verifier := fuzzED25519KeyPair(t)

	env, err := Sign("test", bytes.NewReader([]byte("data")), SignWithSigners(signer))
	require.NoError(t, err)

	// Provide the same verifier 5 times
	verifiers := []cryptoutil.Verifier{verifier, verifier, verifier, verifier, verifier}

	// With threshold=1, should pass (one distinct key verified)
	_, err = env.Verify(VerifyWithVerifiers(verifiers...), VerifyWithThreshold(1))
	require.NoError(t, err)

	// With threshold=2, should fail (still only one distinct key, even though
	// the verifier is provided 5 times)
	_, err = env.Verify(VerifyWithVerifiers(verifiers...), VerifyWithThreshold(2))
	require.Error(t, err, "same verifier provided 5x should only count as 1 distinct key")
}

// TestSignVerifyEdgeCases_GarbageCertificateDoesNotBlockRawVerifier
// ensures that garbage data in the Certificate field of a signature
// does not prevent the raw verifier path from succeeding.
func TestSignVerifyEdgeCases_GarbageCertificateDoesNotBlockRawVerifier(t *testing.T) {
	signer, verifier := fuzzED25519KeyPair(t)

	env, err := Sign("test", bytes.NewReader([]byte("data")), SignWithSigners(signer))
	require.NoError(t, err)

	// Inject garbage certificate data into the signature
	garbageCerts := [][]byte{
		[]byte("not a certificate"),
		[]byte("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----"),
		{0x30, 0x82, 0x01, 0x00, 0xff, 0xfe}, // ASN.1-ish prefix
		make([]byte, 4096),                   // large garbage
		{0x00},                               // single null byte
	}

	for i, gc := range garbageCerts {
		t.Run(fmt.Sprintf("garbage_cert_%d", i), func(t *testing.T) {
			env.Signatures[0].Certificate = gc

			// The raw verifier path should still work despite garbage certs
			_, err := env.Verify(VerifyWithVerifiers(verifier))
			require.NoError(t, err,
				"garbage certificate must not block raw verifier verification")
		})
	}
}

// TestSignVerifyEdgeCases_EmptyEnvelopeFields tests various combinations
// of empty/nil fields in the Envelope struct.
func TestSignVerifyEdgeCases_EmptyEnvelopeFields(t *testing.T) {
	_, verifier := fuzzED25519KeyPair(t)

	tests := []struct {
		name string
		env  Envelope
	}{
		{
			name: "zero_value_envelope",
			env:  Envelope{},
		},
		{
			name: "nil_payload_nil_sigs",
			env:  Envelope{PayloadType: "test"},
		},
		{
			name: "empty_payload_empty_sigs",
			env:  Envelope{Payload: []byte{}, PayloadType: "", Signatures: []Signature{}},
		},
		{
			name: "nil_signature_bytes",
			env: Envelope{
				Payload:     []byte("data"),
				PayloadType: "test",
				Signatures:  []Signature{{KeyID: "k", Signature: nil}},
			},
		},
		{
			name: "huge_keyid",
			env: Envelope{
				Payload:     []byte("data"),
				PayloadType: "test",
				Signatures: []Signature{
					{KeyID: strings.Repeat("k", 100000), Signature: []byte("sig")},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, _ = tc.env.Verify(VerifyWithVerifiers(verifier))
			}, "must not panic on %s", tc.name)
		})
	}
}

// TestSignVerifyEdgeCases_SignatureSwapBetweenEnvelopes tests that a
// signature from one envelope cannot be replayed in a different envelope.
func TestSignVerifyEdgeCases_SignatureSwapBetweenEnvelopes(t *testing.T) {
	signer, verifier := fuzzED25519KeyPair(t)

	env1, err := Sign("type1", bytes.NewReader([]byte("payload-one")), SignWithSigners(signer))
	require.NoError(t, err)

	env2, err := Sign("type2", bytes.NewReader([]byte("payload-two")), SignWithSigners(signer))
	require.NoError(t, err)

	// Cross-envelope replay: use env2's signature on env1's payload
	swapped := Envelope{
		Payload:     env1.Payload,
		PayloadType: env1.PayloadType,
		Signatures:  env2.Signatures,
	}

	_, err = swapped.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err, "cross-envelope signature replay must fail")

	// And the reverse
	swapped2 := Envelope{
		Payload:     env2.Payload,
		PayloadType: env2.PayloadType,
		Signatures:  env1.Signatures,
	}

	_, err = swapped2.Verify(VerifyWithVerifiers(verifier))
	require.Error(t, err, "reverse cross-envelope signature replay must fail")
}

// TestSignVerifyEdgeCases_SignatureWithHugeKeyID tests that a signature
// with an absurdly large KeyID does not cause memory issues or panics
// during verification.
func TestSignVerifyEdgeCases_SignatureWithHugeKeyID(t *testing.T) {
	signer, verifier := fuzzED25519KeyPair(t)

	env, err := Sign("test", bytes.NewReader([]byte("data")), SignWithSigners(signer))
	require.NoError(t, err)

	// Replace the KeyID with something huge
	env.Signatures[0].KeyID = strings.Repeat("X", 1<<20) // 1MB KeyID

	assert.NotPanics(t, func() {
		_, _ = env.Verify(VerifyWithVerifiers(verifier))
	})
}

// TestSignVerifyEdgeCases_PAEWithBigIntPayloadLength verifies that
// the PAE format correctly represents very large lengths as decimal
// strings without integer overflow.
func TestSignVerifyEdgeCases_PAEWithBigIntPayloadLength(t *testing.T) {
	// We can't actually create a multi-GB payload, but we can verify
	// the length representation is self-consistent at interesting sizes.
	sizes := []int{
		0, 1, 127, 128, 255, 256,
		65535, 65536,
		1<<20 - 1, 1 << 20,
		1<<24 - 1, 1 << 24,
	}

	for _, size := range sizes {
		if size > 1<<24 {
			continue // Skip impractically large allocations
		}
		t.Run(fmt.Sprintf("body_size_%d", size), func(t *testing.T) {
			if size > 1<<20 && testing.Short() {
				t.Skip("skipping large allocation in short mode")
			}

			body := make([]byte, size)
			pae := preauthEncode("t", body)

			// Extract and verify the body length from the PAE
			s := string(pae)
			// PAE for type "t": "DSSEv1 1 t <bodyLen> <body>"
			prefix := "DSSEv1 1 t "
			require.True(t, strings.HasPrefix(s, prefix))

			rest := s[len(prefix):]
			spaceIdx := strings.Index(rest, " ")
			require.NotEqual(t, -1, spaceIdx)

			encodedLen, err := strconv.Atoi(rest[:spaceIdx])
			require.NoError(t, err)
			assert.Equal(t, size, encodedLen)
		})
	}
}

// TestSignVerifyEdgeCases_ErrNoMatchingSigsContainsVerifierInfo tests
// that the ErrNoMatchingSigs error message includes useful debugging info.
func TestSignVerifyEdgeCases_ErrNoMatchingSigsContainsVerifierInfo(t *testing.T) {
	signer, _ := fuzzED25519KeyPair(t)
	_, wrongVerifier := fuzzED25519KeyPair(t)

	env, err := Sign("test", bytes.NewReader([]byte("data")), SignWithSigners(signer))
	require.NoError(t, err)

	_, err = env.Verify(VerifyWithVerifiers(wrongVerifier))
	require.Error(t, err)

	var noMatchErr ErrNoMatchingSigs
	require.ErrorAs(t, err, &noMatchErr)
	assert.NotEmpty(t, noMatchErr.Verifiers, "error should include checked verifiers")
	assert.Contains(t, err.Error(), "no valid signatures")
}

// TestSignVerifyEdgeCases_EnvelopeWithMaxSignatures tests an envelope
// with a very large number of signatures (all invalid) to ensure no
// panic or excessive memory allocation in the verify path.
func TestSignVerifyEdgeCases_EnvelopeWithMaxSignatures(t *testing.T) {
	_, verifier := fuzzED25519KeyPair(t)

	// Create 500 fake signatures
	sigs := make([]Signature, 500)
	for i := range sigs {
		fakeSig := make([]byte, 64)
		big.NewInt(int64(i)).FillBytes(fakeSig[:8])
		sigs[i] = Signature{
			KeyID:     fmt.Sprintf("fake-key-%d", i),
			Signature: fakeSig,
		}
	}

	env := Envelope{
		Payload:     []byte("test"),
		PayloadType: "test",
		Signatures:  sigs,
	}

	assert.NotPanics(t, func() {
		_, err := env.Verify(VerifyWithVerifiers(verifier))
		assert.Error(t, err, "500 fake signatures should not verify")
	})
}
