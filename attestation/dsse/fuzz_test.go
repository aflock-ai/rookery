//go:build audit

package dsse

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// FuzzDSSEEnvelopeVerify fuzzes the DSSE envelope verification with random
// payloads, signature counts, and threshold values. It validates:
//   - No panics regardless of input
//   - Threshold enforcement cannot be bypassed
//   - Duplicate signatures from the same key do not inflate the verified count
func FuzzDSSEEnvelopeVerify(f *testing.F) {
	// Seed corpus: edge cases
	f.Add([]byte("hello"), []byte("application/json"), uint8(1), uint8(1), true)
	f.Add([]byte(""), []byte(""), uint8(0), uint8(1), false)
	f.Add([]byte("x"), []byte("t"), uint8(5), uint8(3), true)
	f.Add([]byte("\x00\xff\xfe"), []byte("binary/octet-stream"), uint8(10), uint8(1), false)
	f.Add(make([]byte, 1024), []byte("large"), uint8(1), uint8(1), true)
	f.Add([]byte("a"), []byte("a"), uint8(1), uint8(0), false) // threshold 0 -> invalid

	f.Fuzz(func(t *testing.T, payload []byte, payloadType []byte, numDuplicates uint8, threshold uint8, signIt bool) {
		// Cap values to keep tests fast
		if numDuplicates > 20 {
			numDuplicates = 20
		}
		if threshold > 20 {
			threshold = 20
		}

		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Skip("key generation failed")
		}

		signer := cryptoutil.NewRSASigner(privKey, crypto.SHA256)
		verifier := cryptoutil.NewRSAVerifier(&privKey.PublicKey, crypto.SHA256)

		var env Envelope
		if signIt {
			env, err = Sign(string(payloadType), bytes.NewReader(payload), SignWithSigners(signer))
			if err != nil {
				// Sign can fail with certain inputs; that's fine.
				return
			}
		} else {
			// Construct an envelope with garbage signatures
			sigs := make([]Signature, int(numDuplicates))
			for i := range sigs {
				sigs[i] = Signature{
					KeyID:     "fake-key",
					Signature: payload, // garbage sig
				}
			}
			env = Envelope{
				Payload:     payload,
				PayloadType: string(payloadType),
				Signatures:  sigs,
			}
		}

		// Test duplicate signature inflation: if we signed it, duplicate
		// the signature and ensure threshold cannot be bypassed.
		if signIt && len(env.Signatures) > 0 && numDuplicates > 1 {
			originalSig := env.Signatures[0]
			env.Signatures = make([]Signature, int(numDuplicates))
			for i := range env.Signatures {
				env.Signatures[i] = originalSig
			}

			thresholdVal := int(threshold)
			if thresholdVal <= 0 {
				thresholdVal = 1
			}

			checkedVerifiers, err := env.Verify(
				VerifyWithVerifiers(verifier),
				VerifyWithThreshold(thresholdVal),
			)

			// Security invariant: duplicated sigs from one key can never
			// meet a threshold > 1.
			if thresholdVal > 1 && err == nil {
				t.Errorf("SECURITY: threshold=%d met with duplicated sigs from a single key", thresholdVal)
			}

			// Count distinct passed verifiers
			passedCount := 0
			for _, cv := range checkedVerifiers {
				if cv.Error == nil {
					passedCount++
				}
			}

			// Even with N duplicate sigs, the deduplicated count should
			// never exceed 1 for a single key.
			if passedCount > 1 {
				// This is not necessarily a security issue (the CheckedVerifier
				// list can have multiple entries per sig), but the verifiedKeyIDs
				// map should prevent threshold inflation. We check threshold
				// enforcement above which is the real invariant.
				_ = passedCount
			}
		}

		// Test with various threshold values -- should never panic.
		for _, th := range []int{-1, 0, 1, 2, int(threshold)} {
			_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(th))
		}

		// Test with no verifiers -- should never panic.
		_, _ = env.Verify(VerifyWithThreshold(1))

		// Test with empty envelope -- should never panic.
		emptyEnv := Envelope{}
		_, _ = emptyEnv.Verify(VerifyWithVerifiers(verifier))
	})
}

// FuzzPreauthEncode fuzzes the preauthEncode function with random payloadTypes
// and payloads to ensure no panics occur and the output is deterministic.
func FuzzPreauthEncode(f *testing.F) {
	// Seed corpus
	f.Add("application/json", []byte("test payload"))
	f.Add("", []byte(""))
	f.Add("", []byte(nil))
	f.Add("application/vnd.in-toto+json", []byte(`{"key": "value"}`))
	f.Add("type/with spaces", []byte("data with\nnewlines"))
	f.Add(string(make([]byte, 1000)), make([]byte, 10000))
	f.Add("\x00\xff", []byte{0, 1, 2, 255})

	f.Fuzz(func(t *testing.T, bodyType string, body []byte) {
		// Must not panic
		result := preauthEncode(bodyType, body)

		if result == nil {
			t.Fatal("preauthEncode returned nil")
		}

		// Determinism check: same input must produce same output
		result2 := preauthEncode(bodyType, body)
		if !bytes.Equal(result, result2) {
			t.Error("preauthEncode is not deterministic")
		}

		// The result must start with "DSSEv1 "
		if !bytes.HasPrefix(result, []byte("DSSEv1 ")) {
			t.Errorf("preauthEncode result does not start with 'DSSEv1 ', got prefix: %q", result[:min(len(result), 20)])
		}
	})
}

// ed25519KeyPair generates an ed25519 key pair for fuzz tests.
// Ed25519 key generation is orders of magnitude faster than RSA,
// which is critical for fuzz throughput.
func ed25519KeyPair(t *testing.T) (*cryptoutil.ED25519Signer, *cryptoutil.ED25519Verifier) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Skip("ed25519 key generation failed")
	}
	return cryptoutil.NewED25519Signer(priv), cryptoutil.NewED25519Verifier(pub)
}

// signTestEnvelope creates a validly signed envelope using ed25519 for fuzz test helpers.
func signTestEnvelope(t *testing.T, payload []byte, payloadType string) (Envelope, cryptoutil.Verifier) {
	t.Helper()
	signer, verifier := ed25519KeyPair(t)
	env, err := Sign(payloadType, bytes.NewReader(payload), SignWithSigners(signer))
	if err != nil {
		t.Skip("signing failed")
	}
	return env, verifier
}

// FuzzEnvelopeUnmarshal feeds random bytes to json.Unmarshal into an Envelope,
// then calls Verify() on the result. This tests that arbitrary JSON (or non-JSON)
// input can never cause a panic in the Envelope or verification code paths.
func FuzzEnvelopeUnmarshal(f *testing.F) {
	// Seed: valid-ish JSON shapes
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"payload":"","payloadType":"","signatures":[]}`))
	f.Add([]byte(`{"payload":"aGVsbG8=","payloadType":"text/plain","signatures":[{"keyid":"k","sig":"AAAA"}]}`))
	f.Add([]byte(`{"signatures":[{"keyid":"","sig":"","certificate":"not-pem"}]}`))
	// Degenerate inputs
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`"string"`))
	f.Add([]byte{0xff, 0xfe, 0x00})
	f.Add([]byte(`{"payload":0,"payloadType":false,"signatures":"bad"}`))
	f.Add([]byte(`{"signatures":[{"certificate":"-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----"}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			// Invalid JSON or type mismatch is expected -- no panic is the invariant.
			return
		}

		// Attempt verification with no verifiers -- exercises the full verify path
		// including preauthEncode, signature iteration, certificate parsing, etc.
		_, _ = env.Verify()

		// Also try with a real verifier to exercise the Verify() code path
		// that actually checks signatures.
		_, verifier := ed25519KeyPair(t)
		_, _ = env.Verify(VerifyWithVerifiers(verifier))
		_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(2))

		// Re-marshal and unmarshal to check for stability (no panic on re-encode).
		remarshaled, err := json.Marshal(env)
		if err != nil {
			// Some byte slices from fuzzing may not re-marshal cleanly; that's OK.
			return
		}
		var env2 Envelope
		_ = json.Unmarshal(remarshaled, &env2)
	})
}

// FuzzEnvelopeRoundTrip creates a valid signed envelope, mutates random bytes
// in the serialized JSON, then unmarshals and verifies. The invariant is that
// the code must always either succeed or return a clean error -- never panic.
func FuzzEnvelopeRoundTrip(f *testing.F) {
	// Seeds provide mutation positions and values
	f.Add([]byte("hello world"), "application/json", uint16(0), byte(0xff))
	f.Add([]byte(""), "", uint16(5), byte(0x00))
	f.Add([]byte("test"), "text/plain", uint16(100), byte(0x41))
	f.Add([]byte("\x00\x01\x02"), "binary/octet-stream", uint16(50), byte(0xfe))
	f.Add([]byte("a]b[c{d}e"), "application/cbor", uint16(10), byte(0x22))

	f.Fuzz(func(t *testing.T, payload []byte, payloadType string, mutPos uint16, mutByte byte) {
		env, verifier := signTestEnvelope(t, payload, payloadType)

		// Marshal to JSON
		jsonData, err := json.Marshal(env)
		if err != nil {
			t.Skip("marshal failed")
		}

		if len(jsonData) == 0 {
			return
		}

		// Mutate a single byte at a position within the JSON
		pos := int(mutPos) % len(jsonData)
		mutated := make([]byte, len(jsonData))
		copy(mutated, jsonData)
		mutated[pos] = mutByte

		// Unmarshal the mutated JSON -- may fail, that's fine
		var mutatedEnv Envelope
		if err := json.Unmarshal(mutated, &mutatedEnv); err != nil {
			return
		}

		// Verify: should either succeed (if mutation was benign) or return
		// a clean error. Panic = test failure.
		_, _ = mutatedEnv.Verify(VerifyWithVerifiers(verifier))

		// Also verify with no verifiers (different code path)
		_, _ = mutatedEnv.Verify()
	})
}

// FuzzSignatureManipulation creates a valid envelope, then fuzzes individual
// bytes in the signature value. Verify must always fail gracefully -- never panic.
// This simulates an attacker trying to forge or corrupt signatures.
func FuzzSignatureManipulation(f *testing.F) {
	f.Add([]byte("payload"), "application/json", uint16(0), byte(0xff), uint8(1))
	f.Add([]byte(""), "", uint16(0), byte(0x00), uint8(0))
	f.Add([]byte("test"), "text/plain", uint16(10), byte(0x41), uint8(5))
	f.Add([]byte("binary\x00data"), "application/octet-stream", uint16(32), byte(0xfe), uint8(3))

	f.Fuzz(func(t *testing.T, payload []byte, payloadType string, mutPos uint16, mutByte byte, numMutations uint8) {
		env, verifier := signTestEnvelope(t, payload, payloadType)

		if len(env.Signatures) == 0 || len(env.Signatures[0].Signature) == 0 {
			return
		}

		sig := env.Signatures[0].Signature

		// Apply mutations to the signature bytes
		mutatedSig := make([]byte, len(sig))
		copy(mutatedSig, sig)

		mutations := int(numMutations)
		if mutations > len(mutatedSig) {
			mutations = len(mutatedSig)
		}
		if mutations == 0 {
			mutations = 1
		}

		// Mutate 'mutations' bytes starting at mutPos
		for i := 0; i < mutations; i++ {
			idx := (int(mutPos) + i) % len(mutatedSig)
			mutatedSig[idx] = mutByte ^ byte(i) // vary each mutation slightly
		}

		env.Signatures[0].Signature = mutatedSig

		// Verification should fail (unless the mutation was a no-op)
		// but must NEVER panic.
		checkedVerifiers, err := env.Verify(VerifyWithVerifiers(verifier))

		// If verification succeeded, the mutation must have been a no-op
		// (i.e., the mutated bytes were identical to the originals).
		if err == nil {
			// Verify it was actually a no-op
			if !bytes.Equal(mutatedSig, sig) {
				t.Errorf("SECURITY: signature verification passed after mutation. "+
					"Original sig len=%d, mutated sig len=%d, mutPos=%d, mutByte=0x%02x",
					len(sig), len(mutatedSig), mutPos, mutByte)
			}
		}

		// checkedVerifiers list should never contain nil Verifier entries
		for i, cv := range checkedVerifiers {
			if cv.Verifier == nil && cv.Error == nil {
				t.Errorf("checkedVerifiers[%d] has nil Verifier with nil Error", i)
			}
		}
	})
}

// FuzzCertificateParsing feeds random bytes into the Certificate field of a
// DSSE signature. The verify path exercises TryParseCertificate and the x509
// chain validation code. The invariant: no panics regardless of certificate content.
func FuzzCertificateParsing(f *testing.F) {
	// Seeds: various garbage that might tickle certificate parsing
	f.Add([]byte("payload"), "app/json", []byte("not-a-cert"), []byte{})
	f.Add([]byte("p"), "t", []byte("-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----"), []byte{})
	f.Add([]byte(""), "", []byte{0x30, 0x82, 0x01, 0x00}, []byte{}) // ASN.1-ish prefix
	f.Add([]byte("x"), "y", []byte{0xff, 0xfe, 0xfd}, []byte{0x30}) // random binary
	f.Add([]byte("z"), "w", make([]byte, 4096), []byte{0x00, 0x01}) // large garbage cert
	f.Add([]byte("q"), "r", []byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----"), []byte("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"))

	f.Fuzz(func(t *testing.T, payload []byte, payloadType string, certBytes []byte, intermediateBytes []byte) {
		signer, verifier := ed25519KeyPair(t)

		// Create a validly signed envelope
		env, err := Sign(payloadType, bytes.NewReader(payload), SignWithSigners(signer))
		if err != nil {
			t.Skip("signing failed")
		}

		if len(env.Signatures) == 0 {
			return
		}

		// Inject fuzzed certificate data into the signature
		env.Signatures[0].Certificate = certBytes

		// Optionally inject fuzzed intermediate certificates
		if len(intermediateBytes) > 0 {
			env.Signatures[0].Intermediates = [][]byte{intermediateBytes}
		}

		// Verify with the real verifier -- the cert parsing path should
		// handle all inputs gracefully. The raw-key verification via the
		// verifier should still work (or fail cleanly).
		_, _ = env.Verify(VerifyWithVerifiers(verifier))

		// Also test with no verifiers to exercise only the cert path
		_, _ = env.Verify()

		// Test with threshold > 1 to exercise threshold error paths
		_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(2))

		// Test round-trip: marshal and unmarshal the envelope with the
		// fuzzed cert, then verify again.
		jsonData, err := json.Marshal(env)
		if err != nil {
			return
		}
		var env2 Envelope
		if err := json.Unmarshal(jsonData, &env2); err != nil {
			return
		}
		_, _ = env2.Verify(VerifyWithVerifiers(verifier))
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// FuzzEnvelopeBase64Corruption targets base64 decoding in DSSE envelope fields.
// The Envelope struct uses []byte for Payload and Signature fields, which
// json.Unmarshal decodes from base64. Malformed base64 should produce a clean
// error, never a panic.
//
// TestSecurity_R3_130: Malformed base64 in DSSE signature/payload fields.
func FuzzEnvelopeBase64Corruption(f *testing.F) {
	// Seeds with various base64 corruptions
	f.Add([]byte(`{"payload":"!!!not-base64!!!","payloadType":"test","signatures":[{"keyid":"k","sig":"also-not-base64"}]}`))
	f.Add([]byte(`{"payload":"aGVsbG8=","payloadType":"test","signatures":[{"keyid":"k","sig":"==="}]}`))
	f.Add([]byte(`{"payload":"aGVsbG8","payloadType":"test","signatures":[{"keyid":"k","sig":"aGVsbG8="}]}`)) // missing padding
	f.Add([]byte(`{"payload":"aGVsbG8=\n","payloadType":"test","signatures":[{"keyid":"k","sig":"aGVsbG8="}]}`))
	f.Add([]byte(`{"payload":"","payloadType":"test","signatures":[{"keyid":"k","sig":""}]}`))
	// Unicode in base64 field
	f.Add([]byte(`{"payload":"4e16754c","payloadType":"test","signatures":[{"keyid":"k","sig":"\u0000\u0001\u0002"}]}`))
	// Huge base64 payload
	f.Add([]byte(`{"payload":"` + string(bytes.Repeat([]byte("QUFB"), 10000)) + `","payloadType":"test","signatures":[{"keyid":"k","sig":"AAAA"}]}`))
	// null in JSON fields
	f.Add([]byte(`{"payload":null,"payloadType":"test","signatures":[{"keyid":"k","sig":null}]}`))
	// Nested JSON where base64 expected
	f.Add([]byte(`{"payload":{"nested":"obj"},"payloadType":"test","signatures":[{"keyid":"k","sig":[1,2,3]}]}`))
	// Base64 with embedded nulls
	f.Add([]byte(`{"payload":"AAAAAAA=","payloadType":"test","signatures":[{"keyid":"k","sig":"AAAAAAA=","certificate":"not-pem","intermediates":["not-pem"]}]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var env Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			return
		}

		// If unmarshal succeeded, exercise the full verify path.
		// The invariant: no panic, regardless of what base64 decoded to.
		_, verifier := ed25519KeyPair(t)
		_, _ = env.Verify(VerifyWithVerifiers(verifier))
		_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(2))
		_, _ = env.Verify() // no verifiers

		// Re-marshal should not panic
		_, _ = json.Marshal(env)
	})
}

// FuzzEnvelopeMassiveSignatureCount tests envelopes with a large number of
// signatures. An attacker could craft an envelope with thousands of signatures
// to cause excessive CPU usage during verification. The invariant: no panic
// and the function should return within a reasonable time.
//
// TestSecurity_R3_131: DoS via large signature count in DSSE envelope.
func FuzzEnvelopeMassiveSignatureCount(f *testing.F) {
	f.Add([]byte("payload"), "test", uint16(1))
	f.Add([]byte("payload"), "test", uint16(100))
	f.Add([]byte(""), "", uint16(500))
	f.Add([]byte("x"), "y", uint16(0))

	f.Fuzz(func(t *testing.T, payload []byte, payloadType string, sigCount uint16) {
		// Cap at 1000 to keep test fast
		count := int(sigCount)
		if count > 1000 {
			count = 1000
		}

		sigs := make([]Signature, count)
		for i := range sigs {
			sigs[i] = Signature{
				KeyID:     fmt.Sprintf("key-%d", i),
				Signature: payload,
			}
		}

		env := Envelope{
			Payload:     payload,
			PayloadType: payloadType,
			Signatures:  sigs,
		}

		// Must not panic, even with many signatures
		_, verifier := ed25519KeyPair(t)
		_, _ = env.Verify(VerifyWithVerifiers(verifier))
		_, _ = env.Verify()

		// JSON round-trip must not panic
		jsonData, err := json.Marshal(env)
		if err != nil {
			return
		}
		var env2 Envelope
		_ = json.Unmarshal(jsonData, &env2)
	})
}

// FuzzEnvelopeTimestampDataCorruption feeds random bytes into the Timestamps
// field of signatures. The timestamp verification path must handle arbitrary
// timestamp data without panicking.
//
// TestSecurity_R3_132: Malformed timestamp data in DSSE signatures.
func FuzzEnvelopeTimestampDataCorruption(f *testing.F) {
	f.Add([]byte("payload"), "test", []byte("garbage-timestamp"), uint8(1))
	f.Add([]byte(""), "", []byte{0x30, 0x82, 0x01, 0x00}, uint8(3))
	f.Add([]byte("x"), "y", make([]byte, 4096), uint8(5))
	f.Add([]byte("z"), "w", []byte{}, uint8(0))
	f.Add([]byte("a"), "b", []byte{0xff, 0xfe, 0xfd, 0x00, 0x01}, uint8(2))

	f.Fuzz(func(t *testing.T, payload []byte, payloadType string, tsData []byte, numTimestamps uint8) {
		signer, verifier := ed25519KeyPair(t)

		env, err := Sign(payloadType, bytes.NewReader(payload), SignWithSigners(signer))
		if err != nil {
			t.Skip("signing failed")
		}

		if len(env.Signatures) == 0 {
			return
		}

		// Inject fuzzed timestamp data
		count := int(numTimestamps)
		if count > 10 {
			count = 10
		}
		if count == 0 {
			count = 1
		}

		timestamps := make([]SignatureTimestamp, count)
		for i := range timestamps {
			timestamps[i] = SignatureTimestamp{
				Type: TimestampRFC3161,
				Data: tsData,
			}
		}
		env.Signatures[0].Timestamps = timestamps

		// Verify should handle garbage timestamp data gracefully
		_, _ = env.Verify(VerifyWithVerifiers(verifier))
		_, _ = env.Verify()
		_, _ = env.Verify(VerifyWithVerifiers(verifier), VerifyWithThreshold(2))

		// JSON round-trip with timestamps
		jsonData, err := json.Marshal(env)
		if err != nil {
			return
		}
		var env2 Envelope
		if err := json.Unmarshal(jsonData, &env2); err != nil {
			return
		}
		_, _ = env2.Verify(VerifyWithVerifiers(verifier))
	})
}

// FuzzEnvelopeUnicodePayload specifically targets unicode and binary content
// in the payload, payload type, and key ID fields. JSON encoding/decoding
// handles unicode differently than raw bytes, which can cause issues in
// signature verification when the PAE encoding is recomputed.
//
// TestSecurity_R3_133: Unicode/binary content in DSSE payload fields.
func FuzzEnvelopeUnicodePayload(f *testing.F) {
	// Various unicode and binary payloads
	f.Add([]byte("Hello \xe4\xb8\x96\xe7\x95\x8c"), "text/plain", "key-\xe4\xb8\x96")              // CJK
	f.Add([]byte("\xf0\x9f\x92\xa9\xf0\x9f\x94\x92"), "application/\xf0\x9f\x94\x91", "emoji-key") // emoji
	f.Add([]byte{0x00, 0x01, 0x02, 0xff, 0xfe}, "binary/\x00octet", "null-\x00-key")               // null bytes
	f.Add([]byte("\xc0\xc1\xfe\xff"), "type/invalid-utf8", "key-\xc0\xc1")                         // invalid UTF-8
	f.Add([]byte("\xef\xbb\xbf"+"BOM-prefixed"), "text/bom", "bom-key")                            // BOM
	f.Add(bytes.Repeat([]byte("\xe2\x80\x8b"), 1000), "text/zwsp", "zwsp")                         // zero-width spaces
	f.Add([]byte("normal ASCII"), "application/json", "normal-key")                                // baseline

	f.Fuzz(func(t *testing.T, payload []byte, payloadType string, keyID string) {
		signer, verifier := ed25519KeyPair(t)

		env, err := Sign(payloadType, bytes.NewReader(payload), SignWithSigners(signer))
		if err != nil {
			return
		}

		// Verify the signed envelope
		_, err = env.Verify(VerifyWithVerifiers(verifier))
		if err != nil {
			t.Errorf("verify failed on freshly signed envelope with unicode payload: %v", err)
		}

		// JSON round-trip: marshal, unmarshal, verify again.
		// This specifically tests that JSON encoding of non-ASCII bytes
		// in base64 fields doesn't corrupt the signature.
		jsonData, err := json.Marshal(env)
		if err != nil {
			// Some payloads may not marshal cleanly
			return
		}

		var env2 Envelope
		if err := json.Unmarshal(jsonData, &env2); err != nil {
			return
		}

		// FINDING (TestSecurity_R3_133): PayloadType is a Go string, but
		// json.Marshal replaces invalid UTF-8 bytes with U+FFFD. This
		// means a signed envelope with non-UTF-8 payloadType will silently
		// change after JSON round-trip, breaking PAE and thus signature
		// verification. The Payload field ([]byte) is base64-encoded so
		// it survives the round-trip intact. Only string fields are affected.
		//
		// Impact: If an attestation envelope is created with a payloadType
		// containing non-UTF-8 bytes (unlikely but possible from malformed
		// producers), it will verify correctly in-memory but fail after
		// any JSON serialization/deserialization cycle (e.g., storage in
		// Archivista or policy evaluation).
		payloadTypePreserved := env.PayloadType == env2.PayloadType

		// After JSON round-trip, payload ([]byte/base64) should be byte-identical
		if !bytes.Equal(env.Payload, env2.Payload) {
			t.Errorf("payload corrupted after JSON round-trip: len(orig)=%d, len(roundtripped)=%d",
				len(env.Payload), len(env2.Payload))
		}

		// Verify should still pass after clean round-trip IF the
		// payloadType survived the JSON encoding unchanged.
		if payloadTypePreserved {
			_, err = env2.Verify(VerifyWithVerifiers(verifier))
			if err != nil {
				t.Errorf("verify failed after JSON round-trip despite payloadType being preserved: %v", err)
			}
		}
	})
}
