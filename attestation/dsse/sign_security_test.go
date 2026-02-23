//go:build audit

// Copyright 2024 The Witness Contributors
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
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestSecurity_R3_155_SignNilSignersProducesUnsignedEnvelope proves that
// dsse.Sign() produces an unsigned envelope (zero signatures) when called
// with a slice of nil signers. The len(signers) > 0 check at sign.go:54
// passes because the slice has non-zero length, but all entries are nil
// and get skipped at sign.go:68-69. No post-loop validation checks that
// at least one signature was actually produced.
//
// Impact: CRITICAL — A caller that passes nil signers (e.g., due to a
// configuration error where signer creation fails but returns nil instead
// of error) gets back a seemingly-valid envelope with zero signatures.
// The envelope will be persisted and appear to be a legitimate attestation,
// but has no cryptographic protection whatsoever.
func TestSecurity_R3_155_SignNilSignersProducesUnsignedEnvelope(t *testing.T) {
	tests := []struct {
		name    string
		signers []cryptoutil.Signer
	}{
		{
			name:    "single nil signer",
			signers: []cryptoutil.Signer{nil},
		},
		{
			name:    "multiple nil signers",
			signers: []cryptoutil.Signer{nil, nil, nil},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := bytes.NewReader([]byte(`{"test": "data"}`))
			_, err := Sign("application/json", body, SignWithSigners(tt.signers...))

			// FIX (R3-155): Sign now returns an error when all signers are nil
			if err == nil {
				t.Fatal("REGRESSION R3-155: Sign() should return error for nil signers but returned nil")
			}

			if !strings.Contains(err.Error(), "no signatures produced") {
				t.Fatalf("expected 'no signatures produced' error, got: %v", err)
			}

			t.Logf("R3-155 FIXED: Sign correctly rejected %d nil signers: %v", len(tt.signers), err)
		})
	}
}

// TestSecurity_R3_155_SignMixedNilAndRealSigners proves that when some
// signers are nil and some are real, Sign() produces an envelope with
// fewer signatures than the caller expected. This is a partial signing
// issue — the caller thinks they're getting multi-party signatures but
// the nil signers are silently dropped.
func TestSecurity_R3_155_SignMixedNilAndRealSigners(t *testing.T) {
	signer, _, err := createTestKey()
	if err != nil {
		t.Fatal(err)
	}

	body := bytes.NewReader([]byte(`{"test": "data"}`))
	// Caller intends 3 signatures but 2 signers are nil
	env, err := Sign("application/json", body, SignWithSigners(nil, signer, nil))
	if err != nil {
		t.Fatal(err)
	}

	// Only 1 signature was produced instead of 3
	if len(env.Signatures) != 1 {
		t.Fatalf("expected exactly 1 signature (only non-nil signer), got %d", len(env.Signatures))
	}

	t.Logf("SECURITY FINDING R3-155: Sign() silently dropped %d nil signers out of %d total. "+
		"Caller expected %d signatures but got %d. There is no error or warning. "+
		"In a threshold signing scenario, this could result in an envelope with "+
		"fewer signatures than the required threshold, which would be rejected by "+
		"verification — but the signing side gives no indication of the problem.",
		2, 3, 3, len(env.Signatures))
}

// TestSecurity_R3_156_SignEmptyPayloadType proves that Sign() accepts
// an empty body type string, producing an envelope that may confuse
// consumers expecting a valid media type.
func TestSecurity_R3_156_SignEmptyPayloadType(t *testing.T) {
	signer, _, err := createTestKey()
	if err != nil {
		t.Fatal(err)
	}

	body := bytes.NewReader([]byte(`test`))
	env, err := Sign("", body, SignWithSigners(signer))
	if err != nil {
		t.Logf("Sign correctly rejected empty body type: %v", err)
		return
	}

	if env.PayloadType != "" {
		t.Fatalf("expected empty PayloadType, got %q", env.PayloadType)
	}

	t.Logf("SECURITY FINDING R3-156: Sign() accepted empty PayloadType. "+
		"The PAE encoding uses this value, so the signature is valid for an "+
		"empty type. A verifier must know the expected type to validate. "+
		"This could lead to type confusion where the same signed payload "+
		"is interpreted differently by consumers expecting different types.")
}

// TestSecurity_R3_157_SignDuplicateKeyIDs proves that when two different
// signers produce the same KeyID (e.g., same key loaded twice), the
// envelope has duplicate signatures with the same KeyID. This could
// inflate signature counts and confuse threshold-based verification.
func TestSecurity_R3_157_SignDuplicateKeyIDs(t *testing.T) {
	signer1, _, err := createTestKey()
	if err != nil {
		t.Fatal(err)
	}

	body := bytes.NewReader([]byte(`{"test": "data"}`))

	// Sign with the same signer twice
	env, err := Sign("application/json", body, SignWithSigners(signer1, signer1))
	if err != nil {
		t.Fatal(err)
	}

	if len(env.Signatures) != 2 {
		t.Fatalf("expected 2 signatures, got %d", len(env.Signatures))
	}

	// Both signatures have the same KeyID
	if env.Signatures[0].KeyID != env.Signatures[1].KeyID {
		t.Fatalf("expected same KeyIDs, got %q and %q", env.Signatures[0].KeyID, env.Signatures[1].KeyID)
	}

	t.Logf("SECURITY FINDING R3-157: Sign() produced %d signatures with "+
		"identical KeyID %q. A verification system counting distinct signatures "+
		"by KeyID would only count 1, but a system counting by array index "+
		"would count 2. This inconsistency could allow threshold inflation "+
		"depending on the verifier implementation. Our Verify() already "+
		"deduplicates by KeyID (R3-2 fix), but external consumers of the "+
		"envelope may not.",
		len(env.Signatures), env.Signatures[0].KeyID)
}

// TestSecurity_R3_158_SignBodyReadError proves that when the body reader
// fails, Sign() returns a partially-constructed envelope along with the error.
// The caller could accidentally use the envelope despite the error.
func TestSecurity_R3_158_SignBodyReadError(t *testing.T) {
	signer, _, err := createTestKey()
	if err != nil {
		t.Fatal(err)
	}

	body := &failingReader{err: bytes.ErrTooLarge}
	env, err := Sign("application/json", body, SignWithSigners(signer))

	if err == nil {
		t.Fatal("expected error from failing reader")
	}

	// The envelope is partially constructed — it has no PayloadType set yet
	// because the error occurs at io.ReadAll(body) before PayloadType is set
	if env.PayloadType != "" {
		t.Logf("NOTE: env.PayloadType=%q was set before body read error", env.PayloadType)
	}

	if len(env.Signatures) != 0 {
		t.Logf("NOTE: env has %d signatures despite body read error", len(env.Signatures))
	}
}

type failingReader struct {
	err error
}

func (r *failingReader) Read(p []byte) (n int, err error) {
	return 0, r.err
}

// TestSecurity_R3_159_SignPayloadTypeInjection proves that the payload type
// is used directly in PAE encoding without validation. A crafted payload type
// with special characters could potentially cause parsing issues in consumers.
func TestSecurity_R3_159_SignPayloadTypeInjection(t *testing.T) {
	signer, verifier, err := createTestKey()
	if err != nil {
		t.Fatal(err)
	}

	maliciousTypes := []string{
		"application/json\x00evil",                     // null byte injection
		"application/json\nContent-Type: text/html",    // header injection
		strings.Repeat("A", 1024*1024),                 // 1MB payload type
		"application/json; charset=utf-8; drop table x", // SQL-like injection
	}

	for _, payloadType := range maliciousTypes {
		body := bytes.NewReader([]byte(`{"test": "data"}`))
		env, err := Sign(payloadType, body, SignWithSigners(signer))
		if err != nil {
			continue // some may legitimately fail
		}

		// Verify the envelope can be verified (the PAE encoding must match)
		_, err = env.Verify(VerifyWithVerifiers(verifier))
		if err != nil {
			t.Logf("FINDING: payloadType %q signed OK but verification failed: %v",
				truncate(payloadType, 50), err)
			continue
		}

		if len(payloadType) > 1000 {
			t.Logf("SECURITY FINDING R3-159: Sign() accepted a %d-byte PayloadType "+
				"and it verified successfully. This could be used for resource "+
				"exhaustion (PAE = 2x payload type length in encoding).",
				len(payloadType))
		}
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
