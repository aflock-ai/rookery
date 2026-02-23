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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// Test helpers (all prefixed with "table" or suffixed to avoid name collisions
// with helpers in other _test.go files in this package)
// ============================================================================

// tableErrReader is an io.Reader that always returns an error.
type tableErrReader struct {
	err error
}

func (r *tableErrReader) Read([]byte) (int, error) {
	return 0, r.err
}

// tableErrSigner is a Signer that returns an error on Sign.
type tableErrSigner struct {
	keyID string
	err   error
}

func (s *tableErrSigner) KeyID() (string, error) { return s.keyID, nil }
func (s *tableErrSigner) Sign(io.Reader) ([]byte, error) {
	return nil, s.err
}
func (s *tableErrSigner) Verifier() (cryptoutil.Verifier, error) {
	return nil, fmt.Errorf("no verifier for tableErrSigner")
}

// tableErrKeyIDSigner is a Signer that returns an error on KeyID.
type tableErrKeyIDSigner struct {
	inner cryptoutil.Signer
}

func (s *tableErrKeyIDSigner) KeyID() (string, error) {
	return "", fmt.Errorf("KeyID unavailable for signer")
}
func (s *tableErrKeyIDSigner) Sign(r io.Reader) ([]byte, error) { return s.inner.Sign(r) }
func (s *tableErrKeyIDSigner) Verifier() (cryptoutil.Verifier, error) {
	return s.inner.Verifier()
}

// tableFailingTimestamper is a Timestamper that always returns an error.
type tableFailingTimestamper struct{}

func (ft tableFailingTimestamper) Timestamp(_ context.Context, _ io.Reader) ([]byte, error) {
	return nil, fmt.Errorf("timestamper failure")
}

// tableFailingTimestampVerifier is a TimestampVerifier that always returns an error.
type tableFailingTimestampVerifier struct{}

func (fv tableFailingTimestampVerifier) Verify(_ context.Context, _ io.Reader, _ io.Reader) (time.Time, error) {
	return time.Time{}, fmt.Errorf("timestamp verification failed")
}

// tableErrorKeyIDVerifier is a Verifier that returns an error from KeyID.
type tableErrorKeyIDVerifier struct {
	inner cryptoutil.Verifier
}

func (v *tableErrorKeyIDVerifier) KeyID() (string, error) {
	return "", fmt.Errorf("no key ID")
}
func (v *tableErrorKeyIDVerifier) Verify(body io.Reader, sig []byte) error {
	return v.inner.Verify(body, sig)
}
func (v *tableErrorKeyIDVerifier) Bytes() ([]byte, error) {
	return v.inner.Bytes()
}

// createCertChainForTable builds a root -> intermediate -> leaf CA chain for testing.
// All certs are valid from validFrom to validFrom+validity.
func createCertChainForTable(t *testing.T, validFrom time.Time, validity time.Duration) (
	root *x509.Certificate, rootPriv *rsa.PrivateKey,
	intermediate *x509.Certificate, intermediatePriv *rsa.PrivateKey,
	leaf *x509.Certificate, leafPriv *rsa.PrivateKey,
) {
	t.Helper()

	// Root
	rootPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	rootTemplate.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<32))
	rootCertBytes, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootPriv.PublicKey, rootPriv)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(rootCertBytes)
	require.NoError(t, err)

	// Intermediate
	intermediatePriv, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	intermediateTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	intermediateTemplate.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<32))
	intCertBytes, err := x509.CreateCertificate(rand.Reader, intermediateTemplate, root, &intermediatePriv.PublicKey, rootPriv)
	require.NoError(t, err)
	intermediate, err = x509.ParseCertificate(intCertBytes)
	require.NoError(t, err)

	// Leaf
	leafPriv, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test Leaf"},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	leafTemplate.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<32))
	leafCertBytes, err := x509.CreateCertificate(rand.Reader, leafTemplate, intermediate, &leafPriv.PublicKey, intermediatePriv)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafCertBytes)
	require.NoError(t, err)

	return
}

// ============================================================================
// TestTablePAEEncoding - PAE (Pre-Authentication Encoding) edge cases
// ============================================================================

func TestTablePAEEncoding(t *testing.T) {
	tests := []struct {
		name       string
		bodyType   string
		body       []byte
		wantPrefix string
		check      func(t *testing.T, result []byte)
	}{
		{
			name:       "empty type and empty body",
			bodyType:   "",
			body:       []byte{},
			wantPrefix: "DSSEv1 0  0 ",
			check: func(t *testing.T, result []byte) {
				assert.Equal(t, "DSSEv1 0  0 ", string(result))
			},
		},
		{
			name:       "empty type and nil body",
			bodyType:   "",
			body:       nil,
			wantPrefix: "DSSEv1 0  0 ",
			check: func(t *testing.T, result []byte) {
				// nil body treated the same as empty body
				emptyResult := preauthEncode("", []byte{})
				assert.Equal(t, emptyResult, result,
					"nil body and empty body must produce identical PAE")
			},
		},
		{
			name:     "standard application/json type",
			bodyType: "application/json",
			body:     []byte(`{"key":"value"}`),
			check: func(t *testing.T, result []byte) {
				expected := fmt.Sprintf("DSSEv1 %d %s %d %s",
					len("application/json"), "application/json",
					len(`{"key":"value"}`), `{"key":"value"}`)
				assert.Equal(t, expected, string(result))
			},
		},
		{
			name:     "binary payload with null bytes",
			bodyType: "application/octet-stream",
			body:     []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00},
			check: func(t *testing.T, result []byte) {
				// The binary data is embedded directly in the PAE.
				// Verify the length prefix accounts for all bytes including nulls.
				assert.Contains(t, string(result), "6 ", "length should be 6 for 6-byte body")
				// Verify the result is deterministic.
				result2 := preauthEncode("application/octet-stream", []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0x00})
				assert.Equal(t, result, result2)
			},
		},
		{
			name:     "unicode payload (multi-byte characters)",
			bodyType: "text/plain;charset=utf-8",
			body:     []byte("Hello \xE4\xB8\x96\xE7\x95\x8C"), // "Hello 世界"
			check: func(t *testing.T, result []byte) {
				// len() counts bytes, not runes. "Hello 世界" is 12 bytes.
				bodyLen := len([]byte("Hello \xE4\xB8\x96\xE7\x95\x8C"))
				assert.Contains(t, string(result), fmt.Sprintf("%d ", bodyLen))
			},
		},
		{
			name:     "emoji in body type",
			bodyType: "type/\U0001F4A9",
			body:     []byte("data"),
			check: func(t *testing.T, result []byte) {
				typeLen := len("type/\U0001F4A9") // 10 bytes (emoji is 4 bytes)
				assert.Contains(t, string(result), fmt.Sprintf("%d ", typeLen))
			},
		},
		{
			name:     "1MB payload length prefix",
			bodyType: "test",
			body:     make([]byte, 1024*1024),
			check: func(t *testing.T, result []byte) {
				// The PAE should contain "1048576 " as the body length.
				assert.Contains(t, string(result), "1048576 ")
			},
		},
		{
			name:     "body type with spaces (PAE injection attempt)",
			bodyType: "fake 5 injected",
			body:     []byte("real"),
			check: func(t *testing.T, result []byte) {
				// Even though bodyType contains spaces and digits, the length prefix
				// should prevent ambiguity.
				typeLen := len("fake 5 injected") // 15
				expected := fmt.Sprintf("DSSEv1 %d fake 5 injected 4 real", typeLen)
				assert.Equal(t, expected, string(result))
			},
		},
		{
			name:     "body type with newlines",
			bodyType: "type\nwith\nnewlines",
			body:     []byte("body"),
			check: func(t *testing.T, result []byte) {
				assert.True(t, bytes.HasPrefix(result, []byte("DSSEv1 ")))
				// Length counts the actual byte count including newlines.
				assert.Contains(t, string(result), fmt.Sprintf("%d ", len("type\nwith\nnewlines")))
			},
		},
		{
			name:     "body type with null bytes",
			bodyType: "type\x00null",
			body:     []byte("data"),
			check: func(t *testing.T, result []byte) {
				assert.True(t, len(result) > 0)
				// Must be different from the same type without null.
				otherResult := preauthEncode("typenull", []byte("data"))
				assert.NotEqual(t, result, otherResult,
					"null byte in type must produce different PAE than type without null")
			},
		},
		{
			name:     "PAE collision resistance: type length vs body length",
			bodyType: "a",
			body:     []byte("b"),
			check: func(t *testing.T, result []byte) {
				// "DSSEv1 1 a 1 b" vs "DSSEv1 1 b 1 a" -- must be different.
				other := preauthEncode("b", []byte("a"))
				assert.NotEqual(t, result, other,
					"swapping type and body must produce different PAE")
			},
		},
		{
			name:     "PAE collision: type='1 a 1' body='b' vs type='1' body='a 1 1 b'",
			bodyType: "1 a 1",
			body:     []byte("b"),
			check: func(t *testing.T, result []byte) {
				other := preauthEncode("1", []byte("a 1 1 b"))
				assert.NotEqual(t, result, other,
					"crafted type/body pair must not collide")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := preauthEncode(tc.bodyType, tc.body)
			require.NotNil(t, result, "preauthEncode must never return nil")
			assert.True(t, bytes.HasPrefix(result, []byte("DSSEv1 ")),
				"PAE must always start with 'DSSEv1 '")
			if tc.wantPrefix != "" {
				assert.True(t, strings.HasPrefix(string(result), tc.wantPrefix),
					"expected prefix %q, got %q", tc.wantPrefix, string(result))
			}
			if tc.check != nil {
				tc.check(t, result)
			}
		})
	}
}

// ============================================================================
// TestTableSignEdgeCases - Sign function edge cases
// ============================================================================

func TestTableSignEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (string, io.Reader, []SignOption)
		wantErr bool
		errMsg  string
		check   func(t *testing.T, env Envelope)
	}{
		{
			name: "zero signers returns error",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				return "test", bytes.NewReader([]byte("data")), []SignOption{}
			},
			wantErr: true,
			errMsg:  "must have at least one signer",
		},
		{
			name: "nil signer only returns error (R3-155 fix)",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				return "test", bytes.NewReader([]byte("data")), []SignOption{
					SignWithSigners(nil),
				}
			},
			wantErr: true,
			errMsg:  "no signatures produced",
		},
		{
			name: "signer that returns error on Sign",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				return "test", bytes.NewReader([]byte("data")), []SignOption{
					SignWithSigners(&tableErrSigner{
						keyID: "err-signer",
						err:   fmt.Errorf("signing hardware failure"),
					}),
				}
			},
			wantErr: true,
			errMsg:  "signing hardware failure",
		},
		{
			name: "signer that returns error on KeyID",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				priv, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)
				inner := cryptoutil.NewRSASigner(priv, crypto.SHA256)
				return "test", bytes.NewReader([]byte("data")), []SignOption{
					SignWithSigners(&tableErrKeyIDSigner{inner: inner}),
				}
			},
			wantErr: true,
			errMsg:  "KeyID unavailable",
		},
		{
			name: "error reading body",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				signer, _, _ := createTestKey()
				return "test", &tableErrReader{err: fmt.Errorf("disk read error")}, []SignOption{
					SignWithSigners(signer),
				}
			},
			wantErr: true,
			errMsg:  "disk read error",
		},
		{
			name: "multiple signers all produce signatures",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				s1, _, _ := createTestKey()
				s2, _, _ := createTestKey()
				s3, _, _ := createTestKey()
				return "test", bytes.NewReader([]byte("data")), []SignOption{
					SignWithSigners(s1, s2, s3),
				}
			},
			wantErr: false,
			check: func(t *testing.T, env Envelope) {
				require.Len(t, env.Signatures, 3, "3 signers should produce 3 signatures")
				for i, sig := range env.Signatures {
					assert.NotEmpty(t, sig.KeyID, "signature %d should have a KeyID", i)
					assert.NotEmpty(t, sig.Signature, "signature %d should have signature bytes", i)
				}
			},
		},
		{
			name: "mixed nil and valid signers (nil gets skipped)",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				s1, _, _ := createTestKey()
				s2, _, _ := createTestKey()
				return "test", bytes.NewReader([]byte("data")), []SignOption{
					SignWithSigners(nil, s1, nil, s2, nil),
				}
			},
			wantErr: false,
			check: func(t *testing.T, env Envelope) {
				assert.Len(t, env.Signatures, 2,
					"only non-nil signers should produce signatures")
			},
		},
		{
			name: "empty payload signs successfully",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				s, _, _ := createTestKey()
				return "test", bytes.NewReader([]byte{}), []SignOption{
					SignWithSigners(s),
				}
			},
			wantErr: false,
			check: func(t *testing.T, env Envelope) {
				assert.Empty(t, env.Payload, "payload should be empty")
				assert.NotEmpty(t, env.Signatures, "should still produce a signature")
			},
		},
		{
			name: "empty body type signs successfully",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				s, _, _ := createTestKey()
				return "", bytes.NewReader([]byte("data")), []SignOption{
					SignWithSigners(s),
				}
			},
			wantErr: false,
			check: func(t *testing.T, env Envelope) {
				assert.Equal(t, "", env.PayloadType)
			},
		},
		{
			name: "second signer fails leaves partial state",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				s1, _, _ := createTestKey()
				badSigner := &tableErrSigner{keyID: "bad", err: fmt.Errorf("second signer fails")}
				return "test", bytes.NewReader([]byte("data")), []SignOption{
					SignWithSigners(s1, badSigner),
				}
			},
			wantErr: true,
			errMsg:  "second signer fails",
		},
		{
			name: "timestamper error propagates",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				root, rootPriv, _ := createRoot()
				_, intPriv, _ := createIntermediate(root, rootPriv)
				leaf, leafPriv, _ := createLeaf(root, intPriv)
				s, _ := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
				return "test", bytes.NewReader([]byte("data")), []SignOption{
					SignWithSigners(s),
					SignWithTimestampers(tableFailingTimestamper{}),
				}
			},
			wantErr: true,
			errMsg:  "timestamper failure",
		},
		{
			name: "ECDSA signer produces valid envelope",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				s := cryptoutil.NewECDSASigner(priv, crypto.SHA256)
				return "test", bytes.NewReader([]byte("ecdsa-data")), []SignOption{
					SignWithSigners(s),
				}
			},
			wantErr: false,
			check: func(t *testing.T, env Envelope) {
				assert.Len(t, env.Signatures, 1)
				assert.NotEmpty(t, env.Signatures[0].Signature)
			},
		},
		{
			name: "x509 signer includes certificate in envelope",
			setup: func(t *testing.T) (string, io.Reader, []SignOption) {
				root, rootPriv, _ := createRoot()
				intermediate, intPriv, _ := createIntermediate(root, rootPriv)
				leaf, leafPriv, _ := createLeaf(intermediate, intPriv)
				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)
				return "test", bytes.NewReader([]byte("cert-data")), []SignOption{
					SignWithSigners(s),
				}
			},
			wantErr: false,
			check: func(t *testing.T, env Envelope) {
				require.Len(t, env.Signatures, 1)
				assert.NotEmpty(t, env.Signatures[0].Certificate,
					"x509 signer should include certificate PEM")
				assert.NotEmpty(t, env.Signatures[0].Intermediates,
					"x509 signer should include intermediate certs")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bodyType, body, opts := tc.setup(t)
			env, err := Sign(bodyType, body, opts...)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				require.NoError(t, err)
				if tc.check != nil {
					tc.check(t, env)
				}
			}
		})
	}
}

// ============================================================================
// TestTableVerifyEdgeCases - Verify function edge cases
// ============================================================================

func TestTableVerifyEdgeCases(t *testing.T) {
	// Pre-create reusable keys.
	signer1, verifier1, err := createTestKey()
	require.NoError(t, err)
	signer2, verifier2, err := createTestKey()
	require.NoError(t, err)
	_, wrongVerifier, err := createTestKey()
	require.NoError(t, err)

	// Pre-create envelopes.
	envSingle, err := Sign("test", bytes.NewReader([]byte("single-signer")), SignWithSigners(signer1))
	require.NoError(t, err)

	envDouble, err := Sign("test", bytes.NewReader([]byte("double-signer")), SignWithSigners(signer1, signer2))
	require.NoError(t, err)

	tests := []struct {
		name     string
		envelope Envelope
		opts     []VerificationOption
		wantErr  bool
		check    func(t *testing.T, checked []CheckedVerifier, err error)
	}{
		{
			name:     "threshold=0 returns ErrInvalidThreshold",
			envelope: envSingle,
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
				VerifyWithThreshold(0),
			},
			wantErr: true,
			check: func(t *testing.T, _ []CheckedVerifier, err error) {
				var target ErrInvalidThreshold
				require.ErrorAs(t, err, &target)
				assert.Equal(t, ErrInvalidThreshold(0), target)
			},
		},
		{
			name:     "negative threshold returns ErrInvalidThreshold",
			envelope: envSingle,
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
				VerifyWithThreshold(-42),
			},
			wantErr: true,
			check: func(t *testing.T, _ []CheckedVerifier, err error) {
				var target ErrInvalidThreshold
				require.ErrorAs(t, err, &target)
				assert.Equal(t, ErrInvalidThreshold(-42), target)
			},
		},
		{
			name: "envelope with zero signatures returns ErrNoSignatures",
			envelope: Envelope{
				Payload:     []byte("data"),
				PayloadType: "test",
				Signatures:  []Signature{},
			},
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
			},
			wantErr: true,
			check: func(t *testing.T, _ []CheckedVerifier, err error) {
				var target ErrNoSignatures
				require.ErrorAs(t, err, &target)
			},
		},
		{
			name: "envelope with nil signatures slice returns ErrNoSignatures",
			envelope: Envelope{
				Payload:     []byte("data"),
				PayloadType: "test",
				Signatures:  nil,
			},
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
			},
			wantErr: true,
			check: func(t *testing.T, _ []CheckedVerifier, err error) {
				var target ErrNoSignatures
				require.ErrorAs(t, err, &target)
			},
		},
		{
			name:     "threshold=1 with matching verifier passes",
			envelope: envSingle,
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
				VerifyWithThreshold(1),
			},
			wantErr: false,
			check: func(t *testing.T, checked []CheckedVerifier, _ error) {
				passed := 0
				for _, cv := range checked {
					if cv.Error == nil {
						passed++
					}
				}
				assert.Equal(t, 1, passed)
			},
		},
		{
			name:     "threshold=1 with wrong verifier returns ErrNoMatchingSigs",
			envelope: envSingle,
			opts: []VerificationOption{
				VerifyWithVerifiers(wrongVerifier),
				VerifyWithThreshold(1),
			},
			wantErr: true,
			check: func(t *testing.T, _ []CheckedVerifier, err error) {
				var target ErrNoMatchingSigs
				require.ErrorAs(t, err, &target)
			},
		},
		{
			name:     "threshold=2 with only 1 valid signature returns ErrThresholdNotMet",
			envelope: envSingle,
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
				VerifyWithThreshold(2),
			},
			wantErr: true,
			check: func(t *testing.T, checked []CheckedVerifier, err error) {
				var target ErrThresholdNotMet
				require.ErrorAs(t, err, &target)
				assert.Equal(t, 2, target.Theshold)
				assert.Equal(t, 1, target.Actual)
			},
		},
		{
			name:     "threshold=1 with 2 valid signatures passes",
			envelope: envDouble,
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1, verifier2),
				VerifyWithThreshold(1),
			},
			wantErr: false,
			check: func(t *testing.T, checked []CheckedVerifier, _ error) {
				passed := 0
				for _, cv := range checked {
					if cv.Error == nil {
						passed++
					}
				}
				assert.GreaterOrEqual(t, passed, 2)
			},
		},
		{
			name:     "threshold=2 with 2 distinct valid signatures passes",
			envelope: envDouble,
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1, verifier2),
				VerifyWithThreshold(2),
			},
			wantErr: false,
		},
		{
			name: "duplicate signatures from same key do not meet threshold=2",
			envelope: func() Envelope {
				env := envSingle
				origSig := env.Signatures[0]
				return Envelope{
					Payload:     env.Payload,
					PayloadType: env.PayloadType,
					Signatures:  []Signature{origSig, origSig, origSig},
				}
			}(),
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
				VerifyWithThreshold(2),
			},
			wantErr: true,
			check: func(t *testing.T, _ []CheckedVerifier, err error) {
				var target ErrThresholdNotMet
				require.ErrorAs(t, err, &target)
				assert.Equal(t, 1, target.Actual,
					"duplicated signatures from same key should count as 1")
			},
		},
		{
			name: "tampered payload with valid signature fails",
			envelope: func() Envelope {
				return Envelope{
					Payload:     []byte("TAMPERED PAYLOAD"),
					PayloadType: envSingle.PayloadType,
					Signatures:  envSingle.Signatures,
				}
			}(),
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
			},
			wantErr: true,
		},
		{
			name: "tampered payloadType with valid signature fails",
			envelope: func() Envelope {
				return Envelope{
					Payload:     envSingle.Payload,
					PayloadType: "tampered-type",
					Signatures:  envSingle.Signatures,
				}
			}(),
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
			},
			wantErr: true,
		},
		{
			name: "valid payload but single bit-flipped signature fails",
			envelope: func() Envelope {
				sig := make([]byte, len(envSingle.Signatures[0].Signature))
				copy(sig, envSingle.Signatures[0].Signature)
				sig[len(sig)/2] ^= 0x01
				return Envelope{
					Payload:     envSingle.Payload,
					PayloadType: envSingle.PayloadType,
					Signatures: []Signature{
						{KeyID: envSingle.Signatures[0].KeyID, Signature: sig},
					},
				}
			}(),
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
			},
			wantErr: true,
		},
		{
			name:     "sign with key A, verify with key B fails",
			envelope: envSingle, // signed by signer1
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier2), // verifier for signer2
			},
			wantErr: true,
		},
		{
			name:     "default threshold (omit option) is 1",
			envelope: envSingle,
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
				// No VerifyWithThreshold => default is 1
			},
			wantErr: false,
		},
		{
			name: "cross-envelope signature replay fails (different payload)",
			envelope: func() Envelope {
				env2, err := Sign("test", bytes.NewReader([]byte("different-payload")), SignWithSigners(signer1))
				require.NoError(t, err)
				// Use env2's payload with envSingle's signature
				return Envelope{
					Payload:     env2.Payload,
					PayloadType: env2.PayloadType,
					Signatures:  envSingle.Signatures,
				}
			}(),
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
			},
			wantErr: true,
		},
		{
			name: "cross-algorithm: ECDSA sig does not verify with RSA verifier",
			envelope: func() Envelope {
				ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				ecSigner := cryptoutil.NewECDSASigner(ecPriv, crypto.SHA256)
				env, err := Sign("test", bytes.NewReader([]byte("ec-data")), SignWithSigners(ecSigner))
				require.NoError(t, err)
				return env
			}(),
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1), // RSA verifier
			},
			wantErr: true,
		},
		{
			name:     "empty envelope (zero-value) returns ErrNoSignatures",
			envelope: Envelope{},
			opts: []VerificationOption{
				VerifyWithVerifiers(verifier1),
			},
			wantErr: true,
			check: func(t *testing.T, _ []CheckedVerifier, err error) {
				var target ErrNoSignatures
				require.ErrorAs(t, err, &target)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checked, err := tc.envelope.Verify(tc.opts...)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tc.check != nil {
				tc.check(t, checked, err)
			}
		})
	}
}

// ============================================================================
// TestTableX509Verification - X.509 certificate chain verification
// ============================================================================

func TestTableX509Verification(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (Envelope, []VerificationOption)
		wantErr bool
		check   func(t *testing.T, checked []CheckedVerifier, err error)
	}{
		{
			name: "valid cert chain: leaf -> intermediate -> root",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				env, err := Sign("test", bytes.NewReader([]byte("cert-chain")), SignWithSigners(s))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithThreshold(1),
				}
			},
			wantErr: false,
			check: func(t *testing.T, checked []CheckedVerifier, _ error) {
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
			name: "expired certificate fails with default time.Now()",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				// Create a chain that was valid 48h-24h ago (already expired).
				past := time.Now().Add(-48 * time.Hour)
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, past, 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				env, err := Sign("test", bytes.NewReader([]byte("expired")), SignWithSigners(s))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithThreshold(1),
				}
			},
			wantErr: true,
			check: func(t *testing.T, _ []CheckedVerifier, err error) {
				// Without timestamp verifiers, the cert path uses time.Now(),
				// and without a raw verifier, this must fail.
				assert.Error(t, err)
			},
		},
		{
			name: "not-yet-valid certificate fails",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				// Create a chain that will be valid 24h from now.
				future := time.Now().Add(24 * time.Hour)
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, future, 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				env, err := Sign("test", bytes.NewReader([]byte("future-cert")), SignWithSigners(s))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithThreshold(1),
				}
			},
			wantErr: true,
		},
		{
			name: "self-signed cert works when used as its own root",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				priv, err := rsa.GenerateKey(rand.Reader, 2048)
				require.NoError(t, err)

				now := time.Now()
				template := &x509.Certificate{
					Subject:               pkix.Name{CommonName: "Self-Signed"},
					NotBefore:             now.Add(-1 * time.Hour),
					NotAfter:              now.Add(24 * time.Hour),
					KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
					BasicConstraintsValid: true,
					IsCA:                  true,
				}
				template.SerialNumber, _ = rand.Int(rand.Reader, big.NewInt(1<<32))
				certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
				require.NoError(t, err)
				cert, err := x509.ParseCertificate(certBytes)
				require.NoError(t, err)

				s, err := cryptoutil.NewSigner(priv, cryptoutil.SignWithCertificate(cert))
				require.NoError(t, err)

				env, err := Sign("test", bytes.NewReader([]byte("self-signed")), SignWithSigners(s))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(cert), // The self-signed cert IS the root.
					VerifyWithThreshold(1),
				}
			},
			wantErr: false,
		},
		{
			name: "wrong root CA rejects valid chain",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				_, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				env, err := Sign("test", bytes.NewReader([]byte("wrong-root")), SignWithSigners(s))
				require.NoError(t, err)

				// Create a DIFFERENT root that did not sign the chain.
				wrongRoot, _, _ := createRoot()

				return env, []VerificationOption{
					VerifyWithRoots(wrongRoot),
					VerifyWithIntermediates(intermediate),
					VerifyWithThreshold(1),
				}
			},
			wantErr: true,
		},
		{
			name: "missing intermediate breaks chain",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				root, _, _, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				// Sign with the leaf cert but do NOT include the intermediate in the signer.
				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf))
				require.NoError(t, err)

				env, err := Sign("test", bytes.NewReader([]byte("broken-chain")), SignWithSigners(s))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					// No intermediate provided to the verifier either.
					VerifyWithThreshold(1),
				}
			},
			wantErr: true,
		},
		{
			name: "cert path fails but raw verifier succeeds",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				_, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				rawVerifier := cryptoutil.NewRSAVerifier(&leafPriv.PublicKey, crypto.SHA256)

				env, err := Sign("test", bytes.NewReader([]byte("fallback-to-raw")), SignWithSigners(s))
				require.NoError(t, err)

				wrongRoot, _, _ := createRoot()
				return env, []VerificationOption{
					VerifyWithRoots(wrongRoot), // cert path will fail
					VerifyWithVerifiers(rawVerifier),
					VerifyWithThreshold(1),
				}
			},
			wantErr: false,
			check: func(t *testing.T, checked []CheckedVerifier, _ error) {
				// At least the raw verifier should pass.
				passed := 0
				for _, cv := range checked {
					if cv.Error == nil {
						passed++
					}
				}
				assert.GreaterOrEqual(t, passed, 1,
					"raw verifier should succeed even when cert chain verification fails")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, opts := tc.setup(t)
			checked, err := env.Verify(opts...)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tc.check != nil {
				tc.check(t, checked, err)
			}
		})
	}
}

// ============================================================================
// TestTableTimestampVerification - Timestamp verification with X.509 certs
// ============================================================================

func TestTableTimestampVerification(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (Envelope, []VerificationOption)
		wantErr bool
		check   func(t *testing.T, checked []CheckedVerifier, err error)
	}{
		{
			name: "valid timestamp within cert validity window",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				// Timestamp at "now" which is within the cert validity.
				ts := timestamp.FakeTimestamper{T: now}
				env, err := Sign("test", bytes.NewReader([]byte("ts-valid")),
					SignWithSigners(s), SignWithTimestampers(ts))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithTimestampVerifiers(ts),
					VerifyWithThreshold(1),
				}
			},
			wantErr: false,
			check: func(t *testing.T, checked []CheckedVerifier, _ error) {
				for _, cv := range checked {
					if cv.Error == nil {
						assert.NotEmpty(t, cv.TimestampVerifiers,
							"successful verification should include timestamp verifiers")
						return
					}
				}
				t.Fatal("no passed verifier found")
			},
		},
		{
			name: "timestamp outside cert validity fails",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				// Timestamp 48h in the future, outside the cert's 24h validity.
				futureTS := timestamp.FakeTimestamper{T: now.Add(48 * time.Hour)}
				env, err := Sign("test", bytes.NewReader([]byte("ts-future")),
					SignWithSigners(s), SignWithTimestampers(futureTS))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithTimestampVerifiers(futureTS),
					VerifyWithThreshold(1),
				}
			},
			wantErr: true,
		},
		{
			name: "timestamp verifier with no timestamps in signature fails",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				// Sign WITHOUT timestampers.
				env, err := Sign("test", bytes.NewReader([]byte("no-ts")), SignWithSigners(s))
				require.NoError(t, err)

				// But verify WITH timestamp verifiers. Since sig has no timestamps,
				// the inner loop never executes, so passedTimestampVerifiers is empty.
				ts := timestamp.FakeTimestamper{T: now}
				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithTimestampVerifiers(ts),
					VerifyWithThreshold(1),
				}
			},
			wantErr: true,
		},
		{
			name: "mixed timestamps: some valid some invalid - at least one passes",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				goodTS := timestamp.FakeTimestamper{T: now}
				badTS := timestamp.FakeTimestamper{T: now.Add(100 * time.Hour)}

				env, err := Sign("test", bytes.NewReader([]byte("mixed-ts")),
					SignWithSigners(s), SignWithTimestampers(goodTS, badTS))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithTimestampVerifiers(goodTS, badTS),
					VerifyWithThreshold(1),
				}
			},
			wantErr: false,
		},
		{
			name: "failing timestamp verifier does not block raw verifier",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				rawVerifier := cryptoutil.NewRSAVerifier(&leafPriv.PublicKey, crypto.SHA256)

				// Sign with a timestamp.
				ts := timestamp.FakeTimestamper{T: now.Add(48 * time.Hour)} // outside validity
				env, err := Sign("test", bytes.NewReader([]byte("ts-but-raw-wins")),
					SignWithSigners(s), SignWithTimestampers(ts))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithTimestampVerifiers(ts),
					VerifyWithVerifiers(rawVerifier),
					VerifyWithThreshold(1),
				}
			},
			wantErr: false,
			check: func(t *testing.T, checked []CheckedVerifier, _ error) {
				passed := 0
				for _, cv := range checked {
					if cv.Error == nil {
						passed++
					}
				}
				assert.GreaterOrEqual(t, passed, 1,
					"raw verifier should pass even when timestamp verification fails")
			},
		},
		{
			name: "timestamp verifier that always fails results in cert path failure",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				now := time.Now()
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, now.Add(-1*time.Hour), 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				goodTS := timestamp.FakeTimestamper{T: now}
				env, err := Sign("test", bytes.NewReader([]byte("bad-tv")),
					SignWithSigners(s), SignWithTimestampers(goodTS))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithTimestampVerifiers(tableFailingTimestampVerifier{}),
					VerifyWithThreshold(1),
				}
			},
			wantErr: true,
		},
		{
			name: "expired cert rescued by valid timestamp",
			setup: func(t *testing.T) (Envelope, []VerificationOption) {
				// Create a chain that was valid from 48h ago to 24h ago.
				past := time.Now().Add(-48 * time.Hour)
				root, _, intermediate, _, leaf, leafPriv := createCertChainForTable(t, past, 24*time.Hour)

				s, err := cryptoutil.NewSigner(leafPriv,
					cryptoutil.SignWithCertificate(leaf),
					cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
				require.NoError(t, err)

				// Timestamp at past+12h which is within the cert's validity window.
				validTime := past.Add(12 * time.Hour)
				ts := timestamp.FakeTimestamper{T: validTime}

				env, err := Sign("test", bytes.NewReader([]byte("expired-but-timestamped")),
					SignWithSigners(s), SignWithTimestampers(ts))
				require.NoError(t, err)

				return env, []VerificationOption{
					VerifyWithRoots(root),
					VerifyWithIntermediates(intermediate),
					VerifyWithTimestampVerifiers(ts),
					VerifyWithThreshold(1),
				}
			},
			wantErr: false,
			check: func(t *testing.T, checked []CheckedVerifier, _ error) {
				for _, cv := range checked {
					if cv.Error == nil {
						assert.NotEmpty(t, cv.TimestampVerifiers,
							"expired cert rescued by timestamp should report timestamp verifiers")
						return
					}
				}
				t.Fatal("expected at least one passed verifier with timestamp")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, opts := tc.setup(t)
			checked, err := env.Verify(opts...)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if tc.check != nil {
				tc.check(t, checked, err)
			}
		})
	}
}

// ============================================================================
// TestTableErrorTypes - Error type behavior
// ============================================================================

func TestTableErrorTypes(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantMsg string
	}{
		{
			name:    "ErrNoSignatures message",
			err:     ErrNoSignatures{},
			wantMsg: "no signatures in dsse envelope",
		},
		{
			name:    "ErrInvalidThreshold(0) message",
			err:     ErrInvalidThreshold(0),
			wantMsg: "invalid threshold (0)",
		},
		{
			name:    "ErrInvalidThreshold(-5) message",
			err:     ErrInvalidThreshold(-5),
			wantMsg: "invalid threshold (-5)",
		},
		{
			name:    "ErrThresholdNotMet message",
			err:     ErrThresholdNotMet{Theshold: 3, Actual: 1},
			wantMsg: "envelope did not meet verifier threshold. expected 3 valid verifiers but got 1",
		},
		{
			name:    "ErrNoMatchingSigs with empty verifiers",
			err:     ErrNoMatchingSigs{Verifiers: nil},
			wantMsg: "no valid signatures for the provided verifiers found for keyids:",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Contains(t, tc.err.Error(), tc.wantMsg)
		})
	}
}

// ============================================================================
// TestTableSignAndVerifyRoundTrip - End-to-end sign+verify with various key types
// ============================================================================

func TestTableSignAndVerifyRoundTrip(t *testing.T) {
	tests := []struct {
		name        string
		payloadType string
		payload     []byte
		makeSigner  func(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier)
	}{
		{
			name:        "RSA-2048 with JSON payload",
			payloadType: "application/vnd.in-toto+json",
			payload:     []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[]}`),
			makeSigner: func(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
				s, v, err := createTestKey()
				require.NoError(t, err)
				return s, v
			},
		},
		{
			name:        "RSA-4096 with large payload",
			payloadType: "application/octet-stream",
			payload:     make([]byte, 64*1024), // 64KB
			makeSigner: func(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
				priv, err := rsa.GenerateKey(rand.Reader, 4096)
				require.NoError(t, err)
				return cryptoutil.NewRSASigner(priv, crypto.SHA256),
					cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
			},
		},
		{
			name:        "ECDSA-P256 with empty payload",
			payloadType: "text/plain",
			payload:     []byte{},
			makeSigner: func(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
				priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				require.NoError(t, err)
				return cryptoutil.NewECDSASigner(priv, crypto.SHA256),
					cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
			},
		},
		{
			name:        "ECDSA-P384 with binary payload",
			payloadType: "application/cbor",
			payload:     []byte{0x00, 0xFF, 0x01, 0xFE, 0x02, 0xFD},
			makeSigner: func(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
				priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				require.NoError(t, err)
				return cryptoutil.NewECDSASigner(priv, crypto.SHA256),
					cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
			},
		},
		{
			name:        "ED25519 with unicode payload",
			payloadType: "text/plain;charset=utf-8",
			payload:     []byte("Hej v\xC3\xA4rlden! \xE4\xB8\x96\xE7\x95\x8C \xF0\x9F\x8C\x8D"),
			makeSigner: func(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
				edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)
				return cryptoutil.NewED25519Signer(edPriv),
					cryptoutil.NewED25519Verifier(edPub)
			},
		},
		{
			name:        "RSA with null bytes in payload type",
			payloadType: "type\x00with\x00nulls",
			payload:     []byte("null-type-data"),
			makeSigner: func(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
				s, v, err := createTestKey()
				require.NoError(t, err)
				return s, v
			},
		},
		{
			name:        "RSA with very long payload type",
			payloadType: strings.Repeat("a", 10000),
			payload:     []byte("long-type"),
			makeSigner: func(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
				s, v, err := createTestKey()
				require.NoError(t, err)
				return s, v
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			signer, verifier := tc.makeSigner(t)
			env, err := Sign(tc.payloadType, bytes.NewReader(tc.payload), SignWithSigners(signer))
			require.NoError(t, err)

			// Verify the envelope.
			checked, err := env.Verify(VerifyWithVerifiers(verifier))
			require.NoError(t, err)

			passed := 0
			for _, cv := range checked {
				if cv.Error == nil {
					passed++
				}
			}
			assert.Equal(t, 1, passed, "exactly one verifier should pass")

			// Verify payload integrity.
			assert.Equal(t, tc.payload, env.Payload)
			assert.Equal(t, tc.payloadType, env.PayloadType)
		})
	}
}

// ============================================================================
// TestTableSignAndVerifyRoundTripED25519 - Dedicated ED25519 multi-payload test
// ============================================================================

func TestTableSignAndVerifyRoundTripED25519(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	signer := cryptoutil.NewED25519Signer(edPriv)
	verifier := cryptoutil.NewED25519Verifier(edPub)

	payloads := []struct {
		name        string
		payloadType string
		payload     []byte
	}{
		{"empty", "test", []byte{}},
		{"small", "test", []byte("hello ed25519")},
		{"binary", "application/octet-stream", []byte{0, 1, 2, 255, 254, 253}},
		{"unicode", "text/plain", []byte("Hello \xE4\xB8\x96\xE7\x95\x8C")},
		{"1KB", "test", make([]byte, 1024)},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			env, err := Sign(tc.payloadType, bytes.NewReader(tc.payload), SignWithSigners(signer))
			require.NoError(t, err)

			_, err = env.Verify(VerifyWithVerifiers(verifier))
			require.NoError(t, err)
		})
	}
}

// ============================================================================
// TestTablePAECollisionResistance - Systematic PAE collision testing
// ============================================================================

func TestTablePAECollisionResistance(t *testing.T) {
	type pair struct {
		bodyType string
		body     []byte
	}

	tests := []struct {
		name string
		a    pair
		b    pair
	}{
		{
			name: "type swap",
			a:    pair{"typeA", []byte("bodyB")},
			b:    pair{"typeB", []byte("bodyA")},
		},
		{
			name: "length prefix injection in type",
			a:    pair{"3 abc", []byte("def")},
			b:    pair{"3", []byte("abc 3 def")},
		},
		{
			name: "empty vs single space in type",
			a:    pair{"", []byte("x")},
			b:    pair{" ", []byte("x")},
		},
		{
			name: "null byte in type vs without",
			a:    pair{"a\x00b", []byte("c")},
			b:    pair{"ab", []byte("c")},
		},
		{
			name: "trailing space in type",
			a:    pair{"type ", []byte("body")},
			b:    pair{"type", []byte(" body")},
		},
		{
			name: "body length looks like part of type",
			a:    pair{"type", []byte("4 body")},
			b:    pair{"type 4", []byte("body")},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			paeA := preauthEncode(tc.a.bodyType, tc.a.body)
			paeB := preauthEncode(tc.b.bodyType, tc.b.body)
			assert.NotEqual(t, paeA, paeB,
				"different (type, body) pairs must produce different PAE output")
		})
	}
}

// ============================================================================
// TestTableVerifyWithNilVerifierElements - Nil elements in verifier slice
// ============================================================================

func TestTableVerifyWithNilVerifierElements(t *testing.T) {
	signer, verifier, err := createTestKey()
	require.NoError(t, err)

	env, err := Sign("test", bytes.NewReader([]byte("nil-verifier-test")), SignWithSigners(signer))
	require.NoError(t, err)

	tests := []struct {
		name      string
		verifiers []cryptoutil.Verifier
		threshold int
		wantErr   bool
	}{
		{
			name:      "all nil verifiers",
			verifiers: []cryptoutil.Verifier{nil, nil, nil},
			threshold: 1,
			wantErr:   true,
		},
		{
			name:      "nil before valid verifier",
			verifiers: []cryptoutil.Verifier{nil, verifier},
			threshold: 1,
			wantErr:   false,
		},
		{
			name:      "nil after valid verifier",
			verifiers: []cryptoutil.Verifier{verifier, nil},
			threshold: 1,
			wantErr:   false,
		},
		{
			name:      "nil surrounded by valid verifiers",
			verifiers: []cryptoutil.Verifier{verifier, nil, verifier},
			threshold: 1,
			wantErr:   false,
		},
		{
			name:      "single nil",
			verifiers: []cryptoutil.Verifier{nil},
			threshold: 1,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				_, err := env.Verify(
					VerifyWithVerifiers(tc.verifiers...),
					VerifyWithThreshold(tc.threshold),
				)
				if tc.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			}, "nil verifiers in slice must not cause panics")
		})
	}
}

// ============================================================================
// TestTableSignOptionAccumulation - SignOption behavior
// ============================================================================

func TestTableSignOptionAccumulation(t *testing.T) {
	s1, _, err := createTestKey()
	require.NoError(t, err)
	s2, _, err := createTestKey()
	require.NoError(t, err)

	tests := []struct {
		name         string
		opts         []SignOption
		wantErr      bool
		expectedSigs int
		errMsg       string
	}{
		{
			name:         "SignWithSigners once with 2 signers",
			opts:         []SignOption{SignWithSigners(s1, s2)},
			expectedSigs: 2,
		},
		{
			name: "SignWithSigners twice replaces (last wins)",
			opts: []SignOption{
				SignWithSigners(s1),
				SignWithSigners(s2),
			},
			// The second call replaces so.signers, so only s2 is used.
			expectedSigs: 1,
		},
		{
			name:    "no SignWithSigners option at all",
			opts:    []SignOption{},
			wantErr: true,
			errMsg:  "must have at least one signer",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, err := Sign("test", bytes.NewReader([]byte("data")), tc.opts...)
			if tc.wantErr {
				require.Error(t, err)
				if tc.errMsg != "" {
					assert.Contains(t, err.Error(), tc.errMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, env.Signatures, tc.expectedSigs)
			}
		})
	}
}

// ============================================================================
// TestTableErrNoMatchingSigsMessage - ErrNoMatchingSigs error message content
// ============================================================================

func TestTableErrNoMatchingSigsMessage(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrNoMatchingSigs
		contains []string
	}{
		{
			name: "empty verifiers",
			err:  ErrNoMatchingSigs{Verifiers: nil},
			contains: []string{
				"no valid signatures for the provided verifiers",
			},
		},
		{
			name: "verifier with error",
			err: ErrNoMatchingSigs{
				Verifiers: []CheckedVerifier{
					{
						Verifier: nil,
						Error:    errors.New("test error"),
					},
				},
			},
			contains: []string{
				"<nil verifier>",
				"test error",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			for _, s := range tc.contains {
				assert.Contains(t, msg, s)
			}
		})
	}
}

// ============================================================================
// TestTableVerifierKeyIDFunction - verifierKeyID behavior
// ============================================================================

func TestTableVerifierKeyIDFunction(t *testing.T) {
	priv1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	v1 := cryptoutil.NewRSAVerifier(&priv1.PublicKey, crypto.SHA256)

	priv2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	v2 := cryptoutil.NewRSAVerifier(&priv2.PublicKey, crypto.SHA256)

	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "deterministic for same verifier",
			check: func(t *testing.T) {
				kid1 := verifierKeyID(v1)
				kid2 := verifierKeyID(v1)
				assert.Equal(t, kid1, kid2)
			},
		},
		{
			name: "different for different verifiers",
			check: func(t *testing.T) {
				kid1 := verifierKeyID(v1)
				kid2 := verifierKeyID(v2)
				assert.NotEqual(t, kid1, kid2)
			},
		},
		{
			name: "non-empty for valid verifier",
			check: func(t *testing.T) {
				kid := verifierKeyID(v1)
				assert.NotEmpty(t, kid)
			},
		},
		{
			name: "fallback prefix for error KeyID verifier",
			check: func(t *testing.T) {
				errV := &tableErrorKeyIDVerifier{inner: v1}
				kid := verifierKeyID(errV)
				assert.True(t, strings.HasPrefix(kid, "fallback:"),
					"error KeyID verifier should use fallback: prefix")
			},
		},
		{
			name: "fallback is stable for same pointer",
			check: func(t *testing.T) {
				errV := &tableErrorKeyIDVerifier{inner: v1}
				kid1 := verifierKeyID(errV)
				kid2 := verifierKeyID(errV)
				assert.Equal(t, kid1, kid2)
			},
		},
		{
			name: "fallback differs for different pointers",
			check: func(t *testing.T) {
				errV1 := &tableErrorKeyIDVerifier{inner: v1}
				errV2 := &tableErrorKeyIDVerifier{inner: v2}
				kid1 := verifierKeyID(errV1)
				kid2 := verifierKeyID(errV2)
				assert.NotEqual(t, kid1, kid2)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t)
		})
	}
}
