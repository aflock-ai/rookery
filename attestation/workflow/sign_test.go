package workflow

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

type testSigner struct {
	key *ecdsa.PrivateKey
}

func newTestSigner(t *testing.T) *testSigner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return &testSigner{key: key}
}

func (s *testSigner) KeyID() (string, error) {
	return "test-key-id", nil
}

func (s *testSigner) Sign(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}

func (s *testSigner) Algorithm() string {
	return "ecdsa-p256"
}

func (s *testSigner) Verifier() (cryptoutil.Verifier, error) {
	return nil, nil
}

func TestSign(t *testing.T) {
	signer := newTestSigner(t)

	payload := []byte(`{"test": "data"}`)
	var output bytes.Buffer

	err := Sign(
		bytes.NewReader(payload),
		"application/json",
		&output,
		dsse.SignWithSigners(signer),
	)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// Verify output is valid JSON
	var env dsse.Envelope
	if err := json.Unmarshal(output.Bytes(), &env); err != nil {
		t.Fatalf("output is not valid envelope JSON: %v", err)
	}

	// Verify envelope has expected fields
	if env.PayloadType != "application/json" {
		t.Errorf("PayloadType = %q, want %q", env.PayloadType, "application/json")
	}
	if len(env.Payload) == 0 {
		t.Error("Payload should not be empty")
	}
	if len(env.Signatures) == 0 {
		t.Error("Signatures should not be empty")
	}
	if len(env.Signatures) > 0 && env.Signatures[0].KeyID != "test-key-id" {
		t.Errorf("KeyID = %q, want %q", env.Signatures[0].KeyID, "test-key-id")
	}
}

func TestSign_NoSigners(t *testing.T) {
	payload := []byte(`test`)
	var output bytes.Buffer
	err := Sign(bytes.NewReader(payload), "text/plain", &output)
	if err == nil {
		t.Fatal("expected error when no signers provided")
	}
}
