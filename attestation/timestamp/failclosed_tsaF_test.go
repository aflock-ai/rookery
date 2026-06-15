// Copyright 2022 The Witness Contributors
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

package timestamp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/digitorus/timestamp"
)

// ==========================================================================
// Finding F (#5747): TSA timestamp verification does not require the
// id-kp-timeStamping EKU.
//
// File under test: subtrees/rookery/attestation/timestamp/tsp.go:225-267
// (TSPVerifier.Verify; the chain check now pins the timeStamping EKU via
//  pkcs7.VerifyWithOpts).
//
// Fail-closed contract: an RFC-3161 timestamp token whose signer cert chains
// correctly to a trusted root BUT lacks the id-kp-timeStamping Extended Key
// Usage MUST be REJECTED. A non-timestamping cert from the same CA (e.g. a
// code-signing or TLS leaf) must NOT be able to vouch for signing time.
//
// Before the fix VerifyWithChain defaulted KeyUsages to ExtKeyUsageAny
// (pkcs7 verify.go:75-77), so the EKU was unconstrained and the token was
// accepted — these tests therefore FAILED until Verify pinned the
// timeStamping EKU.
// ==========================================================================

// makeRedgateCA builds a self-signed CA cert + key for use as the trusted root.
func makeRedgateCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "redgate-tsa-ca", Organization: []string{"redgate"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return caCert, caKey
}

// makeRedgateLeaf issues a leaf cert from the CA with the supplied EKUs.
func makeRedgateLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, ekus []x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "redgate-tsa-signer", Organization: []string{"redgate"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  ekus,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf cert: %v", err)
	}
	return leafCert, leafKey
}

// makeRedgateToken synthesizes a real RFC-3161 timestamp token over `payload`,
// signed by `signerCert`/`signerKey`, with `signerCert` embedded so the
// verifier can build a chain. Returns the raw TSR token bytes (as stored in a
// DSSE signature timestamp).
func makeRedgateToken(t *testing.T, signerCert *x509.Certificate, signerKey crypto.Signer, payload []byte) []byte {
	t.Helper()

	hashedMessage, err := func() ([]byte, error) {
		h := crypto.SHA256.New()
		if _, werr := h.Write(payload); werr != nil {
			return nil, werr
		}
		return h.Sum(nil), nil
	}()
	if err != nil {
		t.Fatalf("hash payload: %v", err)
	}

	ts := &timestamp.Timestamp{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: hashedMessage,
		Time:          time.Now().UTC(),
		Accuracy:      time.Second,
		SerialNumber:  big.NewInt(99),
		// A valid TSA policy OID is required: populateTSTInfo asn1-marshals it,
		// and an empty OID fails to encode ("invalid object identifier").
		Policy: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1},
		// Leave Certificates empty so generateSignedData takes the AddSigner
		// path: it embeds the leaf signer cert (issuer = the CA) WITHOUT trying
		// to chain-verify it during signing. The CA is supplied to the verifier
		// as the trusted root instead, exercising tsp.go:263's chain build.
		AddTSACertificate: true,
	}

	respDER, err := ts.CreateResponseWithOpts(signerCert, signerKey, crypto.SHA256)
	if err != nil {
		t.Fatalf("create timestamp response: %v", err)
	}

	parsed, err := timestamp.ParseResponse(respDER)
	if err != nil {
		t.Fatalf("parse synthesized timestamp response: %v", err)
	}
	return parsed.RawToken
}

// TestRed_F_VerifyRejectsNonTimestampingEKU asserts the fail-closed contract:
// a TSA token whose signer cert chains to the trusted root but carries a
// code-signing EKU (NOT id-kp-timeStamping) must be REJECTED by Verify.
//
// Finding F (#5747) — tsp.go:225-267 (chain check now pins timeStamping EKU).
// Contract: a non-timestamping cert from the same CA must not vouch for time.
func TestRed_F_VerifyRejectsNonTimestampingEKU(t *testing.T) {
	caCert, caKey := makeRedgateCA(t)
	// Signer cert with the WRONG EKU (code signing) — explicitly NOT timeStamping.
	signerCert, signerKey := makeRedgateLeaf(t, caCert, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})

	payload := []byte("artifact-bytes-to-be-timestamped")
	token := makeRedgateToken(t, signerCert, signerKey, payload)

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{caCert}))

	signedTime, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	if err == nil {
		t.Fatalf("FAIL-OPEN: Verify accepted a TSA token whose signer cert lacks the "+
			"id-kp-timeStamping EKU (it has only codeSigning). A non-timestamping cert "+
			"from the same CA vouched for signing time %v. Finding F (#5747), tsp.go:263 "+
			"must pin the timeStamping EKU.", signedTime)
	}
}

// TestRed_F_VerifyRejectsNoEKUSigner asserts the same contract for a signer
// cert that declares NO ExtKeyUsage at all. RFC-3161 requires the TSA signing
// cert to carry id-kp-timeStamping (critical, sole); a cert with no EKU does
// not satisfy that and must be REJECTED.
//
// Finding F (#5747) — tsp.go:225-267 (chain check now pins timeStamping EKU).
// Contract: absence of the timeStamping EKU must fail closed.
func TestRed_F_VerifyRejectsNoEKUSigner(t *testing.T) {
	caCert, caKey := makeRedgateCA(t)
	// Signer cert with NO EKU constraints at all.
	signerCert, signerKey := makeRedgateLeaf(t, caCert, caKey, nil)

	payload := []byte("artifact-bytes-to-be-timestamped-2")
	token := makeRedgateToken(t, signerCert, signerKey, payload)

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{caCert}))

	signedTime, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	if err == nil {
		t.Fatalf("FAIL-OPEN: Verify accepted a TSA token whose signer cert declares NO "+
			"ExtKeyUsage (no id-kp-timeStamping). It vouched for signing time %v. "+
			"Finding F (#5747), tsp.go:263.", signedTime)
	}
}

// TestRed_F_VerifyAcceptsTimestampingEKU is the isolation control: the SAME
// synthesis machinery, but the signer cert HAS the id-kp-timeStamping EKU.
// This must continue to PASS. It proves the two rejection tests above fail
// solely because of the missing EKU (not because token synthesis is broken),
// and it must keep passing once the fix lands.
//
// Finding F (#5747) — control for tsp.go:225-267.
func TestRed_F_VerifyAcceptsTimestampingEKU(t *testing.T) {
	caCert, caKey := makeRedgateCA(t)
	// Conformant TSA signer: id-kp-timeStamping EKU present.
	signerCert, signerKey := makeRedgateLeaf(t, caCert, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})

	payload := []byte("artifact-bytes-to-be-timestamped-3")
	token := makeRedgateToken(t, signerCert, signerKey, payload)

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{caCert}))

	signedTime, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("control: Verify rejected a CONFORMANT TSA token (signer has the "+
			"timeStamping EKU); synthesis or chain setup is wrong, the red tests are "+
			"not isolating the EKU defect. err=%v", err)
	}
	if signedTime.IsZero() {
		t.Fatalf("control: Verify returned zero time for a conformant token")
	}
}
