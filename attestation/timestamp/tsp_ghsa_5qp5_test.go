// Copyright 2026 TestifySec, Inc.
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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ekuOID maps a recognized x509.ExtKeyUsage to its OID so a test can emit a
// critical EKU extension by hand (Go's CreateCertificate marshals the
// ExtKeyUsage field as non-critical).
func ekuOID(t *testing.T, e x509.ExtKeyUsage) asn1.ObjectIdentifier {
	t.Helper()
	switch e {
	case x509.ExtKeyUsageTimeStamping:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	case x509.ExtKeyUsageServerAuth:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	case x509.ExtKeyUsageCodeSigning:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	default:
		t.Fatalf("unsupported test EKU: %v", e)
		return nil
	}
}

// makeRedgateLeafCriticalEKU mints a TSA leaf whose Extended Key Usage extension
// is marked CRITICAL (as RFC 3161 §2.3 requires), carrying exactly the supplied
// EKUs. The EKU is emitted as a critical ExtraExtension; tmpl.ExtKeyUsage is left
// unset to avoid a duplicate-extension error.
func makeRedgateLeafCriticalEKU(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, ekus []x509.ExtKeyUsage) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	oids := make([]asn1.ObjectIdentifier, 0, len(ekus))
	for _, e := range ekus {
		oids = append(oids, ekuOID(t, e))
	}
	ekuVal, err := asn1.Marshal(oids)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "redgate-tsa-signer-crit", Organization: []string{"redgate"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
			Critical: true,
			Value:    ekuVal,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	leafCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return leafCert, leafKey
}

// TestSecurity_GHSA_5qp5_RejectsMultiPurposeEKU proves that a TSA signing
// certificate carrying id-kp-timeStamping alongside another EKU (here
// serverAuth) is rejected — timeStamping must be the SOLE EKU
// (GHSA-5qp5-ph6r-qj9f). The EKU extension is critical, so this isolates the
// sole-EKU requirement.
func TestSecurity_GHSA_5qp5_RejectsMultiPurposeEKU(t *testing.T) {
	caCert, caKey := makeRedgateCA(t)
	signerCert, signerKey := makeRedgateLeafCriticalEKU(t, caCert, caKey,
		[]x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageServerAuth})

	payload := []byte("multi-eku-tsa-payload")
	token := makeRedgateToken(t, signerCert, signerKey, payload)

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{caCert}))
	_, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.Error(t, err,
		"a TSA signer carrying id-kp-timeStamping plus another EKU must be rejected (GHSA-5qp5-ph6r-qj9f)")
}

// TestSecurity_GHSA_5qp5_AcceptsNonCriticalSoleEKU is the backward-compatibility
// guard: a TSA signer whose sole EKU is id-kp-timeStamping but whose EKU
// extension is NON-critical must be ACCEPTED. This is the exact shape of the
// platform TSA cert (judge-api/pkg/pki: ExtKeyUsage field → non-critical via
// Go's x509). RFC 3161 §2.3 says the extension "must be critical", but enforcing
// that would reject every already-issued platform timestamp (the token embeds
// the cert) for no added protection beyond the sole-EKU check
// (GHSA-5qp5-ph6r-qj9f).
func TestSecurity_GHSA_5qp5_AcceptsNonCriticalSoleEKU(t *testing.T) {
	caCert, caKey := makeRedgateCA(t)
	signerCert, signerKey := makeRedgateLeaf(t, caCert, caKey, []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping})

	payload := []byte("noncritical-sole-eku-tsa-payload")
	token := makeRedgateToken(t, signerCert, signerKey, payload)

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{caCert}))
	signedTime, err := v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.NoError(t, err,
		"a platform-style TSA signer (sole id-kp-timeStamping EKU, non-critical) must be accepted (GHSA-5qp5-ph6r-qj9f)")
	require.False(t, signedTime.IsZero())
}

// TestSecurity_GHSA_5qp5_RejectsUnknownExtraEKU exercises the
// len(UnknownExtKeyUsage)==0 arm of the sole-EKU check: a signer carrying
// id-kp-timeStamping PLUS an unrecognized EKU OID (which Go's x509 parser puts
// in UnknownExtKeyUsage, not ExtKeyUsage) must still be rejected.
func TestSecurity_GHSA_5qp5_RejectsUnknownExtraEKU(t *testing.T) {
	caCert, caKey := makeRedgateCA(t)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	ekuVal, err := asn1.Marshal([]asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 8},     // id-kp-timeStamping
		{1, 3, 6, 1, 4, 1, 99999, 7, 1}, // an unrecognized EKU OID
	})
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4),
		Subject:      pkix.Name{CommonName: "redgate-tsa-signer-unknown", Organization: []string{"redgate"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
			Critical: true,
			Value:    ekuVal,
		}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	signerCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	payload := []byte("unknown-extra-eku-tsa-payload")
	token := makeRedgateToken(t, signerCert, leafKey, payload)

	v := NewVerifier(VerifyWithCerts([]*x509.Certificate{caCert}))
	_, err = v.Verify(context.Background(), bytes.NewReader(token), bytes.NewReader(payload))
	require.Error(t, err,
		"a TSA signer carrying id-kp-timeStamping plus an unknown EKU OID must be rejected (GHSA-5qp5-ph6r-qj9f)")
}
