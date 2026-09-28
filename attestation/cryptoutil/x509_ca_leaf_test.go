// Copyright 2026 The Aflock Authors
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

package cryptoutil

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A CA certificate is never a signing leaf. Before this, X509Verifier checked
// the chain and the codeSigning EKU but not BasicConstraints, so a CA key
// could sign attestations directly and present its own CA certificate:
//   - an intermediate carrying codeSigning (the platform Fulcio CA's shape)
//     chains to the root and satisfies the EKU check;
//   - a self-signed root without EKU (Go: unrestricted) verifies against a
//     pool that contains itself.
// Either skips the short-lived leaf, its OIDC identity and its SAN
// constraints entirely.

func createCodeSigningIntermediate(t *testing.T, parent *x509.Certificate, parentPriv interface{}) (*x509.Certificate, interface{}) {
	t.Helper()
	priv, pub, err := createRsaKey()
	require.NoError(t, err)
	cert, err := createCert(parentPriv, pub, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Fulcio-shaped CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}, parent)
	require.NoError(t, err)
	return cert, priv
}

func signWith(t *testing.T, priv interface{}, data []byte) []byte {
	t.Helper()
	s, err := NewSigner(priv)
	require.NoError(t, err)
	sig, err := s.Sign(bytes.NewReader(data))
	require.NoError(t, err)
	return sig
}

func TestX509Verifier_RejectsCACertificateAsLeaf(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	plainCA, plainCAPriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	fulcioCA, fulcioCAPriv := createCodeSigningIntermediate(t, root, rootPriv)
	data := []byte("attestation payload")

	cases := []struct {
		name          string
		leaf          *x509.Certificate
		priv          interface{}
		intermediates []*x509.Certificate
	}{
		{"intermediate CA with codeSigning EKU (Fulcio CA shape)", fulcioCA, fulcioCAPriv, nil},
		{"intermediate CA without EKU", plainCA, plainCAPriv, nil},
		{"self-signed root", root, rootPriv, nil},
		{"intermediate CA with itself also offered as intermediate", fulcioCA, fulcioCAPriv, []*x509.Certificate{fulcioCA}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig := signWith(t, tc.priv, data)
			v, err := NewX509Verifier(tc.leaf, tc.intermediates, []*x509.Certificate{root}, time.Time{})
			require.NoError(t, err)

			err = v.Verify(bytes.NewReader(data), sig)
			require.Error(t, err, "a CA certificate must not verify as a signing leaf")
			require.True(t, errors.Is(err, ErrCACertificateAsLeaf), "want ErrCACertificateAsLeaf, got %v", err)

			err = v.BelongsToRoot(root)
			require.Error(t, err, "a CA certificate must not satisfy BelongsToRoot")
			require.True(t, errors.Is(err, ErrCACertificateAsLeaf), "want ErrCACertificateAsLeaf, got %v", err)
		})
	}
}

// The guard is on BasicConstraints only: ordinary leaves, including a v1-style
// leaf with no BasicConstraints extension at all, still verify.
func TestX509Verifier_NonCALeavesStillVerify(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intPriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	data := []byte("attestation payload")

	leaf, leafPriv, err := createLeafWithEKU(intermediate, intPriv, []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning})
	require.NoError(t, err)

	priv, pub, err := createRsaKey()
	require.NoError(t, err)
	noBC, err := createCert(intPriv, pub, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "leaf without basicConstraints"},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}, intermediate)
	require.NoError(t, err)
	require.False(t, noBC.BasicConstraintsValid)

	for name, c := range map[string]struct {
		cert *x509.Certificate
		priv interface{}
	}{"codeSigning leaf": {leaf, leafPriv}, "leaf without basicConstraints": {noBC, priv}} {
		t.Run(name, func(t *testing.T) {
			v, err := NewX509Verifier(c.cert, []*x509.Certificate{intermediate}, []*x509.Certificate{root}, time.Time{})
			require.NoError(t, err)
			require.NoError(t, v.Verify(bytes.NewReader(data), signWith(t, c.priv, data)))
			require.NoError(t, v.BelongsToRoot(root))
		})
	}
}
