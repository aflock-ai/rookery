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

package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// makeCert builds a cert signed by parent (self-signed when parent==nil/parentKey
// is its own key) and returns it plus its key. Mirrors how the platform issues a
// self-signed Root and a Root-issued Fulcio CA.
func makeCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"TestifySec"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	signer := tpl
	signerKey := key
	if parent != nil {
		signer = parent
		signerKey = parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func certPEM(t *testing.T, certs ...*x509.Certificate) []byte {
	t.Helper()
	out := make([]byte, 0, len(certs)*512)
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	return out
}

// TestParsePEMCerts_LoadsEveryBlock proves the policy-trust file loaders read the
// WHOLE chain, not just the first cert. The platform's fulcio-roots.pem /
// tsa-chain.pem are multi-cert bundles; loading only the first cert (the old
// cryptoutil.TryParseCertificate behavior) dropped the trust anchor and broke the
// single-file offline `cilock verify --policy-ca-roots/--policy-timestamp-servers`.
func TestParsePEMCerts_LoadsEveryBlock(t *testing.T) {
	root, rootKey := makeCert(t, "TestifySec Platform Root CA", nil, nil)
	inter, _ := makeCert(t, "TestifySec Platform Fulcio CA", root, rootKey)

	// Real bundle order: intermediate first, self-signed root second.
	certs, err := parsePEMCerts(certPEM(t, inter, root))
	require.NoError(t, err)
	require.Len(t, certs, 2, "must parse BOTH certs, not just the first")
	require.Equal(t, "TestifySec Platform Fulcio CA", certs[0].Subject.CommonName)
	require.Equal(t, "TestifySec Platform Root CA", certs[1].Subject.CommonName)
}

func TestParsePEMCerts_SkipsNonCertBlocksAndErrorsWhenEmpty(t *testing.T) {
	// A PEM with only a non-CERTIFICATE block yields a clear error.
	junk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-cert")})
	_, err := parsePEMCerts(junk)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no PEM CERTIFICATE block")

	// A non-cert block PRECEDING a real cert is skipped, not fatal.
	root, _ := makeCert(t, "Root", nil, nil)
	mixed := append(junk, certPEM(t, root)...)
	certs, err := parsePEMCerts(mixed)
	require.NoError(t, err)
	require.Len(t, certs, 1)
}

// TestSplitPEMCertsBySelfSigned proves --policy-ca-roots anchors a full chain
// correctly: the self-signed Root lands in roots (the trust anchor) and the
// Root-issued Fulcio CA lands in intermediates — so a keyless signing leaf
// chains leaf -> Fulcio CA -> Root. Without this split a single-file bundle put
// the intermediate in the roots pool and chain-building failed.
func TestSplitPEMCertsBySelfSigned(t *testing.T) {
	root, rootKey := makeCert(t, "TestifySec Platform Root CA", nil, nil)
	inter, _ := makeCert(t, "TestifySec Platform Fulcio CA", root, rootKey)

	roots, intermediates, err := splitPEMCertsBySelfSigned(certPEM(t, inter, root))
	require.NoError(t, err)
	require.Len(t, roots, 1, "the self-signed Root CA is the only trust anchor")
	require.Equal(t, "TestifySec Platform Root CA", roots[0].Subject.CommonName)
	require.Len(t, intermediates, 1, "the Root-issued Fulcio CA is an intermediate")
	require.Equal(t, "TestifySec Platform Fulcio CA", intermediates[0].Subject.CommonName)
}
