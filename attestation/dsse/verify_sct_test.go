// jade:ring local
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

package dsse

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// #10032, end to end through Envelope.Verify.

func sctTestChain(t *testing.T, leafExt ...pkix.Extension) (root *x509.Certificate, env Envelope) {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "sct dsse root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(10 * time.Minute),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		ExtraExtensions: leafExt,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	signer, err := cryptoutil.NewSigner(leafKey, cryptoutil.SignWithCertificate(leaf))
	require.NoError(t, err)
	env, err = Sign("test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
	require.NoError(t, err)
	return root, env
}

// The issue's differential vector: a leaf embedding an SCT list no trusted log
// signed, chaining to a trusted root, used to verify.
func TestVerify_SCT_UnverifiableEmbeddedSCTListRefused(t *testing.T) {
	junk := make([]byte, 120)
	_, err := rand.Read(junk)
	require.NoError(t, err)
	list := append([]byte{0, 124, 0, 120}, junk...)
	value, err := asn1.Marshal(list)
	require.NoError(t, err)
	sctExt := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}, Value: value}

	root, env := sctTestChain(t, sctExt)
	_, err = env.Verify(VerifyWithRoots(root), VerifyWithCurrentTimeFallback())
	require.Error(t, err)
	var noMatch ErrNoMatchingSigs
	require.ErrorAs(t, err, &noMatch)
	require.NotEmpty(t, noMatch.Verifiers)
	require.ErrorIs(t, noMatch.Verifiers[0].Error, cryptoutil.ErrSCTVerification)
}

// A CA declared CT-logging through VerifyWithCTTrustRoots must present an SCT;
// the same envelope without that declaration (a CA that does not log, like the
// platform Fulcio) verifies.
func TestVerify_SCT_CTTrustRootRequiresSCT(t *testing.T) {
	root, env := sctTestChain(t)
	require.NoError(t, func() error {
		_, err := env.Verify(VerifyWithRoots(root), VerifyWithCurrentTimeFallback())
		return err
	}())

	logKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	log, err := cryptoutil.NewCTLog("https://ct.test", &logKey.PublicKey, time.Time{}, time.Time{})
	require.NoError(t, err)
	ctRoot := cryptoutil.CTTrustRoot{Name: "sct dsse", CAs: []*x509.Certificate{root}, Logs: []cryptoutil.CTLog{log}}
	_, err = env.Verify(VerifyWithRoots(root), VerifyWithCurrentTimeFallback(), VerifyWithCTTrustRoots(ctRoot))
	var noMatch ErrNoMatchingSigs
	require.ErrorAs(t, err, &noMatch)
	require.ErrorIs(t, noMatch.Verifiers[0].Error, cryptoutil.ErrSCTVerification)
}
