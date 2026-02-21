// Copyright 2023 The Witness Contributors
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

package policysig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- test helpers ---

func createRsaKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, &priv.PublicKey
}

func createTestKey(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	priv, pub := createRsaKey(t)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(pub, crypto.SHA256)
	return signer, verifier
}

func createCert(t *testing.T, priv, pub interface{}, tmpl, parent *x509.Certificate) *x509.Certificate {
	t.Helper()
	var err error
	tmpl.SerialNumber, err = rand.Int(rand.Reader, big.NewInt(4294967295))
	require.NoError(t, err)
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	return cert
}

func createRoot(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := createRsaKey(t)
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"TestifySec"},
			CommonName:   "Test Root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	cert := createCert(t, priv, pub, tmpl, tmpl)
	return cert, priv
}

func createIntermediate(t *testing.T, parent *x509.Certificate, parentPriv interface{}) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := createRsaKey(t)
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"TestifySec"},
			CommonName:   "Test Intermediate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	cert := createCert(t, parentPriv, pub, tmpl, parent)
	return cert, priv
}

func createLeaf(t *testing.T, parent *x509.Certificate, parentPriv interface{}) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := createRsaKey(t)
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"TestifySec"},
			CommonName:   "Test Leaf",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert := createCert(t, parentPriv, pub, tmpl, parent)
	return cert, priv
}

func signEnvelope(t *testing.T, signer cryptoutil.Signer) dsse.Envelope {
	t.Helper()
	env, err := dsse.Sign("dummytype", bytes.NewReader([]byte("test payload")), dsse.SignWithSigners(signer))
	require.NoError(t, err)
	return env
}

// --- NewVerifyPolicySignatureOptions tests ---

func TestNewVerifyPolicySignatureOptions_Defaults(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions()

	assert.Equal(t, "*", vo.policyCommonName, "default common name should be wildcard")
	assert.Equal(t, []string{"*"}, vo.policyDNSNames, "default DNS names should be wildcard")
	assert.Equal(t, []string{"*"}, vo.policyOrganizations, "default organizations should be wildcard")
	assert.Equal(t, []string{"*"}, vo.policyURIs, "default URIs should be wildcard")
	assert.Equal(t, []string{"*"}, vo.policyEmails, "default emails should be wildcard")

	assert.Nil(t, vo.policyVerifiers, "default verifiers should be nil")
	assert.Nil(t, vo.policyTimestampAuthorities, "default timestamp authorities should be nil")
	assert.Nil(t, vo.policyCARoots, "default CA roots should be nil")
	assert.Nil(t, vo.policyCAIntermediates, "default CA intermediates should be nil")
	assert.Equal(t, certificate.Extensions{}, vo.fulcioCertExtensions, "default fulcio extensions should be zero value")
}

func TestNewVerifyPolicySignatureOptions_WithOptions(t *testing.T) {
	_, verifier := createTestKey(t)

	roots := []*x509.Certificate{{Raw: []byte("root")}}
	intermediates := []*x509.Certificate{{Raw: []byte("intermediate")}}

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
		VerifyWithPolicyCARoots(roots),
		VerifyWithPolicyCAIntermediates(intermediates),
		VerifyWithPolicyCertConstraints("my-cn", []string{"dns1"}, []string{"e@x.com"}, []string{"org1"}, []string{"https://x"}),
	)

	assert.Len(t, vo.policyVerifiers, 1)
	assert.Equal(t, roots, vo.policyCARoots)
	assert.Equal(t, intermediates, vo.policyCAIntermediates)
	assert.Equal(t, "my-cn", vo.policyCommonName)
	assert.Equal(t, []string{"dns1"}, vo.policyDNSNames)
	assert.Equal(t, []string{"e@x.com"}, vo.policyEmails)
	assert.Equal(t, []string{"org1"}, vo.policyOrganizations)
	assert.Equal(t, []string{"https://x"}, vo.policyURIs)
}

// --- Individual option function tests ---

func TestVerifyWithPolicyVerifiers_Appends(t *testing.T) {
	_, v1 := createTestKey(t)
	_, v2 := createTestKey(t)
	_, v3 := createTestKey(t)

	// Verify that the option appends, not replaces
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{v1}),
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{v2, v3}),
	)

	assert.Len(t, vo.policyVerifiers, 3, "VerifyWithPolicyVerifiers should append verifiers")
}

func TestVerifyWithPolicyTimestampAuthorities_Sets(t *testing.T) {
	authorities := []timestamp.TimestampVerifier{
		timestamp.FakeTimestamper{T: time.Now()},
	}
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyTimestampAuthorities(authorities),
	)
	assert.Len(t, vo.policyTimestampAuthorities, 1)
}

func TestVerifyWithPolicyCARoots_Sets(t *testing.T) {
	root, _ := createRoot(t)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
	)
	assert.Len(t, vo.policyCARoots, 1)
	assert.Equal(t, root, vo.policyCARoots[0])
}

func TestVerifyWithPolicyCAIntermediates_Sets(t *testing.T) {
	root, rootPriv := createRoot(t)
	inter, _ := createIntermediate(t, root, rootPriv)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
	)
	assert.Len(t, vo.policyCAIntermediates, 1)
	assert.Equal(t, inter, vo.policyCAIntermediates[0])
}

func TestVerifyWithPolicyFulcioCertExtensions_Sets(t *testing.T) {
	ext := certificate.Extensions{
		Issuer: "https://accounts.google.com",
	}
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyFulcioCertExtensions(ext),
	)
	assert.Equal(t, ext, vo.fulcioCertExtensions)
}

func TestVerifyWithPolicyCertConstraints_OverridesDefaults(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCertConstraints(
			"my-cn",
			[]string{"dns1.example.com", "dns2.example.com"},
			[]string{"user@example.com"},
			[]string{"MyOrg"},
			[]string{"https://example.com"},
		),
	)

	assert.Equal(t, "my-cn", vo.policyCommonName)
	assert.Equal(t, []string{"dns1.example.com", "dns2.example.com"}, vo.policyDNSNames)
	assert.Equal(t, []string{"user@example.com"}, vo.policyEmails)
	assert.Equal(t, []string{"MyOrg"}, vo.policyOrganizations)
	assert.Equal(t, []string{"https://example.com"}, vo.policyURIs)
}

func TestVerifyWithPolicyCertConstraints_EmptyValues(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCertConstraints("", nil, nil, nil, nil),
	)
	assert.Equal(t, "", vo.policyCommonName)
	assert.Nil(t, vo.policyDNSNames)
	assert.Nil(t, vo.policyEmails)
	assert.Nil(t, vo.policyOrganizations)
	assert.Nil(t, vo.policyURIs)
}

// --- Options ordering tests ---

func TestOptionsAppliedInOrder(t *testing.T) {
	// CertConstraints set, then overridden by a second call
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCertConstraints("first-cn", []string{"first-dns"}, []string{"first@e.com"}, []string{"first-org"}, []string{"first-uri"}),
		VerifyWithPolicyCertConstraints("second-cn", []string{"second-dns"}, []string{"second@e.com"}, []string{"second-org"}, []string{"second-uri"}),
	)
	assert.Equal(t, "second-cn", vo.policyCommonName, "later option should win")
	assert.Equal(t, []string{"second-dns"}, vo.policyDNSNames)
}

func TestTimestampAuthorities_ReplaceNotAppend(t *testing.T) {
	a1 := []timestamp.TimestampVerifier{timestamp.FakeTimestamper{T: time.Now()}}
	a2 := []timestamp.TimestampVerifier{
		timestamp.FakeTimestamper{T: time.Now().Add(time.Hour)},
		timestamp.FakeTimestamper{T: time.Now().Add(2 * time.Hour)},
	}

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyTimestampAuthorities(a1),
		VerifyWithPolicyTimestampAuthorities(a2),
	)
	assert.Len(t, vo.policyTimestampAuthorities, 2, "second call should replace, not append")
}

func TestCARoots_ReplaceNotAppend(t *testing.T) {
	r1, _ := createRoot(t)
	r2, _ := createRoot(t)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{r1}),
		VerifyWithPolicyCARoots([]*x509.Certificate{r2}),
	)
	assert.Len(t, vo.policyCARoots, 1, "second call should replace, not append")
	assert.Equal(t, r2, vo.policyCARoots[0])
}

// --- VerifyPolicySignature tests ---

func TestVerifyPolicySignature_NoVerifiers_ReturnsError(t *testing.T) {
	signer, _ := createTestKey(t)
	env := signEnvelope(t, signer)
	vo := NewVerifyPolicySignatureOptions()
	// No verifiers set, so envelope.Verify should fail with ErrNoMatchingSigs
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not verify policy")
}

func TestVerifyPolicySignature_NoSignatures_ReturnsError(t *testing.T) {
	env := dsse.Envelope{
		Payload:     []byte("payload"),
		PayloadType: "type",
		Signatures:  []dsse.Signature{},
	}
	_, verifier := createTestKey(t)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not verify policy")
}

func TestVerifyPolicySignature_WrongVerifier_ReturnsError(t *testing.T) {
	signer, _ := createTestKey(t)
	_, wrongVerifier := createTestKey(t)
	env := signEnvelope(t, signer)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{wrongVerifier}),
	)
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not verify policy")
}

func TestVerifyPolicySignature_KeyVerifier_Success(t *testing.T) {
	signer, verifier := createTestKey(t)
	env := signEnvelope(t, signer)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.NoError(t, err)
}

func TestVerifyPolicySignature_MultipleVerifiers_OneMatches(t *testing.T) {
	signer, verifier := createTestKey(t)
	_, wrongVerifier1 := createTestKey(t)
	_, wrongVerifier2 := createTestKey(t)

	env := signEnvelope(t, signer)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{wrongVerifier1, verifier, wrongVerifier2}),
	)

	// Envelope.Verify returns all that matched + the correct one.
	// In this case, envelope.Verify will check each verifier against each signature.
	// Only the correct verifier should pass and CheckedVerifier will be returned for it.
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.NoError(t, err)
}

func TestVerifyPolicySignature_MultipleVerifiers_NoneMatch(t *testing.T) {
	signer, _ := createTestKey(t)
	_, wrong1 := createTestKey(t)
	_, wrong2 := createTestKey(t)

	env := signEnvelope(t, signer)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{wrong1, wrong2}),
	)
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not verify policy")
}

func TestVerifyPolicySignature_X509Verifier_Success(t *testing.T) {
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)
	leaf, leafPriv := createLeaf(t, inter, interPriv)

	signer, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf), cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}), cryptoutil.SignWithRoots([]*x509.Certificate{root}))
	require.NoError(t, err)

	env := signEnvelope(t, signer)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
	)

	err = VerifyPolicySignature(context.Background(), env, vo)
	require.NoError(t, err)
}

func TestVerifyPolicySignature_X509Verifier_WrongRoot_Fails(t *testing.T) {
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)
	leaf, leafPriv := createLeaf(t, inter, interPriv)

	signer, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf), cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}), cryptoutil.SignWithRoots([]*x509.Certificate{root}))
	require.NoError(t, err)

	env := signEnvelope(t, signer)

	// Create a different root that didn't sign the chain
	wrongRoot, _ := createRoot(t)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{wrongRoot}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
	)

	// The envelope embeds the signing cert, and dsse.Verify will try to build
	// a chain using the provided roots. With the wrong root, verification
	// in the dsse.Envelope.Verify will fail, resulting in no passing verifiers.
	err = VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err)
}

func TestVerifyPolicySignature_X509Verifier_WithTimestamps(t *testing.T) {
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)
	leaf, leafPriv := createLeaf(t, inter, interPriv)

	signer, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf), cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}), cryptoutil.SignWithRoots([]*x509.Certificate{root}))
	require.NoError(t, err)

	fakeTS := timestamp.FakeTimestamper{T: time.Now()}

	env, err := dsse.Sign("dummytype", bytes.NewReader([]byte("test payload")), dsse.SignWithSigners(signer), dsse.SignWithTimestampers(fakeTS))
	require.NoError(t, err)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{fakeTS}),
	)

	err = VerifyPolicySignature(context.Background(), env, vo)
	require.NoError(t, err)
}

func TestVerifyPolicySignature_ContextCancelled(t *testing.T) {
	// VerifyPolicySignature accepts a context but the current implementation doesn't
	// check it. This test verifies the function doesn't panic with a cancelled context.
	signer, verifier := createTestKey(t)
	env := signEnvelope(t, signer)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should still succeed because the code doesn't check ctx
	err := VerifyPolicySignature(ctx, env, vo)
	require.NoError(t, err)
}

func TestVerifyPolicySignature_EmptyPayload(t *testing.T) {
	// Sign an envelope with an empty payload
	signer, verifier := createTestKey(t)
	env, err := dsse.Sign("emptytype", bytes.NewReader([]byte("")), dsse.SignWithSigners(signer))
	require.NoError(t, err)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)
	err = VerifyPolicySignature(context.Background(), env, vo)
	require.NoError(t, err)
}

func TestNewVerifyPolicySignatureOptions_NoOptions(t *testing.T) {
	// No options at all — should still return a valid object with defaults
	vo := NewVerifyPolicySignatureOptions()
	require.NotNil(t, vo)
	assert.Equal(t, "*", vo.policyCommonName)
	assert.Equal(t, []string{"*"}, vo.policyDNSNames)
}

func TestVerifyWithPolicyVerifiers_EmptySlice(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{}),
	)
	assert.Empty(t, vo.policyVerifiers)
}

func TestVerifyWithPolicyCARoots_EmptySlice(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{}),
	)
	assert.Empty(t, vo.policyCARoots)
}

func TestVerifyWithPolicyCAIntermediates_EmptySlice(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{}),
	)
	assert.Empty(t, vo.policyCAIntermediates)
}

func TestVerifyWithPolicyTimestampAuthorities_EmptySlice(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{}),
	)
	assert.Empty(t, vo.policyTimestampAuthorities)
}

func TestVerifyWithPolicyFulcioCertExtensions_ZeroValue(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyFulcioCertExtensions(certificate.Extensions{}),
	)
	assert.Equal(t, certificate.Extensions{}, vo.fulcioCertExtensions)
}

func TestVerifyPolicySignature_MutatedEnvelope_Fails(t *testing.T) {
	signer, verifier := createTestKey(t)
	env := signEnvelope(t, signer)

	// Mutate the payload after signing
	env.Payload = []byte("tampered payload")

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not verify policy")
}
