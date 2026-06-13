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

package dsse

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rootCN is the shared Subject CN used by both the prod-like and staging-like
// CAs in these tests. It mirrors the real "TestifySec Platform Root CA"
// collision that motivated the diagnostic.
const (
	rootCN         = "TestifySec Platform Root CA"
	intermediateCN = "TestifySec Platform Fulcio CA"
)

// buildCA returns a self-signed CA root with the given CommonName. Two calls
// with the same CN produce two CAs that share a Subject CN but carry different
// keys — exactly the "same name, different key" condition the diagnostic fires
// on. The returned cert's SubjectKeyId is auto-derived by crypto/x509 from the
// (distinct) public key, so the two CAs have distinct key fingerprints.
func buildCA(t *testing.T, cn string) (*x509.Certificate, interface{}) {
	t.Helper()
	priv, pub, err := createRsaKey()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"TestifySec"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}
	cert, err := createCert(priv, pub, tmpl, tmpl)
	require.NoError(t, err)
	return cert, priv
}

// buildIntermediate returns a CA intermediate with the given CN, signed by parent.
func buildIntermediate(t *testing.T, cn string, parent *x509.Certificate, parentPriv interface{}) (*x509.Certificate, interface{}) {
	t.Helper()
	priv, pub, err := createRsaKey()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"TestifySec"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	cert, err := createCert(parentPriv, pub, tmpl, parent)
	require.NoError(t, err)
	return cert, priv
}

// buildLeaf returns a non-CA signing leaf signed by parent.
func buildLeaf(t *testing.T, parent *x509.Certificate, parentPriv interface{}) (*x509.Certificate, interface{}) {
	t.Helper()
	priv, pub, err := createRsaKey()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}
	cert, err := createCert(parentPriv, pub, tmpl, parent)
	require.NoError(t, err)
	return cert, priv
}

// --- Unit tests for the pure detection function -----------------------------

func TestDetectTrustNameKeyMismatch_FiresOnSameCNDifferentKey(t *testing.T) {
	rootA, _ := buildCA(t, rootCN)
	rootB, _ := buildCA(t, rootCN) // same CN, different key

	got := detectTrustNameKeyMismatch([]*x509.Certificate{rootA}, []*x509.Certificate{rootB}, false)
	require.NotNil(t, got, "same CN + different key must fire")
	assert.Equal(t, rootCN, got.CommonName)
	assert.Equal(t, certKeyFingerprint(rootA), got.ArtifactKeyID)
	assert.Equal(t, certKeyFingerprint(rootB), got.PolicyKeyID)
	assert.NotEqual(t, got.ArtifactKeyID, got.PolicyKeyID)
}

func TestDetectTrustNameKeyMismatch_SilentOnDifferentCN(t *testing.T) {
	rootA, _ := buildCA(t, "Acme Root CA")
	rootB, _ := buildCA(t, "TestifySec Platform Root CA")

	got := detectTrustNameKeyMismatch([]*x509.Certificate{rootA}, []*x509.Certificate{rootB}, false)
	assert.Nil(t, got, "different CN must NOT fire — that is the unknown-authority case")
}

func TestDetectTrustNameKeyMismatch_SilentOnSameKey(t *testing.T) {
	rootA, _ := buildCA(t, rootCN)
	got := detectTrustNameKeyMismatch([]*x509.Certificate{rootA}, []*x509.Certificate{rootA}, false)
	assert.Nil(t, got, "same CN AND same key is a legitimate match, not a mismatch")
}

func TestDetectTrustNameKeyMismatch_IgnoresLeaves(t *testing.T) {
	rootA, privA := buildCA(t, rootCN)
	leaf, _ := buildLeaf(t, rootA, privA)
	rootB, _ := buildCA(t, rootCN)
	// Leaf CN is "leaf"; it must never be treated as a CA for the diagnostic.
	got := detectTrustNameKeyMismatch([]*x509.Certificate{leaf}, []*x509.Certificate{rootB}, false)
	assert.Nil(t, got, "a non-CA leaf must not trigger the CA trust diagnostic")
}

func TestTrustNameKeyMismatchError_RenderingFulcio(t *testing.T) {
	e := TrustNameKeyMismatchError{CommonName: rootCN, ArtifactKeyID: "aaaa1111", PolicyKeyID: "bbbb2222"}
	msg := e.Error()
	assert.Contains(t, msg, "TRUST MISMATCH")
	assert.Contains(t, msg, `artifact signed by : "TestifySec Platform Root CA"  key=aaaa1111`)
	assert.Contains(t, msg, `policy trusts      : "TestifySec Platform Root CA"  key=bbbb2222`)
	assert.Contains(t, msg, "this artifact was signed against a DIFFERENT platform")
	assert.Contains(t, msg, "judge-configuration")
}

func TestTrustNameKeyMismatchError_RenderingTimestamp(t *testing.T) {
	e := TrustNameKeyMismatchError{CommonName: rootCN, ArtifactKeyID: "aaaa1111", PolicyKeyID: "bbbb2222", IsTimestamp: true}
	msg := e.Error()
	assert.Contains(t, msg, "TRUST MISMATCH")
	assert.Contains(t, msg, "the timestamp was produced by a different platform")
	assert.NotContains(t, msg, "this artifact was signed against a DIFFERENT platform")
}

// --- End-to-end through Envelope.Verify (Fulcio path) -----------------------

// signEnvelopeUnderCA signs a DSSE envelope with a leaf issued by an
// intermediate under rootA, embedding the intermediate and root in the
// signature so the artifact's full issuer chain travels with it (as Fulcio
// keyless signing does).
func signEnvelopeUnderCA(t *testing.T, rootA *x509.Certificate, rootAPriv interface{}) (Envelope, *x509.Certificate, interface{}) {
	t.Helper()
	inter, interPriv := buildIntermediate(t, intermediateCN, rootA, rootAPriv)
	leaf, leafPriv := buildLeaf(t, inter, interPriv)
	signer, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter, rootA}),
	)
	require.NoError(t, err)
	env, err := Sign("application/vnd.test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
	require.NoError(t, err)
	return env, inter, interPriv
}

func TestEnvelopeVerify_FulcioTrustMismatch_StillFailsAndDiagnoses(t *testing.T) {
	rootA, rootAPriv := buildCA(t, rootCN) // signing platform (e.g. prod)
	rootB, rootBPriv := buildCA(t, rootCN) // policy-trusted platform (e.g. staging), same CN
	interB, _ := buildIntermediate(t, intermediateCN, rootB, rootBPriv)

	env, _, _ := signEnvelopeUnderCA(t, rootA, rootAPriv)

	// Verify against the WRONG platform's roots/intermediates (same CNs, diff keys).
	_, err := env.Verify(
		VerifyWithRoots(rootB),
		VerifyWithIntermediates(interB),
	)
	// (a) semantics unchanged: it MUST still fail.
	require.Error(t, err, "verification against the wrong platform must still fail")

	// (b) the typed diagnostic must be retrievable via errors.As.
	var tm *TrustNameKeyMismatchError
	require.True(t, errors.As(err, &tm), "TrustNameKeyMismatchError must be reachable via errors.As; got: %v", err)
	// The first shared-CN CA walking the artifact chain is the Fulcio
	// intermediate (the real-world collision: "TestifySec Platform Fulcio CA"
	// embedded in the signature vs the staging intermediate the policy trusts).
	assert.Contains(t, []string{rootCN, intermediateCN}, tm.CommonName)
	assert.False(t, tm.IsTimestamp)

	// (c) the rendered top-level error string contains the block + both fingerprints.
	msg := err.Error()
	assert.Contains(t, msg, "TRUST MISMATCH")
	assert.Contains(t, msg, "key="+tm.ArtifactKeyID)
	assert.Contains(t, msg, "key="+tm.PolicyKeyID)
	assert.NotEqual(t, tm.ArtifactKeyID, tm.PolicyKeyID)
}

func TestEnvelopeVerify_UnrelatedCA_NoTrustMismatch(t *testing.T) {
	rootA, rootAPriv := buildCA(t, rootCN)
	rootB, rootBPriv := buildCA(t, "Totally Different Root CA") // different CN
	interB, _ := buildIntermediate(t, "Totally Different Fulcio CA", rootB, rootBPriv)

	env, _, _ := signEnvelopeUnderCA(t, rootA, rootAPriv)

	_, err := env.Verify(VerifyWithRoots(rootB), VerifyWithIntermediates(interB))
	require.Error(t, err, "unrelated CA must still fail verification")

	var tm *TrustNameKeyMismatchError
	assert.False(t, errors.As(err, &tm), "an unrelated CA must NOT produce a TRUST MISMATCH")
	assert.NotContains(t, err.Error(), "TRUST MISMATCH")
}

func TestEnvelopeVerify_CorrectPlatform_PassesWithNoHint(t *testing.T) {
	rootA, rootAPriv := buildCA(t, rootCN)
	inter, interPriv := buildIntermediate(t, intermediateCN, rootA, rootAPriv)
	leaf, leafPriv := buildLeaf(t, inter, interPriv)
	signer, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
	)
	require.NoError(t, err)
	env, err := Sign("application/vnd.test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
	require.NoError(t, err)

	// Verify against the CORRECT platform's root + intermediate: must pass clean.
	// This test exercises cert-chain trust mechanics, not timestamp policy, so it
	// opts into the current-time fallback (the envelope carries no RFC3161
	// timestamp). Without the opt-in the cert path now fails closed (#5237).
	checked, err := env.Verify(VerifyWithRoots(rootA), VerifyWithIntermediates(inter), VerifyWithCurrentTimeFallback())
	require.NoError(t, err, "correct-platform verify must succeed")

	var tm *TrustNameKeyMismatchError
	assert.False(t, errors.As(err, &tm))
	for _, cv := range checked {
		assert.NoError(t, cv.Error, "no verifier error on a clean verify")
	}
}
