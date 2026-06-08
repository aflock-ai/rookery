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
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	rtimestamp "github.com/aflock-ai/rookery/attestation/timestamp"
	digitimestamp "github.com/digitorus/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tsaCN = "TestifySec Platform TSA"

// buildTSALeaf builds a TSA signing leaf (with the time-stamping EKU) issued by
// parent. The TSA token is signed by this leaf; the leaf travels embedded in
// the token so the verifier (and our diagnostic) can see the TSA's chain.
func buildTSALeaf(t *testing.T, parent *x509.Certificate, parentPriv interface{}) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub, err := createRsaKey()
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "tsa-signer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
	}
	cert, err := createCert(parentPriv, pub, tmpl, parent)
	require.NoError(t, err)
	return cert, priv
}

// makeTSPToken produces a real RFC 3161 timestamp response over signedData,
// signed by tsaLeaf/tsaPriv, with the full TSA chain (leaf + root) embedded so
// the diagnostic can inspect it.
func makeTSPToken(t *testing.T, signedData []byte, tsaLeaf, tsaRoot *x509.Certificate, tsaPriv *rsa.PrivateKey) []byte {
	t.Helper()
	digest := sha256.Sum256(signedData)
	ts := digitimestamp.Timestamp{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: digest[:],
		Time:          time.Now(),
		// A non-empty TSA policy OID is required; an empty asn1.ObjectIdentifier
		// marshals to "invalid object identifier".
		Policy: asn1.ObjectIdentifier{2, 5, 29, 32, 0},
		// Certificates is the PARENT chain for AddSignerChain (root only); the
		// leaf is supplied separately as the signing cert. AddTSACertificate
		// embeds the full chain (leaf + root) into the token.
		Certificates:      []*x509.Certificate{tsaRoot},
		AddTSACertificate: true,
	}
	resp, err := ts.CreateResponseWithOpts(tsaLeaf, tsaPriv, crypto.SHA256)
	require.NoError(t, err)
	// TSPVerifier.Verify and TokenCertificates both expect the bare
	// TimeStampToken, not the full TSP response envelope. Extract RawToken,
	// matching what TSPTimestamper.Timestamp returns in production.
	parsed, err := digitimestamp.ParseResponse(resp)
	require.NoError(t, err)
	return parsed.RawToken
}

// TestEnvelopeVerify_TSATrustMismatch_StillFailsAndDiagnoses builds an artifact
// whose Fulcio chain DOES verify against the policy roots, but whose timestamp
// was produced by a TSA sharing the policy TSA's CN with a different key. The
// verify must still fail (no valid timestamp) AND surface the TSA-variant
// TRUST MISMATCH block at the top-level error.
func TestEnvelopeVerify_TSATrustMismatch_StillFailsAndDiagnoses(t *testing.T) {
	// Fulcio side: sign and verify against the SAME, correct root so the
	// signing chain is not the cause of failure — only the TSA mismatch is.
	fulcioRoot, fulcioRootPriv := buildCA(t, "Fulcio Root")
	inter, interPriv := buildIntermediate(t, "Fulcio Inter", fulcioRoot, fulcioRootPriv)
	leaf, leafPriv := buildLeaf(t, inter, interPriv)
	signer, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
	)
	require.NoError(t, err)
	env, err := Sign("application/vnd.test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
	require.NoError(t, err)
	require.Len(t, env.Signatures, 1)

	// TSA side: produce the token under TSA-A (the "signing platform" TSA).
	tsaRootA, tsaRootAPriv := buildCA(t, tsaCN)
	tsaLeafA, tsaPrivA := buildTSALeaf(t, tsaRootA, tsaRootAPriv)
	token := makeTSPToken(t, env.Signatures[0].Signature, tsaLeafA, tsaRootA, tsaPrivA)
	env.Signatures[0].Timestamps = []SignatureTimestamp{{Type: TimestampRFC3161, Data: token}}

	// Policy trusts TSA-B: SAME CN as TSA-A, DIFFERENT key.
	tsaRootB, _ := buildCA(t, tsaCN)
	tsv := rtimestamp.NewVerifier(rtimestamp.VerifyWithCerts([]*x509.Certificate{tsaRootB}))

	_, verr := env.Verify(
		VerifyWithRoots(fulcioRoot),
		VerifyWithIntermediates(inter),
		VerifyWithTimestampVerifiers(tsv),
	)
	// (a) semantics unchanged: it MUST still fail (the timestamp can't verify).
	require.Error(t, verr, "a timestamp from the wrong TSA platform must still fail verify")

	// (b) the typed diagnostic is reachable and flagged as the timestamp path.
	var tm *TrustNameKeyMismatchError
	require.True(t, errors.As(verr, &tm), "TSA TrustNameKeyMismatchError must be reachable via errors.As; got: %v", verr)
	assert.True(t, tm.IsTimestamp, "the mismatch must be flagged as a timestamp-path mismatch")
	assert.Equal(t, tsaCN, tm.CommonName)
	assert.NotEqual(t, tm.ArtifactKeyID, tm.PolicyKeyID)

	// (c) rendered top-level error carries the TSA wording + both fingerprints.
	msg := verr.Error()
	assert.Contains(t, msg, "TRUST MISMATCH")
	assert.Contains(t, msg, "the timestamp was produced by a different platform")
	assert.Contains(t, msg, "key="+tm.ArtifactKeyID)
	assert.Contains(t, msg, "key="+tm.PolicyKeyID)
}

// TestEnvelopeVerify_TSAUnrelated_NoTrustMismatch verifies that a TSA with an
// entirely different CN produces the normal failure, not a TRUST MISMATCH.
func TestEnvelopeVerify_TSAUnrelated_NoTrustMismatch(t *testing.T) {
	fulcioRoot, fulcioRootPriv := buildCA(t, "Fulcio Root")
	inter, interPriv := buildIntermediate(t, "Fulcio Inter", fulcioRoot, fulcioRootPriv)
	leaf, leafPriv := buildLeaf(t, inter, interPriv)
	signer, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
	)
	require.NoError(t, err)
	env, err := Sign("application/vnd.test", bytes.NewReader([]byte("payload")), SignWithSigners(signer))
	require.NoError(t, err)

	tsaRootA, tsaRootAPriv := buildCA(t, "Acme TSA Root")
	tsaLeafA, tsaPrivA := buildTSALeaf(t, tsaRootA, tsaRootAPriv)
	token := makeTSPToken(t, env.Signatures[0].Signature, tsaLeafA, tsaRootA, tsaPrivA)
	env.Signatures[0].Timestamps = []SignatureTimestamp{{Type: TimestampRFC3161, Data: token}}

	// Policy trusts a TSA with a DIFFERENT CN.
	tsaRootB, _ := buildCA(t, "Globex TSA Root")
	tsv := rtimestamp.NewVerifier(rtimestamp.VerifyWithCerts([]*x509.Certificate{tsaRootB}))

	_, verr := env.Verify(VerifyWithRoots(fulcioRoot), VerifyWithIntermediates(inter), VerifyWithTimestampVerifiers(tsv))
	require.Error(t, verr)

	var tm *TrustNameKeyMismatchError
	assert.False(t, errors.As(verr, &tm), "unrelated TSA CN must NOT fire TRUST MISMATCH")
	assert.NotContains(t, verr.Error(), "TRUST MISMATCH")
}
