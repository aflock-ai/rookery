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

package policysig

import (
	"bytes"
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/stretchr/testify/require"
)

// TestSecurity_GHSA_mpvw_UnconstrainedX509SignerRefused proves that an X.509
// (keyless) policy signer is NOT trusted on the strength of chaining to a CA
// root alone (GHSA-mpvw-hw8p-7x27).
//
// NewVerifyPolicySignatureOptions defaults to all-wildcard certificate
// constraints, and the verifier only WARNED. A library consumer that configures
// a trust root but no identity constraints (e.g. the policyverify attestor's
// default constructor) therefore accepted ANY certificate the CA issued as a
// policy signer — with a broad root such as public Fulcio, any valid OIDC
// identity. The verifier must refuse to confer policy-signing trust unless the
// caller explicitly opted into identity constraints or Fulcio extensions.
func TestSecurity_GHSA_mpvw_UnconstrainedX509SignerRefused(t *testing.T) {
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)
	leaf, leafKey := klCreateKeylessLeaf(t, inter, interPriv, "https://accounts.google.com", "attacker@evil.example")

	signer, err := cryptoutil.NewSigner(leafKey,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
		cryptoutil.SignWithRoots([]*x509.Certificate{root}),
	)
	require.NoError(t, err)

	fakeTS := timestamp.FakeTimestamper{T: time.Now()}
	env, err := dsse.Sign(
		"application/vnd.test+json",
		bytes.NewReader([]byte(`{"test":"policy"}`)),
		dsse.SignWithSigners(signer),
		dsse.SignWithTimestampers(fakeTS),
	)
	require.NoError(t, err)

	// ONLY the trusted root + TSA are configured — no VerifyWithPolicyCertConstraints,
	// no VerifyWithPolicyFulcioCertExtensions. This is the vulnerable default path.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{fakeTS}),
	)

	err = VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err,
		"an X.509 policy signer must be refused when neither certificate constraints "+
			"nor Fulcio extensions are configured (GHSA-mpvw-hw8p-7x27)")
}

// TestSecurity_GHSA_mpvw_WildcardExtensionIsNotAnOptIn proves that a
// wildcard-only Fulcio extension (e.g. {Issuer: "*"}) does NOT count as opting
// into X.509 policy-signer identity matching: it pins nothing, so an
// unconstrained signer is still refused (GHSA-mpvw-hw8p-7x27 — Codex follow-up).
func TestSecurity_GHSA_mpvw_WildcardExtensionIsNotAnOptIn(t *testing.T) {
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)
	leaf, leafKey := klCreateKeylessLeaf(t, inter, interPriv, "https://accounts.google.com", "attacker@evil.example")

	signer, err := cryptoutil.NewSigner(leafKey,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
		cryptoutil.SignWithRoots([]*x509.Certificate{root}),
	)
	require.NoError(t, err)

	fakeTS := timestamp.FakeTimestamper{T: time.Now()}
	env, err := dsse.Sign("application/vnd.test+json", bytes.NewReader([]byte(`{"test":"policy"}`)),
		dsse.SignWithSigners(signer), dsse.SignWithTimestampers(fakeTS))
	require.NoError(t, err)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{fakeTS}),
		VerifyWithPolicyFulcioCertExtensions(certificate.Extensions{Issuer: "*"}),
	)

	err = VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err,
		"a wildcard-only Fulcio extension must not be treated as an identity opt-in (GHSA-mpvw-hw8p-7x27)")
}

// TestExtensionsPinIdentity unit-tests the opt-in predicate directly.
func TestExtensionsPinIdentity(t *testing.T) {
	none := NewVerifyPolicySignatureOptions()
	require.False(t, extensionsPinIdentity(none), "no extensions configured does not pin identity")

	wildcard := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyFulcioCertExtensions(certificate.Extensions{Issuer: "*"}))
	require.False(t, extensionsPinIdentity(wildcard), "a wildcard-only extension does not pin identity")

	concrete := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyFulcioCertExtensions(certificate.Extensions{Issuer: "https://accounts.google.com"}))
	require.True(t, extensionsPinIdentity(concrete), "a concrete extension value pins identity")
}
