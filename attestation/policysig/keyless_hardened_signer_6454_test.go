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

// #6454 flip support: the cilock CLI now ENFORCES the #6266 hardening flags by
// default, including R3_181 (an empty SAN-list constraint matched against an
// empty cert field fails closed). On the policy-SIGNER path an empty
// --policy-* list has always meant "unconstrained" — the release-fanout shape
// is `--policy-emails <author>` with dns/org/uris left at their empty defaults
// against an email-identity Fulcio cert that carries none of them. These tests
// prove that, with EVERY hardening flag enforced:
//
//   - a genuinely-pinned keyless signer still verifies (the empty lists relax
//     to AllowAll only where the cert field is absent), and
//   - nothing-pinned and empty-list-vs-present-value cases still fail closed.
//
// They mutate the policy package's process-global hardening options, so none
// of them may call t.Parallel().

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/require"
)

// withFullEnforcement installs every #6266 hardening flag for the duration of
// the test — the exact process-wide state the cilock CLI now sets at startup.
func withFullEnforcement(t *testing.T) {
	t.Helper()
	prev := policy.Hardening()
	policy.SetHardening(policy.HardeningOptions{
		EnforceCertConstraintOnKeyIDMatch: true,
		RejectEmptyConstraintEmptyField:   true,
		RejectDuplicateRegoPackage:        true,
		EnforceStepNameCoherence:          true,
	})
	t.Cleanup(func() { policy.SetHardening(prev) })
}

// signEmailIdentityEnv mints a keyless email-identity leaf: empty subject,
// SAN email ONLY (no URI SAN — the platform-Fulcio human-author cert shape the
// release fan-out verifies the signed release policy against).
func signEmailIdentityEnv(t *testing.T, signerEmail string) (dsse.Envelope, []Option) {
	t.Helper()
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{},
		EmailAddresses:        []string{signerEmail},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	tmpl.SerialNumber, err = rand.Int(rand.Reader, big.NewInt(4294967295))
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &priv.PublicKey, interPriv)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	signer, err := cryptoutil.NewSigner(priv,
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

	return env, []Option{
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{fakeTS}),
	}
}

// The release-fanout shape, bit for bit: --policy-emails <author> against an
// email-identity cert, every other SAN list at its empty default. Must verify
// under full enforcement — the empty dns/org/uris constraints relax to
// AllowAll because the cert carries none of those fields and the email pins.
func TestHardenedSigner_EmailIdentityCert_EmailPin_Accepts(t *testing.T) {
	withFullEnforcement(t)
	const signerEmail = "colek42@gmail.com"
	env, trustOpts := signEmailIdentityEnv(t, signerEmail)

	opts := append([]Option{}, trustOpts...)
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, []string{signerEmail}, nil, nil))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.NoError(t, err,
		"an email-pinned keyless policy signer must still verify with every #6266 "+
			"hardening flag enforced: empty SAN lists relax only where the cert field is absent")
}

// The workflow-identity shape: email + URI SANs on the cert, email + URI
// pinned, dns/org left empty. Must verify under full enforcement.
func TestHardenedSigner_EmailAndURIPin_Accepts(t *testing.T) {
	withFullEnforcement(t)
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, []string{signerEmail}, nil, []string{issuerURI}))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.NoError(t, err)
}

// Anti-weakening proof: the relaxation must NOT soften the "empty list forbids
// all present values" rule. The cert PRESENTS a URI SAN; the uris constraint
// is empty; the signer is email-pinned. Rejected before #6266, rejected now.
func TestHardenedSigner_EmptyURIConstraintPresentURISAN_StillForbids(t *testing.T) {
	withFullEnforcement(t)
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, []string{signerEmail}, nil, nil))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.Error(t, err,
		"an empty uris constraint must keep forbidding a cert that PRESENTS a URI SAN; "+
			"the signer-path relaxation applies only when the cert field is absent")
}

// Anti-bypass proof (GHSA-mpvw-hw8p-7x27): with NOTHING concretely pinned the
// relaxation must not fire, and the verification must keep failing closed
// under full enforcement.
func TestHardenedSigner_NothingPinned_StillFailsClosed(t *testing.T) {
	withFullEnforcement(t)
	env, trustOpts, _ := signKeylessEnv(t, "https://issuer.example.com", "author@example.com")

	opts := append([]Option{}, trustOpts...)
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, nil, nil, nil))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.Error(t, err,
		"a keyless signer with no concrete identity pin must fail closed under enforcement")
}
