// Copyright 2026 The Witness Contributors
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

// NOTE: This file is intentionally NOT behind the `audit` build tag. The
// adversarial/table DSSE suites (dsse_adversarial_test.go, dsse_table_test.go,
// verify_security_test.go) are `//go:build audit` and are NOT run by the
// default `go test ./...` (nor by `jade test --go` or rookery's own CI
// `_test-go.yml`). The #5237 fail-closed guarantee is security-critical, so its
// regression test must run in the DEFAULT suite where CI actually executes it.
// It carries its own self-contained cert-chain helper for that reason.

package dsse

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failClosedCertChain mints a self-contained leaf->root cert chain whose
// validity window is [validFrom, validFrom+validity). When validFrom straddles
// "now", a wall-clock (time.Now()) validity check WOULD succeed — which is
// exactly the substitution the #5237 fail-closed change must refuse when no
// trusted timestamp is supplied.
func failClosedCertChain(t *testing.T, validFrom time.Time, validity time.Duration) (root, leaf *x509.Certificate, leafPriv *rsa.PrivateKey) {
	t.Helper()

	rootPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "FailClosed Test Root"},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(validity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootTmpl.SerialNumber, err = rand.Int(rand.Reader, big.NewInt(1<<32))
	require.NoError(t, err)
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootPriv.PublicKey, rootPriv)
	require.NoError(t, err)
	root, err = x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafPriv, err = rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "FailClosed Test Leaf"},
		NotBefore:             validFrom,
		NotAfter:              validFrom.Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	leafTmpl.SerialNumber, err = rand.Int(rand.Reader, big.NewInt(1<<32))
	require.NoError(t, err)
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafPriv.PublicKey, rootPriv)
	require.NoError(t, err)
	leaf, err = x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return root, leaf, leafPriv
}

// signCertEnvelopeForFailClosed signs a payload with a freshly minted, CURRENTLY
// VALID cert chain and returns the envelope plus the trust root.
func signCertEnvelopeForFailClosed(t *testing.T) (env Envelope, root *x509.Certificate) {
	t.Helper()
	now := time.Now()
	root, leaf, leafPriv := failClosedCertChain(t, now.Add(-1*time.Hour), 24*time.Hour)

	s, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
	require.NoError(t, err)

	env, err = Sign("test", bytes.NewReader([]byte("fail-closed-payload")), SignWithSigners(s))
	require.NoError(t, err)

	return env, root
}

// TestVerify_CertWithoutTimestamp_FailsClosed is the core regression for #5237.
//
// A cert-based (Fulcio/keyless-style) signature, verified against trusted roots
// but WITHOUT any RFC3161 timestamp verifier, must NOT silently pass by checking
// the certificate's validity window against time.Now(). Doing so substitutes
// wall-clock time for the attested signing time and loses proof-of-signing-time
// (a verify-time time-source fail-open). The verifier must fail closed.
func TestVerify_CertWithoutTimestamp_FailsClosed(t *testing.T) {
	env, root := signCertEnvelopeForFailClosed(t)

	// Roots present, NO timestamp verifiers, NO raw verifiers. Pre-fix this
	// returned NoError via the time.Now() cert path. Post-fix it must error.
	_, err := env.Verify(
		VerifyWithRoots(root),
		VerifyWithThreshold(1),
	)
	require.Error(t, err,
		"cert-based signature with no trusted timestamp must NOT verify against time.Now()")

	// The failure must be the no-matching-signatures path (the cert signature
	// was not counted toward the threshold), not some unrelated error.
	var noMatch ErrNoMatchingSigs
	require.True(t, errors.As(err, &noMatch),
		"expected ErrNoMatchingSigs, got %T: %v", err, err)
}

// TestVerify_CertWithoutTimestamp_ExplicitFallbackOptIn verifies that a caller
// who CONSCIOUSLY opts into wall-clock cert verification (e.g. a long-lived,
// non-Fulcio CA where proof-of-signing-time is intentionally out of scope) can
// still do so via the explicit VerifyWithCurrentTimeFallback() option. The
// escape hatch must be opt-in; it must never be the silent default.
func TestVerify_CertWithoutTimestamp_ExplicitFallbackOptIn(t *testing.T) {
	env, root := signCertEnvelopeForFailClosed(t)

	checked, err := env.Verify(
		VerifyWithRoots(root),
		VerifyWithThreshold(1),
		VerifyWithCurrentTimeFallback(),
	)
	require.NoError(t, err,
		"explicit current-time fallback opt-in must verify a currently-valid cert chain")
	require.NotEmpty(t, checked)
}

// TestVerify_CertWithTimestamp_StillVerifies is the positive regression guard:
// a properly RFC3161-timestamped cert-based envelope must STILL verify (the
// fail-closed change must not regress the trusted-timestamp happy path), and it
// must do so WITHOUT needing the current-time fallback opt-in.
func TestVerify_CertWithTimestamp_StillVerifies(t *testing.T) {
	now := time.Now()
	root, leaf, leafPriv := failClosedCertChain(t, now.Add(-1*time.Hour), 24*time.Hour)

	// A timestamper/verifier pair anchored at "now" (within the cert window).
	ft := timestamp.FakeTimestamper{T: now}

	s, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
	require.NoError(t, err)

	env, err := Sign("test", bytes.NewReader([]byte("timestamped-payload")),
		SignWithSigners(s),
		SignWithTimestampers(ft))
	require.NoError(t, err)

	checked, err := env.Verify(
		VerifyWithRoots(root),
		VerifyWithThreshold(1),
		VerifyWithTimestampVerifiers(ft),
	)
	require.NoError(t, err,
		"a properly timestamped cert envelope must still verify with no current-time fallback")
	assert.NotEmpty(t, checked)
}
