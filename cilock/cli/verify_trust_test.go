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

package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/embeddedtrust"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// trustTestCert returns a certificate and its PEM. A nil parent makes it
// self-signed (a root); otherwise it is issued by parent/parentKey.
func trustTestCert(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	signerCert, signerKey := tpl, key
	if parent != nil {
		signerCert, signerKey = parent, parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, &key.PublicKey, signerKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: pemTypeCertificate, Bytes: der})
}

func trustTestWritePEM(t *testing.T, pemBytes []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "certs.pem")
	require.NoError(t, os.WriteFile(p, pemBytes, 0o600))
	return p
}

// releaseSigner is the shape the release workflow bakes into trust.json: the
// workflow's identity, never an approver's.
func releaseSigner() policy.Functionary {
	return policy.Functionary{
		Type: "root",
		CertConstraint: policy.CertConstraint{
			Emails: []string{"release@example.test"},
			URIs:   []string{"https://github.com/example/rookery/.github/workflows/release.yml@refs/tags/v4.5.0"},
		},
	}
}

func trustTestEmbedded(t *testing.T, signers ...policy.Functionary) (*embeddedPolicyTrust, *x509.Certificate, *x509.Certificate) {
	t.Helper()
	fulcio, _, fulcioPEM := trustTestCert(t, "embedded fulcio root", nil, nil)
	tsa, _, tsaPEM := trustTestCert(t, "embedded tsa root", nil, nil)
	emb, err := parseEmbeddedPolicyTrust(&embeddedtrust.Trust{
		Source: "https://platform.example.test",
		Roots: []embeddedtrust.Root{
			{Name: "fulcio", Kind: embeddedtrust.KindFulcioRoot, PEM: string(fulcioPEM)},
			{Name: "tsa", Kind: embeddedtrust.KindTSARoot, PEM: string(tsaPEM)},
		},
		PolicySigners: signers,
	})
	require.NoError(t, err)
	require.NotNil(t, emb)
	return emb, fulcio, tsa
}

func trustTestContains(certs []*x509.Certificate, want *x509.Certificate) bool {
	for _, c := range certs {
		if c.Equal(want) {
			return true
		}
	}
	return false
}

// Envelope mode (A5 lane 3) calls the extracted function with false: the
// embedded signer is the release workflow's identity, and applying it to an
// approval would pin the wrong principal.
func TestSignatureTrust_EmbeddedSignerOnlyWhenAsked(t *testing.T) {
	emb, fulcio, tsa := trustTestEmbedded(t, releaseSigner())

	var off options.VerifyOptions
	got, err := resolvePolicySignatureTrust(&off, emb, false)
	require.NoError(t, err)
	assert.Empty(t, off.PolicyEmails, "applyEmbeddedSigner=false must not set PolicyEmails")
	assert.Empty(t, off.PolicyURIs, "applyEmbeddedSigner=false must not set PolicyURIs")
	assert.Empty(t, off.PolicyCommonName)
	assert.Empty(t, off.PolicyDNSNames)
	assert.Empty(t, off.PolicyOrganizations)
	assert.Empty(t, off.PolicyFulcioCertExtensions.Issuer)
	assert.True(t, trustTestContains(got.roots, fulcio), "embedded roots still apply without the signer")
	assert.True(t, trustTestContains(got.tsaCerts, tsa))
	assert.Len(t, got.timestampVerifiers, 1)

	var on options.VerifyOptions
	_, err = resolvePolicySignatureTrust(&on, emb, true)
	require.NoError(t, err)
	assert.Equal(t, []string{"release@example.test"}, on.PolicyEmails)
	assert.Equal(t, releaseSigner().CertConstraint.URIs, on.PolicyURIs)
}

// The multiple-signer refusal belongs to applying the signer. A caller that
// never applies it has nothing to choose between.
func TestSignatureTrust_MultipleEmbeddedSignersRefusedOnlyWhenApplied(t *testing.T) {
	second := releaseSigner()
	second.CertConstraint.Emails = []string{"other@example.test"}
	emb, _, _ := trustTestEmbedded(t, releaseSigner(), second)

	var on options.VerifyOptions
	_, err := resolvePolicySignatureTrust(&on, emb, true)
	require.ErrorContains(t, err, "embedded trust defines 2 policy signers")

	var off options.VerifyOptions
	_, err = resolvePolicySignatureTrust(&off, emb, false)
	require.NoError(t, err)
	assert.Empty(t, off.PolicyEmails)
}

// A flag replaces the embedded value for its dimension wholesale; embedded
// trust only fills the dimensions the operator left empty.
func TestSignatureTrust_FlagsWinPerDimension(t *testing.T) {
	emb, embFulcio, embTSA := trustTestEmbedded(t)
	flagRoot, _, flagRootPEM := trustTestCert(t, "flag root", nil, nil)
	flagTSA, _, flagTSAPEM := trustTestCert(t, "flag tsa", nil, nil)

	caOnly := options.VerifyOptions{PolicyCARootPaths: []string{trustTestWritePEM(t, flagRootPEM)}}
	got, err := resolvePolicySignatureTrust(&caOnly, emb, false)
	require.NoError(t, err)
	assert.True(t, trustTestContains(got.roots, flagRoot))
	assert.False(t, trustTestContains(got.roots, embFulcio), "--policy-ca-roots must replace the embedded Fulcio roots")
	assert.True(t, trustTestContains(got.tsaCerts, embTSA), "the TSA dimension was left empty, so embedded fills it")

	tsaOnly := options.VerifyOptions{PolicyTimestampServers: []string{trustTestWritePEM(t, flagTSAPEM)}}
	got, err = resolvePolicySignatureTrust(&tsaOnly, emb, false)
	require.NoError(t, err)
	assert.True(t, trustTestContains(got.tsaCerts, flagTSA))
	assert.False(t, trustTestContains(got.tsaCerts, embTSA), "--policy-timestamp-servers must replace the embedded TSA roots")
	assert.Len(t, got.timestampVerifiers, 1)
	assert.True(t, trustTestContains(got.roots, embFulcio))
}

// Discovered PEM and --policy-ca-roots files are split by self-signedness, so
// a bundle of Fulcio CA + Root chains leaf -> Fulcio CA -> Root.
func TestSignatureTrust_SplitsBundlesBySelfSigned(t *testing.T) {
	root, rootKey, rootPEM := trustTestCert(t, "root", nil, nil)
	inter, _, interPEM := trustTestCert(t, "fulcio intermediate", root, rootKey)
	bundle := append(append([]byte{}, interPEM...), rootPEM...)

	for name, vo := range map[string]options.VerifyOptions{
		"discovered": {PolicyCARootsPEM: bundle},
		"file":       {PolicyCARootPaths: []string{trustTestWritePEM(t, bundle)}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := resolvePolicySignatureTrust(&vo, nil, true)
			require.NoError(t, err)
			assert.True(t, trustTestContains(got.roots, root))
			assert.False(t, trustTestContains(got.roots, inter))
			assert.True(t, trustTestContains(got.intermediates, inter))
			assert.False(t, trustTestContains(got.intermediates, root))
		})
	}
}

func TestSignatureTrust_UnreadableFlagFilesFail(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.pem")
	for name, vo := range map[string]options.VerifyOptions{
		"ca-roots":          {PolicyCARootPaths: []string{missing}},
		"ca-intermediates":  {PolicyCAIntermediatePaths: []string{missing}},
		"timestamp-servers": {PolicyTimestampServers: []string{missing}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := resolvePolicySignatureTrust(&vo, nil, false)
			require.Error(t, err)
		})
	}
}

// swapEmbeddedTrustLoader replaces the package seam for one test. Tests that
// call it must not run in parallel.
func swapEmbeddedTrustLoader(t *testing.T, fn func() (*embeddedtrust.Trust, error)) {
	t.Helper()
	orig := loadEmbeddedTrust
	loadEmbeddedTrust = fn
	t.Cleanup(func() { loadEmbeddedTrust = orig })
}

func sandboxVerifyEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	stateDir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Setenv("CILOCK_STATE_DIR", stateDir)
	t.Setenv("CILOCK_SKIP_VERSION_CHECK", "1")
	t.Setenv("CILOCK_NO_TELEMETRY", "1")
	t.Setenv("CILOCK_NO_EMBEDDED_TRUST", "")
}

const (
	errNoPolicyTrust = "must supply a public key, CA certificates, a verifier, or a cilock built with embedded policy trust"
	errNoEvidence    = "must specify attestation file paths, attestation bundles, or enable archivista"
)

// runVerify reads embedded trust through loadEmbeddedTrust, so a test can hand
// it roots. With no other trust source, the roots from the seam are what
// clears the "must supply ... trust" precheck.
func TestRunVerify_EmbeddedTrustComesThroughTheSeam(t *testing.T) {
	sandboxVerifyEnv(t)

	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) { return nil, nil })
	err := runVerify(context.Background(), options.VerifyOptions{}, nil, nil, false)
	require.ErrorContains(t, err, errNoPolicyTrust)

	_, _, rootPEM := trustTestCert(t, "seam root", nil, nil)
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) {
		return &embeddedtrust.Trust{Roots: []embeddedtrust.Root{{Name: "r", Kind: embeddedtrust.KindFulcioRoot, PEM: string(rootPEM)}}}, nil
	})
	err = runVerify(context.Background(), options.VerifyOptions{}, nil, nil, false)
	require.ErrorContains(t, err, errNoEvidence, "roots from the seam must satisfy the trust precheck")

	boom := errors.New("seam exploded")
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) { return nil, boom })
	err = runVerify(context.Background(), options.VerifyOptions{}, nil, nil, false)
	require.ErrorIs(t, err, boom)
	require.ErrorContains(t, err, "load embedded policy trust")
}

// --no-embedded-trust and CILOCK_NO_EMBEDDED_TRUST opt out before the loader
// runs: a broken or hostile embedded document cannot affect an opted-out run.
func TestRunVerify_NoEmbeddedTrustNeverCallsTheSeam(t *testing.T) {
	for name, tc := range map[string]struct {
		flag bool
		env  string
	}{
		"flag": {flag: true},
		"env":  {env: "1"},
	} {
		t.Run(name, func(t *testing.T) {
			sandboxVerifyEnv(t)
			t.Setenv("CILOCK_NO_EMBEDDED_TRUST", tc.env)
			called := false
			_, _, rootPEM := trustTestCert(t, "must not be trusted", nil, nil)
			swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) {
				called = true
				return &embeddedtrust.Trust{Roots: []embeddedtrust.Root{{Name: "r", Kind: embeddedtrust.KindFulcioRoot, PEM: string(rootPEM)}}}, nil
			})
			err := runVerify(context.Background(), options.VerifyOptions{NoEmbeddedTrust: tc.flag}, nil, nil, false)
			require.ErrorContains(t, err, errNoPolicyTrust)
			assert.False(t, called, "the embedded-trust loader ran despite the opt-out")
		})
	}
}

// A malformed embedded root is an error, never an empty (and therefore
// silently skipped) trust dimension.
func TestParseEmbeddedPolicyTrust_MalformedRootFails(t *testing.T) {
	_, err := parseEmbeddedPolicyTrust(&embeddedtrust.Trust{
		Roots: []embeddedtrust.Root{{Name: "bad", Kind: embeddedtrust.KindFulcioRoot, PEM: "not a pem"}},
	})
	require.Error(t, err)

	got, err := parseEmbeddedPolicyTrust(nil)
	require.NoError(t, err)
	assert.Nil(t, got)
}

// runVerify applies the embedded signer only when no signer-identity flag was
// set. Two embedded signers make "applied" observable: applying them refuses.
func TestRunVerify_EmbeddedSignerOnlyWhenFlagsLeaveIdentityUnpinned(t *testing.T) {
	sandboxVerifyEnv(t)
	_, _, rootPEM := trustTestCert(t, "seam root", nil, nil)
	second := releaseSigner()
	second.CertConstraint.Emails = []string{"other@example.test"}
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) {
		return &embeddedtrust.Trust{
			Roots:         []embeddedtrust.Root{{Name: "r", Kind: embeddedtrust.KindFulcioRoot, PEM: string(rootPEM)}},
			PolicySigners: []policy.Functionary{releaseSigner(), second},
		}, nil
	})
	vo := options.VerifyOptions{AttestationFilePaths: []string{filepath.Join(t.TempDir(), "unused.json")}}

	err := runVerify(context.Background(), vo, nil, nil, false)
	require.ErrorContains(t, err, "embedded trust defines 2 policy signers")

	err = runVerify(context.Background(), vo, nil, nil, true)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "policy signers", "a flag-pinned signer identity must not be overwritten by embedded trust")
}
