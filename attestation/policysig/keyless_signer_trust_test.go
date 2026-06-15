package policysig

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/require"
)

// klCreateKeylessLeaf mints a Fulcio-keyless-style leaf cert: NO CommonName,
// NO Organization, and identity carried entirely in SANs — a URI SAN (the OIDC
// issuer / identity, as a real Fulcio keyless cert carries) plus an email SAN.
// This is the exact cert shape that the partial-wildcard policy constraint
// rejected (#5746 F5: empty constraint fails closed; a cert that PRESENTS a URI
// SAN with an empty `uris` constraint is rejected because "the policy's uri
// constraint is empty, which forbids all").
func klCreateKeylessLeaf(t *testing.T, parent *x509.Certificate, parentPriv interface{}, issuer, email string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	issuerURI, err := url.Parse(issuer)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		// Deliberately empty Subject (no CN, no Org) — keyless Fulcio certs carry
		// identity in SANs, not the subject DN.
		Subject:               pkix.Name{},
		URIs:                  []*url.URL{issuerURI},
		EmailAddresses:        []string{email},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	tmpl.SerialNumber, err = rand.Int(rand.Reader, big.NewInt(4294967295))
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &priv.PublicKey, parentPriv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, priv
}

// TestKeylessSignerTrust_AllWildcardAcceptsKeylessCert is the red→green
// regression proof for the judge-api verify activity's policy-signer trust
// (verify.go, CILockVerifyActivity).
//
// REGRESSION: verify.go built the policy verify options with the PARTIAL
// wildcard call VerifyWithPolicyCertConstraints("", nil, []string{"*"}, nil,
// nil) — emails="*" but commonName="", dnsNames=nil, organizations=nil,
// uris=nil. After the #5746 F5 hardening, an EMPTY cert constraint fails closed
// (attestation/policy/constraints.go). A Fulcio keyless cert carries a URI SAN
// (the OIDC issuer) and identity SANs, so the empty `uris` constraint REJECTS
// every author-signed keyless policy with the exact staging symptom: "policy
// signature verified against a trusted CA root, but the signer identity matched
// no configured policy verifier."
//
// FIX: pass the AllowAll wildcard ("*") for ALL FIVE fields. The trusted-root
// check (VerifyWithPolicyCARoots → dsse.VerifyWithRoots) remains the real gate;
// only the cert IDENTITY is intentionally unconstrained (N1 phase-1).
//
// The test is NON-VACUOUS: it signs ONE keyless cert and asserts the OLD args
// REJECT it and the NEW args ACCEPT it. Same cert, both calls.
func TestKeylessSignerTrust_AllWildcardAcceptsKeylessCert(t *testing.T) {
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)

	// A Fulcio-keyless-style signer: identity in a URI SAN (OIDC issuer) + an
	// email SAN, no CN/Org. This mirrors the staging repro signer
	// (email=colek42@gmail.com under the platform Fulcio root).
	const (
		issuerURI   = "https://accounts.google.com"
		signerEmail = "colek42@gmail.com"
	)
	leaf, leafKey := klCreateKeylessLeaf(t, inter, interPriv, issuerURI, signerEmail)

	signer, err := cryptoutil.NewSigner(leafKey,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
		cryptoutil.SignWithRoots([]*x509.Certificate{root}),
	)
	require.NoError(t, err)

	// Cert-based (keyless) policy signatures are always TSA-timestamped in
	// practice; the verify path fails closed without a trusted signing-time
	// source (#5237). FakeTimestamper supplies one.
	fakeTS := timestamp.FakeTimestamper{T: time.Now()}
	env, err := dsse.Sign(
		"application/vnd.test+json",
		bytes.NewReader([]byte(`{"test":"policy"}`)),
		dsse.SignWithSigners(signer),
		dsse.SignWithTimestampers(fakeTS),
	)
	require.NoError(t, err)

	// Shared trust material for both runs: ONLY the platform root is trusted, so
	// the trusted-root check is the actual gate in both cases.
	trustOpts := []Option{
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{fakeTS}),
	}

	// --- RED: the OLD partial-wildcard args reject this keyless cert ---
	// VerifyWithPolicyCertConstraints("", nil, []string{"*"}, nil, nil): the
	// empty uris/dnsNames/organizations + empty commonName fail closed against a
	// cert that presents a URI SAN. This reproduces the regression.
	oldArgsOpts := append([]Option{}, trustOpts...)
	oldArgsOpts = append(oldArgsOpts, VerifyWithPolicyCertConstraints("", nil, []string{"*"}, nil, nil))
	errOld := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(oldArgsOpts...))
	require.Error(t, errOld,
		"REGRESSION GUARD: the old partial-wildcard constraints "+
			`("", nil, ["*"], nil, nil) MUST reject a keyless cert that carries a `+
			"URI SAN (#5746 F5 empty-constraint-fails-closed). If this no longer "+
			"errors, the fail-closed hardening changed and this test's premise is stale.")
	require.Contains(t, errOld.Error(), "matched no configured policy verifier",
		"the regression must surface the exact staging symptom")

	// --- GREEN: the NEW all-wildcard args accept the SAME keyless cert ---
	// VerifyWithPolicyCertConstraints("*", ["*"], ["*"], ["*"], ["*"]): explicit
	// opt-in to "allow any identity" at this layer; the trusted-root check above
	// is the real gate. This is the fix shipped in verify.go.
	newArgsOpts := append([]Option{}, trustOpts...)
	newArgsOpts = append(newArgsOpts, VerifyWithPolicyCertConstraints("*", []string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}))
	errNew := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(newArgsOpts...))
	require.NoError(t, errNew,
		"FIX: the all-wildcard constraints MUST accept a platform-Fulcio keyless "+
			"policy signer (N1 phase-1: trust any identity issued by the platform "+
			"Fulcio; the trusted-root check is the real gate)")
}

// TestKeylessSignerTrust_UntrustedRootStillRejected proves the all-wildcard
// constraints do NOT weaken the actual gate: a keyless cert that chains to an
// UNTRUSTED root is still rejected even under all-wildcard identity constraints.
// This is the load-bearing safety claim of the fix — identity is unconstrained,
// but the trusted-root chain is mandatory.
func TestKeylessSignerTrust_UntrustedRootStillRejected(t *testing.T) {
	// Trusted platform root (what the verifier is configured with).
	trustedRoot, trustedRootPriv := createRoot(t)
	trustedInter, _ := createIntermediate(t, trustedRoot, trustedRootPriv)

	// A SEPARATE, untrusted root the attacker controls. The keyless cert chains
	// here, NOT to the platform root.
	attackerRoot, attackerRootPriv := createRoot(t)
	attackerInter, attackerInterPriv := createIntermediate(t, attackerRoot, attackerRootPriv)
	attackerLeaf, attackerLeafKey := klCreateKeylessLeaf(t, attackerInter, attackerInterPriv,
		"https://accounts.google.com", "colek42@gmail.com")

	signer, err := cryptoutil.NewSigner(attackerLeafKey,
		cryptoutil.SignWithCertificate(attackerLeaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{attackerInter}),
		cryptoutil.SignWithRoots([]*x509.Certificate{attackerRoot}),
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

	// Verifier trusts ONLY the platform root, with all-wildcard identity.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{trustedRoot}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{trustedInter}),
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{fakeTS}),
		VerifyWithPolicyCertConstraints("*", []string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}),
	)

	err = VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err,
		"all-wildcard identity must NOT bypass the trusted-root gate: a keyless "+
			"cert chaining to an UNTRUSTED root must still be rejected")
}
