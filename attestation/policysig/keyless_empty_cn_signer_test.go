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
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// #5746 regression: a keyless Fulcio policy-SIGNER cert legitimately has an
// EMPTY Subject CommonName (identity lives in the email + OIDC-issuer SANs).
// The release-fanout verify pins the signer with `--policy-emails ...` and
// `--policy-fulcio-oidc-issuer ...` but does NOT pass `--policy-commonname`
// (defaults to ""). After #5746 made an empty CN constraint fail closed, that
// empty default rejected every keyless author-signed policy with the staging
// symptom "signer identity matched no configured policy verifier".
//
// The fix is scoped to the policy-SIGNER path only: an empty CommonName means
// "CN unconstrained" ONLY when the signer is otherwise pinned by a concrete
// (non-empty, non-"*") email or URI constraint. With NO such pin, the empty CN
// MUST still fail closed (the #5746 anti-bypass — a fully-unconstrained policy
// signer must never be accepted). The functionary CN fail-closed path
// (attestation/policy.checkCertConstraintGlob) is untouched.
//
// These tests are the red→green proof at the unit-testable signer-identity
// match (VerifyPolicySignature). They reuse the keyless-leaf + root/inter
// helpers from keyless_signer_trust_test.go / policysig_test.go.
// ---------------------------------------------------------------------------

// signKeylessEnv mints a keyless-style leaf (empty CN, identity in URI+email
// SANs) under the trusted root and returns the TSA-timestamped envelope plus
// the trust options that make ONLY that root trusted.
func signKeylessEnv(t *testing.T, issuerURI, signerEmail string) (dsse.Envelope, []Option, timestamp.FakeTimestamper) {
	t.Helper()
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)
	leaf, leafKey := klCreateKeylessLeaf(t, inter, interPriv, issuerURI, signerEmail)

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

	trustOpts := []Option{
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{fakeTS}),
	}
	return env, trustOpts, fakeTS
}

// TestKeylessEmptyCN_EmailAndURIPin_Accepts is the GREEN target: a keyless
// signer (empty CN) pinned by a concrete email AND issuer URI — and verified
// with an EMPTY --policy-commonname (the CLI default) — must verify. This is
// the exact release-fanout shape: --policy-emails colek42@gmail.com
// --policy-uris <issuer>, no --policy-commonname. v3.0.9 passed; #5746 broke it.
func TestKeylessEmptyCN_EmailAndURIPin_Accepts(t *testing.T) {
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	// EMPTY common name (CLI default), but email AND URI concretely pin identity.
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, []string{signerEmail}, nil, []string{issuerURI}))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.NoError(t, err,
		"a keyless policy signer with an EMPTY CommonName but pinned by a concrete "+
			"email + URI MUST verify — empty CN means 'CN unconstrained' when identity "+
			"is otherwise pinned (#5746 regression for the signer path)")
}

// TestKeylessEmptyCN_EmailOnlyPin_Accepts is the precise staging repro: the
// release fanout passes --policy-emails but NO --policy-uris. The cert carries
// a URI SAN (the issuer) AND an email SAN; identity is pinned by the email
// alone. Empty CN must not fail closed here.
func TestKeylessEmptyCN_EmailOnlyPin_Accepts(t *testing.T) {
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	// EMPTY common name + concrete email pin; URI left as the all-allow wildcard
	// (the cert's URI SAN is otherwise unconstrained, mirroring no --policy-uris).
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, []string{signerEmail}, nil, []string{"*"}))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.NoError(t, err,
		"a keyless policy signer pinned by a concrete email alone (no --policy-uris) "+
			"MUST verify with an empty --policy-commonname (exact release-fanout shape)")
}

// TestKeylessEmptyCN_URIOnlyPin_Accepts: identity pinned by a concrete URI
// alone (email left wildcard). Empty CN must not fail closed.
func TestKeylessEmptyCN_URIOnlyPin_Accepts(t *testing.T) {
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, []string{"*"}, nil, []string{issuerURI}))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.NoError(t, err,
		"a keyless policy signer pinned by a concrete URI alone MUST verify with an "+
			"empty --policy-commonname")
}

// TestKeylessEmptyCN_NoEmailNoURIPin_FailsClosed is GUARD A: the anti-bypass.
// An empty CN with NO concrete email and NO concrete URI constraint is a
// FULLY-unconstrained policy signer and MUST still fail closed (preserve the
// #5746 hardening). Here email and URI are the all-allow wildcard, so nothing
// pins the identity.
func TestKeylessEmptyCN_NoEmailNoURIPin_FailsClosed(t *testing.T) {
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	// EMPTY CN, and email/URI are wildcard (not concrete pins) — fully
	// unconstrained identity. dns/org also wildcard. MUST fail closed.
	opts = append(opts, VerifyWithPolicyCertConstraints("", []string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.Error(t, err,
		"ANTI-BYPASS (GUARD A): an empty CommonName with NO concrete email/URI pin is "+
			"a fully-unconstrained policy signer and MUST still fail closed (#5746). The "+
			"empty-CN relaxation applies ONLY when email or URI concretely pins identity.")
	require.Contains(t, err.Error(), "matched no configured policy verifier",
		"the fully-unconstrained empty-CN case must surface the fail-closed symptom")
}

// TestKeylessEmptyCN_NilEmailNilURI_FailsClosed is GUARD A's nil variant: a
// caller that passes nil (not wildcard) for email and URI with an empty CN.
// This is also a fully-unconstrained signer (no concrete pin) and MUST fail
// closed. (It already failed closed pre-fix because every field was empty/nil;
// the fix must NOT relax it.)
func TestKeylessEmptyCN_NilEmailNilURI_FailsClosed(t *testing.T) {
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, nil, nil, nil))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.Error(t, err,
		"ANTI-BYPASS (GUARD A nil variant): empty CN + nil email + nil URI is fully "+
			"unconstrained and MUST fail closed")
}

// TestKeylessEmptyCN_MixedWildcardEmailAndURI_FailsClosed is the Codex finding
// (PR #5820): the OLD pinsIdentity helper (then hasConcreteConstraint) returned
// true on the FIRST concrete element and ignored a wildcard elsewhere in the
// list. But under the downstream OR-matching of multi-value SAN constraints
// (attestation/policy.checkCertConstraint → hasAllowAll honors "*" at ANY
// position) the list ["*", "trusted@example.com"] matches ANY cert email — it
// does NOT pin identity. With the URI list also wildcard, NOTHING restricts the
// signer, yet the empty CN was relaxed to "*" → a fully-unconstrained policy
// signer was accepted (FAIL-OPEN). It MUST fail closed.
func TestKeylessEmptyCN_MixedWildcardEmailAndURI_FailsClosed(t *testing.T) {
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	// EMPTY CN; email list MIXES a wildcard with a concrete value (so it matches
	// any email under OR-matching), URI is the all-allow wildcard. Nothing pins.
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, []string{"*", "trusted@example.com"}, nil, []string{"*"}))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.Error(t, err,
		"CODEX FINDING (#5820): an email list mixing a wildcard with a concrete value "+
			"(['*','trusted@example.com']) matches ANY email under OR-matching and does NOT "+
			"pin identity; with a wildcard URI and empty CN the signer is fully unconstrained "+
			"and MUST fail closed — the empty-CN relaxation must require a genuine identity pin")
	require.Contains(t, err.Error(), "matched no configured policy verifier",
		"the mixed-wildcard (non-pinning) empty-CN case must surface the fail-closed symptom")
}

// TestKeylessEmptyCN_EmptyElementEmailAndWildcardURI_FailsClosed: an email list
// with an EMPTY-string element next to a concrete value (["", "trusted@..."]) is
// treated conservatively as non-pinning (an empty element carries no identity
// and is dropped downstream). With a wildcard URI and empty CN, the signer is
// not genuinely pinned, so it MUST fail closed under the tightened contract.
func TestKeylessEmptyCN_EmptyElementEmailAndWildcardURI_FailsClosed(t *testing.T) {
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	// EMPTY CN; email list has an empty-string element + a concrete value; URI is
	// the all-allow wildcard. Conservative contract: the empty element makes the
	// list non-pinning, so nothing genuinely restricts identity.
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, []string{"", "trusted@example.com"}, nil, []string{"*"}))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.Error(t, err,
		"an email list with an empty-string element (['','trusted@example.com']) is treated "+
			"conservatively as non-pinning; with a wildcard URI and empty CN the signer is not "+
			"genuinely pinned and MUST fail closed")
	require.Contains(t, err.Error(), "matched no configured policy verifier",
		"the empty-element (non-pinning) empty-CN case must surface the fail-closed symptom")
}

// TestKeylessEmptyCN_SingleConcreteEmailNoWildcard_Accepts is the legit
// release-fanout case kept GREEN: a single concrete email with NO wildcard pins
// identity, so the empty CN is correctly relaxed and verification succeeds.
func TestKeylessEmptyCN_SingleConcreteEmailNoWildcard_Accepts(t *testing.T) {
	const (
		issuerURI   = "https://platform.testifysec.com/fulcio/oidc"
		signerEmail = "colek42@gmail.com"
	)
	env, trustOpts, _ := signKeylessEnv(t, issuerURI, signerEmail)

	opts := append([]Option{}, trustOpts...)
	// EMPTY CN; a SINGLE concrete email, no wildcard → genuinely pins identity.
	// URI left wildcard (no --policy-uris). MUST accept.
	opts = append(opts, VerifyWithPolicyCertConstraints("", nil, []string{signerEmail}, nil, []string{"*"}))

	err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
	require.NoError(t, err,
		"a single concrete email with NO wildcard genuinely pins identity, so the empty CN "+
			"is correctly relaxed and the legit keyless release-fanout signer verifies")
}
