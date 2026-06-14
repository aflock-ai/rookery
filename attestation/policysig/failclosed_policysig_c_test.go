package policysig

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
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Local helpers (the secCreateLeafCert/secSignEnvelopeX509 helpers live behind
// the `audit` build tag and are NOT compiled in the default suite; the
// untagged policysig_test.go helpers createRoot/createIntermediate ARE. We add
// only what's missing: a leaf builder with a caller-chosen CN.)
// ---------------------------------------------------------------------------

// fcCreateLeafCN mints a leaf cert with an explicit CommonName so a test can
// produce two distinct cert identities under the same trusted root.
func fcCreateLeafCN(t *testing.T, parent *x509.Certificate, parentPriv interface{}, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"TestifySec"},
			CommonName:   cn,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	tmpl.SerialNumber, err = rand.Int(rand.Reader, big.NewInt(4294967295))
	require.NoError(t, err)
	certBytes, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &priv.PublicKey, parentPriv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	return cert, priv
}

func fcX509Signer(t *testing.T, leafKey *rsa.PrivateKey, leaf, inter, root *x509.Certificate) cryptoutil.Signer {
	t.Helper()
	signer, err := cryptoutil.NewSigner(leafKey,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
		cryptoutil.SignWithRoots([]*x509.Certificate{root}),
	)
	require.NoError(t, err)
	return signer
}

// TestRed_C_PolicySigRejectsFailedVerifier — Finding C (#5747, CRITICAL).
//
// Target: VerifyPolicySignature, policysig.go. The loop over
// passedPolicyVerifiers (the []dsse.CheckedVerifier returned by
// envelope.Verify) does NOT skip entries with verifier.Error != nil. On the
// success path dsse.Envelope.Verify returns the FULL slice including failed
// entries (dsse/verify.go: a corrupted cert signature whose TSA time verifies
// but whose Fulcio chain fails is appended as CheckedVerifier{Verifier, Error:
// "no valid timestamps found"}). A failed-signature verifier whose cert chains
// to a trusted root and matches the identity constraints therefore sets
// passed=true. The correct Error!=nil filter exists in source/verified.go:115.
//
// Fail-closed contract: when the ONLY constraint-matching verifier had a FAILED
// signature (Error != nil), VerifyPolicySignature MUST reject (return error).
// A non-matching, genuinely-passing signer keeps envelope.Verify's threshold
// satisfied (so the function reaches the buggy loop) but, having a CN the
// constraints reject, must not itself confer trust.
func TestRed_C_PolicySigRejectsFailedVerifier(t *testing.T) {
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)

	// GOOD signer: a genuinely valid, TSA-timestamped cert signature. Its CN
	// "Decoy Signer" does NOT match the configured constraint, so it keeps the
	// envelope.Verify threshold satisfied (verified>=1) without itself passing
	// the policy identity check — it must NOT confer trust on its own.
	goodLeaf, goodKey := fcCreateLeafCN(t, inter, interPriv, "Decoy Signer")
	goodSigner := fcX509Signer(t, goodKey, goodLeaf, inter, root)

	// EVIL signer: a cert whose CN "Trusted Policy Signer" MATCHES the
	// configured constraint and which chains to the trusted root — but whose
	// signature we corrupt below. dsse.Verify's TSA branch validates the
	// timestamp (FakeTimestamper ignores the sig bytes) then fails the Fulcio
	// chain check, appending it as a CheckedVerifier with Error != nil.
	evilLeaf, evilKey := fcCreateLeafCN(t, inter, interPriv, "Trusted Policy Signer")
	evilSigner := fcX509Signer(t, evilKey, evilLeaf, inter, root)

	fakeTS := timestamp.FakeTimestamper{T: time.Now()}

	// Sign one envelope with BOTH signers + the TSA. Signature[i] corresponds
	// to signer i (dsse.Sign iterates signers in order), so the EVIL signature
	// is index 1.
	env, err := dsse.Sign(
		"application/vnd.test+json",
		bytes.NewReader([]byte(`{"test":"policy"}`)),
		dsse.SignWithSigners(goodSigner, evilSigner),
		dsse.SignWithTimestampers(fakeTS),
	)
	require.NoError(t, err)
	require.Len(t, env.Signatures, 2, "expected one signature per signer")

	// Corrupt ONLY the EVIL signature's bytes so its cert-chain signature check
	// fails (Error != nil) while its cert still chains to the trusted root and
	// matches the configured identity constraint.
	require.NotEmpty(t, env.Signatures[1].Signature)
	env.Signatures[1].Signature[0] ^= 0xFF

	// Constraints accept ONLY the EVIL identity ("Trusted Policy Signer").
	// The GOOD ("Decoy Signer") signature, though it passes signature+TSA
	// verification, is rejected by the CN constraint. So the ONLY
	// constraint-matching verifier is the one with the FAILED signature.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{fakeTS}),
		VerifyWithPolicyCertConstraints(
			"Trusted Policy Signer", // matches ONLY the failed (corrupted) signer
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
		),
	)

	err = VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err,
		"VerifyPolicySignature must REJECT a policy whose only constraint-matching "+
			"verifier had a FAILED signature (Error != nil); trusting it is the #5747 "+
			"fail-open (missing `if verifier.Error != nil { continue }` in the "+
			"passedPolicyVerifiers loop, policysig.go)")
}
