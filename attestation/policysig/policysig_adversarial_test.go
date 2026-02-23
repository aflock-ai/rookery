//go:build audit

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
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ==========================================================================
// allWildcard edge case tests
// ==========================================================================

func TestAdversarial_AllWildcard_DefaultOptionsIsWildcard(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions()
	assert.True(t, allWildcard(vo),
		"default options should be all-wildcard")
}

func TestAdversarial_AllWildcard_NilSlicesAreNotWildcard(t *testing.T) {
	// If someone sets constraints with nil slices (as opposed to ["*"]),
	// the allWildcard function should return false because isWildSlice(nil) = false.
	// This is correct behavior but worth documenting.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCertConstraints("*", nil, nil, nil, nil),
	)
	assert.False(t, allWildcard(vo),
		"nil slices should NOT be treated as wildcard (isWildSlice requires len==1 && [0]==\"*\")")
}

func TestAdversarial_AllWildcard_EmptySlicesAreNotWildcard(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCertConstraints("*", []string{}, []string{}, []string{}, []string{}),
	)
	assert.False(t, allWildcard(vo),
		"empty slices should NOT be treated as wildcard")
}

func TestAdversarial_AllWildcard_WildcardAmongOthers(t *testing.T) {
	// BUG INVESTIGATION: If a user sets ["*", "extra"], isWildSlice returns false
	// because len(ss) != 1. So the wildcard warning is suppressed, but "*" is
	// still a constraint that may be accepted by the functionary validation.
	//
	// This means a user could add ["*", "anything"] to silence the warning while
	// the wildcard might still be broadly accepted depending on how CertConstraint.Check works.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCertConstraints("*", []string{"*", "extra.dns"}, []string{"*"}, []string{"*"}, []string{"*"}),
	)
	assert.False(t, allWildcard(vo),
		"wildcard among other values should NOT trigger allWildcard (but may still be overly permissive)")
}

func TestAdversarial_AllWildcard_EmptyCommonName(t *testing.T) {
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCertConstraints("", []string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}),
	)
	assert.False(t, allWildcard(vo),
		"empty common name is not wildcard")
}

func TestAdversarial_AllWildcard_OnlyOneFieldNonWildcard(t *testing.T) {
	// Each field individually set to non-wildcard
	tests := []struct {
		name  string
		cn    string
		dns   []string
		email []string
		org   []string
		uri   []string
	}{
		{"cn_non_wild", "specific-cn", []string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}},
		{"dns_non_wild", "*", []string{"specific.dns"}, []string{"*"}, []string{"*"}, []string{"*"}},
		{"email_non_wild", "*", []string{"*"}, []string{"specific@email"}, []string{"*"}, []string{"*"}},
		{"org_non_wild", "*", []string{"*"}, []string{"*"}, []string{"SpecificOrg"}, []string{"*"}},
		{"uri_non_wild", "*", []string{"*"}, []string{"*"}, []string{"*"}, []string{"https://specific"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			vo := NewVerifyPolicySignatureOptions(
				VerifyWithPolicyCertConstraints(tc.cn, tc.dns, tc.email, tc.org, tc.uri),
			)
			assert.False(t, allWildcard(vo),
				"setting any single field to non-wildcard should make allWildcard false")
		})
	}
}

// ==========================================================================
// VerifyPolicySignature adversarial tests
// ==========================================================================

func TestAdversarial_VerifyPolicySignature_NilOptions(t *testing.T) {
	signer, _ := advCreateTestKey(t)
	env := advSignEnvelope(t, signer)

	// Passing nil options should panic (nil pointer dereference in allWildcard).
	assert.Panics(t, func() {
		_ = VerifyPolicySignature(context.Background(), env, nil)
	}, "nil VerifyPolicySignatureOptions should panic")
}

func TestAdversarial_VerifyPolicySignature_EmptyEnvelope(t *testing.T) {
	_, verifier := advCreateTestKey(t)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)

	// Empty envelope -- no signatures, no payload.
	env := dsse.Envelope{}
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err, "empty envelope should fail verification")
}

func TestAdversarial_VerifyPolicySignature_NilVerifiersSlice(t *testing.T) {
	signer, _ := advCreateTestKey(t)
	env := advSignEnvelope(t, signer)

	// Explicitly pass nil verifiers.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers(nil),
	)
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err, "nil verifiers slice should fail")
}

func TestAdversarial_VerifyPolicySignature_EmptyVerifiersSlice(t *testing.T) {
	signer, _ := advCreateTestKey(t)
	env := advSignEnvelope(t, signer)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{}),
	)
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err, "empty verifiers slice should fail")
}

func TestAdversarial_VerifyPolicySignature_ConcurrentVerification(t *testing.T) {
	// Test thread safety: VerifyPolicySignature should be safe for concurrent use
	// with DIFFERENT options/envelopes. The function itself has no global state,
	// but we want to verify no races exist.
	signer, verifier := advCreateTestKey(t)
	env := advSignEnvelope(t, signer)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)

	var wg sync.WaitGroup
	errs := make([]error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = VerifyPolicySignature(context.Background(), env, vo)
		}(i)
	}

	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "concurrent verification %d should succeed", i)
	}
}

func TestAdversarial_VerifyPolicySignature_ModifiedSignature(t *testing.T) {
	signer, verifier := advCreateTestKey(t)
	env := advSignEnvelope(t, signer)

	// Corrupt the signature bytes.
	if len(env.Signatures) > 0 && len(env.Signatures[0].Signature) > 0 {
		sigBytes := make([]byte, len(env.Signatures[0].Signature))
		copy(sigBytes, env.Signatures[0].Signature)
		sigBytes[0] ^= 0xFF
		env.Signatures[0].Signature = sigBytes
	}

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)
	err := VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err, "corrupted signature should fail")
}

func TestAdversarial_VerifyPolicySignature_X509WithConstraints_CnMismatch(t *testing.T) {
	root, rootPriv := advCreateRoot(t)
	inter, interPriv := advCreateIntermediate(t, root, rootPriv)
	leaf, leafPriv := advCreateLeaf(t, inter, interPriv, "Leaf CN")

	signer, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
		cryptoutil.SignWithRoots([]*x509.Certificate{root}),
	)
	require.NoError(t, err)

	env := advSignEnvelope(t, signer)

	// Set a constraint that doesn't match the leaf cert's CN.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyCertConstraints(
			"Wrong CN", // does not match "Leaf CN"
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
		),
	)

	err = VerifyPolicySignature(context.Background(), env, vo)
	require.Error(t, err,
		"mismatched CN constraint should cause verification to fail")
}

func TestAdversarial_VerifyPolicySignature_X509WithConstraints_MatchingCn(t *testing.T) {
	root, rootPriv := advCreateRoot(t)
	inter, interPriv := advCreateIntermediate(t, root, rootPriv)
	leaf, leafPriv := advCreateLeaf(t, inter, interPriv, "Leaf CN")

	signer, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}),
		cryptoutil.SignWithRoots([]*x509.Certificate{root}),
	)
	require.NoError(t, err)

	env := advSignEnvelope(t, signer)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyCertConstraints(
			"Leaf CN", // matches
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
			[]string{"*"},
		),
	)

	err = VerifyPolicySignature(context.Background(), env, vo)
	require.NoError(t, err,
		"matching CN constraint should allow verification to succeed")
}

func TestAdversarial_VerifyPolicySignature_KeyVerifierWithConstraints(t *testing.T) {
	// When using a key verifier (not x509), the functionary validation
	// goes through the "key" path, not the "root" path. Cert constraints
	// should be irrelevant for key-based verifiers.
	signer, verifier := advCreateTestKey(t)
	env := advSignEnvelope(t, signer)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
		VerifyWithPolicyCertConstraints(
			"some-cn", // these should be irrelevant for key verifiers
			[]string{"specific.dns"},
			[]string{"specific@email"},
			[]string{"SpecificOrg"},
			[]string{"https://specific"},
		),
	)

	err := VerifyPolicySignature(context.Background(), env, vo)
	require.NoError(t, err,
		"key-based verifier should pass regardless of cert constraints")
}

func TestAdversarial_VerifyPolicySignature_LargePayload(t *testing.T) {
	signer, verifier := advCreateTestKey(t)

	// Sign a large payload.
	payload := make([]byte, 1024*1024) // 1 MB
	_, err := rand.Read(payload)
	require.NoError(t, err)

	env, err := dsse.Sign("largetype", bytes.NewReader(payload), dsse.SignWithSigners(signer))
	require.NoError(t, err)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)
	err = VerifyPolicySignature(context.Background(), env, vo)
	require.NoError(t, err, "large payload should verify")
}

func TestAdversarial_VerifyPolicySignature_NilContext(t *testing.T) {
	// The function accepts context but doesn't use it.
	// Passing nil should be safe (no panic) since ctx is unused.
	signer, verifier := advCreateTestKey(t)
	env := advSignEnvelope(t, signer)
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}),
	)

	// This should not panic. The current implementation doesn't use ctx at all.
	//nolint:staticcheck // SA1012: intentionally passing nil context for adversarial test
	err := VerifyPolicySignature(nil, env, vo)
	require.NoError(t, err,
		"nil context should not panic (context is currently unused)")
}

// ==========================================================================
// Option stacking / interaction tests
// ==========================================================================

func TestAdversarial_VerifyWithPolicyVerifiers_NilAppend(t *testing.T) {
	// Appending nil to verifiers.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers(nil),
	)
	assert.Empty(t, vo.policyVerifiers,
		"appending nil verifier slice should result in empty verifiers")
}

func TestAdversarial_Options_ConstraintsThenReset(t *testing.T) {
	// Set specific constraints, then re-set to wildcards. The last
	// call should win.
	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyCertConstraints("specific", []string{"dns"}, []string{"e@m"}, []string{"org"}, []string{"uri"}),
		VerifyWithPolicyCertConstraints("*", []string{"*"}, []string{"*"}, []string{"*"}, []string{"*"}),
	)
	assert.True(t, allWildcard(vo),
		"resetting constraints to wildcards should make allWildcard true again")
}

func TestAdversarial_VerifyWithPolicyVerifiers_MultipleAppends(t *testing.T) {
	_, v1 := advCreateTestKey(t)
	_, v2 := advCreateTestKey(t)
	_, v3 := advCreateTestKey(t)

	vo := NewVerifyPolicySignatureOptions(
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{v1}),
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{v2}),
		VerifyWithPolicyVerifiers([]cryptoutil.Verifier{v3}),
	)
	assert.Len(t, vo.policyVerifiers, 3,
		"three separate append calls should accumulate 3 verifiers")
}

// ==========================================================================
// Helpers
// ==========================================================================

func advCreateRsaKey(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv, &priv.PublicKey
}

func advCreateTestKey(t *testing.T) (cryptoutil.Signer, cryptoutil.Verifier) {
	t.Helper()
	priv, pub := advCreateRsaKey(t)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(pub, crypto.SHA256)
	return signer, verifier
}

func advCreateCert(t *testing.T, priv, pub interface{}, tmpl, parent *x509.Certificate) *x509.Certificate {
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

func advCreateRoot(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := advCreateRsaKey(t)
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
	cert := advCreateCert(t, priv, pub, tmpl, tmpl)
	return cert, priv
}

func advCreateIntermediate(t *testing.T, parent *x509.Certificate, parentPriv interface{}) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := advCreateRsaKey(t)
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
	cert := advCreateCert(t, parentPriv, pub, tmpl, parent)
	return cert, priv
}

func advCreateLeaf(t *testing.T, parent *x509.Certificate, parentPriv interface{}, cn string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, pub := advCreateRsaKey(t)
	tmpl := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"TestifySec"},
			CommonName:   cn,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	cert := advCreateCert(t, parentPriv, pub, tmpl, parent)
	return cert, priv
}

func advSignEnvelope(t *testing.T, signer cryptoutil.Signer) dsse.Envelope {
	t.Helper()
	env, err := dsse.Sign("dummytype", bytes.NewReader([]byte("test payload")), dsse.SignWithSigners(signer))
	require.NoError(t, err)
	return env
}
