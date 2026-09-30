// jade:ring local

package policysig

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/require"
)

var aalOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 100}

// signWithAAL signs a policy as an email identity whose leaf carries the platform Fulcio's
// assurance extension (none when aal is "").
func signWithAAL(t *testing.T, email, aal string) (dsse.Envelope, []Option) {
	t.Helper()
	root, rootPriv := createRoot(t)
	inter, interPriv := createIntermediate(t, root, rootPriv)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		Subject: pkix.Name{}, EmailAddresses: []string{email},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
	}
	if aal != "" {
		v, err := asn1.MarshalWithParams("urn:testifysec:params:acr:nist-800-63b:"+aal, "utf8")
		require.NoError(t, err)
		tmpl.ExtraExtensions = []pkix.Extension{{Id: aalOID, Value: v}}
	}
	tmpl.SerialNumber, err = rand.Int(rand.Reader, big.NewInt(4294967295))
	require.NoError(t, err)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, inter, &priv.PublicKey, interPriv)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(priv, cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{inter}), cryptoutil.SignWithRoots([]*x509.Certificate{root}))
	require.NoError(t, err)
	ts := timestamp.FakeTimestamper{T: time.Now()}
	env, err := dsse.Sign("https://aflock.ai/policy/v0.1", bytes.NewReader([]byte(`{"steps":{}}`)),
		dsse.SignWithSigners(signer), dsse.SignWithTimestampers(ts))
	require.NoError(t, err)
	return env, []Option{
		VerifyWithPolicyCARoots([]*x509.Certificate{root}),
		VerifyWithPolicyCAIntermediates([]*x509.Certificate{inter}),
		VerifyWithPolicyTimestampAuthorities([]timestamp.TimestampVerifier{ts}),
		VerifyWithPolicyCertConstraints("", nil, []string{email}, nil, nil),
	}
}

// A policy countersigned by a person must be signed at the assurance the verifier requires:
// --policy-min-assurance aal2 accepts an aal2 or aal3 leaf and refuses aal1 or no extension.
func TestPolicyMinAssurance(t *testing.T) {
	withFullEnforcement(t)
	cases := []struct {
		leaf, min string
		ok        bool
	}{
		{"aal2", "aal2", true}, {"aal3", "aal2", true}, {"aal1", "aal2", false}, {"", "aal2", false},
		{"aal1", "", true}, {"", "", true},
	}
	for _, c := range cases {
		env, opts := signWithAAL(t, "assessor@3pao.example", c.leaf)
		if c.min != "" {
			opts = append(opts, VerifyWithPolicyMinAssurance(c.min))
		}
		err := VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...))
		if c.ok {
			require.NoError(t, err, "leaf %q min %q", c.leaf, c.min)
		} else {
			require.Error(t, err, "leaf %q min %q", c.leaf, c.min)
		}
	}
}

// A raw key carries no assurance level, so a required minimum refuses it.
func TestPolicyMinAssuranceRefusesKeySigner(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	env, err := dsse.Sign("https://aflock.ai/policy/v0.1", bytes.NewReader([]byte(`{"steps":{}}`)), dsse.SignWithSigners(signer))
	require.NoError(t, err)
	base := make([]Option, 0, 2)
	base = append(base, VerifyWithPolicyVerifiers([]cryptoutil.Verifier{verifier}))
	require.NoError(t, VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(base...)))
	err = VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(append(base, VerifyWithPolicyMinAssurance("aal2"))...))
	require.Error(t, err)
}

// An assurance level is not an identity. With no signer identity pinned (what
// `cilock verify --policy-min-assurance aal2` alone leaves once embedded trust
// steps aside), an AAL3 leaf chaining to a trusted root is still refused: any
// person the root vouches for at AAL2 or above would otherwise sign the policy.
func TestPolicyMinAssuranceIsNotAnIdentity(t *testing.T) {
	withFullEnforcement(t)
	env, opts := signWithAAL(t, "anyone@example.test", "aal3")
	opts = append(opts[:3], VerifyWithPolicyCertConstraints("", nil, nil, nil, nil), VerifyWithPolicyMinAssurance("aal2"))
	require.Error(t, VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...)))
}

// A minimum this build does not know refuses every signer rather than none.
func TestPolicyMinAssuranceUnknownLevelFailsClosed(t *testing.T) {
	withFullEnforcement(t)
	for _, min := range []string{"AAL2", "aal4", "urn:testifysec:params:acr:nist-800-63b:aal2", " aal2"} {
		env, opts := signWithAAL(t, "assessor@3pao.example", "aal3")
		opts = append(opts, VerifyWithPolicyMinAssurance(min))
		require.Error(t, VerifyPolicySignature(context.Background(), env, NewVerifyPolicySignatureOptions(opts...)), "min %q", min)
	}
}
