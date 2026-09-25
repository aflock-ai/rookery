// jade:ring local

package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// RSA verification is pinned to one scheme and one parameter set (#9917).
//
// Wycheproof's rsa_pss_2048_sha256_mgf1_32 vectors tc67-72 ("s_len changed")
// are PSS signatures whose salt length is not the 32 bytes the key's
// parameters name; they are invalid, and PSSSaltLengthAuto accepted all six.
// Wycheproof's rsa_signature_2048_sha256 vectors tc255-257 (WrongPrimitive)
// are PSS signatures presented to a PKCS#1 v1.5 verifier; a verifier for one
// scheme must not accept the other, and the fallback verifier accepted all
// three. These tests rebuild both shapes locally; the downloaded vectors stay
// holdout data and are not committed.

func TestRSAVerifierPinsPSSSaltLength(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	data := []byte("rsa pss salt length")
	digest, err := Digest(bytes.NewReader(data), crypto.SHA256)
	require.NoError(t, err)
	v := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	for _, salt := range []int{0, 1, 20, 31, 33, 222} {
		sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: salt, Hash: crypto.SHA256})
		require.NoError(t, err)
		require.Error(t, v.Verify(bytes.NewReader(data), sig), "a PSS signature with salt length %d must be refused; only the hash length (32) verifies", salt)
	}

	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(data), sig))
}

func TestRSASignerVerifierRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		s := NewRSASigner(priv, h)
		sig, err := s.Sign(bytes.NewReader([]byte("round trip")))
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		require.NoError(t, v.Verify(bytes.NewReader([]byte("round trip")), sig), "hash %v", h)
	}
}

func TestRSAPKCS1VerifierRefusesPSS(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	data := []byte("rsa wrong primitive")
	digest, err := Digest(bytes.NewReader(data), crypto.SHA256)
	require.NoError(t, err)
	v := NewRSAVerifierWithOptions(&priv.PublicKey, crypto.SHA256, WithPKCS1v15())

	pss, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	require.NoError(t, err)
	require.Error(t, v.Verify(bytes.NewReader(data), pss), "a PKCS#1 v1.5 verifier must refuse a PSS signature")

	pkcs1, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	require.NoError(t, err)
	require.NoError(t, v.Verify(bytes.NewReader(data), pkcs1))
}
