// Copyright 2021 The Witness Contributors
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

package cryptoutil

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSecurity_Issue5996_RSAPKCS1Fallback asserts the SECURE behavior: the
// default RSA verifier must NOT silently accept a PKCS#1 v1.5 signature when
// PSS is the expected scheme. The weaker PKCS1v15 acceptance is only allowed
// when explicitly opted in per-verifier.
func TestSecurity_Issue5996_RSAPKCS1Fallback(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	data := []byte("issue 5996 rsa scheme agility")
	digest, err := Digest(bytes.NewReader(data), crypto.SHA256)
	require.NoError(t, err)

	// A signature produced with PKCS#1 v1.5 (the weaker, deterministic scheme).
	pkcs1Sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
	require.NoError(t, err)

	// A signature produced with PSS (the expected scheme).
	pssSig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
	require.NoError(t, err)

	t.Run("default rejects PKCS1v15", func(t *testing.T) {
		v := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
		err := v.Verify(bytes.NewReader(data), pkcs1Sig)
		require.Error(t, err,
			"default verifier MUST reject a PKCS#1 v1.5 signature; the fallback must be opt-in")
	})

	t.Run("default accepts PSS", func(t *testing.T) {
		v := NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
		err := v.Verify(bytes.NewReader(data), pssSig)
		require.NoError(t, err, "default verifier must still accept PSS signatures")
	})

	t.Run("opt-in accepts PKCS1v15", func(t *testing.T) {
		v := NewRSAVerifierWithOptions(&priv.PublicKey, crypto.SHA256, WithPKCS1v15Fallback())
		err := v.Verify(bytes.NewReader(data), pkcs1Sig)
		require.NoError(t, err,
			"opt-in verifier must accept PKCS#1 v1.5 (e.g. AWS KMS compatibility)")
	})
}
