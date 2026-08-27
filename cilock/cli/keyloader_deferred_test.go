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
	"bytes"
	"crypto/x509"
	"io"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type deferredTestSigner struct {
	cert *x509.Certificate
}

func (s deferredTestSigner) Sign(r io.Reader) ([]byte, error) { return io.ReadAll(r) }
func (s deferredTestSigner) KeyID() (string, error)           { return "deferred-key", nil }
func (s deferredTestSigner) Verifier() (cryptoutil.Verifier, error) {
	return nil, nil
}
func (s deferredTestSigner) Certificate() *x509.Certificate     { return s.cert }
func (s deferredTestSigner) Intermediates() []*x509.Certificate { return nil }
func (s deferredTestSigner) Roots() []*x509.Certificate         { return nil }

func TestDeferredTrustSignerLoadsAtFirstSignature(t *testing.T) {
	t.Parallel()

	loads := 0
	cert := &x509.Certificate{}
	signer := &deferredTrustSigner{load: func() (cryptoutil.Signer, error) {
		loads++
		return deferredTestSigner{cert: cert}, nil
	}}

	assert.Equal(t, 0, loads, "constructing the signer must not mint a short-lived certificate")
	signature, err := signer.Sign(bytes.NewBufferString("after-command"))
	require.NoError(t, err)
	assert.Equal(t, []byte("after-command"), signature)
	assert.Equal(t, 1, loads, "the certificate is minted at the first actual signature")

	keyID, err := signer.KeyID()
	require.NoError(t, err)
	assert.Equal(t, "deferred-key", keyID)
	assert.Same(t, cert, signer.Certificate())
	assert.Equal(t, 1, loads, "key and trust-bundle reads must reuse the signing certificate")
}

func TestDeferredTrustSignerCachesLoadFailure(t *testing.T) {
	t.Parallel()

	loads := 0
	signer := &deferredTrustSigner{load: func() (cryptoutil.Signer, error) {
		loads++
		return nil, assert.AnError
	}}

	_, firstErr := signer.Sign(bytes.NewBufferString("one"))
	_, secondErr := signer.Sign(bytes.NewBufferString("two"))
	assert.ErrorIs(t, firstErr, assert.AnError)
	assert.ErrorIs(t, secondErr, assert.AnError)
	assert.Equal(t, 1, loads, "a failed identity ceremony must not be repeated implicitly")
}
