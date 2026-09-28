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

package dsse

import (
	"bytes"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// An envelope signed by a CA key that presents its own CA certificate as the
// signing certificate must not verify, end to end (model T1).
func TestVerify_RejectsEnvelopeSignedWithCACertificate(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)

	verify := func(env Envelope) error {
		_, err := env.Verify(
			VerifyWithRoots(root),
			VerifyWithIntermediates(intermediate),
			VerifyWithThreshold(1),
			VerifyWithCurrentTimeFallback(),
		)
		return err
	}

	caSigner, err := cryptoutil.NewSigner(intermediatePriv, cryptoutil.SignWithCertificate(intermediate))
	require.NoError(t, err)
	caEnv, err := Sign("test", bytes.NewReader([]byte("signed by a CA key")), SignWithSigners(caSigner))
	require.NoError(t, err)
	require.Error(t, verify(caEnv), "an envelope whose signing certificate is a CA must not verify")

	rootSigner, err := cryptoutil.NewSigner(rootPriv, cryptoutil.SignWithCertificate(root))
	require.NoError(t, err)
	rootEnv, err := Sign("test", bytes.NewReader([]byte("signed by the root key")), SignWithSigners(rootSigner))
	require.NoError(t, err)
	require.Error(t, verify(rootEnv), "an envelope signed by the root presenting the root certificate must not verify")

	// Control: the same chain with a real leaf verifies.
	leafSigner, err := cryptoutil.NewSigner(leafPriv, cryptoutil.SignWithCertificate(leaf))
	require.NoError(t, err)
	leafEnv, err := Sign("test", bytes.NewReader([]byte("signed by a leaf")), SignWithSigners(leafSigner))
	require.NoError(t, err)
	require.NoError(t, verify(leafEnv))
}
