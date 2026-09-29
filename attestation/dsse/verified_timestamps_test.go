// Copyright 2026 The Witness Contributors
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
	"crypto/x509"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/timestamp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifySurfacesVerifiedTimestamps proves that the TSA-verified genTime is
// carried out of Envelope.Verify on the passing CheckedVerifier — the trusted
// time that policy timestampConstraint enforcement consumes.
func TestVerifySurfacesVerifiedTimestamps(t *testing.T) {
	root, rootPriv, err := createRoot()
	require.NoError(t, err)
	intermediate, intermediatePriv, err := createIntermediate(root, rootPriv)
	require.NoError(t, err)
	leaf, leafPriv, err := createLeaf(intermediate, intermediatePriv)
	require.NoError(t, err)

	s, err := cryptoutil.NewSigner(leafPriv,
		cryptoutil.SignWithCertificate(leaf),
		cryptoutil.SignWithIntermediates([]*x509.Certificate{intermediate}))
	require.NoError(t, err)

	tsTime := time.Now()
	ts := timestamp.FakeTimestamper{T: tsTime}
	env, err := Sign("test", bytes.NewReader([]byte("timestamped")),
		SignWithSigners(s), SignWithTimestampers(ts))
	require.NoError(t, err)

	checked, err := env.Verify(
		VerifyWithRoots(root),
		VerifyWithIntermediates(intermediate),
		VerifyWithTimestampVerifiers(ts),
		VerifyWithThreshold(1),
	)
	require.NoError(t, err)

	found := false
	for _, cv := range checked {
		if cv.Error == nil && len(cv.VerifiedTimestamps) > 0 {
			found = true
			assert.True(t, cv.VerifiedTimestamps[0].Equal(tsTime),
				"verified timestamp should be the TSA-attested time")
		}
	}
	assert.True(t, found, "a passing verifier should carry the TSA-verified timestamp")
}

// TestVerifyRawKeyCarriesVerifiedTimestamps: a raw-key signature's RFC3161
// token is verified too, so a publickey functionary can meet a
// timestampConstraint. A token that does not verify adds no time and does not
// fail the signature.
func TestVerifyRawKeyCarriesVerifiedTimestamps(t *testing.T) {
	signer, verifier, err := createTestKey()
	require.NoError(t, err)

	tsTime := time.Now().Truncate(time.Second)
	ts := timestamp.FakeTimestamper{T: tsTime}
	env, err := Sign("test", bytes.NewReader([]byte("raw-key timestamped")),
		SignWithSigners(signer), SignWithTimestampers(ts))
	require.NoError(t, err)

	checked, err := env.Verify(VerifyWithVerifiers(verifier), VerifyWithTimestampVerifiers(ts))
	require.NoError(t, err)
	require.Len(t, checked, 1)
	require.NoError(t, checked[0].Error)
	require.Len(t, checked[0].VerifiedTimestamps, 1)
	assert.True(t, checked[0].VerifiedTimestamps[0].Equal(tsTime))

	other := timestamp.FakeTimestamper{T: tsTime.Add(time.Hour)}
	checked, err = env.Verify(VerifyWithVerifiers(verifier), VerifyWithTimestampVerifiers(other))
	require.NoError(t, err, "an unverifiable token must not fail a valid raw-key signature")
	require.Empty(t, checked[0].VerifiedTimestamps)
}
