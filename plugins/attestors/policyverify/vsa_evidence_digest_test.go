// Copyright 2026 The Archivista Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policyverify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const vsaTestDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" // 64 hex chars (sha256-shaped)

// signedCollectionEnvelope builds a validly-signed collection envelope
// attesting one subject digest, returning it with its verifier and the exact
// payload bytes that were signed.
func signedCollectionEnvelope(t *testing.T, ref, collectionName string) (source.CollectionEnvelope, cryptoutil.Verifier, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	predicate, err := json.Marshal(attestation.Collection{Name: collectionName})
	require.NoError(t, err)
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       []intoto.Subject{{Name: "artifact", Digest: map[string]string{"sha256": vsaTestDigest}}},
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(payload), dsse.SignWithSigners(signer))
	require.NoError(t, err)

	return source.CollectionEnvelope{Envelope: env, Statement: stmt, Reference: ref}, verifier, payload
}

type fixedSourcer struct{ env source.CollectionEnvelope }

func (f *fixedSourcer) Search(_ context.Context, _ string, _, _ []string) ([]source.CollectionEnvelope, error) {
	return []source.CollectionEnvelope{f.env}, nil
}

func (f *fixedSourcer) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// The VSA's inputAttestations must digest the EVIDENCE THAT WAS VERIFIED —
// the exact signed payload bytes of each passed collection. VerifiedSource
// releases raw payload bytes from results after signature verification (they
// are dead weight for the policy gate), so the digest must be captured at
// release time and carried on the result; otherwise the signed VSA either
// records the digest of empty bytes or silently drops the evidence
// descriptor, both of which misrepresent what was verified.
func TestVSAInputAttestations_DigestTheVerifiedEvidence(t *testing.T) {
	ce, verifier, payload := signedCollectionEnvelope(t, "vsa-ref-1", "step1")

	actx, err := attestation.NewContext("vsa-test", nil)
	require.NoError(t, err)

	vs := source.NewVerifiedSource(&fixedSourcer{env: ce}, dsse.VerifyWithVerifiers(verifier)).
		WithEvidenceHashes(actx.Hashes())
	results, err := vs.Search(context.Background(), "step1", []string{vsaTestDigest}, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NotEmpty(t, results[0].Verifiers, "fixture must verify — otherwise the test cannot reach the passed-evidence path")

	stepResults := map[string]policy.StepResult{
		"step1": {
			Step:   "step1",
			Passed: []policy.PassedCollection{{Collection: results[0]}},
		},
	}

	policyEnv := dsse.Envelope{Payload: []byte(`{"fake":"policy"}`), PayloadType: "application/vnd.in-toto+json"}
	summary, err := verificationSummaryFromResults(actx, policyEnv, stepResults, true)
	require.NoError(t, err)

	want, err := cryptoutil.CalculateDigestSetFromBytes(payload, actx.Hashes())
	require.NoError(t, err)

	require.Len(t, summary.InputAttestations, 1,
		"the passed collection's evidence descriptor must not be silently dropped from the VSA")
	got := summary.InputAttestations[0]
	assert.Equal(t, "vsa-ref-1", got.URI)
	assert.Equal(t, want, got.Digest,
		"VSA evidence digest must be the digest of the exact signed payload bytes that were verified — not empty bytes, not a re-marshal")
}

// Back-compat: a result that still carries its payload (a source path that
// does not release bytes) must keep producing the same digests as before.
func TestVSAInputAttestations_PayloadStillPresentBackCompat(t *testing.T) {
	ce, verifier, payload := signedCollectionEnvelope(t, "vsa-ref-2", "step1")

	actx, err := attestation.NewContext("vsa-test", nil)
	require.NoError(t, err)

	// No WithEvidenceHashes: this caller never opted in, so Search must not
	// be assumed to have stored digests. The summary must fall back to
	// digesting the payload directly when it is still present.
	cvr := source.CollectionVerificationResult{
		Verifiers:          []cryptoutil.Verifier{verifier},
		ValidFunctionaries: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: ce,
	}
	stepResults := map[string]policy.StepResult{
		"step1": {Step: "step1", Passed: []policy.PassedCollection{{Collection: cvr}}},
	}

	policyEnv := dsse.Envelope{Payload: []byte(`{"fake":"policy"}`), PayloadType: "application/vnd.in-toto+json"}
	summary, err := verificationSummaryFromResults(actx, policyEnv, stepResults, true)
	require.NoError(t, err)

	want, err := cryptoutil.CalculateDigestSetFromBytes(payload, actx.Hashes())
	require.NoError(t, err)

	require.Len(t, summary.InputAttestations, 1)
	assert.Equal(t, want, summary.InputAttestations[0].Digest)
}
