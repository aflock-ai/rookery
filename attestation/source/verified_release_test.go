// Copyright 2026 TestifySec, Inc.
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

package source

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// R1 part 3 (#7611, #7590): once DSSE PAE verification has consumed the raw
// payload bytes — signature check + the artifact-substitution subject guard —
// the envelope bytes are dead weight on the result. Everything downstream
// reads the PARSED forms: the policy gate reads Statement/Collection, rego
// reads the attestor (Statement.Predicate stays retained), the dedup key
// hashes the Statement + verified-signer set, and the diagnostic paths read
// Statement.Subject. Retaining Payload (a full copy of statement+predicate)
// and Signatures (certs, KBs each) per result multiplied resident bytes per
// candidate across the whole traversal (#7572).

// TestVerifiedSearch_ReleasesEnvelopeBytesOnPass: a verified, subject-matched
// result must carry no raw envelope bytes.
func TestVerifiedSearch_ReleasesEnvelopeBytesOnPass(t *testing.T) {
	signed, verifier := signedCollectionForSubject(t, "rel-ref-1", "step1", "sha256", attestedDigest)
	// Parse through the real source pipeline so Collection is populated the
	// way EntSource/MemorySource populate it (signedCollectionForSubject
	// leaves it empty).
	ce, err := envelopeToCollectionEnvelope("rel-ref-1", signed.Envelope)
	require.NoError(t, err)
	vs := NewVerifiedSource(&lyingSourcer{env: ce}, dsse.VerifyWithVerifiers(verifier))

	results, serr := vs.Search(context.Background(), "step1", []string{attestedDigest}, nil)
	require.NoError(t, serr)
	require.Len(t, results, 1)
	r := results[0]

	require.NotEmpty(t, r.Verifiers, "control: the candidate must verify")
	assert.Empty(t, r.Envelope.Payload,
		"verified result must not retain raw payload bytes — verification and the subject guard already consumed them; the parsed Statement is the retained form")
	assert.Empty(t, r.Envelope.Signatures,
		"verified result must not retain signature/cert bytes — ValidFunctionaries/Verifiers carry the verified identities")

	// The parsed, verdict-bearing forms MUST survive the release.
	assert.NotEmpty(t, r.Statement.Subject, "parsed statement must be retained")
	assert.Equal(t, "step1", r.Collection.Name, "parsed collection must be retained")
}

// TestVerifiedSearch_ReleasesEnvelopeBytesOnRejection: a candidate whose
// signature does NOT verify is rejected with recorded errors; its bytes are
// equally dead weight (rejection reasons and diagnostics read the Statement
// and Errors, never the bytes).
func TestVerifiedSearch_ReleasesEnvelopeBytesOnRejection(t *testing.T) {
	ce, _ := signedCollectionForSubject(t, "rel-ref-2", "step1", "sha256", attestedDigest)

	// Verify against a DIFFERENT key so signature verification fails.
	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherVerifier := cryptoutil.NewRSAVerifier(&otherPriv.PublicKey, crypto.SHA256)
	vs := NewVerifiedSource(&lyingSourcer{env: ce}, dsse.VerifyWithVerifiers(otherVerifier))

	results, err := vs.Search(context.Background(), "step1", []string{attestedDigest}, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]

	require.Empty(t, r.Verifiers, "control: the candidate must fail verification")
	require.NotEmpty(t, r.Errors, "control: the rejection reason must be recorded")
	assert.Empty(t, r.Envelope.Payload, "rejected result must not retain raw payload bytes")
	assert.Empty(t, r.Envelope.Signatures, "rejected result must not retain signature bytes")
}

// TestVerifiedSearch_ReleaseDoesNotCorruptTheSource: the release must operate
// on the result copy, never the underlying source's stored envelope — a
// second search of the same MemorySource-backed envelope must still verify
// (the source still holds the bytes).
func TestVerifiedSearch_ReleaseDoesNotCorruptTheSource(t *testing.T) {
	ce, verifier := signedCollectionForSubject(t, "rel-ref-3", "step1", "sha256", attestedDigest)
	mem := NewMemorySource()
	require.NoError(t, mem.LoadEnvelope("rel-ref-3", ce.Envelope))
	vs := NewVerifiedSource(mem, dsse.VerifyWithVerifiers(verifier))

	for i := 0; i < 2; i++ {
		results, err := vs.Search(context.Background(), "step1", []string{attestedDigest}, nil)
		require.NoError(t, err)
		require.Len(t, results, 1)
		require.NotEmpty(t, results[0].Verifiers,
			"search %d must still verify: releasing result bytes must not mutate the source's stored envelope", i)
	}
}
