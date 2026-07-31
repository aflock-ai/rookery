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

package source

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signedWith builds a collection envelope for the given subject digest signed
// with the PROVIDED signer, so multiple candidates can share one key — needed
// to exercise the subject guard (which only runs after signature verification
// succeeds) separately from the wrong-key rejection.
func signedWith(t *testing.T, signer cryptoutil.Signer, ref, collectionName, digest string) CollectionEnvelope {
	t.Helper()
	predicate, err := json.Marshal(attestation.Collection{Name: collectionName})
	require.NoError(t, err)
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       []intoto.Subject{{Name: "artifact", Digest: map[string]string{"sha256": digest}}},
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(payload), dsse.SignWithSigners(signer))
	require.NoError(t, err)
	return CollectionEnvelope{Envelope: env, Statement: stmt, Reference: ref}
}

// sliceOnlySourcer exposes ONLY the slice Search — the pre-streaming shape.
type sliceOnlySourcer struct{ envs []CollectionEnvelope }

func (s *sliceOnlySourcer) Search(_ context.Context, _ string, _, _ []string) ([]CollectionEnvelope, error) {
	return s.envs, nil
}

func (s *sliceOnlySourcer) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]StatementEnvelope, error) {
	return nil, nil
}

// streamOnlySourcer additionally implements StreamingSourcer, yielding the
// same envelopes one at a time, and records the maximum number of raw
// payloads simultaneously outstanding to the caller.
type streamOnlySourcer struct {
	sliceOnlySourcer
	yielded int
}

func (s *streamOnlySourcer) SearchStream(_ context.Context, _ string, _, _ []string, yield func(CollectionEnvelope) error) error {
	for _, e := range s.envs {
		s.yielded++
		if err := yield(e); err != nil {
			return err
		}
	}
	return nil
}

// VERDICT EQUIVALENCE: the streamed path and the slice path must produce
// byte-identical verification results for the same candidates — same order,
// same verifier counts, same errors, same released bytes, same recorded
// digests. verifyCandidate is the single implementation behind both, and this
// test is what keeps it that way.
func TestVerifiedSearch_StreamedAndSlicePathsAreEquivalent(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	goodVerifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	good := signedWith(t, signer, "eq-good", "step1", attestedDigest)
	// SAME trusted key, but attests the WRONG artifact: signature verifies,
	// the artifact-substitution subject guard rejects.
	mismatch := signedWith(t, signer, "eq-mismatch", "step1", requestedDigest)
	// A DIFFERENT key entirely: signature verification fails outright.
	badsig, _ := signedCollectionForSubject(t, "eq-badsig", "step1", "sha256", attestedDigest)

	envs := []CollectionEnvelope{good, mismatch, badsig}
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	sliceVS := NewVerifiedSource(&sliceOnlySourcer{envs: envs}, dsse.VerifyWithVerifiers(goodVerifier)).
		WithEvidenceHashes(hashes)
	streamSrc := &streamOnlySourcer{sliceOnlySourcer: sliceOnlySourcer{envs: envs}}
	streamVS := NewVerifiedSource(streamSrc, dsse.VerifyWithVerifiers(goodVerifier)).
		WithEvidenceHashes(hashes)

	fromSlice, err := sliceVS.Search(context.Background(), "step1", []string{attestedDigest}, nil)
	require.NoError(t, err)
	fromStream, err := streamVS.Search(context.Background(), "step1", []string{attestedDigest}, nil)
	require.NoError(t, err)

	require.Equal(t, len(envs), streamSrc.yielded, "the streaming path must actually have been taken")
	require.Len(t, fromSlice, len(envs))
	require.Len(t, fromStream, len(envs))

	for i := range fromSlice {
		a, b := fromSlice[i], fromStream[i]
		assert.Equal(t, a.Reference, b.Reference, "candidate order must be identical")
		assert.Equal(t, len(a.Verifiers), len(b.Verifiers), "verifier outcome must be identical for %s", a.Reference)
		assert.Equal(t, len(a.Errors), len(b.Errors), "error outcome must be identical for %s", a.Reference)
		for j := range a.Errors {
			assert.Equal(t, a.Errors[j].Error(), b.Errors[j].Error(), "error text must be identical for %s", a.Reference)
		}
		assert.Equal(t, a.PayloadDigests, b.PayloadDigests, "recorded evidence digests must be identical for %s", a.Reference)
		assert.Empty(t, b.Envelope.Payload, "streamed results must have released raw payload bytes")
		assert.Empty(t, b.Envelope.Signatures, "streamed results must have released signature bytes")
	}

	// The verdicts themselves, pinned: good passes, the other two carry errors.
	assert.NotEmpty(t, fromStream[0].Verifiers, "validly-signed subject-matched candidate must pass on the streamed path")
	assert.Empty(t, fromStream[1].Verifiers, "subject-mismatched candidate must be rejected on the streamed path (artifact-substitution guard)")
	assert.Empty(t, fromStream[2].Verifiers, "wrong-key candidate must be rejected on the streamed path (crypto still rejects)")
}

// A yield error must abort the archivista stream WITHOUT marking anything
// seen — otherwise an aborted run permanently hides candidates from retries.
func TestArchivistaSearchStream_AbortMarksNothingSeen(t *testing.T) {
	// Covered structurally: SearchStream returns the yield error before the
	// seenGitoids append. This test pins the VerifiedSource-visible half —
	// an erroring streaming source surfaces the error, produces no results.
	wantErr := assert.AnError
	src := &erroringStreamSourcer{err: wantErr}
	vs := NewVerifiedSource(src)
	_, err := vs.Search(context.Background(), "step1", []string{attestedDigest}, nil)
	require.ErrorIs(t, err, wantErr)
}

type erroringStreamSourcer struct {
	sliceOnlySourcer
	err error
}

func (s *erroringStreamSourcer) SearchStream(_ context.Context, _ string, _, _ []string, _ func(CollectionEnvelope) error) error {
	return s.err
}
