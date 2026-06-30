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
//
// ============================================================================
// Artifact-substitution fail-closed acceptance tests (rookery red-team
// 2026-06-29). Promoted from the redgate scaffold now that VerifiedSource
// enforces the subject binding — the Green acceptance criteria + regression
// guard.
//
// The keyless model treats the attestation store as UNTRUSTED, so the
// subject-digest binding (does this collection actually attest the queried
// artifact?) must be re-checked client-side by the verifier. MemorySource does
// this (matchesSubjects), but the source-agnostic VerifiedSource — through which
// ArchivistaSource flows — only re-verifies SIGNATURES, never subjects. A
// compromised / MITM'd Archivista can therefore return a validly-signed
// collection for a DIFFERENT artifact; its signature passes and the wrong
// artifact is reported VERIFIED.
//
// This test asserts the CORRECT, fail-closed behavior. It FAILS against the
// current code and PASSES once VerifiedSource enforces the subject binding
// (Red phase of Red-Green-Refactor). Gated behind the `redgate` build tag.
// ============================================================================

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

// signedCollectionForSubject builds a VALIDLY-SIGNED collection envelope that
// attests exactly one subject digest, returning the candidate plus the verifier
// whose signature it carries.
func signedCollectionForSubject(t *testing.T, ref, collectionName, algo, digest string) (CollectionEnvelope, cryptoutil.Verifier) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	predicate, err := json.Marshal(attestation.Collection{Name: collectionName})
	require.NoError(t, err)
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       []intoto.Subject{{Name: "artifact", Digest: map[string]string{algo: digest}}},
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(payload), dsse.SignWithSigners(signer))
	require.NoError(t, err)

	return CollectionEnvelope{Envelope: env, Statement: stmt, Reference: ref}, verifier
}

// lyingSourcer returns its fixed envelope for ANY query — models a compromised
// or MITM'd Archivista that ignores the subject-digest filter and returns a
// collection for the wrong artifact.
type lyingSourcer struct{ env CollectionEnvelope }

func (l *lyingSourcer) Search(_ context.Context, _ string, _, _ []string) ([]CollectionEnvelope, error) {
	return []CollectionEnvelope{l.env}, nil
}

func (l *lyingSourcer) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]StatementEnvelope, error) {
	return nil, nil
}

const (
	attestedDigest  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // artifact the collection actually attests
	requestedDigest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" // artifact the verifier asked about
)

// A validly-signed collection whose subject does NOT match the requested
// artifact digest must be rejected — not accepted because its signature is good.
func TestVerifiedSource_RejectsSubjectMismatch(t *testing.T) {
	ce, verifier := signedCollectionForSubject(t, "ref1", "step1", "sha256", attestedDigest)
	vs := NewVerifiedSource(&lyingSourcer{env: ce}, dsse.VerifyWithVerifiers(verifier))

	results, err := vs.Search(context.Background(), "step1", []string{requestedDigest}, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	r := results[0]

	assert.Empty(t, r.Verifiers,
		"a validly-signed collection whose subject does not match the requested digest must NOT be accepted (artifact-substitution guard)")
	assert.NotEmpty(t, r.Errors,
		"subject-mismatched candidate must be rejected with an error, not pass silently")
}

// Control: when the subject DOES match, the validly-signed collection still
// passes (the guard must not over-reject). Passes on both pre- and post-fix.
func TestVerifiedSource_AcceptsSubjectMatch(t *testing.T) {
	ce, verifier := signedCollectionForSubject(t, "ref1", "step1", "sha256", attestedDigest)
	vs := NewVerifiedSource(&lyingSourcer{env: ce}, dsse.VerifyWithVerifiers(verifier))

	results, err := vs.Search(context.Background(), "step1", []string{attestedDigest}, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NotEmpty(t, results[0].Verifiers, "matching subject + valid signature must be accepted")
	assert.Empty(t, results[0].Errors)
}

// signedCollectionSpoofedStatement signs a payload attesting signedDigest but
// sets the CollectionEnvelope.Statement FIELD to claim claimedDigest — modeling
// a malicious/compromised source that populates the struct field independently
// of what the DSSE signature actually covers.
func signedCollectionSpoofedStatement(t *testing.T, ref, collectionName, signedDigest, claimedDigest string) (CollectionEnvelope, cryptoutil.Verifier) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	predicate, err := json.Marshal(attestation.Collection{Name: collectionName})
	require.NoError(t, err)
	mkStmt := func(digest string) intoto.Statement {
		return intoto.Statement{
			Type:          "https://in-toto.io/Statement/v0.1",
			Subject:       []intoto.Subject{{Name: "artifact", Digest: map[string]string{"sha256": digest}}},
			PredicateType: "https://aflock.ai/attestation-collection/v0.1",
			Predicate:     json.RawMessage(predicate),
		}
	}
	payload, err := json.Marshal(mkStmt(signedDigest)) // signature covers signedDigest
	require.NoError(t, err)
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(payload), dsse.SignWithSigners(signer))
	require.NoError(t, err)

	// The struct field LIES: it claims claimedDigest, not what was signed.
	return CollectionEnvelope{Envelope: env, Statement: mkStmt(claimedDigest), Reference: ref}, verifier
}

// A malicious source signs artifact X but sets the Statement FIELD to claim the
// requested artifact D. The guard must read subjects from the SIGNED payload
// (X), not the source-controlled Statement field (D), and reject — otherwise the
// substitution bypass survives even with the guard in place (Codex review of
// PR #6082).
func TestVerifiedSource_RejectsStatementFieldSpoof(t *testing.T) {
	ce, verifier := signedCollectionSpoofedStatement(t, "ref1", "step1", attestedDigest /*signed*/, requestedDigest /*claimed in struct*/)
	vs := NewVerifiedSource(&lyingSourcer{env: ce}, dsse.VerifyWithVerifiers(verifier))

	results, err := vs.Search(context.Background(), "step1", []string{requestedDigest}, nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Empty(t, results[0].Verifiers,
		"signed payload attests X; a source-set Statement field claiming the requested D must not be trusted")
	assert.NotEmpty(t, results[0].Errors)
}
