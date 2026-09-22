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
	"os"
	"path/filepath"
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

// signedCollectionProjectionSpoof signs a collection payload and hands back a
// candidate whose PROJECTION (Statement, Collection, PayloadDigests) was built
// by the source from different bytes. The signed subject is attestedDigest in
// both, so the subject guard passes and only the projection differs.
func signedCollectionProjectionSpoof(t *testing.T) (signed CollectionEnvelope, spoofed CollectionEnvelope, verifier cryptoutil.Verifier) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier = cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)

	mkPayload := func(predicate, extraSubject string) []byte {
		subjects := `{"name":"artifact","digest":{"sha256":"` + attestedDigest + `"}}`
		if extraSubject != "" {
			subjects += `,{"name":"artifact2","digest":{"sha256":"` + extraSubject + `"}}`
		}
		return []byte(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[` + subjects +
			`],"predicateType":"https://aflock.ai/attestation-collection/v0.1","predicate":` + predicate + `}`)
	}
	signedPayload := mkPayload(`{"name":"step1","attestations":[{"type":"https://example.test/attestations/signed/v0.1","attestation":{"k":"signed"},"starttime":"2026-01-01T00:00:00Z","endtime":"2026-01-01T00:00:01Z"}]}`, "")
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(signedPayload), dsse.SignWithSigners(signer))
	require.NoError(t, err)
	signed, err = EnvelopeToCollectionEnvelope("spoof-ref", env)
	require.NoError(t, err)

	// The source decodes bytes nobody signed: another step name, another
	// attestation type, an extra subject and a back-reference edge.
	projected := mkPayload(`{"name":"step1-projected","attestations":[{"type":"https://example.test/attestations/projected/v0.1","attestation":{"k":"projected"},"starttime":"2026-01-01T00:00:00Z","endtime":"2026-01-01T00:00:01Z"}],"backrefs":{"https://example.test/attestations/projected/v0.1/commit":{"sha256":"`+requestedDigest+`"}}}`, requestedDigest)
	fromOther, err := EnvelopeToCollectionEnvelope("spoof-ref", dsse.Envelope{PayloadType: env.PayloadType, Payload: projected})
	require.NoError(t, err)
	spoofed = CollectionEnvelope{
		Envelope:       env,
		Statement:      fromOther.Statement,
		Collection:     fromOther.Collection,
		Reference:      "spoof-ref",
		PayloadDigests: cryptoutil.DigestSet{{Hash: crypto.SHA256}: requestedDigest},
	}
	return signed, spoofed, verifier
}

func attestationTypes(c attestation.Collection) []string {
	types := make([]string, 0, len(c.Attestations))
	for _, a := range c.Attestations {
		types = append(types, a.Type)
	}
	return types
}

// assertProjectionIsSigned checks every projected field a policy verdict reads
// against the decode of the signed payload.
func assertProjectionIsSigned(t *testing.T, want CollectionEnvelope, got CollectionVerificationResult, label string) {
	t.Helper()
	assert.Equal(t, want.Collection.Name, got.Collection.Name, "%s: collection name must come from the signed payload", label)
	assert.Equal(t, attestationTypes(want.Collection), attestationTypes(got.Collection), "%s: attestation types must come from the signed payload", label)
	assert.Equal(t, want.Collection.BackRefs(), got.Collection.BackRefs(), "%s: back-references must come from the signed payload", label)
	assert.Equal(t, want.Collection.Subjects(), got.Collection.Subjects(), "%s: collection subjects must come from the signed payload", label)
	assert.Equal(t, want.Statement.Type, got.Statement.Type, "%s: statement type must come from the signed payload", label)
	assert.Equal(t, want.Statement.Subject, got.Statement.Subject, "%s: statement subjects must come from the signed payload", label)
	assert.Equal(t, want.Statement.PredicateType, got.Statement.PredicateType, "%s: predicate type must come from the signed payload", label)
}

// A source that passes the signature and subject checks on real signed
// evidence must not also choose what the verified result says: the step
// name, attestation types, back-references and statement subjects a policy
// reads have to be decoded from the signed payload. Both the slice and the
// streamed Search paths are checked, since both go through verifyCandidate.
func TestVerifiedSource_RejectsCollectionProjectionSpoof(t *testing.T) {
	signed, spoofed, verifier := signedCollectionProjectionSpoof(t)
	require.NotEqual(t, signed.Collection.Name, spoofed.Collection.Name, "control: the projection must actually differ from the signed payload")

	slice := NewVerifiedSource(&lyingSourcer{env: spoofed}, dsse.VerifyWithVerifiers(verifier))
	stream := NewVerifiedSource(&streamOnlySourcer{sliceOnlySourcer: sliceOnlySourcer{envs: []CollectionEnvelope{spoofed}}}, dsse.VerifyWithVerifiers(verifier))
	for label, vs := range map[string]*VerifiedSource{"slice": slice, "stream": stream} {
		results, err := vs.Search(context.Background(), "step1", []string{attestedDigest}, nil)
		require.NoError(t, err)
		require.Len(t, results, 1)
		r := results[0]
		require.NotEmpty(t, r.Verifiers, "%s: control: signature and signed subject are genuine, so the candidate verifies", label)
		require.Empty(t, r.Errors, label)
		assertProjectionIsSigned(t, signed, r, label)
		assert.Empty(t, r.PayloadDigests, "%s: payload digests are recorded by the verifier, never taken from the source", label)
		assert.Equal(t, "spoof-ref", r.Reference, label)
	}
}

// A payload whose signature and subjects verify but that the source decoder
// refuses is not a verified collection: the candidate fails rather than
// falling back to whatever the source projected.
func TestVerifiedSource_RejectsUndecodableSignedPayload(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	subject := `"subject":[{"name":"artifact","digest":{"sha256":"` + attestedDigest + `"}}]`

	for name, payload := range map[string]string{
		"predicate is not a collection": `{"_type":"https://in-toto.io/Statement/v0.1",` + subject + `,"predicateType":"https://aflock.ai/attestation-collection/v0.1","predicate":["not","a","collection"]}`,
		"empty predicateType":           `{"_type":"https://in-toto.io/Statement/v0.1",` + subject + `,"predicateType":"","predicate":{"name":"step1"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader([]byte(payload)), dsse.SignWithSigners(signer))
			require.NoError(t, err)
			ok, err := payloadMatchesSubjects(env.Payload, []string{attestedDigest})
			require.NoError(t, err)
			require.True(t, ok, "control: the signed subject check passes, so only the decode can reject")

			projected := CollectionEnvelope{
				Envelope:       env,
				Reference:      "undecodable",
				Collection:     attestation.Collection{Name: "step1"},
				PayloadDigests: cryptoutil.DigestSet{{Hash: crypto.SHA256}: requestedDigest},
			}
			vs := NewVerifiedSource(&lyingSourcer{env: projected}, dsse.VerifyWithVerifiers(verifier))
			results, err := vs.Search(context.Background(), "step1", []string{attestedDigest}, nil)
			require.NoError(t, err)
			require.Len(t, results, 1)
			assert.Empty(t, results[0].Verifiers, "an undecodable signed payload must not verify")
			assert.Empty(t, results[0].VerifiedTimestampsByKeyID)
			assert.NotEmpty(t, results[0].Errors)
			assert.Empty(t, results[0].Envelope.Payload, "a rejected candidate releases its payload")
			assert.Empty(t, results[0].PayloadDigests, "a rejected candidate carries no source-supplied payload digests")
		})
	}
}

// recordedCollectionFixtures returns every recorded attestation fixture in the
// rookery tree, re-signed with a test key. The payload bytes are the recorded
// ones; only the signature is replaced, since the recorded keyless signatures
// have no trust root here.
func recordedCollectionFixtures(t testing.TB) (map[string]dsse.Envelope, cryptoutil.Verifier) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)

	var paths []string
	for _, pattern := range []string{
		"../../plugins/attestors/*/testdata/fixtures/*/attestation.json",
		"../../examples/*/attestation.json",
	} {
		matches, err := filepath.Glob(pattern)
		require.NoError(t, err)
		paths = append(paths, matches...)
	}
	require.GreaterOrEqual(t, len(paths), 27, "the recorded fixtures must be found, or this guard checks nothing")

	fixtures := make(map[string]dsse.Envelope, len(paths))
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		require.NoError(t, err)
		var recorded dsse.Envelope
		require.NoError(t, json.Unmarshal(raw, &recorded), p)
		env, err := dsse.Sign(recorded.PayloadType, bytes.NewReader(recorded.Payload), dsse.SignWithSigners(signer))
		require.NoError(t, err, p)
		require.Equal(t, recorded.Payload, env.Payload, p)
		fixtures[p] = env
	}
	return fixtures, cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
}

// matchableSubjectDigest returns one subject digest the signed subject guard
// accepts for ce, so the fixture is searched with the guard engaged.
func matchableSubjectDigest(ce CollectionEnvelope) string {
	scope := ce.SubjectMatchScope()
	for _, sub := range ce.Statement.Subject {
		for algorithm, digest := range sub.Digest {
			if scope.IsMatchableSubjectDigest(sub.Name, algorithm, digest) {
				return digest
			}
		}
	}
	return ""
}

// Honest sources (Memory, Archivista, judge-api's Ent) all build their
// projection by json-decoding the same signed payload, so for them the
// verifier's decode must be indistinguishable from the projection: same
// collection, same back-references, same subjects, same attestation types.
// Checked on every recorded fixture, through a real MemorySource and through
// a source that hands its decode over as-is.
func TestVerifiedSource_SignedDecodeMatchesHonestProjection(t *testing.T) {
	fixtures, verifier := recordedCollectionFixtures(t)
	withEdges := 0
	for p, env := range fixtures {
		honest, err := EnvelopeToCollectionEnvelope(p, env)
		require.NoError(t, err, p)
		if len(honest.Collection.BackRefs()) > 0 || len(honest.Collection.Subjects()) > 0 {
			withEdges++
		}
		var digests []string
		if d := matchableSubjectDigest(honest); d != "" {
			digests = []string{d}
		}

		mem := NewMemorySource()
		require.NoError(t, mem.LoadEnvelope(p, env), p)
		for label, src := range map[string]Sourcer{"memory": mem, "as-is": &lyingSourcer{env: honest}} {
			vs := NewVerifiedSource(src, dsse.VerifyWithVerifiers(verifier))
			results, err := vs.Search(context.Background(), honest.Collection.Name, digests, nil)
			require.NoError(t, err, p)
			require.Len(t, results, 1, p)
			r := results[0]
			require.NotEmpty(t, r.Verifiers, "%s %s: an honest fixture must still verify", label, p)
			require.Empty(t, r.Errors, "%s %s", label, p)
			assertProjectionIsSigned(t, honest, r, label+" "+p)
			assert.Equal(t, honest.Collection, r.Collection, "%s %s: the whole collection must equal the honest projection", label, p)
		}
	}
	t.Logf("%d recorded fixtures, %d with back-references or collection subjects", len(fixtures), withEdges)
	require.Positive(t, withEdges, "at least one fixture must carry back-references or collection subjects, or the comparison is vacuous")
}

// BenchmarkSignedPayloadDecode measures the decode verifyCandidate adds per
// passing candidate, against the signature verification it already pays,
// over the recorded fixtures.
func BenchmarkSignedPayloadDecode(b *testing.B) {
	fixtures, verifier := recordedCollectionFixtures(b)
	var total int64
	for _, env := range fixtures {
		total += int64(len(env.Payload))
	}
	b.Run("decode", func(b *testing.B) {
		b.SetBytes(total)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for p, env := range fixtures {
				if _, err := EnvelopeToCollectionEnvelope(p, env); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
	b.Run("verify", func(b *testing.B) {
		b.SetBytes(total)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			for _, env := range fixtures {
				if _, err := env.Verify(dsse.VerifyWithVerifiers(verifier)); err != nil {
					b.Fatal(err)
				}
			}
		}
	})
}
