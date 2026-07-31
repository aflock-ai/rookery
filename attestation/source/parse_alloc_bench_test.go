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

package source

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

// buildLargeCollectionPayload builds a prod-shaped in-toto statement payload:
// a collection predicate carrying one big raw attestation body (models an SBOM
// or SARIF document of predicateBytes size) plus subjectCount subjects (models
// the per-file product/material subjects a monorepo CI collection carries).
// Returns the marshaled payload bytes and the first subject's digest.
func buildLargeCollectionPayload(tb testing.TB, collectionName string, subjectCount, predicateBytes int) ([]byte, string) {
	tb.Helper()

	// A single attestation whose body is one large JSON string. The attestor
	// type is deliberately unregistered so CollectionAttestation.UnmarshalJSON
	// takes the RawAttestation path — the attestation-module baseline. (In
	// judge-api all plugin factories are registered, so typed parses are
	// strictly MORE expensive than what this fixture measures.)
	filler := strings.Repeat("a", predicateBytes)
	predicate := fmt.Sprintf(
		`{"name":%q,"attestations":[{"type":"https://example.com/bench-sbom/v0.1","attestation":{"doc":%q},"starttime":"2026-01-01T00:00:00Z","endtime":"2026-01-01T00:00:01Z"}]}`,
		collectionName, filler,
	)

	subjects := make([]intoto.Subject, 0, subjectCount)
	firstDigest := ""
	for i := 0; i < subjectCount; i++ {
		d := fmt.Sprintf("%064x", i+1)
		if firstDigest == "" {
			firstDigest = d
		}
		subjects = append(subjects, intoto.Subject{
			Name:   fmt.Sprintf("file:src/pkg/module%04d/file%04d.go", i/16, i),
			Digest: map[string]string{"sha256": d},
		})
	}

	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       subjects,
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		tb.Fatalf("marshal statement: %v", err)
	}
	return payload, firstDigest
}

// signedEnvelopeFromPayload signs payload and returns the envelope plus the
// verifier for its key.
func signedEnvelopeFromPayload(tb testing.TB, payload []byte) (dsse.Envelope, cryptoutil.Verifier) {
	tb.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(payload), dsse.SignWithSigners(signer))
	if err != nil {
		tb.Fatalf("sign envelope: %v", err)
	}
	return env, verifier
}

// BenchmarkPayloadMatchesSubjects_LargePredicate measures the per-candidate
// cost of the artifact-substitution guard on a prod-shaped payload (~8 MB
// predicate, 2k subjects). The guard runs once per candidate envelope per
// VerifiedSource.Search call — i.e. once per step per search depth in the
// policy engine — so its bytes/op multiply directly into verification-turn
// footprint.
func BenchmarkPayloadMatchesSubjects_LargePredicate(b *testing.B) {
	payload, digest := buildLargeCollectionPayload(b, "bench-step", 2000, 8<<20)
	subjectDigests := []string{digest}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ok, err := payloadMatchesSubjects(payload, subjectDigests)
		if err != nil || !ok {
			b.Fatalf("expected match, got ok=%v err=%v", ok, err)
		}
	}
}

// BenchmarkVerifiedSourceSearch_LargeEnvelope measures one full
// VerifiedSource.Search over a single large signed envelope: signature verify +
// substitution guard. In the policy engine this whole cost repeats per step per
// depth when the underlying source has no seen-envelope exclusion.
func BenchmarkVerifiedSourceSearch_LargeEnvelope(b *testing.B) {
	payload, digest := buildLargeCollectionPayload(b, "bench-step", 2000, 8<<20)
	env, verifier := signedEnvelopeFromPayload(b, payload)

	mem := NewMemorySource()
	if err := mem.LoadEnvelope("bench-ref", env); err != nil {
		b.Fatalf("load envelope: %v", err)
	}
	vs := NewVerifiedSource(mem, dsse.VerifyWithVerifiers(verifier))

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := vs.Search(context.Background(), "bench-step", []string{digest}, nil)
		if err != nil || len(results) != 1 {
			b.Fatalf("expected 1 result, got %d err=%v", len(results), err)
		}
	}
}

// TestPayloadMatchesSubjects_DoesNotRetainPredicate locks the allocation bound
// of the substitution guard: matching subjects out of a signed payload must not
// materialize a copy of the (potentially tens-of-MB) predicate body. The guard
// needs only the subject list.
//
// Bound rationale: the payload is ~8.2 MB. Decoding the FULL intoto.Statement
// copies the predicate into a fresh json.RawMessage (~8 MB) per call. Decoding
// only the subjects allocates the subject slice + strings (~500 KB here). The
// 4 MB/op bound cleanly separates the two implementations while leaving slack
// for decoder internals.
func TestPayloadMatchesSubjects_DoesNotRetainPredicate(t *testing.T) {
	payload, digest := buildLargeCollectionPayload(t, "bench-step", 2000, 8<<20)
	subjectDigests := []string{digest}

	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ok, err := payloadMatchesSubjects(payload, subjectDigests)
			if err != nil || !ok {
				b.Fatalf("expected match, got ok=%v err=%v", ok, err)
			}
		}
	})

	const maxBytesPerOp = 4 << 20 // 4 MB
	if res.AllocedBytesPerOp() > maxBytesPerOp {
		t.Fatalf("payloadMatchesSubjects allocates %d B/op (> %d B/op): the subject guard is copying the full predicate body instead of decoding only the subject list",
			res.AllocedBytesPerOp(), maxBytesPerOp)
	}
}
