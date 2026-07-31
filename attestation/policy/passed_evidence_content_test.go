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

package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// goldenPassedEvidenceJSON pins the sha256 of one serialized passed
// collection produced by the STREAMED path over the fixture corpus below.
// The serialized form is the RESULT CONTRACT: full statement (including the
// raw predicate message) and full typed collection, with the envelope bytes
// released — exactly what callers received before pass-time compaction
// existed. The fixture is fully deterministic (fixed content, zero
// timestamps, and the crypto fields — verifiers — marshal to field-free
// objects), so the hash is stable across runs. Any change that guts, or
// reshapes, serialized passed evidence fails here.
const goldenPassedEvidenceJSON = "b269ffebbb671c12e0cc3aa4bab0fe1b56ea7209b0b4d3bcc55878cf0965e631"

// contentFixtureEnvelope builds one deterministic signed collection envelope
// for the content-contract tests: fixed subject digest, fixed raw-attestation
// payload, zero attestation timestamps.
func contentFixtureEnvelope(t *testing.T, f *fanoutFixture) source.CollectionEnvelope {
	t.Helper()
	return f.collection(t, "content-fixture", fanoutCommitDigest)
}

// TestPassedEvidenceContent_SerializedFormIsPreCompactionComplete closes the
// fingerprint gap the transcript golden cannot see: the transcript hashes
// verdicts, references and counts, so a change that strips the CONTENT of
// passed evidence (the decoded predicate and typed attestations) passes the
// transcript golden while breaking every JSON consumer of step results. This
// test pins the full serialized bytes of a passed collection three ways:
//
//  1. the STREAMED (interleaved) path,
//  2. the BATCH path (SearchStream hidden),
//  3. a reference built directly from the raw signed envelope — the
//     pre-compaction shape (envelope bytes released upstream, everything
//     else complete),
//
// and requires all three byte-identical, plus a committed golden hash so the
// contract cannot drift silently even if all in-tree paths drift together.
func TestPassedEvidenceContent_SerializedFormIsPreCompactionComplete(t *testing.T) {
	f := newFanoutFixture(t)
	env := contentFixtureEnvelope(t, f)

	mem := source.NewMemorySource()
	require.NoError(t, mem.LoadEnvelope(env.Reference, env.Envelope))
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))

	verifyOnce := func(src source.VerifiedSourcer) PassedCollection {
		accepted, results, err := f.policy(t).Verify(context.Background(),
			WithVerifiedSource(src),
			WithSubjectDigests([]string{fanoutCommitDigest}),
		)
		require.NoError(t, err)
		require.True(t, accepted)
		require.Len(t, results[fanoutStepName].Passed, 1)
		return results[fanoutStepName].Passed[0]
	}

	streamedPC := verifyOnce(vs)
	batchPC := verifyOnce(batchOnlyVerifiedSourcer{inner: vs})

	streamedJSON, err := json.Marshal(streamedPC)
	require.NoError(t, err)
	batchJSON, err := json.Marshal(batchPC)
	require.NoError(t, err)

	// Reference: the pre-compaction result shape, built from the raw signed
	// envelope itself. Content fields come from an independent decode of the
	// signed payload; the signature-derived fields (verifiers, functionary
	// set, timestamps) are compaction-invariant and copied from the result.
	stmt := intoto.Statement{}
	require.NoError(t, json.Unmarshal(env.Envelope.Payload, &stmt))
	coll := attestation.Collection{}
	require.NoError(t, json.Unmarshal(stmt.Predicate, &coll))
	reference := streamedPC.Collection
	reference.Envelope = dsse.Envelope{PayloadType: env.Envelope.PayloadType}
	reference.Statement = stmt
	reference.Collection = coll
	referenceJSON, err := json.Marshal(&struct {
		Collection  source.CollectionVerificationResult `json:"Collection"`
		AiResponses []AiResponse                        `json:"AiResponses,omitempty"`
	}{Collection: reference})
	require.NoError(t, err)

	assert.True(t, bytes.Equal(streamedJSON, batchJSON),
		"streamed and batch paths serialize passed evidence differently:\nstreamed: %s\nbatch:    %s", streamedJSON, batchJSON)
	assert.True(t, bytes.Equal(streamedJSON, referenceJSON),
		"serialized passed evidence diverges from the pre-compaction contract:\ngot:  %s\nwant: %s", streamedJSON, referenceJSON)

	// Content sanity — the golden must never pin a gutted shape.
	var decoded struct {
		Collection struct {
			Statement  intoto.Statement       `json:"Statement"`
			Collection attestation.Collection `json:"Collection"`
		} `json:"Collection"`
	}
	require.NoError(t, json.Unmarshal(streamedJSON, &decoded))
	require.NotEmpty(t, decoded.Collection.Statement.Predicate, "serialized statement lost its predicate")
	require.NotEmpty(t, decoded.Collection.Collection.Attestations, "serialized collection lost its typed attestations")

	sum := sha256.Sum256(streamedJSON)
	got := hex.EncodeToString(sum[:])
	if goldenPassedEvidenceJSON == "GOLDEN-CAPTURE" {
		t.Logf("GOLDEN CAPTURE: passed-evidence JSON sha256 = %s\nJSON: %s", got, streamedJSON)
		t.Fatal("goldenPassedEvidenceJSON is unset — commit the hash above")
	}
	assert.Equal(t, goldenPassedEvidenceJSON, got,
		"serialized passed-evidence bytes drifted from the committed golden\nJSON: %s", streamedJSON)
}

// TestPassedEvidenceContent_HydratedCollectionServesLeafReaders pins the
// public accessor: a compacted passed collection re-decodes its full typed
// collection (attestation set intact) from the retained payload, and the
// compact stored form really is compact (bodies dropped) — so the accessor
// is load-bearing, not a passthrough.
func TestPassedEvidenceContent_HydratedCollectionServesLeafReaders(t *testing.T) {
	f := newFanoutFixture(t)
	env := contentFixtureEnvelope(t, f)
	mem := source.NewMemorySource()
	require.NoError(t, mem.LoadEnvelope(env.Reference, env.Envelope))
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))

	_, results, err := f.policy(t).Verify(context.Background(),
		WithVerifiedSource(vs),
		WithSubjectDigests([]string{fanoutCommitDigest}),
	)
	require.NoError(t, err)
	require.Len(t, results[fanoutStepName].Passed, 1)
	pc := results[fanoutStepName].Passed[0]

	require.Empty(t, pc.Collection.Collection.Attestations,
		"stored form should be compact — if bodies are retained again, the memory fix regressed")
	hydrated, err := pc.HydratedCollection()
	require.NoError(t, err)
	require.Len(t, hydrated.Attestations, 1)
	assert.Equal(t, fanoutAttestorType, hydrated.Attestations[0].Type)
}
