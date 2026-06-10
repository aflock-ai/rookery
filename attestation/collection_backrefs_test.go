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

package attestation

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	backRefTestDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	backRefTestDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func sha256DigestSet(value string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: value}
}

// backRefSerializationAttestor is a minimal Attestor + BackReffer for
// exercising backref serialization. (The audit-tagged adversarial test
// helpers aren't built in normal test runs, so this file is self-contained.)
type backRefSerializationAttestor struct {
	name          string
	predicateType string
	backRefs      map[string]cryptoutil.DigestSet
}

func (a *backRefSerializationAttestor) Name() string                     { return a.name }
func (a *backRefSerializationAttestor) Type() string                     { return a.predicateType }
func (a *backRefSerializationAttestor) RunType() RunType                 { return ExecuteRunType }
func (a *backRefSerializationAttestor) Schema() *jsonschema.Schema       { return nil }
func (a *backRefSerializationAttestor) Attest(*AttestationContext) error { return nil }
func (a *backRefSerializationAttestor) BackRefs() map[string]cryptoutil.DigestSet {
	return a.backRefs
}

// TestNewCollectionRecordsBackRefs proves that NewCollection captures the
// aggregated attestor BackRefs into the serialized backrefs field, using the
// same <attestor-type>/<name> key format as the live BackRefs() aggregation.
func TestNewCollectionRecordsBackRefs(t *testing.T) {
	att := &backRefSerializationAttestor{
		name:          "scanner",
		predicateType: "https://test/backref-record",
		backRefs: map[string]cryptoutil.DigestSet{
			"imagedigest:sha256:" + backRefTestDigestA: sha256DigestSet(backRefTestDigestA),
		},
	}

	collection := NewCollection("scan-step", []CompletedAttestor{
		{Attestor: att, StartTime: time.Now(), EndTime: time.Now()},
	})

	key := "https://test/backref-record/imagedigest:sha256:" + backRefTestDigestA
	require.Contains(t, collection.RecordedBackRefs, key)
	assert.Equal(t, sha256DigestSet(backRefTestDigestA), collection.RecordedBackRefs[key])
	assert.Equal(t, collection.RecordedBackRefs, collection.BackRefs(),
		"BackRefs() must return the recorded refs on a freshly built collection")
}

// TestCollectionBackRefsRoundTripUnregisteredAttestor is the load-bearing
// case: a collection whose attestor type has NO registered factory
// unmarshals into RawAttestation, which cannot compute BackRefs. The
// serialized backrefs field must preserve the edges across the round trip so
// consumers (platform graph ingest, verifiers handling plugin attestor
// types) recover them without typed factories.
func TestCollectionBackRefsRoundTripUnregisteredAttestor(t *testing.T) {
	att := &backRefSerializationAttestor{
		name:          "plugin-scanner",
		predicateType: "https://test/unregistered-plugin-type",
		backRefs: map[string]cryptoutil.DigestSet{
			"imagedigest:sha256:" + backRefTestDigestA: sha256DigestSet(backRefTestDigestA),
		},
	}

	collection := NewCollection("plugin-step", []CompletedAttestor{
		{Attestor: att, StartTime: time.Now(), EndTime: time.Now()},
	})

	serialized, err := json.Marshal(&collection)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(serialized), `"backrefs"`),
		"collection JSON must carry the backrefs field")

	var parsed Collection
	require.NoError(t, json.Unmarshal(serialized, &parsed))

	// Sanity: the attestor type is unregistered, so it must have decoded as
	// RawAttestation — the case where live aggregation is impossible.
	require.Len(t, parsed.Attestations, 1)
	_, isRaw := parsed.Attestations[0].Attestation.(*RawAttestation)
	require.True(t, isRaw, "test requires an unregistered attestor type")

	key := "https://test/unregistered-plugin-type/imagedigest:sha256:" + backRefTestDigestA
	got := parsed.BackRefs()
	require.Contains(t, got, key,
		"serialized backrefs must survive round trip through RawAttestation")
	assert.Equal(t, sha256DigestSet(backRefTestDigestA), got[key])
}

// TestCollectionBackRefsLegacyFallback proves that collections serialized
// before the backrefs field existed still compute BackRefs from typed
// attestors — the in-memory aggregation remains the fallback.
func TestCollectionBackRefsLegacyFallback(t *testing.T) {
	att := &backRefSerializationAttestor{
		name:          "legacy",
		predicateType: "https://test/legacy-backref",
		backRefs: map[string]cryptoutil.DigestSet{
			"commithash:" + backRefTestDigestB: sha256DigestSet(backRefTestDigestB),
		},
	}

	// A legacy collection: typed attestors present, no recorded backrefs
	// (struct literal mirrors what unmarshaling a pre-field envelope yields).
	collection := Collection{
		Name: "legacy-step",
		Attestations: []CollectionAttestation{
			{Type: att.Type(), Attestation: att, StartTime: time.Now(), EndTime: time.Now()},
		},
	}
	require.Nil(t, collection.RecordedBackRefs)

	key := "https://test/legacy-backref/commithash:" + backRefTestDigestB
	got := collection.BackRefs()
	require.Contains(t, got, key, "legacy collections must fall back to live aggregation")
	assert.Equal(t, sha256DigestSet(backRefTestDigestB), got[key])
}

// TestCollectionBackRefsOmittedWhenEmpty keeps the wire format clean: a
// collection with no BackReffer attestors must not emit a backrefs key.
func TestCollectionBackRefsOmittedWhenEmpty(t *testing.T) {
	att := &backRefSerializationAttestor{
		name:          "no-backrefs",
		predicateType: "https://test/no-backrefs",
	}

	collection := NewCollection("plain-step", []CompletedAttestor{
		{Attestor: att, StartTime: time.Now(), EndTime: time.Now()},
	})

	serialized, err := json.Marshal(&collection)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(serialized), `"backrefs"`),
		"empty backrefs must be omitted from the wire format")
	assert.Empty(t, collection.BackRefs())
}

// TestCollectionBackRefsSerializedIsAuthoritative documents the trust model:
// when the recorded field is present it wins over live aggregation, even if
// an attestor's computed backrefs would differ. The field sits inside the
// signed DSSE payload, so this carries exactly the same trust as attestor
// subjects — signature proves provenance of the claim, not its truth.
// Verification only uses BackRefs to WIDEN candidate search (policy.go
// subject-graph expansion); fabricated refs cannot satisfy digest checks.
func TestCollectionBackRefsSerializedIsAuthoritative(t *testing.T) {
	att := &backRefSerializationAttestor{
		name:          "drift",
		predicateType: "https://test/drift",
		backRefs: map[string]cryptoutil.DigestSet{
			"commithash:" + backRefTestDigestA: sha256DigestSet(backRefTestDigestA),
		},
	}

	collection := NewCollection("drift-step", []CompletedAttestor{
		{Attestor: att, StartTime: time.Now(), EndTime: time.Now()},
	})

	// Mutate the live attestor after recording; recorded refs must win.
	att.backRefs = map[string]cryptoutil.DigestSet{
		"commithash:" + backRefTestDigestB: sha256DigestSet(backRefTestDigestB),
	}

	key := "https://test/drift/commithash:" + backRefTestDigestA
	got := collection.BackRefs()
	assert.Contains(t, got, key, "recorded backrefs are authoritative once present")
	assert.NotContains(t, got, "https://test/drift/commithash:"+backRefTestDigestB)
}
