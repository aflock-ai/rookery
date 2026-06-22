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

package policy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
)

// TestSecurity_GHSA_c346_DedupKeysOnVerifiedSignerNotEnvelope proves that the
// cross-depth de-duplication of passed collections keys on the VERIFIED content
// and signer identity, not on the raw DSSE envelope bytes or the source
// reference (GHSA-c346-qp3r-53vf).
//
// DSSE signatures cover only the payload, so an attacker can mutate/append
// unverified signature entries or vary the source reference to make the SAME
// verified collection hash to a new key and be counted again — inflating the
// passing-collection count that downstream consumers (Rego len(Passed) quorum,
// the step_results UI) rely on.
func TestSecurity_GHSA_c346_DedupKeysOnVerifiedSignerNotEnvelope(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)

	priv2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier2 := cryptoutil.NewECDSAVerifier(&priv2.PublicKey, crypto.SHA256)

	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: attestation.CollectionType,
		Predicate:     json.RawMessage(`{"name":"build","attestations":[]}`),
	}

	mkPC := func(ref string, sig []byte, funcs []cryptoutil.Verifier) PassedCollection {
		return PassedCollection{Collection: source.CollectionVerificationResult{
			ValidFunctionaries: funcs,
			CollectionEnvelope: source.CollectionEnvelope{
				Envelope:  dsse.Envelope{Signatures: []dsse.Signature{{KeyID: "k", Signature: sig}}},
				Statement: stmt,
				Reference: ref,
			},
		}}
	}

	// Same verified collection (same Statement + same verified signer), but the
	// raw DSSE envelope signature bytes and the source reference differ.
	a := mkPC("ref-A", []byte("sig-A"), []cryptoutil.Verifier{verifier})
	b := mkPC("ref-B", []byte("sig-B-mutated"), []cryptoutil.Verifier{verifier})
	require.Len(t, mergePassedCollections([]PassedCollection{a}, []PassedCollection{b}), 1,
		"the same verified collection must dedup to one entry even when envelope signature bytes / reference differ (GHSA-c346-qp3r-53vf)")

	// Different verified signer => genuinely distinct trust, must NOT collapse.
	c := mkPC("ref-A", []byte("sig-A"), []cryptoutil.Verifier{verifier2})
	require.Len(t, mergePassedCollections([]PassedCollection{a}, []PassedCollection{c}), 2,
		"collections passed by different signers must remain distinct")

	// Different statement content => distinct collection, must NOT collapse.
	stmt2 := stmt
	stmt2.Predicate = json.RawMessage(`{"name":"deploy","attestations":[]}`)
	d := PassedCollection{Collection: source.CollectionVerificationResult{
		ValidFunctionaries: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{Statement: stmt2},
	}}
	require.Len(t, mergePassedCollections([]PassedCollection{a}, []PassedCollection{d}), 2,
		"collections with different statement content must remain distinct")
}

// TestPassedCollectionFallbackKey_Deterministic exercises the exceptional-path
// fallback identity directly: it must be deterministic (identical envelopes ->
// identical keys, distinct -> distinct) and namespaced so it cannot collide
// with a normal identity key. This is the path used only when the Statement
// cannot be marshaled or a verified signer's KeyID cannot be derived.
func TestPassedCollectionFallbackKey_Deterministic(t *testing.T) {
	mk := func(payload, sig string) source.CollectionVerificationResult {
		return source.CollectionVerificationResult{
			CollectionEnvelope: source.CollectionEnvelope{
				Envelope: dsse.Envelope{
					Payload:     []byte(payload),
					PayloadType: "application/vnd.in-toto+json",
					Signatures:  []dsse.Signature{{KeyID: "k", Signature: []byte(sig)}},
				},
			},
		}
	}

	a := passedCollectionFallbackKey(mk("payload", "sig"))
	b := passedCollectionFallbackKey(mk("payload", "sig"))
	c := passedCollectionFallbackKey(mk("payload", "DIFFERENT-sig"))

	require.Equal(t, a, b, "identical envelopes must yield identical fallback keys")
	require.NotEqual(t, a, c, "distinct envelopes must yield distinct fallback keys")
	require.True(t, strings.HasPrefix(a, "fallback:"), "fallback key must be namespaced")
}
