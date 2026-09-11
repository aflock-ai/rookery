// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
)

// This file pins the bridge's half of the three-state manifestUploaded
// contract. The bridge is handed a set of envelopes and may find a companion
// manifest among them that hashes to exactly the digest a leaf-less material
// predicate names and rebuilds exactly its root. That match proves WHICH
// manifest it is. It proves nothing about WHETHER the producer published it —
// only the signed manifestUploaded value does — so a companion is followed on
// an explicit true and on nothing else.

// detachedMaterialEnvelopes builds a material v0.3 collection whose predicate
// carries NO inline leaves but does carry the manifest reference, with
// manifestUploaded set to uploaded (nil removes the key), plus the companion
// manifest envelope that resolves it. The companion is ALWAYS valid and
// matching: these tests are about the signed value, not about the companion's
// integrity, which the from-bundles tests already cover.
func detachedMaterialEnvelopes(t *testing.T, digests map[string]string, uploaded any) (collection, manifest dsse.Envelope, root string) {
	t.Helper()
	return materialEnvelopesWithLeaves(t, digests, uploaded, nil)
}

// materialEnvelopesWithLeaves is detachedMaterialEnvelopes with an explicit
// "leaves" value: nil leaves the key ABSENT (the detached shape); a non-nil
// slice, including an empty one, writes the key so the predicate is inline.
func materialEnvelopesWithLeaves(t *testing.T, digests map[string]string, uploaded any, leaves []any) (collection, manifest dsse.Envelope, root string) {
	t.Helper()
	predicate, digest, root := buildManifestSidecarBytes(t, digests)

	tree := map[string]any{
		"merkleRoot":    root,
		"treeSize":      len(digests),
		"hashAlgorithm": "sha256",
		"construction":  "RFC6962",
		"manifest": map[string]any{
			"digest": map[string]string{"sha256": digest},
			"bytes":  len(predicate),
		},
	}
	if leaves != nil {
		tree["leaves"] = leaves
	}
	if uploaded != nil {
		tree["manifestUploaded"] = uploaded
	}
	treeRaw, err := json.Marshal(tree)
	if err != nil {
		t.Fatalf("marshal tree: %v", err)
	}
	stmt := map[string]any{
		"predicateType": collectionPredicateType,
		"predicate": map[string]any{
			"attestations": []map[string]any{
				{"type": materialTreeType, "attestation": json.RawMessage(treeRaw)},
			},
		},
	}
	payload, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("marshal collection: %v", err)
	}
	collection = dsse.Envelope{Payload: payload}

	manifestPayload, err := json.Marshal(intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: material.ManifestType,
		Predicate:     json.RawMessage(predicate),
	})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	manifest = dsse.Envelope{PayloadType: intoto.PayloadType, Payload: manifestPayload}
	return collection, manifest, root
}

// TestBridge_CompanionFollowedOnlyOnSignedPublish is the three-state table.
// Every row hands the bridge the SAME valid, matching companion; only the
// signed manifestUploaded value differs. A requested digest that is one of the
// detached leaves bridges to the tree root exactly when the producer signed
// true. The false row is the finding: a producer that signed "not published"
// must not have its leaves recovered from a companion that happens to be
// present. The nil row pins the legacy rule — absence is "decide from leaves",
// and a leaf-less legacy predicate has none.
func TestBridge_CompanionFollowedOnlyOnSignedPublish(t *testing.T) {
	cases := []struct {
		name     string
		uploaded any
		bridged  bool
	}{
		{name: "published (true)", uploaded: true, bridged: true},
		{name: "withheld (false)", uploaded: false, bridged: false},
		{name: "legacy (absent)", uploaded: nil, bridged: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coll, manifest, root := detachedMaterialEnvelopes(t, multiLeafDigests(), tc.uploaded)

			in := []cryptoutil.DigestSet{subjectDigest(digApp2)}
			out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{coll, manifest}, "", "")

			if got := hasRoot(out, root); got != tc.bridged {
				t.Fatalf("manifestUploaded=%v with a valid matching companion loaded: bridged=%v, want %v (subjects %v)",
					tc.uploaded, got, tc.bridged, out)
			}
		})
	}
}

// TestBridge_PublishedButUnresolvedDoesNotBridge: the positive row above must
// be measuring the companion read. Same predicate signed true, companion NOT
// loaded — nothing to resolve, nothing bridged. (The engine, not the bridge,
// is where "published but unresolved" becomes a reported finding.)
func TestBridge_PublishedButUnresolvedDoesNotBridge(t *testing.T) {
	coll, _, root := detachedMaterialEnvelopes(t, multiLeafDigests(), true)

	in := []cryptoutil.DigestSet{subjectDigest(digApp2)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{coll}, "", "")

	if hasRoot(out, root) {
		t.Fatalf("a detached tree with no companion loaded bridged anyway; the leaves came from nowhere trustworthy: %v", out)
	}
}

// TestBridge_PresentEmptyLeavesNeverReadCompanion pins JSON field PRESENCE on
// the bridge. A published empty tree signs `"leaves": []` alongside its
// manifest reference (this rollout keeps inline leaves when publishing). That
// present key is the authoritative inline set — an empty one — so the bridge
// has nothing to match and must not go to the companion to find something.
// The companion here DOES contain the requested digest, so "not bridged" is
// the proof it was never opened. The absent-key row is the control: same
// predicate with the key removed does follow the companion.
func TestBridge_PresentEmptyLeavesNeverReadCompanion(t *testing.T) {
	cases := []struct {
		name          string
		leaves        []any // nil = key absent
		withCompanion bool
		bridged       bool
	}{
		{name: "leaves:[] with companion loaded", leaves: []any{}, withCompanion: true, bridged: false},
		{name: "leaves:[] without companion", leaves: []any{}, withCompanion: false, bridged: false},
		{name: "leaves absent with companion loaded (control)", leaves: nil, withCompanion: true, bridged: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			coll, manifest, root := materialEnvelopesWithLeaves(t, multiLeafDigests(), true, tc.leaves)
			envs := []dsse.Envelope{coll}
			if tc.withCompanion {
				envs = append(envs, manifest)
			}

			in := []cryptoutil.DigestSet{subjectDigest(digApp2)}
			out := expandSubjectsWithInclusionProofs(in, envs, "", "")

			if got := hasRoot(out, root); got != tc.bridged {
				t.Fatalf("leaves=%v companion=%v: bridged=%v, want %v (subjects %v)", tc.leaves, tc.withCompanion, got, tc.bridged, out)
			}
		})
	}
}
