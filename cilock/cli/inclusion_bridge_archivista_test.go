// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
)

// THE FIX (Archivista lookup): `cilock verify <artifact> --enable-archivista`
// with NO local -a envelope must still be able to find a single-leaf product
// collection. Archivista indexes the collection under its Merkle TREE ROOT, not
// the artifact's plain sha256, so a search by the file digest alone returns
// nothing and no envelope/commitment ever loads. The bridge must reconstruct the
// single-leaf candidate root from (basename, digest) and add it as a SEARCH
// subject even when no envelopes are loaded.
func TestSingleLeafCandidate_NoEnvelope_AddedForArchivistaLookup(t *testing.T) {
	side, err := inclusionproof.BuildSidecar("product", map[string]string{"app.bin": digApp1})
	if err != nil {
		t.Fatalf("BuildSidecar: %v", err)
	}

	in := []cryptoutil.DigestSet{subjectDigest(digApp1)}
	// No envelopes loaded (the --enable-archivista, no -a case), but we know the
	// artifact path + digest being verified.
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{}, "app.bin", digApp1)

	if !hasRoot(out, side.MerkleRoot) {
		t.Fatalf("expected single-leaf candidate tree root %s added as a search subject with no envelope loaded; got %v", side.MerkleRoot, out)
	}
}

// Without an artifact path/digest and with no envelopes there is nothing to
// reconstruct, so the subjects are returned unchanged (no spurious additions).
func TestSingleLeafCandidate_NoArtifact_NoChange(t *testing.T) {
	in := []cryptoutil.DigestSet{subjectDigest(digApp1)}
	out := expandSubjectsWithInclusionProofs(in, []dsse.Envelope{}, "", "")

	if len(out) != len(in) {
		t.Fatalf("no artifact path/digest and no envelopes must not add subjects; got %d, want %d", len(out), len(in))
	}
}
