// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/chain"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inMemoryChainSidecarSource is the test fixture for ChainSidecarSource.
// Keyed by (downstreamStep, upstreamStep, upstreamEnvelopeDigest).
type inMemoryChainSidecarSource struct {
	sidecars map[string]*chain.ChainSidecar
}

func (s *inMemoryChainSidecarSource) LookupChainSidecar(_ context.Context, downstreamStep, upstreamStep, upstreamEnvelopeDigest string) (*chain.ChainSidecar, error) {
	key := downstreamStep + "|" + upstreamStep + "|" + upstreamEnvelopeDigest
	return s.sidecars[key], nil
}

func (s *inMemoryChainSidecarSource) put(downstream, upstream, envDigest string, sc *chain.ChainSidecar) {
	if s.sidecars == nil {
		s.sidecars = map[string]*chain.ChainSidecar{}
	}
	s.sidecars[downstream+"|"+upstream+"|"+envDigest] = sc
}

// chainTestFixture builds a 2-step (source → build) scenario the
// chain-sidecar verifier path needs to validate.
type chainTestFixture struct {
	sourceLeaves   []chain.SidecarLeaf
	sourceEnvHex   string // sha256 of source step's "envelope payload"
	sourceRefForCS chain.SourceStepRef
}

// makeChainFixture constructs a source step with three products and
// returns the bindings (envelope digest, root, treeSize, domain) plus
// the leaves a downstream producer would use to build a chain sidecar.
func makeChainFixture(t *testing.T) chainTestFixture {
	t.Helper()
	const domain = "rookery-product/v0.3"
	leaves := []chain.SidecarLeaf{
		{Path: "src/main.go", FileDigest: sha256Hex("main")},
		{Path: "src/util.go", FileDigest: sha256Hex("util")},
		{Path: "src/parser.go", FileDigest: sha256Hex("parser")},
	}
	// Mirror the producer-side path-sort.
	sort.Slice(leaves, func(i, j int) bool { return leaves[i].Path < leaves[j].Path })

	preHashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, err := chain.LeafHashWithDomain(domain, l.Path, l.FileDigest)
		require.NoError(t, err)
		preHashes[i] = h
	}
	tree, err := merkle.NewTree(preHashes)
	require.NoError(t, err)

	// Synthesize a deterministic "source envelope payload" the build's
	// chain sidecar will bind to. In real production this is the
	// signed in-toto Statement; for the test we just need stable bytes.
	envPayload, _ := json.Marshal(map[string]any{
		"step":       "source",
		"merkleRoot": hex.EncodeToString(tree.Root()),
	})
	envSum := sha256.Sum256(envPayload)
	envHex := hex.EncodeToString(envSum[:])

	return chainTestFixture{
		sourceLeaves: leaves,
		sourceEnvHex: envHex,
		sourceRefForCS: chain.SourceStepRef{
			StepName:       "source",
			EnvelopeDigest: envHex,
			MerkleRoot:     hex.EncodeToString(tree.Root()),
			TreeSize:       tree.Size(),
			Domain:         domain,
		},
	}
}

// makeSourceCollection wraps a v0.3-style source-step collection in a
// CollectionVerificationResult, with the envelope's Payload set so the
// verifier-side envelopePayloadDigest derives the same hex string the
// chain sidecar binds to.
func makeSourceCollection(fix chainTestFixture) source.CollectionVerificationResult {
	envPayload, _ := json.Marshal(map[string]any{
		"step":       "source",
		"merkleRoot": fix.sourceRefForCS.MerkleRoot,
	})
	return source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Envelope:   dsse.Envelope{Payload: envPayload, PayloadType: "application/vnd.in-toto+json"},
			Collection: attestation.Collection{Name: "source"},
		},
	}
}

// makeBuildCollection wraps a downstream build collection. Materials
// map is intentionally EMPTY (v0.3 keeps materials off-envelope),
// which is what makes the chain sidecar path the only way the
// policy can confirm provenance.
func makeBuildCollection() source.CollectionVerificationResult {
	return source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Envelope:   dsse.Envelope{Payload: []byte(`{"step":"build"}`), PayloadType: "application/vnd.in-toto+json"},
			Collection: attestation.Collection{Name: "build"},
		},
	}
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// TestChainSidecarSource_HappyPath: a chain sidecar exists for the
// (build, source) pair, every consumed material has a valid inclusion
// proof against source's signed root, verifier accepts.
func TestChainSidecarSource_HappyPath(t *testing.T) {
	fix := makeChainFixture(t)

	// Step 2 consumes 2 of the 3 source products.
	consumed := []chain.ConsumedMaterial{
		{Path: "src/main.go", FileDigest: sha256Hex("main")},
		{Path: "src/parser.go", FileDigest: sha256Hex("parser")},
	}
	chain, err := chain.BuildChainSidecar(fix.sourceRefForCS, fix.sourceLeaves, consumed)
	require.NoError(t, err)

	src := &inMemoryChainSidecarSource{}
	src.put("build", "source", fix.sourceEnvHex, &chain)

	step := Step{Name: "build", ArtifactsFrom: []string{"source"}}
	build := makeBuildCollection()
	collectionsByStep := map[string]StepResult{
		"source": {
			Step:   "source",
			Passed: []PassedCollection{{Collection: makeSourceCollection(fix)}},
		},
	}

	vo := &verifyOptions{chainSidecarSource: src}
	err = verifyCollectionArtifacts(context.Background(), vo, step, build, collectionsByStep)
	require.NoError(t, err, "chain sidecar with valid proofs must pass verification")
}

// TestChainSidecarSource_TamperedProof: the sidecar exists but one
// proof's audit-path was tampered with. Verifier rejects.
func TestChainSidecarSource_TamperedProof(t *testing.T) {
	fix := makeChainFixture(t)

	consumed := []chain.ConsumedMaterial{
		{Path: "src/main.go", FileDigest: sha256Hex("main")},
	}
	chain, err := chain.BuildChainSidecar(fix.sourceRefForCS, fix.sourceLeaves, consumed)
	require.NoError(t, err)

	// Flip a bit in the audit path.
	raw, _ := hex.DecodeString(chain.MaterialProofs[0].AuditPath[0])
	raw[0] ^= 0x01
	chain.MaterialProofs[0].AuditPath[0] = hex.EncodeToString(raw)

	src := &inMemoryChainSidecarSource{}
	src.put("build", "source", fix.sourceEnvHex, &chain)

	step := Step{Name: "build", ArtifactsFrom: []string{"source"}}
	build := makeBuildCollection()
	collectionsByStep := map[string]StepResult{
		"source": {
			Step:   "source",
			Passed: []PassedCollection{{Collection: makeSourceCollection(fix)}},
		},
	}

	vo := &verifyOptions{chainSidecarSource: src}
	err = verifyCollectionArtifacts(context.Background(), vo, step, build, collectionsByStep)
	require.Error(t, err, "tampered chain sidecar proof must fail")
}

// TestChainSidecarSource_WrongEnvelopeBinding: the sidecar's claimed
// SourceStep.EnvelopeDigest doesn't match the upstream collection's
// actual envelope digest. Closes the cross-step proof-replay attack
// (D1) where an attacker substitutes a sidecar from a different
// attestation that happens to share the same Merkle root.
func TestChainSidecarSource_WrongEnvelopeBinding(t *testing.T) {
	fix := makeChainFixture(t)
	consumed := []chain.ConsumedMaterial{
		{Path: "src/main.go", FileDigest: sha256Hex("main")},
	}
	chain, err := chain.BuildChainSidecar(fix.sourceRefForCS, fix.sourceLeaves, consumed)
	require.NoError(t, err)

	// Tamper: sidecar claims it chains from a DIFFERENT envelope.
	chain.SourceStep.EnvelopeDigest = sha256Hex("some-other-attestation")

	src := &inMemoryChainSidecarSource{}
	// Index under the ACTUAL upstream digest the verifier looks up.
	src.put("build", "source", fix.sourceEnvHex, &chain)

	step := Step{Name: "build", ArtifactsFrom: []string{"source"}}
	build := makeBuildCollection()
	collectionsByStep := map[string]StepResult{
		"source": {
			Step:   "source",
			Passed: []PassedCollection{{Collection: makeSourceCollection(fix)}},
		},
	}
	vo := &verifyOptions{chainSidecarSource: src}
	err = verifyCollectionArtifacts(context.Background(), vo, step, build, collectionsByStep)
	require.Error(t, err, "sidecar bound to wrong envelope digest must fail")
}

// TestChainSidecarSource_NotFound_FallsThroughToLegacy: when the
// source returns (nil, nil) the verifier falls back to the existing
// path-by-path compareArtifacts. With empty mats (v0.3 materials map
// is empty by design), the legacy path vacuously passes — that's the
// pre-existing behavior this change is back-compat with, NOT the
// security improvement (which requires --require-sidecar from #190).
func TestChainSidecarSource_NotFound_FallsThroughToLegacy(t *testing.T) {
	fix := makeChainFixture(t)
	src := &inMemoryChainSidecarSource{} // no sidecars registered

	step := Step{Name: "build", ArtifactsFrom: []string{"source"}}
	build := makeBuildCollection()
	collectionsByStep := map[string]StepResult{
		"source": {
			Step:   "source",
			Passed: []PassedCollection{{Collection: makeSourceCollection(fix)}},
		},
	}
	vo := &verifyOptions{chainSidecarSource: src}
	err := verifyCollectionArtifacts(context.Background(), vo, step, build, collectionsByStep)
	// Existing semantics: passes vacuously. This is the gap #190 closes.
	assert.NoError(t, err, "documents pre-#190 vacuous-pass behavior")
}

// TestVerifyOption_WithChainSidecarSource confirms the public option
// wires the source through to verifyOptions.
func TestVerifyOption_WithChainSidecarSource(t *testing.T) {
	src := &inMemoryChainSidecarSource{}
	vo := &verifyOptions{}
	WithChainSidecarSource(src)(vo)
	require.NotNil(t, vo.chainSidecarSource)
}
