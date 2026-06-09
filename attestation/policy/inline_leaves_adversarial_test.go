// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// These tests pin the v0.3 inline-leaves trust boundary in
// verifyCollectionArtifacts: an artifactsFrom chain is verified from the Merkle
// leaves embedded in (and signed by) each collection — inline leaves are now
// the SOLE trust path (the off-envelope chain sidecar was removed). Verification
// only proceeds after the leaves are confirmed to reconstruct to the signed
// root, and a leaf-less collection with no inline materials ALWAYS fails closed
// (no flag, no opt-out).

package policy

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/require"
)

// inlineFakeAttestor is a configurable stand-in for the product/material v0.3
// attestors. It implements Materialer, Producer and InlineLeafVerifier so the
// engine's inline path exercises real interface dispatch without importing the
// (separate-module) attestor plugins.
type inlineFakeAttestor struct {
	typ           string
	materials     map[string]cryptoutil.DigestSet
	products      map[string]attestation.Product
	verifyErr     error // returned by VerifyInlineLeaves (nil = leaves reconstruct OK)
	inlinePresent bool  // reported by HasInlineLeaves (committed materials inline)
}

func (a *inlineFakeAttestor) HasInlineLeaves() bool { return a.inlinePresent }

func (a *inlineFakeAttestor) Name() string                                 { return a.typ }
func (a *inlineFakeAttestor) Type() string                                 { return a.typ }
func (a *inlineFakeAttestor) RunType() attestation.RunType                 { return attestation.PostProductRunType }
func (a *inlineFakeAttestor) Schema() *jsonschema.Schema                   { return nil }
func (a *inlineFakeAttestor) Attest(*attestation.AttestationContext) error { return nil }
func (a *inlineFakeAttestor) Materials() map[string]cryptoutil.DigestSet   { return a.materials }
func (a *inlineFakeAttestor) Products() map[string]attestation.Product     { return a.products }
func (a *inlineFakeAttestor) VerifyInlineLeaves() error                    { return a.verifyErr }

func digest(hexstr string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: hexstr}
}

func inlineCollection(name string, attestors ...attestation.Attestor) source.CollectionVerificationResult {
	cas := make([]attestation.CollectionAttestation, 0, len(attestors))
	for _, at := range attestors {
		cas = append(cas, attestation.CollectionAttestation{Type: at.Type(), Attestation: at})
	}
	return source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{
			Envelope:   dsse.Envelope{Payload: []byte(`{"step":"` + name + `"}`), PayloadType: "application/vnd.in-toto+json"},
			Collection: attestation.Collection{Name: name, Attestations: cas},
		},
	}
}

// upstream "source" produces libshared.so; downstream "build" consumes it.
func inlineChainSetup(upProduct, downMaterial cryptoutil.DigestSet, downVerifyErr error) (Step, source.CollectionVerificationResult, map[string]StepResult) {
	up := &inlineFakeAttestor{
		typ:      "https://aflock.ai/attestations/product/v0.3",
		products: map[string]attestation.Product{"libshared.so": {Digest: upProduct}},
	}
	down := &inlineFakeAttestor{
		typ:           "https://aflock.ai/attestations/material/v0.3",
		materials:     map[string]cryptoutil.DigestSet{"libshared.so": downMaterial},
		verifyErr:     downVerifyErr,
		inlinePresent: true,
	}
	step := Step{Name: "build", ArtifactsFrom: []string{"source"}}
	build := inlineCollection("build", down)
	collectionsByStep := map[string]StepResult{
		"source": {Step: "source", Passed: []PassedCollection{{Collection: inlineCollection("source", up)}}},
	}
	return step, build, collectionsByStep
}

// Valid inline leaves + matching material digest pass — inline leaves are the
// sole trust path; no sidecar, no flag.
func TestInlineLeaves_PassesFromInlineLeaves(t *testing.T) {
	d := digest("aa")
	step, build, byStep := inlineChainSetup(d, d, nil)
	vo := &verifyOptions{}
	err := verifyCollectionArtifacts(context.Background(), vo, step, build, byStep)
	require.NoError(t, err, "verified inline leaves with matching material must satisfy the chain with no sidecar")
}

// Forged inline leaves (VerifyInlineLeaves errors) must be rejected even when
// the material digest would otherwise match — we never trust un-reconstructed
// leaves.
func TestInlineLeaves_ForgedLeafRejected(t *testing.T) {
	d := digest("aa")
	step, build, byStep := inlineChainSetup(d, d, errors.New("inline leaves reconstruct to a different root"))
	vo := &verifyOptions{}
	err := verifyCollectionArtifacts(context.Background(), vo, step, build, byStep)
	require.Error(t, err, "downstream inline leaves that fail reconstruction must be rejected")
}

// Material digest disagreeing with the upstream product for the same path
// must fail compareArtifacts.
func TestInlineLeaves_MismatchedMaterialRejected(t *testing.T) {
	step, build, byStep := inlineChainSetup(digest("aa"), digest("bb"), nil)
	vo := &verifyOptions{}
	err := verifyCollectionArtifacts(context.Background(), vo, step, build, byStep)
	require.Error(t, err, "downstream material whose digest disagrees with the upstream product must be rejected")
}

// Vacuous-pass defense (UNCONDITIONAL fail-closed): a leaf-less collection (no
// inline materials, no products, no sidecar) can NEVER satisfy the chain —
// empty materials would otherwise make compareArtifacts pass trivially. With
// the chain sidecar removed, inline leaves are the sole trust path, so this
// fails closed with no flag and no opt-out.
func TestInlineLeaves_VacuousAlwaysFailsClosed(t *testing.T) {
	up := &inlineFakeAttestor{typ: "https://aflock.ai/attestations/product/v0.3"}
	down := &inlineFakeAttestor{typ: "https://aflock.ai/attestations/material/v0.3"}
	step := Step{Name: "build", ArtifactsFrom: []string{"source"}}
	build := inlineCollection("build", down)
	byStep := map[string]StepResult{
		"source": {Step: "source", Passed: []PassedCollection{{Collection: inlineCollection("source", up)}}},
	}
	vo := &verifyOptions{}
	err := verifyCollectionArtifacts(context.Background(), vo, step, build, byStep)
	require.Error(t, err, "a leaf-less collection (empty materials, no inline leaves) must always fail closed")
}

// Authoritative empty: a downstream step that INLINES an empty material set
// (HasInlineLeaves == true) has signed a commitment that it consumed nothing —
// e.g. a build in an isolated workingdir. That is a verified fact, not a
// vacuous-pass bypass, so the chain must accept it WITHOUT a sidecar and
// WITHOUT any flag. This is the rc4 regression: the self-host-minimal
// binary-build step records no materials and must still verify.
func TestInlineLeaves_AuthoritativeEmptyPasses(t *testing.T) {
	up := &inlineFakeAttestor{typ: "https://aflock.ai/attestations/product/v0.3", inlinePresent: true}
	down := &inlineFakeAttestor{typ: "https://aflock.ai/attestations/material/v0.3", inlinePresent: true} // inline, zero materials
	step := Step{Name: "build", ArtifactsFrom: []string{"source"}}
	build := inlineCollection("build", down)
	byStep := map[string]StepResult{
		"source": {Step: "source", Passed: []PassedCollection{{Collection: inlineCollection("source", up)}}},
	}
	vo := &verifyOptions{}
	err := verifyCollectionArtifacts(context.Background(), vo, step, build, byStep)
	require.NoError(t, err, "an inline, authoritatively-empty material set must satisfy the chain with no sidecar and no flag")
}
