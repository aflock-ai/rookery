// jade:ring local

package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/stretchr/testify/require"
)

type chainInventory struct {
	inlineFakeAttestor
	ref      *fileinventory.Reference
	hydrated bool
}

func (a *chainInventory) InventoryReference() *fileinventory.Reference { return a.ref }
func (a *chainInventory) HydrateInventory([]byte) error {
	a.hydrated = true
	if a.ref.Kind == "material" {
		a.materials = map[string]cryptoutil.DigestSet{"libshared.so": digest("aa")}
	} else {
		a.products = map[string]attestation.Product{"libshared.so": {Digest: digest("aa")}}
	}
	return nil
}

func TestCompactInventoryChainRequirements(t *testing.T) {
	for _, missingKind := range []string{"", "material", "product"} {
		t.Run(missingKind, func(t *testing.T) {
			up := &chainInventory{ref: fileinventory.NewOmitted("product", "walk", 1)}
			down := &chainInventory{ref: fileinventory.NewOmitted("material", "walk", 1)}
			bodies := map[string][]byte{}
			for i, a := range []*chainInventory{up, down} {
				a.typ = "https://aflock.ai/attestations/" + a.ref.Kind + "/v0.3"
				a.ref.State, a.ref.Digest, a.ref.Bytes = "detached", strings.Repeat(string(rune('a'+i)), 64), 1
				if a.ref.Kind != missingKind {
					bodies[a.ref.Digest] = []byte("x")
				}
			}
			step, _, byStep := inlineChainSetup(digest("aa"), digest("aa"), nil)
			build := inlineCollection("build", down)
			byStep["source"] = StepResult{Passed: []PassedCollection{{Collection: inlineCollection("source", up)}}}
			err := verifyCollectionArtifacts(context.Background(), &verifyOptions{materialManifests: bodies}, step, PassedCollection{Collection: build}, byStep)
			if missingKind == "" {
				require.NoError(t, err)
				require.True(t, up.hydrated && down.hydrated)
			} else {
				require.Error(t, err)
				require.Contains(t, err.Error(), "inventory")
			}
		})
	}
}

func TestCompactInventoryCommandOnlyDoesNotRequireFiles(t *testing.T) {
	a := &chainInventory{ref: fileinventory.NewOmitted("material", "walk", 1)}
	err := verifyCollectionArtifacts(context.Background(), &verifyOptions{}, Step{Name: "build"}, PassedCollection{Collection: inlineCollection("build", a)}, nil)
	require.NoError(t, err)
	require.False(t, a.hydrated)
}

func TestCompactInventoryStrictChainRequiresCompleteUpstream(t *testing.T) {
	step, build, byStep := inlineChainSetup(digest("aa"), digest("aa"), nil)
	up := byStep["source"].Passed[0].Collection
	omitted := &chainInventory{ref: fileinventory.NewOmitted("material", "walk", 1)}
	up.Collection.Attestations = append(up.Collection.Attestations, attestation.CollectionAttestation{Type: "material", Attestation: omitted})
	byStep["source"] = StepResult{Passed: []PassedCollection{{Collection: up}}}
	require.ErrorContains(t, verifyCollectionArtifacts(t.Context(), &verifyOptions{}, step, PassedCollection{Collection: build}, byStep), "inventory")
	require.ErrorContains(t, verifyCollectionArtifacts(t.Context(), &verifyOptions{requireAllArtifacts: true}, step, PassedCollection{Collection: build}, byStep), "inventory")
}

func TestCompactInventoryNormalChainMatchesInlineSemantics(t *testing.T) {
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	ref, body, err := fileinventory.Encode("material", "walk", []fileinventory.Entry{{Path: "b", FileDigest: b}})
	require.NoError(t, err)
	rawDigest, err := hex.DecodeString(b)
	require.NoError(t, err)
	prehash := sha256.Sum256(rawDigest)
	tree, err := merkle.NewTree([][]byte{prehash[:]})
	require.NoError(t, err)
	for _, mismatch := range []bool{false, true} {
		for _, representation := range []string{"inline", "detached", "missing", "omitted"} {
			name := representation + "/matching"
			if mismatch {
				name = representation + "/mismatch"
			}
			t.Run(name, func(t *testing.T) {
				consumedB := b
				if mismatch {
					consumedB = c
				}
				upProduct := &inlineFakeAttestor{typ: "product", products: map[string]attestation.Product{"a": {Digest: digest(a)}}}
				var upMaterial attestation.Attestor = &inlineFakeAttestor{typ: "material", materials: map[string]cryptoutil.DigestSet{"b": digest(b)}, inlinePresent: true}
				vo := &verifyOptions{}
				if representation != "inline" {
					signedRef := ref
					if representation == "omitted" {
						signedRef = fileinventory.NewOmitted("material", "walk", 1)
					}
					predicate, err := json.Marshal(map[string]any{"merkleRoot": hex.EncodeToString(tree.Root()), "treeSize": 1, "hashAlgorithm": "sha256", "construction": "RFC6962", "inventory": signedRef})
					require.NoError(t, err)
					upMaterial = attestation.NewRawAttestation("https://aflock.ai/attestations/material/v0.3", predicate)
					if representation == "detached" {
						vo.materialManifests = map[string][]byte{ref.Digest: body}
					}
				}
				down := &inlineFakeAttestor{typ: "material", materials: map[string]cryptoutil.DigestSet{"a": digest(a), "b": digest(consumedB)}, inlinePresent: true}
				byStep := map[string]StepResult{"source": {Passed: []PassedCollection{{Collection: inlineCollection("source", upProduct, upMaterial)}}}}
				err := verifyCollectionArtifacts(t.Context(), vo, Step{Name: "build", ArtifactsFrom: []string{"source"}}, PassedCollection{Collection: inlineCollection("build", down)}, byStep)
				if representation == "missing" || representation == "omitted" {
					require.ErrorContains(t, err, "inventory")
				} else if mismatch {
					require.ErrorContains(t, err, "mismatched digests for b", "matching product a cannot hide mismatched retained material b")
				} else {
					require.NoError(t, err)
				}
			})
		}
	}
}
