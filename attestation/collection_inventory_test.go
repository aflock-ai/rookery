// jade:ring local

package attestation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/stretchr/testify/require"
)

type inventoryHydratorTest struct {
	fakeHydrator
	ref *fileinventory.Reference
}

func TestResolveInventoriesRawPreservesSignedRepresentation(t *testing.T) {
	for _, kind := range []string{"material", "product"} {
		t.Run(kind, func(t *testing.T) {
			digest := sha256.Sum256([]byte("artifact"))
			prehash := sha256.Sum256(digest[:])
			tree, err := merkle.NewTree([][]byte{prehash[:]})
			require.NoError(t, err)
			ref, body, err := fileinventory.Encode(kind, "walk", []fileinventory.Entry{{Path: "a", FileDigest: hex.EncodeToString(digest[:])}, {Path: "b", FileDigest: hex.EncodeToString(digest[:])}})
			require.NoError(t, err)
			data, err := json.Marshal(map[string]any{"merkleRoot": hex.EncodeToString(tree.Root()), "treeSize": 1, "hashAlgorithm": "sha256", "construction": "RFC6962", "inventory": ref})
			require.NoError(t, err)
			c := collectionWith(NewRawAttestation("https://aflock.ai/attestations/"+kind+"/v0.3", data))
			before, err := json.Marshal(c)
			require.NoError(t, err)
			require.ErrorIs(t, c.ResolveInventories(nil, kind), ErrInventoryNotResolved)
			require.NoError(t, c.ResolveInventories(func(string) ([]byte, bool) { return body, true }, kind))
			require.Len(t, c.Artifacts(), 2)
			after, err := json.Marshal(c)
			require.NoError(t, err)
			require.Equal(t, before, after)
			for _, malformed := range [][]byte{
				bytes.Replace(data, []byte(`"inventory":`), []byte(`"Inventory":`), 1),
				bytes.Replace(data, []byte(`"inventory":`), []byte(`"leaves":null,"inventory":`), 1),
				bytes.Replace(data, []byte(`"fileCount":2`), []byte(`"fileCount":2,"fileCount":2`), 1),
				bytes.Replace(data, []byte(`"fileCount":2`), []byte(`"fileCount":null`), 1),
			} {
				bad := collectionWith(NewRawAttestation("https://aflock.ai/attestations/"+kind+"/v0.3", malformed))
				require.Error(t, bad.ResolveInventories(nil, ""))
				require.Error(t, bad.ResolveInventories(nil, kind), "a failed resolution must not drop the invalid attestor")
			}
		})
	}
}

func (h *inventoryHydratorTest) InventoryReference() *fileinventory.Reference { return h.ref }
func (h *inventoryHydratorTest) HydrateInventory(body []byte) error {
	return h.HydrateFromManifest(body)
}

func TestResolveInventoriesRequirements(t *testing.T) {
	for _, kind := range []string{"material", "product"} {
		for _, state := range []string{"omitted", "detached"} {
			for _, required := range []string{"", "material", "product", "all"} {
				t.Run(kind+"/"+state+"/"+required, func(t *testing.T) {
					ref := fileinventory.NewOmitted(kind, "walk", 1)
					if state == "detached" {
						ref.State, ref.Digest, ref.Bytes = state, strings.Repeat("a", 64), 1
					}
					h := &inventoryHydratorTest{ref: ref}
					c := collectionWith(h)
					err := c.ResolveInventories(nil, required)
					if required == kind || required == "all" {
						require.ErrorIs(t, err, ErrInventoryNotResolved)
					} else {
						require.NoError(t, err)
					}
					require.False(t, h.hydrated)
				})
			}
		}
	}
}

func TestResolveInventoriesExactBodyAndErrors(t *testing.T) {
	ref, body, err := fileinventory.Encode("material", "walk", []fileinventory.Entry{{Path: "a", FileDigest: strings.Repeat("a", 64)}})
	require.NoError(t, err)
	h := &inventoryHydratorTest{ref: ref}
	c := collectionWith(h)
	lookup := func(d string) ([]byte, bool) {
		require.Equal(t, ref.Digest, d)
		return body, true
	}
	require.NoError(t, c.ResolveInventories(lookup, "material"))
	require.Equal(t, body, h.hydrateBy)
	h.hydrateErr = errors.New("root mismatch")
	require.ErrorIs(t, c.ResolveInventories(lookup, ""), h.hydrateErr)
	ref.Schema += "x"
	require.Error(t, c.ResolveInventories(nil, ""))
	require.Error(t, c.ResolveInventories(nil, "typo"))
}
