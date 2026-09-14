// jade:ring local

package material

import (
	"bytes"
	"crypto"
	"encoding/json"
	"maps"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/invopop/jsonschema"
	validation "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/require"
)

func TestCompactMaterialInventory(t *testing.T) {
	files := map[string]string{"x": "same", "y": "same", `a\b`: "different", "a/b": "fourth"}
	legacy := makeMaterialAttestor(t, map[string]string{"x": "same", "y": "same", "c": "different", "d": "fourth"})
	for _, retain := range []bool{false, true} {
		a := makeMaterialAttestor(t, files, WithCompactInventory(retain))
		require.Equal(t, "material", a.Name())
		require.Equal(t, "https://aflock.ai/attestations/material/v0.3", a.Type())
		require.Equal(t, legacy.MerkleRoot, a.MerkleRoot)
		require.Equal(t, legacy.TreeSize, a.TreeSize)
		require.Len(t, a.Materials(), 4, "baseline must retain all captured paths")
		ref := a.InventoryReference()
		require.NotNil(t, ref)
		require.Equal(t, 4, ref.FileCount)
		require.NoError(t, ref.Validate("material"))
		raw, err := json.Marshal(a)
		require.NoError(t, err)
		for _, forbidden := range []string{`"leaves"`, `"manifest"`, `"manifestUploaded"`} {
			require.NotContains(t, string(raw), forbidden)
		}
		var decoded Attestor
		require.NoError(t, json.Unmarshal(raw, &decoded))
		require.False(t, decoded.ManifestPending())
		require.False(t, decoded.ManifestWithheld())
		require.False(t, decoded.HasInlineLeaves())
		body, err := a.InventoryBytes()
		if !retain {
			require.Equal(t, "omitted", ref.State)
			require.Error(t, err)
			require.Empty(t, a.Companions())
			require.Error(t, decoded.HydrateInventory(nil))
			continue
		}
		require.NoError(t, err)
		require.Equal(t, "detached", ref.State)
		require.Len(t, a.Companions(), 1)
		require.Equal(t, fileinventory.Type, a.Companions()[0].Type())
		entries, err := fileinventory.Verify(ref, body, "material", a.MerkleRoot, a.TreeSize)
		require.NoError(t, err)
		require.Len(t, entries, 4)
		require.Error(t, decoded.HydrateInventory(bytes.Replace(body, []byte(`"path":"x"`), []byte(`"path":"z"`), 1)))
		require.Empty(t, decoded.Materials())
		require.NoError(t, decoded.HydrateInventory(body))
		require.Len(t, decoded.Materials(), 4)
		require.Contains(t, decoded.Materials(), `a\b`)
		require.Contains(t, decoded.Materials(), "a/b")
		require.False(t, decoded.HasInlineLeaves())
		after, err := json.Marshal(&decoded)
		require.NoError(t, err)
		require.Equal(t, raw, after, "hydration must not rewrite the signed representation")
		require.Error(t, decoded.HydrateFromManifest(body), "new refs do not enter legacy hydration")
	}
}

func TestCompactMaterialInventoryMixedDigests(t *testing.T) {
	for _, retain := range []bool{false, true} {
		t.Run(map[bool]string{false: "omitted", true: "retained"}[retain], func(t *testing.T) {
			a := makeMaterialAttestor(t, map[string]string{"x": "same", "y": "same", "z": "different"}, WithCompactInventory(retain))
			root, size := a.MerkleRoot, a.TreeSize
			a.materials["directory"] = cryptoutil.DigestSet{{Hash: crypto.SHA256, DirHash: true}: "directory metadata"}
			a.materials["git-only"] = cryptoutil.DigestSet{{Hash: crypto.SHA256, GitOID: true}: "git metadata"}
			a.materials["sha1-only"] = cryptoutil.DigestSet{{Hash: crypto.SHA1}: "sha1 metadata"}
			a.materials["x"][cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: true}] = "additional git metadata"
			baseline := make(map[string]cryptoutil.DigestSet, len(a.materials))
			for path, ds := range a.materials {
				baseline[path] = maps.Clone(ds)
			}
			// This checks the inventory projection of an existing commitment,
			// not acceptance of metadata-only entries by the capture tree.
			_, treeErr := buildLeaves(a.materials)
			require.Error(t, treeErr, "preserve the tree's rejection of inputs without a raw content digest")
			require.NoError(t, a.finishInventory())
			require.Equal(t, baseline, a.Materials(), "preserve every captured path and digest algorithm")
			require.Equal(t, root, a.MerkleRoot)
			require.Equal(t, size, a.TreeSize)
			require.Equal(t, uint64(2), size)
			ref := a.InventoryReference()
			require.Equal(t, 3, ref.FileCount, "count content paths, not unique digests or metadata-only paths")
			if !retain {
				require.Equal(t, "omitted", ref.State)
				return
			}
			body, err := a.InventoryBytes()
			require.NoError(t, err)
			entries, err := fileinventory.Verify(ref, body, "material", root, size)
			require.NoError(t, err)
			require.Equal(t, []fileinventory.Entry{
				{Path: "x", FileDigest: digestOf(t, "same")},
				{Path: "y", FileDigest: digestOf(t, "same")},
				{Path: "z", FileDigest: digestOf(t, "different")},
			}, entries)
		})
	}
}

func TestCompactMaterialInventoryMalformedRawDigest(t *testing.T) {
	for _, digest := range []string{"", "not-hex", "abcd"} {
		t.Run("digest="+digest, func(t *testing.T) {
			a := makeMaterialAttestor(t, map[string]string{"x": "same"}, WithCompactInventory(true))
			a.materials["bad"] = cryptoutil.DigestSet{{Hash: crypto.SHA256}: digest}
			require.Error(t, a.finishInventory(), "selected malformed raw digests must not be silently dropped")
		})
	}
}

func TestCompactMaterialSchema(t *testing.T) {
	raw, err := json.Marshal(New().Schema())
	require.NoError(t, err)
	schema, err := validation.CompileString("material.json", string(raw))
	require.NoError(t, err)
	for _, opts := range [][]Option{nil, {WithCompactInventory(false)}, {WithCompactInventory(true)}} {
		a := makeMaterialAttestor(t, map[string]string{"a": "content"}, opts...)
		raw, err := json.Marshal(a)
		require.NoError(t, err)
		var value map[string]any
		require.NoError(t, json.Unmarshal(raw, &value))
		require.NoError(t, schema.Validate(value))
		if a.Inventory != nil {
			value["leaves"] = []any{}
			require.Error(t, schema.Validate(value))
		}
	}
}

type inventoryTraceProbe struct {
	inputs map[string]attestation.CaptureEntry
}

func (*inventoryTraceProbe) Name() string                                 { return "inventory-trace-test" }
func (*inventoryTraceProbe) Type() string                                 { return "test/trace" }
func (*inventoryTraceProbe) RunType() attestation.RunType                 { return attestation.ExecuteRunType }
func (*inventoryTraceProbe) Attest(*attestation.AttestationContext) error { return nil }
func (*inventoryTraceProbe) Schema() *jsonschema.Schema                   { return jsonschema.Reflect(struct{}{}) }
func (*inventoryTraceProbe) CanProvide(mode attestation.CaptureMode) bool {
	return mode == attestation.CaptureTrace
}
func (p *inventoryTraceProbe) TraceInputs() map[string]attestation.CaptureEntry { return p.inputs }
func (*inventoryTraceProbe) TraceOutputs() map[string]attestation.CaptureEntry  { return nil }

func TestCompactMaterialTraceFinalization(t *testing.T) {
	for _, retain := range []bool{false, true} {
		a := New(WithCompactInventory(retain))
		probe := &inventoryTraceProbe{inputs: map[string]attestation.CaptureEntry{
			"/outside/a": {Digest: map[string]string{"sha256": digestOf(t, "same")}},
			"/outside/b": {Digest: map[string]string{"sha256": digestOf(t, "same")}},
		}}
		ctx, err := attestation.NewContext("trace", []attestation.Attestor{a, probe}, attestation.WithWorkingDir(t.TempDir()), attestation.WithCaptureMode(attestation.CaptureTrace))
		require.NoError(t, err)
		require.NoError(t, ctx.RunAttestors())
		require.NoError(t, a.Finalize(ctx))
		require.Equal(t, uint64(1), a.TreeSize)
		ref := a.InventoryReference()
		require.NotNil(t, ref)
		require.Equal(t, "trace", ref.CaptureMode)
		require.Equal(t, "trace-provider", ref.CaptureScope)
		require.Equal(t, 2, ref.FileCount)
		require.Len(t, a.Materials(), 2)
		if retain {
			_, err := a.InventoryBytes()
			require.NoError(t, err)
		}
	}
}

func TestCompactMaterialEmptyAndStrictParent(t *testing.T) {
	legacy := makeMaterialAttestor(t, nil)
	compact := makeMaterialAttestor(t, nil, WithCompactInventory(true))
	a, err := json.Marshal(legacy)
	require.NoError(t, err)
	b, err := json.Marshal(compact)
	require.NoError(t, err)
	require.Equal(t, a, b)
	require.Nil(t, compact.InventoryReference())
	require.Contains(t, string(b), `"leaves":[]`)
	nonempty := makeMaterialAttestor(t, map[string]string{"a": "content"}, WithCompactInventory(true))
	raw, err := json.Marshal(nonempty)
	require.NoError(t, err)
	for _, malformed := range [][]byte{
		bytes.Replace(raw, []byte(`"inventory":`), []byte(`"Inventory":`), 1),
		bytes.Replace(raw, []byte(`"inventory":`), []byte(`"leaves":[],"inventory":`), 1),
		bytes.Replace(raw, []byte(`"inventory":`), []byte(`"manifest":null,"inventory":`), 1),
		bytes.Replace(raw, []byte(`"inventory":`), []byte(`"manifestUploaded":false,"inventory":`), 1),
		bytes.Replace(raw, []byte(`"treeSize":1`), []byte(`"treeSize":0`), 1),
		bytes.Replace(raw, []byte(`"construction":"RFC6962"`), []byte(`"construction":"other"`), 1),
		bytes.Replace(raw, []byte(`"kind":"material"`), []byte(`"kind":"product"`), 1),
	} {
		var decoded Attestor
		require.Error(t, json.Unmarshal(malformed, &decoded), string(malformed))
	}
}
