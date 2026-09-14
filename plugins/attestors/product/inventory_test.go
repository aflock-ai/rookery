// jade:ring local

package product

import (
	"bytes"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	validation "github.com/santhosh-tekuri/jsonschema/v5"
	"github.com/stretchr/testify/require"
)

func TestCompactProductCompanions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		files    map[string]string
		opts     []Option
		retained bool
	}{
		{name: "legacy", files: map[string]string{"out": "output"}},
		{name: "inline", files: map[string]string{"out": "output"}, opts: []Option{WithCompactInventory(1 << 20)}},
		{name: "empty", opts: []Option{WithCompactInventory(0)}},
		{name: "budget-spill", files: map[string]string{"out": "output"}, opts: []Option{WithCompactInventory(0)}, retained: true},
		{name: "duplicate-content", files: map[string]string{"a": "same", "b": "same"}, opts: []Option{WithCompactInventory(1 << 20)}, retained: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := makeAttestorWithOpts(t, tc.files, tc.opts...)
			var producer attestation.Attestor = a
			exporter, ok := producer.(attestation.CompanionExporter)
			require.True(t, ok, "workflow requires the CompanionExporter interface, not only InventoryExporter")
			typer, ok := producer.(attestation.CompanionTyper)
			require.True(t, ok)
			require.Equal(t, []string{fileinventory.Type}, typer.CompanionTypes())
			require.Equal(t, "product", producer.Name())
			require.Equal(t, "https://aflock.ai/attestations/product/v0.3", producer.Type())
			require.Equal(t, "material", material.New().Name())
			require.Equal(t, "https://aflock.ai/attestations/material/v0.3", material.New().Type())
			companions := exporter.Companions()
			if !tc.retained {
				require.Nil(t, companions)
				return
			}
			require.Len(t, companions, 1)
			companion := companions[0]
			require.Equal(t, fileinventory.Type, companion.Type())
			require.Equal(t, "inventory", companion.Name())
			body, err := json.Marshal(companion)
			require.NoError(t, err)
			retained, err := a.InventoryBytes()
			require.NoError(t, err)
			require.Equal(t, retained, body)
			ref := a.InventoryReference()
			entries, err := fileinventory.Verify(ref, body, "product", a.MerkleRoot, a.TreeSize)
			require.NoError(t, err)
			require.Len(t, entries, len(tc.files))
			require.Equal(t, map[string]cryptoutil.DigestSet{"inventory:product": {{Hash: crypto.SHA256}: ref.Digest}}, companion.(attestation.Subjecter).Subjects())

			parent, err := json.Marshal(a)
			require.NoError(t, err)
			var decoded Attestor
			require.NoError(t, json.Unmarshal(parent, &decoded))
			require.Nil(t, any(&decoded).(attestation.CompanionExporter).Companions(), "a reference without retained bytes cannot emit a companion")
		})
	}
	var fresh attestation.Attestor = New()
	exporter, ok := fresh.(attestation.CompanionExporter)
	require.True(t, ok)
	require.Nil(t, exporter.Companions())
	typer, ok := fresh.(attestation.CompanionTyper)
	require.True(t, ok)
	require.Equal(t, []string{fileinventory.Type}, typer.CompanionTypes())
}

func TestCompactProductInventoryBudget(t *testing.T) {
	files := map[string]string{"a.sarif": "first", "b": "second"}
	legacy := makeAttestor(t, files)
	inline, err := json.Marshal(legacy)
	require.NoError(t, err)
	for _, budget := range []int{len(inline), len(inline) - 1, 0} {
		a := makeAttestorWithOpts(t, files, WithCompactInventory(budget))
		require.Equal(t, "product", a.Name())
		require.Equal(t, "https://aflock.ai/attestations/product/v0.3", a.Type())
		require.Equal(t, legacy.MerkleRoot, a.MerkleRoot)
		raw, err := json.Marshal(a)
		require.NoError(t, err)
		if budget == len(inline) {
			require.Nil(t, a.InventoryReference())
			require.Equal(t, inline, raw)
			continue
		}
		require.NotContains(t, string(raw), `"leaves"`)
		ref := a.InventoryReference()
		require.NotNil(t, ref)
		require.Equal(t, "walk", ref.CaptureMode)
		body, err := a.InventoryBytes()
		require.NoError(t, err)
		entries, err := fileinventory.Verify(ref, body, "product", a.MerkleRoot, a.TreeSize)
		require.NoError(t, err)
		require.Equal(t, "sarif", entries[0].Kind)
		require.NotEmpty(t, entries[0].MIMEType)
		var decoded Attestor
		require.NoError(t, json.Unmarshal(raw, &decoded))
		require.Empty(t, decoded.Products())
		require.Error(t, decoded.HydrateInventory(bytes.Replace(body, []byte(`"path":"b"`), []byte(`"path":"z"`), 1)))
		require.Empty(t, decoded.Products())
		require.NoError(t, decoded.HydrateInventory(body))
		require.Len(t, decoded.Products(), 2)
		require.Equal(t, entries[0].MIMEType, decoded.Products()["a.sarif"].MimeType)
		require.Equal(t, "sarif", decoded.Leaves()[0].Kind)
		after, err := json.Marshal(&decoded)
		require.NoError(t, err)
		require.Equal(t, raw, after)
	}
}

func TestCompactProductSchema(t *testing.T) {
	raw, err := json.Marshal(New().Schema())
	require.NoError(t, err)
	schema, err := validation.CompileString("product.json", string(raw))
	require.NoError(t, err)
	for _, opts := range [][]Option{nil, {WithCompactInventory(0)}} {
		a := makeAttestorWithOpts(t, map[string]string{"a": "content"}, opts...)
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

func TestCompactMaterialBaselineStillFiltersProducts(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "input"), []byte("input"), 0600))
	mat := material.New(material.WithCompactInventory(false))
	ctx, err := attestation.NewContext("baseline", []attestation.Attestor{mat}, attestation.WithWorkingDir(dir), attestation.WithCaptureMode(attestation.CaptureWalk))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	require.Len(t, ctx.Materials(), 1)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "output"), []byte("output"), 0600))
	prod := New(WithCompactInventory(0))
	require.NoError(t, prod.Attest(ctx))
	require.Len(t, prod.Products(), 1)
	require.Contains(t, prod.Products(), "output")
	require.Equal(t, 1, prod.InventoryReference().FileCount)
}

func TestCompactProductPreservesCollapsedPaths(t *testing.T) {
	for _, files := range []map[string]string{
		{"a": "same", "b": "same"},
		{`a\b`: "first", "a/b": "second"},
	} {
		a := makeAttestorWithOpts(t, files, WithCompactInventory(1<<20))
		ref := a.InventoryReference()
		require.NotNil(t, ref, "must detach when legacy path/content projection would collapse")
		require.Equal(t, 2, ref.FileCount)
		body, err := a.InventoryBytes()
		require.NoError(t, err)
		entries, err := fileinventory.Verify(ref, body, "product", a.MerkleRoot, a.TreeSize)
		require.NoError(t, err)
		require.Len(t, entries, 2)
		for _, e := range entries {
			require.Contains(t, files, e.Path)
		}
	}
	a := makeAttestorWithOpts(t, map[string]string{`nested\bom.json`: "{}"}, WithCompactInventory(1<<20))
	body, err := a.InventoryBytes()
	require.NoError(t, err)
	entries, err := fileinventory.Verify(a.InventoryReference(), body, "product", a.MerkleRoot, a.TreeSize)
	require.NoError(t, err)
	require.Equal(t, `nested\bom.json`, entries[0].Path)
	require.Equal(t, "cyclonedx", entries[0].Kind, "retain the existing normalized-path kind hint")
}

type inventoryProductProbe struct {
	*Attestor
	outputs map[string]attestation.CaptureEntry
}

func (*inventoryProductProbe) Name() string                                 { return "inventory-trace-test" }
func (*inventoryProductProbe) Type() string                                 { return "test/trace" }
func (*inventoryProductProbe) RunType() attestation.RunType                 { return attestation.ExecuteRunType }
func (*inventoryProductProbe) Attest(*attestation.AttestationContext) error { return nil }
func (*inventoryProductProbe) CanProvide(mode attestation.CaptureMode) bool {
	return mode == attestation.CaptureTrace
}
func (*inventoryProductProbe) TraceInputs() map[string]attestation.CaptureEntry    { return nil }
func (p *inventoryProductProbe) TraceOutputs() map[string]attestation.CaptureEntry { return p.outputs }

func TestCompactProductReportsActualCaptureBranch(t *testing.T) {
	for _, completed := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "out")
		require.NoError(t, os.WriteFile(path, []byte("output"), 0600))
		probe := &inventoryProductProbe{Attestor: New(), outputs: map[string]attestation.CaptureEntry{
			path: {Digest: map[string]string{"sha256": sha256Hex(t, "output")}},
		}}
		a := New(WithCompactInventory(0))
		ctx, err := attestation.NewContext("trace", []attestation.Attestor{probe}, attestation.WithWorkingDir(dir), attestation.WithCaptureMode(attestation.CaptureTrace),
			attestation.WithCachePatternOptions(attestation.CachePatternOptions{DisableDefaults: true, DisableSystemQuery: true}))
		require.NoError(t, err)
		mode := "walk"
		if completed {
			require.NoError(t, ctx.RunAttestors())
			mode = "trace"
		}
		require.NoError(t, a.Attest(ctx))
		require.Equal(t, mode, a.InventoryReference().CaptureMode)
	}
}

func TestCompactProductEmptyAndStrictParent(t *testing.T) {
	legacy := makeAttestor(t, nil)
	compact := makeAttestorWithOpts(t, nil, WithCompactInventory(0))
	a, err := json.Marshal(legacy)
	require.NoError(t, err)
	b, err := json.Marshal(compact)
	require.NoError(t, err)
	require.Equal(t, a, b)
	require.Nil(t, compact.InventoryReference())
	nonempty := makeAttestorWithOpts(t, map[string]string{"a": "content"}, WithCompactInventory(0))
	raw, err := json.Marshal(nonempty)
	require.NoError(t, err)
	for _, malformed := range [][]byte{
		bytes.Replace(raw, []byte(`"inventory":`), []byte(`"inventory":null,"inventory":`), 1),
		bytes.Replace(raw, []byte(`"inventory":`), []byte(`"INVENTORY":`), 1),
		bytes.Replace(raw, []byte(`"inventory":`), []byte(`"leaves":null,"inventory":`), 1),
		bytes.Replace(raw, []byte(`"inventory":`), []byte(`"manifestUploaded":true,"inventory":`), 1),
		bytes.Replace(raw, []byte(`"treeSize":1`), []byte(`"treeSize":2`), 1),
		bytes.Replace(raw, []byte(`"hashAlgorithm":"sha256"`), []byte(`"hashAlgorithm":"sha1"`), 1),
		bytes.Replace(raw, []byte(`"kind":"product"`), []byte(`"kind":"material"`), 1),
	} {
		var decoded Attestor
		require.Error(t, json.Unmarshal(malformed, &decoded), string(malformed))
	}
}
