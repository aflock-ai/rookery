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

package linkerdcheck

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func defaultHashes() []cryptoutil.DigestValue {
	return []cryptoutil.DigestValue{
		{Hash: crypto.SHA256},
		{Hash: crypto.SHA256, GitOID: true},
		{Hash: crypto.SHA1, GitOID: true},
	}
}

// fakeProducer registers files as products so the attestation context
// exposes them to PostProduct attestors.
type fakeProducer struct {
	products map[string]attestation.Product
}

func (fp *fakeProducer) Name() string                                   { return "fake-producer" }
func (fp *fakeProducer) Type() string                                   { return "fake-type" }
func (fp *fakeProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (fp *fakeProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (fp *fakeProducer) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(fp) }
func (fp *fakeProducer) Products() map[string]attestation.Product       { return fp.products }

// productContext builds an AttestationContext whose product set contains
// each file passed in. Mime type is set to application/json.
func productContext(t *testing.T, dir string, paths ...string) *attestation.AttestationContext {
	t.Helper()
	hashes := defaultHashes()
	prods := map[string]attestation.Product{}
	for _, p := range paths {
		ds, err := cryptoutil.CalculateDigestSetFromFile(p, hashes)
		require.NoError(t, err)
		prods[p] = attestation.Product{MimeType: "application/json", Digest: ds}
	}
	prod := &fakeProducer{products: prods}
	ctx, err := attestation.NewContext("test", []attestation.Attestor{prod},
		attestation.WithWorkingDir(dir),
		attestation.WithHashes(hashes),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return ctx
}

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, data, 0600))
	return p
}

func writeBytes(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, data, 0600))
	return p
}

// ── unit tests ───────────────────────────────────────────────────────────────

func TestAttestorIdentity(t *testing.T) {
	a := New()
	assert.Equal(t, Name, a.Name())
	assert.Equal(t, Type, a.Type())
	assert.Equal(t, RunType, a.RunType())
	assert.NotNil(t, a.Schema())
}

func TestAttest_NoProducts(t *testing.T) {
	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{a})
	require.NoError(t, err)
	err = a.Attest(ctx)
	assert.ErrorContains(t, err, "no products")
}

func TestAttest_CheckOnly_AllSuccess(t *testing.T) {
	dir := t.TempDir()
	report := CheckReport{
		Success: true,
		Categories: []CheckCategory{
			{
				CategoryName: "kubernetes-api",
				Checks: []Check{
					{Description: "can initialize the client", Result: "success"},
					{Description: "can query the Kubernetes API", Result: "success"},
				},
			},
			{
				CategoryName: "linkerd-existence",
				Checks: []Check{
					{Description: "control plane pods are ready", Result: "success"},
				},
			},
		},
	}
	path := writeJSON(t, dir, "linkerd-check.json", report)

	a := New()
	a.ClusterName = "test-cluster"
	ctx := productContext(t, dir, path)
	require.NoError(t, a.Attest(ctx))

	assert.Equal(t, path, a.CheckFile)
	assert.True(t, a.CheckSummary.OverallSuccess)
	assert.Equal(t, 3, a.CheckSummary.Pass)
	assert.Equal(t, 0, a.CheckSummary.Warn)
	assert.Equal(t, 0, a.CheckSummary.Error)
	assert.Equal(t, 2, a.CheckSummary.DistinctCategory)
	require.Len(t, a.CheckSummary.Categories, 2)
}

func TestAttest_CheckOnly_MixedResults(t *testing.T) {
	dir := t.TempDir()
	report := CheckReport{
		Success: false,
		Categories: []CheckCategory{
			{
				CategoryName: "linkerd-identity",
				Checks: []Check{
					{Description: "certs valid", Result: "success"},
					{Description: "issuer about to expire", Result: "warning", Hint: "https://linkerd.io/...", Error: "expires in 7 days"},
					{Description: "trust anchor missing", Result: "error", Error: "no anchor"},
				},
			},
		},
	}
	path := writeJSON(t, dir, "linkerd-check.json", report)

	a := New()
	ctx := productContext(t, dir, path)
	require.NoError(t, a.Attest(ctx))

	assert.False(t, a.CheckSummary.OverallSuccess)
	assert.Equal(t, 1, a.CheckSummary.Pass)
	assert.Equal(t, 1, a.CheckSummary.Warn)
	assert.Equal(t, 1, a.CheckSummary.Error)
	require.Len(t, a.CheckSummary.Categories, 1)
	roll := a.CheckSummary.Categories[0]
	assert.Equal(t, "linkerd-identity", roll.Category)
	assert.Equal(t, []string{"issuer about to expire"}, roll.Warnings)
	assert.Equal(t, []string{"trust anchor missing"}, roll.Errors)
}

func TestAttest_CheckAndEdges(t *testing.T) {
	dir := t.TempDir()
	check := CheckReport{
		Success: true,
		Categories: []CheckCategory{{
			CategoryName: "kubernetes-api",
			Checks:       []Check{{Description: "ok", Result: "success"}},
		}},
	}
	edges := EdgeReport{
		{Src: "web", SrcNamespace: "emojivoto", Dst: "voting", DstNamespace: "emojivoto", ClientID: "default.emojivoto", ServerID: "voting.emojivoto"},
		{Src: "web", SrcNamespace: "emojivoto", Dst: "emoji", DstNamespace: "emojivoto", ClientID: "default.emojivoto", ServerID: "emoji.emojivoto"},
		{Src: "vote-bot", SrcNamespace: "emojivoto", Dst: "web", DstNamespace: "emojivoto", NoTLSReason: "proxy not configured"},
	}
	checkPath := writeJSON(t, dir, "linkerd-check.json", check)
	edgesPath := writeJSON(t, dir, "linkerd-edges.json", edges)

	a := New()
	ctx := productContext(t, dir, checkPath, edgesPath)
	require.NoError(t, a.Attest(ctx))

	assert.Equal(t, checkPath, a.CheckFile)
	assert.Equal(t, edgesPath, a.EdgesFile)
	require.NotNil(t, a.EdgesSummary)
	assert.Equal(t, 3, a.EdgesSummary.TotalEdges)
	assert.Equal(t, 2, a.EdgesSummary.Secured)
	assert.Equal(t, 1, a.EdgesSummary.Insecure)
}

func TestAttest_BadJSON_Skipped(t *testing.T) {
	dir := t.TempDir()
	good := CheckReport{
		Success:    true,
		Categories: []CheckCategory{{CategoryName: "ok", Checks: []Check{{Description: "x", Result: "success"}}}},
	}
	goodPath := writeJSON(t, dir, "linkerd-check.json", good)
	_ = writeBytes(t, dir, "garbage.json", []byte("{this is not json"))

	a := New()
	ctx := productContext(t, dir, goodPath, filepath.Join(dir, "garbage.json"))
	require.NoError(t, a.Attest(ctx))
	assert.Equal(t, goodPath, a.CheckFile)
	assert.Empty(t, a.EdgesFile)
}

func TestAttest_OnlyEdgesFile_Fails(t *testing.T) {
	dir := t.TempDir()
	edges := EdgeReport{
		{Src: "a", Dst: "b", SrcNamespace: "ns", DstNamespace: "ns", ClientID: "x", ServerID: "y"},
	}
	edgesPath := writeJSON(t, dir, "linkerd-edges.json", edges)

	a := New()
	ctx := productContext(t, dir, edgesPath)
	err := a.Attest(ctx)
	assert.ErrorContains(t, err, "no linkerd check report")
}

func TestAttest_RealCheckFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/check-real.json")
	require.NoError(t, err)
	dir := t.TempDir()
	path := writeBytes(t, dir, "linkerd-check.json", body)

	a := New()
	ctx := productContext(t, dir, path)
	require.NoError(t, a.Attest(ctx))

	assert.True(t, a.CheckSummary.OverallSuccess)
	assert.Greater(t, a.CheckSummary.Pass, 0)
	// The fixture has 4 warnings (version-channel + proxy-version mismatches)
	assert.GreaterOrEqual(t, a.CheckSummary.Warn, 4)
	assert.Equal(t, 0, a.CheckSummary.Error)
	// Spot-check a known category from the real output
	found := false
	for _, c := range a.CheckSummary.Categories {
		if c.Category == "linkerd-identity" {
			found = true
			break
		}
	}
	assert.True(t, found, "expected linkerd-identity category in real fixture")
}

func TestAttest_RealEdgesFixture(t *testing.T) {
	checkBody, err := os.ReadFile("testdata/check-real.json")
	require.NoError(t, err)
	edgesBody, err := os.ReadFile("testdata/edges-real.json")
	require.NoError(t, err)

	dir := t.TempDir()
	checkPath := writeBytes(t, dir, "linkerd-check.json", checkBody)
	edgesPath := writeBytes(t, dir, "linkerd-edges.json", edgesBody)

	a := New()
	ctx := productContext(t, dir, checkPath, edgesPath)
	require.NoError(t, a.Attest(ctx))

	require.NotNil(t, a.EdgesSummary)
	// Real fixture: 15 edges, all mTLS-secured (emojivoto demo)
	assert.Equal(t, 15, a.EdgesSummary.TotalEdges)
	assert.Equal(t, 15, a.EdgesSummary.Secured)
	assert.Equal(t, 0, a.EdgesSummary.Insecure)
	assert.Contains(t, a.EdgesSummary.DistinctSrcNS, "emojivoto")
}

func TestSecured(t *testing.T) {
	cases := []struct {
		name   string
		edge   Edge
		secure bool
	}{
		{"both IDs + empty reason", Edge{ClientID: "c", ServerID: "s"}, true},
		{"client missing", Edge{ServerID: "s"}, false},
		{"server missing", Edge{ClientID: "c"}, false},
		{"both present + reason set", Edge{ClientID: "c", ServerID: "s", NoTLSReason: "boom"}, false},
		{"all empty", Edge{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.secure, tc.edge.Secured())
		})
	}
}

func TestSubjects(t *testing.T) {
	a := &Attestor{
		CheckFile:      "/tmp/check.json",
		CheckDigestSet: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc"},
		EdgesFile:      "/tmp/edges.json",
		EdgesDigestSet: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "def"},
		ClusterName:    "prod-eks",
		CheckSummary:   CheckSummary{OverallSuccess: true},
	}
	subs := a.Subjects()
	assert.Contains(t, subs, "check_file:/tmp/check.json")
	assert.Contains(t, subs, "edges_file:/tmp/edges.json")
	assert.Contains(t, subs, "cluster:prod-eks")
	assert.Contains(t, subs, "linkerd-overall:success")
}

func TestSubjects_OverallFail(t *testing.T) {
	a := &Attestor{
		CheckFile:      "/tmp/check.json",
		CheckDigestSet: cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: "abc"},
		CheckSummary:   CheckSummary{OverallSuccess: false},
	}
	subs := a.Subjects()
	assert.Contains(t, subs, "linkerd-overall:fail")
	assert.NotContains(t, subs, "linkerd-overall:success")
}

func TestEnvClusterName(t *testing.T) {
	t.Setenv(envClusterName, "my-cluster")
	a := New()
	assert.Equal(t, "my-cluster", a.ClusterName)
}
