// Copyright 2026 The Aflock Authors
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

package sarif

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestName / TestType / TestRunType pin the registration surface — these
// strings are what consumers pass to --attestations and what verifiers
// match on the predicate type. They should not change without a major
// version bump.
func TestName(t *testing.T) {
	a := New()
	assert.Equal(t, Name, a.Name())
}

func TestType(t *testing.T) {
	a := New()
	assert.Equal(t, Type, a.Type())
}

func TestRunType(t *testing.T) {
	a := New()
	assert.Equal(t, RunType, a.RunType())
}

// TestAttest_HappyPath exercises the full Attestor lifecycle against the
// canonical SARIF 2.1.0 fixture: product attestor classifies the file,
// sarif attestor reads it, stores the report, and records the file path
// + digest. After Attest, marshaling the attestor must round-trip the
// SARIF document content cleanly.
func TestAttest_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, copyFixture(t, "testdata/example.sarif.json", filepath.Join(tmp, "example.sarif.json")))

	sarifAttestor := New()
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sarifAttestor},
		attestation.WithWorkingDir(tmp))
	require.NoError(t, err)

	require.NoError(t, ctx.RunAttestors())

	assert.Equal(t, "example.sarif.json", sarifAttestor.ReportFile, "ReportFile must be the relative path")
	assert.NotEmpty(t, sarifAttestor.ReportDigestSet, "ReportDigestSet must be populated")

	// Marshal the attestor and verify the embedded report is intact.
	out, err := json.Marshal(sarifAttestor)
	require.NoError(t, err)

	var wrapper struct {
		Report   json.RawMessage `json:"report"`
		FileName string          `json:"reportFileName"`
	}
	require.NoError(t, json.Unmarshal(out, &wrapper))
	assert.Equal(t, "example.sarif.json", wrapper.FileName)

	// The embedded report should at minimum carry the SARIF version field.
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(wrapper.Report, &parsed))
	assert.Equal(t, "2.1.0", parsed["version"], "SARIF version field must survive round-trip")
}

// TestAttest_NoProducts surfaces the empty-context error so callers know
// to expect it on misconfiguration rather than getting silent success.
func TestAttest_NoProducts(t *testing.T) {
	sarifAttestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{sarifAttestor},
		attestation.WithWorkingDir(t.TempDir()))
	require.NoError(t, err)

	err = sarifAttestor.Attest(ctx)
	if err == nil {
		t.Fatalf("expected error on empty product context, got nil")
	}
	assert.Contains(t, err.Error(), "no products")
}

// TestAttest_NonSARIFProduct verifies that a file with the wrong MIME
// type is skipped — the attestor only consumes SARIF/JSON. We check the
// attestor's recorded state after RunAttestors (which doesn't propagate
// per-attestor errors), since the contract here is "Report stays empty
// and the per-attestor CompletedAttestor records an error."
func TestAttest_NonSARIFProduct(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "binary.bin"),
		// 4 bytes of binary content — mimetype will classify as
		// application/octet-stream, which doesn't match sarif's
		// {"text/plain", "application/json"} list.
		[]byte{0x00, 0xff, 0x12, 0x34}, 0o644))

	sarifAttestor := New()
	p := product.New()

	ctx, err := attestation.NewContext("test", []attestation.Attestor{p, sarifAttestor},
		attestation.WithWorkingDir(tmp))
	require.NoError(t, err)

	_ = ctx.RunAttestors()

	// The attestor's state should remain empty after the wrong-MIME run.
	assert.Empty(t, sarifAttestor.ReportFile, "ReportFile must stay empty when no SARIF product is present")
	assert.Empty(t, sarifAttestor.Report, "Report must stay empty when no SARIF product is present")
}

func copyFixture(t *testing.T, src, dst string) error {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}
