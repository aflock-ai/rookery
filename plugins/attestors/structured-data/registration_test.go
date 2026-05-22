// Copyright 2026 The Witness Contributors
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

// registration_test.go guards the CLI surface of the structured-data attestor.
// rookery#111: init() previously omitted ConfigOption wiring, so the With*
// setters were unreachable from the command line — `cilock attestors info
// structured-data` listed zero options and `--attestor-structured-data-...`
// flags didn't exist.

package structureddata

import (
	"crypto"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/require"
)

// TestRegistration_ListsAllOptions verifies the attestor exposes all five
// expected configuration options through the registry. This is the data
// powering `cilock attestors info structured-data`.
func TestRegistration_ListsAllOptions(t *testing.T) {
	opts := attestation.AttestorOptions(Name)
	got := make(map[string]bool, len(opts))
	for _, opt := range opts {
		got[opt.Name()] = true
	}

	wantNames := []string{
		"data-file",
		"subject-query",
		"subject-prefix",
		"data-type",
		"embed-data",
	}
	for _, name := range wantNames {
		require.Truef(t, got[name], "option %q not registered; have %v", name, got)
	}
	require.Lenf(t, got, len(wantNames), "expected exactly %d options, got %d: %v", len(wantNames), len(got), got)
}

// TestRegistration_EndToEnd_WithSubjectQuery verifies the attestor obtained
// via attestation.GetAttestor (the production CLI path) actually attests
// against a JSON fixture once subject-query is set via the setter.
func TestRegistration_EndToEnd_WithSubjectQuery(t *testing.T) {
	a, err := attestation.GetAttestor(Name)
	require.NoError(t, err)
	attestor, ok := a.(*Attestor)
	require.True(t, ok, "GetAttestor returned wrong type: %T", a)

	// Simulate `--attestor-structured-data-subject-query=$.identities[*].id`
	// being parsed by the registry.
	WithSubjectQuery("$.identities[*].id")(attestor)
	WithSubjectPrefix("test:id:")(attestor)
	WithDataType("test")(attestor)

	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	body := `{"identities":[{"id":"abc-123"},{"id":"def-456"}]}`
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	dig, err := cryptoutil.CalculateDigestSetFromFile(path, hashes)
	require.NoError(t, err)

	ctx, err := attestation.NewContext("structured-data-registration-test",
		[]attestation.Attestor{&fakeProducer{path: path, digest: dig}, attestor},
		attestation.WithHashes(hashes),
	)
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())

	subs := attestor.Subjects()
	require.Contains(t, subs, "test:id:abc-123")
	require.Contains(t, subs, "test:id:def-456")
}
