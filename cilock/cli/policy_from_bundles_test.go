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

package cli

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writePolicyFixtureKey writes an ed25519 public key PEM to disk and
// returns its path + canonical keyid.
func writePolicyFixtureKey(t *testing.T, dir string) (pubPath, keyid string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubPath = filepath.Join(dir, "signer.pub")
	require.NoError(t, os.WriteFile(pubPath, pubPEM, 0o600))
	keyid, err = cryptoutil.GeneratePublicKeyID(pub, crypto.SHA256)
	require.NoError(t, err)
	return pubPath, keyid
}

// synthBundle synthesises a minimal DSSE envelope on disk with the
// given signing keyid and inner attestation types. The signature is
// not cryptographically valid — from-bundles never re-verifies it,
// only reads metadata.
func synthBundle(t *testing.T, dir, name, keyid string, innerTypes []string, isCollection bool) string {
	t.Helper()

	var stmt map[string]any
	if isCollection {
		atts := make([]map[string]string, 0, len(innerTypes))
		for _, tp := range innerTypes {
			atts = append(atts, map[string]string{"type": tp})
		}
		stmt = map[string]any{
			"_type":         "https://in-toto.io/Statement/v0.1",
			"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "00"}}},
			"predicateType": collectionPredicateURI,
			"predicate":     map[string]any{"attestations": atts},
		}
	} else {
		require.Len(t, innerTypes, 1, "non-collection bundles must declare exactly one predicate type")
		stmt = map[string]any{
			"_type":         "https://in-toto.io/Statement/v0.1",
			"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "00"}}},
			"predicateType": innerTypes[0],
			"predicate":     map[string]any{},
		}
	}

	stmtBytes, err := json.Marshal(stmt)
	require.NoError(t, err)

	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(stmtBytes),
		"signatures": []map[string]string{
			{"keyid": keyid, "sig": "dummy"},
		},
	}
	envBytes, err := json.Marshal(env)
	require.NoError(t, err)

	path := filepath.Join(dir, name+".bundle.json")
	require.NoError(t, os.WriteFile(path, envBytes, 0o600))
	return path
}

func TestDeriveStepName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/tmp/x/source-git.bundle.json", "source-git"},
		{"build-sops.bundle.json", "build-sops"},
		{"plain.json", "plain"},
		{"no-extension", "no-extension"},
		{"/tmp/.hidden.bundle.json", "hidden"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, deriveStepName(c.in), "input %q", c.in)
	}
}

func TestExtractPredicateTypes_BarePredicate(t *testing.T) {
	got := extractPredicateTypes("https://spdx.dev/Document", nil)
	assert.Equal(t, []string{"https://spdx.dev/Document"}, got)
}

func TestExtractPredicateTypes_CollectionFlattens(t *testing.T) {
	atts := []struct {
		Type string `json:"type"`
	}{
		{Type: "https://aflock.ai/attestations/git/v0.1"},
		{Type: "https://aflock.ai/attestations/command-run/v0.1"},
		{Type: "https://aflock.ai/attestations/git/v0.1"}, // dup
		{Type: ""}, // empty (ignored)
	}
	got := extractPredicateTypes(collectionPredicateURI, atts)
	// Output is sorted + deduped.
	assert.Equal(t, []string{
		"https://aflock.ai/attestations/command-run/v0.1",
		"https://aflock.ai/attestations/git/v0.1",
	}, got)
}

func TestPolicyFromBundles_HappyPath(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)

	srcPath := synthBundle(t, dir, "source-git", keyid,
		[]string{
			"https://aflock.ai/attestations/git/v0.1",
			"https://aflock.ai/attestations/material/v0.3",
		}, true)
	sbomPath := synthBundle(t, dir, "sbom", keyid,
		[]string{"https://spdx.dev/Document"}, false)

	var out bytes.Buffer
	err := runPolicyFromBundles(
		&out,
		[]string{srcPath, sbomPath},
		[]string{pubPath},
		"-",              // stdout
		365*24*time.Hour, // expires
		"",               // step prefix
	)
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))

	// PublicKeys: one entry, matching our fixture.
	require.Contains(t, pol.PublicKeys, keyid)
	assert.Equal(t, keyid, pol.PublicKeys[keyid].KeyID)
	assert.NotEmpty(t, pol.PublicKeys[keyid].Key)

	// Steps: source-git + sbom.
	require.Contains(t, pol.Steps, "source-git")
	require.Contains(t, pol.Steps, "sbom")

	src := pol.Steps["source-git"]
	require.Len(t, src.Functionaries, 1)
	assert.Equal(t, "publickey", src.Functionaries[0].Type)
	assert.Equal(t, keyid, src.Functionaries[0].PublicKeyID)
	// Inner attestations should be both git + material, sorted.
	attTypes := make([]string, len(src.Attestations))
	for i, a := range src.Attestations {
		attTypes[i] = a.Type
	}
	assert.Equal(t, []string{
		"https://aflock.ai/attestations/git/v0.1",
		"https://aflock.ai/attestations/material/v0.3",
	}, attTypes)

	// Bare-predicate bundle: one attestation, the outer predicateType.
	sbom := pol.Steps["sbom"]
	require.Len(t, sbom.Attestations, 1)
	assert.Equal(t, "https://spdx.dev/Document", sbom.Attestations[0].Type)

	// Expiry within a sensible window.
	assert.True(t, pol.Expires.After(time.Now().Add(364*24*time.Hour)),
		"expires should be ~1y from now, got %v", pol.Expires)
}

func TestPolicyFromBundles_UnknownKeyIDGetsPlaceholder(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := writePolicyFixtureKey(t, dir)
	bundlePath := synthBundle(t, dir, "rogue", "unknownkeyid12345",
		[]string{"https://example.com/rogue/v1"}, false)

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, []string{bundlePath}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))

	// Placeholder publickey for the unknown signing key.
	require.Contains(t, pol.PublicKeys, "unknownkeyid12345")
	assert.Empty(t, pol.PublicKeys["unknownkeyid12345"].Key,
		"PEM material should be empty when -k didn't cover this keyid; user must fill in")
}

func TestPolicyFromBundles_DuplicateStepNameFails(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)

	// Two bundles with the same basename in different subdirs.
	subA := filepath.Join(dir, "a")
	subB := filepath.Join(dir, "b")
	require.NoError(t, os.MkdirAll(subA, 0o755))
	require.NoError(t, os.MkdirAll(subB, 0o755))
	aPath := synthBundle(t, subA, "build", keyid, []string{"x/v1"}, false)
	bPath := synthBundle(t, subB, "build", keyid, []string{"x/v1"}, false)

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, []string{aPath, bPath}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate step name")
}

func TestPolicyFromBundles_StepPrefixApplied(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)
	bundlePath := synthBundle(t, dir, "build", keyid, []string{"x/v1"}, false)

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, []string{bundlePath}, []string{pubPath}, "-", 365*24*time.Hour, "release-")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))
	assert.Contains(t, pol.Steps, "release-build")
}

func TestPolicyFromBundles_OutputFile(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)
	bundlePath := synthBundle(t, dir, "build", keyid, []string{"x/v1"}, false)
	outPath := filepath.Join(dir, "policy.json")

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, []string{bundlePath}, []string{pubPath}, outPath, 365*24*time.Hour, "")
	require.NoError(t, err)

	// Output file exists, stdout is empty.
	assert.Empty(t, out.String(), "writing to a file must not duplicate the content to stdout")
	body, err := os.ReadFile(outPath)
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(body, &pol))
	assert.Contains(t, pol.Steps, "build")
}

func TestPolicyFromBundles_NoBundlesFails(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := writePolicyFixtureKey(t, dir)
	var out bytes.Buffer
	err := runPolicyFromBundles(&out, nil, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.Error(t, err)
}

func TestPolicyFromBundles_BadEnvelopeFails(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := writePolicyFixtureKey(t, dir)
	bad := filepath.Join(dir, "bad.bundle.json")
	require.NoError(t, os.WriteFile(bad, []byte("not json"), 0o600))

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, []string{bad}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "summarize")
}
