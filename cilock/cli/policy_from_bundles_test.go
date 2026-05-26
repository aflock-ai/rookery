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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
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

// synthBundleWithFilename is the issue-#224 testing variant of
// synthBundle. It lets the caller decouple the on-disk filename
// (`filename`, e.g. `argocd-cli-v3.att.json`) from the recorded
// collection name in the bundle payload (`recordedName`, what
// `cilock run -s <name>` writes into predicate.name). isCollection
// is always true here because the bug only manifests for collection
// envelopes — bare-predicate envelopes don't carry a name.
//
// Pass recordedName="" to mimic an old/malformed bundle that lacks a
// predicate.name field, exercising the filename-fallback path.
func synthBundleWithFilename(t *testing.T, dir, filename, recordedName, keyid string, innerTypes []string) string {
	t.Helper()
	atts := make([]map[string]string, 0, len(innerTypes))
	for _, tp := range innerTypes {
		atts = append(atts, map[string]string{"type": tp})
	}
	predicate := map[string]any{"attestations": atts}
	if recordedName != "" {
		predicate["name"] = recordedName
	}
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "00"}}},
		"predicateType": collectionPredicateURI,
		"predicate":     predicate,
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

	path := filepath.Join(dir, filename)
	require.NoError(t, os.WriteFile(path, envBytes, 0o600))
	return path
}

// writeBarePredicateSidecar synthesizes the kind of DSSE envelope
// cilock's --attestor-*-export flags produce: a signed envelope whose
// inner statement carries a bare predicate (no attestation-collection
// wrapper). Used by the sidecar auto-discovery tests.
func writeBarePredicateSidecar(t *testing.T, path, keyid, predicateType string) {
	t.Helper()
	stmt := map[string]any{
		"_type":         "https://in-toto.io/Statement/v0.1",
		"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "00"}}},
		"predicateType": predicateType,
		"predicate":     map[string]any{},
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
	require.NoError(t, os.WriteFile(path, envBytes, 0o600))
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
		// Issue #224: additional fallback extensions.
		{"foo.att.json", "foo"},
		{"argocd-cli-v3.att.json", "argocd-cli-v3"},
		{"build.envelope.json", "build"},
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
		io.Discard,
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

	// Steps: only the collection bundle (source-git) becomes a Step.
	// The bare-predicate sbom bundle goes into ExternalAttestations
	// instead — see TestPolicyFromBundles_BarePredicateGoesToExternal
	// for the regression coverage.
	require.Contains(t, pol.Steps, "source-git")
	assert.NotContains(t, pol.Steps, "sbom",
		"bare-predicate bundles must not be routed into Steps[]")
	require.Contains(t, pol.ExternalAttestations, "sbom",
		"bare-predicate bundles must land in ExternalAttestations[]")
	assert.Equal(t, "https://spdx.dev/Document", pol.ExternalAttestations["sbom"].PredicateType)

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
	err := runPolicyFromBundles(&out, io.Discard, []string{bundlePath}, []string{pubPath}, "-", 365*24*time.Hour, "")
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

	// Two collection bundles with the same basename in different subdirs.
	subA := filepath.Join(dir, "a")
	subB := filepath.Join(dir, "b")
	require.NoError(t, os.MkdirAll(subA, 0o755))
	require.NoError(t, os.MkdirAll(subB, 0o755))
	aPath := synthBundle(t, subA, "build", keyid, []string{"x/v1"}, true)
	bPath := synthBundle(t, subB, "build", keyid, []string{"x/v1"}, true)

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{aPath, bPath}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate step name")
}

func TestPolicyFromBundles_StepPrefixApplied(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)
	bundlePath := synthBundle(t, dir, "build", keyid, []string{"x/v1"}, true)

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{bundlePath}, []string{pubPath}, "-", 365*24*time.Hour, "release-")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))
	assert.Contains(t, pol.Steps, "release-build")
}

func TestPolicyFromBundles_OutputFile(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)
	bundlePath := synthBundle(t, dir, "build", keyid, []string{"x/v1"}, true)
	outPath := filepath.Join(dir, "policy.json")

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{bundlePath}, []string{pubPath}, outPath, 365*24*time.Hour, "")
	require.NoError(t, err)

	// Output file exists, stdout is empty.
	assert.Empty(t, out.String(), "writing to a file must not duplicate the content to stdout")
	body, err := os.ReadFile(outPath)
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(body, &pol))
	assert.Contains(t, pol.Steps, "build")
}

// TestPolicyFromBundles_BarePredicateGoesToExternal exercises the
// blind-test #2 friction #7 bug: prior to this fix, a bare-predicate
// envelope (e.g., the inclusion-proof DSSE that `cilock prove`
// emits) was incorrectly routed into Steps[] expecting a collection,
// which `cilock verify` could never satisfy. The fix: bare predicates
// go into ExternalAttestations[] instead.
func TestPolicyFromBundles_BarePredicateGoesToExternal(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)

	// synthBundle with isCollection=false produces a bare-predicate
	// envelope (predicateType = the inner URI, no attestation-collection
	// wrapper). This mirrors what `cilock prove` writes.
	bundlePath := synthBundle(t, dir, "inclusion", keyid,
		[]string{"https://aflock.ai/attestations/inclusion-proof/v0.1"}, false)

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{bundlePath}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))

	// Crucially: no Step for "inclusion" — that would be unverifiable.
	assert.NotContains(t, pol.Steps, "inclusion",
		"bare-predicate envelopes must NOT generate a Step (would always fail verify)")

	// They go into ExternalAttestations instead.
	require.Contains(t, pol.ExternalAttestations, "inclusion")
	ext := pol.ExternalAttestations["inclusion"]
	assert.Equal(t, "https://aflock.ai/attestations/inclusion-proof/v0.1", ext.PredicateType)
	assert.True(t, ext.Required, "starter policies should require external attestations by default")
	require.Len(t, ext.Functionaries, 1)
	assert.Equal(t, keyid, ext.Functionaries[0].PublicKeyID)
}

// TestPolicyFromBundles_SidecarsAutoDiscovered covers the blind-test
// #9 silent-downgrade bug. When `cilock run --attestor-sbom-export`
// is used, the SBOM predicate moves to a sibling file
// `<main>-sbom.json`. Without auto-discovery, `policy from-bundles`
// would silently produce a step that requires only material +
// command-run + product — the SBOM content is no longer policy-
// required, so a build with no SBOM still passes verification.
//
// After the fix, the sidecar is discovered, its predicate type is
// recorded as an ExternalAttestation, and the parent Step references
// it via ExternalFrom.
func TestPolicyFromBundles_SidecarsAutoDiscovered(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)

	// Main collection bundle (the kind `cilock run` writes).
	mainPath := synthBundle(t, dir, "build", keyid,
		[]string{
			"https://aflock.ai/attestations/material/v0.3",
			"https://aflock.ai/attestations/command-run/v0.1",
			"https://aflock.ai/attestations/product/v0.3",
		}, true)

	// Sidecar #1: SBOM export — naming convention is
	// `<mainPath>-<exportname>.json`.
	sbomSidecarPath := mainPath + "-sbom.json"
	writeBarePredicateSidecar(t, sbomSidecarPath, keyid, "https://spdx.dev/Document")

	// Sidecar #2: SLSA provenance export.
	slsaSidecarPath := mainPath + "-slsa.json"
	writeBarePredicateSidecar(t, slsaSidecarPath, keyid, "https://slsa.dev/provenance/v1")

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{mainPath}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))

	// The main bundle's Step is present.
	require.Contains(t, pol.Steps, "build")
	step := pol.Steps["build"]

	// Both sidecars surfaced as ExternalAttestations named after the export.
	require.Contains(t, pol.ExternalAttestations, "build-sbom")
	require.Contains(t, pol.ExternalAttestations, "build-slsa")
	assert.Equal(t, "https://spdx.dev/Document", pol.ExternalAttestations["build-sbom"].PredicateType)
	assert.Equal(t, "https://slsa.dev/provenance/v1", pol.ExternalAttestations["build-slsa"].PredicateType)

	// And the Step links to both via ExternalFrom so step-level Rego can read them.
	assert.ElementsMatch(t, []string{"build-sbom", "build-slsa"}, step.ExternalFrom)
}

// TestPolicyFromBundles_SidecarIgnoresNonDSSE confirms we don't get
// confused by cilock's other sidecar kinds (tree.json, detection.json)
// which share the directory but aren't DSSE envelopes.
func TestPolicyFromBundles_SidecarIgnoresNonDSSE(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)

	mainPath := synthBundle(t, dir, "build", keyid,
		[]string{"https://aflock.ai/attestations/material/v0.3"}, true)

	// Plant non-DSSE sidecars that DO match the prefix glob.
	require.NoError(t, os.WriteFile(mainPath+"-bogus.json",
		[]byte(`{"leaves":[],"merkleRoot":"deadbeef"}`), 0o600))
	require.NoError(t, os.WriteFile(mainPath+"-empty.json",
		[]byte(`{}`), 0o600))

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{mainPath}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))
	// No external attestations should have been emitted from the
	// non-DSSE neighbors.
	assert.Empty(t, pol.ExternalAttestations,
		"non-DSSE sidecars (tree/detection/etc) must be silently skipped")
}

func TestPolicyFromBundles_NoBundlesFails(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := writePolicyFixtureKey(t, dir)
	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, nil, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.Error(t, err)
}

func TestPolicyFromBundles_BadEnvelopeFails(t *testing.T) {
	dir := t.TempDir()
	pubPath, _ := writePolicyFixtureKey(t, dir)
	bad := filepath.Join(dir, "bad.bundle.json")
	require.NoError(t, os.WriteFile(bad, []byte("not json"), 0o600))

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{bad}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "summarize")
}

// synthCertSignedBundle synthesises a DSSE envelope whose signature
// carries an x509 leaf certificate (PEM bytes, JSON-encoded as
// base64) — the shape cilock writes whenever the signer is a
// TrustBundler (Fulcio, manual cert chain). The signature value is
// dummy; from-bundles never re-verifies it.
//
// Returns (bundle path, leaf cert keyid, leaf cert CN).
func synthCertSignedBundle(t *testing.T, dir, name string, innerTypes []string, isCollection bool) (path, keyID, commonName string) {
	t.Helper()

	// Self-signed leaf certificate. The "CA" semantics don't matter
	// for the policy generator — it just embeds the bytes.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	commonName = "ci-signer.test.example"
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"TestifySec, Inc."}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &leafKey.PublicKey, leafKey)
	require.NoError(t, err)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	// Derive the keyid the same way cilock does (matches
	// cryptoutil.GeneratePublicKeyID on the leaf's pubkey).
	keyID, err = cryptoutil.GeneratePublicKeyID(&leafKey.PublicKey, crypto.SHA256)
	require.NoError(t, err)

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
		require.Len(t, innerTypes, 1)
		stmt = map[string]any{
			"_type":         "https://in-toto.io/Statement/v0.1",
			"subject":       []map[string]any{{"name": "x", "digest": map[string]string{"sha256": "00"}}},
			"predicateType": innerTypes[0],
			"predicate":     map[string]any{},
		}
	}
	stmtBytes, err := json.Marshal(stmt)
	require.NoError(t, err)

	// Note: `certificate` field is []byte in the canonical DSSE
	// struct, which means Go's json package emits it as base64.
	// Mirror that here by base64-encoding the PEM bytes.
	env := map[string]any{
		"payloadType": "application/vnd.in-toto+json",
		"payload":     base64.StdEncoding.EncodeToString(stmtBytes),
		"signatures": []map[string]any{
			{
				"keyid":       keyID,
				"sig":         "dummy",
				"certificate": base64.StdEncoding.EncodeToString(leafPEM),
			},
		},
	}
	envBytes, err := json.Marshal(env)
	require.NoError(t, err)

	path = filepath.Join(dir, name+".bundle.json")
	require.NoError(t, os.WriteFile(path, envBytes, 0o600))
	return path, keyID, commonName
}

// TestPolicyFromBundles_CertSignedBundle covers the red-team finding
// against PR #186: a cert-signed bundle (x509 leaf cert embedded in
// the DSSE signature) was being emitted as Functionary{Type:
// "publickey"} — a shape `cilock verify` can never satisfy without
// hand-edits because no PEM material lives in PublicKeys[]. The fix
// routes cert-signed signatures through Roots[] +
// Functionary{Type: "root", CertConstraint: {...}} instead.
func TestPolicyFromBundles_CertSignedBundle(t *testing.T) {
	dir := t.TempDir()

	bundlePath, leafKeyID, leafCN := synthCertSignedBundle(t, dir, "build",
		[]string{
			"https://aflock.ai/attestations/material/v0.3",
			"https://aflock.ai/attestations/command-run/v0.1",
		}, true)

	// No -k pubkeys: this is cert-based, so the pubkey path
	// shouldn't be touched. The policy must still build.
	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{bundlePath}, nil, "-", 365*24*time.Hour, "")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))

	// Roots[] must contain the leaf cert, keyed by leaf keyid.
	require.NotEmpty(t, pol.Roots, "cert-signed bundles must populate policy.Roots[]")
	require.Contains(t, pol.Roots, leafKeyID,
		"Roots[] should be keyed by the leaf cert keyid")
	assert.NotEmpty(t, pol.Roots[leafKeyID].Certificate,
		"Root.Certificate must hold the embedded leaf PEM bytes")

	// PublicKeys[] must NOT contain a raw-keyid entry for this cert —
	// that was the bug. The cert-signed path is a separate trust anchor.
	assert.NotContains(t, pol.PublicKeys, leafKeyID,
		"cert-signed bundles must NOT leak into PublicKeys[] (bug from PR #186 red-team)")

	// Step Functionary must be the root shape, not the publickey shape.
	require.Contains(t, pol.Steps, "build")
	step := pol.Steps["build"]
	require.Len(t, step.Functionaries, 1)
	f := step.Functionaries[0]
	assert.Equal(t, "root", f.Type,
		"cert-signed bundle must produce Functionary{Type:\"root\"}, not \"publickey\"")
	assert.Empty(t, f.PublicKeyID,
		"root functionaries should leave PublicKeyID empty")

	// CertConstraint must at minimum pin Roots; CommonName is a
	// starter-template best-effort.
	assert.ElementsMatch(t, []string{leafKeyID}, f.CertConstraint.Roots,
		"CertConstraint.Roots must reference the embedded leaf root")
	assert.Equal(t, leafCN, f.CertConstraint.CommonName,
		"CertConstraint.CommonName should mirror the leaf cert CN as a starter template")
}

// TestPolicyFromBundles_CertSignedBareBundle confirms the cert path
// also lands correctly for bare-predicate envelopes (e.g. a Fulcio-
// signed SLSA provenance export). Bare predicates route to
// ExternalAttestations[], and the functionary there must use the
// root shape — not the pubkey shape — when the sig was cert-based.
func TestPolicyFromBundles_CertSignedBareBundle(t *testing.T) {
	dir := t.TempDir()

	bundlePath, leafKeyID, _ := synthCertSignedBundle(t, dir, "slsa",
		[]string{"https://slsa.dev/provenance/v1"}, false)

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{bundlePath}, nil, "-", 365*24*time.Hour, "")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))

	// Bare predicate → ExternalAttestations, not Steps.
	assert.NotContains(t, pol.Steps, "slsa")
	require.Contains(t, pol.ExternalAttestations, "slsa")
	ext := pol.ExternalAttestations["slsa"]
	require.Len(t, ext.Functionaries, 1)
	assert.Equal(t, "root", ext.Functionaries[0].Type)
	assert.ElementsMatch(t, []string{leafKeyID}, ext.Functionaries[0].CertConstraint.Roots)
}

// TestFromBundles_UsesBundleRecordedStepName covers issue #224.
// The bundle's predicate.name (what `cilock run -s <name>` recorded)
// is authoritative. If a user renames the file to something else
// (e.g. for archival), the generated policy must still reference the
// original step name so `cilock verify` finds the collection.
func TestFromBundles_UsesBundleRecordedStepName(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)

	// File is named one thing, the bundle records a different step name.
	bundlePath := synthBundleWithFilename(t, dir,
		"something-else.att.json", // filename on disk
		"real-step-name",          // predicate.name (what `cilock run -s` set)
		keyid,
		[]string{"https://aflock.ai/attestations/git/v0.1"},
	)

	var out, errOut bytes.Buffer
	err := runPolicyFromBundles(&out, &errOut, []string{bundlePath}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))

	// The bundle-recorded name wins.
	require.Contains(t, pol.Steps, "real-step-name",
		"policy step must use predicate.name from the bundle, not filename")
	assert.NotContains(t, pol.Steps, "something-else.att",
		"policy must not be derived from filename when payload carries a recorded name")
	assert.NotContains(t, pol.Steps, "something-else",
		"policy must not be derived from filename when payload carries a recorded name")

	// And the user gets a notice on stderr explaining the divergence.
	assert.Contains(t, errOut.String(), "real-step-name",
		"notice should mention the bundle-recorded name")
	assert.Contains(t, errOut.String(), "something-else",
		"notice should mention the filename-derived name that was overridden")
}

// TestFromBundles_FallsBackToFilename covers the defensive path: when
// a bundle has no recorded predicate.name (e.g. an older bundle, or a
// malformed payload), the generator still produces a usable step name
// by stripping known extensions from the filename. Issue #224.
func TestFromBundles_FallsBackToFilename(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)

	// Empty recordedName → no `predicate.name` in payload at all.
	bundlePath := synthBundleWithFilename(t, dir,
		"mything.att.json",
		"", // no recorded name
		keyid,
		[]string{"https://aflock.ai/attestations/git/v0.1"},
	)

	var out, errOut bytes.Buffer
	err := runPolicyFromBundles(&out, &errOut, []string{bundlePath}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))

	// Filename `mything.att.json` → step `mything` (extension stripped).
	require.Contains(t, pol.Steps, "mything",
		"missing predicate.name should fall back to filename with extension stripped")
	// And no notice when nothing to compare against — the user didn't
	// "lose" any expected name in this path.
	assert.Empty(t, errOut.String(),
		"no notice should fire when the bundle carries no recorded name to diverge from")
}

// TestFromBundles_StripsAttJsonExtension covers the longest-match-first
// extension stripping requirement from issue #224: a file named
// `foo.att.json` must produce step `foo`, not `foo.att`. The same
// applies to other compound suffixes (.bundle.json, .envelope.json).
// Without the ordered strip, a simple `TrimSuffix(.json)` would leave
// the `.att` part in the step name and break verify.
func TestFromBundles_StripsAttJsonExtension(t *testing.T) {
	dir := t.TempDir()
	pubPath, keyid := writePolicyFixtureKey(t, dir)

	bundlePath := synthBundleWithFilename(t, dir,
		"foo.att.json",
		"", // empty recorded name → exercise filename fallback
		keyid,
		[]string{"https://aflock.ai/attestations/git/v0.1"},
	)

	var out bytes.Buffer
	err := runPolicyFromBundles(&out, io.Discard, []string{bundlePath}, []string{pubPath}, "-", 365*24*time.Hour, "")
	require.NoError(t, err)

	var pol policy.Policy
	require.NoError(t, json.Unmarshal(out.Bytes(), &pol))

	assert.Contains(t, pol.Steps, "foo",
		"foo.att.json should yield step foo, with the full .att.json suffix stripped")
	assert.NotContains(t, pol.Steps, "foo.att",
		"step name must not retain the .att fragment (would be the naive TrimSuffix(.json) bug)")
}
