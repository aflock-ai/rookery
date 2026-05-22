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

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// digestHex returns the hex-encoded sha256 of body.
func digestHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// buildFixtureSidecar creates a small sidecar on disk for prove tests.
// It returns (sidecarPath, digests-by-path). The leaf order is implicit
// in the sidecar (lex-sorted by path) — tests read it back from disk
// when they need to walk every leaf.
func buildFixtureSidecar(t *testing.T, dir string) (string, map[string]string) {
	t.Helper()
	digests := map[string]string{
		"dist/binary":   digestHex([]byte("binary-content")),
		"dist/notes.md": digestHex([]byte("# notes\n")),
		"dist/checksum": digestHex([]byte("checksum-data")),
	}
	side, err := inclusionproof.BuildSidecar("product", digests)
	require.NoError(t, err)

	path := filepath.Join(dir, "tree.json")
	require.NoError(t, inclusionproof.WriteSidecarFile(path, side))
	return path, digests
}

// readProveEnvelope reads a signed envelope written by `cilock prove`,
// decodes its in-toto statement, and returns the inclusion-proof
// predicate plus the statement subjects.
func readProveEnvelope(t *testing.T, path string) (*inclusionproof.Attestor, []intoto.Subject) {
	t.Helper()
	raw, err := os.ReadFile(path) //nolint:gosec // test fixture path
	require.NoError(t, err)

	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))

	var stmt intoto.Statement
	require.NoError(t, json.Unmarshal(env.Payload, &stmt))
	assert.Equal(t, inclusionproof.Type, stmt.PredicateType)

	var att inclusionproof.Attestor
	require.NoError(t, json.Unmarshal(stmt.Predicate, &att))
	return &att, stmt.Subject
}

// TestProveCmd_RoundTrip is the spec's mandatory round-trip test —
// covered at the `cilock prove` integration level so we exercise the
// CLI surface (flag wiring, sidecar load, signing) rather than just
// the library round-trip the attestor package already covers.
func TestProveCmd_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	sidecarPath, digests := buildFixtureSidecar(t, dir)
	keyPath := generateTestKey(t, dir)
	outBase := filepath.Join(dir, "proof.json")

	err := executeCmd(
		"prove",
		"--tree-sidecar", sidecarPath,
		"--file", "dist/binary",
		"--file", "dist/notes.md",
		"--signer-file-key-path", keyPath,
		"--outfile", outBase,
	)
	require.NoError(t, err)

	// Multiple --file values produce <out>-<sanitised>.json files.
	for _, leaf := range []string{"dist/binary", "dist/notes.md"} {
		safe := strings.ReplaceAll(leaf, "/", "-")
		expected := strings.TrimSuffix(outBase, ".json") + "-" + safe + ".json"
		_, err := os.Stat(expected)
		require.NoError(t, err, "expected envelope at %s", expected)

		att, _ := readProveEnvelope(t, expected)
		assert.Equal(t, leaf, att.LeafPath)
		assert.Equal(t, digests[leaf], att.FileDigest)
		assert.Equal(t, inclusionproof.HashAlgorithm, att.HashAlgorithm)
		assert.Equal(t, inclusionproof.Construction, att.Construction)

		// Reconstruct from the sidecar and verify the proof.
		side, err := inclusionproof.ReadSidecarFile(sidecarPath)
		require.NoError(t, err)
		root, err := hex.DecodeString(side.MerkleRoot)
		require.NoError(t, err)
		require.NoError(t, att.Verify(side.TreeSize, root))
	}
}

// TestProveCmd_SingleFile covers the single-file convenience path:
// --outfile points to the exact envelope output, no path mangling.
func TestProveCmd_SingleFile(t *testing.T) {
	dir := t.TempDir()
	sidecarPath, digests := buildFixtureSidecar(t, dir)
	keyPath := generateTestKey(t, dir)
	out := filepath.Join(dir, "single.json")

	err := executeCmd(
		"prove",
		"--tree-sidecar", sidecarPath,
		"--file", "dist/binary",
		"--signer-file-key-path", keyPath,
		"--outfile", out,
	)
	require.NoError(t, err)

	att, _ := readProveEnvelope(t, out)
	assert.Equal(t, "dist/binary", att.LeafPath)
	assert.Equal(t, digests["dist/binary"], att.FileDigest)
}

// TestProveCmd_SubjectsIncludeFileDigest verifies the integration-
// level expectation that the signed statement carries one subject
// keyed by "file:<path>" with digest sha256:<FileDigest>.
func TestProveCmd_SubjectsIncludeFileDigest(t *testing.T) {
	dir := t.TempDir()
	sidecarPath, digests := buildFixtureSidecar(t, dir)
	keyPath := generateTestKey(t, dir)
	out := filepath.Join(dir, "subject-check.json")

	err := executeCmd(
		"prove",
		"--tree-sidecar", sidecarPath,
		"--file", "dist/binary",
		"--signer-file-key-path", keyPath,
		"--outfile", out,
	)
	require.NoError(t, err)

	_, subjects := readProveEnvelope(t, out)
	require.Len(t, subjects, 1)
	assert.Equal(t, "file:dist/binary", subjects[0].Name)
	assert.Equal(t, digests["dist/binary"], subjects[0].Digest["sha256"])
}

// TestProveCmd_RefusesCorruptedSidecar is mandatory test #7 from the
// design spec: a sidecar whose claimed root doesn't match its leaves
// must produce a "sidecar root mismatch" error rather than a signed
// (but useless) proof.
func TestProveCmd_RefusesCorruptedSidecar(t *testing.T) {
	dir := t.TempDir()
	sidecarPath, _ := buildFixtureSidecar(t, dir)
	keyPath := generateTestKey(t, dir)
	out := filepath.Join(dir, "should-not-exist.json")

	// Hand-corrupt one leaf's digest in the sidecar JSON.
	raw, err := os.ReadFile(sidecarPath) //nolint:gosec // test
	require.NoError(t, err)
	var side inclusionproof.Sidecar
	require.NoError(t, json.Unmarshal(raw, &side))
	require.GreaterOrEqual(t, len(side.Leaves), 1)
	// Replace with a fresh, internally-valid hex digest (still 32
	// bytes) so the failure mode is "Merkle root mismatch", not
	// "malformed digest".
	side.Leaves[0].FileDigest = digestHex([]byte("totally different bytes"))
	out2, err := json.Marshal(side)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(sidecarPath, out2, 0o600))

	err = executeCmd(
		"prove",
		"--tree-sidecar", sidecarPath,
		"--file", "dist/binary",
		"--signer-file-key-path", keyPath,
		"--outfile", out,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sidecar root mismatch")

	// And the envelope file must not have been written.
	_, statErr := os.Stat(out)
	assert.True(t, os.IsNotExist(statErr), "no envelope must be written on sidecar corruption")
}

// TestProveCmd_UnknownLeafPath checks the friendly-error path when
// --file isn't in the sidecar.
func TestProveCmd_UnknownLeafPath(t *testing.T) {
	dir := t.TempDir()
	sidecarPath, _ := buildFixtureSidecar(t, dir)
	keyPath := generateTestKey(t, dir)
	out := filepath.Join(dir, "no.json")

	err := executeCmd(
		"prove",
		"--tree-sidecar", sidecarPath,
		"--file", "dist/does-not-exist",
		"--signer-file-key-path", keyPath,
		"--outfile", out,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a leaf of the supplied sidecar")
}

// TestProveCmd_HelpAdvertisesFlags is mandatory test #8 — make sure
// `cilock prove --help` mentions every flag the design spec requires.
func TestProveCmd_HelpAdvertisesFlags(t *testing.T) {
	cmd := New()
	cmd.SetArgs([]string{"prove", "--help"})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	require.NoError(t, cmd.Execute())

	out := stdout.String()
	for _, flag := range []string{
		"--tree-sidecar",
		"--file",
		"--outfile",
		"--signer-file-key-path",
	} {
		assert.Contains(t, out, flag, "prove --help must advertise %s", flag)
	}
}

// TestProveCmd_MissingSidecarFlag covers the friendly-error path when
// the required flag is omitted.
func TestProveCmd_MissingSidecarFlag(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	out := filepath.Join(dir, "no.json")

	err := executeCmd(
		"prove",
		"--file", "dist/binary",
		"--signer-file-key-path", keyPath,
		"--outfile", out,
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--tree-sidecar")
}

// TestProveCmd_HookedFromRun is mandatory wiring proof: after `cilock
// run --outfile X.json` finishes, sidecars must land at
// `X.product.tree.json` and `X.material.tree.json`. We then feed the
// product sidecar to `cilock prove` and verify the proof.
func TestProveCmd_HookedFromRun(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	out := filepath.Join(dir, "att.json")

	// Pre-populate a material file so the material attestor has
	// something to commit to. The product attestor sees only files
	// that appear during the command run, so for a `true` command we
	// expect no product sidecar — which matches the production
	// contract: empty product sets DO NOT produce a sidecar.
	binaryPath := filepath.Join(dir, "binary.txt")
	require.NoError(t, os.WriteFile(binaryPath, []byte("binary content here"), 0o600))

	err := executeCmd(
		"run",
		"--step", "build",
		"--signer-file-key-path", keyPath,
		"--outfile", out,
		"--workingdir", dir,
		"--platform-url", "",
		// Override DefaultAttestors so we don't try to run the git
		// attestor in a non-git temp dir.
		"--attestations", "environment",
		"--", "true",
	)
	require.NoError(t, err)

	// Material sidecar must exist adjacent to the outfile (the
	// material attestor saw binary.txt and the key.pem we wrote
	// earlier). The product sidecar is absent because no new files
	// were created during the run — a `true` command produces no
	// products. That's the documented contract: empty sets don't
	// produce sidecars.
	matSidecar := strings.TrimSuffix(out, ".json") + ".material.tree.json"
	prodSidecar := strings.TrimSuffix(out, ".json") + ".product.tree.json"
	_, err = os.Stat(matSidecar)
	require.NoError(t, err, "material sidecar must be written by cilock run when the working dir contains pre-existing files")
	if _, statErr := os.Stat(prodSidecar); statErr == nil {
		t.Fatalf("product sidecar should NOT exist when the run produces no new files, but found %s", prodSidecar)
	}

	// And the material sidecar's reconstructed root must match its
	// claimed root (the integrity check `cilock prove` performs).
	side, err := inclusionproof.ReadSidecarFile(matSidecar)
	require.NoError(t, err)
	_, _, err = side.Reconstruct()
	require.NoError(t, err)

	// Pick any leaf from the material sidecar and generate a proof.
	require.GreaterOrEqual(t, len(side.Leaves), 1)
	leaf := side.Leaves[0].Path
	proofOut := filepath.Join(dir, "proof.json")

	err = executeCmd(
		"prove",
		"--tree-sidecar", matSidecar,
		"--file", leaf,
		"--signer-file-key-path", keyPath,
		"--outfile", proofOut,
	)
	require.NoError(t, err)

	att, _ := readProveEnvelope(t, proofOut)
	root, err := hex.DecodeString(side.MerkleRoot)
	require.NoError(t, err)
	require.NoError(t, att.Verify(side.TreeSize, root))
}
