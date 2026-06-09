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

package inclusionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// digestHex returns the hex-encoded sha256 of body.
func digestHex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// fixtureLeaves returns a deterministic small leaf set used across tests.
func fixtureLeaves() map[string]string {
	return map[string]string{
		"dist/binary":     digestHex([]byte("the binary bytes")),
		"dist/checksum":   digestHex([]byte("CHECKSUM=abc")),
		"dist/notes.md":   digestHex([]byte("# release notes\n")),
		"dist/sub/lib.so": digestHex([]byte("lib bytes")),
	}
}

// buildProof builds a sidecar from the given leaves, then produces a
// valid inclusion-proof attestor for the requested path.
func buildProof(t *testing.T, leaves map[string]string, path string) (*Attestor, []byte, uint64) {
	t.Helper()
	side, err := BuildSidecar("product", leaves)
	require.NoError(t, err)
	tree, idx, err := side.Reconstruct()
	require.NoError(t, err)

	// v0.3: the reconstructed index is keyed by content DIGEST, not path
	// (the leaf hash binds content only). Look up by the file's digest.
	leafIdx, ok := idx[leaves[path]]
	require.True(t, ok, "digest for path %q must exist in sidecar index", path)

	auditPath, err := tree.InclusionProof(leafIdx)
	require.NoError(t, err)

	hexAudit := make([]string, len(auditPath))
	for i, b := range auditPath {
		hexAudit[i] = hex.EncodeToString(b)
	}

	att := New()
	att.TreeRoot = side.MerkleRoot
	att.LeafIndex = leafIdx
	att.LeafPath = path
	att.FileDigest = leaves[path]
	att.AuditPath = hexAudit

	rootBytes, err := hex.DecodeString(side.MerkleRoot)
	require.NoError(t, err)
	return att, rootBytes, side.TreeSize
}

// TestRoundTrip_TwoProofs covers the core mandatory test: build a tree,
// emit proofs for two distinct files, verify both succeed.
func TestRoundTrip_TwoProofs(t *testing.T) {
	leaves := fixtureLeaves()

	for _, path := range []string{"dist/binary", "dist/sub/lib.so"} {
		att, root, size := buildProof(t, leaves, path)
		err := att.Verify(size, root)
		assert.NoError(t, err, "proof for %q must verify", path)
	}
}

// TestVerify_ForgedFileDigest covers CVE-2026-22703 class defence: a
// mutated FileDigest must fail verification with the merkle wrapper's
// root-mismatch error.
func TestVerify_ForgedFileDigest(t *testing.T) {
	leaves := fixtureLeaves()
	att, root, size := buildProof(t, leaves, "dist/binary")

	// Flip the last hex nibble of FileDigest.
	mutated := att.FileDigest
	if mutated[len(mutated)-1] == '0' {
		att.FileDigest = mutated[:len(mutated)-1] + "1"
	} else {
		att.FileDigest = mutated[:len(mutated)-1] + "0"
	}

	err := att.Verify(size, root)
	require.Error(t, err, "forged FileDigest must fail to verify")
	// The predicate-side claimed-root check fires first because TreeRoot
	// is still the original root but the leaf no longer hashes to a
	// matching path. The error path through to the merkle layer is
	// reachable if we also forge TreeRoot; the test below exercises the
	// raw merkle-layer error, here we just confirm we refuse.
	assert.Contains(t, err.Error(), "does not match")
}

// TestVerify_ForgedFileDigest_RawMerklePath drops the predicate's
// claimed treeRoot so the failure path lands on the merkle wrapper's
// constant-time root comparison — exactly the CVE-2026-22703 defence
// behaviour we care about.
func TestVerify_ForgedFileDigest_RawMerklePath(t *testing.T) {
	leaves := fixtureLeaves()
	att, root, size := buildProof(t, leaves, "dist/binary")
	att.TreeRoot = "" // bypass the friendlier predicate-side guard

	// Flip every nibble in FileDigest.
	att.FileDigest = digestHex([]byte("totally different content"))

	err := att.Verify(size, root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "calculated root does not match expected root")
}

// TestVerify_WrongTreeRoot covers: a valid proof against a different
// root must fail.
func TestVerify_WrongTreeRoot(t *testing.T) {
	leaves := fixtureLeaves()
	att, _, size := buildProof(t, leaves, "dist/binary")

	other := sha256.Sum256([]byte("another tree entirely"))
	att.TreeRoot = "" // skip the friendly predicate-side check
	err := att.Verify(size, other[:])
	require.Error(t, err)
	assert.Contains(t, err.Error(), "calculated root does not match expected root")
}

// TestVerify_TamperedAuditPath covers: flipping one bit in any
// audit-path element must fail.
func TestVerify_TamperedAuditPath(t *testing.T) {
	leaves := fixtureLeaves()
	att, root, size := buildProof(t, leaves, "dist/binary")
	require.NotEmpty(t, att.AuditPath, "fixture must produce a non-trivial proof")

	// Flip the last nibble of the first audit-path element.
	target := att.AuditPath[0]
	if target[len(target)-1] == '0' {
		att.AuditPath[0] = target[:len(target)-1] + "1"
	} else {
		att.AuditPath[0] = target[:len(target)-1] + "0"
	}

	err := att.Verify(size, root)
	require.Error(t, err)
	// The treeRoot predicate-side guard passes (we didn't touch TreeRoot)
	// so this lands on the merkle wrapper's root comparison.
	assert.Contains(t, err.Error(), "calculated root does not match expected root")
}

// TestSubjects_SingleFileDigestEntry covers the mandatory subject-shape
// contract: name = "file:<LeafPath>", digest = {sha256: FileDigest}.
func TestSubjects_SingleFileDigestEntry(t *testing.T) {
	leaves := fixtureLeaves()
	att, _, _ := buildProof(t, leaves, "dist/binary")

	subjects := att.Subjects()
	require.Len(t, subjects, 1)
	ds, ok := subjects["file:dist/binary"]
	require.True(t, ok)
	require.Len(t, ds, 1, "single digest algorithm — sha256")
	values := make([]string, 0, len(ds))
	for _, v := range ds {
		values = append(values, v)
	}
	assert.Equal(t, []string{att.FileDigest}, values)
}

// TestBackRefs_SingleFileDigestEntry mirrors TestSubjects.
func TestBackRefs_SingleFileDigestEntry(t *testing.T) {
	leaves := fixtureLeaves()
	att, _, _ := buildProof(t, leaves, "dist/binary")

	br := att.BackRefs()
	require.Len(t, br, 1)
	ds, ok := br["file:dist/binary"]
	require.True(t, ok)
	require.Len(t, ds, 1)
}

// TestSubjects_UninitialisedReturnsEmpty defends against a half-built
// Attestor accidentally leaking a useless subject entry.
func TestSubjects_UninitialisedReturnsEmpty(t *testing.T) {
	att := New()
	assert.Empty(t, att.Subjects())
	assert.Empty(t, att.BackRefs())
}

// TestSidecar_ReconstructionRootMismatch covers test #7: hand-corrupt a
// sidecar leaf hash and Reconstruct() must refuse with ErrSidecarRootMismatch.
func TestSidecar_ReconstructionRootMismatch(t *testing.T) {
	leaves := fixtureLeaves()
	side, err := BuildSidecar("product", leaves)
	require.NoError(t, err)

	// Corrupt the LAST leaf's digest to all-f's. Leaves are canonically
	// ordered by (fileDigest, path); an all-f digest sorts to the end so the
	// canonical-order check still passes — isolating the failure on the ROOT
	// mismatch path (the claimed MerkleRoot is still the ORIGINAL root).
	require.GreaterOrEqual(t, len(side.Leaves), 1)
	side.Leaves[len(side.Leaves)-1].FileDigest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"

	_, _, err = side.Reconstruct()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSidecarRootMismatch))
}

// TestSidecar_RoundTripFile covers the on-disk path (Write / Read).
func TestSidecar_RoundTripFile(t *testing.T) {
	leaves := fixtureLeaves()
	side, err := BuildSidecar("product", leaves)
	require.NoError(t, err)

	dir := t.TempDir()
	p := dir + "/sidecar.json"
	require.NoError(t, WriteSidecarFile(p, side))
	got, err := ReadSidecarFile(p)
	require.NoError(t, err)
	assert.Equal(t, side, got)
}

// TestSidecar_RefusesUnknownSchemaVersion exercises the schema-pinning
// guard: a downgrade attack changing the schemaVersion in transit must
// be detected.
func TestSidecar_RefusesUnknownSchemaVersion(t *testing.T) {
	leaves := fixtureLeaves()
	side, err := BuildSidecar("product", leaves)
	require.NoError(t, err)
	side.SchemaVersion = "rookery.inclusion-proof.sidecar/v999"

	buf, err := json.Marshal(side)
	require.NoError(t, err)

	_, err = ReadSidecar(bytesReader(buf))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "schemaVersion")
}

// TestSidecar_RefusesUnsortedLeaves exercises the lex-order guard.
func TestSidecar_RefusesUnsortedLeaves(t *testing.T) {
	leaves := fixtureLeaves()
	side, err := BuildSidecar("product", leaves)
	require.NoError(t, err)

	// Swap the first two leaves, breaking lex order.
	require.GreaterOrEqual(t, len(side.Leaves), 2)
	side.Leaves[0], side.Leaves[1] = side.Leaves[1], side.Leaves[0]

	_, _, err = side.Reconstruct()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "canonical")
}

// TestVerify_RefusesHashAlgorithmConfusion: changing the predicate's
// declared hashAlgorithm must produce a clear refusal rather than
// silently re-deriving with sha256.
func TestVerify_RefusesHashAlgorithmConfusion(t *testing.T) {
	leaves := fixtureLeaves()
	att, root, size := buildProof(t, leaves, "dist/binary")
	att.HashAlgorithm = "blake2b-256"

	err := att.Verify(size, root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hashAlgorithm")
}

// TestVerify_RefusesConstructionConfusion mirrors the hash-confusion
// guard for the construction field.
func TestVerify_RefusesConstructionConfusion(t *testing.T) {
	leaves := fixtureLeaves()
	att, root, size := buildProof(t, leaves, "dist/binary")
	att.Construction = "OpenZeppelin"

	err := att.Verify(size, root)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "construction")
}

// TestLeafHash_RejectsMalformedDigest documents the leaf-hash contract.
func TestLeafHash_RejectsMalformedDigest(t *testing.T) {
	_, err := LeafHash("path", "not-hex")
	require.Error(t, err)

	_, err = LeafHash("path", "deadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode to 32 bytes")
}

// TestLeafHashWithDomain_EmptyDomainIsBackCompat (RESCUED from the deleted
// chain_sidecar_test.go) confirms the empty-domain leaf is byte-identical to
// LeafHash. This is the only in-package regression test for the empty-domain
// canonical form; it must survive the chain-sidecar rip. Rewritten to the v0.3
// path-dropped hash: the path arg is non-authoritative.
func TestLeafHashWithDomain_EmptyDomainIsBackCompat(t *testing.T) {
	digest := digestHex([]byte("content"))
	legacy, err := LeafHash("src/main.go", digest)
	require.NoError(t, err)
	domained, err := LeafHashWithDomain("", "src/main.go", digest)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(legacy), hex.EncodeToString(domained),
		"empty-domain leaf must equal LeafHash byte-for-byte")
}

// TestLeafHashWithDomain_NonEmptyDomainShifts (RESCUED from the deleted
// chain_sidecar_test.go AND attestation/chain's TestAdversarial_LeafHashDomainPrefix)
// confirms a non-empty domain produces a DIFFERENT hash than empty for the same
// digest, AND that the domained hash is deterministic. This is the E4
// citation-hijack defense's regression test; it must survive the chain-sidecar
// rip. Path-independent in v0.3 — the leaf binds (domain, content) only.
func TestLeafHashWithDomain_NonEmptyDomainShifts(t *testing.T) {
	digest := digestHex([]byte("content"))
	empty, err := LeafHashWithDomain("", "src/main.go", digest)
	require.NoError(t, err)
	domained, err := LeafHashWithDomain("rookery-product/v0.3", "src/main.go", digest)
	require.NoError(t, err)
	assert.NotEqual(t, hex.EncodeToString(empty), hex.EncodeToString(domained),
		"domain separation: a non-empty domain must shift the leaf hash")

	// Determinism: the same domain at two calls must produce identical bytes.
	domained2, err := LeafHashWithDomain("rookery-product/v0.3", "src/main.go", digest)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(domained), hex.EncodeToString(domained2),
		"LeafHashWithDomain must be deterministic")
}

// TestPredicateConstants makes sure the package exports the same
// algorithm/construction strings as attestation/merkle. Drift here
// would silently break cross-attestor verification.
func TestPredicateConstants(t *testing.T) {
	assert.Equal(t, merkle.Hash, HashAlgorithm)
	assert.Equal(t, merkle.Construction, Construction)
}

// TestAttest_NoOp documents the Attest contract.
func TestAttest_NoOp(t *testing.T) {
	att := New()
	assert.NoError(t, att.Attest(nil))
}

// TestUnmarshalJSON_PredicateRoundTrip verifies the on-the-wire shape
// matches the documented schema.
func TestUnmarshalJSON_PredicateRoundTrip(t *testing.T) {
	leaves := fixtureLeaves()
	att, _, _ := buildProof(t, leaves, "dist/binary")
	buf, err := json.Marshal(att)
	require.NoError(t, err)

	var got Attestor
	require.NoError(t, json.Unmarshal(buf, &got))
	assert.Equal(t, *att, got)

	// Spot-check the wire keys.
	var raw map[string]any
	require.NoError(t, json.Unmarshal(buf, &raw))
	for _, k := range []string{"treeRoot", "leafIndex", "leafPath", "fileDigest", "auditPath", "hashAlgorithm", "construction"} {
		_, ok := raw[k]
		assert.True(t, ok, "predicate must carry key %q", k)
	}
}

// bytesReader is a small helper for ReadSidecar tests so the file
// stays free of extra imports we'd otherwise pull in just to wrap a
// []byte.
func bytesReader(b []byte) *jsonReader { return &jsonReader{buf: b} }

type jsonReader struct {
	buf []byte
	off int
}

func (r *jsonReader) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}
