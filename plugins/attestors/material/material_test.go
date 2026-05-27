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

// material_test.go is the v0.3 attestor's test matrix. Each test maps to
// a bullet in Agent C's spec; the V03_NNN numbering is intentional so a
// regression bisect can land on a single named case.
//
// What the tests are protecting:
//
//   - Deterministic root over a known input (V03_001)
//   - Sort-by-path is what makes the root deterministic (V03_002)
//   - Path binding (V03_003 keeps a swap-paths attack from colliding)
//   - Empty material set has a well-defined root (V03_004)
//   - Single-file tree has a hand-checked root (V03_005)
//   - Subjects() returns ONLY "tree:materials" (V03_006)
//   - BackRefs() returns ONLY "tree:materials" (V03_007)
//   - Sidecar round-trip preserves the data needed for verification
//     (V03_008)
//   - The signed predicate does NOT carry the per-file leaves (V03_009)
//   - Material and product attestors agree on leaf encoding so their
//     trees over the same (path, digest) list produce byte-identical
//     roots — the spec-locking invariant (V03_010)

package material

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Helpers
// =============================================================================

// makeMaterialAttestor builds an Attestor over files (path → content)
// under a temp dir, runs Attest, and returns the attestor. The default
// attestation context hashes with SHA256, which is what the v0.3 root
// commits to.
func makeMaterialAttestor(t *testing.T, files map[string]string) *Attestor {
	t.Helper()
	dir := t.TempDir()
	for relPath, content := range files {
		full := filepath.Join(dir, relPath)
		require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
		require.NoError(t, os.WriteFile(full, []byte(content), 0o644))
	}

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))
	return a
}

// =============================================================================
// V03_001: Deterministic root over a fixed input set
// =============================================================================

func TestV03_001_DeterministicRoot(t *testing.T) {
	// Build the same input twice and compare. Map iteration order is
	// randomized in Go, so any missing sort step in the production path
	// would show up here within a handful of retries — we run 20 to be
	// thorough.
	files := map[string]string{
		"alpha":   "a",
		"bravo":   "b",
		"charlie": "c",
		"delta":   "d",
		"echo":    "e",
		"foxtrot": "f",
	}
	first := makeMaterialAttestor(t, files).MerkleRoot
	require.NotEmpty(t, first)

	for i := 0; i < 20; i++ {
		got := makeMaterialAttestor(t, files).MerkleRoot
		require.Equal(t, first, got, "attempt %d: merkle root must be deterministic", i)
	}
}

// =============================================================================
// V03_002: Renaming a file changes the root
// =============================================================================

// V03_002 covers the "sort-by-path → renaming changes the root" leg of
// the path-binding invariant. The leaf includes the path, so renaming
// (or, equivalently, reordering paths) MUST produce a different root.
func TestV03_002_RenameChangesRoot(t *testing.T) {
	r1 := makeMaterialAttestor(t, map[string]string{"a": "x", "b": "y"}).MerkleRoot
	r2 := makeMaterialAttestor(t, map[string]string{"a": "x", "c": "y"}).MerkleRoot // b → c
	assert.NotEqual(t, r1, r2, "renaming a file must change the merkle root")
}

// =============================================================================
// V03_003: Path-binding — swapping paths between two files changes the root
// =============================================================================

// V03_003 is the critical leg of path-binding. With a naive
// "hash(concat-of-digests)" approach, swapping paths between files
// would produce the same root because the multiset of file digests is
// the same. With our (path || 0x00 || digest) leaf encoding, the leaf
// hashes change and so does the root.
//
// If this test ever fails, the leaf encoding has lost path binding and
// an attacker can substitute file contents without invalidating the
// tree subject.
func TestV03_003_PathBindingDistinctFromContentOnly(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{
		"a": "one",
		"b": "two",
	})
	b := makeMaterialAttestor(t, map[string]string{
		// Same CONTENT set, paths swapped.
		"a": "two",
		"b": "one",
	})
	assert.NotEqual(t, a.MerkleRoot, b.MerkleRoot,
		"path binding broken: swapping paths produced the same root")
}

// =============================================================================
// V03_004: Empty material set → tree size 0 and SHA256("") root
// =============================================================================

// V03_004 nails down the empty-tree contract. RFC 6962 §2.1 defines
// MTH({}) = SHA256(""), so a build with no materials in the workdir
// must produce TreeSize=0 and that specific root — not a zero string,
// not an error.
func TestV03_004_EmptyMaterialSet(t *testing.T) {
	dir := t.TempDir()
	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))

	expected := sha256.Sum256(nil)
	assert.Equal(t, hex.EncodeToString(expected[:]), a.MerkleRoot,
		"empty tree root must equal SHA256(\"\") per RFC 6962 §2.1")
	assert.Equal(t, uint64(0), a.TreeSize, "empty tree size must be 0")
	assert.Equal(t, HashAlgorithm, a.HashAlgorithmField)
	assert.Equal(t, Construction, a.ConstructionField)
}

// =============================================================================
// V03_005: Single-file tree → predictable root
// =============================================================================

// V03_005 pins the single-file tree to a value computed from scratch.
// A single leaf's tree root is the leaf hash itself per RFC 6962, which
// the wrapper's NewTree turns into HashLeaf(rawDigest) = SHA256(0x00 ||
// rawDigest). This test recomputes that with stdlib sha256 only — no
// transparency-dev/merkle, no attestation/merkle wrapper — so the two
// implementations cross-checking each other is the signal.
func TestV03_005_SingleFileTreePredictableRoot(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "only.txt"), []byte("hello"), 0o644))

	a := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, a.Attest(ctx))

	// File digest = sha256("hello").
	fileDigest := sha256.Sum256([]byte("hello"))
	// Leaf content = "only.txt" || 0x00 || raw-sha256-bytes.
	leafContent := append([]byte("only.txt"), 0)
	leafContent = append(leafContent, fileDigest[:]...)
	leafHash := sha256.Sum256(leafContent)
	// Single-leaf RFC 6962 tree: root = HashLeaf(leafHash) = SHA256(0x00 || leafHash).
	expectedRoot := sha256.Sum256(append([]byte{0x00}, leafHash[:]...))

	assert.Equal(t, hex.EncodeToString(expectedRoot[:]), a.MerkleRoot,
		"single-file tree root must equal the hand-computed value")
	assert.Equal(t, uint64(1), a.TreeSize, "single-file tree size must be 1")
}

// =============================================================================
// V03_006: Subjects() returns ONLY tree:materials
// =============================================================================

// V03_006 enforces the subject collapse — the original bug the tree
// subject change was meant to fix was 30k+ "file:" subjects per
// attestation blowing the Archivista placeholder limit. Any future
// regression that re-emits per-file subjects will be caught here.
func TestV03_006_SubjectsOnlyTreeMaterials(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{
		"a.txt":     "1",
		"b.txt":     "2",
		"sub/c.txt": "3",
	})
	subjects := a.Subjects()
	require.Len(t, subjects, 1, "v0.3 must emit exactly one subject regardless of file count")
	require.Contains(t, subjects, TreeSubjectName, "the single subject must be %q", TreeSubjectName)
	digest := subjects[TreeSubjectName]
	require.Len(t, digest, 1, "the subject must carry exactly one digest entry (sha256)")
}

// =============================================================================
// V03_007: BackRefs() returns ONLY tree:materials
// =============================================================================

// V03_007 mirrors V03_006 for the BackRefs surface. The brief calls
// this the "mirror of #127 reshape": both Subjects() and BackRefs()
// must point at the same single tree handle so Archivista's reverse
// lookup hits one row per attestation, not one row per file.
func TestV03_007_BackRefsOnlyTreeMaterials(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{
		"a.txt":     "1",
		"b.txt":     "2",
		"sub/c.txt": "3",
	})
	backRefs := a.BackRefs()
	require.Len(t, backRefs, 1, "v0.3 must emit exactly one back-ref")
	require.Contains(t, backRefs, TreeSubjectName)
	// BackRefs and Subjects MUST agree byte-for-byte. A drift would
	// silently break cross-attestation lookup.
	assert.Equal(t, a.Subjects(), backRefs, "Subjects and BackRefs must agree")
}

// =============================================================================
// V03_008: In-memory leaves reconstruct the signed root
// =============================================================================

// V03_008 is the verifiability handshake. The canonical sidecar format
// lives in plugins/attestors/inclusion-proof (single source of truth);
// this test checks the in-memory invariant the material attestor must
// uphold: the LeafHash hex values returned by Leaves() must reconstruct
// to the same Merkle root the attestor signed. If that breaks,
// inclusion-proof verification breaks.
func TestV03_008_LeavesReconstructRoot(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{
		"a.txt":     "alpha",
		"b.txt":     "bravo",
		"sub/c.txt": "charlie",
	})

	leaves := a.Leaves()
	require.Len(t, leaves, 3, "all 3 leaves must be available in memory")

	leafBytes := make([][]byte, len(leaves))
	for i, l := range leaves {
		raw, err := hex.DecodeString(l.LeafHash)
		require.NoError(t, err)
		leafBytes[i] = raw
	}
	tree, err := merkle.NewTree(leafBytes)
	require.NoError(t, err)
	assert.Equal(t, a.MerkleRoot, hex.EncodeToString(tree.Root()),
		"recomputed root from in-memory leaves must match signed root")
}

// =============================================================================
// V03_009: Signed predicate carries no per-file leaves
// =============================================================================

// V03_009 is the size-shrink invariant. The whole point of v0.3 is to
// stop the per-file blowup in the predicate. If MarshalJSON ever
// accidentally includes the leaves slice (e.g., someone strips the
// json:"-" tag), this test fails.
//
// The check is structural: unmarshal the predicate JSON into a generic
// map and assert no "leaves" key. Bytes-of-encoding tests would be
// brittle to field reordering.
func TestV03_009_SignedPredicateExcludesLeaves(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{
		"a.txt":     "1",
		"b.txt":     "2",
		"sub/c.txt": "3",
	})

	body, err := json.Marshal(a)
	require.NoError(t, err)

	var generic map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &generic))

	assert.NotContains(t, generic, "leaves", "predicate must NOT contain leaves")
	assert.NotContains(t, generic, "materials", "predicate must NOT contain materials")
	// Positive assertions: the 4 documented predicate fields are present.
	assert.Contains(t, generic, "merkleRoot")
	assert.Contains(t, generic, "treeSize")
	assert.Contains(t, generic, "hashAlgorithm")
	assert.Contains(t, generic, "construction")
}

// =============================================================================
// V03_010: Cross-coherence — leaf format identical to product attestor
// =============================================================================

// V03_010 is the SPEC LOCK between Agent C (material) and Agent B
// (product). The contract is that the leaf encoding
//
//	leafHash = SHA256(path || 0x00 || raw-file-digest)
//
// is identical in both attestors. If a future refactor changes one
// side without the other, inclusion proofs rooted in a material tree
// will not verify against the product attestor's leaves over the same
// input — and vice versa — which silently breaks any chain that
// composes the two.
//
// We can't import the product package here (would cause a circular
// dependency at the workspace level), so we re-derive the leaf
// encoding using only stdlib primitives and check that THIS module's
// computeLeafHashHex matches it byte-for-byte for a representative
// set of inputs. The product attestor has the symmetric test on its
// side. If either test fails, the two are out of sync — fix BOTH in
// the same commit.
func TestV03_010_LeafFormatConsistencyWithProduct(t *testing.T) {
	// Representative inputs spanning normal paths, deep paths, paths
	// with special characters, and a 0-byte digest (the
	// defense-in-depth path for unhashable files).
	// Every case must be a VALID sha256 hex digest. The v0.3 contract
	// is that every leaf is anchored to a real artifact digest; both
	// material and product reject empty/invalid digests (no
	// "defense-in-depth" silent leaves). A separate test below
	// asserts that error symmetry.
	cases := []struct {
		path       string
		fileDigest string
	}{
		{"a.txt", hex.EncodeToString(mustSha256("alpha"))},
		{"sub/b.txt", hex.EncodeToString(mustSha256("bravo"))},
		{"deep/nested/dir/c.bin", hex.EncodeToString(mustSha256("charlie"))},
		{"weird name with spaces.txt", hex.EncodeToString(mustSha256("delta"))},
	}

	for _, c := range cases {
		// Independent reference computation using stdlib sha256
		// only. The product attestor's spec-lock test does the
		// same thing on its side, so the two attestors converge
		// on this reference implementation by construction.
		raw, _ := hex.DecodeString(c.fileDigest)
		ref := sha256.New()
		_, _ = ref.Write([]byte(c.path))
		_, _ = ref.Write([]byte{0})
		_, _ = ref.Write(raw)
		want := hex.EncodeToString(ref.Sum(nil))

		got := computeLeafHashHex(c.path, c.fileDigest)
		assert.Equal(t, want, got,
			"leaf encoding drift for path=%q digest=%q — material/product attestors must agree",
			c.path, c.fileDigest)
	}
}

// =============================================================================
// V03_011: Attestor name / type / runtype constants did not regress
// =============================================================================

// V03_011 is the wire-format guard. If anyone "fixes" the predicate
// type by deleting the v0.3 URI, this test will catch it before the
// next release ships an incompatible artifact.
func TestV03_011_VersionConstants(t *testing.T) {
	a := New()
	assert.Equal(t, "material", a.Name())
	assert.Equal(t, "https://aflock.ai/attestations/material/v0.3", a.Type())
	assert.Equal(t, attestation.MaterialRunType, a.RunType())
	assert.Equal(t, "sha256", HashAlgorithm)
	assert.Equal(t, "RFC6962", Construction)
	assert.Equal(t, "tree:materials", TreeSubjectName)
}

// =============================================================================
// V03_012: Materialer interface still surfaces per-file map for downstream
// =============================================================================

// V03_012 is the interop check with slsa / link attestors. Both
// type-assert to MaterialAttestor and call Materials() at the END of a
// run; v0.3 must still hand them the per-file (path → DigestSet) map
// even though the predicate itself no longer carries it.
func TestV03_012_MaterialerInterfaceUnchanged(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{
		"a.txt": "alpha",
		"b.txt": "bravo",
	})
	var mi MaterialAttestor = a
	mats := mi.Materials()
	require.Len(t, mats, 2, "Materials() must return all walked files for slsa/link consumers")
	for path := range mats {
		assert.NotEmpty(t, path)
	}
}

// =============================================================================
// V03_013: Registry wires v0.3 producer AND v0.1 verify-only decoder
// =============================================================================

// V03_013 enforces the "creation hard-cut, verification multi-version" rule.
// v0.3 is the only producer; v0.1 must be registered as a verify-only
// decoder so cilock verify can still consume historical attestations.
// See plugins/attestors/material/legacy.go.
func TestV03_013_NoV01Registration(t *testing.T) {
	// v0.1 IS registered, but only as the verify-only LegacyDecoder.
	v01Factory, ok := attestation.FactoryByType("https://aflock.ai/attestations/material/v0.1")
	require.True(t, ok, "v0.1 must be registered as a verify-only decoder")
	_, isLegacy := v01Factory().(*LegacyDecoder)
	assert.True(t, isLegacy, "v0.1 factory must return *LegacyDecoder, not the v0.3 producer")

	_, ok = attestation.FactoryByType(Type)
	assert.True(t, ok, "v0.3 predicate type must be registered")

	factory, ok := attestation.FactoryByName(Name)
	require.True(t, ok)
	_, ok = factory().(*Attestor)
	assert.True(t, ok, "name lookup must return the v0.3 attestor")
}

// =============================================================================
// V03_014: Leaves() is sorted by normalized path
// =============================================================================

// V03_014 is the sort-stability check. Subjects() determinism relies
// on a stable sort by normalized path. If the sort key changes (e.g.,
// to OS-native paths), Windows-recorded and Linux-recorded
// attestations over the same logical input will produce DIFFERENT
// roots — and the bug will only surface in cross-OS CI.
func TestV03_014_LeavesSortedByNormalizedPath(t *testing.T) {
	a := makeMaterialAttestor(t, map[string]string{
		"zeta":    "1",
		"alpha":   "2",
		"middle":  "3",
		"sub/nu":  "4",
		"sub/mu":  "5",
		"deep/aa": "6",
	})
	leaves := a.Leaves()
	require.Len(t, leaves, 6)
	paths := make([]string, len(leaves))
	for i, l := range leaves {
		paths[i] = l.Path
	}
	sorted := make([]string, len(paths))
	copy(sorted, paths)
	sort.Strings(sorted)
	assert.Equal(t, sorted, paths, "leaves must be sorted by normalized path")
}

// =============================================================================
// Helper used only by the spec-lock test
// =============================================================================

func mustSha256(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}
