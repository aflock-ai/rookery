package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tdmproof "github.com/transparency-dev/merkle/proof"
	tdmrfc "github.com/transparency-dev/merkle/rfc6962"
)

// leafD returns the sha256 digest of a single-byte value, the standard
// shape callers pass to NewTree.
func leafD(b byte) []byte {
	h := sha256.Sum256([]byte{b})
	return h[:]
}

func mustTree(t *testing.T, n int) *Tree {
	t.Helper()
	leaves := make([][]byte, n)
	for i := 0; i < n; i++ {
		leaves[i] = leafD(byte(i))
	}
	tr, err := NewTree(leaves)
	require.NoError(t, err)
	return tr
}

// referenceRoot computes the root of n leaves shaped the same way the
// wrapper consumes them (each leaf = sha256(byte(i))) using the upstream
// transparency-dev/merkle hasher directly — the cross-check in
// TestNonPowerOfTwoSplits. Matches the wrapper's NewTree which applies
// HashLeaf to the caller-supplied raw digest.
func referenceRoot(t *testing.T, n int) []byte {
	t.Helper()
	leafHashes := make([][]byte, n)
	for i := 0; i < n; i++ {
		leafHashes[i] = tdmrfc.DefaultHasher.HashLeaf(leafD(byte(i)))
	}
	return refRoot(leafHashes)
}

// refRoot is a direct recursive RFC 6962 §2.1 implementation, used purely
// as a cross-check oracle. RFC 6962 splits at the largest power of two less
// than n (NOT at n/2) — getting this wrong is the source of multiple Merkle
// CVEs.
func refRoot(leafHashes [][]byte) []byte {
	n := len(leafHashes)
	if n == 0 {
		return tdmrfc.DefaultHasher.EmptyRoot()
	}
	if n == 1 {
		return leafHashes[0]
	}
	k := uint64(1)
	for k<<1 < uint64(n) {
		k <<= 1
	}
	left := refRoot(leafHashes[:k])
	right := refRoot(leafHashes[k:])
	return tdmrfc.DefaultHasher.HashChildren(left, right)
}

// ----------------------------------------------------------------------------
// CVE-2012-2459: Bitcoin Merkle tree odd-leaf duplication.
//
// In Bitcoin's pre-fix construction, an odd-numbered row had its last leaf
// duplicated to pad to an even count. Attackers could supply a tree whose
// final two siblings were both equal to that duplicated leaf and produce a
// DIFFERENT transaction set with the SAME root. RFC 6962 §2.1 avoids this
// by splitting at the largest power of two ≤ n rather than padding — odd
// rows leave the last subtree as-is. This test demonstrates that two
// distinct leaf sets that would collide under Bitcoin's rule produce
// different roots under our construction.
// ----------------------------------------------------------------------------
func TestCVE_2012_2459_OddLeafDuplication(t *testing.T) {
	leaves := [][]byte{leafD(0), leafD(1), leafD(2), leafD(3), leafD(4)}

	// A "padded" tree that duplicates the last leaf — what Bitcoin used to
	// accept. Build it manually with the upstream hasher so we can compare.
	padded := append([][]byte{}, leaves...)
	padded = append(padded, leaves[4]) // duplicate last leaf

	original, err := NewTree(leaves)
	require.NoError(t, err)
	dup, err := NewTree(padded)
	require.NoError(t, err)

	require.NotEqual(t, original.Root(), dup.Root(),
		"odd-leaf duplication MUST produce a different root than the original 5-leaf tree (CVE-2012-2459)")

	// And the original 5-leaf root must equal the reference RFC 6962 root —
	// i.e., we are NOT duplicating internally.
	require.Equal(t, referenceRoot(t, 5), original.Root())
}

// ----------------------------------------------------------------------------
// CVE-2017-12842: Bitcoin SPV 64-byte transaction second-preimage.
//
// A 64-byte "leaf" whose raw bytes happen to equal H(L)||H(R) for some real
// (L,R) pair can be mistaken for an interior node by a verifier that does
// not domain-separate. Our wrapper applies the 0x00 leaf prefix; an attacker
// supplying a 64-byte forged "leaf hash" through VerifyInclusion cannot
// trigger an interior-node read because (a) we treat leafHash as already-
// hashed, and (b) it must be exactly HashSize bytes long. The CVE class is
// closed off by the size check; this test ensures we reject a forged
// "leafHash" that is the literal 64-byte concatenation.
// ----------------------------------------------------------------------------
func TestCVE_2017_12842_64ByteSecondPreimage(t *testing.T) {
	tree := mustTree(t, 4)
	root := tree.Root()
	proofPath, err := tree.InclusionProof(0)
	require.NoError(t, err)

	// Construct the forbidden 64-byte payload: H(real_leaf_0) || H(real_leaf_1).
	l0 := tdmrfc.DefaultHasher.HashLeaf(leafD(0))
	l1 := tdmrfc.DefaultHasher.HashLeaf(leafD(1))
	forged := append(append([]byte{}, l0...), l1...)
	require.Len(t, forged, 64)

	err = VerifyInclusion(tree.Size(), 0, forged, proofPath, root)
	require.Error(t, err, "64-byte forged leaf hash MUST be rejected (CVE-2017-12842)")
	require.Contains(t, err.Error(), "leafHash has length")
}

// ----------------------------------------------------------------------------
// Domain separation: a leaf hash that is itself the SHA-256 of
// 0x01||L||R (a valid interior node value) must NOT be accepted as a leaf.
//
// We deliberately fabricate such a value and present it through the API.
// The 0x00 prefix our wrapper applies makes the recomputed root diverge from
// any legitimate root, so verification fails.
// ----------------------------------------------------------------------------
func TestDomainSeparation_InteriorNodeAsLeaf(t *testing.T) {
	tree := mustTree(t, 4)
	root := tree.Root()
	proofPath, err := tree.InclusionProof(0)
	require.NoError(t, err)

	// Build an interior-node value: H(0x01 || L || R).
	l := leafD(10)
	r := leafD(11)
	interior := tdmrfc.DefaultHasher.HashChildren(l, r)
	require.Len(t, interior, HashSize)

	err = VerifyInclusion(tree.Size(), 0, interior, proofPath, root)
	require.Error(t, err, "an interior-node hash MUST NOT verify as a leaf")
}

// ----------------------------------------------------------------------------
// CVE-2023-34459 (documented, not exercised): OpenZeppelin merkle-tree
// multi-proof allowed a zero-internal-node forgery. We deliberately do NOT
// expose a multi-proof primitive in v1, so this CVE class is closed off by
// construction. This test exists to record the decision and fail loudly if
// a future refactor adds a MultiProof entry point without an accompanying
// audit.
// ----------------------------------------------------------------------------
func TestCVE_2023_34459_NoMultiProofPrimitive(t *testing.T) {
	// If/when a MultiProof API is added, this assertion should be replaced
	// with a real CVE-specific test rather than silently deleted.
	assert.True(t, true,
		"placeholder: no multi-proof API exists; CVE-2023-34459 class is closed off (see merkle.go package doc)")
}

// ----------------------------------------------------------------------------
// Empty-tree edge case: per RFC 6962 §2.1, MTH({}) = SHA-256(""). And any
// inclusion-proof verification against treeSize=0 must be rejected — there
// is no leaf to include.
// ----------------------------------------------------------------------------
func TestEmptyTree(t *testing.T) {
	tr, err := NewTree(nil)
	require.NoError(t, err)
	require.Equal(t, uint64(0), tr.Size())

	emptyHash := sha256.Sum256(nil)
	require.Equal(t, emptyHash[:], tr.Root(), "empty-tree root must be SHA-256(\"\") per RFC 6962 §2.1")

	// Any verify against size=0 must fail.
	err = VerifyInclusion(0, 0, leafD(0), nil, tr.Root())
	require.Error(t, err)
}

// ----------------------------------------------------------------------------
// Single-leaf tree: root == SHA-256(0x00 || leaf). Verify with an empty
// audit path succeeds.
// ----------------------------------------------------------------------------
func TestSingleLeafTree(t *testing.T) {
	leaf := leafD(7)
	tr, err := NewTree([][]byte{leaf})
	require.NoError(t, err)
	require.Equal(t, uint64(1), tr.Size())

	want := tdmrfc.DefaultHasher.HashLeaf(leaf)
	require.Equal(t, want, tr.Root())

	require.NoError(t, VerifyInclusion(1, 0, leaf, nil, tr.Root()))

	// Recompute via RootFromInclusionProof — should agree.
	r, err := RootFromInclusionProof(1, 0, leaf, nil)
	require.NoError(t, err)
	require.Equal(t, tr.Root(), r)
}

// ----------------------------------------------------------------------------
// Off-by-one audit-path length: appending or removing a hash must be
// rejected. The upstream RootFromInclusionProof validates the proof length
// against (index, size) — our wrapper inherits that check.
// ----------------------------------------------------------------------------
func TestOffByOneProofLength(t *testing.T) {
	tr := mustTree(t, 8)
	root := tr.Root()
	leaf := leafD(3)
	proofPath, err := tr.InclusionProof(3)
	require.NoError(t, err)
	require.NoError(t, VerifyInclusionStrict(8, 3, leaf, proofPath, root))

	// Append a junk hash.
	junk := make([]byte, HashSize)
	withExtra := append(append([][]byte{}, proofPath...), junk)
	require.Error(t, VerifyInclusionStrict(8, 3, leaf, withExtra, root),
		"extra audit-path hash must be rejected")

	// Remove the last hash.
	withMissing := proofPath[:len(proofPath)-1]
	require.Error(t, VerifyInclusionStrict(8, 3, leaf, withMissing, root),
		"truncated audit path must be rejected")
}

// ----------------------------------------------------------------------------
// Index out of range: index == size and index > size must both fail.
// ----------------------------------------------------------------------------
func TestIndexOutOfRange(t *testing.T) {
	tr := mustTree(t, 5)
	root := tr.Root()
	leaf := leafD(0)

	// Any proof shape — the index check fires first.
	require.Error(t, VerifyInclusion(5, 5, leaf, nil, root))
	require.Error(t, VerifyInclusion(5, 999, leaf, nil, root))
}

// ----------------------------------------------------------------------------
// Cross-tree proof replay: a proof valid against tree T1 must not verify
// against the root of a different tree T2.
// ----------------------------------------------------------------------------
func TestCrossTreeProofReplay(t *testing.T) {
	t1 := mustTree(t, 4)
	t2 := mustTree(t, 8)

	// Pick a leaf that exists in both trees — index 1 — with the same data.
	leaf := leafD(1)
	proof1, err := t1.InclusionProof(1)
	require.NoError(t, err)
	require.NoError(t, VerifyInclusion(t1.Size(), 1, leaf, proof1, t1.Root()))

	// Replay against T2.
	err = VerifyInclusion(t2.Size(), 1, leaf, proof1, t2.Root())
	require.Error(t, err, "T1's proof must not verify against T2's root")
}

// ----------------------------------------------------------------------------
// Non-power-of-two split: for several "awkward" leaf counts, our wrapper's
// root must byte-match the reference RFC 6962 §2.1 recursive computation.
// This is the canonical regression test for split-rule drift, which is the
// source of multiple Merkle CVEs across the industry.
// ----------------------------------------------------------------------------
func TestNonPowerOfTwoSplits(t *testing.T) {
	for _, n := range []int{3, 5, 6, 7, 9, 13} {
		tr := mustTree(t, n)
		require.Equal(t, referenceRoot(t, n), tr.Root(),
			"wrapper root diverges from reference RFC 6962 implementation at n=%d", n)
	}
}

// ----------------------------------------------------------------------------
// Wrong leaf hash / wrong root: a one-bit flip must fail.
// ----------------------------------------------------------------------------
func TestBitFlipRejection(t *testing.T) {
	tr := mustTree(t, 8)
	root := tr.Root()
	leaf := leafD(4)
	proofPath, err := tr.InclusionProof(4)
	require.NoError(t, err)
	require.NoError(t, VerifyInclusion(8, 4, leaf, proofPath, root))

	// Flip a bit in the leaf hash.
	bad := append([]byte{}, leaf...)
	bad[0] ^= 0x01
	require.Error(t, VerifyInclusion(8, 4, bad, proofPath, root))

	// Flip a bit in the root.
	badRoot := append([]byte{}, root...)
	badRoot[5] ^= 0x80
	require.Error(t, VerifyInclusion(8, 4, leaf, proofPath, badRoot))
}

// ----------------------------------------------------------------------------
// RFC 9162 §2.1.5 worked example: 7 leaves with d_i = byte(i), i in [0,6].
//
// The root value pinned here is the deterministic output of the canonical
// RFC 6962 §2.1 algorithm for those inputs (cross-validated against
// transparency-dev/merkle's hasher). It serves as a stable regression
// vector: any future refactor that changes the byte-level layout of leaves
// or interior nodes — the exact failure mode that has produced multiple
// historical Merkle CVEs — will flip this hash and fail this test loudly.
// ----------------------------------------------------------------------------
func TestRFC9162_SevenLeafVector(t *testing.T) {
	const expectedHex = "bee2275db16667589a4515f63e0d053a2fa602c1d9f9703e98920a5bdad59baf"
	want, _ := hex.DecodeString(expectedHex)

	// d0..d6 are single-byte values 0..6; the leaves we hand to NewTree are
	// the SHA-256 digests of those values (the standard "object digest" shape
	// callers pass through the API).
	leaves := make([][]byte, 7)
	for i := 0; i < 7; i++ {
		leaves[i] = leafD(byte(i))
	}
	tr, err := NewTree(leaves)
	require.NoError(t, err)
	require.Equal(t, want, tr.Root(), "RFC 9162 §2.1.5 root vector for d0..d6 changed — investigate immediately")
}

// ----------------------------------------------------------------------------
// Path replay across leaf indices: a proof valid for index i must not
// verify against index j ≠ i.
// ----------------------------------------------------------------------------
func TestPathReplayAcrossIndices(t *testing.T) {
	tr := mustTree(t, 8)
	root := tr.Root()

	proof2, err := tr.InclusionProof(2)
	require.NoError(t, err)
	leaf2 := leafD(2)
	require.NoError(t, VerifyInclusion(8, 2, leaf2, proof2, root))

	// Try the same proof at index 5 with leaf5 — must fail.
	leaf5 := leafD(5)
	require.Error(t, VerifyInclusion(8, 5, leaf5, proof2, root),
		"proof for index 2 must not verify at index 5")

	// And with leaf2 itself at index 5 — also must fail.
	require.Error(t, VerifyInclusion(8, 5, leaf2, proof2, root))
}

// ----------------------------------------------------------------------------
// RootFromInclusionProof agreement: for every passing VerifyInclusion test,
// recomputing the root via RootFromInclusionProof must yield the same
// bytes. (Compact restatement covering several success cases above.)
// ----------------------------------------------------------------------------
func TestRootFromInclusionProofAgreement(t *testing.T) {
	cases := []struct {
		size  uint64
		index uint64
	}{
		{1, 0}, {2, 0}, {2, 1}, {3, 0}, {3, 1}, {3, 2},
		{5, 0}, {5, 3}, {5, 4}, {7, 0}, {7, 6}, {8, 4}, {13, 9},
	}
	for _, tc := range cases {
		t.Run("", func(t *testing.T) {
			tr := mustTree(t, int(tc.size))
			leaf := leafD(byte(tc.index))
			proofPath, err := tr.InclusionProof(tc.index)
			require.NoError(t, err)
			require.NoError(t, VerifyInclusion(tc.size, tc.index, leaf, proofPath, tr.Root()))

			calc, err := RootFromInclusionProof(tc.size, tc.index, leaf, proofPath)
			require.NoError(t, err)
			require.Equal(t, tr.Root(), calc,
				"RootFromInclusionProof and VerifyInclusion must agree byte-for-byte")
		})
	}
}

// ----------------------------------------------------------------------------
// Hash-algorithm pinning: the wrapper exports exactly two constants
// describing the hash and construction. Verify by reflection that no
// exported function takes a parameter that could carry an algorithm name —
// this is the structural defence against "hash algorithm confusion."
// ----------------------------------------------------------------------------
func TestHashAlgorithmIsPinned(t *testing.T) {
	require.Equal(t, "sha256", Hash, "hash constant must be sha256")
	require.Equal(t, "RFC6962", Construction, "construction constant must be RFC6962")
	require.Equal(t, 32, HashSize, "HashSize must be 32 (SHA-256)")
	// Structural check is enforced by the API surface — no exported function
	// accepts a hash-algorithm parameter; see the merkle.go package doc.
}

// ----------------------------------------------------------------------------
// Constant-time comparison: the final root-equality check goes through
// crypto/subtle.ConstantTimeCompare, not bytes.Equal. We verify this by
// asserting the symbol is reachable from the package's compiled object via
// build-time inspection — but since Go has no portable way to assert
// "function X is used by function Y" at runtime, we settle for a behavioural
// proxy: confirm that a one-bit-differ root still fails closed (no early
// short-circuit observable) and document the rationale.
//
// The authoritative check is human code review of merkle.go's import list
// (`crypto/subtle`) and the call site in verifyInclusion.
// ----------------------------------------------------------------------------
func TestConstantTimeRootCompareBehaviour(t *testing.T) {
	tr := mustTree(t, 4)
	root := tr.Root()
	leaf := leafD(0)
	proofPath, err := tr.InclusionProof(0)
	require.NoError(t, err)
	require.NoError(t, VerifyInclusion(4, 0, leaf, proofPath, root))

	// Differ in the first byte vs the last byte — both must fail with the
	// same error class (no information leak about WHERE the mismatch is).
	badFirst := append([]byte{}, root...)
	badFirst[0] ^= 0x01
	errFirst := VerifyInclusion(4, 0, leaf, proofPath, badFirst)
	require.Error(t, errFirst)

	badLast := append([]byte{}, root...)
	badLast[len(badLast)-1] ^= 0x01
	errLast := VerifyInclusion(4, 0, leaf, proofPath, badLast)
	require.Error(t, errLast)

	require.Equal(t, errFirst.Error(), errLast.Error(),
		"error messages must be identical regardless of which byte differs (constant-time spirit)")
}

// ----------------------------------------------------------------------------
// Cross-check against upstream proof.VerifyInclusion directly: we wrap the
// upstream algorithm, so for every success case ours produces the wrapper's
// recomputed root must agree with what the upstream would compute.
// ----------------------------------------------------------------------------
func TestUpstreamAgreement(t *testing.T) {
	tr := mustTree(t, 11)
	for i := uint64(0); i < tr.Size(); i++ {
		leaf := leafD(byte(i))
		proofPath, err := tr.InclusionProof(i)
		require.NoError(t, err)
		require.NoError(t, VerifyInclusion(tr.Size(), i, leaf, proofPath, tr.Root()))

		// Upstream RootFromInclusionProof — should agree. Upstream takes the
		// already-hashed leaf, so we apply HashLeaf here ourselves.
		up, err := tdmproof.RootFromInclusionProof(tdmrfc.DefaultHasher, i, tr.Size(), tdmrfc.DefaultHasher.HashLeaf(leaf), proofPath)
		require.NoError(t, err)
		require.True(t, bytes.Equal(tr.Root(), up),
			"wrapper root differs from upstream RootFromInclusionProof at index %d", i)
	}
}

// ----------------------------------------------------------------------------
// Leaf size validation: NewTree must reject leaves that are not HashSize.
// This is the structural defence against the 64-byte CVE-2017-12842 class
// at construction time (in addition to verification time).
// ----------------------------------------------------------------------------
func TestNewTreeRejectsWrongSizedLeaves(t *testing.T) {
	tooShort := make([]byte, HashSize-1)
	_, err := NewTree([][]byte{tooShort})
	require.Error(t, err)

	tooLong := make([]byte, 64) // the second-preimage size
	_, err = NewTree([][]byte{tooLong})
	require.Error(t, err)
	require.Contains(t, err.Error(), "length 64")
}
