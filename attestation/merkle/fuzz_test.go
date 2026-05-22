//go:build audit

package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// chunk32 splits b into HashSize-byte slices. If len(b) is not a multiple of
// HashSize, returns ok=false — the fuzzer should treat that as malformed
// input and skip rather than crash.
func chunk32(b []byte) ([][]byte, bool) {
	if len(b)%HashSize != 0 {
		return nil, false
	}
	out := make([][]byte, len(b)/HashSize)
	for i := range out {
		out[i] = b[i*HashSize : (i+1)*HashSize]
	}
	return out, true
}

// FuzzInclusionProofVerify exercises VerifyInclusion with arbitrary inputs.
// The contract:
//
//   - Never panic regardless of input.
//   - Never return nil (success) unless RootFromInclusionProof independently
//     recomputes the SAME claimed root from the same inputs. This catches
//     any future drift between Verify and RootFromInclusionProof.
//
// Seeds cover the RFC 9162 §2.1.5 7-leaf vector, the 5-leaf odd-split case,
// a single-leaf tree, and the empty-tree edge.
func FuzzInclusionProofVerify(f *testing.F) {
	// Seed: 7-leaf RFC 9162 example, index 3.
	tr7 := buildTree(7)
	leaf3 := sha256One(3)
	proof3, _ := tr7.InclusionProof(3)
	f.Add(uint64(7), uint64(3), leaf3, flatten(proof3), tr7.Root())

	// Seed: 5-leaf odd-split, index 4 (the awkward right edge).
	tr5 := buildTree(5)
	leaf4 := sha256One(4)
	proof4, _ := tr5.InclusionProof(4)
	f.Add(uint64(5), uint64(4), leaf4, flatten(proof4), tr5.Root())

	// Seed: single-leaf tree.
	tr1 := buildTree(1)
	f.Add(uint64(1), uint64(0), sha256One(0), []byte{}, tr1.Root())

	// Seed: empty tree (treeSize=0 always rejects).
	empty := sha256.Sum256(nil)
	f.Add(uint64(0), uint64(0), sha256One(0), []byte{}, empty[:])

	f.Fuzz(func(t *testing.T, treeSize, leafIndex uint64, leafHash, proofBytes, root []byte) {
		// Bound treeSize so the upstream proof package doesn't allocate
		// unbounded memory chasing huge sizes. Real attestor inputs are
		// trillions-of-leaves-at-most; capping at 1<<32 is generous.
		if treeSize > 1<<32 {
			t.Skip()
		}
		proofPath, ok := chunk32(proofBytes)
		if !ok {
			// Malformed proof byte length — the fuzzer should still call
			// the API to make sure we don't panic on unaligned inputs.
			err := VerifyInclusion(treeSize, leafIndex, leafHash, [][]byte{proofBytes}, root)
			_ = err // any error is fine; no panic is the invariant
			return
		}

		err := VerifyInclusion(treeSize, leafIndex, leafHash, proofPath, root)
		if err == nil {
			// Cross-check: the wrapper claimed success. RootFromInclusionProof
			// must yield the same root, or we have a Verify/Root divergence.
			calc, err2 := RootFromInclusionProof(treeSize, leafIndex, leafHash, proofPath)
			require.NoError(t, err2, "Verify accepted but Root rejected — divergence")
			require.True(t, bytes.Equal(calc, root),
				"Verify accepted a proof but RootFromInclusionProof produced a different root")
		}
	})
}

// FuzzProofGeneration exercises the generator → verifier round trip. For
// any well-shaped (leaves, index) input we generate a proof and verify it.
// Asserts: generator and verifier agree.
func FuzzProofGeneration(f *testing.F) {
	// Seeds: same shapes as the per-test matrix.
	f.Add(uint8(7), uint64(3))
	f.Add(uint8(5), uint64(4))
	f.Add(uint8(1), uint64(0))
	f.Add(uint8(13), uint64(9))
	f.Add(uint8(0), uint64(0)) // empty tree edge

	f.Fuzz(func(t *testing.T, n uint8, index uint64) {
		// n caps at 255 already (uint8), which keeps runtime bounded
		// without distorting tree shape diversity.
		if n == 0 {
			tr, err := NewTree(nil)
			require.NoError(t, err)
			_, err = tr.InclusionProof(index)
			require.Error(t, err, "InclusionProof on empty tree must fail")
			return
		}
		tr := buildTree(int(n))
		if index >= tr.Size() {
			_, err := tr.InclusionProof(index)
			require.Error(t, err, "out-of-range index must fail")
			return
		}
		leaf := sha256One(byte(index))
		proofPath, err := tr.InclusionProof(index)
		require.NoError(t, err)
		require.NoError(t, VerifyInclusion(tr.Size(), index, leaf, proofPath, tr.Root()))
		require.NoError(t, VerifyInclusionStrict(tr.Size(), index, leaf, proofPath, tr.Root()))
	})
}

// merklePredicate mirrors the shape we will publish in v0.3
// product/material/inclusion-proof attestations. Held here as a forward
// declaration so we can lock down JSON round-trip stability before the
// attestor packages land.
//
// Tracking issue: https://github.com/aflock-ai/rookery/issues/135.
type merklePredicate struct {
	MerkleRoot    string `json:"merkleRoot"`
	TreeSize      uint64 `json:"treeSize"`
	HashAlgorithm string `json:"hashAlgorithm"`
	Construction  string `json:"construction"`
}

// FuzzPredicateRoundTrip locks down byte-stable JSON for the predicate
// shape that v0.3 attestors will emit. Forward-looking; the real attestor
// packages will adopt this exact shape and re-run the fuzz.
func FuzzPredicateRoundTrip(f *testing.F) {
	// Canonical shapes drawn from issue #135.
	f.Add("deadbeef", uint64(0), Hash, Construction)
	f.Add("", uint64(0), Hash, Construction)
	f.Add("3560191803028444b232018ac047fdb561c09c23a7a6876c85e08b5e4d48e9f3", uint64(7), Hash, Construction)
	f.Add("xyz", uint64(1<<40), "sha256", "RFC6962")

	f.Fuzz(func(t *testing.T, root string, size uint64, alg, cons string) {
		// The real v0.3 predicate fields are all ASCII (hex roots, fixed
		// algorithm/construction identifiers). Skip non-UTF-8 inputs —
		// encoding/json normalises invalid UTF-8 to U+FFFD on Marshal, which
		// is a documented (and stable) behaviour, but it makes the round
		// trip lossy. Filtering matches the production contract.
		if !utf8.ValidString(root) || !utf8.ValidString(alg) || !utf8.ValidString(cons) {
			t.Skip()
		}
		p := merklePredicate{
			MerkleRoot:    root,
			TreeSize:      size,
			HashAlgorithm: alg,
			Construction:  cons,
		}
		b1, err := json.Marshal(p)
		require.NoError(t, err)
		var back merklePredicate
		require.NoError(t, json.Unmarshal(b1, &back))
		b2, err := json.Marshal(back)
		require.NoError(t, err)
		require.True(t, bytes.Equal(b1, b2), "predicate JSON must be byte-stable on round-trip")
	})
}

// ---- fuzz helpers ----------------------------------------------------------

func buildTree(n int) *Tree {
	leaves := make([][]byte, n)
	for i := 0; i < n; i++ {
		leaves[i] = sha256One(byte(i))
	}
	tr, _ := NewTree(leaves)
	return tr
}

func sha256One(b byte) []byte {
	h := sha256.Sum256([]byte{b})
	return h[:]
}

func flatten(proof [][]byte) []byte {
	out := make([]byte, 0, len(proof)*HashSize)
	for _, p := range proof {
		out = append(out, p...)
	}
	return out
}
