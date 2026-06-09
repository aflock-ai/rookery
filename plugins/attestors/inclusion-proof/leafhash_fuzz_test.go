// Copyright 2026 TestifySec, Inc.
//
// SPDX-License-Identifier: Apache-2.0

package inclusionproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Fuzz harnesses for the v0.3 path-dropped trust surface. These guard the
// security-load-bearing invariants of the leaf hash + the dedup helper + the
// producer/verifier agreement that Archivista discovery and inline-leaf verify
// both depend on. Run e.g.:
//   GOWORK=off go test -run x -fuzz FuzzProducerVerifierAgree -fuzztime 30s .

// splitEntries turns fuzz bytes into a list of (path, rawDigestSeed) pairs by
// splitting on NUL. Even fields are paths, odd fields are digest seeds.
func splitEntries(raw []byte) []LeafEntry {
	parts := bytes.Split(raw, []byte{0x00})
	out := make([]LeafEntry, 0, len(parts)/2)
	for i := 0; i+1 < len(parts); i += 2 {
		out = append(out, LeafEntry{Path: string(parts[i]), DigestHex: string(parts[i+1])})
	}
	return out
}

// validEntries is like splitEntries but maps each digest seed to a real
// lowercase-hex sha256 so it survives LeafHash/BuildSidecar validation.
func validEntries(raw []byte) []LeafEntry {
	in := splitEntries(raw)
	out := make([]LeafEntry, 0, len(in))
	for _, e := range in {
		sum := sha256.Sum256([]byte(e.DigestHex))
		out = append(out, LeafEntry{Path: e.Path, DigestHex: hex.EncodeToString(sum[:])})
	}
	return out
}

// FuzzLeafHashWithDomain: the leaf hash must be total (no panic/error on any
// 32-byte digest), fixed-width, deterministic, path-independent, and
// domain-separating.
func FuzzLeafHashWithDomain(f *testing.F) {
	f.Add("rookery-product/v0.3", "a/b/c", []byte("seed"))
	f.Add("", "", []byte{})
	f.Fuzz(func(t *testing.T, domain, path string, digestSeed []byte) {
		sum := sha256.Sum256(digestSeed)
		dg := hex.EncodeToString(sum[:])

		h1, err := LeafHashWithDomain(domain, path, dg)
		require.NoError(t, err)
		require.Len(t, h1, sha256.Size)

		// deterministic
		h2, err := LeafHashWithDomain(domain, path, dg)
		require.NoError(t, err)
		require.Equal(t, h1, h2)

		// path-independent
		h3, err := LeafHashWithDomain(domain, path+"/suffix", dg)
		require.NoError(t, err)
		require.Equal(t, h1, h3, "leaf hash must not depend on path")

		// domain-separating: a different domain yields a different leaf
		h4, err := LeafHashWithDomain(domain+"\x01alt", path, dg)
		require.NoError(t, err)
		require.NotEqual(t, h1, h4, "distinct domains must separate")
	})
}

// FuzzDedupAndSortByDigest pins the dedup helper invariants: idempotent,
// permutation-invariant, canonical (sorted, one survivor per digest), the
// survivor is the smallest path, and every distinct input digest is preserved
// (never silently dropped).
func FuzzDedupAndSortByDigest(f *testing.F) {
	f.Add([]byte("a\x00d1\x00b\x00d1\x00c\x00d2"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		entries := splitEntries(raw)

		got := DedupAndSortByDigest(append([]LeafEntry(nil), entries...))

		// idempotent
		again := DedupAndSortByDigest(append([]LeafEntry(nil), got...))
		require.Equal(t, got, again, "dedup must be idempotent")

		// canonical: strictly ascending by digest (already deduped), so each
		// digest appears at most once and the slice is sorted.
		for i := 1; i < len(got); i++ {
			require.Less(t, got[i-1].DigestHex, got[i].DigestHex, "output must be strictly ascending unique digests")
		}

		// expected survivors: every distinct input digest, with the smallest path.
		want := map[string]string{}
		for _, e := range entries {
			if p, ok := want[e.DigestHex]; !ok || e.Path < p {
				want[e.DigestHex] = e.Path
			}
		}
		require.Len(t, got, len(want), "must preserve exactly the distinct digests")
		for _, e := range got {
			require.Equal(t, want[e.DigestHex], e.Path, "survivor must be the smallest path for its digest")
		}

		// permutation-invariant: any input order yields the same canonical output.
		rev := make([]LeafEntry, len(entries))
		for i := range entries {
			rev[i] = entries[len(entries)-1-i]
		}
		require.Equal(t, got, DedupAndSortByDigest(rev), "dedup must be permutation-invariant")
	})
}

// FuzzProducerVerifierAgree is the differential invariant the whole discovery
// fix rests on: a sidecar BUILT by the producer must self-RECONSTRUCT (the
// verify-side path), be deterministic, and commit exactly one leaf per unique
// content digest. If producer and reconstruction ever diverge, digest discovery
// and inline-leaf verify silently break.
func FuzzProducerVerifierAgree(f *testing.F) {
	f.Add([]byte("bin\x00v1\x00bin2\x00v1\x00lib\x00v2"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		entries := validEntries(raw)
		if len(entries) == 0 {
			return // empty product set is exercised elsewhere
		}
		// BuildSidecar consumes a path->digest map, so same-path entries collapse
		// (last digest wins). Count unique digests over the MAP, not the raw
		// entries, to match what the producer actually trees.
		m := make(map[string]string, len(entries))
		for _, e := range entries {
			m[e.Path] = e.DigestHex
		}
		uniq := map[string]struct{}{}
		for _, dg := range m {
			uniq[strings.ToLower(dg)] = struct{}{}
		}

		sc, err := BuildSidecar("build", m)
		require.NoError(t, err)

		// producer sidecar must reconstruct to its own claimed root
		_, _, err = sc.Reconstruct()
		require.NoError(t, err, "producer sidecar must self-reconstruct")

		// deterministic: same logical input -> identical root AND leaves
		sc2, err := BuildSidecar("build", m)
		require.NoError(t, err)
		require.Equal(t, sc.MerkleRoot, sc2.MerkleRoot)
		require.Equal(t, sc.Leaves, sc2.Leaves)

		// one leaf per unique digest (dedup) and canonical order
		require.Equal(t, uint64(len(uniq)), sc.TreeSize, "tree commits one leaf per unique digest")
		require.True(t, sort.SliceIsSorted(sc.Leaves, func(i, j int) bool {
			if sc.Leaves[i].FileDigest != sc.Leaves[j].FileDigest {
				return sc.Leaves[i].FileDigest < sc.Leaves[j].FileDigest
			}
			return sc.Leaves[i].Path < sc.Leaves[j].Path
		}), "leaves in canonical (digest,path) order")
	})
}

// FuzzReadSidecar is a parse-robustness harness: an arbitrary (attacker-
// supplied) sidecar must never panic the parser or reconstructor. It may error
// — that is the expected fail-closed outcome.
func FuzzReadSidecar(f *testing.F) {
	f.Add([]byte(`{"schemaVersion":"x"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		s, err := ReadSidecar(bytes.NewReader(raw))
		if err != nil {
			return
		}
		// If it parsed, reconstruction must fail closed (error) or succeed —
		// never panic.
		_, _, _ = s.Reconstruct()
	})
}

// FuzzReconstructSoundness is the core soundness property of the verify-side
// reconstruction: a sidecar whose leaf set has been TAMPERED (content digest
// flipped, a leaf added, dropped, or duplicated) while keeping the original
// claimed MerkleRoot/TreeSize MUST fail closed. Reconstruct binds the leaf
// CONTENT + multiset to the claimed root; path-only changes are intentionally
// NOT caught here (the DSSE signature over the inline leaves protects the path).
func FuzzReconstructSoundness(f *testing.F) {
	f.Add([]byte("bin\x00v1\x00lib\x00v2\x00doc\x00v3"), uint8(0), uint8(0))
	f.Fuzz(func(t *testing.T, raw []byte, mut uint8, idx uint8) {
		entries := validEntries(raw)
		if len(entries) == 0 {
			return
		}
		m := make(map[string]string, len(entries))
		for _, e := range entries {
			m[e.Path] = e.DigestHex
		}
		sc, err := BuildSidecar("build", m)
		require.NoError(t, err)
		if len(sc.Leaves) == 0 {
			return
		}
		// Sanity: the honest sidecar reconstructs.
		if _, _, err := sc.Reconstruct(); err != nil {
			t.Fatalf("honest sidecar failed to reconstruct: %v", err)
		}

		k := int(idx) % len(sc.Leaves)
		switch mut % 4 {
		case 0: // content tamper: flip a bit in a leaf's digest, keep the claimed root
			rawd, derr := hex.DecodeString(sc.Leaves[k].FileDigest)
			if derr != nil || len(rawd) == 0 {
				return
			}
			rawd[0] ^= 0x01
			sc.Leaves[k].FileDigest = hex.EncodeToString(rawd)
		case 1: // extra leaf, claimed TreeSize/root unchanged
			sum := sha256.Sum256([]byte("smuggled-extra-leaf"))
			sc.Leaves = append(sc.Leaves, SidecarLeaf{Path: "x", FileDigest: hex.EncodeToString(sum[:])})
		case 2: // drop a leaf
			sc.Leaves = append(sc.Leaves[:k], sc.Leaves[k+1:]...)
		case 3: // duplicate a leaf (collide a digest)
			sc.Leaves = append(sc.Leaves, sc.Leaves[k])
		}

		// After ANY content/structure tamper that keeps the original claimed
		// root + size, Reconstruct MUST return an error. A nil error here would
		// mean the signed root does not actually bind the leaf set.
		if _, _, rerr := sc.Reconstruct(); rerr == nil {
			t.Fatalf("TAMPER ACCEPTED (mut=%d): a mutated leaf set reconstructed against the original root\nleaves=%v root=%s size=%d",
				mut%4, sc.Leaves, sc.MerkleRoot, sc.TreeSize)
		}
	})
}
