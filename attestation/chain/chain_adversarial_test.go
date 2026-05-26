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

package chain

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/merkle"
)

// buildSampleChain assembles a small but real chain sidecar for the
// adversarial tests to mutate. Returns the sidecar, the source-step
// reference (with EnvelopeDigest binding), and the audit-path
// material so individual tests can poke specific fields.
func buildSampleChain(t *testing.T, domain string) (ChainSidecar, []SidecarLeaf, []ConsumedMaterial) {
	t.Helper()
	leaves := []SidecarLeaf{
		{Path: "build/binary", FileDigest: strings.Repeat("aa", 32)},
		{Path: "build/manifest.json", FileDigest: strings.Repeat("bb", 32)},
		{Path: "src/main.go", FileDigest: strings.Repeat("cc", 32)},
	}

	// Pre-hash leaves to compute the source root the same way
	// BuildChainSidecar will.
	preHashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, err := LeafHashWithDomain(domain, l.Path, l.FileDigest)
		if err != nil {
			t.Fatalf("LeafHashWithDomain: %v", err)
		}
		preHashes[i] = h
	}
	tree, err := merkle.NewTree(preHashes)
	if err != nil {
		t.Fatalf("merkle.NewTree: %v", err)
	}
	rootHex := hex.EncodeToString(tree.Root())

	source := SourceStepRef{
		StepName:       "source",
		EnvelopeDigest: strings.Repeat("01", 32),
		MerkleRoot:     rootHex,
		TreeSize:       uint64(len(leaves)),
		Domain:         domain,
	}

	consumed := []ConsumedMaterial{
		{Path: "build/binary", FileDigest: strings.Repeat("aa", 32)},
	}

	sidecar, err := BuildChainSidecar(source, leaves, consumed)
	if err != nil {
		t.Fatalf("BuildChainSidecar: %v", err)
	}
	return sidecar, leaves, consumed
}

// TestAdversarial_TamperedMerkleRoot exercises the verifier's
// root-binding check. An attacker who flips one byte of the signed
// MerkleRoot must cause every inclusion proof to fail — otherwise
// the chain anchor is meaningless.
func TestAdversarial_TamperedMerkleRoot(t *testing.T) {
	sidecar, _, _ := buildSampleChain(t, "")

	// Flip the trailing hex nibble of the root.
	root := sidecar.SourceStep.MerkleRoot
	lastIdx := len(root) - 1
	flipped := root[:lastIdx]
	switch root[lastIdx] {
	case '0':
		flipped += "1"
	default:
		flipped += "0"
	}
	sidecar.SourceStep.MerkleRoot = flipped

	if err := VerifyChainSidecar(sidecar); err == nil {
		t.Fatal("expected verify to fail with tampered MerkleRoot; got nil")
	}
}

// TestAdversarial_TamperedAuditPath confirms an attacker can't
// fabricate a passing proof by swapping out audit-path siblings.
// Drop the first sibling hash; the rebuilt root will diverge from
// the signed root.
func TestAdversarial_TamperedAuditPath(t *testing.T) {
	sidecar, _, _ := buildSampleChain(t, "")
	if len(sidecar.MaterialProofs[0].AuditPath) == 0 {
		t.Fatalf("expected non-empty audit path; tree may have only one leaf")
	}
	// Replace a sibling with an all-zero hash.
	sidecar.MaterialProofs[0].AuditPath[0] = strings.Repeat("00", 32)
	if err := VerifyChainSidecar(sidecar); err == nil {
		t.Fatal("expected verify to fail with tampered audit path; got nil")
	}
}

// TestAdversarial_SchemaVersionDowngrade rejects any sidecar that
// claims a schema version this build doesn't understand. Future v0.2
// formats must not be accepted by a v0.1 verifier — that would let
// a malicious producer add semantics the verifier silently ignores.
func TestAdversarial_SchemaVersionDowngrade(t *testing.T) {
	sidecar, _, _ := buildSampleChain(t, "")
	sidecar.SchemaVersion = "rookery.chain-proof.sidecar/v0.99"
	err := VerifyChainSidecar(sidecar)
	if err == nil {
		t.Fatal("expected verify to fail with unknown schema version; got nil")
	}
	if !strings.Contains(err.Error(), "schema") {
		t.Errorf("error %q should mention schema; verify caller can't diagnose otherwise", err)
	}
}

// TestAdversarial_DomainSeparation checks that a proof built under
// domain A does NOT verify under domain B even with identical
// (path, digest) leaf data. Closes threat-model E4
// (cross-application replay).
func TestAdversarial_DomainSeparation(t *testing.T) {
	sidecar, _, _ := buildSampleChain(t, "rookery-product/v0.3")

	// Forge a "matching" sidecar under a different domain. The leaf
	// pre-hash bytes will differ because the domain prefix differs;
	// the rebuilt-root check inside VerifyChainSidecar uses the
	// SourceStep.Domain field — so flipping that field without
	// regenerating the proofs must produce a verification failure.
	sidecar.SourceStep.Domain = "rookery-material/v0.3"
	if err := VerifyChainSidecar(sidecar); err == nil {
		t.Fatal("expected verify to fail when domain is swapped; got nil")
	}
}

// TestAdversarial_NFCNFDPathDivergence is the regression guard for
// the cross-platform path-normalization bug PR #176b fixes. The same
// logical material "café.txt" encoded as NFC and NFD must hash to
// IDENTICAL leaf bytes after NormalizePath. Without NFC, a chain
// produced on macOS (NFD default) wouldn't verify on Linux (NFC
// default).
func TestAdversarial_NFCNFDPathDivergence(t *testing.T) {
	const digestHex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	// "café" composed (NFC): c, a, f, é=U+00E9 (single codepoint)
	pathNFC := "build/café.txt"
	// "café" decomposed (NFD): c, a, f, e=U+0065, combining acute U+0301
	pathNFD := "build/café.txt"

	// Sanity: the raw strings DIFFER before normalization.
	if pathNFC == pathNFD {
		t.Fatal("test fixtures broken: NFC and NFD strings compare equal pre-normalize")
	}

	normNFC := NormalizePath(pathNFC)
	normNFD := NormalizePath(pathNFD)
	if normNFC != normNFD {
		t.Fatalf("NormalizePath must collapse NFC/NFD to the same bytes; got %q vs %q (NFC %x vs NFD %x)",
			normNFC, normNFD, normNFC, normNFD)
	}

	// Both produce the same leaf hash → cross-platform chains verify.
	hNFC, err := LeafHash(normNFC, digestHex)
	if err != nil {
		t.Fatalf("LeafHash NFC: %v", err)
	}
	hNFD, err := LeafHash(normNFD, digestHex)
	if err != nil {
		t.Fatalf("LeafHash NFD: %v", err)
	}
	if hex.EncodeToString(hNFC) != hex.EncodeToString(hNFD) {
		t.Fatalf("leaf hash must be identical for NFC/NFD encodings of the same logical path")
	}
}

// TestAdversarial_ConsumedNotProduced exercises the producer-side
// check that catches an attempt to claim a material the upstream
// step didn't actually produce. BuildChainSidecar must refuse — a
// successful build there would yield an unverifiable sidecar that
// any honest verifier would reject anyway, but failing fast at
// produce time tells the operator immediately.
func TestAdversarial_ConsumedNotProduced(t *testing.T) {
	_, leaves, _ := buildSampleChain(t, "")
	// Reuse the real root so we get past the rebuilt-root check
	// and reach the consumed-material validation.
	preHashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, _ := LeafHashWithDomain("", l.Path, l.FileDigest)
		preHashes[i] = h
	}
	tree, _ := merkle.NewTree(preHashes)
	source := SourceStepRef{
		StepName:       "source",
		EnvelopeDigest: strings.Repeat("01", 32),
		MerkleRoot:     hex.EncodeToString(tree.Root()),
		TreeSize:       uint64(len(leaves)),
		Domain:         "",
	}
	fabricated := []ConsumedMaterial{
		{Path: "build/fabricated.bin", FileDigest: strings.Repeat("ff", 32)},
	}
	_, err := BuildChainSidecar(source, leaves, fabricated)
	if err == nil {
		t.Fatal("BuildChainSidecar must reject consumed materials absent from sourceLeaves")
	}
	if !strings.Contains(err.Error(), "NOT a product") {
		t.Errorf("error %q should mention 'NOT a product' for the operator's diagnosis", err)
	}
}

// TestAdversarial_DigestMismatch catches a producer-side attempt to
// substitute a different file under the same path: same upstream
// product path appears in consumed, but with a different digest.
// BuildChainSidecar must refuse — verifying this sidecar later
// would silently accept a substituted artifact.
func TestAdversarial_DigestMismatch(t *testing.T) {
	_, leaves, _ := buildSampleChain(t, "")
	// Rebuild the source ref so the root matches the leaves.
	preHashes := make([][]byte, len(leaves))
	for i, l := range leaves {
		h, _ := LeafHashWithDomain("", l.Path, l.FileDigest)
		preHashes[i] = h
	}
	tree, _ := merkle.NewTree(preHashes)
	source := SourceStepRef{
		StepName:       "source",
		EnvelopeDigest: strings.Repeat("01", 32),
		MerkleRoot:     hex.EncodeToString(tree.Root()),
		TreeSize:       uint64(len(leaves)),
		Domain:         "",
	}

	substituted := []ConsumedMaterial{
		{Path: "build/binary", FileDigest: strings.Repeat("ee", 32)}, // wrong digest
	}
	_, err := BuildChainSidecar(source, leaves, substituted)
	if err == nil {
		t.Fatal("BuildChainSidecar must reject digest mismatch on a consumed path")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error %q should explain the digest mismatch", err)
	}
}

// TestAdversarial_UnsortedSourceLeaves catches producer-side leaf-
// order tampering. The producer is supposed to ship leaves sorted
// by NormalizePath, with any reorder being a strong signal of
// tampering (or buggy producer code). BuildChainSidecar must refuse
// to build a sidecar against unsorted leaves.
func TestAdversarial_UnsortedSourceLeaves(t *testing.T) {
	leaves := []SidecarLeaf{
		{Path: "z.go", FileDigest: strings.Repeat("aa", 32)},
		{Path: "a.go", FileDigest: strings.Repeat("bb", 32)}, // out of order
	}
	source := SourceStepRef{
		StepName:       "source",
		EnvelopeDigest: strings.Repeat("01", 32),
		MerkleRoot:     strings.Repeat("00", 32),
		TreeSize:       uint64(len(leaves)),
		Domain:         "",
	}
	_, err := BuildChainSidecar(source, leaves, nil)
	if err == nil {
		t.Fatal("BuildChainSidecar must reject unsorted sourceLeaves")
	}
	if !strings.Contains(err.Error(), "not sorted") {
		t.Errorf("error %q should explicitly mention sort order", err)
	}
}

// TestAdversarial_EmptyEnvelopeDigest prevents tree-root-only
// binding. A sidecar whose SourceStep.EnvelopeDigest is empty
// could in principle verify against any signed envelope publishing
// the same Merkle root — closes threat-model D1 (cross-step proof
// replay). Both produce and verify paths must refuse.
func TestAdversarial_EmptyEnvelopeDigest(t *testing.T) {
	_, leaves, _ := buildSampleChain(t, "")
	source := SourceStepRef{
		StepName:       "source",
		EnvelopeDigest: "", // load-bearing field deliberately omitted
		MerkleRoot:     strings.Repeat("00", 32),
		TreeSize:       uint64(len(leaves)),
		Domain:         "",
	}
	_, err := BuildChainSidecar(source, leaves, nil)
	if err == nil {
		t.Fatal("BuildChainSidecar must reject empty EnvelopeDigest at produce time")
	}
	if !strings.Contains(err.Error(), "EnvelopeDigest") {
		t.Errorf("error %q should mention EnvelopeDigest", err)
	}

	// And the verify side, in case a sidecar was somehow constructed
	// out-of-band with an empty digest:
	sc := ChainSidecar{
		SchemaVersion: ChainSidecarSchemaVersion,
		SourceStep:    SourceStepRef{EnvelopeDigest: ""},
	}
	if err := VerifyChainSidecar(sc); err == nil {
		t.Fatal("VerifyChainSidecar must reject empty EnvelopeDigest at verify time")
	}
}

// TestAdversarial_LeafHashDomainPrefix verifies that the domain
// prefix actually changes the leaf hash — the test guards against
// a future refactor accidentally collapsing the domain into a no-op.
func TestAdversarial_LeafHashDomainPrefix(t *testing.T) {
	path := "build/binary"
	digest := strings.Repeat("aa", 32)

	empty, err := LeafHashWithDomain("", path, digest)
	if err != nil {
		t.Fatalf("empty-domain hash: %v", err)
	}
	withDomain, err := LeafHashWithDomain("rookery-product/v0.3", path, digest)
	if err != nil {
		t.Fatalf("domain hash: %v", err)
	}
	if hex.EncodeToString(empty) == hex.EncodeToString(withDomain) {
		t.Fatal("leaf hash domain prefix must change the output bytes")
	}

	// And the same domain at two different calls must produce
	// identical bytes (determinism).
	withDomain2, err := LeafHashWithDomain("rookery-product/v0.3", path, digest)
	if err != nil {
		t.Fatalf("domain hash 2: %v", err)
	}
	if hex.EncodeToString(withDomain) != hex.EncodeToString(withDomain2) {
		t.Fatal("LeafHashWithDomain must be deterministic")
	}
}

// ensure `fmt` import is used — keeps imports clean if future
// refactors move tests around without removing the import.
var _ = fmt.Sprintf
