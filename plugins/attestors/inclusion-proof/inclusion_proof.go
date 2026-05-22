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

// Package inclusionproof implements the inclusion-proof attestor used by
// `cilock prove` to commit, in a signed DSSE envelope, to the fact that a
// particular file (path + content digest) is a leaf of a v0.3 product or
// material Merkle tree.
//
// # Predicate shape
//
//	{
//	  "treeRoot":      "<hex sha256>",       // root of the product/material tree
//	  "leafIndex":     <uint64>,             // 0-based index of the leaf in the tree
//	  "leafPath":      "<string>",           // original file path (the predicate's leaf identity)
//	  "fileDigest":    "<hex sha256>",       // sha256 of the file's content
//	  "auditPath":     ["<hex sha256>", ...], // RFC 6962 inclusion proof, low-to-high
//	  "hashAlgorithm": "sha256",             // hardcoded
//	  "construction":  "RFC6962"             // hardcoded
//	}
//
// # Leaf encoding (binding contract with product/material v0.3 attestors)
//
// Every v0.3 product/material tree leaf is constructed as:
//
//	preHash := sha256(pathBytes || 0x00 || fileDigestBytes)
//
// where `fileDigestBytes` is the 32-byte SHA-256 of the file content (NOT
// the hex-string representation). The merkle wrapper then applies the
// RFC 6962 §2.1 0x00 leaf domain prefix internally, so the actual leaf
// hash committed to is `H(0x00 || preHash)`.
//
// The path bytes are the UTF-8 bytes of the **portable**, forward-slash
// form of the path that the producing attestor recorded in its sidecar
// (so the leaf hash is reproducible across operating systems). Callers of
// this attestor never need to know that detail — they just pass the same
// `leafPath` string the producing attestor wrote into its sidecar.
//
// The 0x00 separator between path and digest is critical: without framing,
// `("foo", digestA)` and `("fooX", digestA')` could collide.
//
// # Verification contract
//
// `treeSize` is NOT carried in this predicate — it lives in the
// producing attestor's predicate (the tree's own attestation). The caller
// of Verify() MUST supply the matching tree's `treeSize` AND its
// `merkleRoot`; this attestor refuses to make either trust decision on
// its own. That separation is deliberate: an inclusion proof alone is
// useless without a vetted tree to prove inclusion *into*.
//
// # Subjects / BackRefs
//
// The single Subject and BackRef is `name = "file:<LeafPath>"` with
// digest set `{sha256: FileDigest}`. The file digest is the narrow,
// low-cardinality, content-addressed spine that downstream subject-graph
// traversal uses to find this attestation when querying by artifact
// digest. We deliberately do NOT publish the tree root or any leaf-index
// derivative as a subject — those are not stable identifiers across
// recompilations and would explode the subject graph.
package inclusionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/invopop/jsonschema"
)

const (
	// Name is the attestor name used for CLI selection and registry lookup.
	Name = "inclusion-proof"

	// Type is the predicate URI emitted in the in-toto Statement.
	Type = "https://aflock.ai/attestations/inclusion-proof/v0.1"

	// RunType is PostProductRunType. This attestor is emitted by `cilock
	// prove` and NOT by `cilock run`'s collection — it is a standalone
	// signed predicate. The run-type is set to PostProductRunType because
	// proofs are logically a post-product activity: they only become
	// meaningful once the product (or material) Merkle tree has been
	// committed to. We reuse the existing run-type taxonomy rather than
	// inventing a new "prove" stage because adding a stage would expand
	// every attestor's ordering contract for a feature that doesn't
	// participate in `cilock run` at all.
	RunType = attestation.PostProductRunType

	// HashAlgorithm and Construction match the constants in
	// attestation/merkle. They are exported in the predicate so a verifier
	// can refuse anything that claims a different algorithm.
	HashAlgorithm = merkle.Hash
	Construction  = merkle.Construction
)

// Compile-time interface checks.
var (
	_ attestation.Attestor   = &Attestor{}
	_ attestation.Subjecter  = &Attestor{}
	_ attestation.BackReffer = &Attestor{}
)

// Attestor is the inclusion-proof predicate. It is constructed by
// `cilock prove` (see cilock/cli/prove.go) and never by a `cilock run`
// attestation flow — its Attest method is a no-op for that reason.
type Attestor struct {
	TreeRoot      string   `json:"treeRoot"`
	LeafIndex     uint64   `json:"leafIndex"`
	LeafPath      string   `json:"leafPath"`
	FileDigest    string   `json:"fileDigest"`
	AuditPath     []string `json:"auditPath"`
	HashAlgorithm string   `json:"hashAlgorithm"`
	Construction  string   `json:"construction"`
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// New returns a zero-valued Attestor with the constant fields populated.
// Callers (i.e. `cilock prove`) fill in TreeRoot/LeafIndex/LeafPath/
// FileDigest/AuditPath before signing.
func New() *Attestor {
	return &Attestor{
		HashAlgorithm: HashAlgorithm,
		Construction:  Construction,
	}
}

// Name returns the attestor name.
func (a *Attestor) Name() string { return Name }

// Type returns the predicate URI.
func (a *Attestor) Type() string { return Type }

// RunType returns the run-stage tag.
func (a *Attestor) RunType() attestation.RunType { return RunType }

// Schema returns the JSON schema for the predicate.
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&Attestor{})
}

// Attest is a no-op. The inclusion-proof attestor does not participate
// in `cilock run`; it is constructed and signed directly by `cilock
// prove`, which fills in the predicate fields from a sidecar before
// passing it to the DSSE signing path. Returning nil here makes the
// attestor harmless if a future caller accidentally schedules it in a
// run context.
func (a *Attestor) Attest(_ *attestation.AttestationContext) error {
	return nil
}

// MarshalJSON emits the predicate fields directly (no wrapping object).
func (a *Attestor) MarshalJSON() ([]byte, error) {
	type alias Attestor
	return json.Marshal((*alias)(a))
}

// UnmarshalJSON parses the predicate fields directly.
func (a *Attestor) UnmarshalJSON(data []byte) error {
	type alias Attestor
	return json.Unmarshal(data, (*alias)(a))
}

// fileDigestSubjectKey returns the subject/backref key for the file digest.
func (a *Attestor) fileDigestSubjectKey() string {
	return "file:" + a.LeafPath
}

// fileDigestSet returns the {sha256: FileDigest} digest set, or nil if
// the file digest is empty (an uninitialised Attestor).
func (a *Attestor) fileDigestSet() cryptoutil.DigestSet {
	if a.FileDigest == "" {
		return nil
	}
	return cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: hashSHA256()}: a.FileDigest,
	}
}

// Subjects returns the in-toto subject set: a single entry binding
// "file:<LeafPath>" to the file content digest. This is what makes a
// subject-graph BFS find this attestation when querying by file digest.
//
// Returning an empty map for an uninitialised Attestor matches the
// "no products → no subjects" pattern used elsewhere in the codebase
// and prevents bogus subjects from leaking into the in-toto statement
// when the attestor is loaded from JSON with a missing FileDigest.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	ds := a.fileDigestSet()
	if ds == nil {
		return map[string]cryptoutil.DigestSet{}
	}
	return map[string]cryptoutil.DigestSet{
		a.fileDigestSubjectKey(): ds,
	}
}

// BackRefs returns the file digest as the cross-attestation correlation
// spine. The same single entry as Subjects() — the file digest is a
// narrow, low-cardinality, content-addressed identifier and is the
// only field on this predicate that's safe to advertise as a
// subject-graph join key per the broader BackRef discipline.
func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	ds := a.fileDigestSet()
	if ds == nil {
		return map[string]cryptoutil.DigestSet{}
	}
	return map[string]cryptoutil.DigestSet{
		a.fileDigestSubjectKey(): ds,
	}
}

// Verify re-derives the leaf hash from (LeafPath, FileDigest) using the
// v0.3 leaf encoding documented at the top of this file, packs the
// AuditPath into [][]byte, and delegates root recomputation +
// constant-time comparison to attestation/merkle.VerifyInclusion.
//
// The caller MUST supply both treeSize and merkleRoot from a trusted
// source — typically the matching product or material v0.3 tree
// attestation's predicate. The inclusion-proof predicate intentionally
// does NOT carry treeSize; rebinding to whatever value the proof's own
// predicate claims would break the proof's CVE-2026-22703 defence
// (which depends on the tree-size constraint coming from outside the
// proof).
//
// On failure, the returned error is the merkle wrapper's descriptive
// error — including the "calculated root does not match expected root"
// sentinel when verification fails.
func (a *Attestor) Verify(treeSize uint64, merkleRoot []byte) error {
	if a.HashAlgorithm != HashAlgorithm {
		return fmt.Errorf("inclusion-proof: refusing predicate with hashAlgorithm=%q (only %q is supported)", a.HashAlgorithm, HashAlgorithm)
	}
	if a.Construction != Construction {
		return fmt.Errorf("inclusion-proof: refusing predicate with construction=%q (only %q is supported)", a.Construction, Construction)
	}

	leafHash, err := LeafHash(a.LeafPath, a.FileDigest)
	if err != nil {
		return fmt.Errorf("inclusion-proof: %w", err)
	}

	path, err := decodeAuditPath(a.AuditPath)
	if err != nil {
		return fmt.Errorf("inclusion-proof: %w", err)
	}

	// Sanity-check that the predicate's claimed root matches the caller's
	// expected root BEFORE the cryptographic check. This is a developer-
	// affordance: if a caller passes the wrong tree root, they get a
	// clear "predicate's claimed root does not match supplied root"
	// error instead of a generic merkle "calculated root does not match"
	// error. The cryptographic check below is still what actually
	// enforces correctness — this is just for diagnostics.
	if a.TreeRoot != "" {
		claimedRoot, decErr := hex.DecodeString(a.TreeRoot)
		if decErr != nil {
			return fmt.Errorf("inclusion-proof: predicate treeRoot is not hex: %w", decErr)
		}
		if len(claimedRoot) != len(merkleRoot) || !constantTimeEqual(claimedRoot, merkleRoot) {
			return errors.New("inclusion-proof: predicate's claimed treeRoot does not match expected root")
		}
	}

	return merkle.VerifyInclusion(treeSize, a.LeafIndex, leafHash, path, merkleRoot)
}

// LeafHash returns the v0.3 pre-hash for a (path, fileDigest) pair —
// i.e. sha256(path || 0x00 || rawFileDigest). The merkle wrapper applies
// the 0x00 leaf domain prefix on top of this when building or verifying
// the tree.
//
// fileDigestHex must be the lowercase hex encoding of a 32-byte SHA-256
// digest. The function rejects anything else loudly: a silently mis-
// encoded leaf would make the entire tree unverifiable.
//
// This function is exported because the matching v0.3 product/material
// attestors AND `cilock prove`'s sidecar reconstruction MUST produce
// byte-identical leaves. Centralising the encoding here is the only way
// to guarantee that across module boundaries.
func LeafHash(path, fileDigestHex string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("leaf path must not be empty")
	}
	digest, err := hex.DecodeString(fileDigestHex)
	if err != nil {
		return nil, fmt.Errorf("file digest must be hex: %w", err)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("file digest must decode to %d bytes (got %d)", sha256.Size, len(digest))
	}
	h := sha256.New()
	_, _ = h.Write([]byte(path))
	_, _ = h.Write([]byte{0x00})
	_, _ = h.Write(digest)
	return h.Sum(nil), nil
}

// decodeAuditPath converts the hex audit-path strings into the [][]byte
// shape that merkle.VerifyInclusion expects. It validates length on the
// way so a malformed proof element produces a clear error rather than
// surfacing as a downstream cryptographic mismatch.
func decodeAuditPath(in []string) ([][]byte, error) {
	out := make([][]byte, len(in))
	for i, s := range in {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("audit-path element %d is not hex: %w", i, err)
		}
		if len(b) != merkle.HashSize {
			return nil, fmt.Errorf("audit-path element %d has length %d, want %d", i, len(b), merkle.HashSize)
		}
		out[i] = b
	}
	return out, nil
}

// constantTimeEqual is a thin wrapper around crypto/subtle.ConstantTimeCompare
// kept here so callers don't need to know we're using the constant-time
// primitive — the call site reads naturally and the choice is documented.
func constantTimeEqual(a, b []byte) bool {
	return subtleEqual(a, b)
}
