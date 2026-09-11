// Copyright 2025 The Witness Contributors
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

package material

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
)

// newAttestedFixture builds a material attestor holding a real, self-consistent
// tree over the given (path -> digest) inputs, exactly as a completed walk
// would leave it. Using the production buildLeaves/BuildSidecar path (rather
// than hand-assembling leaves) is deliberate: a fixture that computed its own
// root would be able to agree with a broken implementation.
func newTreeFixture(t *testing.T, emitManifest bool, files map[string]string) *Attestor {
	t.Helper()
	side, err := inclusionproof.BuildSidecar(ManifestSource, files)
	if err != nil {
		t.Fatalf("build fixture sidecar: %v", err)
	}
	leaves := make([]MaterialLeaf, 0, len(side.Leaves))
	for _, lf := range side.Leaves {
		lh, err := inclusionproof.LeafHash(lf.Path, lf.FileDigest)
		if err != nil {
			t.Fatalf("leaf hash: %v", err)
		}
		leaves = append(leaves, MaterialLeaf{Path: lf.Path, FileDigest: lf.FileDigest, LeafHash: hex.EncodeToString(lh)})
	}
	a := New(WithManifest(emitManifest))
	a.MerkleRoot = side.MerkleRoot
	a.TreeSize = side.TreeSize
	a.HashAlgorithmField = HashAlgorithm
	a.ConstructionField = Construction
	a.setLeaves(leaves)
	return a
}

// newAttestedFixture is newTreeFixture plus the manifest reference, i.e. the
// state every Attest path leaves behind. Fails the test if the reference
// cannot be stamped — use newTreeFixture when that refusal is the subject.
func newAttestedFixture(t *testing.T, emitManifest bool, files map[string]string) *Attestor {
	t.Helper()
	a := newTreeFixture(t, emitManifest, files)
	if err := a.finishManifestRef(); err != nil {
		t.Fatalf("finishManifestRef: %v", err)
	}
	return a
}

// withManifestByteCeiling lowers the shared limit for one test so the REAL
// producer and consumer paths can be driven over it with a few kilobytes
// instead of half a gigabyte. Restored on cleanup; the package tests do not
// run in parallel.
func withManifestByteCeiling(t *testing.T, n int) {
	t.Helper()
	prev := manifestByteCeiling
	manifestByteCeiling = n
	t.Cleanup(func() { manifestByteCeiling = prev })
}

func digestOf(t *testing.T, s string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func fixtureFiles(t *testing.T) map[string]string {
	t.Helper()
	return map[string]string{
		"src/main.go": digestOf(t, "package main"),
		"go.mod":      digestOf(t, "module example"),
		"README.md":   digestOf(t, "hello"),
	}
}

// manifestBody returns the compact manifest predicate bytes for an attestor
// that opted in — i.e. exactly what its companion envelope would carry.
func manifestBody(t *testing.T, a *Attestor) []byte {
	t.Helper()
	companions := a.Companions()
	if len(companions) != 1 {
		t.Fatalf("expected exactly 1 companion, got %d", len(companions))
	}
	m, ok := companions[0].(*ManifestAttestor)
	if !ok {
		t.Fatalf("companion is %T, want *ManifestAttestor", companions[0])
	}
	body, _, err := manifestPredicateBytes(m.Sidecar())
	if err != nil {
		t.Fatalf("manifest predicate bytes: %v", err)
	}
	return body
}

// ── The additive predicate fields ───────────────────────────────────────────

// TestManifestFieldsAlwaysEmitted locks the ruling that manifestUploaded and
// manifest.digest are emitted UNCONDITIONALLY by a new-shape producer, including
// when the answer is "not published". A signed `false` is a different statement
// from an absent key, and only the former is distinguishable from a stripped
// field without a network round trip.
func TestManifestFieldsAlwaysEmitted(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		a := newAttestedFixture(t, optIn, fixtureFiles(t))
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got map[string]any
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		uploaded, present := got["manifestUploaded"]
		if !present {
			t.Fatalf("optIn=%v: manifestUploaded key is absent; it must ALWAYS be emitted", optIn)
		}
		if uploaded != optIn {
			t.Errorf("optIn=%v: manifestUploaded=%v, want %v", optIn, uploaded, optIn)
		}

		mf, present := got["manifest"].(map[string]any)
		if !present {
			t.Fatalf("optIn=%v: manifest reference is absent; it must be emitted even when not uploaded", optIn)
		}
		dg, _ := mf["digest"].(map[string]any)
		if dg["sha256"] == "" || dg["sha256"] == nil {
			t.Errorf("optIn=%v: manifest.digest.sha256 is empty", optIn)
		}
		if b, _ := mf["bytes"].(float64); b <= 0 {
			t.Errorf("optIn=%v: manifest.bytes=%v, want > 0", optIn, b)
		}
	}
}

// TestManifestDigestMatchesCompanionBytes proves the digest in the signed
// predicate actually addresses the companion the producer emits. This is the
// binding the whole design rests on; a digest that named nothing would look
// identical in every other test.
func TestManifestDigestMatchesCompanionBytes(t *testing.T) {
	a := newAttestedFixture(t, true, fixtureFiles(t))
	body := manifestBody(t, a)
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != a.Manifest.SHA256() {
		t.Fatalf("companion bytes hash to %s but the predicate references %s", got, a.Manifest.SHA256())
	}
	if a.Manifest.Bytes != len(body) {
		t.Errorf("manifest.bytes=%d, actual %d", a.Manifest.Bytes, len(body))
	}
}

// TestLeavesStillInlineByDefault is the guard on the ROLLOUT STEP, not on the
// mechanism: this change adds the manifest subsystem, and flipping the default
// is a deliberately separate change. If a later edit detaches the leaves by
// default, three shipped artifactsFrom policies start failing closed — this
// test is what makes that a red build instead of a production surprise.
func TestLeavesStillInlineByDefault(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		a := newAttestedFixture(t, optIn, fixtureFiles(t))
		raw, err := json.Marshal(a)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got struct {
			Leaves *[]MaterialLeaf `json:"leaves"`
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got.Leaves == nil {
			t.Fatalf("optIn=%v: leaves were OMITTED. Detaching by default is a separate, "+
				"sequenced change — the chain-consuming producers must opt in first.", optIn)
		}
		if len(*got.Leaves) != len(fixtureFiles(t)) {
			t.Errorf("optIn=%v: got %d inline leaves, want %d", optIn, len(*got.Leaves), len(fixtureFiles(t)))
		}
	}
}

// ── The consumer state table ────────────────────────────────────────────────

// TestManifestStateTable walks every row of the design's consumer state table
// and asserts the classification is decided from the SIGNED PREDICATE ALONE.
// That is what keeps a store outage from moving an attestation between "the
// producer withheld the leaves" and "the producer published and we cannot read
// them" — two states that must never be confused for each other.
func TestManifestStateTable(t *testing.T) {
	files := fixtureFiles(t)

	inline := newAttestedFixture(t, false, files)

	withheld := newAttestedFixture(t, false, files)
	withheld.leaves = nil

	published := newAttestedFixture(t, true, files)
	published.leaves = nil

	legacyLeafless := New()
	legacyLeafless.MerkleRoot = inline.MerkleRoot

	legacyInline := newAttestedFixture(t, false, files)
	legacyInline.ManifestUploaded = nil
	legacyInline.Manifest = nil

	cases := []struct {
		name      string
		a         *Attestor
		want      ManifestState
		pending   bool
		withheldB bool
	}{
		{"inline leaves present", inline, ManifestInline, false, false},
		{"manifestUploaded=false", withheld, ManifestNotPublished, false, true},
		{"manifestUploaded=true", published, ManifestPublished, true, false},
		{"key absent, leaves absent", legacyLeafless, ManifestLegacyLeafless, false, false},
		{"key absent, leaves present", legacyInline, ManifestInline, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.ManifestState(); got != tc.want {
				t.Errorf("ManifestState()=%v, want %v", got, tc.want)
			}
			if got := tc.a.ManifestPending(); got != tc.pending {
				t.Errorf("ManifestPending()=%v, want %v", got, tc.pending)
			}
			if got := tc.a.ManifestWithheld(); got != tc.withheldB {
				t.Errorf("ManifestWithheld()=%v, want %v", got, tc.withheldB)
			}
		})
	}
}

// TestAbsentKeyIsNotFalse is called out separately because collapsing nil into
// false is the single most tempting simplification here, and it is wrong: an
// absent key and a stripped key are byte-identical, so reading absence as a
// signed "false" would let a stripped field masquerade as a producer decision.
func TestAbsentKeyIsNotFalse(t *testing.T) {
	legacy := New()
	legacy.MerkleRoot = "ab" // leaf-less legacy shape
	if legacy.ManifestWithheld() {
		t.Fatal("an ABSENT manifestUploaded key was read as a signed false")
	}
	if legacy.ManifestState() != ManifestLegacyLeafless {
		t.Fatalf("state=%v, want ManifestLegacyLeafless", legacy.ManifestState())
	}
}

// TestUnmarshalDoesNotFabricateManifestClaim guards the round-trip: decoding a
// pre-change predicate and re-encoding it must not invent fields the signer
// never committed to.
func TestUnmarshalDoesNotFabricateManifestClaim(t *testing.T) {
	legacy := []byte(`{"merkleRoot":"aa","treeSize":1,"hashAlgorithm":"sha256","construction":"RFC6962","leaves":[{"path":"a","fileDigest":"bb","leafHash":"cc"}]}`)
	var a Attestor
	if err := json.Unmarshal(legacy, &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if a.ManifestUploaded != nil {
		t.Errorf("decoding a legacy predicate invented manifestUploaded=%v", *a.ManifestUploaded)
	}
	if a.Manifest != nil {
		t.Errorf("decoding a legacy predicate invented a manifest reference")
	}
	out, err := json.Marshal(&a)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(out, []byte("manifestUploaded")) || bytes.Contains(out, []byte(`"manifest"`)) {
		t.Errorf("re-encoding a legacy predicate emitted manifest fields: %s", out)
	}
}

// ── Hydration: not-found and root-mismatch must stay DISTINCT ───────────────

func TestHydrateFromManifestSucceeds(t *testing.T) {
	files := fixtureFiles(t)
	producer := newAttestedFixture(t, true, files)
	body := manifestBody(t, producer)

	// The consumer's view: same signed scalars, leaves detached.
	consumer := newAttestedFixture(t, true, files)
	consumer.leaves = nil
	consumer.materials = nil

	if !consumer.ManifestPending() {
		t.Fatal("consumer should be pending a manifest")
	}
	if err := consumer.HydrateFromManifest(body); err != nil {
		t.Fatalf("hydrate: %v", err)
	}
	if !consumer.HasInlineLeaves() {
		t.Error("after hydration the leaves should be present")
	}
	if got := len(consumer.Materials()); got != len(files) {
		t.Errorf("Materials() has %d entries, want %d", got, len(files))
	}
	if err := consumer.VerifyInlineLeaves(); err != nil {
		t.Errorf("hydrated leaves do not reconstruct the signed root: %v", err)
	}
}

// TestHydrateDistinguishesFailureModes is the acceptance bar's "not found and
// root mismatch as DISTINCT errors" requirement. Collapsing them into one
// failure would file "someone signed a root that does not match its leaves" —
// a real integrity finding — as if it were a missing object.
func TestHydrateDistinguishesFailureModes(t *testing.T) {
	files := fixtureFiles(t)
	producer := newAttestedFixture(t, true, files)
	good := manifestBody(t, producer)

	// A well-formed manifest over DIFFERENT inputs: it parses, and it is
	// internally consistent, but it belongs to another tree.
	otherFiles := map[string]string{"other.go": digestOf(t, "different")}
	otherProducer := newAttestedFixture(t, true, otherFiles)
	otherBody := manifestBody(t, otherProducer)

	cases := []struct {
		name string
		body []byte
		want error
	}{
		{
			// Wrong bytes for the referenced digest. Caught by the digest gate
			// before anything is parsed.
			name: "digest mismatch",
			body: otherBody,
			want: ErrMaterialManifestMismatch,
		},
		{
			name: "not JSON",
			body: []byte("this is not json"),
			want: ErrMaterialManifestUnreadable,
		},
		{
			name: "empty",
			body: []byte(""),
			want: ErrMaterialManifestUnreadable,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			consumer := newAttestedFixture(t, true, files)
			consumer.leaves = nil
			err := consumer.HydrateFromManifest(tc.body)
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want an error wrapping %v", err, tc.want)
			}
			if consumer.HasInlineLeaves() {
				t.Error("a FAILED hydration populated the leaves anyway")
			}
		})
	}

	// Root mismatch specifically: bytes that DO hash to the referenced digest
	// but whose tree does not fold to the signed root. Constructed by pointing
	// a consumer's signed root somewhere else while keeping the reference.
	t.Run("root mismatch", func(t *testing.T) {
		consumer := newAttestedFixture(t, true, files)
		consumer.leaves = nil
		consumer.MerkleRoot = strings.Repeat("0", 64)

		err := consumer.HydrateFromManifest(good)
		if err == nil {
			t.Fatal("a manifest whose leaves rebuild a DIFFERENT root was accepted")
		}
		if !errors.Is(err, ErrMaterialManifestMismatch) {
			t.Fatalf("got %v, want ErrMaterialManifestMismatch", err)
		}
		if errors.Is(err, ErrMaterialManifestUnreadable) {
			t.Fatal("a root MISMATCH was reported as merely unreadable; the two must stay distinct")
		}
		if consumer.HasInlineLeaves() {
			t.Error("a failed hydration populated the leaves anyway")
		}
	})

	// Oversized bodies are refused BEFORE they are compacted, hashed or parsed:
	// the signed reference records the manifest's compact size, and a body an
	// order of magnitude past it cannot be the referenced manifest. Without
	// this, the inline-leaf cap applied by the policy engine was bypassed for
	// the detached path — a verifier could be handed unbounded work by
	// whatever served the manifest bytes.
	t.Run("oversized body is refused before any work", func(t *testing.T) {
		consumer := newAttestedFixture(t, true, files)
		consumer.leaves = nil
		limit := manifestByteLimit(consumer.Manifest.Bytes)
		if limit < len(good) {
			t.Fatalf("limit %d must admit the real manifest of %d bytes", limit, len(good))
		}
		// The real manifest padded past the limit with whitespace: it would
		// STILL compact and hash to the signed digest, which is exactly why the
		// bound has to be on the bytes handed in, not on what they decode to.
		padded := append([]byte(nil), good...)
		padded = append(padded, bytes.Repeat([]byte(" "), limit-len(good)+1)...)
		err := consumer.HydrateFromManifest(padded)
		if !errors.Is(err, ErrMaterialManifestMismatch) {
			t.Fatalf("a body over the signed size bound must be refused as a mismatch, got %v", err)
		}
		if consumer.HasInlineLeaves() {
			t.Error("a refused hydration populated the leaves anyway")
		}
		// Just inside the bound, the same padded body hydrates: the limit is a
		// ceiling on work, not a second digest check.
		consumer = newAttestedFixture(t, true, files)
		consumer.leaves = nil
		inside := append([]byte(nil), good...)
		inside = append(inside, bytes.Repeat([]byte(" "), limit-len(good))...)
		if err := consumer.HydrateFromManifest(inside); err != nil {
			t.Fatalf("a whitespace-padded body inside the bound must still hydrate: %v", err)
		}
	})

	// A manifest that CLAIMS more leaves than any tree this package builds is
	// refused by the sidecar reader before a tree is attempted — the same
	// inclusionproof.MaxLeaves the inline path enforces.
	t.Run("more leaves than MaxLeaves is refused", func(t *testing.T) {
		consumer := newAttestedFixture(t, true, files)
		consumer.leaves = nil
		consumer.TreeSize = inclusionproof.MaxLeaves + 1
		consumer.Manifest.Bytes = 0 // no signed size: only the leaf ceiling applies
		oversized := []byte(fmt.Sprintf(`{"merkleRoot":%q,"treeSize":%d,"hashAlgorithm":"sha256","construction":"rfc6962","leaves":[]}`,
			consumer.MerkleRoot, inclusionproof.MaxLeaves+1))
		sum := sha256.Sum256(oversized)
		consumer.Manifest.Digest = map[string]string{"sha256": hex.EncodeToString(sum[:])}
		err := consumer.HydrateFromManifest(oversized)
		if err == nil {
			t.Fatal("a manifest claiming more than MaxLeaves leaves was accepted")
		}
		if !errors.Is(err, ErrMaterialManifestUnreadable) && !errors.Is(err, ErrMaterialManifestMismatch) {
			t.Fatalf("got %v, want a hydration error", err)
		}
		if consumer.HasInlineLeaves() {
			t.Error("a refused hydration populated the leaves anyway")
		}
	})

	// And the not-found case is not an error from this method at all — it is the
	// caller's, and it must not be reachable as "mismatch".
	t.Run("not published is not a hydration failure", func(t *testing.T) {
		withheld := newAttestedFixture(t, false, files)
		withheld.leaves = nil
		if withheld.ManifestPending() {
			t.Fatal("a withheld manifest must never trigger a resolution attempt")
		}
	})
}

// TestHydrationIsWhitespaceInsensitive: the producer hashes the compact
// encoding, so a pretty-printing intermediary must not break the binding.
func TestHydrationIsWhitespaceInsensitive(t *testing.T) {
	files := fixtureFiles(t)
	producer := newAttestedFixture(t, true, files)
	compact := manifestBody(t, producer)

	var indented bytes.Buffer
	if err := json.Indent(&indented, compact, "", "    "); err != nil {
		t.Fatalf("indent: %v", err)
	}
	if bytes.Equal(indented.Bytes(), compact) {
		t.Fatal("indent produced identical bytes; the test is not exercising what it claims")
	}

	consumer := newAttestedFixture(t, true, files)
	consumer.leaves = nil
	if err := consumer.HydrateFromManifest(indented.Bytes()); err != nil {
		t.Fatalf("a re-indented manifest was rejected: %v", err)
	}
}

// ── The companion envelope ──────────────────────────────────────────────────

// TestCompanionOnlyWhenOptedIn: the default must leave the workflow untouched.
func TestCompanionOnlyWhenOptedIn(t *testing.T) {
	if got := newAttestedFixture(t, false, fixtureFiles(t)).Companions(); len(got) != 0 {
		t.Errorf("default run emitted %d companions, want 0", len(got))
	}
	if got := newAttestedFixture(t, true, fixtureFiles(t)).Companions(); len(got) != 1 {
		t.Errorf("opted-in run emitted %d companions, want 1", len(got))
	}
}

// TestCompanionCarriesOnlyItsOwnSubject locks the subject rule. If a companion
// ever inherited the collection's commit subject it would start appearing in
// commit-keyed lookups and consume the small number of envelope-examination
// slots the push gate spends per sha — the exact cost this design removes.
func TestCompanionCarriesOnlyItsOwnSubject(t *testing.T) {
	a := newAttestedFixture(t, true, fixtureFiles(t))
	m, ok := a.Companions()[0].(*ManifestAttestor)
	if !ok {
		t.Fatal("companion is not a *ManifestAttestor")
	}
	subs := m.Subjects()
	if len(subs) != 1 {
		t.Fatalf("companion has %d subjects, want exactly 1", len(subs))
	}
	ds, present := subs[TreeSubjectName]
	if !present {
		t.Fatalf("companion subject is not %q: %v", TreeSubjectName, subs)
	}
	for _, root := range ds {
		if root != a.MerkleRoot {
			t.Errorf("companion subject digest %s != material root %s", root, a.MerkleRoot)
		}
	}
}

// TestManifestAttestorRefusesDirectAttest: the manifest is derived from a
// completed material walk, never collected on its own. A registered producer
// would let a caller request an empty manifest with no tree behind it.
func TestManifestAttestorRefusesDirectAttest(t *testing.T) {
	if err := (&ManifestAttestor{}).Attest(nil); err == nil {
		t.Fatal("ManifestAttestor.Attest should refuse")
	}
}

// TestManifestTypeIsANewFamily is the guard on the no-version-bump ruling. The
// platform's drift check derives an attestor family by splitting at the last
// "/", and fails when a TRACKED family gains an unknown version. Keeping this
// a new family (material-manifest) rather than material/v0.4 is what makes the
// change additive for every exact-URI consumer.
func TestManifestTypeIsANewFamily(t *testing.T) {
	if !strings.HasPrefix(ManifestType, "https://aflock.ai/attestations/material-manifest/") {
		t.Fatalf("ManifestType=%q is not in the material-manifest family", ManifestType)
	}
	if strings.HasPrefix(ManifestType, "https://aflock.ai/attestations/material/") {
		t.Fatalf("ManifestType=%q is a new VERSION of the material family; it must be a new FAMILY", ManifestType)
	}
	if Type != "https://aflock.ai/attestations/material/v0.3" {
		t.Fatalf("the material predicate version moved to %q; this change is additive on v0.3 by ruling", Type)
	}
}

// TestManifestSatisfiesInterfaces keeps the workflow and engine hooks honest.
func TestManifestSatisfiesInterfaces(t *testing.T) {
	var a any = New()
	if _, ok := a.(attestation.CompanionExporter); !ok {
		t.Error("material.Attestor does not implement attestation.CompanionExporter")
	}
	if _, ok := a.(attestation.CompanionTyper); !ok {
		t.Error("material.Attestor does not implement attestation.CompanionTyper (the catalog cannot describe its companion)")
	}
	if _, ok := a.(attestation.ManifestHydrator); !ok {
		t.Error("material.Attestor does not implement attestation.ManifestHydrator")
	}
	if _, ok := a.(attestation.ManifestWithholder); !ok {
		t.Error("material.Attestor does not implement attestation.ManifestWithholder")
	}
	var m any = &ManifestAttestor{}
	if _, ok := m.(attestation.Attestor); !ok {
		t.Error("ManifestAttestor does not implement attestation.Attestor")
	}
	if _, ok := m.(attestation.Subjecter); !ok {
		t.Error("ManifestAttestor does not implement attestation.Subjecter")
	}
}

// ── The shared byte limit ───────────────────────────────────────────────────

// TestManifestByteLimitIsTheSharedConstant pins the wiring: the consumer's
// ceiling and the producer's refusal are BOTH inclusionproof.MaxManifestBytes,
// checked by value so the 512 MiB path is proven without allocating it. The
// behavioural test below drives the same code at a small ceiling.
func TestManifestByteLimitIsTheSharedConstant(t *testing.T) {
	if manifestByteCeiling != inclusionproof.MaxManifestBytes {
		t.Fatalf("manifestByteCeiling=%d is not inclusionproof.MaxManifestBytes=%d", manifestByteCeiling, inclusionproof.MaxManifestBytes)
	}
	if got := manifestByteLimit(0); got != inclusionproof.MaxManifestBytes {
		t.Fatalf("a reference with no signed size must get exactly the shared ceiling, got %d", got)
	}
	if got := manifestByteLimit(inclusionproof.MaxManifestBytes); got != inclusionproof.MaxManifestBytes {
		t.Fatalf("whitespace slack must never lift the limit above the shared ceiling, got %d", got)
	}
	if err := checkManifestSize(inclusionproof.MaxManifestBytes); err != nil {
		t.Fatalf("a manifest exactly at the limit must be publishable: %v", err)
	}
	err := checkManifestSize(inclusionproof.MaxManifestBytes + 1)
	if !errors.Is(err, ErrMaterialManifestTooLarge) {
		t.Fatalf("one byte over the limit must be refused with ErrMaterialManifestTooLarge, got %v", err)
	}
	if !strings.Contains(err.Error(), "MaxManifestBytes") || !strings.Contains(err.Error(), fmt.Sprint(inclusionproof.MaxManifestBytes)) {
		t.Fatalf("the refusal must name the limit and its value so an operator can act on it: %v", err)
	}
}

// TestManifestSizeLimitIsEnforcedOnBothSides is the round trip Codex asked
// for, with LONG paths: a tree whose leaves are few but whose paths are
// hundreds of bytes each, so the manifest's size is set by path length, not
// by leaf count (the case a per-leaf heuristic mis-sized). Its real compact
// size becomes the ceiling: at the limit the producer publishes and the
// consumer hydrates; one byte under the size, the producer refuses with the
// named error and publishes nothing, and a consumer handed the same bytes
// refuses with the same error. A producer that is not publishing is never
// size-checked.
func TestManifestSizeLimitIsEnforcedOnBothSides(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < 8; i++ {
		files[fmt.Sprintf("%s%02d.go", strings.Repeat("a-rather-long-directory-name/", 12), i)] = digestOf(t, fmt.Sprintf("file-%d", i))
	}
	size := len(manifestBody(t, newAttestedFixture(t, true, files)))
	if size < 2048 {
		t.Fatalf("fixture too small (%d bytes) to be path-dominated; lengthen the paths", size)
	}

	t.Run("at the limit round-trips", func(t *testing.T) {
		withManifestByteCeiling(t, size)
		producer := newTreeFixture(t, true, files)
		if err := producer.finishManifestRef(); err != nil {
			t.Fatalf("a manifest exactly at the limit must be publishable: %v", err)
		}
		body := manifestBody(t, producer)
		if len(body) != size {
			t.Fatalf("published %d bytes, expected %d", len(body), size)
		}
		consumer := newAttestedFixture(t, true, files)
		consumer.leaves = nil
		if err := consumer.HydrateFromManifest(body); err != nil {
			t.Fatalf("a manifest at the limit must hydrate: %v", err)
		}
		if !consumer.HasInlineLeaves() || len(consumer.leaves) != len(files) {
			t.Fatalf("hydration left %d leaves, want %d", len(consumer.leaves), len(files))
		}
	})

	t.Run("over the limit: producer refuses and publishes nothing", func(t *testing.T) {
		withManifestByteCeiling(t, size-1)
		producer := newTreeFixture(t, true, files)
		err := producer.finishManifestRef()
		if !errors.Is(err, ErrMaterialManifestTooLarge) {
			t.Fatalf("producer must refuse with ErrMaterialManifestTooLarge, got %v", err)
		}
		if !strings.Contains(err.Error(), "MaxManifestBytes") {
			t.Fatalf("refusal must name the limit: %v", err)
		}
		if producer.ManifestUploaded != nil || producer.Manifest != nil {
			t.Fatal("a refused publication must not stamp a manifestUploaded/manifest reference")
		}
		if got := producer.Companions(); got != nil {
			t.Fatalf("Companions() published %d envelope(s) past the limit", len(got))
		}
	})

	t.Run("over the limit: consumer refuses identically", func(t *testing.T) {
		// Mint the reference at the production ceiling, then read it at the
		// small one — the shape of a consumer whose limit is lower than the
		// bytes it was handed.
		body := manifestBody(t, newAttestedFixture(t, true, files))
		consumer := newAttestedFixture(t, true, files)
		consumer.leaves = nil
		withManifestByteCeiling(t, size-1)
		err := consumer.HydrateFromManifest(body)
		if !errors.Is(err, ErrMaterialManifestTooLarge) {
			t.Fatalf("consumer must refuse with ErrMaterialManifestTooLarge, got %v", err)
		}
		if !errors.Is(err, ErrMaterialManifestMismatch) {
			t.Fatalf("an oversized body is still state (c) — must also wrap ErrMaterialManifestMismatch, got %v", err)
		}
		if consumer.HasInlineLeaves() {
			t.Error("a refused hydration populated the leaves anyway")
		}
	})

	t.Run("a withheld manifest is not size-checked", func(t *testing.T) {
		withManifestByteCeiling(t, size-1)
		withheld := newTreeFixture(t, false, files)
		if err := withheld.finishManifestRef(); err != nil {
			t.Fatalf("a producer that is not publishing must still stamp its digest reference: %v", err)
		}
		if withheld.ManifestUploaded == nil || *withheld.ManifestUploaded || withheld.Manifest.SHA256() == "" {
			t.Fatal("withheld producer must sign manifestUploaded=false with the digest reference")
		}
		if got := withheld.Companions(); got != nil {
			t.Fatal("a withheld producer must not publish a companion")
		}
	})
}

// TestCompanionTypesMatchWhatCompanionsEmit keeps the static declaration the
// catalog reads (CompanionTypes) equal to what a run actually signs
// (Companions()[i].Type()), and distinct from the attestor's own type.
func TestCompanionTypesMatchWhatCompanionsEmit(t *testing.T) {
	declared := New().CompanionTypes()
	if len(declared) != 1 || declared[0] != ManifestType {
		t.Fatalf("CompanionTypes() = %v, want exactly [%s]", declared, ManifestType)
	}
	if declared[0] == Type {
		t.Fatal("a companion type must not be the attestor's own predicate type")
	}
	producer := newAttestedFixture(t, true, fixtureFiles(t))
	companions := producer.Companions()
	if len(companions) != 1 {
		t.Fatalf("got %d companions, want 1", len(companions))
	}
	if got := companions[0].Type(); got != declared[0] {
		t.Fatalf("the emitted companion is %q but CompanionTypes() declares %q — the catalog would describe evidence that is never signed", got, declared[0])
	}
}

// ── Reuse and round-trip of a decoded predicate ─────────────────────────────

// detachedBytes returns the signed predicate of an opted-in producer with the
// "leaves" key REMOVED (the detached wire shape) and, when withheld, with
// manifestUploaded rewritten to false.
func detachedBytes(t *testing.T, files map[string]string, withheld bool) []byte {
	t.Helper()
	raw, err := json.Marshal(newAttestedFixture(t, !withheld, files))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(m, "leaves")
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return out
}

// TestUnmarshalResetsDerivedStateBetweenDecodes: decoding into an Attestor
// that already holds a decoded predicate must leave NOTHING of the previous
// one behind — in particular the derived materials map, which is exactly what
// artifactsFrom reads (policy.go: `downstream.Materials()`). An inline
// predicate followed by a detached or withheld one into the same Attestor
// must yield empty materials; the reverse order must yield the inline set.
func TestUnmarshalResetsDerivedStateBetweenDecodes(t *testing.T) {
	files := fixtureFiles(t)
	inline, err := json.Marshal(newAttestedFixture(t, false, files))
	if err != nil {
		t.Fatalf("marshal inline: %v", err)
	}

	for _, tc := range []struct {
		name      string
		second    []byte
		wantState ManifestState
	}{
		{name: "inline then detached", second: detachedBytes(t, files, false), wantState: ManifestPublished},
		{name: "inline then withheld", second: detachedBytes(t, files, true), wantState: ManifestNotPublished},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var a Attestor
			if err := json.Unmarshal(inline, &a); err != nil {
				t.Fatalf("decode inline: %v", err)
			}
			if len(a.Materials()) != len(files) || !a.HasInlineLeaves() {
				t.Fatalf("inline decode should hydrate %d materials, got %d", len(files), len(a.Materials()))
			}
			if err := json.Unmarshal(tc.second, &a); err != nil {
				t.Fatalf("decode second: %v", err)
			}
			if got := a.Materials(); len(got) != 0 {
				t.Fatalf("a leaf-less predicate decoded into a reused Attestor carried %d stale materials from the previous decode: %v — artifactsFrom would be satisfied by digests this predicate never signed", len(got), got)
			}
			if a.HasInlineLeaves() {
				t.Fatal("a leaf-less predicate reported inline leaves after a reused decode")
			}
			if got := a.ManifestState(); got != tc.wantState {
				t.Fatalf("ManifestState = %v, want %v", got, tc.wantState)
			}
		})
	}

	t.Run("detached then inline", func(t *testing.T) {
		var a Attestor
		if err := json.Unmarshal(detachedBytes(t, files, false), &a); err != nil {
			t.Fatalf("decode detached: %v", err)
		}
		if len(a.Materials()) != 0 || a.HasInlineLeaves() {
			t.Fatal("detached decode must start with no materials")
		}
		if err := json.Unmarshal(inline, &a); err != nil {
			t.Fatalf("decode inline: %v", err)
		}
		if got := len(a.Materials()); got != len(files) {
			t.Fatalf("inline decode after a detached one hydrated %d materials, want %d", got, len(files))
		}
		if a.ManifestState() != ManifestInline {
			t.Fatalf("ManifestState = %v, want ManifestInline", a.ManifestState())
		}
	})
}

// TestDecodedLeafPresenceRoundTrips pins the wire shape across a decode and
// re-encode: an ABSENT "leaves" key stays absent, and a PRESENT-EMPTY one
// stays "leaves":[]. The CLI (bundleInnerPredicate.leavesInline, the bridge)
// and the engine (HasInlineLeaves) all decide the three-state manifest
// question from that key's presence, so a re-marshalled detached predicate
// that grew "leaves":[] would become an authoritative-empty inline one: it
// would skip manifest resolution and silently drop every edge the manifest
// carries.
func TestDecodedLeafPresenceRoundTrips(t *testing.T) {
	files := fixtureFiles(t)

	t.Run("absent stays absent", func(t *testing.T) {
		var a Attestor
		if err := json.Unmarshal(detachedBytes(t, files, false), &a); err != nil {
			t.Fatalf("decode: %v", err)
		}
		raw, err := json.Marshal(&a)
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, present := m["leaves"]; present {
			t.Fatalf("a decoded detached predicate re-marshalled WITH a leaves key: %s", raw)
		}
		var b Attestor
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatalf("decode round-tripped: %v", err)
		}
		if b.HasInlineLeaves() || b.ManifestState() != ManifestPublished || !b.ManifestPending() {
			t.Fatalf("round-tripped detached predicate changed its three-state decision: inline=%v state=%v pending=%v", b.HasInlineLeaves(), b.ManifestState(), b.ManifestPending())
		}
	})

	t.Run("present-empty stays present", func(t *testing.T) {
		var a Attestor
		if err := json.Unmarshal([]byte(`{"merkleRoot":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","treeSize":0,"hashAlgorithm":"sha256","construction":"RFC6962","leaves":[]}`), &a); err != nil {
			t.Fatalf("decode: %v", err)
		}
		raw, err := json.Marshal(&a)
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		if !strings.Contains(string(raw), `"leaves":[]`) {
			t.Fatalf("a decoded present-empty leaf set did not survive re-marshalling: %s", raw)
		}
		var b Attestor
		if err := json.Unmarshal(raw, &b); err != nil {
			t.Fatalf("decode round-tripped: %v", err)
		}
		if !b.HasInlineLeaves() || b.ManifestState() != ManifestInline {
			t.Fatalf("round-tripped present-empty predicate is no longer inline: inline=%v state=%v", b.HasInlineLeaves(), b.ManifestState())
		}
	})
}
