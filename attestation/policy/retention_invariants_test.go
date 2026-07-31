// Copyright 2026 The Archivista Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package policy

// Retention-invariant suite: the regression gate for the policy-verify memory
// work (#7572). The prod-corpus harness (judge-api/pkg/policybench) pins ONE
// (policy, corpus) pair whose verdict is FAIL; these scenarios pin the
// directions that pair cannot see, each as a full end-to-end Policy.Verify
// over DSSE-signed envelopes through a VerifiedSource:
//
//	A. a PASS verdict
//	B. depth>=1 BackRef expansion driving the cross-depth MERGE/dedup path
//	   (passedCollectionKey)
//	C. cross-step Rego consuming an upstream PASSED collection's attestor
//	   content (buildStepContext)
//	D. an artifactsFrom chain re-reading passed collections' inline-leaf
//	   materials/products post-gate (verifyCollectionArtifacts) — with both
//	   the passing chain and a digest-mismatch failure pinned
//
// Each scenario's outcome is reduced to a deterministic fingerprint (the
// run-specific key ID is normalized out) and compared against a golden
// captured from UNMODIFIED verification code. Any retention change must
// reproduce every golden bit-identically: these scenarios are built to FAIL
// if a passed collection's attestor content, materials, back-refs, or merge
// identity is dropped without an equivalent rehydration path.
//
// Scenarios C and D are the DISCRIMINATING tests for the post-decision
// re-reader contracts: C's Rego rule denies unless the upstream attestor's
// content is present in input.steps; D's chain fails "leaf-less" unless the
// upstream/downstream materials rehydrate. Skipping rehydration flips those
// verdicts — it cannot sail through.

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Golden fingerprints live in testdata/retention_goldens.json — a DATA-DRIVEN
// test set keyed by scenario name, designed to grow to thousands of entries.
// Each was captured from unmodified verification code (identical across two
// independent runs). A scenario absent from the file is in CAPTURE mode: the
// test logs the computed fingerprint instead of comparing, so adding a
// scenario is: write the test, run once on unmodified code, commit the
// logged value into the JSON.
const (
	goldenInvariantPass      = "A-pass"
	goldenInvariantMerge     = "B-merge"
	goldenInvariantRego      = "C-rego"
	goldenInvariantArtifacts = "D-artifacts"
	goldenInvariantArtMismat = "D-mismatch"
)

var (
	invGoldensOnce sync.Once
	invGoldens     map[string]string
)

// loadInvGoldens loads the golden set once per test binary.
func loadInvGoldens(t *testing.T) map[string]string {
	t.Helper()
	invGoldensOnce.Do(func() {
		raw, err := os.ReadFile(filepath.Join("testdata", "retention_goldens.json"))
		if err != nil {
			t.Fatalf("read retention goldens: %v", err)
		}
		var doc struct {
			Goldens map[string]string `json:"goldens"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse retention goldens: %v", err)
		}
		invGoldens = doc.Goldens
	})
	return invGoldens
}

// Deterministic subject digests (arbitrary fixed 64-hex values).
const (
	invDigestSeed    = "1111111111111111111111111111111111111111111111111111111111111111"
	invDigestBackRef = "2222222222222222222222222222222222222222222222222222222222222222"
	invDigestFile    = "3333333333333333333333333333333333333333333333333333333333333333"
	invDigestWrong   = "4444444444444444444444444444444444444444444444444444444444444444"
)

const (
	invAttType     = "https://test.invariant/att/v0.1"
	invMatProdType = "https://test.invariant/matprod/v0.1"
)

// invFixture carries the per-run RSA key. The key is generated fresh per run;
// determinism of the fingerprints comes from normalizing the key ID out.
type invFixture struct {
	signer   cryptoutil.Signer
	verifier cryptoutil.Verifier
	keyID    string
	pubPEM   string
}

func newInvFixture(t *testing.T) *invFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signer := cryptoutil.NewRSASigner(priv, crypto.SHA256)
	verifier := cryptoutil.NewRSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	pemBytes, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
	require.NoError(t, err)
	return &invFixture{signer: signer, verifier: verifier, keyID: keyID, pubPEM: string(pemBytes)}
}

func (f *invFixture) functionary() Functionary {
	return Functionary{Type: "publickey", PublicKeyID: f.keyID}
}

func (f *invFixture) publicKeys() map[string]PublicKey {
	return map[string]PublicKey{f.keyID: {KeyID: f.keyID, Key: []byte(f.pubPEM)}}
}

// invMatProdAttestor is a registered, JSON-round-trippable attestor carrying
// inline-leaf materials/products, so the artifactsFrom chain runs end to end
// from DECODED envelopes (Materials()/Products() require typed attestors; a
// RawAttestation fallback implements neither).
type invMatProdAttestor struct {
	Mats   map[string]cryptoutil.DigestSet `json:"materials,omitempty"`
	Prods  map[string]attestation.Product  `json:"products,omitempty"`
	Inline bool                            `json:"inline"`
}

func (a *invMatProdAttestor) Name() string                                 { return invMatProdType }
func (a *invMatProdAttestor) Type() string                                 { return invMatProdType }
func (a *invMatProdAttestor) RunType() attestation.RunType                 { return attestation.PostProductRunType }
func (a *invMatProdAttestor) Schema() *jsonschema.Schema                   { return nil }
func (a *invMatProdAttestor) Attest(*attestation.AttestationContext) error { return nil }
func (a *invMatProdAttestor) Materials() map[string]cryptoutil.DigestSet   { return a.Mats }
func (a *invMatProdAttestor) Products() map[string]attestation.Product     { return a.Prods }
func (a *invMatProdAttestor) VerifyInlineLeaves() error                    { return nil }
func (a *invMatProdAttestor) HasInlineLeaves() bool                        { return a.Inline }

var invRegisterOnce sync.Once

func registerInvMatProd() {
	invRegisterOnce.Do(func() {
		attestation.RegisterAttestation(invMatProdType, invMatProdType, attestation.PostProductRunType,
			func() attestation.Attestor { return &invMatProdAttestor{} })
	})
}

// invCollection signs a collection envelope: name, subject digests, raw
// attestation payloads by type, and optional recorded backrefs.
func invCollection(t *testing.T, f *invFixture, ref, name string, subjects []string, atts map[string]string, backrefs map[string]cryptoutil.DigestSet) source.CollectionEnvelope {
	t.Helper()
	collAtts := make([]attestation.CollectionAttestation, 0, len(atts))
	attTypes := make([]string, 0, len(atts))
	for typ := range atts {
		attTypes = append(attTypes, typ)
	}
	sort.Strings(attTypes) // deterministic order in the signed payload
	for _, typ := range attTypes {
		collAtts = append(collAtts, attestation.CollectionAttestation{
			Type:        typ,
			Attestation: attestation.NewRawAttestation(typ, json.RawMessage(atts[typ])),
		})
	}
	coll := attestation.Collection{Name: name, Attestations: collAtts, RecordedBackRefs: backrefs}
	predicate, err := json.Marshal(coll)
	require.NoError(t, err)

	subs := make([]intoto.Subject, 0, len(subjects))
	for i, d := range subjects {
		subs = append(subs, intoto.Subject{Name: fmt.Sprintf("subject-%d", i), Digest: map[string]string{"sha256": d}})
	}
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       subs,
		PredicateType: attestation.CollectionType,
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	env, err := dsse.Sign("application/vnd.in-toto+json", strings.NewReader(string(payload)), dsse.SignWithSigners(f.signer))
	require.NoError(t, err)
	return source.CollectionEnvelope{Reference: ref, Envelope: env}
}

// invVerify runs the full end-to-end pipeline: MemorySource + VerifiedSource
// (real DSSE signature verification with the fixture key) + Policy.Verify.
func invVerify(t *testing.T, f *invFixture, pol Policy, corpus []source.CollectionEnvelope, seeds []string) (bool, map[string]StepResult, error) {
	t.Helper()
	mem := source.NewMemorySource()
	for _, e := range corpus {
		require.NoError(t, mem.LoadEnvelope(e.Reference, e.Envelope))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))
	return pol.Verify(context.Background(),
		WithVerifiedSource(vs),
		WithSubjectDigests(seeds),
	)
}

// invFingerprint reduces a verify outcome to a deterministic hash: verdict,
// error presence, and per step (sorted) the analyze verdict, sorted passed
// references, and sorted rejected (reference + reason with the run's key ID
// normalized out). Everything else that varies per run is excluded.
func invFingerprint(f *invFixture, pass bool, results map[string]StepResult, err error) string {
	h := sha256.New()
	norm := func(s string) string { return strings.ReplaceAll(s, f.keyID, "<kid>") }
	fmt.Fprintf(h, "pass=%t|err=%t", pass, err != nil)
	if err != nil {
		fmt.Fprintf(h, "|errmsg=%s", norm(err.Error()))
	}
	names := make([]string, 0, len(results))
	for name := range results {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sr := results[name]
		fmt.Fprintf(h, "|step=%s analyze=%t passed=%d rejected=%d", name, sr.Analyze(), len(sr.Passed), len(sr.Rejected))
		passed := make([]string, 0, len(sr.Passed))
		for _, pc := range sr.Passed {
			passed = append(passed, pc.Collection.Reference)
		}
		sort.Strings(passed)
		for _, p := range passed {
			fmt.Fprintf(h, "|P:%s", p)
		}
		rejected := make([]string, 0, len(sr.Rejected))
		for _, rc := range sr.Rejected {
			reason := ""
			if rc.Reason != nil {
				reason = norm(rc.Reason.Error())
			}
			rejected = append(rejected, fmt.Sprintf("%s reason=%s", rc.Collection.Reference, reason))
		}
		sort.Strings(rejected)
		for _, r := range rejected {
			fmt.Fprintf(h, "|R:%s", r)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func checkInvGolden(t *testing.T, scenario, got, goldenKey string) {
	t.Helper()
	t.Logf("INVARIANT %s fingerprint: %s", scenario, got)
	golden, ok := loadInvGoldens(t)[goldenKey]
	if !ok || golden == "" {
		t.Logf("GOLDEN CAPTURE %s: no golden in testdata/retention_goldens.json under %q — commit the fingerprint above", scenario, goldenKey)
		return
	}
	assert.Equal(t, golden, got, "scenario %s verification outcome diverged from the unmodified-code golden (testdata/retention_goldens.json %q)", scenario, goldenKey)
}

// ---------------------------------------------------------------------------
// Scenario A: PASS verdict
// ---------------------------------------------------------------------------

func TestRetentionInvariant_PassVerdict(t *testing.T) {
	f := newInvFixture(t)
	pol := Policy{
		Expires:    metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: f.publicKeys(),
		Steps: map[string]Step{
			"build-a": {
				Name:          "build-a",
				Attestations:  []Attestation{{Type: invAttType}},
				Functionaries: []Functionary{f.functionary()},
			},
		},
	}
	corpus := []source.CollectionEnvelope{
		invCollection(t, f, "c-a1", "build-a", []string{invDigestSeed}, map[string]string{invAttType: `{"commithash":"abc"}`}, nil),
	}

	pass, results, err := invVerify(t, f, pol, corpus, []string{invDigestSeed})
	require.NoError(t, err)
	require.True(t, pass, "scenario A must PASS")
	require.Equal(t, 1, len(results["build-a"].Passed))
	checkInvGolden(t, "A-pass", invFingerprint(f, pass, results, err), goldenInvariantPass)
}

// ---------------------------------------------------------------------------
// Scenario B: BackRef depth expansion + cross-depth merge dedup
// ---------------------------------------------------------------------------

func TestRetentionInvariant_BackRefExpansionAndMergeDedup(t *testing.T) {
	f := newInvFixture(t)
	pol := Policy{
		Expires:    metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: f.publicKeys(),
		Steps: map[string]Step{
			"src-b": {
				Name:          "src-b",
				Attestations:  []Attestation{{Type: invAttType}},
				Functionaries: []Functionary{f.functionary()},
			},
			"down-b": {
				Name:          "down-b",
				Attestations:  []Attestation{{Type: invAttType}},
				Functionaries: []Functionary{f.functionary()},
			},
		},
	}
	corpus := []source.CollectionEnvelope{
		// c-b1 matches the seed and carries a recorded BackRef to invDigestBackRef.
		invCollection(t, f, "c-b1", "src-b", []string{invDigestSeed}, map[string]string{invAttType: `{"commithash":"b1"}`},
			map[string]cryptoutil.DigestSet{"test/backref": {cryptoutil.DigestValue{Hash: crypto.SHA256}: invDigestBackRef}}),
		// c-b2 is reachable ONLY via the BackRef digest — requires depth >= 1.
		invCollection(t, f, "c-b2", "down-b", []string{invDigestBackRef}, map[string]string{invAttType: `{"commithash":"b2"}`}, nil),
	}

	pass, results, err := invVerify(t, f, pol, corpus, []string{invDigestSeed})
	require.NoError(t, err)
	require.True(t, pass, "scenario B must PASS via BackRef expansion")
	// The MERGE discriminator: src-b is re-discovered at depth 1 (MemorySource
	// has no seen-marking) and mergePassedCollections must dedup it to ONE
	// passed collection. A broken merge identity yields 2+ and fails here and
	// in the fingerprint.
	require.Equal(t, 1, len(results["src-b"].Passed), "cross-depth rediscovery must dedup to one passed collection")
	require.Equal(t, 1, len(results["down-b"].Passed), "BackRef-reachable evidence must be found at depth >= 1")
	checkInvGolden(t, "B-merge", invFingerprint(f, pass, results, err), goldenInvariantMerge)
}

// ---------------------------------------------------------------------------
// Scenario C: cross-step Rego reads an upstream passed attestor's CONTENT
// ---------------------------------------------------------------------------

func TestRetentionInvariant_CrossStepRegoReadsUpstreamContent(t *testing.T) {
	f := newInvFixture(t)
	// Deny unless the upstream attestor's content is present AND correct in
	// input.steps — dropping upstream attestor bodies without rehydration
	// flips this scenario's verdict.
	regoModule := fmt.Sprintf(`package invariant.crossstep

deny[msg] {
	not upstream_ok
	msg := "upstream commithash missing or wrong in input.steps"
}

upstream_ok {
	input.steps["up-c"][%q].commithash == "abc"
}
`, invAttType)

	pol := Policy{
		Expires:    metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: f.publicKeys(),
		Steps: map[string]Step{
			"up-c": {
				Name:          "up-c",
				Attestations:  []Attestation{{Type: invAttType}},
				Functionaries: []Functionary{f.functionary()},
			},
			"down-c": {
				Name:             "down-c",
				AttestationsFrom: []string{"up-c"},
				Attestations: []Attestation{{
					Type:         invAttType,
					RegoPolicies: []RegoPolicy{{Name: "crossstep-invariant", Module: []byte(regoModule)}},
				}},
				Functionaries: []Functionary{f.functionary()},
			},
		},
	}
	corpus := []source.CollectionEnvelope{
		invCollection(t, f, "c-c1", "up-c", []string{invDigestSeed}, map[string]string{invAttType: `{"commithash":"abc"}`}, nil),
		invCollection(t, f, "c-c2", "down-c", []string{invDigestSeed}, map[string]string{invAttType: `{"commithash":"down"}`}, nil),
	}

	pass, results, err := invVerify(t, f, pol, corpus, []string{invDigestSeed})
	require.NoError(t, err)
	require.True(t, pass, "scenario C must PASS: the rego rule reads the upstream attestor's content from input.steps")
	require.Equal(t, 1, len(results["down-c"].Passed))
	checkInvGolden(t, "C-rego", invFingerprint(f, pass, results, err), goldenInvariantRego)
}

// ---------------------------------------------------------------------------
// Scenario D: artifactsFrom chain re-reads passed materials/products
// ---------------------------------------------------------------------------

func invArtifactsPolicy(f *invFixture) Policy {
	return Policy{
		Expires:    metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: f.publicKeys(),
		Steps: map[string]Step{
			"build-d": {
				Name:          "build-d",
				Attestations:  []Attestation{{Type: invMatProdType}},
				Functionaries: []Functionary{f.functionary()},
			},
			"test-d": {
				Name:          "test-d",
				ArtifactsFrom: []string{"build-d"},
				Attestations:  []Attestation{{Type: invMatProdType}},
				Functionaries: []Functionary{f.functionary()},
			},
		},
	}
}

func invArtifactsCorpus(t *testing.T, f *invFixture, downstreamDigest string) []source.CollectionEnvelope {
	t.Helper()
	ds := func(d string) cryptoutil.DigestSet {
		return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: d}
	}
	build, err := json.Marshal(&invMatProdAttestor{
		Prods:  map[string]attestation.Product{"out/bin": {MimeType: "application/octet-stream", Digest: ds(invDigestFile)}},
		Inline: true,
	})
	require.NoError(t, err)
	test, err := json.Marshal(&invMatProdAttestor{
		Mats:   map[string]cryptoutil.DigestSet{"out/bin": ds(downstreamDigest)},
		Inline: true,
	})
	require.NoError(t, err)
	return []source.CollectionEnvelope{
		invCollection(t, f, "c-d1", "build-d", []string{invDigestSeed}, map[string]string{invMatProdType: string(build)}, nil),
		invCollection(t, f, "c-d2", "test-d", []string{invDigestSeed}, map[string]string{invMatProdType: string(test)}, nil),
	}
}

func TestRetentionInvariant_ArtifactChainPasses(t *testing.T) {
	registerInvMatProd()
	f := newInvFixture(t)

	pass, results, err := invVerify(t, f, invArtifactsPolicy(f), invArtifactsCorpus(t, f, invDigestFile), []string{invDigestSeed})
	require.NoError(t, err)
	require.True(t, pass, "scenario D must PASS: downstream materials match upstream products")
	require.Equal(t, 1, len(results["test-d"].Passed))
	checkInvGolden(t, "D-artifacts", invFingerprint(f, pass, results, err), goldenInvariantArtifacts)
}

// The negative direction pins that the artifact compare actually runs on the
// REAL rehydrated data: a mismatched downstream material digest must fail the
// chain. If rehydration produced empty maps, this would fail differently (or
// the positive case above would fail) — between the two, an emptied or
// skipped artifact compare cannot go unnoticed.
func TestRetentionInvariant_ArtifactChainDigestMismatchFails(t *testing.T) {
	registerInvMatProd()
	f := newInvFixture(t)

	pass, results, err := invVerify(t, f, invArtifactsPolicy(f), invArtifactsCorpus(t, f, invDigestWrong), []string{invDigestSeed})
	require.NoError(t, err)
	require.False(t, pass, "scenario D-mismatch must FAIL: downstream material digest differs from upstream product")
	require.Equal(t, 0, len(results["test-d"].Passed), "mismatched chain must clear test-d's passed set")
	checkInvGolden(t, "D-mismatch", invFingerprint(f, pass, results, err), goldenInvariantArtMismat)
}
