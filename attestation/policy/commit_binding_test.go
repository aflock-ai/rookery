// jade:ring local
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

package policy

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
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

// ---------------------------------------------------------------------------
// HSEC1: a commit gate must only accept witnesses bound to the commit it
// judges.
//
// The depth loop used to harvest BackRefs from every passing collection. The
// git attestor signs a parenthash BackRef, so the evaluated commit C's own
// build collection made its PARENT P searchable at depth 1, and P's clean
// secrets scan then satisfied C's secrets step while C's own scan had
// findings. Nothing in the engine asked whether a witness belongs to C.
//
// Edges are no longer followed, so P is reached only when a caller SEEDS it
// (as a RunSync request carrying extra subjects does). The cases below that
// used to reach a foreign witness through an edge now seed its digest
// explicitly, so the binding is still exercised on it.
//
// WithCommitBinding(C) adds that question to the step gate: a collection counts
// only when it carries at least one git attestation and EVERY git
// attestation's commithash is C. The corpus below is synthetic: throwaway keys,
// fixed fake commit ids, and the real git attestor JSON shape (commithash,
// commithashverified, parenthashes) with its commithash/parenthash BackRefs.
// ---------------------------------------------------------------------------

const (
	hsecGitType   = "https://aflock.ai/attestations/git/v0.1"
	hsecBuildType = "https://example.com/hsec1-build/v1"
	hsecScanType  = "https://example.com/hsec1-secretscan/v1"

	hsecG = "1111111111111111111111111111111111111111" // grandparent
	hsecP = "2222222222222222222222222222222222222222" // parent
	hsecC = "3333333333333333333333333333333333333333" // the evaluated commit
	hsecS = "4444444444444444444444444444444444444444" // sibling: another child of P
	hsecK = "5555555555555555555555555555555555555555" // child of C

	// hsecTreeRoot is a non-empty product-tree root shared by two unrelated
	// collections: a link that is not a commit relation at all.
	hsecTreeRoot = "7777777777777777777777777777777777777777777777777777777777777777"
)

// hsecGit mirrors the git attestor's predicate fields that matter here, under
// the attestor's own JSON names.
type hsecGit struct {
	CommitHash         string   `json:"commithash"`
	CommitHashVerified bool     `json:"commithashverified"`
	ParentHashes       []string `json:"parenthashes,omitempty"`
}

func (g *hsecGit) Name() string                                   { return "git" }
func (g *hsecGit) Type() string                                   { return hsecGitType }
func (g *hsecGit) RunType() attestation.RunType                   { return attestation.PreMaterialRunType }
func (g *hsecGit) Schema() *jsonschema.Schema                     { return nil }
func (g *hsecGit) Attest(_ *attestation.AttestationContext) error { return nil }

// hsecAtt is the step's own required attestation: a build marker, or a secret
// scan whose findings the secrets rego denies on.
type hsecAtt struct {
	AttType  string   `json:"-"`
	Findings []string `json:"findings"`
}

func (a *hsecAtt) Name() string                                   { return "hsec" }
func (a *hsecAtt) Type() string                                   { return a.AttType }
func (a *hsecAtt) RunType() attestation.RunType                   { return attestation.PostProductRunType }
func (a *hsecAtt) Schema() *jsonschema.Schema                     { return nil }
func (a *hsecAtt) Attest(_ *attestation.AttestationContext) error { return nil }

var hsecDenyFindings = []byte(`package hsec1secrets

deny[msg] {
	count(input.findings) > 0
	msg := sprintf("secretscan: %d findings", [count(input.findings)])
}
`)

// hsecSpec describes one fixture collection.
type hsecSpec struct {
	ref      string
	step     string // "build" or "secrets"
	gits     []hsecGit
	findings int
	// treeRoot, when set, is both a searchable digest of this collection and a
	// product-tree BackRef on it.
	treeRoot string
	// alsoIndexed are extra digests the source finds this collection under.
	alsoIndexed []string
}

func hsecGitOf(commit string, parents ...string) []hsecGit {
	return []hsecGit{{CommitHash: commit, CommitHashVerified: true, ParentHashes: parents}}
}

// sha1Set is the git attestor's encoding of a commit id (addCommitSubject).
func sha1Set(v string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA1}: v}
}

// backRefs reproduces what attestation.NewCollection records for these
// attestors: git's commithash and parenthash edges, namespaced by type, plus
// the product-tree root when one is set.
func (s hsecSpec) backRefs() map[string]cryptoutil.DigestSet {
	refs := map[string]cryptoutil.DigestSet{}
	for _, g := range s.gits {
		refs[hsecGitType+"/commithash:"+g.CommitHash] = sha1Set(g.CommitHash)
		for _, p := range g.ParentHashes {
			refs[hsecGitType+"/parenthash:"+p] = sha1Set(p)
		}
	}
	if s.treeRoot != "" {
		refs[hsecBuildType+"/tree:products"] = newDigestSet(s.treeRoot)
	}
	return refs
}

// subjects reproduces git.Attestor.Subjects for commit ids (commithash AND
// parenthash, both sha1), plus the tree root and a per-collection unique
// subject so no two fixtures share a content key.
func (s hsecSpec) subjects() []intoto.Subject {
	sum := sha256.Sum256([]byte(s.ref))
	subs := []intoto.Subject{{Name: "fixture:" + s.ref, Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])}}}
	for _, g := range s.gits {
		subs = append(subs, intoto.Subject{Name: hsecGitType + "/commithash:" + g.CommitHash, Digest: map[string]string{"sha1": g.CommitHash}})
		for _, p := range g.ParentHashes {
			subs = append(subs, intoto.Subject{Name: hsecGitType + "/parenthash:" + p, Digest: map[string]string{"sha1": p}})
		}
	}
	if s.treeRoot != "" {
		subs = append(subs, intoto.Subject{Name: "tree-root", Digest: map[string]string{"sha256": s.treeRoot}})
	}
	return subs
}

func (s hsecSpec) collection() attestation.Collection {
	cas := make([]attestation.CollectionAttestation, 0, len(s.gits)+1)
	for i := range s.gits {
		g := s.gits[i]
		cas = append(cas, attestation.CollectionAttestation{Type: hsecGitType, Attestation: &g})
	}
	stepAtt := &hsecAtt{AttType: hsecBuildType}
	if s.step == "secrets" {
		stepAtt = &hsecAtt{AttType: hsecScanType, Findings: []string{}}
		for i := 0; i < s.findings; i++ {
			stepAtt.Findings = append(stepAtt.Findings, "synthetic-finding")
		}
	}
	cas = append(cas, attestation.CollectionAttestation{Type: stepAtt.Type(), Attestation: stepAtt})
	return attestation.Collection{Name: s.step, Attestations: cas, RecordedBackRefs: s.backRefs()}
}

// result builds a directly-constructed verified candidate, the shape a source
// with no retained payload hands the engine (the envelope fields are the
// source of truth).
func (s hsecSpec) result(v cryptoutil.Verifier) source.CollectionVerificationResult {
	return source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{v},
		CollectionEnvelope: source.CollectionEnvelope{
			Reference:  s.ref,
			Collection: s.collection(),
			Statement: intoto.Statement{
				Type:          intoto.StatementType,
				PredicateType: attestation.CollectionType,
				Subject:       s.subjects(),
			},
		},
	}
}

// searchDigests are the values the collection is findable under. Every subject
// digest is indexed by VALUE, parenthash included, the way a SQL subject index
// (judge-api's EntSource) answers a digest query.
func (s hsecSpec) searchDigests() []string {
	out := append([]string(nil), s.alsoIndexed...)
	for _, sub := range s.subjects() {
		for _, d := range sub.Digest {
			out = append(out, d)
		}
	}
	return out
}

// The fixture corpus. Keyed by ref so each case names the collections it holds.
var hsecCorpus = map[string]hsecSpec{
	"C-build":         {ref: "C-build", step: "build", gits: hsecGitOf(hsecC, hsecP)},
	"C-build-tree":    {ref: "C-build-tree", step: "build", gits: hsecGitOf(hsecC, hsecP), treeRoot: hsecTreeRoot},
	"C-secrets-dirty": {ref: "C-secrets-dirty", step: "secrets", gits: hsecGitOf(hsecC, hsecP), findings: 2},
	"C-secrets-clean": {ref: "C-secrets-clean", step: "secrets", gits: hsecGitOf(hsecC, hsecP)},
	"P-build":         {ref: "P-build", step: "build", gits: hsecGitOf(hsecP, hsecG)},
	"P-secrets-clean": {ref: "P-secrets-clean", step: "secrets", gits: hsecGitOf(hsecP, hsecG)},
	"S-secrets-clean": {ref: "S-secrets-clean", step: "secrets", gits: hsecGitOf(hsecS, hsecP)},
	"K-secrets-clean": {ref: "K-secrets-clean", step: "secrets", gits: hsecGitOf(hsecK, hsecC)},
	// A clean scan reachable only through the shared product-tree root. It
	// carries no git attestation at all.
	"T-secrets-nogit": {ref: "T-secrets-nogit", step: "secrets", treeRoot: hsecTreeRoot},
	// A clean scan findable under C's own digest (it names C as a subject) that
	// carries no git attestation: "no git" must not read as "unknown, so OK".
	"N-secrets-nogit": {ref: "N-secrets-nogit", step: "secrets", alsoIndexed: []string{hsecC}},
	// A clean scan with two git attestations that disagree.
	"D-secrets-twogit": {ref: "D-secrets-twogit", step: "secrets", gits: []hsecGit{
		{CommitHash: hsecC, CommitHashVerified: true, ParentHashes: []string{hsecP}},
		{CommitHash: hsecP, CommitHashVerified: true, ParentHashes: []string{hsecG}},
	}},
}

// hsecSource answers digest queries from the corpus and records every digest
// the engine searched for.
type hsecSource struct {
	byDigest map[string][]source.CollectionVerificationResult
	all      []source.CollectionVerificationResult
	searched map[string]struct{}
}

func newHsecSource(v cryptoutil.Verifier, refs ...string) *hsecSource {
	specs := make([]hsecSpec, 0, len(refs))
	for _, ref := range refs {
		spec, ok := hsecCorpus[ref]
		if !ok {
			panic("unknown fixture " + ref)
		}
		specs = append(specs, spec)
	}
	return newHsecSourceOf(v, specs...)
}

func newHsecSourceOf(v cryptoutil.Verifier, specs ...hsecSpec) *hsecSource {
	s := &hsecSource{byDigest: map[string][]source.CollectionVerificationResult{}, searched: map[string]struct{}{}}
	for _, spec := range specs {
		cvr := spec.result(v)
		s.all = append(s.all, cvr)
		for _, d := range spec.searchDigests() {
			s.byDigest[d] = append(s.byDigest[d], cvr)
		}
	}
	return s
}

func (s *hsecSource) matches(step string, digests []string) []source.CollectionVerificationResult {
	var out []source.CollectionVerificationResult
	seen := map[string]struct{}{}
	pool := s.all
	if len(digests) > 0 {
		pool = nil
		for _, d := range digests {
			s.searched[d] = struct{}{}
			pool = append(pool, s.byDigest[d]...)
		}
	}
	for _, cvr := range pool {
		if cvr.Collection.Name != step {
			continue
		}
		if _, dup := seen[cvr.Reference]; dup {
			continue
		}
		seen[cvr.Reference] = struct{}{}
		out = append(out, cvr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Reference < out[j].Reference })
	return out
}

func (s *hsecSource) Search(_ context.Context, step string, digests, _ []string) ([]source.CollectionVerificationResult, error) {
	return s.matches(step, digests), nil
}

func (s *hsecSource) SearchStream(_ context.Context, step string, digests, _ []string, yield func(source.CollectionVerificationResult) error) error {
	for _, cvr := range s.matches(step, digests) {
		if err := yield(cvr); err != nil {
			return err
		}
	}
	return nil
}

func (s *hsecSource) SearchByPredicateType(context.Context, []string, []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// CanonicalStreamOrder: matches sorts by reference, so the lazy arm is live.
func (s *hsecSource) CanonicalStreamOrder() bool { return true }

// hsecBatch hides SearchStream (named field, never embedded) to force the
// batch arm.
type hsecBatch struct{ inner *hsecSource }

func (b hsecBatch) Search(ctx context.Context, step string, digests, atts []string) ([]source.CollectionVerificationResult, error) {
	return b.inner.Search(ctx, step, digests, atts)
}

func (b hsecBatch) SearchByPredicateType(ctx context.Context, pts, digests []string) ([]source.StatementEnvelope, error) {
	return b.inner.SearchByPredicateType(ctx, pts, digests)
}

// hsecKey is a throwaway signing identity for one test.
type hsecKey struct {
	signer   cryptoutil.Signer
	verifier cryptoutil.Verifier
	keyID    string
	pem      []byte
}

func newHsecKey(t *testing.T) hsecKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	verifier := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	pem, err := cryptoutil.PublicPemBytes(&priv.PublicKey)
	require.NoError(t, err)
	return hsecKey{signer: cryptoutil.NewECDSASigner(priv, crypto.SHA256), verifier: verifier, keyID: keyID, pem: pem}
}

func hsecPolicy(keyID string, publicKeys map[string]PublicKey) Policy {
	fn := []Functionary{{Type: "publickey", PublicKeyID: keyID}}
	return Policy{
		Expires:    metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: publicKeys,
		Steps: map[string]Step{
			"build": {Name: "build", Functionaries: fn, Attestations: []Attestation{{Type: hsecBuildType}}},
			"secrets": {Name: "secrets", Functionaries: fn, Attestations: []Attestation{{
				Type:         hsecScanType,
				RegoPolicies: []RegoPolicy{{Name: "no-findings", Module: hsecDenyFindings}},
			}}},
		},
	}
}

// hsecArms runs one corpus through the streamed, batch and lazy arms.
var hsecArms = []string{"streamed", "batch", "lazy"}

type hsecRun struct {
	accepted bool
	results  map[string]StepResult
	src      *hsecSource
}

func hsecVerify(t *testing.T, arm string, refs []string, opts ...VerifyOption) hsecRun {
	t.Helper()
	key := newHsecKey(t)
	src := newHsecSource(key.verifier, refs...)
	var vsrc source.VerifiedSourcer = src
	switch arm {
	case "batch":
		vsrc = hsecBatch{inner: src}
	case "lazy":
		opts = append(opts, WithLazyStepSatisfaction(true))
	}
	all := append([]VerifyOption{
		WithVerifiedSource(vsrc),
		WithSubjectDigests([]string{hsecC}),
		WithSearchDepth(3),
	}, opts...)
	accepted, results, err := hsecPolicy(key.keyID, nil).Verify(context.Background(), all...)
	require.NoError(t, err)
	return hsecRun{accepted: accepted, results: results, src: src}
}

// hsecSeeds seeds C plus extra digests. Edges are no longer followed, so a
// foreign witness is reached only by seeding a digest it is indexed under.
// It overrides hsecVerify's default seed ({C}) because the last
// WithSubjectDigests wins.
func hsecSeeds(extra ...string) VerifyOption {
	return WithSubjectDigests(append([]string{hsecC}, extra...))
}

func hsecPassedRefs(sr StepResult) []string {
	out := make([]string, 0, len(sr.Passed))
	for _, pc := range sr.Passed {
		out = append(out, pc.Collection.Reference)
	}
	sort.Strings(out)
	return out
}

// unboundRejections maps each rejected reference to its binding refusal.
func unboundRejections(sr StepResult) map[string]ErrWitnessNotBoundToCommit {
	out := map[string]ErrWitnessNotBoundToCommit{}
	for _, rc := range sr.Rejected {
		var nb ErrWitnessNotBoundToCommit
		if errors.As(rc.Reason, &nb) {
			out[rc.Collection.Reference] = nb
		}
	}
	return out
}

// CHARACTERIZATION of the zero value. Without WithCommitBinding the engine is
// unbound, which is correct for verifies whose subject is not a commit (a
// registry or image-digest gate) and is exactly the HSEC1 exposure when the
// subject IS a commit: C's secrets step is satisfied by a collection from its
// parent, its sibling, its child, or an unrelated tree-root link.
//
// With edges no longer followed, only the child (it names C as a subject) is
// reached from {C}. The parent, sibling and tree-root witnesses are reached
// only when their digest is seeded too, and then unbound mode still accepts
// on them.
func TestCommitBinding_ZeroValueIsUnbound(t *testing.T) {
	cases := []struct {
		name        string
		refs        []string
		wantWitness string
		// seed reaches the witness; "" means {C} alone reaches it.
		seed string
	}{
		{"parent", []string{"C-build", "C-secrets-dirty", "P-build", "P-secrets-clean"}, "P-secrets-clean", hsecP},
		{"sibling", []string{"C-build", "C-secrets-dirty", "S-secrets-clean"}, "S-secrets-clean", hsecS},
		{"child", []string{"C-build", "C-secrets-dirty", "K-secrets-clean"}, "K-secrets-clean", ""},
		{"tree-root link", []string{"C-build-tree", "C-secrets-dirty", "T-secrets-nogit"}, "T-secrets-nogit", hsecTreeRoot},
	}
	for _, tc := range cases {
		for _, arm := range hsecArms {
			t.Run(tc.name+"/"+arm, func(t *testing.T) {
				if tc.seed != "" {
					seedOnly := hsecVerify(t, arm, tc.refs)
					assert.False(t, seedOnly.accepted, "the witness is reachable from C only through an edge, which is no longer followed")
					assert.NotContains(t, hsecPassedRefs(seedOnly.results["secrets"]), tc.wantWitness)
				}
				run := hsecVerify(t, arm, tc.refs, hsecSeeds(tc.seed))
				require.True(t, run.accepted, "unbound mode accepts on a foreign witness the seeds reach (the documented zero-value behaviour)")
				assert.Equal(t, []string{tc.wantWitness}, hsecPassedRefs(run.results["secrets"]))
			})
		}
	}
}

// With the binding, every foreign witness is Rejected with
// ErrWitnessNotBoundToCommit and C fails on its own evidence. A witness that
// used to be reached through an edge is reached here by seeding its digest.
func TestCommitBinding_RejectsWitnessesFromOtherCommits(t *testing.T) {
	cases := []struct {
		name string
		refs []string
		// foreign is the witness that must be refused, and the commit the
		// refusal must name ("" = it carries no git attestation).
		foreign       string
		foreignCommit string
		// seed is the extra digest that reaches foreign ("" = {C} reaches it).
		seed string
	}{
		// (a) C's own scan has findings; P's clean scan is seeded.
		{"a parent", []string{"C-build", "C-secrets-dirty", "P-build", "P-secrets-clean"}, "P-secrets-clean", hsecP, hsecP},
		// (b) C has no secrets collection at all.
		{"b omitted step", []string{"C-build", "P-build", "P-secrets-clean"}, "P-secrets-clean", hsecP, hsecP},
		// (c) S is another child of P, reached through the seeded parent digest.
		{"c sibling", []string{"C-build", "C-secrets-dirty", "S-secrets-clean"}, "S-secrets-clean", hsecS, hsecP},
		// (d) K names C as its parent, so it matches the SEED.
		{"d child of seed", []string{"C-build", "C-secrets-dirty", "K-secrets-clean"}, "K-secrets-clean", hsecK, ""},
		// (e) linked through a shared product-tree root, no commit relation.
		{"e tree-root link", []string{"C-build-tree", "C-secrets-dirty", "T-secrets-nogit"}, "T-secrets-nogit", "", hsecTreeRoot},
		// A collection under C's own digest with no git attestation.
		{"no git attestation", []string{"C-build", "N-secrets-nogit"}, "N-secrets-nogit", "", ""},
		// Two git attestations that disagree: one of them is not C.
		{"two git commits", []string{"C-build", "D-secrets-twogit"}, "D-secrets-twogit", hsecP, ""},
	}
	for _, tc := range cases {
		for _, arm := range hsecArms {
			t.Run(tc.name+"/"+arm, func(t *testing.T) {
				run := hsecVerify(t, arm, tc.refs, hsecSeeds(tc.seed), WithCommitBinding(hsecC))
				sr := run.results["secrets"]
				assert.False(t, run.accepted, "a commit gate must not accept on a witness bound to another commit")
				assert.NotContains(t, hsecPassedRefs(sr), tc.foreign)
				nb, ok := unboundRejections(sr)[tc.foreign]
				require.True(t, ok, "%s must be Rejected with ErrWitnessNotBoundToCommit; rejected=%v", tc.foreign, sr.Rejected)
				assert.Equal(t, "secrets", nb.Step)
				assert.Equal(t, strings.ToLower(hsecC), nb.Commit)
				assert.Equal(t, tc.foreignCommit, nb.WitnessCommit)
			})
		}
	}
}

// (f) Positive control: C's own clean evidence passes, and every witness in
// every step is bound to C, with P's clean scan in the corpus. (Every step is
// satisfied at depth 0 here, so the walk stops before it reaches P.)
func TestCommitBinding_OwnEvidencePasses(t *testing.T) {
	refs := []string{"C-build", "C-secrets-clean", "P-build", "P-secrets-clean"}
	for _, arm := range hsecArms {
		t.Run(arm, func(t *testing.T) {
			run := hsecVerify(t, arm, refs, WithCommitBinding(hsecC))
			require.True(t, run.accepted, "C's own clean evidence must pass under the binding")
			assert.Equal(t, []string{"C-build"}, hsecPassedRefs(run.results["build"]))
			assert.Equal(t, []string{"C-secrets-clean"}, hsecPassedRefs(run.results["secrets"]))
			for step, sr := range run.results {
				for _, pc := range sr.Passed {
					for _, g := range hsecCorpus[pc.Collection.Reference].gits {
						assert.Equal(t, hsecC, g.CommitHash, "step %s witness %s is not bound to C", step, pc.Collection.Reference)
					}
				}
			}
		})
	}
}

// The comparison is over full hex, case-folded: a binding spelled in upper
// case binds a lower-case commithash, and vice versa.
func TestCommitBinding_ComparesCaseFoldedHex(t *testing.T) {
	const lower = "abcdef3333333333333333333333333333333333"
	upper := strings.ToUpper(lower)
	for _, tc := range []struct{ attested, bound string }{{lower, upper}, {upper, lower}} {
		t.Run(tc.bound[:8], func(t *testing.T) {
			key := newHsecKey(t)
			src := newHsecSourceOf(key.verifier,
				hsecSpec{ref: "build", step: "build", gits: hsecGitOf(tc.attested, hsecP), alsoIndexed: []string{tc.bound}},
				hsecSpec{ref: "secrets", step: "secrets", gits: hsecGitOf(tc.attested, hsecP), alsoIndexed: []string{tc.bound}},
			)
			accepted, results, err := hsecPolicy(key.keyID, nil).Verify(context.Background(),
				WithVerifiedSource(src), WithSubjectDigests([]string{tc.bound}), WithCommitBinding(tc.bound))
			require.NoError(t, err)
			assert.True(t, accepted, "rejected=%v", results["secrets"].Rejected)
		})
	}
}

// No edge widens the search, refused witness or not. The unbound control used
// to show P-build passing and its parenthash edge making G searchable; now G is
// never searched in either mode, and C's own parenthash edge does not make P
// searchable either. With P seeded, P-build is reached and refused as not
// bound to C, and its edges still widen nothing.
func TestCommitBinding_RefusedWitnessBackRefsAreNotHarvested(t *testing.T) {
	refs := []string{"C-build", "C-secrets-dirty", "P-build"}
	for _, arm := range hsecArms {
		t.Run(arm, func(t *testing.T) {
			unbound := hsecVerify(t, arm, refs)
			require.False(t, unbound.accepted)
			_, pSearched := unbound.src.searched[hsecP]
			assert.False(t, pSearched, "C's own parenthash edge must not make the parent searchable")
			_, gSearched := unbound.src.searched[hsecG]
			assert.False(t, gSearched, "no edge may widen the search")

			bound := hsecVerify(t, arm, refs, hsecSeeds(hsecP), WithCommitBinding(hsecC))
			require.False(t, bound.accepted)
			_, gSearched = bound.src.searched[hsecG]
			assert.False(t, gSearched, "a refused witness's BackRefs must not widen the search")
			_, refused := unboundRejections(bound.results["build"])["P-build"]
			assert.True(t, refused, "P-build, reached through the seeded parent digest, must be in Rejected as not bound to C")
		})
	}
}

// A binding that is not a full hex commit id is refused up front. A short or
// malformed value would otherwise fail every comparison (a silent
// false-reject) or, worse, invite a prefix match later.
func TestCommitBinding_MalformedBindingIsRefused(t *testing.T) {
	for _, bad := range []string{"33333", "zz" + hsecC[2:], hsecC + "3", " " + hsecC} {
		t.Run(bad, func(t *testing.T) {
			key := newHsecKey(t)
			_, _, err := hsecPolicy(key.keyID, nil).Verify(context.Background(),
				WithVerifiedSource(newHsecSource(key.verifier, "C-build")),
				WithSubjectDigests([]string{hsecC}),
				WithCommitBinding(bad))
			var inv ErrInvalidOption
			require.ErrorAs(t, err, &inv)
		})
	}
}

// hsecSign signs a corpus collection with a throwaway key. The attestations
// are raw JSON (no plugin factory in this package), so the payload a
// VerifiedSource retains is the only place their fields live.
func hsecSign(t *testing.T, key hsecKey, spec hsecSpec) dsse.Envelope {
	t.Helper()
	coll := spec.collection()
	for i, ca := range coll.Attestations {
		body, err := json.Marshal(ca.Attestation)
		require.NoError(t, err)
		coll.Attestations[i].Attestation = attestation.NewRawAttestation(ca.Type, body)
	}
	predicate, err := json.Marshal(coll)
	require.NoError(t, err)
	payload, err := json.Marshal(intoto.Statement{
		Type:          intoto.StatementType,
		Subject:       spec.subjects(),
		PredicateType: attestation.CollectionType,
		Predicate:     predicate,
	})
	require.NoError(t, err)
	env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(key.signer))
	require.NoError(t, err)
	return env
}

// hsecVerifySigned verifies C against signed corpus envelopes held in the
// in-memory source behind a real VerifiedSource.
func hsecVerifySigned(t *testing.T, key hsecKey, pol Policy, refs []string, opts ...VerifyOption) (bool, map[string]StepResult) {
	t.Helper()
	mem := source.NewMemorySource()
	for _, ref := range refs {
		require.NoError(t, mem.LoadEnvelope(ref, hsecSign(t, key, hsecCorpus[ref])))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(key.verifier))
	accepted, results, err := pol.Verify(context.Background(), append([]VerifyOption{
		WithVerifiedSource(vs), WithSubjectDigests([]string{hsecC}),
	}, opts...)...)
	require.NoError(t, err)
	return accepted, results
}

// End to end through real signatures: throwaway-key DSSE envelopes, the
// in-memory source, and VerifiedSource. The git attestation decodes as a
// RawAttestation (no plugin factory in this package), the parent is reached
// only by seeding its digest (the signed backrefs are no longer followed), and
// the binding reads commithash from the signed payload.
func TestCommitBinding_SignedCorpusThroughVerifiedSource(t *testing.T) {
	key := newHsecKey(t)
	pks := map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}}

	verify := func(t *testing.T, refs []string, opts ...VerifyOption) (bool, map[string]StepResult) {
		return hsecVerifySigned(t, key, hsecPolicy(key.keyID, pks), refs, opts...)
	}

	parent := []string{"C-build", "C-secrets-dirty", "P-build", "P-secrets-clean"}
	accepted, results := verify(t, parent)
	require.False(t, accepted, "unbound, seeded with C alone: the parent is reachable only through the signed parenthash edge, which is no longer followed")
	require.Empty(t, hsecPassedRefs(results["secrets"]))

	accepted, results = verify(t, parent, hsecSeeds(hsecP))
	require.True(t, accepted, "characterization: unbound, with the parent seeded, the signed parent scan satisfies C")
	require.Equal(t, []string{"P-secrets-clean"}, hsecPassedRefs(results["secrets"]))

	accepted, results = verify(t, parent, hsecSeeds(hsecP), WithCommitBinding(hsecC))
	assert.False(t, accepted, "bound: C must fail on its own findings")
	nb, ok := unboundRejections(results["secrets"])["P-secrets-clean"]
	require.True(t, ok, "the parent scan must be refused as unbound; rejected=%v", results["secrets"].Rejected)
	assert.Equal(t, hsecP, nb.WitnessCommit)

	accepted, results = verify(t, []string{"C-build", "C-secrets-clean", "P-build", "P-secrets-clean"}, WithCommitBinding(hsecC))
	assert.True(t, accepted, "bound: C's own signed clean evidence passes")
	assert.Equal(t, []string{"C-secrets-clean"}, hsecPassedRefs(results["secrets"]))
}

// The binding reads commithash from the SIGNED payload when one is retained.
// A source populates the decoded Collection itself, so a source that projects
// the evaluated commit's git attestation onto the parent's signed scan must
// not bind that scan to C.
func TestCommitBinding_ReadsTheSignedPayloadNotTheProjection(t *testing.T) {
	key := newHsecKey(t)
	parent := hsecCorpus["P-secrets-clean"]
	predicate, err := json.Marshal(parent.collection())
	require.NoError(t, err)
	payload, err := json.Marshal(intoto.Statement{
		Type: intoto.StatementType, Subject: parent.subjects(),
		PredicateType: attestation.CollectionType, Predicate: predicate,
	})
	require.NoError(t, err)

	// Signed bytes say P; the projected Collection claims C.
	projected := hsecCorpus["C-secrets-clean"].result(key.verifier)
	projected.Reference = "P-secrets-projected-as-C"
	projected.Envelope = dsse.Envelope{PayloadType: intoto.PayloadType, Payload: payload}

	err = checkCommitBinding("secrets", projected, hsecC)
	var nb ErrWitnessNotBoundToCommit
	require.ErrorAs(t, err, &nb, "a projection must not bind a signed payload from another commit")
	assert.Equal(t, hsecP, nb.WitnessCommit)

	// Control: the same projection with no retained payload is its own truth.
	projected.Envelope = dsse.Envelope{}
	require.NoError(t, checkCommitBinding("secrets", projected, hsecC))
}

// hsecPassAI passes every AI policy, so the AI verdict never decides the step
// and the binding is the only thing that can refuse the parent's scan.
type hsecPassAI struct{}

func (hsecPassAI) Evaluate(_ context.Context, _ attestation.Attestor, pol AiPolicy, _ string) (AiResponse, error) {
	return AiResponse{Status: AiStatusPass, Reason: "stub", Model: pol.Model}, nil
}

// The deferred-AI arm: with a fan-out tracker set and an AI policy on the
// step, the gate runs later on a candidate rehydrated from its retained signed
// payload. That arm has its own gate call, so it is bound separately from the
// streamed, batch and lazy arms and needs its own case.
func TestCommitBinding_DeferredAIArmIsBound(t *testing.T) {
	key := newHsecKey(t)
	pks := map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}}
	pol := hsecPolicy(key.keyID, pks)
	secrets := pol.Steps["secrets"]
	secrets.Attestations[0].AiPolicies = []AiPolicy{{Name: "stub", Prompt: "clean?", Model: "stub"}}
	pol.Steps["secrets"] = secrets
	refs := []string{"C-build", "C-secrets-dirty", "P-build", "P-secrets-clean"}
	// The parent is reached only by seeding its digest: edges are no longer
	// followed.
	deferred := []VerifyOption{WithMaxSubjectFanout(50), WithAiProvider(hsecPassAI{}), hsecSeeds(hsecP)}

	accepted, results := hsecVerifySigned(t, key, pol, refs, deferred...)
	require.True(t, accepted, "characterization: unbound, the deferred arm accepts the seeded parent's scan")
	require.Equal(t, []string{"P-secrets-clean"}, hsecPassedRefs(results["secrets"]))

	accepted, results = hsecVerifySigned(t, key, pol, refs, append(deferred, WithCommitBinding(hsecC))...)
	assert.False(t, accepted, "bound: the deferred arm must not accept the parent's scan")
	assert.Empty(t, hsecPassedRefs(results["secrets"]))
	nb, ok := unboundRejections(results["secrets"])["P-secrets-clean"]
	require.True(t, ok, "the parent scan must be refused as unbound; rejected=%v", results["secrets"].Rejected)
	assert.Equal(t, hsecP, nb.WitnessCommit)
}
