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
	"encoding/json"
	"flag"
	"fmt"
	mrand "math/rand"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// formal:differential cilock-policy TestFormalDifferential
// formal:differential cilock-policy TestFormalDifferentialGlobs
//
// Differential test: the Lean model (formal/cilock-policy, `lake exe
// cilock-policy-eval`) against this engine, on random cases plus pinned ones.
// Every disagreement is a model bug or an engine bug.
//
// Boundary. The engine runs for real from the verified source's output down:
// functionary triage, the timestamp constraint, the step gate with real Rego,
// the step loop, the subject fan-out guard, artifactsFrom pruning, and the
// verdict. The verified source itself (DSSE and the signed-subject guard) is
// replaced by a fake that applies the same two rules, with the subject rule
// calling the exported cryptoutil matchability predicate, because DSSE with
// real certificates and TSAs is out of scope here. Raw-key functionaries only.
//
// Skips when `lake` is not on PATH. -formal-diff-n sets the random case count
// (default 300), -formal-diff-seed the seed (default 1).

var (
	formalDiffN    = flag.Int("formal-diff-n", 300, "random cases for TestFormalDifferential")
	formalDiffSeed = flag.Int64("formal-diff-seed", 1, "seed for TestFormalDifferential")
)

const (
	diffMarker = "https://example.com/marker/v1"
	diffChain  = "https://example.com/chain/v1"
	diffT0     = "https://example.com/t0/v1"
	diffT1     = "https://example.com/t1/v1"
)

var diffGateModules = map[int][]byte{
	1: []byte(`package diffgate1

deny[msg] {
	not has_marker
	msg := "no marker in input.steps"
}

has_marker {
	some d
	input.steps[d]["` + diffMarker + `"]
}
`),
	2: []byte(`package diffgate2

deny[msg] {
	object.get(input, "name", "") == "b1"
	msg := "bad body"
}

deny[msg] {
	att := object.get(input, "attestation", {})
	object.get(att, "name", "") == "b1"
	msg := "bad body"
}
`),
}

// --- the case format shared with Main.lean ---

type diffFunctionary struct {
	KeyID string `json:"keyId"`
}
type diffAtt struct {
	Type string `json:"type"`
	Gate int    `json:"gate"`
}
type diffStep struct {
	Name             string            `json:"name"`
	Functionaries    []diffFunctionary `json:"functionaries"`
	Atts             []diffAtt         `json:"atts"`
	ArtifactsFrom    []string          `json:"artifactsFrom"`
	AttestationsFrom []string          `json:"attestationsFrom"`
	AllowedUntracked []string          `json:"allowedUntracked"`
	MaxAge           *int              `json:"maxAge,omitempty"`
}
type diffPolicy struct {
	Expires int        `json:"expires"`
	Keys    []string   `json:"keys"`
	Steps   []diffStep `json:"steps"`
}
type diffOptions struct {
	Now        int      `json:"now"`
	Seeds      []string `json:"seeds"`
	MaxFanout  int      `json:"maxFanout"`
	RequireAll bool     `json:"requireAll"`
}
type diffSubject struct {
	Name  string `json:"name"`
	Alg   string `json:"alg"`
	Value string `json:"value"`
}
type diffAttestor struct {
	Type string `json:"type"`
	Body int    `json:"body"`
}
type diffSig struct {
	Key string `json:"key"`
	OK  bool   `json:"ok"`
}
type diffEnvelope struct {
	Ref       string          `json:"ref"`
	Name      string          `json:"name"`
	Subjects  []diffSubject   `json:"subjects"`
	Attestors []diffAttestor  `json:"attestors"`
	Materials [][]interface{} `json:"materials"`
	Products  [][]interface{} `json:"products"`
	Inline    bool            `json:"inline"`
	Sigs      []diffSig       `json:"sigs"`
	// HardenedGit is the collection's SubjectMatchScope: a hardened git
	// attestation that verified its commit hash opens the SHA-1 arm.
	HardenedGit bool `json:"hardenedGit,omitempty"`
}
type diffCase struct {
	Name      string         `json:"name"`
	Policy    diffPolicy     `json:"policy"`
	Options   diffOptions    `json:"options"`
	Hardening string         `json:"hardening"`
	Evidence  []diffEnvelope `json:"evidence"`
}

// --- the Go side ---

type diffKeys struct {
	ids       []string
	verifiers map[string]cryptoutil.Verifier
}

func newDiffKeys(t *testing.T, n int) diffKeys {
	t.Helper()
	k := diffKeys{verifiers: map[string]cryptoutil.Verifier{}}
	for i := 0; i < n; i++ {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		v := cryptoutil.NewECDSAVerifier(&priv.PublicKey, crypto.SHA256)
		id, err := v.KeyID()
		if err != nil {
			t.Fatal(err)
		}
		k.ids = append(k.ids, id)
		k.verifiers[id] = v
	}
	return k
}

func diffPathSets(rows [][]interface{}) map[string]cryptoutil.DigestSet {
	out := map[string]cryptoutil.DigestSet{}
	for _, r := range rows {
		byName := map[string]string{}
		for _, d := range r[1].([][]string) {
			byName[d[0]] = d[1]
		}
		ds, err := cryptoutil.NewDigestSet(byName)
		if err != nil {
			panic(err)
		}
		out[r[0].(string)] = ds
	}
	return out
}

// diffSubjectMatches mirrors the verified source's subject guard
// (source/verified.go subjectsMatchDigests) with the exported predicate,
// under the collection's hardened-git scope.
func diffSubjectMatches(subjects []diffSubject, seeds []string, hardenedGit bool) bool {
	scope := cryptoutil.SubjectMatchScope{HardenedGitAttested: hardenedGit}
	have := map[string]bool{}
	for _, s := range subjects {
		if scope.IsMatchableSubjectDigest(s.Name, s.Alg, s.Value) {
			have[cryptoutil.SubjectDigestKey(s.Alg, s.Value)] = true
		}
	}
	for _, d := range seeds {
		if have[cryptoutil.NormalizeSubjectSeed(d)] {
			return true
		}
	}
	return false
}

func diffCVR(keys diffKeys, c diffCase, e diffEnvelope) source.CollectionVerificationResult {
	atts := make([]attestation.CollectionAttestation, 0, len(e.Attestors)+1)
	for _, a := range e.Attestors {
		at := &lazyAttestor{AttName: "b" + strconv.Itoa(a.Body), AttType: a.Type}
		atts = append(atts, attestation.CollectionAttestation{Type: at.Type(), Attestation: at})
	}
	prods := map[string]attestation.Product{}
	for p, ds := range diffPathSets(e.Products) {
		prods[p] = attestation.Product{Digest: ds}
	}
	chain := &lazyAttestor{AttName: "chain", AttType: diffChain, materials: diffPathSets(e.Materials), products: prods, inline: e.Inline}
	atts = append(atts, attestation.CollectionAttestation{Type: chain.Type(), Attestation: chain})
	subj := make([]intoto.Subject, 0, len(e.Subjects))
	for _, s := range e.Subjects {
		subj = append(subj, intoto.Subject{Name: s.Name, Digest: map[string]string{s.Alg: s.Value}})
	}
	cvr := source.CollectionVerificationResult{CollectionEnvelope: source.CollectionEnvelope{
		Reference:  e.Ref,
		Statement:  intoto.Statement{Type: intoto.StatementType, Subject: subj, PredicateType: attestation.CollectionType},
		Collection: attestation.Collection{Name: e.Name, Attestations: atts},
	}}
	policyKeys := map[string]bool{}
	for _, k := range c.Policy.Keys {
		policyKeys[k] = true
	}
	for _, s := range e.Sigs {
		if s.OK && policyKeys[s.Key] {
			cvr.Verifiers = append(cvr.Verifiers, keys.verifiers[s.Key])
		}
	}
	switch {
	case len(cvr.Verifiers) == 0:
		cvr.Errors = []error{fmt.Errorf("failed to verify envelope: no verifiers passed")}
	case !diffSubjectMatches(e.Subjects, c.Options.Seeds, e.HardenedGit):
		cvr.Verifiers = nil
		cvr.Errors = []error{fmt.Errorf("collection subject does not match requested artifact digest(s): artifact-substitution guard")}
	}
	return cvr
}

// diffSource is a batch-only source; diffStreamSource adds the streamed arm.
type diffSource struct {
	cvrs []source.CollectionVerificationResult
}

func (s *diffSource) Search(_ context.Context, name string, _ []string, _ []string) ([]source.CollectionVerificationResult, error) {
	var out []source.CollectionVerificationResult
	for _, c := range s.cvrs {
		if c.Collection.Name == name {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *diffSource) SearchByPredicateType(context.Context, []string, []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

type diffStreamSource struct{ diffSource }

func (s *diffStreamSource) SearchStream(ctx context.Context, name string, d, a []string, yield func(source.CollectionVerificationResult) error) error {
	out, _ := s.Search(ctx, name, d, a)
	for _, c := range out {
		if err := yield(c); err != nil {
			return err
		}
	}
	return nil
}

func diffGoVerdict(t *testing.T, keys diffKeys, c diffCase, streamed bool) bool {
	t.Helper()
	steps := map[string]Step{}
	for _, s := range c.Policy.Steps {
		st := Step{Name: s.Name, ArtifactsFrom: s.ArtifactsFrom, AttestationsFrom: s.AttestationsFrom, AllowedUntracked: s.AllowedUntracked}
		for _, f := range s.Functionaries {
			st.Functionaries = append(st.Functionaries, Functionary{Type: "publickey", PublicKeyID: f.KeyID})
		}
		for _, a := range s.Atts {
			att := Attestation{Type: a.Type}
			if m, ok := diffGateModules[a.Gate]; ok {
				att.RegoPolicies = []RegoPolicy{{Module: m, Name: fmt.Sprintf("gate%d.rego", a.Gate)}}
			}
			st.Attestations = append(st.Attestations, att)
		}
		if s.MaxAge != nil {
			st.TimestampConstraint = &TimestampConstraint{MaxAge: fmt.Sprintf("%ds", *s.MaxAge)}
		}
		steps[s.Name] = st
	}
	expires := time.Now().Add(time.Hour)
	if c.Policy.Expires < c.Options.Now {
		expires = time.Now().Add(-time.Hour)
	}
	pol := Policy{Expires: metav1.Time{Time: expires}, Steps: steps}
	cvrs := make([]source.CollectionVerificationResult, 0, len(c.Evidence))
	for _, e := range c.Evidence {
		cvrs = append(cvrs, diffCVR(keys, c, e))
	}
	var src source.VerifiedSourcer = &diffSource{cvrs: cvrs}
	if streamed {
		src = &diffStreamSource{diffSource{cvrs: cvrs}}
	}
	prev := Hardening()
	if c.Hardening == "warn" {
		SetHardening(HardeningOptions{})
	} else {
		SetHardening(holdoutEnforce)
	}
	defer SetHardening(prev)
	opts := []VerifyOption{WithVerifiedSource(src), WithSubjectDigests(c.Options.Seeds)}
	if c.Options.MaxFanout > 0 {
		opts = append(opts, WithMaxSubjectFanout(c.Options.MaxFanout))
	}
	if c.Options.RequireAll {
		opts = append(opts, WithRequireAllArtifacts())
	}
	pass, _, err := pol.Verify(context.Background(), opts...)
	return err == nil && pass
}

// --- case generation ---

func hex64(b byte) string { return strings.Repeat(fmt.Sprintf("%02x", b), 32) }

func diffRandomCase(r *mrand.Rand, keys diffKeys, i int) diffCase {
	seed := hex64(0xaa)
	digests := []string{hex64(0xb1), hex64(0xb2)}
	names := []string{"s0", "s1", "s2"}
	nSteps := 1 + r.Intn(3)
	pick := func(xs []string) string { return xs[r.Intn(len(xs))] }
	c := diffCase{Name: fmt.Sprintf("random-%d", i), Hardening: "enforce",
		Options: diffOptions{Now: 10, Seeds: []string{seed}}}
	if r.Intn(4) == 0 {
		c.Hardening = "warn"
	}
	c.Policy.Expires = 1000
	if r.Intn(20) == 0 {
		c.Policy.Expires = 5
	}
	c.Policy.Keys = []string{}
	for _, k := range keys.ids {
		if r.Intn(6) != 0 {
			c.Policy.Keys = append(c.Policy.Keys, k)
		}
	}
	if r.Intn(3) == 0 {
		c.Options.MaxFanout = 1 + r.Intn(2)
	}
	c.Options.RequireAll = r.Intn(5) == 0
	types := []string{diffT0, diffT1, diffMarker}
	for s := 0; s < nSteps; s++ {
		st := diffStep{Name: names[s], ArtifactsFrom: []string{}, AttestationsFrom: []string{}}
		for f := 0; f < 1+r.Intn(2); f++ {
			st.Functionaries = append(st.Functionaries, diffFunctionary{KeyID: pick(keys.ids)})
		}
		for a := 0; a < 1+r.Intn(2); a++ {
			st.Atts = append(st.Atts, diffAtt{Type: types[r.Intn(2)], Gate: r.Intn(3)})
		}
		for d := 0; d < s; d++ {
			if r.Intn(3) == 0 {
				st.AttestationsFrom = append(st.AttestationsFrom, names[d])
			}
		}
		for d := 0; d < nSteps; d++ {
			if d != s && r.Intn(4) == 0 {
				st.ArtifactsFrom = append(st.ArtifactsFrom, names[d])
			}
		}
		// allowedUntracked only matters under an artifactsFrom edge (#9862).
		if len(st.ArtifactsFrom) > 0 && r.Intn(3) == 0 {
			st.AllowedUntracked = []string{pick([]string{"*.bin", "b.bin", "/tmp/*", "/tmp/**", "**/b.bin", "?.bin", "a*"})}
		}
		if r.Intn(15) == 0 {
			m := 3600
			st.MaxAge = &m
		}
		c.Policy.Steps = append(c.Policy.Steps, st)
	}
	pathSets := func() [][]interface{} {
		var out [][]interface{}
		for _, p := range []string{"a.bin", "b.bin", "/tmp/x/y.sh", "vendor/b.bin"} {
			// The two nested paths are rarer: no step is built to produce
			// them, so they exercise allowedUntracked (#9862).
			odds := 2
			if strings.Contains(p, "/") {
				odds = 6
			}
			if r.Intn(odds) == 0 {
				d := digests[0]
				if r.Intn(4) == 0 {
					d = digests[1]
				}
				out = append(out, []interface{}{p, [][]string{{"sha256", d}}})
			}
		}
		if out == nil {
			out = [][]interface{}{}
		}
		return out
	}
	// Mostly-valid evidence for each step, so verdicts are not all FAIL.
	for s, st := range c.Policy.Steps {
		for e := 0; e < r.Intn(3); e++ {
			env := diffEnvelope{Ref: fmt.Sprintf("v%d-%d", s, e), Name: st.Name, Inline: r.Intn(5) != 0,
				Subjects: []diffSubject{{Name: "x", Alg: "sha256", Value: seed}}}
			if r.Intn(8) == 0 {
				env.Subjects[0].Value = digests[0]
			}
			for _, a := range st.Atts {
				if r.Intn(10) != 0 {
					body := 0
					if r.Intn(6) == 0 {
						body = 1
					}
					env.Attestors = append(env.Attestors, diffAttestor{Type: a.Type, Body: body})
				}
			}
			if r.Intn(2) == 0 {
				env.Attestors = append(env.Attestors, diffAttestor{Type: diffMarker})
			}
			if env.Attestors == nil {
				env.Attestors = []diffAttestor{}
			}
			env.Materials, env.Products = pathSets(), pathSets()
			env.Sigs = []diffSig{{Key: st.Functionaries[r.Intn(len(st.Functionaries))].KeyID, OK: r.Intn(10) != 0}}
			c.Evidence = append(c.Evidence, env)
		}
	}
	// Noise.
	for e := 0; e < r.Intn(4); e++ {
		env := diffEnvelope{Ref: fmt.Sprintf("r%d", e), Name: names[r.Intn(nSteps+1)%3], Inline: r.Intn(3) != 0}
		switch r.Intn(5) {
		case 0:
			env.Subjects = []diffSubject{{Name: "x", Alg: "sha256", Value: pick(digests)}}
		case 1:
			env.Subjects = []diffSubject{{Name: "x", Alg: "gitoid:sha256", Value: seed}}
		default:
			env.Subjects = []diffSubject{{Name: "x", Alg: "sha256", Value: seed}}
		}
		for a := 0; a < 1+r.Intn(3); a++ {
			env.Attestors = append(env.Attestors, diffAttestor{Type: types[r.Intn(3)], Body: r.Intn(3)})
		}
		env.Materials, env.Products = pathSets(), pathSets()
		for s := 0; s < 1+r.Intn(2); s++ {
			env.Sigs = append(env.Sigs, diffSig{Key: pick(keys.ids), OK: r.Intn(6) != 0})
		}
		c.Evidence = append(c.Evidence, env)
	}
	if c.Evidence == nil {
		c.Evidence = []diffEnvelope{}
	}
	return c
}

// diffPinnedCases are the traces the model's counterexamples are about.
func diffPinnedCases(keys diffKeys) []diffCase {
	k := keys.ids[0]
	seed := hex64(0xaa)
	built, other := hex64(0xb1), hex64(0xb2)
	sig := []diffSig{{Key: k, OK: true}}
	subj := []diffSubject{{Name: "x", Alg: "sha256", Value: seed}}
	one := func(name string, gate int) diffStep {
		return diffStep{Name: name, Functionaries: []diffFunctionary{{KeyID: k}}, Atts: []diffAtt{{Type: diffT0, Gate: gate}},
			ArtifactsFrom: []string{}, AttestationsFrom: []string{}}
	}
	env := func(ref, name string, extra []diffAttestor, mats, prods [][]interface{}) diffEnvelope {
		if mats == nil {
			mats = [][]interface{}{}
		}
		if prods == nil {
			prods = [][]interface{}{}
		}
		return diffEnvelope{Ref: ref, Name: name, Subjects: subj, Attestors: append([]diffAttestor{{Type: diffT0}}, extra...),
			Materials: mats, Products: prods, Inline: true, Sigs: sig}
	}
	ds := func(p, d string) [][]interface{} { return [][]interface{}{{p, [][]string{{"sha256", d}}}} }
	scan := one("s1", 0)
	scan.ArtifactsFrom = []string{"s0"}
	gate := one("s2", 1)
	gate.AttestationsFrom = []string{"s1"}
	launder := diffPolicy{Expires: 1000, Keys: []string{k}, Steps: []diffStep{one("s0", 0), scan, gate}}
	opts := diffOptions{Now: 10, Seeds: []string{seed}}
	source0 := env("src", "s0", nil, nil, ds("app.bin", built))
	scanClean := env("a-scan-clean", "s1", []diffAttestor{{Type: diffMarker}}, ds("app.bin", other), nil)
	scanReal := env("b-scan-real", "s1", nil, ds("app.bin", built), nil)
	gateC := env("gate", "s2", nil, nil, nil)
	build := one("s1", 0)
	build.ArtifactsFrom = []string{"s0"}
	allow := func(g string) diffStep {
		s := build
		s.AllowedUntracked = []string{g}
		return s
	}
	injected := env("inj", "s1", nil, [][]interface{}{{"app.bin", [][]string{{"sha256", built}}}, {"/tmp/x.sh", [][]string{{"sha256", other}}}}, nil)
	return append([]diffCase{
		{Name: "launder-9813-control", Policy: launder, Options: opts, Hardening: "enforce", Evidence: []diffEnvelope{source0, scanReal, gateC}},
		{Name: "launder-9813-flooded", Policy: launder, Options: opts, Hardening: "enforce", Evidence: []diffEnvelope{source0, scanClean, scanReal, gateC}},
		{Name: "untracked-9815", Policy: diffPolicy{Expires: 1000, Keys: []string{k}, Steps: []diffStep{one("s0", 0), build}}, Options: opts, Hardening: "enforce", Evidence: []diffEnvelope{source0, injected}},
		{Name: "untracked-9815-warn", Policy: diffPolicy{Expires: 1000, Keys: []string{k}, Steps: []diffStep{one("s0", 0), build}}, Options: opts, Hardening: "warn", Evidence: []diffEnvelope{source0, injected}},
		{Name: "untracked-9815-allowed", Policy: diffPolicy{Expires: 1000, Keys: []string{k}, Steps: []diffStep{one("s0", 0), allow("/tmp/*")}}, Options: opts, Hardening: "enforce", Evidence: []diffEnvelope{source0, injected}},
		{Name: "untracked-9815-star-one-segment", Policy: diffPolicy{Expires: 1000, Keys: []string{k}, Steps: []diffStep{one("s0", 0), allow("/*")}}, Options: opts, Hardening: "enforce", Evidence: []diffEnvelope{source0, injected}},
		{Name: "algorithm-label-9816", Policy: diffPolicy{Expires: 1000, Keys: []string{k}, Steps: []diffStep{one("s0", 0)}}, Options: opts, Hardening: "enforce",
			Evidence: []diffEnvelope{{Ref: "r", Name: "s0", Subjects: []diffSubject{{Name: "x", Alg: "gitoid:sha256", Value: seed}}, Attestors: []diffAttestor{{Type: diffT0}}, Materials: [][]interface{}{}, Products: [][]interface{}{}, Sigs: sig}}},
		{Name: "fanout-flood", Policy: diffPolicy{Expires: 1000, Keys: []string{k}, Steps: []diffStep{one("s0", 0)}}, Options: diffOptions{Now: 10, Seeds: []string{seed}, MaxFanout: 1}, Hardening: "enforce",
			Evidence: []diffEnvelope{env("g", "s0", nil, nil, nil), {Ref: "x", Name: "s0", Subjects: subj, Attestors: []diffAttestor{{Type: diffT1}}, Materials: [][]interface{}{}, Products: [][]interface{}{}, Sigs: sig}}},
	}, diffCommitSubjectCases(k, one("s0", 0))...)
}

// diffCommitSubjectCases pin the hardened-git SHA-1 arm (isGitCommitSubject):
// a one-step policy that passes exactly when its only subject anchors.
func diffCommitSubjectCases(k string, step diffStep) []diffCase {
	const sha = "3d7b1c0e9f2a4b6c8d0e1f2a3b4c5d6e7f8a9b0c"
	const null = "0000000000000000000000000000000000000000"
	gitType := "https://aflock.ai/attestations/git/v0.1"
	one := func(name, subjName, value string, hardened bool) diffCase {
		return diffCase{Name: name, Policy: diffPolicy{Expires: 1000, Keys: []string{k}, Steps: []diffStep{step}},
			Options: diffOptions{Now: 10, Seeds: []string{value}}, Hardening: "enforce",
			Evidence: []diffEnvelope{{Ref: "r", Name: "s0", Subjects: []diffSubject{{Name: subjName, Alg: "sha1", Value: value}},
				Attestors: []diffAttestor{{Type: diffT0}}, Materials: [][]interface{}{}, Products: [][]interface{}{},
				Sigs: []diffSig{{Key: k, OK: true}}, HardenedGit: hardened}}}
	}
	return []diffCase{
		one("commit-bare", "commithash:"+sha, sha, true),
		one("commit-bare-not-hardened", "commithash:"+sha, sha, false),
		one("commit-null-oid", "commithash:"+null, null, true),
		one("commit-digest-case-folded", "commithash:"+strings.ToUpper(sha), sha, true),
		one("commit-git-namespace", gitType+"/commithash:"+sha, sha, true),
		one("commit-foreign-namespace", "https://aflock.ai/attestations/sbom/v0.1/commithash:"+sha, sha, true),
		one("commit-git-type-case-variant", "https://aflock.ai/attestations/GIT/v0.1/commithash:"+sha, sha, true),
		one("commit-no-segment-boundary", "notacommithash:"+sha, sha, true),
	}
}

// --- the Lean side ---

// diffLeanRun builds the oracle and runs it once on the given JSON input.
func diffLeanRun(t *testing.T, in []byte, args ...string) []string {
	t.Helper()
	lake, err := exec.LookPath("lake")
	if err != nil {
		t.Skip("lake not on PATH; the differential test needs the Lean toolchain")
	}
	dir := filepath.Join("..", "..", "formal", "cilock-policy")
	build := exec.Command(lake, "build", "cilock-policy-eval")
	build.Dir = dir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("lake build cilock-policy-eval: %v\n%s", err, out)
	}
	run := exec.Command(filepath.Join(dir, ".lake", "build", "bin", "cilock-policy-eval"), args...)
	run.Stdin = bytes.NewReader(in)
	out, err := run.Output()
	if err != nil {
		t.Fatalf("cilock-policy-eval: %v", err)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

func diffLeanVerdicts(t *testing.T, cases []diffCase, args ...string) []string {
	t.Helper()
	in, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	lines := diffLeanRun(t, in, args...)
	if len(lines) != len(cases) {
		t.Fatalf("lean printed %d verdicts for %d cases:\n%s", len(lines), len(cases), strings.Join(lines, "\n"))
	}
	return lines
}

func TestFormalDifferential(t *testing.T) {
	n, seed := *formalDiffN, *formalDiffSeed
	keys := newDiffKeys(t, 3)
	cases := diffPinnedCases(keys)
	r := mrand.New(mrand.NewSource(seed))
	for i := 0; i < n; i++ {
		cases = append(cases, diffRandomCase(r, keys, i))
	}
	// The engine ships the round-bounded #9813 fix (#9860), which the model
	// states as verifyFix9813.
	lean := diffLeanVerdicts(t, cases, "--fix9813")
	// The pre-#9860 as-built semantics, as a sensitivity check on the harness
	// itself: it MUST disagree with the engine on the laundering case, or the
	// harness cannot see a difference and a zero mismatch count means nothing.
	asBuilt := diffLeanVerdicts(t, cases)
	mismatches, passes, asBuiltDiffers := 0, 0, 0
	sawLaunder := false
	for i, c := range cases {
		batch := diffGoVerdict(t, keys, c, false)
		streamed := diffGoVerdict(t, keys, c, true)
		if batch {
			passes++
		}
		if batch != streamed {
			t.Errorf("%s: batch arm %v, streamed arm %v", c.Name, batch, streamed)
		}
		if lean[i] != strconv.FormatBool(batch) {
			mismatches++
			js, _ := json.Marshal(c)
			t.Errorf("%s: Go %v, Lean %s\n%s", c.Name, batch, lean[i], js)
		}
		if asBuilt[i] != strconv.FormatBool(batch) {
			asBuiltDiffers++
			if c.Name == "launder-9813-flooded" {
				sawLaunder = true
			}
		}
	}
	if !sawLaunder {
		t.Errorf("sensitivity: the pre-#9860 model must disagree with the engine on launder-9813-flooded")
	}
	t.Logf("differential: %d cases (%d pinned, %d random, seed %d), %d Go passes, %d mismatches; "+
		"the pre-#9860 semantics differs from the engine on %d case(s)",
		len(cases), len(cases)-n, n, seed, passes, mismatches, asBuiltDiffers)
}

// --- glob matchers ---

type diffGlobCase struct {
	Kind    string `json:"kind"`
	Pattern string `json:"pattern"`
	Value   string `json:"value"`
}

// diffGlobCases enumerates every pattern of up to three tokens over
// {a, b, *, **, ?, /} against every value of up to four characters over
// {a, b, /}. Untracked values are kept only when path.Clean leaves them
// unchanged: the model takes material paths as already clean. A run of three
// or more '*' is left out: the model does not specify it, and gobwas reads
// "a***" as refusing "a".
func diffGlobCases() []diffGlobCase {
	tokens := []string{"a", "b", "*", "**", "?", "/"}
	var pats []string
	seen := map[string]bool{}
	var grow func(prefix string, n int)
	grow = func(prefix string, n int) {
		if prefix != "" && !seen[prefix] && !strings.Contains(prefix, "***") {
			seen[prefix] = true
			pats = append(pats, prefix)
		}
		if n == 0 {
			return
		}
		for _, t := range tokens {
			grow(prefix+t, n-1)
		}
	}
	grow("", 3)
	vals := []string{""}
	for frontier := []string{""}; len(frontier[0]) < 4; {
		var next []string
		for _, v := range frontier {
			for _, c := range []string{"a", "b", "/"} {
				next = append(next, v+c)
			}
		}
		vals = append(vals, next...)
		frontier = next
	}
	var out []diffGlobCase
	for _, p := range pats {
		for _, v := range vals {
			out = append(out, diffGlobCase{Kind: "cert", Pattern: p, Value: v})
			if v == "" || path.Clean(v) == v {
				out = append(out, diffGlobCase{Kind: "untracked", Pattern: p, Value: v})
			}
		}
	}
	return out
}

func diffGoGlob(t *testing.T, c diffGlobCase) bool {
	t.Helper()
	if c.Kind == "cert" {
		g, err := compileCertGlob(c.Pattern)
		if err != nil {
			t.Fatalf("compileCertGlob(%q): %v", c.Pattern, err)
		}
		return g.Match(c.Value)
	}
	m, err := compileAllowedUntracked([]string{c.Pattern})
	if err != nil {
		t.Fatalf("compileAllowedUntracked(%q): %v", c.Pattern, err)
	}
	return m.matches(c.Value)
}

// diffGlobKnownEngineDivergence are inputs where the engine's allowedUntracked
// matcher admits a path the pattern does not describe. gobwas lets the literal
// on each side of '**' overlap, so "a**a" matches "a": the defect #9867 took
// cert-constraint globs off gobwas for. The model states the pattern's meaning
// (LinkingCounterexamples.v6_overlap_not_allowed). Each entry must still
// diverge: when the matcher is fixed the test fails and the entry is deleted.
var diffGlobKnownEngineDivergence = map[diffGlobCase]bool{
	{Kind: "untracked", Pattern: "a**a", Value: "a"}: true,
	{Kind: "untracked", Pattern: "b**b", Value: "b"}: true,
	{Kind: "untracked", Pattern: "/**/", Value: "/"}: true,
}

// TestFormalDifferentialGlobs holds the two glob matchers the verdict reads to
// the model: certGlob (cert constraints, RE2 since #9867) and the
// allowedUntracked matcher (#9862, gobwas with '/' as separator).
func TestFormalDifferentialGlobs(t *testing.T) {
	cases := diffGlobCases()
	in, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	lean := diffLeanRun(t, in, "--glob")
	if len(lean) != len(cases) {
		t.Fatalf("lean printed %d verdicts for %d cases", len(lean), len(cases))
	}
	mismatches, known := 0, 0
	for i, c := range cases {
		got := diffGoGlob(t, c)
		agree := lean[i] == strconv.FormatBool(got)
		switch {
		case diffGlobKnownEngineDivergence[c] && agree:
			t.Errorf("%s %q %q: the engine now agrees with the model; delete it from diffGlobKnownEngineDivergence", c.Kind, c.Pattern, c.Value)
		case diffGlobKnownEngineDivergence[c]:
			known++
		case !agree:
			mismatches++
			t.Errorf("%s %q %q: Go %v, Lean %s", c.Kind, c.Pattern, c.Value, got, lean[i])
		}
	}
	if known != len(diffGlobKnownEngineDivergence) {
		t.Errorf("%d of %d known divergences were generated; the enumeration no longer covers them", known, len(diffGlobKnownEngineDivergence))
	}
	t.Logf("glob differential: %d cases, %d mismatches, %d known engine divergences", len(cases), mismatches, known)
}
