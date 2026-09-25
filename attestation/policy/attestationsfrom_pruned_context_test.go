// jade:ring local
// Copyright 2026 The Witness Contributors
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
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #9813: an attestationsFrom dependent's Rego input was built from its
// dependency's PRE-pruning Passed set. A dependency collection that the
// artifactsFrom chain check later rejects had already been fed to the
// dependent's Rego, so a policy could flip FAIL→PASS on evidence about a
// different artifact.
//
// Shape: source (product app.bin=built) ← scan (artifactsFrom=[source]) ←
// gate (attestationsFrom=[scan]; Rego needs a "clean" marker in scan).

const prunedCtxCleanType = "https://example.com/pruned-ctx-clean/v1"

const prunedCtxWrongChainRef = "a-scan-clean"

// Denies unless the scan step carries the clean marker.
var prunedCtxRequireClean = []byte(`package prunedctx

deny[msg] {
	not input.steps.scan["` + prunedCtxCleanType + `"]
	msg := "no clean scan result"
}
`)

// Denies when the wrong-chain collection is VISIBLE in the Rego input through
// either view (collections list or the legacy per-type key). A pass therefore
// proves the rejected collection never reached the dependent's input.
var prunedCtxProbeAbsent = []byte(`package prunedctx

deny[msg] {
	input.steps.scan.collections[_].reference == "` + prunedCtxWrongChainRef + `"
	msg := "wrong-chain scan collection reached rego input"
}

deny[msg] {
	input.steps.scan["` + prunedCtxCleanType + `"]
	msg := "wrong-chain clean marker reached rego input"
}
`)

// Non-monotone rule: exactly one upstream scan collection. The count sits in a
// helper rule so a missing scan step denies too (a bare `count(...) != 1`
// is undefined, and so silent, when the step is absent).
var prunedCtxExactlyOne = []byte(`package prunedctx

exactly_one {
	count(input.steps.scan.collections) == 1
}

deny[msg] {
	not exactly_one
	msg := "want exactly one scan collection"
}
`)

type prunedCtxArm struct {
	name string
	// wrap turns the streaming fixture into the source handed to Verify.
	wrap func(*lazySource) source.VerifiedSourcer
	opts []VerifyOption
}

func prunedCtxArms() []prunedCtxArm {
	return []prunedCtxArm{
		{name: "batch", wrap: func(s *lazySource) source.VerifiedSourcer { return lazyBatchSource{inner: s} }},
		{name: "streamed", wrap: func(s *lazySource) source.VerifiedSourcer { return s }},
		{
			name: "streamed-lazy",
			wrap: func(s *lazySource) source.VerifiedSourcer { return s },
			opts: []VerifyOption{WithLazyStepSatisfaction(true)},
		},
	}
}

type prunedCtxCorpus struct {
	wrongChainClean bool           // a-scan-clean: marker present, chain broken
	realClean       bool           // the chain-linked scan carries the marker too
	aiStep          string         // step whose required attestation also carries an AI policy
	extra           []VerifyOption // appended to the arm's options
}

func prunedCtxRun(t testing.TB, arm prunedCtxArm, corpus prunedCtxCorpus, gateRego []byte) (bool, map[string]StepResult) {
	t.Helper()
	var v cryptoutil.Verifier
	var keyID string
	if b, ok := t.(*testing.B); ok {
		v, keyID = earlyExitVerifierB(b)
	} else {
		v, keyID = earlyExitVerifier(t.(*testing.T))
	}
	built := lazyDigest("aa11")
	other := lazyDigest("bb22")

	src := lazyCollection(v, "source-1", "source", "",
		&lazyAttestor{AttName: "source-1", AttType: lazyAttType},
		&lazyAttestor{AttName: "source-1-prod", AttType: lazyChainAttType,
			products: map[string]attestation.Product{"app.bin": {Digest: built}}, inline: true})
	// A genuine, signed, clean scan of a DIFFERENT input: its material chain
	// does not link to source.
	scanWrongChain := lazyCollection(v, prunedCtxWrongChainRef, "scan", "",
		&lazyAttestor{AttName: prunedCtxWrongChainRef, AttType: lazyAttType},
		&lazyAttestor{AttName: "clean-marker", AttType: prunedCtxCleanType},
		&lazyAttestor{AttName: "a-scan-clean-mat", AttType: lazyChainAttType,
			materials: map[string]cryptoutil.DigestSet{"app.bin": other}, inline: true})
	realAttestors := []attestation.Attestor{
		&lazyAttestor{AttName: "b-scan-real", AttType: lazyAttType},
		&lazyAttestor{AttName: "b-scan-real-mat", AttType: lazyChainAttType,
			materials: map[string]cryptoutil.DigestSet{"app.bin": built}, inline: true},
	}
	if corpus.realClean {
		realAttestors = append(realAttestors, &lazyAttestor{AttName: "real-clean-marker", AttType: prunedCtxCleanType})
	}
	scanReal := lazyCollection(v, "b-scan-real", "scan", "", realAttestors...)
	gate := lazyCollection(v, "gate-1", "gate", "", &lazyAttestor{AttName: "gate-1", AttType: lazyAttType})

	scanStep := lazyStep("scan", keyID)
	scanStep.ArtifactsFrom = []string{"source"}
	gateStep := Step{
		Name:             "gate",
		Functionaries:    []Functionary{{PublicKeyID: keyID}},
		AttestationsFrom: []string{"scan"},
		Attestations: []Attestation{{
			Type:         lazyAttType,
			RegoPolicies: []RegoPolicy{{Module: gateRego, Name: "gate.rego"}},
		}},
	}
	cands := []source.CollectionVerificationResult{src, scanReal, gate}
	if corpus.wrongChainClean {
		cands = []source.CollectionVerificationResult{src, scanWrongChain, scanReal, gate}
	}
	pol := lazyPolicy(keyID, lazyStep("source", keyID), scanStep, gateStep)
	if corpus.aiStep != "" {
		step := pol.Steps[corpus.aiStep]
		atts := append([]Attestation(nil), step.Attestations...)
		atts[0].AiPolicies = []AiPolicy{{Name: "clean", Prompt: "is this clean?", Model: "stub"}}
		step.Attestations = atts
		pol.Steps[corpus.aiStep] = step
	}
	s := newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": cands})
	opts := append([]VerifyOption{WithVerifiedSource(arm.wrap(s)), WithSubjectDigests([]string{"sha256:seed"})}, arm.opts...)
	opts = append(opts, corpus.extra...)
	pass, results, err := pol.Verify(context.Background(), opts...)
	require.NoError(t, err)
	return pass, results
}

func prunedCtxRefs(cs []PassedCollection) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Collection.Reference)
	}
	return out
}

func prunedCtxRejectedRefs(cs []RejectedCollection) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Collection.Reference)
	}
	return out
}

// The reproduction from #9813, on every source arm: a wrong-chain "clean"
// scan must not turn the control FAIL into a PASS.
func TestAttestationsFromContextExcludesArtifactPrunedCollections(t *testing.T) {
	for _, arm := range prunedCtxArms() {
		t.Run(arm.name, func(t *testing.T) {
			passCtl, resCtl := prunedCtxRun(t, arm, prunedCtxCorpus{}, prunedCtxRequireClean)
			require.False(t, passCtl, "control: the only chain-linked scan carries no clean marker, so the gate must FAIL")
			assert.Empty(t, resCtl["gate"].Passed)

			pass, res := prunedCtxRun(t, arm, prunedCtxCorpus{wrongChainClean: true}, prunedCtxRequireClean)
			assert.False(t, pass, "a scan collection rejected for a broken artifactsFrom chain laundered a PASS through the gate's Rego (#9813)")
			assert.NotContains(t, prunedCtxRefs(res["scan"].Passed), prunedCtxWrongChainRef, "wrong-chain scan must not survive artifact verification")
			assert.Contains(t, prunedCtxRejectedRefs(res["scan"].Rejected), prunedCtxWrongChainRef, "wrong-chain scan must be recorded as rejected")
			assert.Empty(t, res["gate"].Passed, "gate must not pass on a context holding the rejected scan")
		})
	}
}

// Direct observation of the dependent's Rego input: the probe gate denies if
// the rejected collection is visible through either input.steps view.
func TestAttestationsFromContextNeverShowsRejectedCollectionToRego(t *testing.T) {
	for _, arm := range prunedCtxArms() {
		t.Run(arm.name, func(t *testing.T) {
			pass, res := prunedCtxRun(t, arm, prunedCtxCorpus{wrongChainClean: true}, prunedCtxProbeAbsent)
			assert.True(t, pass, "the rejected wrong-chain scan was visible in gate's Rego input: gate rejected=%v", res["gate"].Rejected)
			assert.Equal(t, []string{"gate-1"}, prunedCtxRefs(res["gate"].Passed))
		})
	}
}

// The fixed point must not cost a legitimate pass: a chain-linked clean scan
// still satisfies the gate alongside a rejected sibling.
func TestAttestationsFromContextKeepsLegitimatePass(t *testing.T) {
	for _, arm := range prunedCtxArms() {
		t.Run(arm.name, func(t *testing.T) {
			pass, res := prunedCtxRun(t, arm, prunedCtxCorpus{wrongChainClean: true, realClean: true}, prunedCtxRequireClean)
			assert.True(t, pass, "gate rejected=%v", res["gate"].Rejected)
			assert.Equal(t, []string{"b-scan-real"}, prunedCtxRefs(res["scan"].Passed))
		})
	}
}

// A non-monotone rule is judged on the converged set: with the wrong-chain
// scan pruned exactly one scan remains, so "exactly one" holds. A gate
// collection REJECTED under the unconverged context must be re-evaluated, not
// merely have its passes filtered.
func TestAttestationsFromContextReevaluatesRejectedDependents(t *testing.T) {
	for _, arm := range prunedCtxArms() {
		t.Run(arm.name, func(t *testing.T) {
			pass, res := prunedCtxRun(t, arm, prunedCtxCorpus{wrongChainClean: true}, prunedCtxExactlyOne)
			assert.True(t, pass, "gate rejected=%v", res["gate"].Rejected)
		})
	}
}

// Batch and streamed arms must reach the same verdict and the same Passed sets
// on every corpus and rule (#7572 verdict identity).
func TestAttestationsFromContextArmsAgree(t *testing.T) {
	rules := map[string][]byte{"require-clean": prunedCtxRequireClean, "probe": prunedCtxProbeAbsent, "exactly-one": prunedCtxExactlyOne}
	corpora := []prunedCtxCorpus{{}, {wrongChainClean: true}, {realClean: true}, {wrongChainClean: true, realClean: true}}
	arms := prunedCtxArms()
	for ruleName, rule := range rules {
		for _, corpus := range corpora {
			basePass, baseRes := prunedCtxRun(t, arms[0], corpus, rule)
			for _, arm := range arms[1:] {
				pass, res := prunedCtxRun(t, arm, corpus, rule)
				assert.Equal(t, basePass, pass, "%s %+v: %s verdict differs from batch", ruleName, corpus, arm.name)
				for _, step := range []string{"source", "scan", "gate"} {
					assert.Equal(t, prunedCtxRefs(baseRes[step].Passed), prunedCtxRefs(res[step].Passed), "%s %+v: %s Passed[%s] differs from batch", ruleName, corpus, arm.name, step)
				}
			}
		}
	}
}

// Cost of the fixed point on the #9813 shape: the control corpus converges in
// one round, the wrong-chain corpus needs a second.
func BenchmarkAttestationsFromContext(b *testing.B) {
	for _, bc := range []struct {
		name   string
		corpus prunedCtxCorpus
	}{{"control", prunedCtxCorpus{}}, {"wrong-chain", prunedCtxCorpus{wrongChainClean: true}}} {
		for _, arm := range prunedCtxArms()[:2] {
			b.Run(bc.name+"/"+arm.name, func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					prunedCtxRun(b, arm, bc.corpus, prunedCtxRequireClean)
				}
			})
		}
	}
}

func prunedCtxRegoStep(name, keyID string, rego string, from ...string) Step {
	return Step{
		Name:             name,
		Functionaries:    []Functionary{{PublicKeyID: keyID}},
		AttestationsFrom: from,
		Attestations: []Attestation{{
			Type:         lazyAttType,
			RegoPolicies: []RegoPolicy{{Module: []byte(rego), Name: name + ".rego"}},
		}},
	}
}

// A dependency set must be able to GROW back across rounds, not only shrink.
//
// source ← x (artifactsFrom) ← build (attestationsFrom x, "exactly one x")
// ← scan (artifactsFrom build) ← gate (attestationsFrom scan, "clean").
//
// Round 1: build sees both x collections and fails, so scan has no upstream
// and is pruned. Round 2: build sees only the chain-linked x and passes, and
// scan now survives, but gate was judged on round 1's empty scan set. Round 3:
// gate sees the surviving scan. A context that could only shrink would never
// re-admit scan and would refuse a policy whose converged evidence passes.
func TestAttestationsFromContextRegrowsAcrossRounds(t *testing.T) {
	for _, arm := range prunedCtxArms() {
		t.Run(arm.name, func(t *testing.T) {
			v, keyID := earlyExitVerifier(t)
			built, other, out := lazyDigest("aa11"), lazyDigest("bb22"), lazyDigest("cc33")

			cands := []source.CollectionVerificationResult{
				lazyCollection(v, "source-1", "source", "",
					&lazyAttestor{AttName: "source-1", AttType: lazyAttType},
					&lazyAttestor{AttName: "source-1-prod", AttType: lazyChainAttType,
						products: map[string]attestation.Product{"app.bin": {Digest: built}}, inline: true}),
				lazyCollection(v, "x-good", "x", "",
					&lazyAttestor{AttName: "x-good", AttType: lazyAttType},
					&lazyAttestor{AttName: "x-good-mat", AttType: lazyChainAttType,
						materials: map[string]cryptoutil.DigestSet{"app.bin": built}, inline: true}),
				lazyCollection(v, "x-wrong", "x", "",
					&lazyAttestor{AttName: "x-wrong", AttType: lazyAttType},
					&lazyAttestor{AttName: "x-wrong-mat", AttType: lazyChainAttType,
						materials: map[string]cryptoutil.DigestSet{"app.bin": other}, inline: true}),
				lazyCollection(v, "build-1", "build", "",
					&lazyAttestor{AttName: "build-1", AttType: lazyAttType},
					&lazyAttestor{AttName: "build-1-prod", AttType: lazyChainAttType,
						products: map[string]attestation.Product{"out.bin": {Digest: out}}, inline: true}),
				lazyCollection(v, "scan-1", "scan", "",
					&lazyAttestor{AttName: "scan-1", AttType: lazyAttType},
					&lazyAttestor{AttName: "clean-marker", AttType: prunedCtxCleanType},
					&lazyAttestor{AttName: "scan-1-mat", AttType: lazyChainAttType,
						materials: map[string]cryptoutil.DigestSet{"out.bin": out}, inline: true}),
				lazyCollection(v, "gate-1", "gate", "", &lazyAttestor{AttName: "gate-1", AttType: lazyAttType}),
			}

			xStep := lazyStep("x", keyID)
			xStep.ArtifactsFrom = []string{"source"}
			scanStep := lazyStep("scan", keyID)
			scanStep.ArtifactsFrom = []string{"build"}
			pol := lazyPolicy(keyID,
				lazyStep("source", keyID), xStep, scanStep,
				prunedCtxRegoStep("build", keyID, `package prunedctx
exactly_one {
	count(input.steps.x.collections) == 1
}

deny[msg] {
	not exactly_one
	msg := "want exactly one x collection"
}
`, "x"),
				prunedCtxRegoStep("gate", keyID, string(prunedCtxRequireClean), "scan"),
			)
			s := newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": cands})
			opts := append([]VerifyOption{WithVerifiedSource(arm.wrap(s)), WithSubjectDigests([]string{"sha256:seed"})}, arm.opts...)
			pass, res, err := pol.Verify(context.Background(), opts...)
			require.NoError(t, err)
			assert.True(t, pass, "build rejected=%v scan rejected=%v gate rejected=%v", res["build"].Rejected, res["scan"].Rejected, res["gate"].Rejected)
			assert.Equal(t, []string{"x-good"}, prunedCtxRefs(res["x"].Passed))
			assert.Equal(t, []string{"scan-1"}, prunedCtxRefs(res["scan"].Passed))
			assert.Equal(t, []string{"gate-1"}, prunedCtxRefs(res["gate"].Passed))
		})
	}
}

// prunedCtxOscillator is a combined cycle: d artifactsFrom s, s
// attestationsFrom d. s passes only while d is empty, and d survives pruning
// only while s passes, so no context ever equals its surviving evidence.
func prunedCtxOscillator(t *testing.T) (Policy, *lazySource) {
	v, keyID := earlyExitVerifier(t)
	m := lazyDigest("dd44")
	cands := []source.CollectionVerificationResult{
		lazyCollection(v, "d-1", "d", "",
			&lazyAttestor{AttName: "d-1", AttType: lazyAttType},
			&lazyAttestor{AttName: "d-1-mat", AttType: lazyChainAttType,
				materials: map[string]cryptoutil.DigestSet{"m.bin": m}, inline: true}),
		lazyCollection(v, "s-1", "s", "",
			&lazyAttestor{AttName: "s-1", AttType: lazyAttType},
			&lazyAttestor{AttName: "s-1-prod", AttType: lazyChainAttType,
				products: map[string]attestation.Product{"m.bin": {Digest: m}}, inline: true}),
	}
	dStep := lazyStep("d", keyID)
	dStep.ArtifactsFrom = []string{"s"}
	pol := lazyPolicy(keyID, dStep, prunedCtxRegoStep("s", keyID, `package prunedctx
deny[msg] {
	input.steps.d
	msg := "d must be empty"
}
`, "d"))
	return pol, newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": cands})
}

// The round bound holds only when attestationsFrom ∪ artifactsFrom is acyclic
// (the Lean policy model refuted it on a combined cycle whose fixed point is a
// PASS), so Validate refuses the union's cycles and names every hop.
func TestAttestationsFromContextCombinedCycleRejectedAtValidate(t *testing.T) {
	cases := []struct {
		name  string
		steps []Step
		want  ErrCircularDependency
	}{
		{
			// The Lean counterexample's shape.
			name: "artifactsFrom-then-attestationsFrom",
			steps: []Step{
				{Name: "a", ArtifactsFrom: []string{"b"}},
				{Name: "b", AttestationsFrom: []string{"a"}},
			},
			want: ErrCircularDependency{Steps: []string{"a", "b", "a"}, Edges: []string{"artifactsFrom", "attestationsFrom"}},
		},
		{
			name: "three-step-mixed",
			steps: []Step{
				{Name: "a", AttestationsFrom: []string{"b"}},
				{Name: "b", ArtifactsFrom: []string{"c"}},
				{Name: "c", AttestationsFrom: []string{"a"}},
			},
			want: ErrCircularDependency{Steps: []string{"a", "b", "c", "a"}, Edges: []string{"attestationsFrom", "artifactsFrom", "attestationsFrom"}},
		},
		{
			// Already refused by cilock's static validator; the engine now agrees.
			name: "artifactsFrom-pair",
			steps: []Step{
				{Name: "a", ArtifactsFrom: []string{"b"}},
				{Name: "b", ArtifactsFrom: []string{"a"}},
			},
			want: ErrCircularDependency{Steps: []string{"a", "b", "a"}, Edges: []string{"artifactsFrom", "artifactsFrom"}},
		},
		{
			name:  "artifactsFrom-self",
			steps: []Step{{Name: "a", ArtifactsFrom: []string{"a"}}},
			want:  ErrCircularDependency{Steps: []string{"a", "a"}, Edges: []string{"artifactsFrom"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := Policy{Steps: map[string]Step{}}
			for _, s := range tc.steps {
				p.Steps[s.Name] = s
			}
			var got ErrCircularDependency
			require.ErrorAs(t, p.Validate(), &got)
			assert.Equal(t, tc.want, got)
			assert.Contains(t, got.Error(), "a -["+tc.want.Edges[0]+"]-> ")
		})
	}

	// And end to end: Verify refuses the oscillator before searching anything.
	pol, s := prunedCtxOscillator(t)
	_, _, err := pol.Verify(context.Background(), WithVerifiedSource(s), WithSubjectDigests([]string{"sha256:seed"}))
	var cycle ErrCircularDependency
	require.ErrorAs(t, err, &cycle)
	assert.Equal(t, []string{"artifactsFrom", "attestationsFrom"}, cycle.Edges)
	assert.Zero(t, s.searches, "a refused policy must not search")

	// Acyclic union: the mixed shape pointing one way is still valid.
	ok := Policy{Steps: map[string]Step{
		"a": {Name: "a", ArtifactsFrom: []string{"b"}},
		"b": {Name: "b", AttestationsFrom: []string{"c"}},
		"c": {Name: "c"},
	}}
	require.NoError(t, ok.Validate())
}

// ErrAttestationsFromNotConverged stays as the defensive exit. It cannot be
// reached through Verify on a validated policy, so the loop is driven directly
// on the oscillator Validate would refuse.
func TestAttestationsFromContextNonConvergenceFailsClosed(t *testing.T) {
	for _, arm := range prunedCtxArms() {
		t.Run(arm.name, func(t *testing.T) {
			pol, s := prunedCtxOscillator(t)
			vo := &verifyOptions{}
			for _, opt := range append([]VerifyOption{WithVerifiedSource(arm.wrap(s)), WithSubjectDigests([]string{"sha256:seed"})}, arm.opts...) {
				opt(vo)
			}
			require.NoError(t, checkVerifyOpts(vo))
			bundles, err := pol.TrustBundles()
			require.NoError(t, err)
			results, err := pol.verifySteps(context.Background(), vo, bundles, nil)
			assert.Nil(t, results, "no verdict may be returned from an unconverged context")
			var notConverged ErrAttestationsFromNotConverged
			require.ErrorAs(t, err, &notConverged)
			assert.Equal(t, len(pol.Steps)+1, notConverged.Rounds, "the loop must stop at its bound")
		})
	}
}

// On an acyclic union the bound holds and is tight: a chain of n
// attestationsFrom edges needs exactly n+1 rounds.
//
// source ← x (artifactsFrom; a wrong-chain sibling is pruned) ← s1 ← … ← sn,
// each s_k attestationsFrom its predecessor with "exactly one upstream
// collection". Round 1 sees two x collections, so s1 fails and every later s_k
// fails on an empty upstream; each round then lets one more level pass, and
// the final round observes that nothing changed.
func TestAttestationsFromContextChainConvergesWithinBound(t *testing.T) {
	const n = 4
	for _, arm := range prunedCtxArms() {
		t.Run(arm.name, func(t *testing.T) {
			v, keyID := earlyExitVerifier(t)
			built, other := lazyDigest("aa11"), lazyDigest("bb22")
			cands := []source.CollectionVerificationResult{
				lazyCollection(v, "source-1", "source", "",
					&lazyAttestor{AttName: "source-1", AttType: lazyAttType},
					&lazyAttestor{AttName: "source-1-prod", AttType: lazyChainAttType,
						products: map[string]attestation.Product{"app.bin": {Digest: built}}, inline: true}),
				lazyCollection(v, "x-good", "x", "",
					&lazyAttestor{AttName: "x-good", AttType: lazyAttType},
					&lazyAttestor{AttName: "x-good-mat", AttType: lazyChainAttType,
						materials: map[string]cryptoutil.DigestSet{"app.bin": built}, inline: true}),
				lazyCollection(v, "x-wrong", "x", "",
					&lazyAttestor{AttName: "x-wrong", AttType: lazyAttType},
					&lazyAttestor{AttName: "x-wrong-mat", AttType: lazyChainAttType,
						materials: map[string]cryptoutil.DigestSet{"app.bin": other}, inline: true}),
			}
			xStep := lazyStep("x", keyID)
			xStep.ArtifactsFrom = []string{"source"}
			steps := []Step{lazyStep("source", keyID), xStep}
			prev := "x"
			for k := 1; k <= n; k++ {
				name := fmt.Sprintf("s%d", k)
				cands = append(cands, lazyCollection(v, name+"-c", name, "", &lazyAttestor{AttName: name + "-c", AttType: lazyAttType}))
				// The count sits in a helper rule so a MISSING upstream denies too:
				// `not count(input.steps.x.collections) == 1` is the fail-open
				// shape warnRegoFailOpen describes (OPA hoists the read out of the
				// negation, so an absent step makes the body undefined).
				steps = append(steps, prunedCtxRegoStep(name, keyID, fmt.Sprintf(`package prunedctx
exactly_one {
	count(input.steps.%s.collections) == 1
}

deny[msg] {
	not exactly_one
	msg := "want exactly one upstream collection"
}
`, prev), prev))
				prev = name
			}
			pol := lazyPolicy(keyID, steps...)
			s := newLazySource(map[string][]source.CollectionVerificationResult{"sha256:seed": cands})
			opts := append([]VerifyOption{WithVerifiedSource(arm.wrap(s)), WithSubjectDigests([]string{"sha256:seed"})}, arm.opts...)
			pass, res, err := pol.Verify(context.Background(), opts...)
			require.NoError(t, err)
			assert.True(t, pass, "s%d rejected=%v", n, res[prev].Rejected)
			require.Zero(t, s.searches%len(pol.Steps), "every round searches every step once")
			rounds := s.searches / len(pol.Steps)
			assert.Equal(t, n+1, rounds, "a chain of n attestationsFrom edges needs n+1 rounds")
			assert.LessOrEqual(t, rounds, len(pol.Steps)+1)
		})
	}
}

// flipAI answers PASS the first time it is asked about an attestor and FAIL on
// every later call, and counts calls per attestor. Any re-query of an
// unchanged question therefore changes the answer.
type flipAI struct {
	mu    sync.Mutex
	calls map[string]int
}

func newFlipAI() *flipAI { return &flipAI{calls: map[string]int{}} }

func (f *flipAI) Evaluate(_ context.Context, att attestation.Attestor, pol AiPolicy, _ string) (AiResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[att.Name()]++
	// Echo the requested model the way Ollama does; #9820 E5 refuses a
	// verdict that names no model.
	if f.calls[att.Name()] == 1 {
		return AiResponse{Status: AiStatusPass, Reason: "first answer", Model: pol.Model}, nil
	}
	return AiResponse{Status: AiStatusFail, Reason: "a later answer differs", Model: pol.Model}, nil
}

func (f *flipAI) snapshot() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int, len(f.calls))
	for k, v := range f.calls {
		out[k] = v
	}
	return out
}

// A later round must reuse, not re-run, the gate verdict of a collection
// whose Rego/AI input did not change. scan has no attestationsFrom, so its
// context is identical in every round: each scan collection is asked about
// exactly once, and the flip provider's later FAIL can never be observed.
// Without the memo, round 2 re-asks b-scan-real, gets FAIL, and the verdict
// depends on how often the engine asked.
func TestAttestationsFromContextReusesUnchangedGateVerdicts(t *testing.T) {
	for _, arm := range prunedCtxArms() {
		t.Run(arm.name, func(t *testing.T) {
			ai := newFlipAI()
			corpus := prunedCtxCorpus{wrongChainClean: true, realClean: true, aiStep: "scan", extra: []VerifyOption{WithAiProvider(ai)}}
			pass, res := prunedCtxRun(t, arm, corpus, prunedCtxRequireClean)
			assert.True(t, pass, "scan rejected=%v gate rejected=%v", res["scan"].Rejected, res["gate"].Rejected)
			assert.Equal(t, []string{"b-scan-real"}, prunedCtxRefs(res["scan"].Passed))
			assert.Equal(t, map[string]int{prunedCtxWrongChainRef: 1, "b-scan-real": 1}, ai.snapshot(),
				"each (collection, context) must be asked exactly once across rounds")
		})
	}
}

// The memo key includes the input context: gate's context changes between
// round 1 (both scans) and round 2 (the surviving scan), so gate-1 is a
// distinct question in each and is asked exactly twice.
func TestAttestationsFromContextReevaluatesWhenContextChanges(t *testing.T) {
	for _, arm := range prunedCtxArms() {
		t.Run(arm.name, func(t *testing.T) {
			ai := &scriptedAI{resp: AiResponse{Status: AiStatusPass, Reason: "stub"}}
			corpus := prunedCtxCorpus{wrongChainClean: true, realClean: true, aiStep: "gate", extra: []VerifyOption{WithAiProvider(ai)}}
			pass, res := prunedCtxRun(t, arm, corpus, prunedCtxRequireClean)
			assert.True(t, pass, "gate rejected=%v", res["gate"].Rejected)
			assert.Equal(t, 2, ai.calls, "gate-1 is asked once per distinct context: round 1 and round 2")
		})
	}
}
