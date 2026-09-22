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
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// Commit binding and external attestations.
//
// A step that lists an external attestation in externalFrom reads it as
// input.external.<name>, built from that external's first PASSED envelope
// (collectExternalRegoContext). External envelopes are found once, before the
// steps, by predicate type and the SEED subjects (verifyExternalAttestations),
// and never through the step gate, so WithCommitBinding's gate check
// (gateBound) never saw them.
//
// Through a real VerifiedSource an envelope is a candidate only when its
// SIGNED subjects name the seed, and a SHA-1 commit subject anchors only a
// hardened git-attested collection. So for a SHA-1 commit the envelopes that
// can reach input.external are collections whose git attestation names C;
// every other commit's evidence is not a candidate at all (the structural
// guard below). The escape is a collection whose git attestations name C AND
// another commit: before the fix it passed the external and decided C's step.
//
// Shape: external "scan" selects collection-typed envelopes and keeps only
// secrets scans (its own Rego). "build" reads it through externalFrom and
// denies unless the scan has zero findings; its deny message names the git
// commits of the scan it saw, so the test reads the Rego input directly.
// ---------------------------------------------------------------------------

var externalScanOnlyRego = []byte(`package externalscanonly

import rego.v1

deny contains msg if {
	input.name != "secrets"
	msg := sprintf("not a secrets scan: %v", [input.name])
}
`)

var externalBuildRego = []byte(`package externalcommitbuild

import rego.v1

commits := sort([a.attestation.commithash |
	some a in input.external.scan.attestations
	a.type == "https://aflock.ai/attestations/git/v0.1"
])

clean if {
	some a in input.external.scan.attestations
	a.type == "https://example.com/hsec1-secretscan/v1"
	count(a.attestation.findings) == 0
}

deny contains msg if {
	not clean
	msg := sprintf("no clean external scan (scan commits %v)", [commits])
}
`)

func externalScanPolicy(keyID string, publicKeys map[string]PublicKey, predicateType string) Policy {
	fn := []Functionary{{Type: "publickey", PublicKeyID: keyID}}
	ext := ExternalAttestation{Name: "scan", PredicateType: predicateType, Functionaries: fn, Required: false}
	if predicateType == attestation.CollectionType {
		ext.RegoPolicies = []RegoPolicy{{Name: "scans-only", Module: externalScanOnlyRego}}
	}
	return Policy{
		Expires:              metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys:           publicKeys,
		ExternalAttestations: map[string]ExternalAttestation{"scan": ext},
		Steps: map[string]Step{
			"build": {
				Name:          "build",
				Functionaries: fn,
				ExternalFrom:  []string{"scan"},
				Attestations: []Attestation{{
					Type:         hsecBuildType,
					RegoPolicies: []RegoPolicy{{Name: "needs-clean-external-scan", Module: externalBuildRego}},
				}},
			},
		},
	}
}

type externalRun struct {
	accepted bool
	steps    map[string]StepResult
	external ExternalResult
}

// externalVerifySigned verifies seed against signed corpus collections (by
// ref) plus signed bare statements, all held in the in-memory source behind a
// real VerifiedSource.
func externalVerifySigned(t *testing.T, key hsecKey, pol Policy, seed string, refs []string, bare map[string][]byte, opts ...VerifyOption) externalRun {
	t.Helper()
	mem := source.NewMemorySource()
	for _, ref := range refs {
		require.NoError(t, mem.LoadEnvelope(ref, hsecSign(t, key, hsecCorpus[ref])))
	}
	for ref, payload := range bare {
		env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(key.signer))
		require.NoError(t, err)
		require.NoError(t, mem.LoadEnvelope(ref, env))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(key.verifier))
	accepted, steps, externals, err := pol.VerifyWithExternals(context.Background(), append([]VerifyOption{
		WithVerifiedSource(vs), WithSubjectDigests([]string{seed}), WithSearchDepth(3),
	}, opts...)...)
	require.NoError(t, err)
	return externalRun{accepted: accepted, steps: steps, external: externals["scan"]}
}

func externalPassedRefs(er ExternalResult) []string {
	out := make([]string, 0, len(er.Passed))
	for _, p := range er.Passed {
		out = append(out, p.Envelope.Reference)
	}
	sort.Strings(out)
	return out
}

func externalCandidateRefs(er ExternalResult) []string {
	out := externalPassedRefs(er)
	for _, r := range er.Rejected {
		out = append(out, r.Envelope.Reference)
	}
	sort.Strings(out)
	return out
}

// externalUnbound maps each rejected external reference to its binding refusal.
func externalUnbound(er ExternalResult) map[string]ErrExternalNotBoundToCommit {
	out := map[string]ErrExternalNotBoundToCommit{}
	for _, r := range er.Rejected {
		var nb ErrExternalNotBoundToCommit
		if errors.As(r.Reason, &nb) {
			out[r.Envelope.Reference] = nb
		}
	}
	return out
}

// buildSawExternal joins the build rule's deny messages for C-build.
func buildSawExternal(sr StepResult) string {
	var msgs []string
	for _, rc := range sr.Rejected {
		if rc.Collection.Reference == "C-build" && rc.Reason != nil && strings.Contains(rc.Reason.Error(), "no clean external scan") {
			msgs = append(msgs, rc.Reason.Error())
		}
	}
	return strings.Join(msgs, "\n")
}

// The escape: a clean scan whose git attestations name C and P is a candidate
// under C, passes the external, and decides C's build, while C's own (dirty)
// scan fails it.
func TestCommitBinding_ExternalInputIsBound(t *testing.T) {
	key := newHsecKey(t)
	pks := map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}}
	pol := externalScanPolicy(key.keyID, pks, attestation.CollectionType)

	for _, tc := range []struct {
		name    string
		refs    []string
		foreign string
	}{
		// The escape. (With C's dirty scan also in the corpus the outcome
		// would turn on which passed envelope the source returns first, so
		// C's own evidence is exercised in its own control below.)
		{"bound to C and P", []string{"C-build", "D-secrets-twogit"}, "D-secrets-twogit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Control: C's own evidence alone fails build, bound and unbound.
			for _, opts := range [][]VerifyOption{nil, {WithCommitBinding(hsecC)}} {
				own := externalVerifySigned(t, key, pol, hsecC, []string{"C-build", "C-secrets-dirty"}, nil, opts...)
				require.False(t, own.accepted, "C's own dirty scan must fail build")
				require.Contains(t, buildSawExternal(own.steps["build"]), "scan commits ["+`"`+hsecC+`"`+"]", "build must read C's own scan")
			}

			unbound := externalVerifySigned(t, key, pol, hsecC, tc.refs, nil)
			require.True(t, unbound.accepted, "control: unbound, build passes on the foreign scan; build rejected=%v", unbound.steps["build"].Rejected)
			require.Equal(t, []string{tc.foreign}, externalPassedRefs(unbound.external), "control: the foreign scan passes the external when unbound")

			bound := externalVerifySigned(t, key, pol, hsecC, tc.refs, nil, WithCommitBinding(hsecC))
			assert.False(t, bound.accepted, "bound to C: build must not pass on a scan not bound to C")
			assert.Empty(t, externalPassedRefs(bound.external), "no external envelope not bound to C may pass")
			nb, refused := externalUnbound(bound.external)[tc.foreign]
			require.True(t, refused, "%s must be refused as not bound to C; reasons=%v", tc.foreign, externalReasons(bound.external))
			assert.Equal(t, hsecP, nb.WitnessCommit)
			assert.Equal(t, "scan", nb.External)
			assert.Empty(t, hsecPassedRefs(bound.steps["build"]))
			seen := buildSawExternal(bound.steps["build"])
			require.NotEmpty(t, seen, "C-build must be rejected by its external rule; rejected=%v", bound.steps["build"].Rejected)
			assert.Contains(t, seen, "scan commits []", "build's Rego input must not carry the foreign scan")
		})
	}
}

// Positive control under the binding: C's own clean scan is the external build
// reads, with the parent's scan and the two-commit scan in the corpus.
func TestCommitBinding_ExternalOwnEvidencePasses(t *testing.T) {
	key := newHsecKey(t)
	pks := map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}}
	pol := externalScanPolicy(key.keyID, pks, attestation.CollectionType)

	run := externalVerifySigned(t, key, pol, hsecC,
		[]string{"C-build", "C-secrets-clean", "P-secrets-clean", "D-secrets-twogit"}, nil, WithCommitBinding(hsecC))
	require.True(t, run.accepted, "build rejected=%v external reasons=%v", run.steps["build"].Rejected, externalReasons(run.external))
	assert.Equal(t, []string{"C-secrets-clean"}, externalPassedRefs(run.external))
	assert.Equal(t, []string{"C-build"}, hsecPassedRefs(run.steps["build"]))
	_, refused := externalUnbound(run.external)["D-secrets-twogit"]
	assert.True(t, refused, "the two-commit scan is refused even when C's own scan passes")
}

// Structural guard: evidence bound only to ANOTHER commit is never an external
// candidate under C, bound or not, because external search runs on the seed
// subjects and the verified source matches a SHA-1 subject only as a hardened
// git commithash. The parent, a sibling, a child (which names C only as its
// parenthash) and a scan with no git attestation all stay out, so build fails
// on C's own (absent) scan in both runs.
func TestCommitBinding_ExternalOfAnotherCommitIsNeverACandidate(t *testing.T) {
	key := newHsecKey(t)
	pks := map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}}
	pol := externalScanPolicy(key.keyID, pks, attestation.CollectionType)

	for _, foreign := range []string{"P-secrets-clean", "S-secrets-clean", "K-secrets-clean", "N-secrets-nogit"} {
		t.Run(foreign, func(t *testing.T) {
			for _, opts := range [][]VerifyOption{nil, {WithCommitBinding(hsecC)}} {
				run := externalVerifySigned(t, key, pol, hsecC, []string{"C-build", foreign}, nil, opts...)
				assert.False(t, run.accepted)
				assert.NotContains(t, externalCandidateRefs(run.external), foreign, "%s must not be an external candidate under C", foreign)
				assert.Contains(t, buildSawExternal(run.steps["build"]), "scan commits []")
			}
		})
	}
}

// bareStatement is a bare-predicate statement (a verification summary shape)
// with the given subjects.
func bareStatement(t *testing.T, result string, subjects ...intoto.Subject) []byte {
	t.Helper()
	predicate, err := json.Marshal(map[string]any{
		"verifier":           map[string]any{"id": "external-fixture"},
		"verificationResult": result,
	})
	require.NoError(t, err)
	payload, err := json.Marshal(intoto.Statement{
		Type: intoto.StatementType, Subject: subjects,
		PredicateType: vsaPredicateType, Predicate: predicate,
	})
	require.NoError(t, err)
	return payload
}

var externalVSABuildRego = []byte(`package externalvsabuild

import rego.v1

deny contains msg if {
	input.external.scan.verificationResult != "PASSED"
	msg := "external summary did not pass"
}

deny contains msg if {
	not input.external.scan
	msg := "no external summary"
}
`)

func externalVSAPolicy(keyID string, publicKeys map[string]PublicKey) Policy {
	pol := externalScanPolicy(keyID, publicKeys, vsaPredicateType)
	build := pol.Steps["build"]
	build.Attestations[0].RegoPolicies = []RegoPolicy{{Name: "needs-passed-summary", Module: externalVSABuildRego}}
	pol.Steps["build"] = build
	return pol
}

// A bare predicate carries subjects, not a git commit claim. With a SHA-1
// commit the verified source never lets its sha1 subject anchor (not a git
// collection), so it is not a candidate; with a SHA-256 commit it is, and a
// summary naming C and another commit decided C's build. Under the binding a
// bare predicate is refused: it has nothing that binds it to C.
func TestCommitBinding_BareExternalIsNotBound(t *testing.T) {
	key := newHsecKey(t)
	pks := map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}}
	pol := externalVSAPolicy(key.keyID, pks)

	const (
		c256 = "3333333333333333333333333333333333333333333333333333333333333333"
		p256 = "2222222222222222222222222222222222222222222222222222222222222222"
	)
	sub := func(name, alg, v string) intoto.Subject {
		return intoto.Subject{Name: name, Digest: map[string]string{alg: v}}
	}

	t.Run("sha1 commit: a bare summary is never a candidate", func(t *testing.T) {
		bare := map[string][]byte{"V-cp": bareStatement(t, "PASSED", sub("artifact:"+hsecC, "sha1", hsecC), sub("artifact:"+hsecP, "sha1", hsecP))}
		for _, opts := range [][]VerifyOption{nil, {WithCommitBinding(hsecC)}} {
			run := externalVerifySigned(t, key, pol, hsecC, []string{"C-build"}, bare, opts...)
			assert.False(t, run.accepted)
			assert.Empty(t, externalPassedRefs(run.external))
		}
	})

	for _, tc := range []struct {
		name string
		bare []byte
	}{
		{"sha256 commit: summary names C and P", bareStatement(t, "PASSED", sub("artifact:"+c256, "sha256", c256), sub("artifact:"+p256, "sha256", p256))},
		{"sha256 commit: summary names C only", bareStatement(t, "PASSED", sub("artifact:"+c256, "sha256", c256))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			build := hsecCorpus["C-build"]
			build.gits = hsecGitOf(c256, p256)
			// Findable under the SHA-256 seed: the fixture's commit subjects
			// are sha1-keyed, so name C through a sha256 subject.
			build.treeRoot = c256
			key2 := key
			mem := map[string][]byte{"V": tc.bare}
			unbound := externalVerifyOne(t, key2, pol, c256, build, mem)
			require.True(t, unbound.accepted, "control: unbound, build passes on the summary; rejected=%v ext=%v", unbound.steps["build"].Rejected, externalReasons(unbound.external))

			bound := externalVerifyOne(t, key2, pol, c256, build, mem, WithCommitBinding(c256))
			assert.False(t, bound.accepted, "bound: a bare summary is not bound to C")
			assert.Empty(t, externalPassedRefs(bound.external))
			nb, refused := externalUnbound(bound.external)["V"]
			require.True(t, refused, "reasons=%v", externalReasons(bound.external))
			assert.Empty(t, nb.WitnessCommit, "a bare predicate carries no commit claim")
		})
	}
}

// externalVerifyOne is externalVerifySigned for one ad-hoc build collection.
func externalVerifyOne(t *testing.T, key hsecKey, pol Policy, seed string, build hsecSpec, bare map[string][]byte, opts ...VerifyOption) externalRun {
	t.Helper()
	mem := source.NewMemorySource()
	require.NoError(t, mem.LoadEnvelope(build.ref, hsecSign(t, key, build)))
	for ref, payload := range bare {
		env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(key.signer))
		require.NoError(t, err)
		require.NoError(t, mem.LoadEnvelope(ref, env))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(key.verifier))
	accepted, steps, externals, err := pol.VerifyWithExternals(context.Background(), append([]VerifyOption{
		WithVerifiedSource(vs), WithSubjectDigests([]string{seed}), WithSearchDepth(3),
	}, opts...)...)
	require.NoError(t, err)
	return externalRun{accepted: accepted, steps: steps, external: externals["scan"]}
}

// externalReasons lists an external's rejection reasons, for failure messages.
func externalReasons(er ExternalResult) []string {
	out := make([]string, 0, len(er.Rejected))
	for _, r := range er.Rejected {
		out = append(out, r.Envelope.Reference+": "+r.Reason.Error())
	}
	return out
}

// The binding rule on single envelopes, including the shapes a verified source
// never hands the engine but a direct caller could: it reads the signed
// payload, and only an attestation collection can carry a commit claim.
func TestCheckExternalCommitBinding(t *testing.T) {
	key := newHsecKey(t)
	signed := func(ref string, spec hsecSpec) source.StatementEnvelope {
		env := hsecSign(t, key, spec)
		return source.StatementEnvelope{Envelope: env, Reference: ref}
	}
	bare := func(ref string, predicate map[string]any) source.StatementEnvelope {
		body, err := json.Marshal(predicate)
		require.NoError(t, err)
		payload, err := json.Marshal(intoto.Statement{
			Type: intoto.StatementType, PredicateType: vsaPredicateType, Predicate: body,
			Subject: []intoto.Subject{{Name: "artifact:" + hsecC, Digest: map[string]string{"sha1": hsecC}}},
		})
		require.NoError(t, err)
		env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(key.signer))
		require.NoError(t, err)
		return source.StatementEnvelope{Envelope: env, Reference: ref}
	}
	gitBody := map[string]any{"attestations": []map[string]any{{
		"type": hsecGitType, "attestation": map[string]any{"commithash": hsecC, "commithashverified": true},
	}}}

	// A directly-constructed envelope: no payload, the Statement is the truth.
	direct := func(spec hsecSpec) source.StatementEnvelope {
		predicate, err := json.Marshal(spec.collection())
		require.NoError(t, err)
		return source.StatementEnvelope{Reference: spec.ref, Statement: intoto.Statement{
			Type: intoto.StatementType, PredicateType: attestation.CollectionType, Predicate: predicate, Subject: spec.subjects(),
		}}
	}
	// Signed bytes say P; the source's projected Statement claims C.
	projected := signed("P-projected-as-C", hsecCorpus["P-secrets-clean"])
	projected.Statement = direct(hsecCorpus["C-secrets-clean"]).Statement

	for _, tc := range []struct {
		name          string
		env           source.StatementEnvelope
		bound         bool
		witnessCommit string
	}{
		{"bound to C only", signed("c", hsecCorpus["C-secrets-clean"]), true, ""},
		{"bound to C only, directly constructed", direct(hsecCorpus["C-secrets-clean"]), true, ""},
		{"parent", signed("p", hsecCorpus["P-secrets-clean"]), false, hsecP},
		{"child", signed("k", hsecCorpus["K-secrets-clean"]), false, hsecK},
		{"bound to C and P", signed("d", hsecCorpus["D-secrets-twogit"]), false, hsecP},
		{"collection bound to no commit", signed("n", hsecCorpus["N-secrets-nogit"]), false, ""},
		{"bare predicate", bare("v", map[string]any{"verificationResult": "PASSED"}), false, ""},
		{"bare predicate whose body mimics a git collection", bare("m", gitBody), false, ""},
		{"projection claims C, signed payload is P", projected, false, hsecP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkExternalCommitBinding("scan", tc.env, hsecC)
			if tc.bound {
				require.NoError(t, err)
				return
			}
			var nb ErrExternalNotBoundToCommit
			require.ErrorAs(t, err, &nb)
			assert.Equal(t, tc.witnessCommit, nb.WitnessCommit)
			assert.Equal(t, "scan", nb.External)
			assert.Equal(t, tc.env.Reference, nb.Reference)
			assert.Equal(t, hsecC, nb.Commit)
		})
	}
}
