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
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// Commit binding and the cross-step Rego input.
//
// A step that reads another step's evidence through attestationsFrom gets it
// as input.steps.<dep>.collections, built from resultsByStep[dep].Passed
// (buildStepContext). The question here is whether that input can carry a
// dependency collection bound to ANOTHER commit when the verify is bound to C:
// such a collection could never satisfy the dependency step directly, so it
// must not be able to satisfy a consumer step indirectly either.
//
// Shape: "secrets" has no Rego of its own, so both a dirty and a clean scan
// pass its attestation check. "build" reads secrets through attestationsFrom
// and denies unless SOME passed secrets collection has zero findings. C's own
// scan is dirty; a clean scan exists for another commit (or for none). Its
// deny message lists every secrets reference the rule saw, so the test
// observes the Rego input directly instead of inferring it from the verdict.
// ---------------------------------------------------------------------------

var hsecCrossStepBuildRego = []byte(`package hsec1crossstep

import rego.v1

seen := sort([c.reference | some c in input.steps.secrets.collections])

clean if {
	some c in input.steps.secrets.collections
	count(c.attestations["https://example.com/hsec1-secretscan/v1"].findings) == 0
}

deny contains msg if {
	not clean
	msg := sprintf("no clean secrets scan among %v", [seen])
}
`)

func hsecCrossStepPolicy(keyID string, publicKeys map[string]PublicKey) Policy {
	fn := []Functionary{{Type: "publickey", PublicKeyID: keyID}}
	return Policy{
		Expires:    metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: publicKeys,
		Steps: map[string]Step{
			"secrets": {Name: "secrets", Functionaries: fn, Attestations: []Attestation{{Type: hsecScanType}}},
			"build": {
				Name:             "build",
				Functionaries:    fn,
				AttestationsFrom: []string{"secrets"},
				Attestations: []Attestation{{
					Type:         hsecBuildType,
					RegoPolicies: []RegoPolicy{{Name: "needs-clean-scan", Module: hsecCrossStepBuildRego}},
				}},
			},
		},
	}
}

// hsecCrossStepVerify is hsecVerify over the cross-step policy.
func hsecCrossStepVerify(t *testing.T, arm string, refs []string, opts ...VerifyOption) hsecRun {
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
	accepted, results, err := hsecCrossStepPolicy(key.keyID, nil).Verify(context.Background(), all...)
	require.NoError(t, err)
	return hsecRun{accepted: accepted, results: results, src: src}
}

// crossStepSeen joins every deny message the build rule produced for ref,
// across all depths, or returns "" when the rule never rejected ref. Joining
// matters: ref is re-gated at each depth with that depth's cross-step input,
// and the depth-0 message alone would show only the seed's evidence.
func crossStepSeen(sr StepResult, ref string) string {
	var msgs []string
	for _, rc := range sr.Rejected {
		if rc.Collection.Reference == ref && rc.Reason != nil && strings.Contains(rc.Reason.Error(), "no clean secrets scan among") {
			msgs = append(msgs, rc.Reason.Error())
		}
	}
	return strings.Join(msgs, "\n")
}

// Every case pairs C's dirty scan with ONE clean scan that is not bound to C
// alone. The unbound run is the control: it proves the clean scan is
// reachable and does reach build's Rego input (build then passes on it), so a
// green bound run means the binding kept it out, not that the fixture never
// produced it.
var hsecCrossStepCases = []struct {
	name    string
	refs    []string
	foreign string
}{
	// The parent's clean scan, reached at depth 1 through the parenthash edge
	// of C's own (dirty) scan.
	{"parent", []string{"C-build", "C-secrets-dirty", "P-build", "P-secrets-clean"}, "P-secrets-clean"},
	// A sibling (another child of P), reached the same way.
	{"sibling", []string{"C-build", "C-secrets-dirty", "S-secrets-clean"}, "S-secrets-clean"},
	// A child of C, which names C as its parent and so matches the seed.
	{"child", []string{"C-build", "C-secrets-dirty", "K-secrets-clean"}, "K-secrets-clean"},
	// A clean scan findable under C's digest that is bound to no commit.
	{"bound to no commit", []string{"C-build", "C-secrets-dirty", "N-secrets-nogit"}, "N-secrets-nogit"},
	// A clean scan that carries git attestations for both C and P.
	{"bound to C and P", []string{"C-build", "C-secrets-dirty", "D-secrets-twogit"}, "D-secrets-twogit"},
}

func TestCommitBinding_CrossStepInputIsBound(t *testing.T) {
	for _, tc := range hsecCrossStepCases {
		for _, arm := range hsecArms {
			t.Run(tc.name+"/"+arm, func(t *testing.T) {
				unbound := hsecCrossStepVerify(t, arm, tc.refs)
				require.True(t, unbound.accepted, "control: unbound, build must pass on the foreign clean scan; build rejected=%v", unbound.results["build"].Rejected)
				require.Contains(t, hsecPassedRefs(unbound.results["secrets"]), tc.foreign, "control: the foreign scan must be a passed secrets collection when unbound")
				require.Contains(t, hsecPassedRefs(unbound.results["build"]), "C-build", "control: C's own build passes on the foreign scan when unbound")

				bound := hsecCrossStepVerify(t, arm, tc.refs, WithCommitBinding(hsecC))
				assert.False(t, bound.accepted, "bound to C: build must be judged on C's own dirty scan")
				assert.Equal(t, []string{"C-secrets-dirty"}, hsecPassedRefs(bound.results["secrets"]), "only C's own scan may be a passed secrets collection")
				assert.Empty(t, hsecPassedRefs(bound.results["build"]), "no build collection may pass on evidence not bound to C")
				_, refused := unboundRejections(bound.results["secrets"])[tc.foreign]
				assert.True(t, refused, "%s must be refused at its own step as not bound to C", tc.foreign)

				seen := crossStepSeen(bound.results["build"], "C-build")
				require.NotEmpty(t, seen, "C-build must be rejected by the cross-step rule; rejected=%v", bound.results["build"].Rejected)
				assert.Contains(t, seen, "C-secrets-dirty", "build's Rego input must carry C's own scan")
				assert.NotContains(t, seen, tc.foreign, "build's Rego input must not carry a scan not bound to C")
			})
		}
	}
}

// Positive control under the binding: C's own clean scan reaches build's Rego
// input and build passes, with the parent's evidence in the corpus.
func TestCommitBinding_CrossStepOwnEvidencePasses(t *testing.T) {
	refs := []string{"C-build", "C-secrets-clean", "P-build", "P-secrets-clean"}
	for _, arm := range hsecArms {
		t.Run(arm, func(t *testing.T) {
			run := hsecCrossStepVerify(t, arm, refs, WithCommitBinding(hsecC))
			require.True(t, run.accepted, "build rejected=%v", run.results["build"].Rejected)
			assert.Equal(t, []string{"C-build"}, hsecPassedRefs(run.results["build"]))
			assert.Equal(t, []string{"C-secrets-clean"}, hsecPassedRefs(run.results["secrets"]))
		})
	}
}

// The same property through real signatures and VerifiedSource: the binding
// reads commithash from the signed payload, and the cross-step input is built
// from what that gate passed.
func TestCommitBinding_CrossStepSignedCorpus(t *testing.T) {
	key := newHsecKey(t)
	pks := map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}}
	pol := hsecCrossStepPolicy(key.keyID, pks)
	refs := []string{"C-build", "C-secrets-dirty", "P-build", "P-secrets-clean"}

	accepted, results := hsecVerifySigned(t, key, pol, refs, WithSearchDepth(3))
	require.True(t, accepted, "control: unbound, build passes on the signed parent scan; rejected=%v", results["build"].Rejected)

	accepted, results = hsecVerifySigned(t, key, pol, refs, WithSearchDepth(3), WithCommitBinding(hsecC))
	assert.False(t, accepted, "bound to C: build must be judged on C's own dirty scan")
	assert.Equal(t, []string{"C-secrets-dirty"}, hsecPassedRefs(results["secrets"]))
	assert.Empty(t, hsecPassedRefs(results["build"]))
	seen := crossStepSeen(results["build"], "C-build")
	require.NotEmpty(t, seen, "rejected=%v", results["build"].Rejected)
	assert.Contains(t, seen, "C-secrets-dirty")
	assert.NotContains(t, seen, "P-secrets-clean")
}
