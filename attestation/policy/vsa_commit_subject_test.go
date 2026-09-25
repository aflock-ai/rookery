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
	"fmt"
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

// ExternalAttestation.commitSubject: a Pushgate VSA names its commit only as a
// SHA-1 subject https://pushgate.dev/v0.1/commithash:<sha>. The policy (signed
// by a human) declares that exact prefix for ONE external; only that external
// may then match the commit through it, and commit binding admits it through
// the same field.

const (
	vsaBindingPredicate = "https://pushgate.dev/verification_summary/v0.5"
	vsaBindingPrefix    = "https://pushgate.dev/v0.1/commithash:"
	vsaBindingCommit    = "ef2115760123456789abcdef0123456789abcdef"
	vsaBindingOther     = "0123456789abcdef0123456789abcdef01234567"
)

var vsaBindingPassedRego = []byte(`package vsabinding

deny[msg] {
	input.verificationResult != "PASSED"
	msg := "verdict is not PASSED"
}
`)

func vsaBindingExternal(name, commitSubject string) ExternalAttestation {
	return ExternalAttestation{
		Name:          name,
		PredicateType: vsaBindingPredicate,
		RegoPolicies:  []RegoPolicy{{Name: "passed", Module: vsaBindingPassedRego}},
		Required:      true,
		CommitSubject: commitSubject,
	}
}

// vsaBindingPolicy has NO steps: the VSA is the whole gate.
func vsaBindingPolicy(key hsecKey, exts ...ExternalAttestation) Policy {
	fn := []Functionary{{Type: "publickey", PublicKeyID: key.keyID}}
	m := map[string]ExternalAttestation{}
	for _, e := range exts {
		e.Functionaries = fn
		m[e.Name] = e
	}
	return Policy{
		Expires:              metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys:           map[string]PublicKey{key.keyID: {KeyID: key.keyID, Key: key.pem}},
		ExternalAttestations: m,
	}
}

func vsaBindingStatement(predicateType, verdict string, subjects ...intoto.Subject) []byte {
	payload, err := json.Marshal(intoto.Statement{
		Type:          intoto.StatementType,
		PredicateType: predicateType,
		Subject:       subjects,
		Predicate:     json.RawMessage(fmt.Sprintf(`{"verificationResult":%q}`, verdict)),
	})
	if err != nil {
		panic(err)
	}
	return payload
}

func vsaBindingVSA(commit, verdict string) []byte {
	return vsaBindingStatement(vsaBindingPredicate, verdict,
		intoto.Subject{Name: "https://pushgate.dev/v0.1/repository:github.com/testifysec/judge", Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}},
		intoto.Subject{Name: vsaBindingPrefix + commit, Digest: map[string]string{"sha1": commit}},
	)
}

func vsaBindingVerify(t *testing.T, key hsecKey, pol Policy, seed string, bare map[string][]byte, opts ...VerifyOption) (bool, map[string]ExternalResult, error) {
	t.Helper()
	mem := source.NewMemorySource()
	for ref, payload := range bare {
		env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(key.signer))
		require.NoError(t, err)
		require.NoError(t, mem.LoadEnvelope(ref, env))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(key.verifier))
	accepted, _, externals, err := pol.VerifyWithExternals(context.Background(), append([]VerifyOption{
		WithVerifiedSource(vs), WithSubjectDigests([]string{seed}),
	}, opts...)...)
	return accepted, externals, err
}

// vsaBindingArchivistaShape returns every loaded bare statement for any
// predicate search, the way Archivista answers a SHA-1 digest query: its own
// filter is not trusted, so the VerifiedSource guard alone decides.
type vsaBindingArchivistaShape struct{ envs []source.StatementEnvelope }

func (a *vsaBindingArchivistaShape) Search(context.Context, string, []string, []string) ([]source.CollectionEnvelope, error) {
	return nil, nil
}

func (a *vsaBindingArchivistaShape) SearchByPredicateType(context.Context, []string, []string) ([]source.StatementEnvelope, error) {
	out := make([]source.StatementEnvelope, len(a.envs))
	copy(out, a.envs)
	return out, nil
}

func vsaBindingVerifyUnfiltered(t *testing.T, key hsecKey, pol Policy, seed string, bare map[string][]byte, opts ...VerifyOption) (bool, map[string]ExternalResult, error) {
	t.Helper()
	src := &vsaBindingArchivistaShape{}
	for _, ref := range sortedNames(bare) {
		payload := bare[ref]
		env, err := dsse.Sign(intoto.PayloadType, bytes.NewReader(payload), dsse.SignWithSigners(key.signer))
		require.NoError(t, err)
		var stmt intoto.Statement
		require.NoError(t, json.Unmarshal(payload, &stmt))
		src.envs = append(src.envs, source.StatementEnvelope{
			Envelope: env, Statement: stmt, Reference: ref,
			Attestor: attestation.NewRawAttestation(stmt.PredicateType, stmt.Predicate),
		})
	}
	vs := source.NewVerifiedSource(src, dsse.VerifyWithVerifiers(key.verifier))
	accepted, _, externals, err := pol.VerifyWithExternals(context.Background(), append([]VerifyOption{
		WithVerifiedSource(vs), WithSubjectDigests([]string{seed}),
	}, opts...)...)
	return accepted, externals, err
}

type vsaBindingVerifier func(t *testing.T, key hsecKey, pol Policy, seed string, bare map[string][]byte, opts ...VerifyOption) (bool, map[string]ExternalResult, error)

// vsaBindingVias runs a test through both source shapes: the in-memory
// source (local bundle verify) and a source whose own filter returns
// everything (Archivista).
var vsaBindingVias = []struct {
	name   string
	verify vsaBindingVerifier
}{
	{"memory", vsaBindingVerify},
	{"archivista-shape", vsaBindingVerifyUnfiltered},
}

func TestVsaBindingZeroStepPolicyAcceptsVSAWithCommitSubject(t *testing.T) {
	for _, via := range vsaBindingVias {
		t.Run(via.name, func(t *testing.T) {
			key := newHsecKey(t)
			pol := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", vsaBindingPrefix))
			accepted, ext, err := via.verify(t, key, pol, vsaBindingCommit, map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "PASSED")})
			require.NoError(t, err)
			assert.True(t, accepted)
			assert.Len(t, ext["pushgate-vsa"].Passed, 1)
		})
	}
}

func TestVsaBindingFailedVerdictStillFails(t *testing.T) {
	for _, via := range vsaBindingVias {
		t.Run(via.name, func(t *testing.T) {
			key := newHsecKey(t)
			pol := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", vsaBindingPrefix))
			_, _, err := via.verify(t, key, pol, vsaBindingCommit, map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "FAILED")})
			var rejected ErrExternalAttestationRejected
			require.ErrorAs(t, err, &rejected)
			msg := err.Error()
			assert.Contains(t, msg, "verdict is not PASSED")
			assert.Contains(t, msg, "sha1:"+vsaBindingCommit, "names the requested subject")
			assert.Contains(t, msg, "1 candidate", "names the candidate count")
			assert.Contains(t, msg, vsaBindingPrefix+vsaBindingCommit+" (sha1)", "names the candidate's signed subjects")
		})
	}
}

// Through the in-memory source the SHA-1 subject is never indexed, so there
// is no candidate to explain; the message still says why a sha1 search can
// come back empty and which field would change that.
func TestVsaBindingWithoutCommitSubjectMemoryHint(t *testing.T) {
	key := newHsecKey(t)
	pol := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", ""))
	_, _, err := vsaBindingVerify(t, key, pol, vsaBindingCommit, map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "PASSED")})
	var missing ErrMissingExternalAttestation
	require.ErrorAs(t, err, &missing)
	msg := err.Error()
	assert.Contains(t, msg, "sha1:"+vsaBindingCommit)
	assert.Contains(t, msg, "0 candidate")
	assert.Contains(t, msg, "commitSubject")
}

func TestVsaBindingWithoutCommitSubjectIsMissingAndSaysWhy(t *testing.T) {
	key := newHsecKey(t)
	pol := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", ""))
	accepted, _, err := vsaBindingVerifyUnfiltered(t, key, pol, vsaBindingCommit, map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "PASSED")})
	assert.False(t, accepted)
	var missing ErrMissingExternalAttestation
	require.ErrorAs(t, err, &missing)
	msg := err.Error()
	for _, want := range []string{
		vsaBindingPredicate,
		"sha1:" + vsaBindingCommit,
		"1 candidate",
		vsaBindingPrefix + vsaBindingCommit + " (sha1)",
		"SHA-1",
		"commitSubject",
		`"` + vsaBindingPrefix + `"`,
	} {
		assert.Contains(t, msg, want)
	}
}

// A second external in the same policy, same predicate type, without the
// opt-in, does not inherit the first one's.
func TestVsaBindingSecondExternalDoesNotInherit(t *testing.T) {
	for _, via := range vsaBindingVias {
		t.Run(via.name, func(t *testing.T) {
			key := newHsecKey(t)
			pol := vsaBindingPolicy(key,
				vsaBindingExternal("a-declares", vsaBindingPrefix),
				vsaBindingExternal("b-does-not", ""),
			)
			_, ext, err := via.verify(t, key, pol, vsaBindingCommit, map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "PASSED")})
			var missing ErrMissingExternalAttestation
			require.ErrorAs(t, err, &missing)
			assert.Equal(t, "b-does-not", missing.Name)
			assert.Len(t, ext["a-declares"].Passed, 1, "the declaring external still passes")
			assert.Empty(t, ext["b-does-not"].Passed)
			require.Len(t, ext["b-does-not"].Unbound, 1, "b saw the shared candidate and refused it itself")
			assert.ErrorIs(t, ext["b-does-not"].Unbound[0].Reason, source.ErrExternalSubjectNotRequested)

			// And with b optional the policy passes on a alone, b skipped.
			b := vsaBindingExternal("b-does-not", "")
			b.Required = false
			pol = vsaBindingPolicy(key, vsaBindingExternal("a-declares", vsaBindingPrefix), b)
			accepted, ext, err := via.verify(t, key, pol, vsaBindingCommit, map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "PASSED")})
			require.NoError(t, err)
			assert.True(t, accepted)
			assert.True(t, ext["b-does-not"].Skipped)
		})
	}
}

func TestVsaBindingCommitBindingAdmitsDeclaredSubject(t *testing.T) {
	for _, via := range vsaBindingVias {
		t.Run(via.name, func(t *testing.T) {
			key := newHsecKey(t)
			pol := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", vsaBindingPrefix))
			accepted, _, err := via.verify(t, key, pol, vsaBindingCommit,
				map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "PASSED")}, WithCommitBinding(vsaBindingCommit))
			require.NoError(t, err)
			assert.True(t, accepted)

			// Upper-case binding is normalized; still the same commit.
			accepted, _, err = via.verify(t, key, pol, vsaBindingCommit,
				map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "PASSED")}, WithCommitBinding(strings.ToUpper(vsaBindingCommit)))
			require.NoError(t, err)
			assert.True(t, accepted)
		})
	}
}

func TestVsaBindingCommitBindingRefusesOtherCommit(t *testing.T) {
	for _, via := range vsaBindingVias {
		t.Run(via.name, func(t *testing.T) {
			key := newHsecKey(t)
			pol := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", vsaBindingPrefix))
			// The seed names the VSA's commit, but the verify evaluates another.
			accepted, ext, err := via.verify(t, key, pol, vsaBindingCommit,
				map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "PASSED")}, WithCommitBinding(vsaBindingOther))
			assert.False(t, accepted)
			var missing ErrMissingExternalAttestation
			require.ErrorAs(t, err, &missing)
			require.Len(t, ext["pushgate-vsa"].Unbound, 1)
			var nb ErrExternalNotBoundToCommit
			require.ErrorAs(t, ext["pushgate-vsa"].Unbound[0].Reason, &nb)
			assert.Equal(t, vsaBindingCommit, nb.WitnessCommit)
			assert.Contains(t, err.Error(), "is bound to commit "+vsaBindingCommit+", not "+vsaBindingOther)
		})
	}
}

// Direct unit coverage of the binding check, both directions.
func TestVsaBindingCheckExternalCommitBinding(t *testing.T) {
	env := func(payload []byte) source.StatementEnvelope {
		return source.StatementEnvelope{Envelope: dsse.Envelope{Payload: payload}, Reference: "r"}
	}
	vsa := vsaBindingVSA(vsaBindingCommit, "PASSED")
	declared := vsaBindingExternal("x", vsaBindingPrefix)
	plain := vsaBindingExternal("x", "")

	require.NoError(t, checkExternalCommitBinding(declared, env(vsa), vsaBindingCommit))
	require.Error(t, checkExternalCommitBinding(plain, env(vsa), vsaBindingCommit), "a bare predicate without commitSubject keeps today's refusal")
	require.Error(t, checkExternalCommitBinding(declared, env(vsa), vsaBindingOther))

	otherType := vsaBindingStatement("https://example.com/other/v1", "PASSED",
		intoto.Subject{Name: vsaBindingPrefix + vsaBindingCommit, Digest: map[string]string{"sha1": vsaBindingCommit}})
	require.Error(t, checkExternalCommitBinding(declared, env(otherType), vsaBindingCommit), "only the external's own signed predicate type")

	wrongDigest := vsaBindingStatement(vsaBindingPredicate, "PASSED",
		intoto.Subject{Name: vsaBindingPrefix + vsaBindingCommit, Digest: map[string]string{"sha1": vsaBindingOther}})
	require.Error(t, checkExternalCommitBinding(declared, env(wrongDigest), vsaBindingCommit), "name and digest must agree")

	// Every claim under the prefix must name the commit: an envelope that
	// also names another commit is not about this commit alone.
	twoCommits := vsaBindingStatement(vsaBindingPredicate, "PASSED",
		intoto.Subject{Name: vsaBindingPrefix + vsaBindingCommit, Digest: map[string]string{"sha1": vsaBindingCommit}},
		intoto.Subject{Name: vsaBindingPrefix + vsaBindingOther, Digest: map[string]string{"sha1": vsaBindingOther}})
	err := checkExternalCommitBinding(declared, env(twoCommits), vsaBindingCommit)
	var nb ErrExternalNotBoundToCommit
	require.ErrorAs(t, err, &nb)
	assert.Equal(t, vsaBindingOther, nb.WitnessCommit)

	malformedSibling := vsaBindingStatement(vsaBindingPredicate, "PASSED",
		intoto.Subject{Name: vsaBindingPrefix + vsaBindingCommit, Digest: map[string]string{"sha1": vsaBindingCommit}},
		intoto.Subject{Name: vsaBindingPrefix + "not-a-commit", Digest: map[string]string{"sha1": vsaBindingOther}})
	require.Error(t, checkExternalCommitBinding(declared, env(malformedSibling), vsaBindingCommit))

	// Subjects outside the prefix (repository, tenant, nonce) do not matter.
	require.NoError(t, checkExternalCommitBinding(declared, env(vsaBindingVSA(vsaBindingCommit, "FAILED")), vsaBindingCommit))

	sha256Only := vsaBindingStatement(vsaBindingPredicate, "PASSED",
		intoto.Subject{Name: vsaBindingPrefix + vsaBindingCommit, Digest: map[string]string{"sha256": strings.Repeat("ab", 32)}})
	require.Error(t, checkExternalCommitBinding(declared, env(sha256Only), vsaBindingCommit))

	// No signed payload: the projected Statement is never trusted for this arm.
	projected := source.StatementEnvelope{Reference: "r", Statement: intoto.Statement{
		PredicateType: vsaBindingPredicate,
		Subject:       []intoto.Subject{{Name: vsaBindingPrefix + vsaBindingCommit, Digest: map[string]string{"sha1": vsaBindingCommit}}},
	}}
	require.Error(t, checkExternalCommitBinding(declared, projected, vsaBindingCommit))
}

func TestVsaBindingValidateCommitSubject(t *testing.T) {
	key := newHsecKey(t)
	ok := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", vsaBindingPrefix))
	require.NoError(t, ok.Validate())

	for name, prefix := range map[string]string{
		"bare infix":       "commithash:",
		"whitespace":       vsaBindingPrefix + " ",
		"no commithash":    "https://pushgate.dev/v0.1/",
		"leading space":    " " + vsaBindingPrefix,
		"case variant tag": "https://pushgate.dev/v0.1/CommitHash:",
	} {
		bad := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", prefix))
		assert.Error(t, bad.Validate(), name)
	}

	coll := vsaBindingExternal("coll", vsaBindingPrefix)
	coll.PredicateType = attestation.CollectionType
	assert.Error(t, vsaBindingPolicy(key, coll).Validate(), "commitSubject on a collection-typed external is refused")
	coll.PredicateType = attestation.LegacyCollectionType
	assert.Error(t, vsaBindingPolicy(key, coll).Validate(), "legacy collection type too")

	// An invalid commitSubject also refuses the verify outright.
	bad := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", "commithash:"))
	_, _, err := vsaBindingVerify(t, key, bad, vsaBindingCommit, map[string][]byte{"vsa": vsaBindingVSA(vsaBindingCommit, "PASSED")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commitSubject")
}

func TestVsaBindingStrictV02DecodeKnowsCommitSubject(t *testing.T) {
	doc := fmt.Sprintf(`{"expires":"2030-01-01T00:00:00Z","externalAttestations":{"pushgate-vsa":{"name":"pushgate-vsa","predicateType":%q,"functionaries":[],"commitSubject":%q}}}`,
		vsaBindingPredicate, vsaBindingPrefix)
	p, err := DecodePolicyEnvelope(PolicyPredicateV02, []byte(doc))
	require.NoError(t, err)
	assert.Equal(t, vsaBindingPrefix, p.ExternalAttestations["pushgate-vsa"].CommitSubject)
	assert.True(t, p.ExternalAttestations["pushgate-vsa"].Required, "required defaults to true")
}

// Diagnostics stay bounded however many candidates an uploader plants.
func TestVsaBindingDiagnosticsAreBounded(t *testing.T) {
	key := newHsecKey(t)
	pol := vsaBindingPolicy(key, vsaBindingExternal("pushgate-vsa", ""))
	bare := map[string][]byte{}
	for i := 0; i < 40; i++ {
		// Distinct payloads: a different verdict string per candidate.
		bare[fmt.Sprintf("vsa-%02d", i)] = vsaBindingStatement(vsaBindingPredicate, fmt.Sprintf("PASSED-%d", i),
			intoto.Subject{Name: vsaBindingPrefix + vsaBindingCommit, Digest: map[string]string{"sha1": vsaBindingCommit}})
	}
	_, _, err := vsaBindingVerifyUnfiltered(t, key, pol, vsaBindingCommit, bare)
	var missing ErrMissingExternalAttestation
	require.ErrorAs(t, err, &missing)
	msg := err.Error()
	assert.Contains(t, msg, "40 candidate")
	assert.Contains(t, msg, "35 more refused candidate(s) omitted")
	assert.Len(t, missing.Refused, 5)
	assert.Equal(t, 35, missing.RefusedOmitted)
	assert.Less(t, len(msg), 8192, "message must be bounded: %d bytes", len(msg))
	assert.True(t, errors.As(err, &missing))
}
