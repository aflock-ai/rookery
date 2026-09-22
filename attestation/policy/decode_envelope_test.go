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
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The policy predicate types, spelled literally so a test cannot pass by
// comparing a constant with itself.
const (
	decTypeV01       = "https://aflock.ai/policy/v0.1"
	decTypeLegacyV01 = "https://witness.testifysec.com/policy/v0.1"
	decTypeV02       = "https://aflock.ai/policy/v0.2"
)

// decPolicyJSON is hsecPolicy as the signed bytes an author's file holds, with
// edit applied to the decoded document first (nil for none).
func decPolicyJSON(t *testing.T, keyID string, edit func(doc map[string]any)) []byte {
	t.Helper()
	raw, err := json.Marshal(hsecPolicy(keyID, nil))
	require.NoError(t, err)
	if edit == nil {
		return raw
	}
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	edit(doc)
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

// decStep returns the named step object of a decoded policy document.
func decStep(doc map[string]any, name string) map[string]any {
	return doc["steps"].(map[string]any)[name].(map[string]any)
}

// decAbout sets "about" on the named steps.
func decAbout(value string, steps ...string) func(doc map[string]any) {
	return func(doc map[string]any) {
		for _, s := range steps {
			decStep(doc, s)["about"] = value
		}
	}
}

func requireRefused(t *testing.T, err error, reason string) {
	t.Helper()
	require.Error(t, err)
	var refused ErrPolicyRefused
	require.True(t, errors.As(err, &refused), "want ErrPolicyRefused(%s), got %T: %v", reason, err, err)
	require.Equal(t, reason, refused.Reason)
	require.Contains(t, err.Error(), reason, "the reason string is what operators and the closed list key on")
}

// ---------------------------------------------------------------------------
// The shared decoder (design 3.6, revision 4.3 F43-5). The engine never sees
// the envelope, so the type allowlist, the strict v0.2 decode and the version
// stamp live in one decoder the verify entry calls.
// ---------------------------------------------------------------------------

// R27f / PV8, the decoder half: exactly three payload types decode. Anything
// else, including an empty type and near-miss spellings, is refused before a
// byte of the payload is trusted, so a 4.6.0 v0.3 policy cannot be decoded
// with its restrictions silently dropped.
func TestDecodePolicyEnvelope_TypeAllowlist(t *testing.T) {
	doc := decPolicyJSON(t, "k", nil)
	for _, pt := range []string{decTypeV01, decTypeLegacyV01, decTypeV02} {
		_, err := DecodePolicyEnvelope(pt, doc)
		require.NoError(t, err, "payload type %q is on the allowlist", pt)
	}
	for _, pt := range []string{
		"",
		"https://aflock.ai/policy/v0.3",
		"https://aflock.ai/policy/v0.2 ",
		"HTTPS://AFLOCK.AI/POLICY/V0.2",
		"https://witness.testifysec.com/policy/v0.2",
		"https://aflock.ai/policy/",
		"application/vnd.in-toto+json",
	} {
		t.Run(pt, func(t *testing.T) {
			got, err := DecodePolicyEnvelope(pt, doc)
			requireRefused(t, err, ReasonPolicyTypeUnknown)
			require.Empty(t, got.Steps, "a refused envelope decodes nothing")
			require.Equal(t, policyVersionUnknown, got.payloadVersion)
		})
	}
}

// R27f / PV8: v0.2 decodes strictly; v0.1 keeps today's lenient decode, so no
// signed v0.1 policy in the wild changes meaning.
func TestDecodePolicyEnvelope_V02DecodesStrictly(t *testing.T) {
	cases := map[string]func(doc map[string]any){
		"top-level field": func(doc map[string]any) { doc["links"] = []any{"x"} },
		"step field":      func(doc map[string]any) { decStep(doc, "secrets")["seedMatch"] = "recomputed" },
		"attestation field": func(doc map[string]any) {
			decStep(doc, "secrets")["attestations"].([]any)[0].(map[string]any)["maxMatches"] = 1
		},
		"functionary field": func(doc map[string]any) {
			decStep(doc, "build")["functionaries"].([]any)[0].(map[string]any)["from"] = "build"
		},
		// ExternalAttestation has its own UnmarshalJSON (the Required default),
		// and a custom unmarshaler escapes the outer DisallowUnknownFields. The
		// strict decode must still see inside it.
		"external attestation field": func(doc map[string]any) {
			doc["externalAttestations"] = map[string]any{"vsa": map[string]any{
				"name": "vsa", "predicateType": "https://slsa.dev/verification_summary/v1",
				"functionaries": []any{}, "required": false, "seedMatch": "recomputed",
			}}
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			raw := decPolicyJSON(t, "k", edit)
			_, err := DecodePolicyEnvelope(decTypeV02, raw)
			require.Error(t, err, "v0.2 refuses a member it does not know")
			require.Contains(t, err.Error(), "unknown field")

			for _, pt := range []string{decTypeV01, decTypeLegacyV01} {
				_, err := DecodePolicyEnvelope(pt, raw)
				require.NoError(t, err, "v0.1 (%s) decodes leniently, exactly as json.Unmarshal did", pt)
			}
		})
	}

	t.Run("trailing data", func(t *testing.T) {
		raw := append(decPolicyJSON(t, "k", nil), []byte(` {}`)...)
		for _, pt := range []string{decTypeV01, decTypeLegacyV01, decTypeV02} {
			_, err := DecodePolicyEnvelope(pt, raw)
			require.Error(t, err, "%s: a second JSON value after the policy is refused (json.Unmarshal refused it too)", pt)
		}
	})

	t.Run("not json", func(t *testing.T) {
		for _, pt := range []string{decTypeV01, decTypeLegacyV01, decTypeV02} {
			_, err := DecodePolicyEnvelope(pt, []byte(`not json`))
			require.Error(t, err)
		}
	})
}

// Known positive for the strict decode: everything the Policy type itself
// writes decodes under v0.2. A strict decoder that refused a field of its own
// type would refuse legitimate policies, and the arms above would still pass.
func TestDecodePolicyEnvelope_V02AcceptsEverythingThePolicyTypeWrites(t *testing.T) {
	yes := 0.9
	notBefore := metav1.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	fn := []Functionary{
		{Type: "publickey", PublicKeyID: "k"},
		{Type: "root", CertConstraint: CertConstraint{
			CommonName: "*", DNSNames: []string{"*"}, Emails: []string{"*"}, Organizations: []string{"*"},
			URIs: []string{"*"}, Roots: []string{"r"}, RequiredPolicyOIDs: []string{"1.3.6.1.4.1.57264.1.99"},
		}},
	}
	full := Policy{
		Expires:              metav1.NewTime(time.Now().Add(time.Hour).UTC().Truncate(time.Second)),
		Roots:                map[string]Root{"r": {Certificate: []byte("c"), Intermediates: [][]byte{[]byte("i")}}},
		TimestampAuthorities: map[string]Root{"t": {Certificate: []byte("c")}},
		PublicKeys:           map[string]PublicKey{"k": {KeyID: "k", Key: []byte("pem")}},
		Steps: map[string]Step{
			"build": {Name: "build", Functionaries: fn, Attestations: []Attestation{{Type: hsecBuildType}}},
			"secrets": {
				Name:          "secrets",
				Functionaries: fn,
				Attestations: []Attestation{{
					Type:         hsecScanType,
					RegoPolicies: []RegoPolicy{{Name: "no-findings", Module: hsecDenyFindings}},
					AiPolicies: []AiPolicy{{Name: "q", Model: "m", Decision: &AiDecision{
						YesNo: &AiYesNo{Instructions: "is it clean", MinProbability: &yes},
					}}},
				}},
				ArtifactsFrom:       []string{"build"},
				AttestationsFrom:    []string{"build"},
				ExternalFrom:        []string{"vsa"},
				AllowedUntracked:    []string{"/usr/lib/**"},
				TimestampConstraint: &TimestampConstraint{NotBefore: &notBefore, MaxAge: "720h"},
				About:               StepAboutSource,
			},
		},
		ExternalAttestations: map[string]ExternalAttestation{"vsa": {
			Name: "vsa", PredicateType: "https://slsa.dev/verification_summary/v1",
			Functionaries: fn, RegoPolicies: []RegoPolicy{{Name: "r", Module: []byte("package r")}}, Required: true,
		}},
	}
	raw, err := json.Marshal(full)
	require.NoError(t, err)

	got, err := DecodePolicyEnvelope(decTypeV02, raw)
	require.NoError(t, err, "the strict v0.2 decode must accept every field the Policy type writes")
	again, err := json.Marshal(got)
	require.NoError(t, err)
	require.JSONEq(t, string(raw), string(again), "strict decoding loses nothing")
}

// Author comment keys ("_comment", "_renewal_policy"), the shape the in-tree
// deploy policies use. v0.1 decodes them exactly as json.Unmarshal does; under
// v0.2 the same bytes are refused, which is the design's strict decode
// (DisallowUnknownFields). Stated here so moving such a file to v0.2 is a
// visible decision, not a surprise at verify.
func TestDecodePolicyEnvelope_AuthorCommentKeys(t *testing.T) {
	raw := decPolicyJSON(t, "k", func(doc map[string]any) {
		doc["_comment"] = "reviewers read this"
		doc["_renewal_policy"] = "bump expires every release"
	})

	var want Policy
	require.NoError(t, json.Unmarshal(raw, &want))
	for _, pt := range []string{decTypeV01, decTypeLegacyV01} {
		got, err := DecodePolicyEnvelope(pt, raw)
		require.NoError(t, err)
		require.Equal(t, policyVersionV01, got.payloadVersion)
		got.payloadVersion = policyVersionUnknown
		require.Equal(t, want, got, "v0.1 decode is json.Unmarshal, unchanged")
	}

	_, err := DecodePolicyEnvelope(decTypeV02, raw)
	require.Error(t, err)
	require.Contains(t, err.Error(), `unknown field "_comment"`)
}

// The stamp: set only by the decoder, zero means unknown (never v0.2), carried
// by value copies and DeepCopy, and never serialized.
func TestDecodePolicyEnvelope_StampsTheVersion(t *testing.T) {
	doc := decPolicyJSON(t, "k", decAbout(StepAboutSource, "secrets"))

	for pt, want := range map[string]policyVersion{
		decTypeV01:       policyVersionV01,
		decTypeLegacyV01: policyVersionV01,
		decTypeV02:       policyVersionV02,
	} {
		got, err := DecodePolicyEnvelope(pt, doc)
		require.NoError(t, err)
		require.Equal(t, want, got.payloadVersion, "payload type %s", pt)
	}

	var zero Policy
	require.Equal(t, policyVersionUnknown, zero.payloadVersion)
	require.NotEqual(t, policyVersionV02, zero.payloadVersion, "the zero value must never mean v0.2")

	var plain Policy
	require.NoError(t, json.Unmarshal(doc, &plain))
	require.Equal(t, policyVersionUnknown, plain.payloadVersion, "json.Unmarshal cannot stamp")

	v02, err := DecodePolicyEnvelope(decTypeV02, doc)
	require.NoError(t, err)
	byValue := v02
	require.Equal(t, policyVersionV02, byValue.payloadVersion)
	require.Equal(t, policyVersionV02, v02.DeepCopy().payloadVersion)

	out, err := json.Marshal(v02)
	require.NoError(t, err)
	require.NotContains(t, string(out), "payloadVersion")
	var roundTrip Policy
	require.NoError(t, json.Unmarshal(out, &roundTrip))
	require.Equal(t, policyVersionUnknown, roundTrip.payloadVersion, "a JSON round trip drops the stamp: fail closed")
}

// ---------------------------------------------------------------------------
// The engine's refusal (R27f engine arms, including the sixth: a v0.2-shaped
// Policy that never went through the decoder). Every refusal happens before
// any evidence is searched.
// ---------------------------------------------------------------------------

func decVerify(t *testing.T, pol Policy, key hsecKey) (bool, map[string]StepResult, *hsecSource, error) {
	t.Helper()
	src := newHsecSource(key.verifier, "C-build", "C-secrets-clean")
	accepted, results, err := pol.Verify(context.Background(),
		WithVerifiedSource(src),
		WithSubjectDigests([]string{hsecC}),
	)
	return accepted, results, src, err
}

func TestVerify_AboutNeedsTheV02Stamp(t *testing.T) {
	key := newHsecKey(t)
	withAbout := decPolicyJSON(t, key.keyID, decAbout(StepAboutSource, "secrets"))

	decoded := func(pt string, raw []byte) Policy {
		p, err := DecodePolicyEnvelope(pt, raw)
		require.NoError(t, err)
		return p
	}
	var unmarshaled Policy
	require.NoError(t, json.Unmarshal(withAbout, &unmarshaled))
	handBuilt := hsecPolicy(key.keyID, nil)
	s := handBuilt.Steps["secrets"]
	s.About = StepAboutSource
	handBuilt.Steps["secrets"] = s

	refusals := []struct {
		name   string
		pol    Policy
		reason string
	}{
		{"hand-built v0.2-shaped Policy, never decoded (sixth arm)", handBuilt, ReasonAboutNeedsPolicyV02},
		{"v0.2 bytes decoded with json.Unmarshal", unmarshaled, ReasonAboutNeedsPolicyV02},
		{"aflock v0.1 with about", decoded(decTypeV01, withAbout), ReasonAboutNeedsPolicyV02},
		{"legacy v0.1 with about", decoded(decTypeLegacyV01, withAbout), ReasonAboutNeedsPolicyV02},
		{"v0.2 with about: seed", decoded(decTypeV02, decPolicyJSON(t, key.keyID, decAbout("seed", "secrets"))), ReasonAboutUnknownValue},
		{"v0.2 with about: Source (values are case-sensitive)", decoded(decTypeV02, decPolicyJSON(t, key.keyID, decAbout("Source", "secrets"))), ReasonAboutUnknownValue},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			accepted, results, src, err := decVerify(t, tc.pol, key)
			requireRefused(t, err, tc.reason)
			require.False(t, accepted)
			require.Empty(t, results)
			require.Empty(t, src.searched, "the policy is refused before any evidence is searched")
		})
	}

	accepts := []struct {
		name string
		pol  Policy
	}{
		{"v0.2 with about: source", decoded(decTypeV02, withAbout)},
		{"aflock v0.1 without about", decoded(decTypeV01, decPolicyJSON(t, key.keyID, nil))},
		{"hand-built without about", hsecPolicy(key.keyID, nil)},
	}
	for _, tc := range accepts {
		t.Run(tc.name, func(t *testing.T) {
			accepted, results, _, err := decVerify(t, tc.pol, key)
			require.NoError(t, err)
			require.True(t, accepted, "C's own build and clean scan satisfy both steps")
			require.Equal(t, []string{"C-secrets-clean"}, hsecPassedRefs(results["secrets"]))
		})
	}
}

// ---------------------------------------------------------------------------
// About is a grant of reach, not a requirement (design 3.6: "Before LA-4 they
// are fail-closed only ... on v0.2 its about: source steps get only depth-0
// witnesses"; after LA-4 an about: source step accepts every witness it
// accepts today PLUS what the declared link reaches).
//
// The property, over a table of policies and evidence sets:
//   - monotone, the half that must survive LA-4: adding About to a step never
//     removes a witness any step would otherwise pass on, so it never turns a
//     PASS into a FAIL;
//   - today, the half LA-4 relaxes to the one above: adding About changes
//     nothing at all, neither the verdict nor any step's passed or rejected
//     set, and a v0.2 policy verifies exactly like the same v0.1 policy.
// ---------------------------------------------------------------------------

type decRun struct {
	accepted bool
	passed   map[string][]string
	rejected map[string][]string
}

func decRunOf(accepted bool, results map[string]StepResult) decRun {
	r := decRun{accepted: accepted, passed: map[string][]string{}, rejected: map[string][]string{}}
	for name, sr := range results {
		r.passed[name] = hsecPassedRefs(sr)
		rej := make([]string, 0, len(sr.Rejected))
		for _, rc := range sr.Rejected {
			rej = append(rej, rc.Collection.Reference)
		}
		sort.Strings(rej)
		r.rejected[name] = rej
	}
	return r
}

func TestAbout_IsAGrantOfReachNeverARequirement(t *testing.T) {
	corpora := []struct {
		name  string
		refs  []string
		seeds []string
	}{
		{"own clean scan", []string{"C-build", "C-secrets-clean"}, []string{hsecC}},
		{"own dirty scan", []string{"C-build", "C-secrets-dirty"}, []string{hsecC}},
		{"own clean and dirty scans", []string{"C-build", "C-secrets-clean", "C-secrets-dirty"}, []string{hsecC}},
		{"parent's clean scan, parent unseeded", []string{"C-build", "C-secrets-dirty", "P-build", "P-secrets-clean"}, []string{hsecC}},
		{"parent's clean scan, parent seeded", []string{"C-build", "C-secrets-dirty", "P-build", "P-secrets-clean"}, []string{hsecC, hsecP}},
		{"child names C", []string{"C-build", "C-secrets-dirty", "K-secrets-clean"}, []string{hsecC}},
		{"sibling seeded", []string{"C-build", "C-secrets-dirty", "S-secrets-clean"}, []string{hsecC, hsecS}},
		{"tree-root link seeded", []string{"C-build-tree", "C-secrets-dirty", "T-secrets-nogit"}, []string{hsecC, hsecTreeRoot}},
		{"no-git scan indexed under C", []string{"C-build", "N-secrets-nogit"}, []string{hsecC}},
		{"two-git scan", []string{"C-build", "D-secrets-twogit"}, []string{hsecC}},
		{"no build", []string{"C-secrets-clean"}, []string{hsecC}},
		{"nothing seeded matches", []string{"C-build", "C-secrets-clean"}, []string{hsecG}},
	}
	aboutSets := [][]string{{"secrets"}, {"build"}, {"build", "secrets"}}

	key := newHsecKey(t)
	base := decPolicyJSON(t, key.keyID, nil)
	decode := func(pt string, raw []byte) Policy {
		p, err := DecodePolicyEnvelope(pt, raw)
		require.NoError(t, err)
		return p
	}
	run := func(t *testing.T, pol Policy, refs, seeds []string, arm string, bound bool) decRun {
		t.Helper()
		src := newHsecSource(key.verifier, refs...)
		var vsrc source.VerifiedSourcer = src
		opts := []VerifyOption{WithSubjectDigests(seeds)}
		switch arm {
		case "batch":
			vsrc = hsecBatch{inner: src}
		case "lazy":
			opts = append(opts, WithLazyStepSatisfaction(true))
		}
		opts = append(opts, WithVerifiedSource(vsrc))
		if bound {
			opts = append(opts, WithCommitBinding(hsecC))
		}
		accepted, results, err := pol.Verify(context.Background(), opts...)
		require.NoError(t, err)
		return decRunOf(accepted, results)
	}

	var sawPass, sawFail, sawWitnessUnderAbout bool
	for _, c := range corpora {
		for _, arm := range hsecArms {
			for _, bound := range []bool{false, true} {
				name := c.name + "/" + arm
				if bound {
					name += "/bound"
				}
				t.Run(name, func(t *testing.T) {
					without := run(t, decode(decTypeV02, base), c.refs, c.seeds, arm, bound)
					v01 := run(t, decode(decTypeV01, base), c.refs, c.seeds, arm, bound)
					require.Equal(t, v01, without, "a v0.2 policy without About verifies exactly like v0.1")
					if without.accepted {
						sawPass = true
					} else {
						sawFail = true
					}

					for _, steps := range aboutSets {
						with := run(t, decode(decTypeV02, decPolicyJSON(t, key.keyID, decAbout(StepAboutSource, steps...))), c.refs, c.seeds, arm, bound)

						// Monotone: the grant never takes a witness away.
						if without.accepted {
							require.True(t, with.accepted, "About on %v turned a PASS into a FAIL", steps)
						}
						for step, refs := range without.passed {
							require.Subset(t, with.passed[step], refs, "About on %v removed a witness of step %s", steps, step)
							for _, s := range steps {
								if s == step && len(with.passed[step]) > 0 {
									sawWitnessUnderAbout = true
								}
							}
						}

						// Today: no change at all (depth-0 witnesses only).
						require.Equal(t, without, with, "About on %v must not change any result before the declared link lands", steps)
					}
				})
			}
		}
	}
	require.True(t, sawPass, "the table must hold a PASS, or 'never turns a PASS into a FAIL' is vacuous")
	require.True(t, sawFail, "the table must hold a FAIL")
	require.True(t, sawWitnessUnderAbout, "some step declared about must pass on a witness, or 'never removes a witness' is vacuous")
}
