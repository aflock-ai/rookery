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
// an earlier report: an envelope that IS loaded for a step but is dropped
// by the source's attestation-type or subject filter used to collapse into
// ErrNoCollections — a ~700-character "Likely causes, in order: (1) the
// attestation wasn't loaded ..." wall in which not one cause applied. These
// tests run the real engine over the real MemorySource (the source whose
// silent drop the issue names), on both the streamed and batch arms, and pin
// that the rejection names the envelope, the step, and the predicate that
// dropped it — and that the generic block survives for the case it is for.
// ---------------------------------------------------------------------------

const (
	ineligibleStep        = "push-tests"
	ineligibleGitType     = "https://aflock.ai/attestations/git/v0.1"
	ineligibleCmdRunType  = "https://aflock.ai/attestations/command-run/v0.2"
	ineligibleOtherDigest = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

// ineligibleCollection is fanoutFixture.collection with the step name and the
// attestation TYPES under test control: the filter being diagnosed is keyed on
// exactly those two things.
func ineligibleCollection(t *testing.T, f *fanoutFixture, ref, step string, types []string, digests ...string) source.CollectionEnvelope {
	t.Helper()
	atts := make([]attestation.CollectionAttestation, 0, len(types))
	for _, typ := range types {
		body, err := json.Marshal(map[string]any{"commithash": ref})
		require.NoError(t, err)
		atts = append(atts, attestation.CollectionAttestation{Type: typ, Attestation: attestation.NewRawAttestation(typ, body)})
	}
	predicate, err := json.Marshal(attestation.Collection{Name: step, Attestations: atts})
	require.NoError(t, err)
	subjects := make([]intoto.Subject, 0, len(digests))
	for i, d := range digests {
		subjects = append(subjects, intoto.Subject{Name: "artifact-" + string(rune('0'+i)), Digest: map[string]string{"sha256": d}})
	}
	stmt := intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		Subject:       subjects,
		PredicateType: "https://aflock.ai/attestation-collection/v0.1",
		Predicate:     json.RawMessage(predicate),
	}
	payload, err := json.Marshal(stmt)
	require.NoError(t, err)
	env, err := dsse.Sign("application/vnd.in-toto+json", bytes.NewReader(payload), dsse.SignWithSigners(f.signer))
	require.NoError(t, err)
	return source.CollectionEnvelope{Envelope: env, Statement: stmt, Reference: ref}
}

func ineligiblePolicy(f *fanoutFixture, step string, types ...string) Policy {
	atts := make([]Attestation, 0, len(types))
	for _, typ := range types {
		atts = append(atts, Attestation{Type: typ})
	}
	return Policy{
		Expires:    metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: map[string]PublicKey{f.keyID: {KeyID: f.keyID, Key: []byte(f.pubPEM)}},
		Steps: map[string]Step{step: {
			Name:          step,
			Attestations:  atts,
			Functionaries: []Functionary{{Type: "publickey", PublicKeyID: f.keyID}},
		}},
	}
}

// ineligibleArms presents one loaded MemorySource through both engine arms.
func ineligibleArms(t *testing.T, f *fanoutFixture, envs ...source.CollectionEnvelope) map[string]source.VerifiedSourcer {
	t.Helper()
	mem := source.NewMemorySource()
	for _, env := range envs {
		require.NoError(t, mem.LoadEnvelope(env.Reference, env.Envelope))
	}
	vs := source.NewVerifiedSource(mem, dsse.VerifyWithVerifiers(f.verifier))
	return map[string]source.VerifiedSourcer{"streamed": vs, "batch": batchOnlyVerifiedSourcer{inner: vs}}
}

// soleDiagnosis returns the one diagnostic rejection reason for the step —
// the entry the CLI renders as "verification failure: Reason: ..." — after
// filtering out the derivative "no passed collections present" artifact
// rejection the engine appends to every zero-passed step.
func soleDiagnosis(t *testing.T, results map[string]StepResult, step string) error {
	t.Helper()
	var reasons []error
	for _, rc := range results[step].Rejected {
		if rc.Reason == nil || strings.Contains(rc.Reason.Error(), "no passed collections present") {
			continue
		}
		reasons = append(reasons, rc.Reason)
	}
	require.Len(t, reasons, 1, "want exactly one diagnostic rejection for step %q, got %v", step, reasons)
	return reasons[0]
}

func TestDiagnose_LoadedButFilteredEnvelopeIsNamedWithItsReason(t *testing.T) {
	f := newFanoutFixture(t)
	// The envelope carries git only; the step also requires command-run — the
	// exact shape from the issue (a failing wrapped command drops command-run).
	pt := ineligibleCollection(t, f, "pt.json", ineligibleStep, []string{ineligibleGitType}, fanoutCommitDigest)
	p := ineligiblePolicy(f, ineligibleStep, ineligibleGitType, ineligibleCmdRunType)

	for arm, src := range ineligibleArms(t, f, pt) {
		t.Run(arm+"/missing attestation type", func(t *testing.T) {
			accepted, results, err := p.Verify(context.Background(), WithVerifiedSource(src), WithSubjectDigests([]string{fanoutCommitDigest}))
			require.NoError(t, err)
			assert.False(t, accepted, "an envelope missing a required attestation must not satisfy the step")

			reason := soleDiagnosis(t, results, ineligibleStep)
			msg := reason.Error()
			var ineligible ErrIneligibleCollections
			require.True(t, errors.As(reason, &ineligible), "want ErrIneligibleCollections, got %T: %v", reason, reason)
			assert.Contains(t, msg, `step "push-tests"`)
			assert.Contains(t, msg, "1 envelope loaded")
			assert.Contains(t, msg, "pt.json")
			assert.Contains(t, msg, "missing required attestation "+ineligibleCmdRunType)
			assert.Contains(t, msg, "(has: git/v0.1)")
			assert.NotContains(t, msg, "Likely causes", "the generic wall lists causes that do not apply when the envelope IS loaded")
			assert.NotContains(t, msg, "wasn't loaded")
			// The subjects DID match — the message must not blame them.
			assert.NotContains(t, msg, "supplied digest")

			// judge-api's readiness classifier (activities/cilock/readiness.go)
			// reads ErrNoCollections through errors.As to mean "evidence has
			// not arrived": an envelope without the required attestation is
			// still evidence that has not arrived, so that reading must hold.
			var noColl ErrNoCollections
			assert.True(t, errors.As(reason, &noColl), "must unwrap to ErrNoCollections for the PENDING classifier")
			var mismatch ErrSubjectDigestMismatch
			assert.False(t, errors.As(reason, &mismatch))
		})

		t.Run(arm+"/missing attestation type and subject", func(t *testing.T) {
			_, results, err := p.Verify(context.Background(), WithVerifiedSource(src), WithSubjectDigests([]string{ineligibleOtherDigest}))
			require.NoError(t, err)
			msg := soleDiagnosis(t, results, ineligibleStep).Error()
			assert.Contains(t, msg, "pt.json")
			assert.Contains(t, msg, "missing required attestation "+ineligibleCmdRunType)
			assert.Contains(t, msg, "none of the supplied digest(s) ["+ineligibleOtherDigest+"]")
			assert.Contains(t, msg, "subjects present: artifact-0 (sha256:"+fanoutCommitDigest+")")
			assert.NotContains(t, msg, "Likely causes")
		})
	}
}

// TestDiagnose_NothingLoadedKeepsTheGenericCauses pins the case the generic
// block exists for: the step name has NO envelope at all. The loaded envelope
// belongs to another step, so it must neither be named nor count.
func TestDiagnose_NothingLoadedKeepsTheGenericCauses(t *testing.T) {
	f := newFanoutFixture(t)
	other := ineligibleCollection(t, f, "other.json", "other-step", []string{ineligibleGitType}, fanoutCommitDigest)
	p := ineligiblePolicy(f, ineligibleStep, ineligibleGitType, ineligibleCmdRunType)

	for arm, src := range ineligibleArms(t, f, other) {
		t.Run(arm, func(t *testing.T) {
			accepted, results, err := p.Verify(context.Background(), WithVerifiedSource(src), WithSubjectDigests([]string{fanoutCommitDigest}))
			require.NoError(t, err)
			assert.False(t, accepted)
			reason := soleDiagnosis(t, results, ineligibleStep)
			var ineligible ErrIneligibleCollections
			assert.False(t, errors.As(reason, &ineligible), "nothing was loaded for this step; naming another step's envelope would be a lie")
			assert.Contains(t, reason.Error(), "no collection passed verification for step push-tests. Likely causes, in order:")
			assert.NotContains(t, reason.Error(), "other.json")
		})
	}
}

// TestDiagnose_EligibleTypeWithSubjectMismatchIsUnchanged pins that an
// envelope carrying every required attestation type but none of the supplied
// digests still yields ErrSubjectDigestMismatch — the pre-existing specific
// diagnosis — not the new ineligible report.
func TestDiagnose_EligibleTypeWithSubjectMismatchIsUnchanged(t *testing.T) {
	f := newFanoutFixture(t)
	pt := ineligibleCollection(t, f, "pt.json", ineligibleStep, []string{ineligibleGitType}, fanoutCommitDigest)
	p := ineligiblePolicy(f, ineligibleStep, ineligibleGitType)

	for arm, src := range ineligibleArms(t, f, pt) {
		t.Run(arm, func(t *testing.T) {
			_, results, err := p.Verify(context.Background(), WithVerifiedSource(src), WithSubjectDigests([]string{ineligibleOtherDigest}))
			require.NoError(t, err)
			reason := soleDiagnosis(t, results, ineligibleStep)
			var mismatch ErrSubjectDigestMismatch
			require.True(t, errors.As(reason, &mismatch), "got %T: %v", reason, reason)
			var ineligible ErrIneligibleCollections
			assert.False(t, errors.As(reason, &ineligible))
		})
	}
}

// TestDiagnose_StepWithoutAttestationRequirementsProbesOnce pins the cost
// contract: when a step requires no attestation types, the filtered probe IS
// the unfiltered probe, so the diagnostic must not issue it twice.
func TestDiagnose_StepWithoutAttestationRequirementsProbesOnce(t *testing.T) {
	corpus := newDiagCorpus()
	err := diagnoseEmptyCollectionResult(context.Background(), diagStreamSource{corpus}, "build", []string{"nope"}, nil)
	var noColl ErrNoCollections
	require.True(t, errors.As(err, &noColl))
	assert.Equal(t, 1, corpus.probeCalls, "no attestation filter to relax: the second probe would repeat the first verbatim")
}

func TestErrIneligibleCollections_Error(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  ErrIneligibleCollections
		want string
	}{
		{
			name: "one envelope, missing type only",
			err: ErrIneligibleCollections{Step: "push-tests", Collections: []IneligibleCollection{{
				Reference:           "pt.json",
				MissingAttestations: []string{ineligibleCmdRunType},
				PresentAttestations: []string{"git/v0.1", "material/v0.3", "product/v0.3"},
			}}},
			want: `step "push-tests": 1 envelope loaded but not eligible: pt.json is missing required attestation ` + ineligibleCmdRunType + ` (has: git/v0.1, material/v0.3, product/v0.3)`,
		},
		{
			name: "two envelopes, both reasons, one signature failure, sample truncated",
			err: ErrIneligibleCollections{Step: "secrets", Truncated: true, Collections: []IneligibleCollection{
				{
					Reference:           "pt.json",
					MissingAttestations: []string{"https://a/x", "https://a/y"},
					PresentAttestations: []string{"git/v0.1"},
					SuppliedDigests:     []string{"d1", "d2"},
					ObservedSubjects:    []string{"commithash:abc (sha1:abc)"},
					SubjectMismatch:     true,
				},
				{
					Reference:           "sec.json",
					MissingAttestations: []string{"https://a/x"},
					SignatureErrors:     []string{"no valid signatures"},
				},
			}},
			want: `step "secrets": at least 2 envelopes loaded but none eligible: pt.json is missing required attestations https://a/x, https://a/y (has: git/v0.1) and carries none of the supplied digest(s) [d1, d2] (subjects present: commithash:abc (sha1:abc)); sec.json is missing required attestation https://a/x (has: none) and its signature did not verify (no valid signatures)`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.err.Error())
			assert.NotContains(t, tc.err.Error(), "Likely causes")
			var noColl ErrNoCollections
			require.True(t, errors.As(tc.err, &noColl))
			assert.Equal(t, tc.err.Step, noColl.Step)
		})
	}
}
