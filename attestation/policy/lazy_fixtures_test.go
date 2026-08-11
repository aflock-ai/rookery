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
	"crypto"
	"fmt"
	"sort"

	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ---------------------------------------------------------------------------
// Fixtures for the minimum-witness (lazy) Phase 1 suite.
//
// Everything here is prefixed lazy* so it cannot collide with the shared
// fixtures in policy_test.go / rejected_dedup_test.go / searchdepth_*.
// ---------------------------------------------------------------------------

const (
	lazyAttType        = "https://example.com/lazy-att/v1"
	lazyTaintedAttType = "https://example.com/lazy-tainted/v1"
	lazyChainAttType   = "https://aflock.ai/attestations/material/v0.3"
)

// lazyAttestor is a marshalable attestor that can also carry inline material /
// product leaves, so one type covers both the plain-gate shapes and the
// artifactsFrom chain shapes.
type lazyAttestor struct {
	AttName   string `json:"name"`
	AttType   string `json:"type"`
	materials map[string]cryptoutil.DigestSet
	products  map[string]attestation.Product
	inline    bool
}

func (a *lazyAttestor) Name() string                                   { return a.AttName }
func (a *lazyAttestor) Type() string                                   { return a.AttType }
func (a *lazyAttestor) RunType() attestation.RunType                   { return attestation.PostProductRunType }
func (a *lazyAttestor) Schema() *jsonschema.Schema                     { return nil }
func (a *lazyAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *lazyAttestor) Materials() map[string]cryptoutil.DigestSet     { return a.materials }
func (a *lazyAttestor) Products() map[string]attestation.Product       { return a.products }
func (a *lazyAttestor) VerifyInlineLeaves() error                      { return nil }
func (a *lazyAttestor) HasInlineLeaves() bool                          { return a.inline }

func lazyDigest(hexstr string) cryptoutil.DigestSet {
	return cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: hexstr}
}

// lazyStatement gives every fixture collection a DISTINCT in-toto statement.
//
// THE FIXTURE TRAP (design doc §10.7): passedCollectionKey hashes only the
// Statement plus the verified key IDs, so N fixtures built "the obvious way"
// with an identical statement collapse to ONE entry inside
// mergePassedCollections — which would vacuum out every count this suite
// measures. TestLazyFixtures_DistinctStatementsDoNotCollapse pins that these
// do not collapse.
func lazyStatement(ref string) intoto.Statement {
	return intoto.Statement{
		PredicateType: attestation.CollectionType,
		Subject:       []intoto.Subject{{Name: ref, Digest: map[string]string{"sha256": fmt.Sprintf("%064x", len(ref)*7919+int(ref[0]))}}},
	}
}

// lazyCollection builds a functionary-verifiable candidate for stepName.
func lazyCollection(verifier cryptoutil.Verifier, ref, stepName, backRef string, attestors ...attestation.Attestor) source.CollectionVerificationResult {
	cas := make([]attestation.CollectionAttestation, 0, len(attestors))
	for _, at := range attestors {
		cas = append(cas, attestation.CollectionAttestation{Type: at.Type(), Attestation: at})
	}
	coll := attestation.Collection{Name: stepName, Attestations: cas}
	if backRef != "" {
		coll.RecordedBackRefs = map[string]cryptoutil.DigestSet{"ref": newDigestSet(backRef)}
	}
	return source.CollectionVerificationResult{
		Verifiers: []cryptoutil.Verifier{verifier},
		CollectionEnvelope: source.CollectionEnvelope{
			Reference:  ref,
			Collection: coll,
			Statement:  lazyStatement(ref),
		},
	}
}

// lazyPlain is the common case: one candidate carrying the step's required
// attestation type and nothing else.
func lazyPlain(verifier cryptoutil.Verifier, ref, stepName, backRef string) source.CollectionVerificationResult {
	return lazyCollection(verifier, ref, stepName, backRef,
		&lazyAttestor{AttName: ref, AttType: lazyAttType})
}

// lazyBadSig is a candidate whose signature did not verify upstream — the
// shape VerifiedSource hands back for an untrusted signer. checkFunctionaries
// / triageOne routes it to Rejected, so it can never satisfy a step. Used to
// build FAIL corpora whose examination must stay exhaustive.
func lazyBadSig(ref, stepName string) source.CollectionVerificationResult {
	return source.CollectionVerificationResult{
		Errors: []error{fmt.Errorf("failed to verify envelope: no matching signatures")},
		CollectionEnvelope: source.CollectionEnvelope{
			Reference: ref,
			Collection: attestation.Collection{
				Name:         stepName,
				Attestations: []attestation.CollectionAttestation{{Type: lazyAttType, Attestation: &lazyAttestor{AttName: ref, AttType: lazyAttType}}},
			},
			Statement: lazyStatement(ref),
		},
	}
}

// ---------------------------------------------------------------------------
// lazySource: a reachability-by-digest source that STREAMS and counts.
//
// It models judge-api's EntSource (no seen-envelope exclusion across calls),
// which is the shape that makes the depth loop re-adjudicate — and therefore
// the shape a lazy stop has to be correct against. The streaming presentation
// replays Search exactly as (*source.VerifiedSource).SearchStream does over a
// non-streaming Sourcer, so the candidate SEQUENCE is identical between eager
// and lazy runs of the same fixture and the only variable is where the
// consumer stops.
// ---------------------------------------------------------------------------
type lazySource struct {
	byDigest map[string][]source.CollectionVerificationResult
	// unfiltered feeds the empty-result diagnostic probe (subjectDigests==nil).
	unfiltered map[string][]source.CollectionVerificationResult

	// yielded counts candidates handed to the policy engine — the direct
	// analogue of a prod envelope download + DSSE verification.
	yielded int
	// distinct records the reference of every candidate ever yielded, so a
	// test can compare the EXAMINED SET (not just the count) between arms.
	distinct map[string]struct{}
	probes   int
	searches int

	// ordered makes matches() sort by Reference, modelling an ORDER BY in the
	// query. It is only meaningful in combination with a wrapper that DECLARES
	// source.CanonicalOrderSourcer — sorting without declaring buys nothing,
	// and declaring without sorting is a lie the engine cannot detect.
	ordered bool
}

func newLazySource(byDigest map[string][]source.CollectionVerificationResult) *lazySource {
	return &lazySource{byDigest: byDigest, distinct: map[string]struct{}{}}
}

func (s *lazySource) withUnfiltered(u map[string][]source.CollectionVerificationResult) *lazySource {
	s.unfiltered = u
	return s
}

// Search is the batch presentation. It counts every candidate it returns,
// because the batch arm consumes all of them by construction.
func (s *lazySource) Search(_ context.Context, stepName string, subjectDigests, _ []string) ([]source.CollectionVerificationResult, error) {
	if len(subjectDigests) == 0 {
		s.probes++
		return append([]source.CollectionVerificationResult(nil), s.unfiltered[stepName]...), nil
	}
	s.searches++
	out := s.matches(stepName, subjectDigests)
	for i := range out {
		s.record(out[i])
	}
	return out, nil
}

// SearchStream is the presentation prod takes. Candidates are counted ONE AT A
// TIME as they are consumed, so a consumer that aborts the stream is measured
// as having examined only what it actually pulled.
func (s *lazySource) SearchStream(_ context.Context, stepName string, subjectDigests, _ []string, yield func(source.CollectionVerificationResult) error) error {
	if len(subjectDigests) == 0 {
		s.probes++
		for _, cvr := range s.unfiltered[stepName] {
			s.record(cvr)
			if err := yield(cvr); err != nil {
				return err
			}
		}
		return nil
	}
	s.searches++
	for _, cvr := range s.matches(stepName, subjectDigests) {
		s.record(cvr)
		if err := yield(cvr); err != nil {
			return err
		}
	}
	return nil
}

func (s *lazySource) SearchByPredicateType(_ context.Context, _ []string, _ []string) ([]source.StatementEnvelope, error) {
	return nil, nil
}

// CanonicalStreamOrder: an in-memory fixture whose corpus is a fixed slice
// yields the same sequence on every call, for every run — which is exactly
// what the contract asks for. Declaring it here keeps the shape table testing
// the LAZY path; the wrappers in lazy_order_test.go are what model sources
// that cannot make the promise.
func (s *lazySource) CanonicalStreamOrder() bool { return true }

func (s *lazySource) record(cvr source.CollectionVerificationResult) {
	s.yielded++
	s.distinct[cvr.Reference] = struct{}{}
}

// matches applies the digest-reachability filter. It de-duplicates WITHIN one
// call (a real query returns a row once) but deliberately NOT across calls.
//
// When `ordered` is set it sorts the result by Reference before returning —
// modelling an ORDER BY inside the QUERY, which is where judge-api's EntSource
// does it. That placement is load-bearing for the fixture: ordering must happen
// before candidates are handed out one at a time, so a consumer that aborts the
// stream still pays for only the rows it actually pulled.
func (s *lazySource) matches(stepName string, subjectDigests []string) []source.CollectionVerificationResult {
	out := make([]source.CollectionVerificationResult, 0)
	seen := map[string]struct{}{}
	for _, d := range subjectDigests {
		for _, cvr := range s.byDigest[d] {
			if cvr.Collection.Name != stepName {
				continue
			}
			if _, dup := seen[cvr.Reference]; dup {
				continue
			}
			seen[cvr.Reference] = struct{}{}
			out = append(out, cvr)
		}
	}
	if s.ordered {
		sort.Slice(out, func(i, j int) bool { return out[i].Reference < out[j].Reference })
	}
	return out
}

func (s *lazySource) examined() []string {
	out := make([]string, 0, len(s.distinct))
	for ref := range s.distinct {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// lazyBatchSource hides SearchStream so a fixture can be forced down the batch
// arm. The inner source is held in a NAMED field, never embedded: an embedded
// *lazySource would PROMOTE SearchStream, the type would satisfy
// StreamingVerifiedSourcer after all, and every "batch" run would silently
// take the streamed arm.
type lazyBatchSource struct{ inner *lazySource }

func (s lazyBatchSource) Search(ctx context.Context, stepName string, subjectDigests, attestations []string) ([]source.CollectionVerificationResult, error) {
	return s.inner.Search(ctx, stepName, subjectDigests, attestations)
}

func (s lazyBatchSource) SearchByPredicateType(ctx context.Context, pts []string, sd []string) ([]source.StatementEnvelope, error) {
	return s.inner.SearchByPredicateType(ctx, pts, sd)
}

// The batch control DECLARES canonical order deliberately, so
// TestLazyWitness_BatchArmIsUnaffected proves the stronger claim: even with
// every lazy precondition satisfied, the batch arm is untouched.
func (s lazyBatchSource) CanonicalStreamOrder() bool { return true }

var (
	_ source.VerifiedSourcer          = (*lazySource)(nil)
	_ source.StreamingVerifiedSourcer = (*lazySource)(nil)
	_ source.CanonicalOrderSourcer    = (*lazySource)(nil)
	_ source.VerifiedSourcer          = lazyBatchSource{}
	_ source.CanonicalOrderSourcer    = lazyBatchSource{}
)

// ---------------------------------------------------------------------------
// Policy builders
// ---------------------------------------------------------------------------

func lazyStep(name, keyID string) Step {
	return Step{
		Name:          name,
		Functionaries: []Functionary{{PublicKeyID: keyID}},
		Attestations:  []Attestation{{Type: lazyAttType}},
	}
}

func lazyPolicy(keyID string, steps ...Step) Policy {
	m := make(map[string]Step, len(steps))
	for _, s := range steps {
		m[s.Name] = s
	}
	return Policy{
		Expires: metav1.Time{Time: time.Now().Add(time.Hour)},
		Steps:   m,
	}
}
