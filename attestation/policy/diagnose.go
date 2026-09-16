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
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/source"
)

// maxDiagnosticProbeCollections bounds how many collections the empty-result
// diagnostic will pull from the source.
//
// The bound is sized by what the MESSAGE needs, not by what the cost budget
// allows, which is what makes it obviously correct:
//
//   - Deciding ErrNoCollections vs ErrSubjectDigestMismatch needs exactly ONE
//     collection — "does this step have any evidence at all?" is answered by
//     the first one that arrives.
//   - The rest is illustration. ObservedSubjects exists so an operator can see
//     what the step DOES attest; four collections' worth of subjects is a
//     readable list, and a longer one stops being read.
//
// It bounds the number of COLLECTIONS, not the number of subjects within them:
// for a corpus at or below the bound the rendered message is byte-identical to
// the unbounded one, so nothing about the common case changes.
//
// Prod motivation: the unbounded probe re-fetched and re-verified the whole
// historical corpus for a step name — 806 candidate envelopes, four times in
// one 30-minute window — to build an error string.
const maxDiagnosticProbeCollections = 4

// errDiagnosticProbeSatisfied is the sentinel the bounded probe returns from
// its yield to stop a streaming source mid-iteration. StreamingSourcer's
// contract makes an abort first-class: no further candidates are fetched, and
// the source marks NOTHING as seen.
//
// SCOPE OF THAT GUARANTEE — read this before relying on it. It holds ON THE
// ABORT PATH ONLY, i.e. when the corpus exceeds maxDiagnosticProbeCollections
// and this sentinel actually fires. A stream of 1..bound collections ends on
// its own, SearchStream returns nil, and a seen-tracking source commits every
// collection it delivered — so the probe DOES consume a small corpus.
//
// That residue is inherited, not introduced: before the bound the probe
// drained the stream at every size, so an unbounded probe marked the WHOLE
// corpus seen no matter how large it was. The bound strictly removes mutation
// (above the bound: nothing; at or below: unchanged) and adds none.
// TestProbeBound_ExactBoundary asserts that size by size against the legacy
// oracle, so the claim is checked rather than asserted here.
//
// Closing the remainder is the source's job, not the diagnostic's, and it is
// now closed: both seen-tracking sources gate their seen-set on
// source.IsDiagnosticProbe — judge-api's EntSource always did, ArchivistaSource
// does since testifysec/judge#7592 — so a probe mutates nothing at any corpus
// size. A probe must not mutate what the real search can still find, and only
// the source can promise that at every size; this bound only ever removes
// fetches.
//
// It never escapes probeStepEvidence.
var errDiagnosticProbeSatisfied = errors.New("diagnostic probe: sample bound reached")

// diagnoseEmptyCollectionResult is called when the subject-filtered Search
// for (stepName, subjectDigests) returns zero collections. It re-probes the
// source to find out WHY, asking at most two bounded questions:
//
//   - With an empty subject filter and the step's attestation filter:
//     >0 collections → ErrSubjectDigestMismatch. An envelope carrying every
//     required attestation type IS loaded; the operator's --artifactfile /
//     --subjects digest just doesn't match anything in it. Surface the
//     observed subjects so the operator can see what they ARE asked to
//     verify against.
//   - Otherwise, and only when the step requires attestation types, with
//     NEITHER filter: >0 collections → ErrIneligibleCollections. The step's
//     envelope(s) were loaded and then dropped by the source's
//     attestation-type filter (and possibly its subject filter too). Each is
//     named with the predicate that dropped it: the generic list below opens
//     with "the attestation wasn't loaded", and for this case not one of its
//     causes applies (testifysec/judge#9309).
//   - 0 collections either way → ErrNoCollections. The step legitimately has
//     no envelope loaded — the operator forgot to pass --attestations, the
//     file didn't load, etc.
//
// The probes are unverified-search-aware: they perform the SAME signature
// verification the original Search did (via the same VerifiedSourcer), so
// envelopes with bad signatures don't fool the diagnostic into reporting a
// digest mismatch on something that wouldn't have verified anyway.
//
// Errors from a probe itself collapse back to ErrNoCollections — we don't
// want a diagnostic helper to surface a different error class than the
// original failure mode.
func diagnoseEmptyCollectionResult(ctx context.Context, src source.VerifiedSourcer, stepName string, suppliedDigests, attestations []string) error {
	present, observed, truncated, err := probeStepEvidence(ctx, src, stepName, attestations)
	if err != nil {
		return ErrNoCollections{Step: stepName}
	}
	if present {
		// Collection loaded but subject set doesn't intersect supplied digests.
		// The observed subjects are already a stable, sorted, deduplicated list
		// so the error message is reproducible across runs.
		return ErrSubjectDigestMismatch{
			Step:              stepName,
			SuppliedDigests:   append([]string(nil), suppliedDigests...),
			ObservedSubjects:  observed,
			ObservedTruncated: truncated,
		}
	}
	// With no attestation filter to relax, the second probe would be the
	// first one repeated verbatim: the step has no envelope, full stop.
	if len(attestations) == 0 {
		return ErrNoCollections{Step: stepName}
	}
	ineligible, truncated, err := probeIneligibleCollections(ctx, src, stepName, suppliedDigests, attestations)
	if err != nil || len(ineligible) == 0 {
		return ErrNoCollections{Step: stepName}
	}
	return ErrIneligibleCollections{Step: stepName, Collections: ineligible, Truncated: truncated}
}

// probeStepEvidence answers the two questions the subject-mismatch diagnosis
// asks of the source — "does this step have ANY collection carrying its
// required attestation types?" and "name a few of the subjects they carry" —
// reading at most maxDiagnosticProbeCollections collections to do it.
//
// STRUCTURAL CONTAINMENT. The bound is safe to apply to the diagnostic, and
// ONLY to the diagnostic, because of what its probes return: a bool and a
// list of rendered strings here, a list of string-only IneligibleCollection
// records in probeIneligibleCollections. Neither hands back a
// CollectionVerificationResult, an envelope, a statement or a verifier, so a
// truncated view cannot become — or silently shrink — the evidence a policy
// is judged on. A caller on the verification path could not use them even if
// one existed; there is nothing here to verify. That is the property, not a
// naming convention: see TestBoundedProbeIsStructurallyContained, which
// fails if any function outside the diagnostic path reaches the bound, and
// TestBoundedProbeReturnsNoEvidence, which fails if a probe's signature ever
// grows a channel through which candidates could escape.
//
// The third return reports whether the subject set is a TRUNCATED SAMPLE.
// It matters because ObservedSubjects drives hint selection: finding a
// "tree:" subject in a sample is sound, but concluding there is NONE from a
// sample is not. The caller must not turn absence-in-a-sample into a claim.
func probeStepEvidence(ctx context.Context, src source.VerifiedSourcer, stepName string, attestations []string) (bool, []string, bool, error) {
	observed := make(map[string]struct{})
	sampled, truncated, err := probeStepCollections(ctx, src, stepName, attestations, func(cvr source.CollectionVerificationResult) {
		collectSubjectReprs(cvr.Statement.Subject, observed)
	})
	if err != nil {
		return false, nil, false, err
	}
	return sampled > 0, sortedSubjectReprs(observed), truncated, nil
}

// probeIneligibleCollections answers the question the diagnostic asks once
// NO collection carries the step's required attestation types: "which
// envelopes ARE loaded under this step name, and what dropped each one?" It
// searches with neither filter and renders, per sampled collection, the
// required types it lacks, whether it carries any supplied subject digest,
// and whether its signature verified. Strings only — the same containment
// as probeStepEvidence, for the same reason.
func probeIneligibleCollections(ctx context.Context, src source.VerifiedSourcer, stepName string, suppliedDigests, attestations []string) ([]IneligibleCollection, bool, error) {
	var out []IneligibleCollection
	_, truncated, err := probeStepCollections(ctx, src, stepName, nil, func(cvr source.CollectionVerificationResult) {
		out = append(out, describeIneligibleCollection(cvr, suppliedDigests, attestations))
	})
	if err != nil {
		return nil, false, err
	}
	return out, truncated, nil
}

// probeStepCollections is the ONE bounded, subject-unfiltered walk over a
// step's collections, shared by both probes: it is the only search in the
// package issued with a nil subject-digest set (TestOnlyTheDiagnosticIssues
// AnUnfilteredSearch), and the only function that applies the bound. It calls
// visit for each sampled collection and returns how many it sampled and
// whether the source had more. visit is package-private and its two callers
// render strings; nothing they retain can reach the verification path.
//
// STREAMING: stop the source mid-iteration once the sample is full, so a
// remote source never downloads the rest of the step's history. It reads ONE
// PAST the bound before stopping: aborting at exactly the bound cannot
// distinguish "there were exactly N" from "there were more than N", and
// reporting truncation for the former is a false positive that would hedge a
// hint on a complete observation. The extra collection is never visited —
// its only job is to prove that more existed.
//
// NON-STREAMING: the source can only hand back the whole slice, so the bound
// cannot save the fetch — and the union is computed over the COMPLETE slice,
// deliberately. Truncating here saved no fetch; it only decided which
// subjects the operator got to see, and ObservedSubjects is NOT merely
// illustrative: the mismatch hint scans it for a "tree:" subject. Truncating
// first made a "tree:" subject in the fifth collection invisible, and the
// operator was told to go looking for a file modified after attestation
// instead. This branch has the whole set, so it answers exactly.
func probeStepCollections(ctx context.Context, src source.VerifiedSourcer, stepName string, attestations []string, visit func(source.CollectionVerificationResult)) (int, bool, error) {
	if streamer, ok := src.(source.StreamingVerifiedSourcer); ok {
		sampled := 0
		err := streamer.SearchStream(ctx, stepName, nil, attestations, func(cvr source.CollectionVerificationResult) error {
			sampled++
			if sampled > maxDiagnosticProbeCollections {
				return errDiagnosticProbeSatisfied
			}
			visit(cvr)
			return nil
		})
		// Only OUR abort is swallowed. A genuine source error still collapses
		// to the caller's ErrNoCollections fallback, exactly as before.
		if err != nil && !errors.Is(err, errDiagnosticProbeSatisfied) {
			return 0, false, err
		}
		// Truncated exactly when our abort fired: the stream had more to give.
		return sampled, errors.Is(err, errDiagnosticProbeSatisfied), nil
	}

	allForStep, err := src.Search(ctx, stepName, nil, attestations)
	if err != nil {
		return 0, false, err
	}
	for _, cvr := range allForStep {
		visit(cvr)
	}
	return len(allForStep), false, nil
}

// describeIneligibleCollection renders why one loaded collection was not a
// candidate for the step, mirroring the predicates the sources filter on:
// every required attestation type must be present — as-is or as its
// registered legacy alternate, which is how MemorySource indexes them — and,
// when the verify names subjects, at least one must be a matchable subject
// digest of the collection. Matchable under the collection's OWN
// SubjectMatchScope, so a SHA-1 commit id counts exactly where the source
// would count it and nowhere else.
func describeIneligibleCollection(cvr source.CollectionVerificationResult, suppliedDigests, required []string) IneligibleCollection {
	present := make(map[string]struct{}, 2*len(cvr.Collection.Attestations))
	has := make([]string, 0, len(cvr.Collection.Attestations))
	for _, att := range cvr.Collection.Attestations {
		present[att.Type] = struct{}{}
		if alt := attestation.LegacyAlternate(att.Type); alt != "" {
			present[alt] = struct{}{}
		}
		has = append(has, shortAttestationType(att.Type))
	}
	desc := IneligibleCollection{Reference: cvr.Reference, PresentAttestations: has}
	for _, req := range required {
		if _, ok := present[req]; !ok {
			desc.MissingAttestations = append(desc.MissingAttestations, req)
		}
	}
	if len(suppliedDigests) > 0 && !carriesAnySubject(cvr, suppliedDigests) {
		desc.SubjectMismatch = true
		desc.SuppliedDigests = append([]string(nil), suppliedDigests...)
		observed := make(map[string]struct{})
		collectSubjectReprs(cvr.Statement.Subject, observed)
		desc.ObservedSubjects = sortedSubjectReprs(observed)
	}
	for _, err := range cvr.Errors {
		desc.SignatureErrors = append(desc.SignatureErrors, err.Error())
	}
	return desc
}

// carriesAnySubject reports whether at least one supplied digest is a
// matchable subject digest of the collection — matchable under the
// collection's OWN SubjectMatchScope, the same predicate the sources index
// on, so a SHA-1 commit id counts exactly where the source would count it.
func carriesAnySubject(cvr source.CollectionVerificationResult, suppliedDigests []string) bool {
	scope := cvr.SubjectMatchScope()
	matchable := make(map[string]struct{})
	for _, subj := range cvr.Statement.Subject {
		for algorithm, digest := range subj.Digest {
			if scope.IsMatchableSubjectDigest(subj.Name, algorithm, digest) {
				matchable[digest] = struct{}{}
			}
		}
	}
	for _, d := range suppliedDigests {
		if _, ok := matchable[d]; ok {
			return true
		}
	}
	return false
}

// shortAttestationType trims the aflock predicate-URI prefix so the has-list
// reads "git/v0.1, material/v0.3" rather than a row of full URIs. The
// MISSING type is always rendered in full: it is what the policy says.
func shortAttestationType(uri string) string {
	return strings.TrimPrefix(uri, "https://aflock.ai/attestations/")
}

// collectSubjectReprs adds each subject's rendering to seen. Shared by the
// streamed and slice probe branches so the two render identically by
// construction rather than by matching copies.
func collectSubjectReprs(subjects []intoto.Subject, seen map[string]struct{}) {
	for _, subj := range subjects {
		repr := subj.Name
		// Include the first digest pair so operators can see what they
		// would need to pass via --artifactfile / --subjects to match.
		for algo, dig := range subj.Digest {
			repr = fmt.Sprintf("%s (%s:%s)", subj.Name, algo, dig)
			break
		}
		seen[repr] = struct{}{}
	}
}

func sortedSubjectReprs(seen map[string]struct{}) []string {
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
