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
// Closing the remainder is the source's job, not the diagnostic's: judge-api's
// EntSource already refuses to mark from a probe, while ArchivistaSource has no
// equivalent guard (testifysec/judge#8026). A probe must not mutate what the
// real search can still find, and only the source can promise that at every
// size.
//
// It never escapes probeStepEvidence.
var errDiagnosticProbeSatisfied = errors.New("diagnostic probe: sample bound reached")

// diagnoseEmptyCollectionResult is called when the subject-filtered Search
// for (stepName, subjectDigests) returns zero collections. It re-probes the
// source with an empty subject filter to figure out whether the step has
// ANY loaded collections at all:
//
//   - 0 collections after the empty-subject probe   → ErrNoCollections.
//     The step legitimately has no envelope loaded — the operator forgot
//     to pass --attestations, the file didn't load, etc.
//   - >0 collections after the empty-subject probe → ErrSubjectDigestMismatch.
//     The envelope IS loaded; the operator's --artifactfile / --subjects
//     digest just doesn't match anything in the collection. Surface the
//     observed subjects so the operator can see what they ARE asked to
//     verify against.
//
// The probe is unverified-search-aware: it performs the SAME signature
// verification the original Search did (via the same VerifiedSourcer), so
// envelopes with bad signatures don't fool the diagnostic into reporting a
// digest mismatch on something that wouldn't have verified anyway.
//
// Errors from the probe itself collapse back to ErrNoCollections — we don't
// want a diagnostic helper to surface a different error class than the
// original failure mode.
func diagnoseEmptyCollectionResult(ctx context.Context, src source.VerifiedSourcer, stepName string, suppliedDigests, attestations []string) error {
	present, observed, truncated, err := probeStepEvidence(ctx, src, stepName, attestations)
	if err != nil || !present {
		return ErrNoCollections{Step: stepName}
	}

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

// probeStepEvidence answers the only two questions the empty-collection
// diagnostic asks of the source — "does this step have ANY collection?" and
// "name a few of the subjects they carry" — reading at most
// maxDiagnosticProbeCollections collections to do it.
//
// STRUCTURAL CONTAINMENT. The bound is safe to apply here, and ONLY here,
// because of what this function returns: a bool and a list of rendered
// strings. It hands back no CollectionVerificationResult, no envelope, no
// statement and no verifier, so its truncated view cannot become — or
// silently shrink — the evidence a policy is judged on. A caller on the
// verification path could not use it even if one existed; there is nothing
// here to verify. That is the property, not a naming convention: see
// TestBoundedProbeIsStructurallyContained, which fails if any function other
// than diagnoseEmptyCollectionResult reaches the bound, and
// TestBoundedProbeReturnsNoEvidence, which fails if this signature ever grows
// a channel through which candidates could escape.
//
// The engine itself can never issue the unfiltered search this performs:
// checkVerifyOpts rejects a Verify with no subject digests, so every search
// on the verification path is digest-filtered. This probe is the only
// unfiltered search in the package.
// The third return reports whether the subject set is a TRUNCATED SAMPLE.
// It matters because ObservedSubjects drives hint selection: finding a
// "tree:" subject in a sample is sound, but concluding there is NONE from a
// sample is not. The caller must not turn absence-in-a-sample into a claim.
func probeStepEvidence(ctx context.Context, src source.VerifiedSourcer, stepName string, attestations []string) (bool, []string, bool, error) {
	// STREAMING: stop the source mid-iteration once the sample is full, so a
	// remote source never downloads the rest of the step's history.
	if streamer, ok := src.(source.StreamingVerifiedSourcer); ok {
		observed := make(map[string]struct{})
		sampled := 0
		err := streamer.SearchStream(ctx, stepName, nil, attestations, func(cvr source.CollectionVerificationResult) error {
			sampled++
			// Read ONE PAST the bound before stopping. Aborting at exactly the
			// bound cannot distinguish "there were exactly N" from "there were
			// more than N", and reporting truncation for the former is a false
			// positive that would hedge the hint on a complete observation. The
			// extra collection is never rendered — its only job is to prove that
			// more existed.
			if sampled > maxDiagnosticProbeCollections {
				return errDiagnosticProbeSatisfied
			}
			collectSubjectReprs(cvr.Statement.Subject, observed)
			return nil
		})
		// Only OUR abort is swallowed. A genuine source error still collapses
		// to the caller's ErrNoCollections fallback, exactly as before.
		if err != nil && !errors.Is(err, errDiagnosticProbeSatisfied) {
			return false, nil, false, err
		}
		// Truncated exactly when our abort fired: the stream had more to give.
		return sampled > 0, sortedSubjectReprs(observed), errors.Is(err, errDiagnosticProbeSatisfied), nil
	}

	// NON-STREAMING: the source can only hand back the whole slice, so the
	// bound cannot save the fetch — it still caps what the message renders and
	// what the diagnostic retains.
	allForStep, err := src.Search(ctx, stepName, nil, attestations)
	if err != nil {
		return false, nil, false, err
	}
	if len(allForStep) == 0 {
		return false, nil, false, nil
	}
	// The union is computed over the COMPLETE slice, deliberately. The source
	// already handed back everything, so truncating here saved no fetch — it
	// only decided which subjects the operator got to see, and ObservedSubjects
	// is NOT merely illustrative: ErrNoCollections.Error scans it for a "tree:"
	// subject to choose the remediation hint. Truncating first made a "tree:"
	// subject in the fifth collection invisible, and the operator was told to
	// go looking for a file modified after attestation instead.
	//
	// Finding a "tree:" subject in a sample is sound; NOT finding one in a
	// sample is not. This branch has the whole set, so it answers exactly.
	return true, observedCollectionSubjects(allForStep), false, nil
}

// observedCollectionSubjects walks a list of CollectionVerificationResults
// and returns the union of subject entries (rendered as "<name>"). The
// in-toto statement's Subject slice is the authoritative source — that's
// what subject-digest matching runs against in source.Search. Each subject
// is rendered with its first available digest so the operator sees both
// the symbolic name (e.g. "file:dist/argocd") AND the digest they would
// need to match against. Sorted + deduped for stable output.
func observedCollectionSubjects(results []source.CollectionVerificationResult) []string {
	seen := make(map[string]struct{})
	for _, r := range results {
		// Statement.Subject is the canonical list source.Search filters on.
		collectSubjectReprs(r.Statement.Subject, seen)
	}
	return sortedSubjectReprs(seen)
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
