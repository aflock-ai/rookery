// Copyright 2022 The Witness Contributors
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
	"fmt"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

type ErrVerifyArtifactsFailed struct {
	Reasons []string
}

func (e ErrVerifyArtifactsFailed) Error() string {
	return fmt.Sprintf("failed to verify artifacts: %v", strings.Join(e.Reasons, ", "))
}

// ErrNoPassedCollections is the step-level summary recorded when a step ends
// with nothing in its Passed list.
//
// It is an UMBRELLA over causes that are also reported individually — a
// subject-digest mismatch, a functionary rejection, a rego deny — so a consumer
// rendering a refusal usually wants to suppress it and show the specific
// reasons instead. Typed rather than a bare fmt.Errorf precisely so that
// suppression can be done with errors.As, instead of by matching this
// sentence and silently breaking the next time it is reworded.
//
// The message is unchanged from the untyped error it replaces; two published
// troubleshooting tables key off this wording (site/docs/getting-started).
// ErrCollectionValidationFailed gathers every reason one collection was
// rejected, AS ERRORS rather than as strings.
//
// The rendered message is byte-identical to the fmt.Sprintf it replaces, and
// deliberately so — operators and two published troubleshooting tables know
// this wording. What changes is that the chain SURVIVES: this used to be built
// by calling .Error() on each cause and joining the strings, then wrapping the
// result with %s, which severed every typed error at the point a consumer most
// needs it. A caller doing errors.As(err, &ErrPolicyDenied{}) got false, and
// the rego message that says WHICH rule denied — the only part a developer can
// act on — was unreachable. Downstream that surfaced as a git push refused with
// "collection validation failed:" and nothing else.
//
// Unwrap returns the slice (Go 1.20+ multi-error), so errors.As and errors.Is
// traverse to every cause. Same shape as ErrExternalAttestationRejected below.
type ErrCollectionValidationFailed struct {
	Reasons []error
}

func (e ErrCollectionValidationFailed) Error() string {
	parts := make([]string, 0, len(e.Reasons))
	for _, r := range e.Reasons {
		parts = append(parts, r.Error())
	}
	return fmt.Sprintf("collection validation failed:\n - %s", strings.Join(parts, ",\n - "))
}

func (e ErrCollectionValidationFailed) Unwrap() []error { return e.Reasons }

type ErrNoPassedCollections struct {
	Step string
}

func (e ErrNoPassedCollections) Error() string {
	return fmt.Sprintf("failed to verify artifacts for step %s: no passed collections present", e.Step)
}

type ErrNoCollections struct {
	Step string
}

func (e ErrNoCollections) Error() string {
	return fmt.Sprintf("no collection passed verification for step %v. Likely causes, in order: "+
		"(1) the attestation wasn't loaded — pass it with --attestations/--bundle or --enable-archivista; "+
		"(2) a collection loaded but its signature or functionary check failed — see the \"collection rejected\" reason(s) logged above for the specific cause (e.g. a certConstraint that doesn't match the signer's identity); "+
		"(3) the artifact is a product committed in a Merkle tree (subject \"tree:products\") whose root differs from the file digest. Load the parent envelope and required inventory companions via --attestations/--bundle. Product and material details can be inline or detached; omitted details are not empty sets. Compact-chain producers retain the inventories needed for artifact checks. Legacy material manifests must also accompany their parent collection", e.Step)
}

// ErrSubjectDigestMismatch fires when a collection IS loaded for the step
// (signed envelope present, signature-verified) but the operator's supplied
// artifact / subject digests don't intersect ANY of the collection's
// subjects. Distinct from ErrNoCollections so operators don't chase a
// phantom "did I load my attestation?" issue when the real problem is that
// they passed the wrong artifact path or built a different binary than the
// one the collection covers. (Fixes blind Linux UX test Bug 2.)
//
// ObservedSubjects is a sorted, deduplicated rendering of the subject
// strings that ARE present in the loaded collections for this step. It is
// intentionally a []string (not a typed digest set) so the error message
// can be read at a glance; debugging needs to see "what was actually in the
// envelope vs what I asked for", not parse a structured payload.
//
// ObservedTruncated reports that ObservedSubjects is a SAMPLE, not the whole
// union — the streaming probe stopped the source early. It exists because the
// hint below is chosen by scanning for a "tree:" subject, and that scan is
// only sound in one direction: finding "tree:" in a sample proves it is there,
// while not finding it proves nothing. Without this flag a "tree:" subject
// past the sample bound made the message confidently recommend the wrong fix.
type ErrSubjectDigestMismatch struct {
	Step              string
	SuppliedDigests   []string
	ObservedSubjects  []string
	ObservedTruncated bool
}

func (e ErrSubjectDigestMismatch) Error() string {
	observed := "(none)"
	if len(e.ObservedSubjects) > 0 {
		observed = strings.Join(e.ObservedSubjects, ", ")
	}
	supplied := "(none)"
	if len(e.SuppliedDigests) > 0 {
		supplied = strings.Join(e.SuppliedDigests, ", ")
	}
	// Steer toward the most likely cause. The collection IS loaded and its
	// signature verified for this step — the operator's artifact digest simply
	// isn't among its subjects. Lead with the fail-closed reading (a modified /
	// wrong file) so the message never reads as "add a flag to make it pass". The
	// inclusion-proof path is offered only when the collection actually commits
	// its products in a Merkle tree (a "tree:" subject), and even then second.
	hint := "If you expected this artifact to match, the file was likely modified after it was " +
		"attested, or you pointed at a different artifact than the one this step covers."
	sawTree := false
	for _, s := range e.ObservedSubjects {
		if strings.Contains(s, "tree:") {
			sawTree = true
			break
		}
	}
	switch {
	case sawTree:
		// Sound in a sample too: seeing "tree:" proves it is there.
		hint = "This step commits its products in a Merkle tree (a \"tree:\" subject), so a " +
			"plain file digest never equals the tree root. If you expected this artifact to " +
			"match, the file was likely modified after it was attested; only if it is " +
			"genuinely a member of that tree do you need its inclusion proof to bridge the file to the tree."
	case e.ObservedTruncated:
		// NOT sound: the subjects above are a sample, so "no tree: subject"
		// is unknown rather than false. Say so instead of confidently steering
		// the operator at the wrong cause.
		hint = "If you expected this artifact to match, the file was likely modified after it was " +
			"attested, or you pointed at a different artifact than the one this step covers. " +
			"Note: the subjects listed are a sample of this step's collections, not the complete " +
			"set — if this step commits its products in a Merkle tree, the \"tree:\" subject may " +
			"simply not appear above, and you would need an inclusion proof rather than a plain file digest."
	}
	return fmt.Sprintf(
		"supplied artifact digest(s) [%s] not present in any subject of step %q collection. Subjects observed: [%s]. %s",
		supplied, e.Step, observed, hint,
	)
}

type ErrMissingAttestation struct {
	Step        string
	Attestation string
}

func (e ErrMissingAttestation) Error() string {
	return fmt.Sprintf("missing attestation in collection for step %v: %v", e.Step, e.Attestation)
}

type ErrPolicyExpired time.Time

func (e ErrPolicyExpired) Error() string {
	return fmt.Sprintf("policy expired on %v", time.Time(e))
}

type ErrKeyIDMismatch struct {
	Expected string
	Actual   string
}

func (e ErrKeyIDMismatch) Error() string {
	return fmt.Sprintf("public key in policy has expected key id %v but got %v", e.Expected, e.Actual)
}

type ErrUnknownStep string

func (e ErrUnknownStep) Error() string {
	return fmt.Sprintf("policy has no step named %v", string(e))
}

type ErrArtifactCycle string

func (e ErrArtifactCycle) Error() string {
	return fmt.Sprintf("cycle detected in step's artifact dependencies: %v", string(e))
}

type ErrMismatchArtifact struct {
	Artifact cryptoutil.DigestSet
	Material cryptoutil.DigestSet
	Path     string
}

func (e ErrMismatchArtifact) Error() string {
	return fmt.Sprintf("mismatched digests for %v", e.Path)
}

// ErrNoArtifactOverlap is returned when an artifactsFrom comparison finds no
// path in common between a step's materials and the referenced step's
// artifacts. Nothing actually flowed between the steps, so the edge would
// otherwise pass vacuously and must be rejected (GHSA-vmvj-p3hw-39q3).
// ErrUntrackedMaterials is returned when a step with artifactsFrom consumed
// materials that no accepted upstream step produced and that no
// Step.AllowedUntracked glob admits (#9815).
type ErrUntrackedMaterials struct {
	Step  string
	Paths []string
}

// untrackedPathsShown bounds how many paths ErrUntrackedMaterials prints; a
// walk-mode build can carry tens of thousands of materials.
const untrackedPathsShown = 20

func (e ErrUntrackedMaterials) Error() string {
	shown := e.Paths
	suffix := ""
	if len(shown) > untrackedPathsShown {
		shown = shown[:untrackedPathsShown]
		suffix = fmt.Sprintf(", ... and %d more", len(e.Paths)-untrackedPathsShown)
	}
	return fmt.Sprintf("step %q: %d material(s) not produced by any artifactsFrom step and not matched by allowedUntracked: %s%s", e.Step, len(e.Paths), strings.Join(shown, ", "), suffix)
}

type ErrNoArtifactOverlap struct{}

func (e ErrNoArtifactOverlap) Error() string {
	return "no artifacts in common between the step's materials and the referenced step's artifacts"
}

// ErrUnconsumedArtifacts is returned ONLY under strict artifact matching
// (opt-in via WithRequireAllArtifacts) when a producing step emits an artifact
// that the consuming step does not consume as a material. An unconsumed
// artifact is a potential supply-chain injection — a file added to a step's
// output that nothing downstream checks. Default (warn-only) verification does
// NOT return this error.
type ErrUnconsumedArtifacts struct {
	Step          string
	ArtifactsFrom string
	Paths         []string
}

func (e ErrUnconsumedArtifacts) Error() string {
	return fmt.Sprintf("step %q (strict artifact matching): %d artifact(s) produced by step %q are not consumed as materials: %s", e.Step, len(e.Paths), e.ArtifactsFrom, strings.Join(e.Paths, ", "))
}

type ErrRegoInvalidData struct {
	Path     string
	Expected string
	Actual   interface{}
}

func (e ErrRegoInvalidData) Error() string {
	return fmt.Sprintf("invalid data from rego at %v, expected %v but got %T", e.Path, e.Expected, e.Actual)
}

type ErrPolicyDenied struct {
	Reasons []string
}

func (e ErrPolicyDenied) Error() string {
	return fmt.Sprintf("policy was denied due to: %v", strings.Join(e.Reasons, ", "))
}

type ErrConstraintCheckFailed struct {
	errs []error
}

func (e ErrConstraintCheckFailed) Error() string {
	return fmt.Sprintf("cert failed constraints check: %+q", e.errs)
}

type ErrInvalidOption struct {
	Option string
	Reason string
}

func (e ErrInvalidOption) Error() string {
	return fmt.Sprintf("invalid option (%v): %v", e.Option, e.Reason)
}

type ErrCircularDependency struct {
	Steps []string
	// Edges, when set, names the relation (attestationsFrom or artifactsFrom)
	// of each hop: Edges[i] links Steps[i] to Steps[i+1]. It is set for a cycle
	// that runs through artifactsFrom, which is only a cycle in the union of
	// the two relations (#9813).
	Edges []string
}

func (e ErrCircularDependency) Error() string {
	if len(e.Edges) == 0 || len(e.Edges) != len(e.Steps)-1 {
		return fmt.Sprintf("circular dependency detected: %v", strings.Join(e.Steps, " -> "))
	}
	var b strings.Builder
	b.WriteString(e.Steps[0])
	for i, rel := range e.Edges {
		fmt.Fprintf(&b, " -[%s]-> %s", rel, e.Steps[i+1])
	}
	return "circular dependency across attestationsFrom and artifactsFrom detected: " + b.String()
}

type ErrSelfReference struct {
	Step string
}

func (e ErrSelfReference) Error() string {
	return fmt.Sprintf("step '%v' cannot depend on itself", e.Step)
}

// ErrStepNameIncoherent is returned by Policy.Validate, ONLY when step-name
// coherence enforcement is opted in (HardeningOptions.EnforceStepNameCoherence,
// #6266), when a step's Name is empty or disagrees with its map key. The map key
// is authoritative during search/result-merge while Step.Name drives the
// collection-name filter and artifact lookup; a disagreement otherwise surfaces
// far later at verify as a misleading "no passed collections" error. Key and Name
// are both reported so the misconfiguration is unambiguous.
type ErrStepNameIncoherent struct {
	Key  string
	Name string
}

func (e ErrStepNameIncoherent) Error() string {
	if e.Name == "" {
		return fmt.Sprintf("step keyed %q has an empty Name; the map key and Step.Name must match (#6266)", e.Key)
	}
	return fmt.Sprintf("step keyed %q has mismatched Name %q; the map key and Step.Name must match (#6266)", e.Key, e.Name)
}

type ErrDependencyNotVerified struct {
	Step string
}

func (e ErrDependencyNotVerified) Error() string {
	return fmt.Sprintf("dependency '%v' not verified - cannot evaluate dependent step", e.Step)
}

// ErrAttestationsFromNotConverged is returned when step verification and
// artifact pruning do not reach a joint fixed point: no Rego context could be
// found that equals the attestationsFrom evidence surviving pruning. The
// verify refuses to answer rather than return a verdict judged on evidence it
// rejected (#9813).
type ErrAttestationsFromNotConverged struct {
	Rounds int
}

func (e ErrAttestationsFromNotConverged) Error() string {
	return fmt.Sprintf("attestationsFrom context did not converge with artifact verification after %d rounds", e.Rounds)
}

// ErrUnknownExternalAttestation is returned by Policy.Validate when a step's
// ExternalFrom references an external-attestation name that is not declared
// in Policy.ExternalAttestations.
type ErrUnknownExternalAttestation struct {
	Step string
	Name string
}

func (e ErrUnknownExternalAttestation) Error() string {
	return fmt.Sprintf("step '%v' references unknown external attestation '%v' in externalFrom", e.Step, e.Name)
}

// ErrMissingExternalAttestation is returned when an external attestation is
// declared as Required but no DSSE envelope matching the predicate type +
// policy seed subjects could be found in the attestation source.
//
// Unbound counts candidates the search returned that are not about the
// verify's subject (another commit, or a subject the caller did not ask for):
// they are not evidence, so they do not turn "not found" into "rejected".
//
// RequestedSubjects, Candidates and Refused say what was searched and why
// each candidate did not count; Refused is capped and RefusedOmitted counts
// the rest. They are diagnostics only and are empty on an error built by hand.
type ErrMissingExternalAttestation struct {
	Name          string
	PredicateType string
	Unbound       int

	// RequestedSubjects are the searched digests as algorithm:value (the
	// algorithm inferred from the value, source.LabelSubjectDigest).
	RequestedSubjects []string
	// Candidates is how many envelopes the search returned.
	Candidates     int
	Refused        []ExternalCandidateDiagnostic
	RefusedOmitted int
}

func (e ErrMissingExternalAttestation) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "required external attestation %q (predicateType=%v) not found", e.Name, e.PredicateType)
	if e.Unbound > 0 {
		fmt.Fprintf(&b, " (%d candidate(s) not about the evaluated subject, commit or bound child policy were ignored)", e.Unbound)
	}
	writeExternalSearchDiagnostics(&b, e.RequestedSubjects, e.Candidates, e.Refused, e.RefusedOmitted)
	return b.String()
}

// ErrExternalAssignmentsExceedBound refuses a verify in which not every
// assignment of external candidates could be evaluated and none of those
// tried made the policy pass. An untried assignment could have passed, so the
// engine has no answer: this is a refusal, never a FAILED. Two causes reach
// it: two or more externals with several candidates each whose product
// exceeds maxExternalAssignments, and an evidence source that cannot be
// forked for the next assignment (SourceNotForkable), which bounds the walk
// at the assignments already run.
type ErrExternalAssignmentsExceedBound struct {
	// Externals are the external names whose candidates were combined, sorted.
	Externals   []string
	Assignments int
	// Bound is how many assignments were tried.
	Bound int
	// SourceNotForkable: the walk stopped because the source could not give
	// the next assignment a faithful fork, not at maxExternalAssignments.
	SourceNotForkable bool
}

func (e ErrExternalAssignmentsExceedBound) Error() string {
	if e.SourceNotForkable {
		return fmt.Sprintf("external attestations %s have %d candidate combinations; the evidence source cannot be forked to try the rest, the first %d were tried and none passed, so the verify has no answer",
			strings.Join(e.Externals, ", "), e.Assignments, e.Bound)
	}
	return fmt.Sprintf("external attestations %s have %d candidate combinations; the first %d were tried and none passed, so the verify has no answer",
		strings.Join(e.Externals, ", "), e.Assignments, e.Bound)
}

// ErrExternalAttestationRejected is returned when an external attestation is
// declared as Required and DSSE envelopes matching the predicate type were
// found, but ALL of them were rejected — typically by a rego deny rule, or
// by functionary / signature validation failure. The Rejections slice carries
// the per-envelope reasons so callers can surface the real deny message
// instead of a misleading "not found" error.
//
// When the engine fills RequestedSubjects/Candidates/Refused, the message
// lists at most a few refused candidates with their subjects and reasons
// (bounded) instead of every rejection; Rejections still carries them all.
type ErrExternalAttestationRejected struct {
	Name          string
	PredicateType string
	Rejections    []error

	RequestedSubjects []string
	Candidates        int
	Refused           []ExternalCandidateDiagnostic
	RefusedOmitted    int
}

func (e ErrExternalAttestationRejected) Error() string {
	if len(e.Refused) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "required external attestation %q (predicateType=%v) rejected by all %d matching envelopes", e.Name, e.PredicateType, len(e.Rejections))
		writeExternalSearchDiagnostics(&b, e.RequestedSubjects, e.Candidates, e.Refused, e.RefusedOmitted)
		return b.String()
	}
	if len(e.Rejections) == 0 {
		return fmt.Sprintf("required external attestation %q (predicateType=%v) was rejected", e.Name, e.PredicateType)
	}
	msgs := make([]string, 0, len(e.Rejections))
	for _, r := range e.Rejections {
		msgs = append(msgs, r.Error())
	}
	return fmt.Sprintf("required external attestation %q (predicateType=%v) rejected by all %d matching envelopes: %s",
		e.Name, e.PredicateType, len(e.Rejections), strings.Join(msgs, "; "))
}

func (e ErrExternalAttestationRejected) Unwrap() []error { return e.Rejections }

// ErrIneligibleCollections fires when the source holds at least one envelope
// under the step's collection name, but every one of them was dropped before
// verification by the source's own filters: it lacks an attestation type the
// step requires, or carries none of the supplied subject digests. It is
// distinct from ErrNoCollections — whose "likely causes" list opens with "the
// attestation wasn't loaded" — because here it WAS loaded, and the operator
// needs the envelope named with the predicate that dropped it, not a list of
// causes that do not apply (testifysec/judge#9309).
//
// It unwraps to ErrNoCollections, so a consumer that classifies a step by
// that type through errors.As — judge-api's readiness classifier, which reads
// it as "evidence has not arrived" and reports PENDING — keeps reading it the
// same way: an envelope without the required attestation is evidence that has
// not arrived yet, not a substantive verification failure.
type ErrIneligibleCollections struct {
	Step        string
	Collections []IneligibleCollection
	// Truncated reports that Collections is a bounded SAMPLE of the step's
	// loaded envelopes rather than all of them, so the count renders as a
	// floor ("at least N").
	Truncated bool
}

// IneligibleCollection is one loaded-but-filtered envelope and why. Strings
// only, on purpose: it is a rendering for the operator, never evidence, and
// the bounded diagnostic probe that builds it must not be able to hand a
// collection back (see probeStepCollections).
type IneligibleCollection struct {
	Reference string
	// MissingAttestations are the step's required attestation type URIs the
	// collection does not carry (neither as-is nor as a registered legacy
	// alternate, which is how the sources index them).
	MissingAttestations []string
	// PresentAttestations are the types it does carry, short form.
	PresentAttestations []string
	// SubjectMismatch reports that the verify named subject digests and none
	// of them is a matchable subject of this collection.
	SubjectMismatch  bool
	SuppliedDigests  []string
	ObservedSubjects []string
	// SignatureErrors carry the source's verification errors, when the
	// envelope would have failed signature verification as well.
	SignatureErrors []string
}

func (e ErrIneligibleCollections) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "step %q: ", e.Step)
	if e.Truncated {
		b.WriteString("at least ")
	}
	if len(e.Collections) == 1 {
		b.WriteString("1 envelope loaded but not eligible: ")
	} else {
		fmt.Fprintf(&b, "%d envelopes loaded but none eligible: ", len(e.Collections))
	}
	for i, c := range e.Collections {
		if i > 0 {
			b.WriteString("; ")
		}
		b.WriteString(c.describe())
	}
	return b.String()
}

// Unwrap keeps the evidence-not-arrived reading for errors.As consumers.
func (e ErrIneligibleCollections) Unwrap() error { return ErrNoCollections{Step: e.Step} }

// describe renders "<reference> <reason> and <reason>" for one envelope.
func (c IneligibleCollection) describe() string {
	reasons := make([]string, 0, 3)
	if len(c.MissingAttestations) > 0 {
		has := "none"
		if len(c.PresentAttestations) > 0 {
			has = strings.Join(c.PresentAttestations, ", ")
		}
		noun := "attestation"
		if len(c.MissingAttestations) > 1 {
			noun = "attestations"
		}
		reasons = append(reasons, fmt.Sprintf("is missing required %s %s (has: %s)", noun, strings.Join(c.MissingAttestations, ", "), has))
	}
	if c.SubjectMismatch {
		observed := "none"
		if len(c.ObservedSubjects) > 0 {
			observed = strings.Join(c.ObservedSubjects, ", ")
		}
		reasons = append(reasons, fmt.Sprintf("carries none of the supplied digest(s) [%s] (subjects present: %s)", strings.Join(c.SuppliedDigests, ", "), observed))
	}
	if len(c.SignatureErrors) > 0 {
		reasons = append(reasons, fmt.Sprintf("its signature did not verify (%s)", strings.Join(c.SignatureErrors, "; ")))
	}
	if len(reasons) == 0 {
		// The source dropped it on a predicate this rendering does not model.
		// Say so rather than fabricate a cause.
		reasons = append(reasons, "was filtered by the attestation source for a reason it did not report")
	}
	return c.Reference + " " + strings.Join(reasons, " and ")
}
