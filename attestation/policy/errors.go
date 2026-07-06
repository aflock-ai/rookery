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

type ErrNoCollections struct {
	Step string
}

func (e ErrNoCollections) Error() string {
	return fmt.Sprintf("no collection passed verification for step %v. Likely causes, in order: "+
		"(1) the attestation wasn't loaded — pass it with --attestations/--bundle or --enable-archivista; "+
		"(2) a collection loaded but its signature or functionary check failed — see the \"collection rejected\" reason(s) logged above for the specific cause (e.g. a certConstraint that doesn't match the signer's identity); "+
		"(3) the artifact is a product committed in a Merkle tree (subject \"tree:products\") whose root won't equal the plain file digest — load the attestation carrying the inline v0.3 tree leaves (the leaves are always inlined in the DSSE-signed predicate; pass that envelope via --attestations/--bundle)", e.Step)
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
type ErrSubjectDigestMismatch struct {
	Step             string
	SuppliedDigests  []string
	ObservedSubjects []string
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
	for _, s := range e.ObservedSubjects {
		if strings.Contains(s, "tree:") {
			hint = "This step commits its products in a Merkle tree (a \"tree:\" subject), so a " +
				"plain file digest never equals the tree root. If you expected this artifact to " +
				"match, the file was likely modified after it was attested; only if it is " +
				"genuinely a member of that tree do you need its inclusion proof to bridge the file to the tree."
			break
		}
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
}

func (e ErrCircularDependency) Error() string {
	return fmt.Sprintf("circular dependency detected: %v", strings.Join(e.Steps, " -> "))
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
type ErrMissingExternalAttestation struct {
	Name          string
	PredicateType string
}

func (e ErrMissingExternalAttestation) Error() string {
	return fmt.Sprintf("required external attestation %q (predicateType=%v) not found", e.Name, e.PredicateType)
}

// ErrExternalAttestationRejected is returned when an external attestation is
// declared as Required and DSSE envelopes matching the predicate type were
// found, but ALL of them were rejected — typically by a rego deny rule, or
// by functionary / signature validation failure. The Rejections slice carries
// the per-envelope reasons so callers can surface the real deny message
// instead of a misleading "not found" error.
type ErrExternalAttestationRejected struct {
	Name          string
	PredicateType string
	Rejections    []error
}

func (e ErrExternalAttestationRejected) Error() string {
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
