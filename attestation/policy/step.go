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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/source"
)

// +kubebuilder:object:generate=true
type Step struct {
	Name             string        `json:"name" jsonschema:"title=Name,description=Unique name for this step in the policy"`
	Functionaries    []Functionary `json:"functionaries" jsonschema:"title=Functionaries,description=Authorized signers whose attestations are accepted for this step"`
	Attestations     []Attestation `json:"attestations" jsonschema:"title=Attestations,description=Required attestation types and their associated policies"`
	ArtifactsFrom    []string      `json:"artifactsFrom,omitempty" jsonschema:"title=Artifacts From,description=Other step names whose products must match this step's materials"`
	AttestationsFrom []string      `json:"attestationsFrom,omitempty" jsonschema:"title=Attestations From,description=Other step names whose attestation data is accessible during Rego evaluation"`
	ExternalFrom     []string      `json:"externalFrom,omitempty" jsonschema:"title=External From,description=Names of external attestations (from Policy.ExternalAttestations) whose predicates are accessible during Rego evaluation as input.external.<name>"`
}

// ExternalAttestation describes a bare-predicate DSSE envelope (non-Collection)
// that the policy engine verifies as first-class evidence alongside step
// collections. External attestations are matched by predicate type + policy
// seed subjects, validated against their own Functionaries and RegoPolicies,
// and do NOT participate in the Collection subject-graph / BackRef traversal.
//
// See issue #39 for the full design.
//
// +kubebuilder:object:generate=true
type ExternalAttestation struct {
	Name          string        `json:"name" jsonschema:"title=Name,description=Unique name for this external attestation; referenced by Step.ExternalFrom"`
	PredicateType string        `json:"predicateType" jsonschema:"title=Predicate Type,description=Statement predicateType URI to match (e.g. https://slsa.dev/provenance/v1)"`
	Functionaries []Functionary `json:"functionaries" jsonschema:"title=Functionaries,description=Authorized signers for this external attestation"`
	RegoPolicies  []RegoPolicy  `json:"regopolicies,omitempty" jsonschema:"title=Rego Policies,description=Rego policies evaluated against the bare predicate (input is the predicate itself)"`
	AiPolicies    []AiPolicy    `json:"aipolicies,omitempty" jsonschema:"title=AI Policies,description=AI policies evaluated against the bare predicate"`
	Required      bool          `json:"required" jsonschema:"title=Required,description=When true (default), verification fails if no envelope matches; when false, absence is tolerated"`
}

// +kubebuilder:object:generate=true
type Functionary struct {
	Type           string         `json:"type" jsonschema:"title=Type,description=Type of functionary (publickey or root)"`
	CertConstraint CertConstraint `json:"certConstraint,omitempty" jsonschema:"title=Certificate Constraint,description=X.509 certificate constraints the functionary must satisfy"`
	PublicKeyID    string         `json:"publickeyid,omitempty" jsonschema:"title=Public Key ID,description=ID of a public key from the policy's publickeys map"`
}

// +kubebuilder:object:generate=true
type AiPolicy struct {
	Name   string `json:"name" jsonschema:"title=Name,description=Human-readable name for this AI policy"`
	Prompt string `json:"prompt" jsonschema:"title=Prompt,description=Prompt text sent to the AI model for evaluation"`
	Model  string `json:"model,omitempty" jsonschema:"title=Model,description=AI model to use for evaluation"`
}

// +kubebuilder:object:generate=true
type Attestation struct {
	Type         string       `json:"type" jsonschema:"title=Type,description=Attestation type URI that must be present in the collection"`
	RegoPolicies []RegoPolicy `json:"regopolicies" jsonschema:"title=Rego Policies,description=Rego policies to evaluate against the attestation data"`
	AiPolicies   []AiPolicy   `json:"aipolicies" jsonschema:"title=AI Policies,description=AI-based policies to evaluate against the attestation data"`
}

// +kubebuilder:object:generate=true
type RegoPolicy struct {
	Module []byte `json:"module" jsonschema:"title=Module,description=Base64-encoded Rego policy module source code"`
	Name   string `json:"name" jsonschema:"title=Name,description=Human-readable name for this Rego policy"`
}

// StepResult contains information about the verified collections for each step.
// Passed contains the collections that passed any rego policies and all expected attestations exist.
// Rejected contains the rejected collections and the error that caused them to be rejected.
type StepResult struct {
	Step     string
	Passed   []PassedCollection
	Rejected []RejectedCollection
}

// PassedCollection contains a collection that passed verification along with any AI responses
type PassedCollection struct {
	Collection  source.CollectionVerificationResult
	AiResponses []AiResponse `json:"AiResponses,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface for PassedCollection
func (p PassedCollection) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Collection  source.CollectionVerificationResult `json:"Collection"`
		AiResponses []AiResponse                        `json:"AiResponses,omitempty"`
	}{
		Collection:  p.Collection,
		AiResponses: p.AiResponses,
	})
}

// Analyze inspects the StepResult to determine if the step passed or failed.
// We do this rather than failing at the first point of failure in the verification flow
// in order to save the failure reasons so we can present them all at the end of the verification process.
func (r StepResult) Analyze() bool {
	var pass bool
	if len(r.Passed) > 0 {
		pass = true
	}

	for _, coll := range r.Passed {
		// we don't fail on warnings so we process these under debug logs
		if len(coll.Collection.Warnings) > 0 {
			for _, warn := range coll.Collection.Warnings {
				log.Debug("Warning: Step: %s, Collection: %s, Warning: %s", r.Step, coll.Collection.Collection.Name, warn)
			}
		}

		// Want to ensure that undiscovered errors aren't lurking in the passed collections
		if len(coll.Collection.Errors) > 0 {
			for _, err := range coll.Collection.Errors {
				pass = false
				log.Errorf("Unexpected Error in Passed Collection: Step: %s, Collection: %s, Error: %s", r.Step, coll.Collection.Collection.Name, err)
			}
		}
	}

	return pass
}

func (r StepResult) HasErrors() bool {
	return len(r.Rejected) > 0
}

func (r StepResult) HasPassed() bool {
	return len(r.Passed) > 0
}

func (r StepResult) Error() string {
	errs := make([]string, len(r.Rejected))
	for i, reject := range r.Rejected {
		errs[i] = reject.Reason.Error()
	}

	return fmt.Sprintf("attestations for step %v could not be used due to:\n%v", r.Step, strings.Join(errs, "\n"))
}

type RejectedCollection struct {
	Collection  source.CollectionVerificationResult
	Reason      error
	AiResponses []AiResponse `json:"AiResponses,omitempty"`
}

// ExternalResult contains information about verified external attestations
// for a single Policy.ExternalAttestations entry. Mirrors StepResult but
// carries StatementEnvelopes (bare predicate DSSEs) instead of Collections.
//
// Passed contains envelopes whose functionary matched and whose Rego/AI
// policies all succeeded. Rejected captures mismatches with the reason.
// Skipped is true when the external attestation was not required and no
// matching envelope was found — a legitimate "pass" that nevertheless
// contributes nothing to downstream Rego input.
type ExternalResult struct {
	Name     string
	Passed   []PassedExternal
	Rejected []RejectedExternal
	Skipped  bool
}

// PassedExternal holds an external attestation envelope that passed
// functionary and rego/AI policy evaluation.
type PassedExternal struct {
	Envelope    source.StatementEnvelope
	AiResponses []AiResponse `json:"AiResponses,omitempty"`
}

// MarshalJSON implements json.Marshaler for PassedExternal.
func (p PassedExternal) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Envelope    source.StatementEnvelope `json:"Envelope"`
		AiResponses []AiResponse             `json:"AiResponses,omitempty"`
	}{
		Envelope:    p.Envelope,
		AiResponses: p.AiResponses,
	})
}

// RejectedExternal holds an external attestation envelope that failed
// verification along with the reason.
type RejectedExternal struct {
	Envelope    source.StatementEnvelope
	Reason      error
	AiResponses []AiResponse `json:"AiResponses,omitempty"`
}

// MarshalJSON implements json.Marshaler for RejectedExternal so that the
// Reason field (an error interface) serializes to a useful string instead
// of `{}`.
func (r RejectedExternal) MarshalJSON() ([]byte, error) {
	var reasonStr string
	if r.Reason != nil {
		reasonStr = r.Reason.Error()
	}
	return json.Marshal(&struct {
		Envelope    source.StatementEnvelope `json:"Envelope"`
		Reason      string                   `json:"Reason"`
		AiResponses []AiResponse             `json:"AiResponses,omitempty"`
	}{
		Envelope:    r.Envelope,
		Reason:      reasonStr,
		AiResponses: r.AiResponses,
	})
}

// Analyze returns true iff the external attestation is considered satisfied.
// A Skipped (not-required, not-found) external passes. An external with at
// least one Passed envelope passes. Anything else fails.
func (r ExternalResult) Analyze() bool {
	if r.Skipped {
		return true
	}
	return len(r.Passed) > 0
}

// MarshalJSON implements the json.Marshaler interface to properly serialize the Reason field
// which is an error interface that would otherwise serialize to an empty object {}
func (r RejectedCollection) MarshalJSON() ([]byte, error) {
	var reasonStr string
	if r.Reason != nil {
		reasonStr = r.Reason.Error()
	}

	return json.Marshal(&struct {
		Collection  source.CollectionVerificationResult `json:"Collection"`
		Reason      string                              `json:"Reason"`
		AiResponses []AiResponse                        `json:"AiResponses,omitempty"`
	}{
		Collection:  r.Collection,
		Reason:      reasonStr,
		AiResponses: r.AiResponses,
	})
}

func (f Functionary) Validate(verifier cryptoutil.Verifier, trustBundles map[string]TrustBundle) error {
	verifierID, err := verifier.KeyID()
	if err != nil {
		return fmt.Errorf("could not get key id: %w", err)
	}

	if f.PublicKeyID != "" && f.PublicKeyID == verifierID {
		return nil
	}

	x509Verifier, ok := verifier.(*cryptoutil.X509Verifier)
	if !ok {
		return fmt.Errorf("verifier with ID %v is not a public key verifier or a x509 verifier", verifierID)
	}

	if len(f.CertConstraint.Roots) == 0 {
		return fmt.Errorf("verifier with ID %v is an x509 verifier, but no trusted roots provided in functionary", verifierID)
	}

	if err := f.CertConstraint.Check(x509Verifier, trustBundles); err != nil {
		return fmt.Errorf("verifier with ID %v doesn't meet certificate constraint: %w", verifierID, err)
	}

	return nil
}

// buildStepContext extracts attestation data from already-verified steps referenced
// by AttestationsFrom. The result is a map[stepName]->map[attestationType]->attestorJSON
// that gets passed into Rego policy evaluation as input.steps.
func buildStepContext(attestationsFrom []string, resultsByStep map[string]StepResult) map[string]interface{} { //nolint:gocognit
	if len(attestationsFrom) == 0 {
		return nil
	}

	ctx := make(map[string]interface{})
	for _, depStep := range attestationsFrom {
		result, ok := resultsByStep[depStep]
		if !ok || len(result.Passed) == 0 {
			continue
		}

		stepData := make(map[string]interface{})
		for _, pc := range result.Passed {
			for _, att := range pc.Collection.Collection.Attestations {
				// Marshal the attestor to a generic map so Rego can traverse it.
				b, err := json.Marshal(att.Attestation)
				if err != nil {
					log.Debugf("failed to marshal attestation %s from step %s: %v", att.Type, depStep, err)
					continue
				}
				var data interface{}
				dec := json.NewDecoder(bytes.NewReader(b))
				dec.UseNumber()
				if err := dec.Decode(&data); err != nil {
					log.Debugf("failed to decode attestation %s from step %s: %v", att.Type, depStep, err)
					continue
				}
				stepData[att.Type] = data
			}
		}
		if len(stepData) > 0 {
			ctx[depStep] = stepData
		}
	}

	if len(ctx) == 0 {
		return nil
	}
	return ctx
}

// buildStepRegoContext combines buildStepContext (for AttestationsFrom) and
// an external-attestation context (for ExternalFrom) into the shape the
// policy engine hands to Rego. When neither *From list is set this returns
// nil so that backward-compatible input = raw attestor JSON applies.
//
// When any *From list is non-empty, the returned map is the union of:
//   - cross-step context under the map itself (consumed by EvaluateRegoPolicy
//     which wraps it under input.steps.<name>.<type>)
//   - external-attestation entries under the magic key
//     externalAttestationsContextKey so EvaluateRegoPolicy can lift them to
//     input.external.<name>.
//
// The external value for a given name is the first Passed envelope's
// attestor marshaled to JSON. When the external was Skipped or has no
// Passed envelope, its entry is omitted so Rego `not input.external.x`
// works as expected.
func buildStepRegoContext(step Step, resultsByStep map[string]StepResult, externalResults map[string]ExternalResult) map[string]interface{} {
	if len(step.AttestationsFrom) == 0 && len(step.ExternalFrom) == 0 {
		return nil
	}

	ctx := make(map[string]interface{})

	if len(step.AttestationsFrom) > 0 {
		if err := checkDependencies(step.AttestationsFrom, resultsByStep); err != nil {
			log.Debugf("step %s: dependency not yet verified: %v", step.Name, err)
		} else {
			stepCtx := buildStepContext(step.AttestationsFrom, resultsByStep)
			for k, v := range stepCtx {
				ctx[k] = v
			}
		}
	}

	if len(step.ExternalFrom) > 0 {
		external := make(map[string]interface{})
		for _, name := range step.ExternalFrom {
			er, ok := externalResults[name]
			if !ok || len(er.Passed) == 0 {
				// Skipped externals or externals with no passed envelopes
				// are omitted so Rego `not input.external.<name>` fires.
				continue
			}
			// Serialize the first passed envelope's attestor to JSON and
			// decode as generic JSON so Rego can traverse it.
			first := er.Passed[0]
			if first.Envelope.Attestor == nil {
				continue
			}
			b, err := json.Marshal(first.Envelope.Attestor)
			if err != nil {
				log.Debugf("step %s: failed to marshal external attestor %q: %v", step.Name, name, err)
				continue
			}
			var data interface{}
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.UseNumber()
			if err := dec.Decode(&data); err != nil {
				log.Debugf("step %s: failed to decode external attestor %q: %v", step.Name, name, err)
				continue
			}
			external[name] = data
		}
		if len(external) > 0 {
			ctx[externalAttestationsContextKey] = external
		}
	}

	if len(ctx) == 0 {
		// Non-nil empty context so Rego cross-step rules still fire (same
		// reasoning as verifySteps' empty stepCtx fallback).
		return map[string]interface{}{}
	}
	return ctx
}

// externalAttestationsContextKey is a reserved map key used to carry the
// external-attestation context from buildStepRegoContext to
// EvaluateRegoPolicy. It is not a valid step name (contains characters not
// allowed in step names per the schema) so it cannot collide.
const externalAttestationsContextKey = "__external__"

// checkDependencies verifies that all steps listed in AttestationsFrom have
// at least one passed collection in the results so far. Returns an error if any
// dependency has not been verified yet.
func checkDependencies(attestationsFrom []string, resultsByStep map[string]StepResult) error {
	for _, dep := range attestationsFrom {
		result, ok := resultsByStep[dep]
		if !ok || len(result.Passed) == 0 {
			return ErrDependencyNotVerified{Step: dep}
		}
	}
	return nil
}

// validateAttestations will test each collection against to ensure the expected attestations
// appear in the collection as well as that any rego policies pass for the step.
func (s Step) validateAttestations(collectionResults []source.CollectionVerificationResult, aiServerURL string, stepContext map[string]interface{}) StepResult { //nolint:gocognit,gocyclo,funlen
	result := StepResult{Step: s.Name}
	if len(collectionResults) <= 0 {
		return result
	}

	for _, collection := range collectionResults {
		if collection.Collection.Name != s.Name && collection.Collection.Name != "" {
			log.Debugf("Skipping collection %s as it is not for step %s", collection.Collection.Name, s.Name)
			continue
		}

		found := make(map[string]attestation.Attestor)
		reasons := make([]string, 0)
		passed := true
		var allAiResponses []AiResponse

		if len(collection.Errors) > 0 {
			passed = false
			for _, err := range collection.Errors {
				reasons = append(reasons, fmt.Sprintf("collection verification failed: %s", err.Error()))
			}
		}

		for _, att := range collection.Collection.Attestations {
			found[att.Type] = att.Attestation
			// Also register under the alternate URI so that policies
			// written with witness.dev URIs match aflock.ai attestations and
			// vice versa.
			if alt := attestation.LegacyAlternate(att.Type); alt != "" {
				found[alt] = att.Attestation
			}
		}

		for _, expected := range s.Attestations {
			// Try both the original and alternate URI for the expected type.
			attestor, ok := found[expected.Type]
			if !ok {
				if alt := attestation.LegacyAlternate(expected.Type); alt != "" {
					attestor, ok = found[alt]
				}
			}
			if !ok {
				passed = false
				reasons = append(reasons, ErrMissingAttestation{
					Step:        s.Name,
					Attestation: expected.Type,
				}.Error())
				// Skip policy evaluation — the attestation is missing so there is
				// nothing to evaluate. Continuing would pass a nil attestor to the
				// Rego/AI evaluators.
				continue
			}

			if err := EvaluateRegoPolicy(attestor, expected.RegoPolicies, stepContext); err != nil {
				passed = false
				reasons = append(reasons, err.Error())
			}

			aiResponses, err := EvaluateAIPolicy(attestor, expected.AiPolicies, aiServerURL)
			if err != nil {
				passed = false
				reasons = append(reasons, err.Error())
			}

			if len(aiResponses) > 0 { //nolint:nestif
				allAiResponses = append(allAiResponses, aiResponses...)

				if err == nil {
					for i, resp := range aiResponses {
						if resp.Status == AiStatusFail {
							policyName := ""
							if i < len(expected.AiPolicies) {
								policyName = expected.AiPolicies[i].Name
							}
							if policyName == "" {
								policyName = fmt.Sprintf("AI Policy %d", i+1)
							}

							reason := fmt.Sprintf("AI Policy '%s': %s - %s",
								policyName,
								resp.Status,
								resp.Reason)

							passed = false
							reasons = append(reasons, reason)
						}
					}
				}
			}
		}

		if passed {
			result.Passed = append(result.Passed, PassedCollection{
				Collection:  collection,
				AiResponses: allAiResponses,
			})
		} else {
			r := strings.Join(reasons, ",\n - ")
			reason := fmt.Sprintf("collection validation failed:\n - %s", r)
			result.Rejected = append(result.Rejected, RejectedCollection{
				Collection:  collection,
				Reason:      fmt.Errorf("%s", reason),
				AiResponses: allAiResponses,
			})
		}
	}

	return result
}
