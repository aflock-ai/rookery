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

package workflow

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/timestamp"
)

type runOptions struct {
	stepName           string
	signers            []cryptoutil.Signer
	attestors          []attestation.Attestor
	attestationOpts    []attestation.AttestationContextOption
	timestampers       []timestamp.Timestamper
	additionalSubjects map[string]cryptoutil.DigestSet
	insecure           bool
	ignoreErrors       bool
}

type RunOption func(ro *runOptions)

// RunWithInsecure will allow attestations to be generated unsigned. If insecure is true, RunResult will not
// contain a signed DSSE envelope
func RunWithInsecure(insecure bool) RunOption {
	return func(ro *runOptions) {
		ro.insecure = insecure
	}
}

// RunWithIgnoreErrors will ignore any errors that occur during the execution of the attestors
func RunWithIgnoreErrors(ignoreErrors bool) RunOption {
	return func(ro *runOptions) {
		ro.ignoreErrors = ignoreErrors
	}
}

// RunWithAttestors defines which attestors should be run and added to the resulting AttestationCollection
func RunWithAttestors(attestors []attestation.Attestor) RunOption {
	return func(ro *runOptions) {
		ro.attestors = append(ro.attestors, attestors...)
	}
}

// RunWithAttestationOpts takes in any AttestationContextOptions and forwards them to the context that Run
// creates
func RunWithAttestationOpts(opts ...attestation.AttestationContextOption) RunOption {
	return func(ro *runOptions) {
		ro.attestationOpts = append(ro.attestationOpts, opts...)
	}
}

// RunWithTimestampers will timestamp any signatures created on the DSSE time envelope with the provided
// timestampers
func RunWithTimestampers(ts ...timestamp.Timestamper) RunOption {
	return func(ro *runOptions) {
		ro.timestampers = append(ro.timestampers, ts...)
	}
}

// RunWithSigners configures the signers that will be used to sign the DSSE envelope containing the generated
// attestation collection.
func RunWithSigners(signers ...cryptoutil.Signer) RunOption {
	return func(ro *runOptions) {
		ro.signers = append(ro.signers, signers...)
	}
}

// RunWithAdditionalSubjects merges user-supplied subjects into the in-toto statement
// generated for the attestation collection. These subjects are additive to whatever
// attestors discover — if a key collides with an attestor-produced subject, the
// user-supplied entry wins. Only the collection-level statement is augmented; per-
// attestor exported statements are left untouched.
func RunWithAdditionalSubjects(subjects map[string]cryptoutil.DigestSet) RunOption {
	return func(ro *runOptions) {
		if len(subjects) == 0 {
			return
		}
		if ro.additionalSubjects == nil {
			ro.additionalSubjects = make(map[string]cryptoutil.DigestSet, len(subjects))
		}
		for name, digest := range subjects {
			ro.additionalSubjects[name] = digest
		}
	}
}

// AttestorRunErrors is the structured aggregate returned by Run /
// RunWithExports when one or more attestors reported a non-nil error.
//
// Callers (specifically `cilock run`) split the legs into two classes to set
// the process exit code correctly (finding #221):
//
//   - Fatal: the attestor's contract was violated (signer failure, tracing
//     requested on a platform that doesn't support it, output path
//     inaccessible, command exited non-zero). Exit 1.
//   - Soft:  the attestor ran successfully but the project didn't ship the
//     evidence the attestor wraps (sbom: no SBOM file; go-build: no Go
//     binary). Exit 0; surfaced as a Warnings: line, not Errors:.
//
// SoftLegs() and FatalLegs() walk the captured per-attestor errors so the
// CLI doesn't have to re-do the errors.As dispatch itself.
type AttestorRunErrors struct {
	// Legs is the per-attestor error list, in completion order. Each
	// entry already wraps the underlying error with the
	// "attestor X failed: ..." prefix the legacy code path used.
	Legs []AttestorErrorLeg
}

// AttestorErrorLeg pairs an attestor name with the error it returned. The
// Err field still wraps any SoftError or other typed error returned by the
// attestor, so callers can errors.As(leg.Err, &target) freely.
type AttestorErrorLeg struct {
	Attestor string
	Err      error
}

// Error implements error. Preserves the legacy "attestors failed with error
// messages: ..." shape so existing string-matching consumers don't break.
func (e *AttestorRunErrors) Error() string {
	if e == nil || len(e.Legs) == 0 {
		return "attestors failed with error messages"
	}
	parts := make([]string, 0, len(e.Legs)+1)
	parts = append(parts, "attestors failed with error messages")
	for _, leg := range e.Legs {
		parts = append(parts, leg.Err.Error())
	}
	return strings.Join(parts, "\n")
}

// Unwrap returns the slice of per-attestor errors. errors.As / errors.Is
// traverse this slice so callers can interrogate any individual leg.
func (e *AttestorRunErrors) Unwrap() []error {
	if e == nil {
		return nil
	}
	out := make([]error, 0, len(e.Legs))
	for _, leg := range e.Legs {
		out = append(out, leg.Err)
	}
	return out
}

// SoftLegs returns the legs whose error wraps an attestation.SoftError —
// i.e. "attestor ran but had nothing to do" cases. CLI demotes these to
// warnings and keeps the exit code at zero.
func (e *AttestorRunErrors) SoftLegs() []AttestorErrorLeg {
	if e == nil {
		return nil
	}
	var out []AttestorErrorLeg
	for _, leg := range e.Legs {
		if attestation.IsSoftError(leg.Err) {
			out = append(out, leg)
		}
	}
	return out
}

// FatalLegs returns the legs that are NOT SoftErrors — contract violations
// that should propagate to a non-zero process exit code.
func (e *AttestorRunErrors) FatalLegs() []AttestorErrorLeg {
	if e == nil {
		return nil
	}
	var out []AttestorErrorLeg
	for _, leg := range e.Legs {
		if !attestation.IsSoftError(leg.Err) {
			out = append(out, leg)
		}
	}
	return out
}

// HasFatal reports whether any leg is fatal. Convenience over FatalLegs()
// for callers that only need a boolean.
func (e *AttestorRunErrors) HasFatal() bool {
	if e == nil {
		return false
	}
	for _, leg := range e.Legs {
		if !attestation.IsSoftError(leg.Err) {
			return true
		}
	}
	return false
}

// RunResult contains the generated attestation collection as well as the signed DSSE envelope, if one was
// created.
//
// CollectionSubjects is the post-merge subject set for the collection-level statement —
// i.e. attestor-discovered subjects plus any entries supplied via RunWithAdditionalSubjects.
// It is populated for the collection RunResult regardless of whether the run was signed
// or insecure, so unsigned-envelope callers can reproduce the same subject set the signed
// path would have used. It is nil for per-attestor exported RunResults.
type RunResult struct {
	Collection         attestation.Collection
	SignedEnvelope     dsse.Envelope
	AttestorName       string
	CollectionSubjects map[string]cryptoutil.DigestSet
}

// Deprecated: Use RunWithExports instead
func Run(stepName string, opts ...RunOption) (RunResult, error) {
	results, err := run(stepName, opts)
	if len(results) == 0 {
		return RunResult{}, err
	} else if len(results) > 1 {
		return RunResult{}, errors.New("expected a single result, got multiple")
	}

	return results[0], err
}

func RunWithExports(stepName string, opts ...RunOption) ([]RunResult, error) {
	return run(stepName, opts)
}

func run(stepName string, opts []RunOption) ([]RunResult, error) { //nolint:gocognit,gocyclo,funlen
	ro := runOptions{
		stepName:     stepName,
		insecure:     false,
		ignoreErrors: false,
	}

	for _, opt := range opts {
		opt(&ro)
	}

	result := []RunResult{}
	if err := validateRunOpts(ro); err != nil {
		return result, err
	}

	runCtx, err := attestation.NewContext(stepName, ro.attestors, ro.attestationOpts...)
	if err != nil {
		return result, fmt.Errorf("failed to create attestation context: %w", err)
	}

	if err = runCtx.RunAttestors(); err != nil {
		return result, fmt.Errorf("failed to run attestors: %w", err)
	}

	// Compute the parent-subject pool ONCE: the union of subjects from
	// every non-exported attestor (git, material, product, …) plus the
	// user-supplied additional subjects. This is the same anchor set the
	// wrapping collection envelope's subjects[] will carry.
	//
	// Each exported sidecar envelope (sbom, slsa, link, vex, …) is then
	// signed with `parentSubjects ∪ exporter.Subjects()`. Without this,
	// the sidecar only carries its own internal subjects (file digests
	// of the predicate body), which don't overlap with the seed subjects
	// users pass to `cilock verify -s <commit>` — verify's
	// ExternalAttestation lookup returns 0 envelopes even though the
	// sidecar is on disk and signed by a trusted functionary. Bug
	// surfaced by the prometheus blind-test (cf. `cilock policy
	// from-bundles` sidecar discovery, PR #186).
	parentSubjects := collectParentSubjects(runCtx, ro.additionalSubjects)

	legs := make([]AttestorErrorLeg, 0)
	for _, r := range runCtx.CompletedAttestors() {
		if r.Error != nil { //nolint:nestif
			wrappedErr := fmt.Errorf("attestor %s failed: %w", r.Attestor.Name(), r.Error)
			legs = append(legs, AttestorErrorLeg{Attestor: r.Attestor.Name(), Err: wrappedErr})
		} else {
			// Check if this is a MultiExporter first
			if multiExporter, ok := r.Attestor.(attestation.MultiExporter); ok {
				// Create individual attestations for each exported attestor
				for _, exportedAttestor := range multiExporter.ExportedAttestations() {
					// Guard against nil entries in ExportedAttestations to prevent
					// nil pointer panics (R3-233). This code path has no recover(),
					// so a nil entry would crash the entire process.
					if exportedAttestor == nil {
						log.Warnf("MultiExporter %s returned nil attestor in ExportedAttestations(), skipping", r.Attestor.Name())
						continue
					}

					var envelope dsse.Envelope
					var ownSubjects map[string]cryptoutil.DigestSet

					// Get subjects if the exported attestor implements Subjecter
					if subjecter, ok := exportedAttestor.(attestation.Subjecter); ok {
						ownSubjects = subjecter.Subjects()
					}

					if !ro.insecure {
						envelope, err = createAndSignEnvelope(exportedAttestor, exportedAttestor.Type(), mergeCollectionSubjects(parentSubjects, ownSubjects), dsse.SignWithSigners(ro.signers...), dsse.SignWithTimestampers(ro.timestampers...))
						if err != nil {
							return result, fmt.Errorf("failed to sign envelope for %s: %w", exportedAttestor.Name(), err)
						}
					}

					// Create attestor name combining parent and exported attestor names
					attestorName := fmt.Sprintf("%s/%s", r.Attestor.Name(), exportedAttestor.Name())
					result = append(result, RunResult{SignedEnvelope: envelope, AttestorName: attestorName})
				}
				// Skip regular Exporter processing for MultiExporter attestors
			} else if exporter, ok := r.Attestor.(attestation.Exporter); ok {
				if !exporter.Export() {
					log.Debugf("%s attestor not configured to be exported as its own attestation", r.Attestor.Name())
					continue
				}
				if subjecter, ok := r.Attestor.(attestation.Subjecter); ok {
					var envelope dsse.Envelope
					if !ro.insecure {
						envelope, err = createAndSignEnvelope(r.Attestor, r.Attestor.Type(), mergeCollectionSubjects(parentSubjects, subjecter.Subjects()), dsse.SignWithSigners(ro.signers...), dsse.SignWithTimestampers(ro.timestampers...))
						if err != nil {
							return result, fmt.Errorf("failed to sign envelope: %w", err)
						}
					}
					result = append(result, RunResult{SignedEnvelope: envelope, AttestorName: r.Attestor.Name()})
				}
			}
		}
	}
	// Build and sign the collection even when attestors failed. This ensures
	// forensic data (e.g. secretscan findings) is captured in the attestation
	// file so it can be used for post-incident analysis and policy verification.
	//
	// Errors are returned as a typed AttestorRunErrors so callers (the
	// `cilock run` CLI) can split soft errors (attestor had nothing to do)
	// from fatal ones (contract violation). See finding #221.
	var attestorErr error
	if !ro.ignoreErrors && len(legs) > 0 {
		attestorErr = &AttestorRunErrors{Legs: legs}
	}

	// Filter attestors for collection - exclude those that are exported separately
	var attestorsForCollection []attestation.CompletedAttestor
	for _, completed := range runCtx.CompletedAttestors() {
		if completed.Error != nil {
			continue
		}

		// Skip MultiExporter attestors as they export their own attestations
		if _, ok := completed.Attestor.(attestation.MultiExporter); ok {
			continue
		}

		// Skip attestors that implement Exporter and want to be exported separately
		if exporter, ok := completed.Attestor.(attestation.Exporter); ok && exporter.Export() {
			continue
		}

		// Include all other attestors in the collection
		attestorsForCollection = append(attestorsForCollection, completed)
	}

	var collectionResult RunResult
	collectionResult.Collection = attestation.NewCollection(ro.stepName, attestorsForCollection)
	// Merge user-supplied subjects into the collection's in-toto subject set.
	// User entries take precedence on key collision so an explicit override is
	// honoured deterministically. The merge runs for both signed and insecure
	// paths so downstream consumers that build unsigned envelopes from
	// CollectionSubjects see the same set the signed path would have used.
	collectionResult.CollectionSubjects = mergeCollectionSubjects(collectionResult.Collection.Subjects(), ro.additionalSubjects)
	if !ro.insecure {
		collectionResult.SignedEnvelope, err = createAndSignEnvelope(collectionResult.Collection, attestation.CollectionType, collectionResult.CollectionSubjects, dsse.SignWithSigners(ro.signers...), dsse.SignWithTimestampers(ro.timestampers...))
		if err != nil {
			return result, fmt.Errorf("failed to sign collection: %w", err)
		}
	}
	result = append(result, collectionResult)

	return result, attestorErr
}

// collectParentSubjects walks the completed attestors and assembles
// the subject pool that the wrapping collection envelope will carry.
// Subjects from any attestor opting OUT of the collection (i.e.,
// implementing Exporter with Export()==true, or MultiExporter) are
// excluded — those attestors carry their own subjects in their
// sidecar envelopes, and inheriting them here would create a
// circular subject graph (sidecar carrying its own digest as a
// subject to itself).
//
// User-supplied additional subjects are merged on top with precedence
// matching mergeCollectionSubjects.
//
// This pool is then unioned with each exported attestor's own
// subjects when signing its sidecar — see the export loop in run().
// Without it, a sidecar's subjects don't overlap with the seed
// subjects users pass to `cilock verify -s <commit>`, and
// ExternalAttestation lookups fail with "not found" even though the
// envelope is loaded and trusted.
func collectParentSubjects(runCtx *attestation.AttestationContext, additional map[string]cryptoutil.DigestSet) map[string]cryptoutil.DigestSet {
	pool := make(map[string]cryptoutil.DigestSet)
	for _, completed := range runCtx.CompletedAttestors() {
		if completed.Error != nil {
			continue
		}
		// Skip attestors that emit their own sidecar — we're computing
		// the *non-sidecar* subject pool.
		if _, ok := completed.Attestor.(attestation.MultiExporter); ok {
			continue
		}
		if exp, ok := completed.Attestor.(attestation.Exporter); ok && exp.Export() {
			continue
		}
		subjecter, ok := completed.Attestor.(attestation.Subjecter)
		if !ok {
			continue
		}
		for name, digest := range subjecter.Subjects() {
			pool[name] = digest
		}
	}
	return mergeCollectionSubjects(pool, additional)
}

// mergeCollectionSubjects returns the union of attestor-discovered subjects
// (base) and user-supplied additional subjects. On key collision the user
// entry wins. Returns nil if both inputs are empty so callers can distinguish
// "no subjects" from "empty map". Safe to call with either argument nil.
func mergeCollectionSubjects(base, additional map[string]cryptoutil.DigestSet) map[string]cryptoutil.DigestSet {
	if len(base) == 0 && len(additional) == 0 {
		return nil
	}
	merged := make(map[string]cryptoutil.DigestSet, len(base)+len(additional))
	for name, digest := range base {
		merged[name] = digest
	}
	for name, digest := range additional {
		merged[name] = digest
	}
	return merged
}

func validateRunOpts(ro runOptions) error {
	if ro.stepName == "" {
		return fmt.Errorf("step name is required")
	}

	if len(ro.signers) == 0 && !ro.insecure {
		return fmt.Errorf("at least one signer is required if not in insecure mode")
	}

	return nil
}

func createAndSignEnvelope(predicate interface{}, predType string, subjects map[string]cryptoutil.DigestSet, opts ...dsse.SignOption) (dsse.Envelope, error) {
	data, err := json.Marshal(&predicate)
	if err != nil {
		return dsse.Envelope{}, err
	}

	stmt, err := intoto.NewStatement(predType, data, subjects)
	if err != nil {
		return dsse.Envelope{}, err
	}

	stmtJSON, err := json.Marshal(&stmt)
	if err != nil {
		return dsse.Envelope{}, err
	}

	return dsse.Sign(intoto.PayloadType, bytes.NewReader(stmtJSON), opts...)
}
