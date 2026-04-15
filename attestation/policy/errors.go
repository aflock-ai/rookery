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
	return fmt.Sprintf("no collections found for step %v", e.Step)
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
