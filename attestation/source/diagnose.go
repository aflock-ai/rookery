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

package source

import (
	"fmt"
	"sort"
)

// StepDiagnosis explains WHY candidate selection for a policy step found no
// collection. Candidate selection filters loaded collections by three things at
// once — collection NAME (must equal the step name), required attestation TYPES,
// and SUBJECT digests — and the filtered Search returns a single empty result
// regardless of which filter excluded everything. That ambiguity is what made
// the generic "no collections found ... supply the inclusion-proof sidecar"
// message misleading: it fires for a name mismatch, a required-type mismatch,
// AND a genuine subject mismatch, but only describes the last.
//
// StepDiagnosis re-derives the three states directly from the source index (no
// subject filter, no signature check — candidate selection happens before
// signature verification, and signature failures surface separately as
// "no verifiers"), so the caller can emit a cause-specific error.
type StepDiagnosis struct {
	// NameLoaded is true when at least one collection is loaded under the
	// step's name. False means nothing was supplied for the step, or the
	// collection name does not match the step name.
	NameLoaded bool
	// TypesSatisfied is true when at least one name-matched collection carries
	// ALL of the step's required attestation types.
	TypesSatisfied bool
	// MissingTypes lists required types absent from the union of name-matched
	// collections. Meaningful only when TypesSatisfied is false. It can be empty
	// while TypesSatisfied is false when every required type is present in SOME
	// collection but no single collection carries all of them.
	MissingTypes []string
	// ObservedTypes is the union of attestation types across name-matched
	// collections, sorted.
	ObservedTypes []string
	// ObservedSubjects renders "<name> (<algo>:<digest>)" for the subjects of the
	// collections that satisfy the required types — i.e. what the operator could
	// have matched. Populated only when TypesSatisfied is true (when types are
	// the problem, subjects are not the relevant signal).
	ObservedSubjects []string
}

// StepDiagnoser is implemented by sources that can cheaply enumerate their
// loaded collections by name (the in-memory index). Remote sources (e.g.
// Archivista) do not implement it; callers fall back to a coarser probe.
type StepDiagnoser interface {
	DiagnoseStep(collectionName string, requiredTypes []string) StepDiagnosis
}

// sortedStringSet returns the set's keys as a sorted slice (nil for an empty set
// so callers can distinguish "no entries" from "[]" cleanly in errors).
func sortedStringSet(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// DiagnoseStep inspects the in-memory index to explain why candidate selection
// for collectionName found nothing. It deliberately ignores subject filters and
// signatures (see StepDiagnosis) — its job is to attribute a candidate-selection
// miss to name / type / subject.
func (s *MemorySource) DiagnoseStep(collectionName string, requiredTypes []string) StepDiagnosis {
	s.mu.RLock()
	defer s.mu.RUnlock()

	diag := StepDiagnosis{}
	refs := s.referencesByCollectionName[collectionName]
	if len(refs) == 0 {
		return diag // NameLoaded stays false: nothing under this collection name.
	}
	diag.NameLoaded = true

	observedTypes := make(map[string]struct{})
	var satisfyingRefs []string
	for _, ref := range refs {
		idx := s.attestationsByReference[ref]
		for t := range idx {
			observedTypes[t] = struct{}{}
		}
		hasAll := true
		for _, rt := range requiredTypes {
			if _, ok := idx[rt]; !ok {
				hasAll = false
				break
			}
		}
		if hasAll {
			satisfyingRefs = append(satisfyingRefs, ref)
		}
	}
	diag.ObservedTypes = sortedStringSet(observedTypes)
	diag.TypesSatisfied = len(satisfyingRefs) > 0

	if !diag.TypesSatisfied {
		var missing []string
		for _, rt := range requiredTypes {
			if _, ok := observedTypes[rt]; !ok {
				missing = append(missing, rt)
			}
		}
		diag.MissingTypes = missing
		return diag
	}

	// Types satisfy — the miss was a subject mismatch. Surface the subjects the
	// operator could have matched against.
	subjects := make(map[string]struct{})
	for _, ref := range satisfyingRefs {
		env, ok := s.envelopesByReference[ref]
		if !ok {
			continue
		}
		for _, sub := range env.Statement.Subject {
			repr := sub.Name
			for algo, dig := range sub.Digest {
				repr = fmt.Sprintf("%s (%s:%s)", sub.Name, algo, dig)
				break
			}
			subjects[repr] = struct{}{}
		}
	}
	diag.ObservedSubjects = sortedStringSet(subjects)
	return diag
}

// DiagnoseStep aggregates the diagnoses of every child source that supports it
// (e.g. a MemorySource sitting beside a remote Archivista source). A child that
// cannot diagnose is skipped; if none can, the aggregate reports NameLoaded
// false and callers fall back to the coarser probe.
func (s *MultiSource) DiagnoseStep(collectionName string, requiredTypes []string) StepDiagnosis {
	agg := StepDiagnosis{}
	types := make(map[string]struct{})
	subjects := make(map[string]struct{})
	for _, src := range s.sources {
		d, ok := src.(StepDiagnoser)
		if !ok {
			continue
		}
		sub := d.DiagnoseStep(collectionName, requiredTypes)
		agg.NameLoaded = agg.NameLoaded || sub.NameLoaded
		agg.TypesSatisfied = agg.TypesSatisfied || sub.TypesSatisfied
		for _, t := range sub.ObservedTypes {
			types[t] = struct{}{}
		}
		for _, sj := range sub.ObservedSubjects {
			subjects[sj] = struct{}{}
		}
	}
	agg.ObservedTypes = sortedStringSet(types)
	agg.ObservedSubjects = sortedStringSet(subjects)
	if !agg.TypesSatisfied {
		var missing []string
		for _, rt := range requiredTypes {
			if _, ok := types[rt]; !ok {
				missing = append(missing, rt)
			}
		}
		agg.MissingTypes = missing
	}
	return agg
}

// DiagnoseStep delegates to the underlying source when it supports diagnosis.
// The bool reports whether a real diagnosis was produced (false → the caller
// should fall back to a coarser probe). Signature verification is irrelevant
// here: candidate selection — which this diagnoses — runs before it.
func (s *VerifiedSource) DiagnoseStep(collectionName string, requiredTypes []string) (StepDiagnosis, bool) {
	if d, ok := s.source.(StepDiagnoser); ok {
		return d.DiagnoseStep(collectionName, requiredTypes), true
	}
	return StepDiagnosis{}, false
}
