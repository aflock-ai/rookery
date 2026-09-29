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

import "errors"

// ErrEvidenceUnavailable marks a verification that stopped because the evidence
// could not be read (a source search failed: authentication, network, a store
// error), as opposed to a policy decision over evidence that was read. A caller
// gating on the result must not report it as a denial: nothing was judged.
var ErrEvidenceUnavailable = errors.New("evidence could not be read")

// NoVerdict reports whether a failed verification reached no decision at all:
// the evidence could not be read (ErrEvidenceUnavailable), an evaluator refused
// to answer (an AI refusal or a Rego deadline, regorefusal.go), or the external
// candidate assignments could not all be tried (ErrExternalAssignmentsExceedBound).
// Every other failure is a policy decision over evidence that was read: a denial.
//
// Modelled as `ErrTree.noVerdict` in formal/cilock-evaluators Verdict.lean.
func NoVerdict(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrEvidenceUnavailable) || evaluationRefusal(err) != nil {
		return true
	}
	var bound ErrExternalAssignmentsExceedBound
	return errors.As(err, &bound)
}

// DenyReasons returns every Rego/AI deny message in err's chain, in depth-first
// order: the Reasons of each ErrPolicyDenied reachable through Unwrap() error
// and Unwrap() []error. A collection rejected by several attestors carries one
// ErrPolicyDenied per attestor (ErrCollectionValidationFailed), so errors.As,
// which stops at the first, would drop the rest. Nothing is parsed out of
// rendered text: a deny message may itself contain ", ".
//
// Modelled as `ErrTree.denies` in formal/cilock-evaluators Verdict.lean.
func DenyReasons(err error) []string {
	var out []string
	var walk func(error)
	walk = func(e error) {
		switch d := e.(type) {
		case nil:
			return
		case ErrPolicyDenied:
			out = append(out, d.Reasons...)
			return
		case *ErrPolicyDenied:
			if d != nil {
				out = append(out, d.Reasons...)
			}
			return
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, c := range u.Unwrap() {
				walk(c)
			}
		case interface{ Unwrap() error }:
			walk(u.Unwrap())
		}
	}
	walk(err)
	return out
}
