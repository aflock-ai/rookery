package cli

import (
	"encoding/json"
	"sort"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/attestation/slsa"
	"github.com/aflock-ai/rookery/attestation/workflow"
)

// The stepResults extension's types live with the VSA type, so the attestor that reads a VSA back
// (policyverify, a parent policy's external) keeps what this writes.
type vsaRejection = slsa.VerificationRejection

type vsaStepResult = slsa.VerificationStepResult

type vsaPredicateWithSteps struct {
	slsa.VerificationSummary
	StepResults []vsaStepResult `json:"stepResults"`
}

// denies is every Rego/AI deny message in a rejection reason's error chain
// (policy.DenyReasons): structural only, never parsed out of rendered text.
func denies(err error) []string { return policy.DenyReasons(err) }

// marshalVSAPredicate is the SLSA VSA v1 predicate plus a stepResults extension.
func marshalVSAPredicate(evidence workflow.VerifyResult) ([]byte, error) {
	names := make([]string, 0, len(evidence.StepResults))
	for n := range evidence.StepResults {
		names = append(names, n)
	}
	sort.Strings(names)
	steps := make([]vsaStepResult, 0, len(names))
	for _, n := range names {
		r := evidence.StepResults[n]
		s := vsaStepResult{Step: n, Passed: []string{}, Rejected: []vsaRejection{}}
		for _, p := range r.Passed {
			s.Passed = append(s.Passed, p.Collection.Reference)
		}
		for _, rj := range r.Rejected {
			reason := ""
			if rj.Reason != nil {
				reason = rj.Reason.Error()
			}
			s.Rejected = append(s.Rejected, vsaRejection{
				Reference:  rj.Collection.Reference,
				Collection: rj.Collection.Collection.Name,
				Reason:     reason,
				Denies:     denies(rj.Reason),
			})
		}
		steps = append(steps, s)
	}
	return json.Marshal(vsaPredicateWithSteps{VerificationSummary: evidence.VerificationSummary, StepResults: steps})
}
