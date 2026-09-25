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

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// The platform door verifies EVERY policy binding of the product. A product's
// gate can span several bound releases (judge's own push gate spans two), and
// no single binding expresses it; an earlier revision refused any product with
// more than one binding (ResolveBoundPolicy, internal/options/policypublish.go).
//
// The acceptance rule composes gateAccepts per binding: the gate passes only
// when every binding's verdict is PASSED and carries its VSA. A binding the
// door could not evaluate (transport error, timeout, a refusal, a nil row) is
// reported as UNEVALUATED, distinct from FAILED, and never passes. A product
// with no binding is an error, not a vacuous pass.

// Per-binding and overall statuses beyond the door's own PASSED/FAILED/PENDING.
const (
	gateStatusPassed      = "PASSED"
	gateStatusFailed      = "FAILED"
	gateStatusPending     = "PENDING"
	gateStatusUnevaluated = "UNEVALUATED"
)

// platformDoorEvalConcurrency bounds how many bindings are evaluated at once.
// Each evaluation is an inline verify on the platform; a small bound keeps a
// product with many bindings from stampeding it while still overlapping the
// common two- or three-binding case.
const platformDoorEvalConcurrency = 4

// errNoBoundPolicy marks a product with no binding at all. The caller turns it
// into the remedy message with the product's display name.
var errNoBoundPolicy = errors.New("no policy bound")

// platformDoor is the slice of the policy client the door fan-out uses; a
// fake satisfies it in tests.
type platformDoor interface {
	ListProductBindings(ctx context.Context, productID string) ([]options.BoundPolicy, error)
	VerifyComplianceSync(ctx context.Context, bindingID, commitHash string, subjectDigests []string, force bool) (*options.PlatformEvaluation, error)
}

// bindingOutcome is one binding's answer: the door's evaluation, or the reason
// it could not be had.
type bindingOutcome struct {
	Binding options.BoundPolicy
	Eval    *options.PlatformEvaluation
	Err     error
}

func (o bindingOutcome) accepted() bool { return o.Err == nil && gateAccepts(o.Eval) }

// status is the binding's verdict. An error or a missing row is UNEVALUATED:
// the door never answered, so nothing was judged, and calling it FAILED would
// tell the reader their evidence is bad when it was never looked at.
func (o bindingOutcome) status() string {
	if o.Err != nil || o.Eval == nil {
		return gateStatusUnevaluated
	}
	return strings.ToUpper(o.Eval.Status)
}

// platformGate is the whole answer: every binding, in deterministic order.
type platformGate struct {
	Outcomes []bindingOutcome
}

func (g *platformGate) accepted() bool {
	if len(g.Outcomes) == 0 {
		return false
	}
	for _, o := range g.Outcomes {
		if !o.accepted() {
			return false
		}
	}
	return true
}

// status aggregates the per-binding verdicts. FAILED is the definitive answer
// and wins; then UNEVALUATED (something was never judged); then PENDING. When
// every binding PASSED the overall is PASSED, and `passed` in the JSON still
// says whether the gate accepts (a PASSED binding without its VSA does not).
// Any status the door invents later that is none of these is not a pass, so it
// surfaces as UNEVALUATED rather than being read as one.
func (g *platformGate) status() string {
	counts := map[string]int{}
	for _, o := range g.Outcomes {
		counts[o.status()]++
	}
	switch {
	case len(g.Outcomes) == 0:
		return gateStatusUnevaluated
	case counts[gateStatusFailed] > 0:
		return gateStatusFailed
	case counts[gateStatusUnevaluated] > 0:
		return gateStatusUnevaluated
	case counts[gateStatusPending] > 0:
		return gateStatusPending
	case counts[gateStatusPassed] == len(g.Outcomes):
		return gateStatusPassed
	default:
		return gateStatusUnevaluated
	}
}

// evaluateAllBindings lists every binding of the product and asks the door for
// each one's verdict under the same anchors. It returns an error only when
// there is nothing to evaluate (no binding, or the listing itself failed);
// per-binding failures are carried in the outcomes so every one is reported.
func evaluateAllBindings(ctx context.Context, door platformDoor, productID, commit string, subjects []string) (*platformGate, error) {
	bindings, err := door.ListProductBindings(ctx, productID)
	if err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		return nil, fmt.Errorf("%w for product %s: bind one with `cilock policy bind`, or pass -p/--policy for local verification", errNoBoundPolicy, productID)
	}
	bindings = append([]options.BoundPolicy(nil), bindings...)
	options.SortBoundPolicies(bindings)

	for _, b := range bindings {
		// The loud provenance line, BEFORE any verdict output: name each policy
		// about to be trusted and on whose authority.
		log.Infof("platform verify: policy %q release %s (binding %s), bound by %s at %s; --client verifies locally instead",
			b.DefinitionName, releaseLabel(b), b.BindingID, b.BoundBy, b.BoundAt)
	}

	outcomes := make([]bindingOutcome, len(bindings))
	sem := make(chan struct{}, platformDoorEvalConcurrency)
	var wg sync.WaitGroup
	for i, b := range bindings {
		wg.Add(1)
		go func(i int, b options.BoundPolicy) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			eval, verr := door.VerifyComplianceSync(ctx, b.BindingID, commit, subjects, false)
			if verr == nil && eval == nil {
				verr = errors.New("the door answered with no evaluation row")
			}
			outcomes[i] = bindingOutcome{Binding: b, Eval: eval, Err: verr}
		}(i, b)
	}
	wg.Wait()
	return &platformGate{Outcomes: outcomes}, nil
}

// releaseLabel names the release a binding verifies under. An unpinned binding
// is resolved by the platform, and the client does not guess which release.
func releaseLabel(b options.BoundPolicy) string {
	if b.ReleaseTag == "" {
		return "(unpinned: the platform resolves it)"
	}
	return fmt.Sprintf("%q", b.ReleaseTag)
}

// platformVerdictJSON is the machine-readable platform-mode verdict, the
// sibling of the local mode's VerifyVerdict: `passed` for branching, and it
// means "this gate accepts", never a raw platform verdict, so branching on it
// and branching on the exit code are the same branch.
//
// The top-level fields predate multi-binding verification and keep their
// meaning for a single binding. With several bindings no one VSA or evaluation
// speaks for the gate, so vsaGitoidSha256 and evaluationId are left empty and
// each binding's answer is in `bindings`. A consumer that gates on
// `passed && vsaGitoidSha256 != ""` therefore refuses a multi-binding verdict:
// the safe direction, and the cue to read `bindings`.
type platformVerdictJSON struct {
	Passed          bool                 `json:"passed"`
	Status          string               `json:"status"`
	Reasons         []string             `json:"reasons,omitempty"`
	VsaGitoidSha256 string               `json:"vsaGitoidSha256,omitempty"`
	EvaluationID    string               `json:"evaluationId,omitempty"`
	CommitHash      string               `json:"commitHash,omitempty"`
	Bindings        []bindingVerdictJSON `json:"bindings"`
}

// bindingVerdictJSON is one binding's verdict. Error is set only when the door
// could not evaluate the binding (status UNEVALUATED).
type bindingVerdictJSON struct {
	BindingID       string   `json:"bindingId"`
	Policy          string   `json:"policy,omitempty"`
	Release         string   `json:"release,omitempty"`
	PolicyGitoid    string   `json:"policyGitoid,omitempty"`
	Passed          bool     `json:"passed"`
	Status          string   `json:"status"`
	Reasons         []string `json:"reasons,omitempty"`
	VsaGitoidSha256 string   `json:"vsaGitoidSha256,omitempty"`
	EvaluationID    string   `json:"evaluationId,omitempty"`
	CommitHash      string   `json:"commitHash,omitempty"`
	Error           string   `json:"error,omitempty"`
}

func (o bindingOutcome) toJSON() bindingVerdictJSON {
	bj := bindingVerdictJSON{
		BindingID:    o.Binding.BindingID,
		Policy:       o.Binding.DefinitionName,
		Release:      o.Binding.ReleaseTag,
		PolicyGitoid: o.Binding.Gitoid,
		Passed:       o.accepted(),
		Status:       o.status(),
	}
	if o.Err != nil {
		bj.Error = o.Err.Error()
	}
	if o.Eval != nil {
		bj.Reasons = o.Eval.Reasons
		bj.VsaGitoidSha256 = o.Eval.VsaGitoidSha256
		bj.EvaluationID = o.Eval.ID
		bj.CommitHash = o.Eval.CommitHash
	}
	return bj
}

func (g *platformGate) toJSON() platformVerdictJSON {
	out := platformVerdictJSON{Passed: g.accepted(), Status: g.status()}
	out.Bindings = make([]bindingVerdictJSON, 0, len(g.Outcomes))
	for _, o := range g.Outcomes {
		out.Bindings = append(out.Bindings, o.toJSON())
	}

	if len(out.Bindings) == 1 {
		// The pre-multi-binding shape, field for field.
		one := out.Bindings[0]
		out.Reasons = one.Reasons
		out.VsaGitoidSha256 = one.VsaGitoidSha256
		out.EvaluationID = one.EvaluationID
		out.CommitHash = one.CommitHash
		if one.Error != "" {
			out.Reasons = append(out.Reasons, "could not evaluate: "+one.Error)
		}
		return out
	}
	out.Reasons = aggregateReasons(out.Bindings)
	out.CommitHash = sharedCommit(out.Bindings)
	return out
}

// aggregateReasons prefixes every non-accepted binding's reasons with the
// policy they belong to, so the top-level list says which policy refused.
func aggregateReasons(bs []bindingVerdictJSON) []string {
	var reasons []string
	for _, b := range bs {
		if b.Passed {
			continue
		}
		label := bindingLabel(b.Policy, b.BindingID)
		switch {
		case b.Error != "":
			reasons = append(reasons, fmt.Sprintf("%s: could not evaluate: %s", label, b.Error))
		case len(b.Reasons) == 0:
			reasons = append(reasons, fmt.Sprintf("%s: %s", label, notAcceptedReason(b)))
		default:
			for _, r := range b.Reasons {
				reasons = append(reasons, fmt.Sprintf("%s: %s", label, r))
			}
		}
	}
	return reasons
}

// sharedCommit is the commit every answering binding named, or "" when they
// named none or disagree.
func sharedCommit(bs []bindingVerdictJSON) string {
	commit := ""
	for _, b := range bs {
		if b.CommitHash == "" {
			continue
		}
		if commit != "" && commit != b.CommitHash {
			return ""
		}
		commit = b.CommitHash
	}
	return commit
}

func notAcceptedReason(b bindingVerdictJSON) string {
	if strings.EqualFold(b.Status, gateStatusPassed) && b.VsaGitoidSha256 == "" {
		return "passed, but no VSA was recorded, so the verdict is not independently verifiable"
	}
	return "status " + b.Status
}

func bindingLabel(policy, bindingID string) string {
	if policy == "" {
		return "binding " + bindingID
	}
	return fmt.Sprintf("policy %q (binding %s)", policy, bindingID)
}

// renderPlatformGate reports every binding's answer and the overall verdict,
// then returns the exit decision. The VSA gitoid is printed on success AND on
// failure when present: the signed claim exists either way, and the failure
// VSA is exactly what an auditor wants.
func renderPlatformGate(vo options.VerifyOptions, g *platformGate, stdout, stderr io.Writer) error {
	if vo.OutputJSON() {
		if err := json.NewEncoder(stdout).Encode(g.toJSON()); err != nil {
			return fmt.Errorf("encode platform verdict: %w", err)
		}
	} else {
		writeHumanGate(stderr, g)
	}
	return gateExitError(g)
}

func writeHumanGate(w io.Writer, g *platformGate) {
	n := len(g.Outcomes)
	for i, o := range g.Outcomes {
		head := fmt.Sprintf("[%d/%d] policy %q release %s (binding %s):", i+1, n,
			o.Binding.DefinitionName, releaseLabel(o.Binding), o.Binding.BindingID)
		switch st := o.status(); st {
		case gateStatusUnevaluated:
			_, _ = fmt.Fprintf(w, "%s UNEVALUATED, could not evaluate: %v\n", head, errOrMissing(o))
		case gateStatusPassed:
			_, _ = fmt.Fprintf(w, "%s PASSED, VSA %s\n", head, orNoVSA(o.Eval.VsaGitoidSha256))
		case gateStatusPending:
			_, _ = fmt.Fprintf(w, "%s PENDING, the policy's evidence has not arrived for this anchor yet; "+
				"if the pipeline just uploaded, confirm the upload returned before verifying\n", head)
		default:
			_, _ = fmt.Fprintf(w, "%s %s, VSA %s\n", head, st, orNoVSA(o.Eval.VsaGitoidSha256))
		}
		if o.Eval != nil {
			for _, r := range o.Eval.Reasons {
				_, _ = fmt.Fprintf(w, "  reason: %s\n", r)
			}
		}
	}
	if g.accepted() {
		_, _ = fmt.Fprintf(w, "PASSED: all %d bound %s passed, each with its own VSA\n", n, plural(n, "policy", "policies"))
		return
	}
	_, _ = fmt.Fprintf(w, "%s: %s\n", g.status(), gateSummary(g))
}

func errOrMissing(o bindingOutcome) error {
	if o.Err != nil {
		return o.Err
	}
	return errors.New("the door answered with no evaluation row")
}

// gateSummary counts the bindings by verdict, e.g. "1 of 2 bound policies
// passed; 1 could not evaluate".
func gateSummary(g *platformGate) string {
	var passed, failed, pending, unevaluated, noVSA int
	for _, o := range g.Outcomes {
		switch {
		case o.accepted():
			passed++
		case o.status() == gateStatusUnevaluated:
			unevaluated++
		case o.status() == gateStatusPending:
			pending++
		case o.status() == gateStatusPassed:
			noVSA++
		default:
			failed++
		}
	}
	n := len(g.Outcomes)
	parts := []string{fmt.Sprintf("%d of %d bound %s passed", passed, n, plural(n, "policy", "policies"))}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", failed))
	}
	if unevaluated > 0 {
		parts = append(parts, fmt.Sprintf("%d could not evaluate", unevaluated))
	}
	if pending > 0 {
		parts = append(parts, fmt.Sprintf("%d pending", pending))
	}
	if noVSA > 0 {
		parts = append(parts, fmt.Sprintf("%d passed without a recorded VSA", noVSA))
	}
	return strings.Join(parts, "; ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// gateExitError is the exit decision, derived from the same predicate as the
// JSON `passed` field so the two cannot drift.
func gateExitError(g *platformGate) error {
	if g.accepted() {
		return nil
	}
	if len(g.Outcomes) == 1 {
		// The pre-multi-binding messages, unchanged for a single binding.
		o := g.Outcomes[0]
		switch {
		case o.status() == gateStatusUnevaluated:
			return fmt.Errorf("platform verification could not evaluate policy %q: %w; the gate fails closed", o.Binding.DefinitionName, errOrMissing(o))
		case o.Eval.Passed():
			// A PASSED verdict with no VSA is a degraded answer, and the gate
			// fails CLOSED on it (Codex, #8666 rounds 1 and 3). RunSync
			// deliberately preserves the verdict when the VSA upload fails, but
			// an answer nobody can independently re-verify is refused on EVERY
			// surface.
			return fmt.Errorf("the policy passed, but the platform could not record the VSA for it: " +
				"the verdict is not independently verifiable, so this gate fails closed; re-run to mint one")
		default:
			return fmt.Errorf("platform verification did not pass: status %s", o.status())
		}
	}
	st := g.status()
	if st == gateStatusUnevaluated {
		return fmt.Errorf("platform verification could not evaluate every bound policy (%s); the gate fails closed", gateSummary(g))
	}
	return fmt.Errorf("platform verification did not pass: status %s (%s)", st, gateSummary(g))
}

// renderPlatformEvaluation renders one binding's door answer to the process's
// stdout and stderr: the single-binding form of renderPlatformGate.
func renderPlatformEvaluation(vo options.VerifyOptions, eval *options.PlatformEvaluation) error {
	g := &platformGate{Outcomes: []bindingOutcome{{Eval: eval}}}
	return renderPlatformGate(vo, g, os.Stdout, os.Stderr)
}

// orNoVSA renders a missing VSA gitoid honestly rather than as an empty
// string: an upload that failed leaves the verdict standing and the gitoid
// blank, loudly, and hiding that would launder a degraded answer.
func orNoVSA(gitoid string) string {
	if gitoid == "" {
		return "(none recorded: the VSA upload failed; the verdict stands but is not independently checkable)"
	}
	return gitoid
}
