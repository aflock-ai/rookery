// Copyright 2026 The Witness Contributors
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
	"errors"

	"github.com/aflock-ai/rookery/attestation/source"
)

// errStepSatisfied is the sentinel a step's candidate stream yields to ABORT
// itself once the step is satisfied (minimum-witness Phase 1). It never
// escapes verifyStepStreamed: the caller recognises it, swallows it, and
// treats the truncated stream as a normal end of stream.
//
// It is deliberately unexported and package-local so no source can produce it
// and no caller can mistake a real stream error for a satisfied stop.
var errStepSatisfied = errors.New("policy: step satisfied, candidate stream aborted")

// WithLazyStepSatisfaction enables WITHIN-STEP stop-at-first-pass: a step's
// candidate stream is aborted at the first collection that passes the step
// gate, instead of verifying every candidate the search matched
// (docs/design/minimum-witness-verification.md, Phase 1).
//
// DEFAULT OFF. With the option unset, every code path below behaves exactly as
// it did before the option existed — no extra searches, no extra predicate
// evaluations, no changed ordering. The option only ever REMOVES work from a
// step that has already found a passing collection.
//
// SOUNDNESS, and the three exclusions that make it hold. Stopping shrinks
// StepResult.Passed, and Passed is what every verdict component reads
// (Analyze, verifyArtifacts, allStepsSatisfied, cross-step Rego input). All of
// them are EXISTENTIAL over Passed, so a subset can only ever move a verdict in
// the PASS→FAIL direction — with three exceptions, each excluded here rather
// than argued around:
//
//  1. Step.AttestationsFrom (conservative, whole-policy). An upstream step's
//     Passed set is Rego INPUT for a downstream step, and an arbitrary Rego
//     module over that set need not be monotone: a rule asserting "exactly one
//     upstream collection" flips FAIL→PASS as the upstream set SHRINKS. That is
//     the manufacture-a-pass direction, and the demand valve cannot catch it
//     because the valve only fires when an ARTIFACT edge fails. Lazy is
//     therefore disabled for any policy whose shape contains AttestationsFrom
//     at all — the same whole-policy test searchExpansionIsMonotone already
//     applies to the depth loop's early break. Narrowing this to source steps
//     only is Phase 2 work and requires a per-shape argument about what
//     downstream Rego can observe.
//
//  2. The subject fan-out guard (WithMaxSubjectFanout). Hub classification
//     counts candidates, and counts only grow, so a TRUNCATED stream sees a
//     SMALLER hub set and admits candidates the full stream would have
//     demoted. The guard's demotions are false rejects by construction, so
//     that divergence is FAIL→PASS: the dangerous direction for a Phase 1
//     whose contract is bit-identical verdicts. Lazy is disabled whenever the
//     guard is active for a search (see verifyStepStreamed). Note this makes
//     the option inert under judge's production default
//     VERIFY_SUBJECT_FANOUT_LIMIT=32; lifting it is a policy decision (accept
//     the documented false-reject immunity) and not an engineering trick — the
//     guard fundamentally needs the whole authorized candidate set.
//
//  3. Demand (the resumption valve). A step that stopped early, in a verify
//     that is NOT globally satisfied, is re-verified EXHAUSTIVELY from the next
//     depth iteration on. See demandExhaustive in verifySteps: it covers both
//     the artifactsFrom edge that the single witness fails to satisfy AND the
//     BackRef frontier the skipped candidates would have contributed.
//
// A FAILING step is never truncated for the simple reason that it has no
// passing collection to stop at, so failing steps remain exhaustive by
// construction — which is what keeps judge's readiness classifier and
// findTrustMismatch sound (design doc §6.1).
func WithLazyStepSatisfaction(enabled bool) VerifyOption {
	return func(vo *verifyOptions) {
		vo.lazyStepSatisfaction = enabled
	}
}

// lazyWitnessEligible reports whether within-step stop-at-first-pass may be
// used at all for THIS policy, THIS source, in THIS verify. It carries the
// option itself plus two of the four exclusions; the per-search fan-out
// exclusion lives in verifyStepStreamed, next to the tracker it is about, and
// the per-step demand exclusion lives in the depth loop.
func (p Policy) lazyWitnessEligible(vo *verifyOptions) bool {
	return vo.lazyStepSatisfaction &&
		p.searchExpansionIsMonotone() &&
		sourceHasCanonicalOrder(vo.verifiedSource)
}

// sourceHasCanonicalOrder reports whether the source DECLARES that its results
// arrive in a stable, content-derived order (source.CanonicalOrderSourcer).
//
// EXCLUSION 4, and the one that protects a SIGNED ARTIFACT rather than a
// verdict. Stopping at the first passing collection makes StepResult.Passed —
// which the policyverify attestor copies verbatim into the signed VSA — a
// function of which candidate arrived first. Over an identical corpus, two
// verifies that differ only in row-delivery order would then produce two
// different signed attestations.
//
// The witness is therefore DEFINED as "the first passing collection in
// canonical stream order", and a source that will not promise canonical order
// does not get the stop. Declaring is the source's job because only the source
// knows: it owns the query, the index, and (for a remote source) whether the
// ordering is even its own decision to make.
//
// Fail-safe by default: not implementing the interface means eager
// verification, which costs performance and nothing else.
func sourceHasCanonicalOrder(s source.VerifiedSourcer) bool {
	c, ok := s.(source.CanonicalOrderSourcer)
	return ok && c.CanonicalStreamOrder()
}

// searchableDigests returns the digests reachable within maxDepth hops of the
// seeds, preserving the accumulated slice's order and its duplicates.
//
// This is the bound that makes the demand valve's replay sound. searchDepth
// limits REACHABILITY, not iterations, so a replay must be handed the same
// digest set the pass it is replaying was entitled to — never the widened set
// the previous pass left behind.
//
// In an EAGER verify the bound never removes anything: a digest discovered at
// iteration j carries depth j+1, and iteration `depth` only runs after j <
// depth, so every accumulated digest is already within reach. The equal-length
// fast path therefore returns the caller's slice untouched on every eager
// iteration — no allocation, no copy, and no behavioural difference to the
// pre-minimum-witness engine.
func searchableDigests(all []string, depths map[string]int, maxDepth int) []string {
	n := 0
	for _, d := range all {
		if depths[d] <= maxDepth {
			n++
		}
	}
	if n == len(all) {
		return all
	}
	out := make([]string, 0, n)
	for _, d := range all {
		if depths[d] <= maxDepth {
			out = append(out, d)
		}
	}
	return out
}

// countDigestsAtDepth reports how many digests first became searchable at
// exactly this logical depth — i.e. whether the next iteration would see
// anything the current one did not.
func countDigestsAtDepth(depths map[string]int, depth int) int {
	n := 0
	for _, d := range depths {
		if d == depth {
			n++
		}
	}
	return n
}

// demandValve records the steps whose lazily-truncated stream must be re-run
// exhaustively because the verify did not settle on the witness they produced.
// It is monotone: a step marked demand-exhaustive never becomes lazy again
// within the same verify, which is what bounds the depth loop's extra
// iterations at one per firing.
type demandValve struct {
	exhaustive map[string]struct{}
	// firings counts how many depth iterations ended with a NEW step marked.
	// Each one costs the loop an iteration whose searches were truncated, so
	// each one buys the loop exactly one extra iteration back (see verifySteps).
	firings int
}

func newDemandValve() *demandValve {
	return &demandValve{exhaustive: map[string]struct{}{}}
}

// lazyAllowedFor reports whether the named step may still stop at first pass.
func (d *demandValve) lazyAllowedFor(stepName string) bool {
	_, demanded := d.exhaustive[stepName]
	return !demanded
}

// demand marks every named step demand-exhaustive and reports whether that
// changed anything. A step already marked cannot have been truncated again
// (lazyAllowedFor gates that), so in practice any non-empty input is new work.
func (d *demandValve) demand(stepNames []string) bool {
	marked := false
	for _, name := range stepNames {
		if _, already := d.exhaustive[name]; already {
			continue
		}
		d.exhaustive[name] = struct{}{}
		marked = true
	}
	if marked {
		d.firings++
	}
	return marked
}
