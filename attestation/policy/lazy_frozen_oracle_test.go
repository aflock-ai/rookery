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

// FROZEN EAGER ORACLE — do not "fix" this file to match policy.go.
//
// The three functions below are a VERBATIM copy of the pre-lazy verification
// engine, taken from policy.go at main@da402c396c (the #7951 streamed
// depth-guard port) and mechanically rewritten from methods into free
// functions taking the policy as a first argument. Nothing else was changed.
//
// It exists because of the M7 lesson: an oracle that calls the code under test
// MOVES WITH THE MUTATION. Running the live engine with the flag off would
// green a mutation that broke both arms at once. This copy contains no lazy
// stop, no exemption test and no demand valve, so no Phase 1 mutation can
// reach it.
//
// It calls the LIVE leaf helpers (triageOne, gateOne, validateAttestations,
// mergePassedCollections, the fan-out guard, …) on purpose: those are shared
// with the pre-change engine and are not what Phase 1 mutates. Freezing them
// too would vendor half the package.
//
// ANTI-ROT: TestFrozenOracleMatchesLiveEagerEngine asserts this copy and the
// live engine agree on every generated case with the flag OFF. If someone
// changes eager verification, that test reddens and this file must be
// re-frozen from the new policy.go — it is never the differential test that
// should be relaxed.

package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/aflock-ai/rookery/attestation/source"
)

func frozenEagerVerifyWithExternals(p Policy, ctx context.Context, opts ...VerifyOption) (bool, map[string]StepResult, map[string]ExternalResult, error) {
	vo := &verifyOptions{
		searchDepth: 3,
	}

	for _, opt := range opts {
		opt(vo)
	}

	if err := checkVerifyOpts(vo); err != nil {
		return false, nil, nil, err
	}

	if time.Now().After(p.Expires.Add(vo.clockSkewTolerance)) {
		return false, nil, nil, ErrPolicyExpired(p.Expires.Time)
	}

	// Validate the policy structure (self-references, unknown steps, cycles).
	if err := p.Validate(); err != nil {
		return false, nil, nil, err
	}

	trustBundles, err := p.TrustBundles()
	if err != nil {
		return false, nil, nil, err
	}

	// Verify external attestations BEFORE step verification so their results
	// are available when building Rego input.external for steps that
	// reference them via Step.ExternalFrom.
	//
	// Subject-graph isolation: we pass vo.subjectDigests as-is and do NOT
	// feed the externals' additional subjects back into the policy's
	// running seed set. This keeps Collection-graph semantics independent
	// from external-verification semantics (see issue #39 non-goals).
	externalResults, err := p.verifyExternalAttestations(ctx, vo, trustBundles)
	if err != nil {
		return false, nil, externalResults, err
	}

	stepResults, err := frozenEagerVerifySteps(p, ctx, vo, trustBundles, externalResults)
	if err != nil {
		return false, stepResults, externalResults, err
	}

	// A policy must affirmatively verify something to pass. A step imposes a real
	// obligation; an external attestation only counts if it was actually
	// satisfied — a Skipped (optional, unmatched) external verifies nothing.
	// A policy with no steps whose only external is Skipped therefore proves
	// nothing and must fail closed rather than pass vacuously
	// (GHSA-rgp5-33mp-jhfm). The no-steps-and-no-externals case is already
	// rejected with an error in verifySteps.
	pass := true
	verifiedSomething := len(p.Steps) > 0
	for _, result := range stepResults {
		if !result.Analyze() {
			pass = false
		}
	}
	for _, er := range externalResults {
		if !er.Analyze() {
			pass = false
		}
		if !er.Skipped {
			verifiedSomething = true
		}
	}
	if !verifiedSomething {
		pass = false
	}

	return pass, stepResults, externalResults, nil
}

// the pre-lazy verifySteps (see this file's header), so dupl correctly reports
// it as a clone of policy.go. De-duplicating it — by calling the live function,
// or by factoring out a shared helper — would destroy the one property that
// makes it an oracle: that no mutation to the live engine can move it.
//
//nolint:dupl // THE DUPLICATION IS THE POINT. This is a verbatim frozen copy of
func frozenEagerVerifySteps(p Policy, ctx context.Context, vo *verifyOptions, trustBundles map[string]TrustBundle, externalResults map[string]ExternalResult) (map[string]StepResult, error) {
	// Validate that all artifactsFrom references point to steps defined in the policy.
	// This catches configuration errors early rather than producing confusing
	// "failed to verify artifacts" errors during the artifact comparison phase.
	for stepName, step := range p.Steps {
		for _, ref := range step.ArtifactsFrom {
			if _, ok := p.Steps[ref]; !ok {
				return nil, fmt.Errorf("step %q references unknown step %q in artifactsFrom", stepName, ref)
			}
		}
	}

	attestationsByStep := make(map[string][]string)
	for name, step := range p.Steps {
		for _, attestation := range step.Attestations {
			attestationsByStep[name] = append(attestationsByStep[name], attestation.Type)
		}
	}

	// Compute topological order so that steps are verified after their
	// AttestationsFrom dependencies, enabling cross-step context.
	stepOrder, err := p.topologicalSort()
	if err != nil {
		return nil, err
	}

	resultsByStep := make(map[string]StepResult)
	// Track all known subject digests to prevent duplicates across depth
	// iterations. Without de-duplication, the search set can grow
	// exponentially as back-references are re-discovered each iteration.
	knownDigests := make(map[string]struct{})
	for _, d := range vo.subjectDigests {
		knownDigests[d] = struct{}{}
	}

	for depth := 0; depth < vo.searchDepth; depth++ {
		// Collect back-reference digests discovered during this depth
		// iteration. They will be added to the search set for the NEXT
		// depth iteration, not the current one, to prevent a single
		// collection from widening the scope of its own depth.
		var nextDepthDigests []string

		for _, stepName := range stepOrder {
			step := p.Steps[stepName]

			// Build cross-step context from already-verified dependencies
			// AND external-attestation context (input.external.<name>) from
			// this step's ExternalFrom list. When either AttestationsFrom or
			// ExternalFrom is non-empty, Rego input is wrapped; otherwise
			// input is the raw attestor JSON (backward compat). Built BEFORE
			// the search: its inputs (resultsByStep + externalResults) cannot
			// change while this step's candidates are fetched.
			stepCtx := buildStepRegoContext(step, resultsByStep, externalResults)

			var stepResult StepResult
			//nolint:nestif // the streamed-vs-batch dispatch is two parallel arms by design; hoisting either arm would separate it from the fallback it must stay verdict-identical to
			if streamer, ok := vo.verifiedSource.(source.StreamingVerifiedSourcer); ok {
				// INTERLEAVED path (#7572): consume candidates one at a time —
				// verify, triage, gate, compact — so at most one decoded
				// envelope body is in flight per turn, instead of
				// materializing the full matching set before evaluation.
				streamed, candidates, serr := frozenEagerVerifyStepStreamed(p, ctx, streamer, step, vo, trustBundles, stepCtx, attestationsByStep[stepName])
				if serr != nil {
					return nil, serr
				}
				stepResult = streamed
				if candidates == 0 {
					// Same empty-result diagnosis as the batch path below,
					// under the same once-per-verify depth guard (#7572) —
					// see diagnoseEmptyResultOnce. A nil diag means "already
					// adjudicated at an earlier depth"; nothing is appended
					// and nothing else in this iteration has work to do,
					// since a zero-candidate stream leaves stepResult with no
					// Passed and no Rejected entries to merge or expand from.
					if diag := diagnoseEmptyResultOnce(ctx, vo.verifiedSource, stepName, resultsByStep[stepName], vo.subjectDigests, attestationsByStep[stepName]); diag != nil {
						placeholder := source.CollectionVerificationResult{Errors: []error{diag}}
						if _, rejected := step.triageOne(placeholder, trustBundles); rejected != nil {
							stepResult.Rejected = append(stepResult.Rejected, *rejected)
						}
					}
				}
			} else {
				// Use search to get all the attestations that match the supplied step name and subjects
				collections, err := vo.verifiedSource.Search(ctx, stepName, vo.subjectDigests, attestationsByStep[stepName])
				if err != nil {
					return nil, err
				}

				if len(collections) == 0 {
					// Distinguish "no envelope loaded for this step" from
					// "envelope IS loaded but operator's artifact digest
					// isn't a subject of it." Without this the operator
					// chases a phantom 'did I load my attestation?' issue
					// when the real problem is digest mismatch / scoping.
					// (Fixes blind Linux UX test Bug 2.)
					//
					// A nil diag means the step was already adjudicated at an
					// earlier depth, so this empty result carries no new
					// information — see diagnoseEmptyResultOnce (#7572).
					// Nothing below can act on an empty collection set, so
					// skip the rest of the iteration.
					diag := diagnoseEmptyResultOnce(ctx, vo.verifiedSource, stepName, resultsByStep[stepName], vo.subjectDigests, attestationsByStep[stepName])
					if diag == nil {
						continue
					}
					collections = append(collections, source.CollectionVerificationResult{Errors: []error{diag}})
				}

				// Verify the functionaries
				functionaryCheckResults := step.checkFunctionaries(collections, trustBundles)

				// Subject fan-out guard: confine this verify to the dispatch
				// subject's evidence closure — candidates connected only through
				// hub digests are dropped before the gate's attestation checks.
				// Applied to the FUNCTIONARY-AUTHORIZED set, never the raw
				// candidates: only evidence the policy authorizes for THIS step
				// may classify a digest as a hub, or a signer trusted for some
				// other step could flood a victim digest and suppress this step's
				// legitimate evidence. False-reject-only; see filterHubOnlyPassed.
				var hubRejected []RejectedCollection
				if vo.maxSubjectFanout > 0 {
					functionaryCheckResults.Passed, hubRejected = filterHubOnlyPassed(functionaryCheckResults.Passed, vo.subjectDigests, vo.maxSubjectFanout)
				}

				passedCollections := make([]source.CollectionVerificationResult, len(functionaryCheckResults.Passed))
				for i, pc := range functionaryCheckResults.Passed {
					passedCollections[i] = pc.Collection
				}

				stepResult = step.validateAttestations(passedCollections, vo.aiServerURL, stepCtx)
				stepResult.Rejected = append(stepResult.Rejected, functionaryCheckResults.Rejected...)
				// Hub-suppressed candidates are reported, never silently dropped:
				// an operator whose expected evidence was demoted as a hub sees
				// the exact digests and the limit that fired.
				stepResult.Rejected = append(stepResult.Rejected, hubRejected...)
			}

			// We perform many searches against the same step (once per depth
			// iteration), so we merge results across depths. The SAME collection
			// can be returned on multiple iterations once its subjects re-enter
			// the search set, so we de-duplicate Passed collections by content
			// key (#5746, finding F12): accumulating duplicates inflates trust
			// signals and the step_results UI with phantom passing collections.
			if result, ok := resultsByStep[stepName]; ok && result.Step != "" {
				result.Passed = mergePassedCollections(result.Passed, stepResult.Passed)
				// Rejected entries get the same cross-depth de-duplication as
				// Passed (#7572): a source without seen-envelope exclusion
				// (judge-api's EntSource) re-returns the same envelope every
				// depth, and each RejectedCollection retains the FULL parsed
				// envelope — payload bytes, statement subject tree, collection
				// attestor tree. Appending raw retained one multi-MB parse
				// tree per depth per rejection. Identity is content-based
				// (statement + reason), so distinct rejections — including the
				// same collection rejected for a different reason at a later
				// depth — are all preserved. Rejected entries never affect the
				// verdict (see searchExpansionIsMonotone).
				result.Rejected = mergeRejectedCollections(result.Rejected, stepResult.Rejected)
				resultsByStep[stepName] = result
			} else {
				resultsByStep[stepName] = stepResult
			}

			// Expand the reachable-subject set from the BackRefs of collections
			// that PASSED THE STEP GATE (stepResult.Passed), NOT merely the
			// functionary survivors (passedCollections) (#5747, finding B). A
			// collection that clears the functionary check but is REJECTED by the
			// gate (missing required attestation, failing rego, etc.) is not
			// trusted, so its signer-asserted BackRefs must not widen the search
			// — otherwise a throwaway rejected collection can make an unrelated
			// downstream collection reachable.
			for _, pc := range stepResult.Passed {
				for backRefName, digestSet := range pc.Collection.Collection.BackRefs() {
					for _, digest := range digestSet {
						// Empty-merkle-tree sentinel: shared identically by every
						// step that consumed or produced nothing, so it names no
						// particular collection and must not widen the search.
						// See isEmptyTreeHubBackRef.
						if isEmptyTreeHubBackRef(backRefName, digest) {
							continue
						}
						if _, seen := knownDigests[digest]; !seen {
							knownDigests[digest] = struct{}{}
							nextDepthDigests = append(nextDepthDigests, digest)
						}
					}
				}
			}
		}

		// Expand search scope for the next depth iteration only.
		//
		// Subject-graph isolation rule (issue #39): external-attestation
		// subjects are NOT added here. Only Collection BackRefs expand the
		// seed set. This preserves Collection-graph semantics.
		vo.subjectDigests = append(vo.subjectDigests, nextDepthDigests...)

		// Stop expanding once a further iteration cannot change the verdict.
		// Depth expansion exists to REACH evidence the seed digests do not name
		// directly; it is not an evidence-quantity requirement. Continuing past
		// the point where the answer is settled costs a full re-search of every
		// step against the accumulated digest set — on a monorepo that is
		// hundreds of envelope fetches per artifact (judge#7551).
		//
		// Case 1: no new digests were discovered, so the next iteration would
		// issue byte-identical queries. Unconditionally safe.
		if len(nextDepthDigests) == 0 {
			break
		}

		// Case 2: every step is already satisfied, and the policy shape has no
		// AttestationsFrom (the only construct that makes verification
		// arbitrarily non-monotone). Safe because the break fires ONLY on an
		// already-passing verdict, so it can never skip evidence that would
		// rescue a failing step — see searchExpansionIsMonotone for why the
		// fan-out guard's non-monotonicity does not break this.
		//
		// NOTE: a multi-step policy that is only PARTIALLY satisfied never
		// takes either break and runs the full depth walk, re-searching every
		// step — including the already-satisfied ones — on every iteration.
		// That is the dominant cost shape in practice, not attestationsFrom.
		if p.searchExpansionIsMonotone() && p.allStepsSatisfied(ctx, vo, resultsByStep) {
			break
		}
	}

	resultsByStep, err = p.verifyArtifacts(ctx, vo, resultsByStep)
	if err != nil {
		return nil, fmt.Errorf("failed to verify artifacts: %w", err)
	}

	// A policy is invalid when it declares nothing to verify — no steps AND no
	// external attestations. External-attestations-only policies (e.g. VSA-chain
	// gates) are valid after #39; they're verified in verifyExternalAttestations
	// which runs before this function returns control.
	if len(resultsByStep) == 0 && len(p.ExternalAttestations) == 0 {
		return nil, fmt.Errorf("policy has no steps or external attestations to verify")
	}

	return resultsByStep, nil
}

func frozenEagerVerifyStepStreamed(p Policy, ctx context.Context, streamer source.StreamingVerifiedSourcer, step Step, vo *verifyOptions, trustBundles map[string]TrustBundle, stepCtx map[string]interface{}, attestations []string) (StepResult, int, error) {
	_ = p
	// authorizedCandidate is the compact per-candidate state retained while
	// the stream is in flight: the gate verdict, the closure-intersection
	// digests for the final fan-out classification, and the compacted
	// rejection material a hub demotion would need (captured post-triage,
	// exactly what the batch guard's compactHubReject reads). No decoded
	// bodies and no raw envelope bytes are retained here beyond what the
	// compacted verdicts themselves carry.
	type authorizedCandidate struct {
		verdict     streamedVerdict
		pc          PassedCollection
		gateReject  RejectedCollection
		hubMaterial source.CollectionVerificationResult
		digests     map[string]struct{}
		// deferred holds the candidate awaiting its gate run (raw payload
		// kept, decoded bodies dropped) when verdict == streamedDeferredGate.
		deferred source.CollectionVerificationResult
	}

	var authorized []authorizedCandidate
	var funcRejected []RejectedCollection
	tracker := newFanoutTracker(vo.subjectDigests, vo.maxSubjectFanout)
	// AI policies make external server calls from inside the gate. With the
	// guard active, a provisional gate run on a candidate the final
	// classification later hub-rejects would be an AI request the batch path
	// never makes — so for AI-bearing steps the whole gate is deferred until
	// admission is final. Hub-rejected candidates make ZERO AI calls. The
	// cost is holding the raw payload of each not-provably-rejected
	// candidate until end of stream — bounded by ~(maxFanout+1) candidates
	// per hub digest plus the genuine closure evidence.
	deferGateForAI := tracker != nil && stepHasAiPolicies(step)
	candidates := 0

	err := streamer.SearchStream(ctx, step.Name, vo.subjectDigests, attestations, func(cvr source.CollectionVerificationResult) error {
		candidates++
		triaged, rejected := step.triageOne(cvr, trustBundles)
		if rejected != nil {
			funcRejected = append(funcRejected, *rejected)
			return nil
		}

		ac := authorizedCandidate{hubMaterial: compactRejected(triaged)}
		provablyRejected := false
		if tracker != nil {
			ac.digests, provablyRejected = tracker.add(triaged.Statement.Subject)
		}
		switch {
		case provablyRejected:
			ac.verdict = streamedHubSkip
		case deferGateForAI:
			ac.verdict = streamedDeferredGate
			ac.deferred = compactAwaitingGate(triaged)
		default:
			switch outcome, pc, rc := step.gateOne(triaged, vo.aiServerURL, stepCtx); outcome {
			case gatePassed:
				ac.verdict, ac.pc = streamedGatePassed, pc
			case gateRejected:
				ac.verdict, ac.gateReject = streamedGateRejected, rc
			case gateWrongName:
				ac.verdict = streamedWrongName
			}
		}
		authorized = append(authorized, ac)
		return nil
	})
	if err != nil {
		return StepResult{}, 0, err
	}

	// End of stream: final hub classification over the full authorized set,
	// then assembly in the batch path's entry order.
	result := StepResult{Step: step.Name}
	var hubRejected []RejectedCollection
	var hubs map[string]struct{}
	if tracker != nil {
		hubs = tracker.hubs()
	}
	for _, ac := range authorized {
		admitted := true
		var hubOnly []string
		if tracker != nil {
			admitted, hubOnly = classifyAdmission(ac.digests, hubs)
		}
		if !admitted {
			// Hub-suppressed candidates are reported, never silently
			// dropped, whichever provisional verdict they carried.
			hubRejected = append(hubRejected, RejectedCollection{
				Collection: compactHubReject(ac.hubMaterial),
				Reason:     hubRejectReason(hubOnly, vo.maxSubjectFanout),
			})
			continue
		}
		switch ac.verdict {
		case streamedGatePassed:
			result.Passed = append(result.Passed, ac.pc)
		case streamedGateRejected:
			result.Rejected = append(result.Rejected, ac.gateReject)
		case streamedWrongName:
			// Admitted but not named for this step: skipped, as in the batch
			// gate (F10).
		case streamedDeferredGate:
			// Admission is final — run the deferred gate (including its AI
			// evaluations) on the rehydrated candidate, in stream order,
			// exactly as the batch path gates its admitted set.
			full, rerr := rehydrateAwaitingGate(ac.deferred)
			if rerr != nil {
				// Fail closed: the payload decoded successfully at the
				// source, so this is unreachable for a real candidate.
				return StepResult{}, 0, rerr
			}
			switch outcome, pc, rc := step.gateOne(full, vo.aiServerURL, stepCtx); outcome {
			case gatePassed:
				result.Passed = append(result.Passed, pc)
			case gateRejected:
				result.Rejected = append(result.Rejected, rc)
			case gateWrongName:
				// Skipped, as in the batch gate (F10).
			}
		case streamedHubSkip:
			// Impossible: a provably-rejected candidate cannot be admitted by
			// the final classification (counts are monotone). Fail closed
			// rather than silently dropping a candidate whose gate never ran.
			return StepResult{}, 0, fmt.Errorf("internal: hub-skipped candidate %s admitted by final fan-out classification", ac.hubMaterial.Reference)
		}
	}
	result.Rejected = append(result.Rejected, funcRejected...)
	result.Rejected = append(result.Rejected, hubRejected...)
	return result, candidates, nil
}
