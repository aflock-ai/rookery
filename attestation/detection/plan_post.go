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

package detection

// RunPostPlan evaluates every registered detector's post-gate block
// against the post-execute inputs (exec trace, products, materials
// diff, exit code) and returns the plan result.
//
// The PrePlan result must be supplied so the post-result can reference
// pre-gate decisions in its audit trail. The combined pre + post plan
// is what cilock stamps into the bundle as separate predicates.
func RunPostPlan(p PostPlan) PlanResult {
	return RunPostPlanWith(Default(), p)
}

// RunPostPlanWith is the registry-injectable variant for tests.
func RunPostPlanWith(reg *Registry, p PostPlan) PlanResult {
	// Non-nil slice init so JSON serializes empty as [] not null. See
	// the same comment in plan.go::runPlanWith.
	result := PlanResult{
		Gate:     GatePost,
		Fire:     []FireDecision{},
		Skip:     []SkipDecision{},
		Warnings: []Warning{},
		Inputs:   inputSnapshotFromPost(p),
	}

	ctx := newPostEvalContext(p)

	// Post-gate considers every registered plugin, regardless of which
	// plugins fired at pre-gate. A purely post-gate plugin like docker
	// has no pre-gate match and must still be visible here.
	for _, name := range candidateNames(reg, nil) {
		d, _, err := reg.Lookup(name)
		if err != nil {
			result.Skip = append(result.Skip, SkipDecision{
				Attestor: name,
				Gate:     GatePost,
				Cause:    "schema-error",
				Reason:   err.Error(),
			})
			continue
		}
		if d == nil {
			continue
		}
		if d.Post == nil {
			result.Skip = append(result.Skip, SkipDecision{
				Attestor: name,
				Gate:     GatePost,
				Cause:    "pre-gate-only",
			})
			continue
		}

		// Pre-gate context-only predicates are still valid inside the
		// post-gate match block (e.g. a plugin may want
		// `all_of: [exec_observed: ..., file_exists: Dockerfile]`).
		// The matcher's predicate dispatch handles both transparently.
		r := Evaluate(d.Post.Match, ctx)
		switch r.State {
		case StateMatch:
			result.Fire = append(result.Fire, FireDecision{
				Attestor:    name,
				Gate:        GatePost,
				MatchedRule: r.Rule,
				LLMHint:     d.LLMHints.OnMatch,
				Evidence:    postFireEvidence(ctx),
			})
			// Use the cilock argv (Pre.Inputs.Argv) for warnings'
			// original_command, not any nested exec argv — warnings
			// are about the user's invocation, not the child process.
			originalArgv := postOriginalArgv(p)
			collectWarnings(name, GatePost, originalArgv, d, d.Post, ctx, &result)
		case StateTraceUnavailable:
			result.Skip = append(result.Skip, SkipDecision{
				Attestor: name,
				Gate:     GatePost,
				Cause:    "trace-unavailable",
				Reason:   r.Rule,
			})
		default:
			result.Skip = append(result.Skip, SkipDecision{
				Attestor: name,
				Gate:     GatePost,
				Cause:    "no-match",
				Reason:   r.Rule,
			})
		}
	}

	result.Inputs.EnvKeysObserved = sortedKeys(ctx.observedEnv)
	result.Inputs.NamedProbes = ctx.ObservedProbes()
	return result
}

func newPostEvalContext(p PostPlan) *EvalContext {
	ctx := NewEvalContext(GatePost)
	ctx.Argv = postOriginalArgv(p)
	ctx.Env = p.Env
	ctx.Cwd = p.Cwd
	ctx.ExecTrace = p.ExecTrace
	ctx.TraceMode = p.TraceMode
	if ctx.TraceMode == "" {
		// Default: if no trace was supplied, mark as "off" rather than
		// empty so traceIsUnavailable behaves predictably.
		ctx.TraceMode = TraceOff
	}
	ctx.Products = p.Products
	ctx.MaterialsDiff = p.MaterialsDiff
	ctx.ExitCode = p.ExitCode
	return ctx
}

// postOriginalArgv returns the user-typed argv for warning rendering.
// It comes from the PrePlan's input snapshot, not from any child exec
// in the trace.
func postOriginalArgv(p PostPlan) []string {
	if p.Pre != nil {
		return append([]string{}, p.Pre.Inputs.Argv...)
	}
	return nil
}

// postFireEvidence collects evidence fields to attach to a FireDecision
// when a post-gate predicate matches. Records trace mode, products
// observed, and exit code so the audit trail explains why the
// detector fired.
func postFireEvidence(ctx *EvalContext) map[string]any {
	ev := make(map[string]any, 4)
	if ctx.TraceMode != "" {
		ev["trace_mode"] = string(ctx.TraceMode)
	}
	if len(ctx.ExecTrace) > 0 {
		ev["exec_count"] = len(ctx.ExecTrace)
	}
	if len(ctx.Products) > 0 {
		ev["product_count"] = len(ctx.Products)
	}
	ev["exit_code"] = ctx.ExitCode
	return ev
}

func inputSnapshotFromPost(p PostPlan) InputSnapshot {
	snap := InputSnapshot{
		TraceMode:        p.TraceMode,
		ExecCount:        len(p.ExecTrace),
		ProductCount:     len(p.Products),
		MaterialsChanged: len(p.MaterialsDiff),
		ExitCode:         p.ExitCode,
	}
	if p.Pre != nil {
		snap.Argv = append([]string{}, p.Pre.Inputs.Argv...)
		snap.BinaryDigests = cloneStringMap(p.Pre.Inputs.BinaryDigests)
	}
	return snap
}
