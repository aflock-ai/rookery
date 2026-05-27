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

import (
	"sort"
)

// RunPrePlan evaluates every registered detector's pre-gate block
// against the given inputs and returns the plan result. Pure function
// modulo named probes (which have process-lifetime cache).
//
// Callers are typically cilock/cli/run.go which builds the PrePlan from
// argv, the current environment, and the working directory. Tests
// construct their own PrePlan with synthetic inputs.
//
// The returned PlanResult carries Fire / Skip / Warnings / Inputs and
// is suitable for stamping into the cilock.detection.pre/v0.1
// predicate (or, in M1 shadow mode, the JSON sidecar).
func RunPrePlan(p PrePlan) PlanResult {
	return runPlanWith(Default(), p, nil)
}

// RunPrePlanWith is the registry-injectable variant for tests.
func RunPrePlanWith(reg *Registry, p PrePlan) PlanResult {
	return runPlanWith(reg, p, nil)
}

func runPlanWith(reg *Registry, p PrePlan, postCtx *EvalContext) PlanResult {
	// Initialize the slices as non-nil so JSON marshaling emits `[]`
	// rather than `null` when nothing matches. LLM consumers depend on
	// the empty-array shape for `if len(d["warnings"]) > 0` checks.
	result := PlanResult{
		Gate:     GatePre,
		Fire:     []FireDecision{},
		Skip:     []SkipDecision{},
		Warnings: []Warning{},
		Inputs:   inputSnapshotFromPre(p),
	}

	// Build the eval context. postCtx is nil for pre-gate; non-nil
	// callers (runPostPlanWith) supply a context that already has the
	// post-gate fields populated.
	var ctx *EvalContext
	if postCtx != nil {
		ctx = postCtx
	} else {
		ctx = newPreEvalContext(p)
	}

	// Iterate detectors in stable order so the audit trail is
	// reproducible across runs with the same inputs.
	for _, name := range candidateNames(reg, p.EnabledPlugins) {
		d, _, err := reg.Lookup(name)
		if err != nil {
			result.Skip = append(result.Skip, SkipDecision{
				Attestor: name,
				Gate:     GatePre,
				Cause:    "schema-error",
				Reason:   err.Error(),
			})
			continue
		}
		if d == nil {
			continue
		}
		if d.Pre == nil {
			result.Skip = append(result.Skip, SkipDecision{
				Attestor: name,
				Gate:     GatePre,
				Cause:    "post-gate-only",
			})
			continue
		}

		r := Evaluate(d.Pre.Match, ctx)
		switch r.State {
		case StateMatch:
			result.Fire = append(result.Fire, FireDecision{
				Attestor:    name,
				Gate:        GatePre,
				MatchedRule: r.Rule,
				LLMHint:     d.LLMHints.OnMatch,
			})
			// Evaluate warnings on match.
			collectWarnings(name, GatePre, p.Argv, d, d.Pre, ctx, &result)
		case StateTraceUnavailable:
			// Pre-gate predicates can't be trace-unavailable (no exec
			// trace at pre-gate), but evalIMDSReachable returning a
			// network error doesn't get mapped to TraceUnavailable —
			// it just returns no-match. So this branch is defensive.
			result.Skip = append(result.Skip, SkipDecision{
				Attestor: name,
				Gate:     GatePre,
				Cause:    "trace-unavailable",
				Reason:   r.Rule,
			})
		default:
			result.Skip = append(result.Skip, SkipDecision{
				Attestor: name,
				Gate:     GatePre,
				Cause:    "no-match",
				Reason:   r.Rule,
			})
		}
	}

	// Finalize input snapshot with the env keys + probes that the
	// matcher actually consulted, not the full environment.
	result.Inputs.EnvKeysObserved = sortedKeys(ctx.observedEnv)
	result.Inputs.NamedProbes = ctx.ObservedProbes()
	return result
}

// collectWarnings evaluates a gate's warn_unless and emits one Warning
// per failing warn_unless. Warnings without warn_unless are always
// emitted on match (these are advisory notices a plugin wants to make
// every time it fires). Each warning's suggested_fix is rendered into
// a suggested_command via render.go.
func collectWarnings(name string, gate Gate, originalArgv []string, d *DetectorYAML, block *GateBlock, ctx *EvalContext, result *PlanResult) {
	if len(block.Warnings) == 0 {
		return
	}
	// If warn_unless is declared and it currently matches, the warning
	// is suppressed (the user is already doing the recommended thing).
	if block.WarnUnless != nil {
		r := Evaluate(block.WarnUnless, ctx)
		if r.State == StateMatch {
			return
		}
	}
	for _, w := range block.Warnings {
		warn := Warning{
			Attestor:        name,
			Gate:            gate,
			Code:            w.Code,
			Severity:        w.Severity,
			Message:         w.Message,
			Summary:         w.Summary,
			OriginalCommand: append([]string{}, originalArgv...),
			DocAnchor:       w.DocAnchor,
			LLMHint:         pickLLMHint(w.LLMHint, d.LLMHints.OnWarn),
		}
		if w.SuggestedFix != nil {
			suggested, envOverride, diff := RenderSuggestedCommand(originalArgv, w.SuggestedFix)
			warn.SuggestedCommand = suggested
			warn.DiffSummary = diff
			if len(envOverride) > 0 {
				if warn.Extra == nil {
					warn.Extra = make(map[string]any, 1)
				}
				warn.Extra["env_override"] = envOverride
			}
		}
		result.Warnings = append(result.Warnings, warn)
	}
}

// pickLLMHint returns the per-warning hint if set, else falls back to
// the detector-level on_warn hint.
func pickLLMHint(perWarning, detectorFallback string) string {
	if perWarning != "" {
		return perWarning
	}
	return detectorFallback
}

// candidateNames returns the registry plugin names, optionally filtered
// to the EnabledPlugins set. If EnabledPlugins is nil/empty, all
// registered detectors are returned. The result is sorted for
// determinism.
func candidateNames(reg *Registry, allowed []string) []string {
	all := reg.Names()
	if len(allowed) == 0 {
		return all
	}
	allow := make(map[string]bool, len(allowed))
	for _, n := range allowed {
		allow[n] = true
	}
	out := make([]string, 0, len(all))
	for _, n := range all {
		if allow[n] {
			out = append(out, n)
		}
	}
	return out
}

// newPreEvalContext builds the EvalContext for a pre-gate run. The
// observed-keys / probe caches are fresh; the matcher updates them as
// it walks.
func newPreEvalContext(p PrePlan) *EvalContext {
	ctx := NewEvalContext(GatePre)
	ctx.Argv = p.Argv
	ctx.Env = p.Env
	ctx.Cwd = p.Cwd
	ctx.BinaryDigests = p.BinaryDigests
	// Pre-gate context never has trace data. Setting TraceMode to
	// "off" rather than "unsupported" because pre-gate doesn't ask
	// the question — the post-gate context decides which it is.
	ctx.TraceMode = TraceOff
	return ctx
}

func inputSnapshotFromPre(p PrePlan) InputSnapshot {
	return InputSnapshot{
		Argv:          append([]string{}, p.Argv...),
		BinaryDigests: cloneStringMap(p.BinaryDigests),
		TraceMode:     TraceOff,
	}
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
