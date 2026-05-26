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

import "fmt"

// evalExecObserved evaluates a nested predicate against every observed
// exec in the trace. If any exec matches, the predicate matches and the
// matched exec is recorded in the Rule string for the audit trail.
//
// When no trace was captured (TraceMode == TraceOff or TraceUnsupported,
// or ExecTrace is empty), the predicate returns TraceUnavailable. This
// is the third state — distinct from "did not match" — so the audit
// trail records the truthful reason a post-gate detector didn't fire on
// macOS / Windows / a Linux run without --tracing.
//
// The nested predicate is evaluated against a synthetic EvalContext
// whose Argv field is set to each exec's argv. Other fields (Env, Cwd)
// are carried over unchanged from the parent context so that env_set /
// file_exists predicates can still be composed within exec_observed.
// This matches the schema validation rule that exec_observed wraps a
// pre-gate-style predicate.
func evalExecObserved(nested *Predicate, ctx *EvalContext) EvalResult {
	if nested == nil {
		return EvalResult{State: StateNoMatch, Rule: "exec_observed:empty"}
	}
	if traceIsUnavailable(ctx) {
		return EvalResult{
			State: StateTraceUnavailable,
			Rule:  fmt.Sprintf("exec_observed:trace-unavailable:%s", ctx.TraceMode),
		}
	}
	for i, ev := range ctx.ExecTrace {
		// Build a per-exec EvalContext that shadows Argv. The nested
		// predicate will see this exec's argv when it consults
		// ctx.Argv. observed-env and probe caches are shared with the
		// parent so accounting stays consistent.
		sub := *ctx
		sub.Argv = ev.Argv
		// BinaryDigests for this specific exec — argv[0] resolved to
		// the captured binary. Preserves the convention that
		// binary_digest_in looks up the program in ctx.BinaryDigests.
		if ev.BinaryDigest != "" && len(ev.Argv) > 0 {
			sub.BinaryDigests = mergeBinaryDigests(ctx.BinaryDigests, ev.Argv[0], ev.BinaryDigest)
		}
		r := Evaluate(nested, &sub)
		if r.State == StateMatch {
			return EvalResult{
				State: StateMatch,
				Rule:  fmt.Sprintf("exec_observed[%d]:%s", i, r.Rule),
			}
		}
	}
	return EvalResult{State: StateNoMatch, Rule: "exec_observed:no-exec-matched"}
}

// traceIsUnavailable reports whether the exec trace cannot answer
// exec_observed predicates. A trace is unavailable when:
//   - TraceMode is explicitly Off or Unsupported, OR
//   - the ExecTrace slice is empty regardless of mode.
//
// A non-empty trace with TraceMode == TraceLight or TraceFull is
// considered available even if the specific predicate doesn't match
// any exec — that's a legitimate "no" answer.
func traceIsUnavailable(ctx *EvalContext) bool {
	switch ctx.TraceMode {
	case TraceOff, TraceUnsupported:
		return true
	}
	return len(ctx.ExecTrace) == 0
}

// mergeBinaryDigests returns a new map containing ctx's binary digests
// plus an override for the named program. Used by evalExecObserved so
// a nested binary_digest_in predicate can resolve argv[0] for the
// specific exec being evaluated, not the cilock-level argv[0].
func mergeBinaryDigests(base map[string]string, name, digest string) map[string]string {
	out := make(map[string]string, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[name] = digest
	return out
}
