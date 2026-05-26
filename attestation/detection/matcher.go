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
	"fmt"
	"strings"
)

// Predicate-tag identifiers. Used by the matcher's dispatch table and
// the schema validator. Defined as constants so a rename in one place
// stays consistent everywhere.
const (
	tagAnyOf                  = "any_of"
	tagAllOf                  = "all_of"
	tagNot                    = "not"
	tagArgvPrefix             = "argv_prefix"
	tagArgvContains           = "argv_contains"
	tagArgvRegex              = "argv_regex"
	tagEnvSet                 = "env_set"
	tagEnvEquals              = "env_equals"
	tagFileExists             = "file_exists"
	tagFileGlob               = "file_glob"
	tagBinaryDigestIn         = "binary_digest_in"
	tagIMDSReachable          = "imds_reachable"
	tagGCPMetadataReachable   = "gcp_metadata_reachable"
	tagAzureMetadataReachable = "azure_metadata_reachable"
	tagSocketListening        = "socket_listening"
	tagExecObserved           = "exec_observed"
	tagProductGlob            = "product_glob"
	tagProductMime            = "product_mime"
	tagMaterialChanged        = "material_changed"
	tagExitCode               = "exit_code"
)

// EvalContext carries everything a leaf predicate needs to evaluate. The
// matcher passes the same context down through composers; leaves pick
// the fields they need. Fields not relevant to a given predicate are
// ignored — e.g. argv_prefix never looks at Products.
//
// All fields are read-only during evaluation. The matcher never mutates
// the context; predicates report results, not state changes.
type EvalContext struct {
	// Gate is which detection pass is running. Pre-gate forbids
	// post-gate-only predicates, enforced by the validator at YAML
	// parse time (defense in depth: the leaf evaluators also check).
	Gate Gate

	// Argv, Env, Cwd, BinaryDigests mirror PrePlan fields.
	Argv          []string
	Env           map[string]string
	Cwd           string
	BinaryDigests map[string]string

	// ExecTrace, TraceMode, Products, MaterialsDiff, ExitCode mirror
	// PostPlan fields. Empty/nil on pre-gate evaluation.
	ExecTrace     []ExecEvent
	TraceMode     TraceMode
	Products      map[string]ProductRef
	MaterialsDiff []string
	ExitCode      int

	// observedEnv, observedProbes accumulate which env keys and probe
	// names a predicate actually consulted, so the audit trail can
	// record the truthful inputs without leaking unrelated env values.
	observedEnv    map[string]bool
	observedProbes map[string]bool

	// probeCache memoizes named-probe results for the lifetime of the
	// context (typically one Plan invocation). Probes are otherwise
	// repeated for every leaf that mentions them.
	probeCache map[string]bool
}

// NewEvalContext constructs an EvalContext with internal bookkeeping
// initialized. Callers normally don't use this directly — RunPrePlan /
// RunPostPlan build the context from their input structs.
func NewEvalContext(gate Gate) *EvalContext {
	return &EvalContext{
		Gate:           gate,
		observedEnv:    make(map[string]bool),
		observedProbes: make(map[string]bool),
		probeCache:     make(map[string]bool),
	}
}

// ObservedEnvKeys returns the env var names that were read during
// evaluation. Used by the input-snapshot renderer to record only the
// keys the predicates actually consulted (privacy + audit-trail accuracy).
func (c *EvalContext) ObservedEnvKeys() []string {
	out := make([]string, 0, len(c.observedEnv))
	for k := range c.observedEnv {
		out = append(out, k)
	}
	return out
}

// ObservedProbes returns the named-probe results consulted during
// evaluation, in their cached form.
func (c *EvalContext) ObservedProbes() map[string]bool {
	out := make(map[string]bool, len(c.observedProbes))
	for k := range c.observedProbes {
		if v, ok := c.probeCache[k]; ok {
			out[k] = v
		}
	}
	return out
}

// EvalResult is the outcome of evaluating one predicate sub-tree. It
// carries the state plus a human-readable rule trace (for the
// MatchedRule field on FireDecision and for cilock explain output).
type EvalResult struct {
	State PredicateState
	// Rule is a short structural description of the predicate that
	// produced the State. Examples: "argv_prefix:docker.build",
	// "any_of[1]:file_exists:.git/HEAD". Used for audit; never parsed.
	Rule string
}

// Evaluate runs a predicate tree against ctx and returns the result.
//
// Composer semantics:
//   - any_of: matches if ANY child matches. TraceUnavailable propagates
//     only if no child matched AND at least one was trace-unavailable.
//   - all_of: matches if ALL children matched. If any child is
//     TraceUnavailable and none returned NoMatch, the result is
//     TraceUnavailable (we cannot confirm all-of without all answers).
//   - not: matches if child did not match. TraceUnavailable on the
//     child propagates as TraceUnavailable on the parent — we cannot
//     negate an unknown.
//
// These rules mirror three-valued (Kleene) logic and keep the audit
// trail honest about which decisions hinged on unavailable trace data.
//
// Complexity is inherent to dispatching over the fixed predicate
// vocabulary; an abstraction layer here would obscure more than help.
//
//nolint:gocyclo
func Evaluate(p *Predicate, ctx *EvalContext) EvalResult {
	if p == nil {
		return EvalResult{State: StateNoMatch, Rule: "<nil>"}
	}
	tags := predicateTags(p)
	if len(tags) != 1 {
		return EvalResult{State: StateNoMatch, Rule: fmt.Sprintf("invalid:%d-tags", len(tags))}
	}
	switch tags[0] {
	case tagAnyOf:
		return evalAnyOf(p.AnyOf, ctx)
	case tagAllOf:
		return evalAllOf(p.AllOf, ctx)
	case tagNot:
		return evalNot(p.Not, ctx)
	case tagArgvPrefix:
		return evalArgvPrefix(p.ArgvPrefix, ctx)
	case tagArgvContains:
		return evalArgvContains(p.ArgvContains, ctx)
	case tagArgvRegex:
		return evalArgvRegex(p.ArgvRegex, ctx)
	case tagEnvSet:
		return evalEnvSet(p.EnvSet, ctx)
	case tagEnvEquals:
		return evalEnvEquals(p.EnvEquals, ctx)
	case tagFileExists:
		return evalFileExists(p.FileExists, ctx)
	case tagFileGlob:
		return evalFileGlob(p.FileGlob, ctx)
	case tagBinaryDigestIn:
		return evalBinaryDigestIn(p.BinaryDigestIn, ctx)
	case tagIMDSReachable:
		return evalIMDSReachable(*p.IMDSReachable, ctx)
	case tagGCPMetadataReachable:
		return evalGCPMetadataReachable(*p.GCPMetadataReachable, ctx)
	case tagAzureMetadataReachable:
		return evalAzureMetadataReachable(*p.AzureMetadataReachable, ctx)
	case tagSocketListening:
		return evalSocketListening(*p.SocketListening, ctx)
	case tagExecObserved:
		return evalExecObserved(p.ExecObserved, ctx)
	case tagProductGlob:
		return evalProductGlob(p.ProductGlob, ctx)
	case tagProductMime:
		return evalProductMime(p.ProductMime, ctx)
	case tagMaterialChanged:
		return evalMaterialChanged(p.MaterialChanged, ctx)
	case tagExitCode:
		return evalExitCode(p.ExitCode, ctx)
	}
	return EvalResult{State: StateNoMatch, Rule: "unknown:" + tags[0]}
}

func evalAnyOf(preds []Predicate, ctx *EvalContext) EvalResult {
	sawUnavailable := false
	matchedRule := ""
	for i := range preds {
		r := Evaluate(&preds[i], ctx)
		switch r.State {
		case StateMatch:
			return EvalResult{State: StateMatch, Rule: fmt.Sprintf("any_of[%d]:%s", i, r.Rule)}
		case StateTraceUnavailable:
			sawUnavailable = true
			if matchedRule == "" {
				matchedRule = r.Rule
			}
		}
	}
	if sawUnavailable {
		return EvalResult{State: StateTraceUnavailable, Rule: "any_of:trace-unavailable:" + matchedRule}
	}
	return EvalResult{State: StateNoMatch, Rule: "any_of:no-match"}
}

func evalAllOf(preds []Predicate, ctx *EvalContext) EvalResult {
	sawUnavailable := false
	for i := range preds {
		r := Evaluate(&preds[i], ctx)
		switch r.State {
		case StateNoMatch:
			return EvalResult{State: StateNoMatch, Rule: fmt.Sprintf("all_of[%d]:no-match:%s", i, r.Rule)}
		case StateTraceUnavailable:
			sawUnavailable = true
		}
	}
	if sawUnavailable {
		return EvalResult{State: StateTraceUnavailable, Rule: "all_of:trace-unavailable"}
	}
	return EvalResult{State: StateMatch, Rule: "all_of:match"}
}

func evalNot(p *Predicate, ctx *EvalContext) EvalResult {
	r := Evaluate(p, ctx)
	switch r.State {
	case StateMatch:
		return EvalResult{State: StateNoMatch, Rule: "not:" + r.Rule}
	case StateNoMatch:
		return EvalResult{State: StateMatch, Rule: "not:" + r.Rule}
	case StateTraceUnavailable:
		// Cannot negate an unknown.
		return EvalResult{State: StateTraceUnavailable, Rule: "not:trace-unavailable"}
	}
	return r
}

// joinArgv joins argv with single-space separators for substring matching.
// Quoting is intentionally not applied: this is matching, not shelling
// out. Plugin authors who need quoting use argv_regex.
func joinArgv(argv []string) string {
	return strings.Join(argv, " ")
}
