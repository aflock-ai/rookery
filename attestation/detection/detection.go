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

// Package detection plans which attestors should fire for a cilock run.
//
// Detection runs at two gates in the lifecycle:
//
//   - Pre-gate: before the command executes. Inputs are static — argv, env,
//     filesystem, named probes, target binary digest. Decides which
//     PreMaterial/Material attestors fire.
//   - Post-gate: after the command executes. Inputs are the optional exec
//     trace, products, materials diff, and exit code. Decides which
//     Product/PostProduct attestors actually run via the ConditionalAttestor
//     interface.
//
// The package is platform-agnostic. Predicates that require an eBPF trace
// (exec_observed) evaluate to TraceUnavailable on platforms without tracing
// (macOS, Windows, or Linux without --tracing / --auto).
//
// Plugins describe their detection logic declaratively via a detector.yaml
// file embedded next to their Go code. The YAML is parsed lazily on first
// matcher use so that malformed files crash with a meaningful stack instead
// of failing at init().
package detection

// PredicateState is the three-valued result of evaluating a predicate.
// The third state — TraceUnavailable — exists because exec_observed
// predicates cannot be answered honestly when no exec trace was captured
// (macOS, Windows, or Linux without tracing). Recording the unevaluated
// state keeps the audit trail truthful.
type PredicateState int

const (
	// StateNoMatch means the predicate evaluated and the result was false.
	StateNoMatch PredicateState = iota
	// StateMatch means the predicate evaluated and the result was true.
	StateMatch
	// StateTraceUnavailable means the predicate required execution-trace
	// data that was not captured. Treated as "did not match" for the
	// purposes of firing attestors, but distinguished in the audit trail.
	StateTraceUnavailable
)

func (s PredicateState) String() string {
	switch s {
	case StateMatch:
		return "match"
	case StateNoMatch:
		return "no-match"
	case StateTraceUnavailable:
		return "trace-unavailable"
	default:
		return "unknown"
	}
}

// Matched reports whether the state should cause the predicate's parent
// rule to fire. TraceUnavailable does not match.
func (s PredicateState) Matched() bool {
	return s == StateMatch
}

// Severity classifies how a warning should be surfaced. "info" is logged
// only; "warn" prints to stderr and lands in the bundle; "error" forces a
// non-zero exit regardless of --strict.
type Severity string

const (
	SeverityInfo  Severity = "info"
	SeverityWarn  Severity = "warn"
	SeverityError Severity = "error"
)

// Gate identifies which detection pass produced a result.
type Gate string

const (
	GatePre  Gate = "pre"
	GatePost Gate = "post"
)

// PrePlan is the input to RunPrePlan. All fields except Argv are optional;
// the caller fills in what it has. RunPrePlan never mutates the input.
type PrePlan struct {
	// Argv is the command the user invoked (e.g. ["docker", "build", "."]).
	// Required. argv[0] is the program; subsequent entries are positional or
	// flag arguments in the original order.
	Argv []string

	// Env is the captured environment at cilock startup. Keys are env var
	// names. Typically populated from os.Environ() parsed into a map.
	Env map[string]string

	// Cwd is the working directory the command will run from. Used by
	// file_exists / file_glob predicates. Defaults to "." if empty.
	Cwd string

	// EnabledPlugins is the set of plugin names whose detector.yaml is
	// loaded into the detection registry. RunPrePlan only considers
	// detectors for plugins in this set. If nil, all registered detectors
	// are considered.
	EnabledPlugins []string

	// BinaryDigests carries pre-resolved digests of binaries on PATH that
	// argv[0] might resolve to. Populated by the caller when available; if
	// nil, binary_digest_in predicates evaluate to no-match.
	BinaryDigests map[string]string
}

// PostPlan is the input to RunPostPlan. It always carries the PrePlan
// result so post-gate decisions can reference what the pre-gate decided.
type PostPlan struct {
	// Pre is the result of RunPrePlan for the same run. Required.
	Pre *PlanResult

	// ExecTrace is the list of observed child execs captured during
	// execution. Empty slice means no trace was captured (the trace was
	// not enabled, or the platform does not support it). nil and empty
	// are treated identically: exec_observed predicates evaluate to
	// TraceUnavailable.
	ExecTrace []ExecEvent

	// TraceMode records which tracing tier was active so the audit trail
	// can distinguish "no trace captured because off" from "no trace
	// captured because platform unsupported".
	TraceMode TraceMode

	// Products is the map produced by the product attestor, path → digest.
	// May be nil on platforms or runs where the product attestor did not
	// participate; product_glob / product_mime then evaluate to no-match.
	Products map[string]ProductRef

	// MaterialsDiff is the set of paths whose materials changed during
	// execution (i.e. the symmetric difference between pre-execute and
	// post-execute material captures). May be nil.
	MaterialsDiff []string

	// ExitCode is the command's exit code. Defaults to zero when unset.
	ExitCode int

	// Env is the captured environment (same shape as PrePlan.Env) for
	// post-gate predicates that re-evaluate environmental predicates.
	Env map[string]string

	// Cwd is the working directory, threaded from PrePlan.
	Cwd string
}

// TraceMode mirrors the tracing tier selected by the CLI.
type TraceMode string

const (
	// TraceOff means no trace was captured. exec_observed always returns
	// TraceUnavailable.
	TraceOff TraceMode = "off"
	// TraceLight means only child argv was captured.
	TraceLight TraceMode = "light"
	// TraceFull means the full commandrun eBPF trace was captured.
	TraceFull TraceMode = "full"
	// TraceUnsupported means the platform does not support tracing
	// (macOS, Windows). Distinct from TraceOff for audit clarity.
	TraceUnsupported TraceMode = "unsupported"
)

// ExecEvent is one observed child exec from the trace. Populated by the
// caller from commandrun.ProcessInfo. The fields here are the minimum the
// matcher needs — additional process metadata stays in the trace itself.
type ExecEvent struct {
	// Argv is the command line as observed. Argv[0] is the program path
	// or basename as recorded by the kernel.
	Argv []string
	// BinaryPath is the resolved on-disk path of the program (e.g. from
	// /proc/<pid>/exe). May be empty.
	BinaryPath string
	// BinaryDigest is the SHA-256 hex digest of the binary content. May
	// be empty when not captured.
	BinaryDigest string
	// PID, PPID identify the process for audit-trail correlation.
	PID  int
	PPID int
}

// ProductRef is the minimum digest reference the matcher needs for
// product_glob / product_mime predicates. Callers populate it from the
// product attestor's Products() map. The full product type stays in the
// product package.
type ProductRef struct {
	// Path is the path of the product relative to the working dir.
	Path string
	// Digest is the SHA-256 hex digest (or empty if not captured).
	Digest string
	// Size in bytes if known; zero if not.
	Size int64
}

// PlanResult is what RunPrePlan / RunPostPlan return. It carries the
// firing decisions, the skipped attestors with reasons, and any warnings
// that were emitted.
//
// JSON keys are lowercase by deliberate API contract: LLM consumers and
// CI integrations parse this shape. Field renames are breaking changes.
type PlanResult struct {
	// Gate identifies which gate produced this result.
	Gate Gate `json:"gate"`

	// Fire is the ordered list of attestor names that matched and should
	// be enabled for this run. Order matches detector registration order
	// (deterministic but not lexicographic). Initialized to a non-nil
	// empty slice so JSON always emits [], never null.
	Fire []FireDecision `json:"fire"`

	// Skip is the list of detectors that were considered but did not
	// match, with a human-readable reason. Useful for cilock explain.
	Skip []SkipDecision `json:"skip"`

	// Warnings is the union of warnings emitted by matched detectors via
	// warn_unless or always-on warnings.
	Warnings []Warning `json:"warnings"`

	// Inputs is a redacted snapshot of the inputs that produced this
	// result, suitable for stamping into the cilock.detection.{pre,post}
	// predicate. Redaction removes env values for keys not explicitly
	// referenced by a matching predicate (privacy: env vars are sensitive
	// by default).
	Inputs InputSnapshot `json:"inputs"`
}

// FireDecision records that an attestor matched, the rule that triggered
// it, and any extra evidence the matcher attached (binary digest, matched
// product, etc.). The LLMHint comes from the detector.yaml's llm_hints
// block and is pre-written by the plugin author.
type FireDecision struct {
	Attestor    string         `json:"attestor"`
	Gate        Gate           `json:"gate"`
	MatchedRule string         `json:"matched_rule"`
	Evidence    map[string]any `json:"evidence,omitempty"`
	LLMHint     string         `json:"llm_hint,omitempty"`
}

// SkipDecision records that a detector was evaluated but did not match.
// Reason is human-readable; Cause is the optional structured cause code
// (e.g. "trace-unavailable", "no-match", "post-gate-only").
type SkipDecision struct {
	Attestor string `json:"attestor"`
	Gate     Gate   `json:"gate"`
	Cause    string `json:"cause"`
	Reason   string `json:"reason,omitempty"`
}

// Warning is an actionable message emitted by a detector when a rule
// matches but the invocation is suboptimal (e.g. docker build without
// --provenance=true) or when the detector wants to surface advice.
type Warning struct {
	Attestor         string         `json:"attestor"`
	Gate             Gate           `json:"gate"`
	Code             string         `json:"code"`
	Severity         Severity       `json:"severity"`
	Message          string         `json:"message"`
	Summary          string         `json:"summary,omitempty"`
	OriginalCommand  []string       `json:"original_command,omitempty"`
	SuggestedCommand []string       `json:"suggested_command,omitempty"`
	DiffSummary      string         `json:"diff_summary,omitempty"`
	DocAnchor        string         `json:"doc_anchor,omitempty"`
	LLMHint          string         `json:"llm_hint,omitempty"`
	Extra            map[string]any `json:"extra,omitempty"`
}

// InputSnapshot is the redacted record of inputs that drove a plan
// result, stamped into the bundle predicate for later auditability.
type InputSnapshot struct {
	Argv             []string          `json:"argv,omitempty"`
	EnvKeysObserved  []string          `json:"env_keys_observed,omitempty"`
	FSProbes         map[string]bool   `json:"fs_probes,omitempty"`
	NamedProbes      map[string]bool   `json:"named_probes,omitempty"`
	BinaryDigests    map[string]string `json:"binary_digests,omitempty"`
	TraceMode        TraceMode         `json:"trace_mode,omitempty"`
	ExecCount        int               `json:"exec_count,omitempty"`
	ProductCount     int               `json:"product_count,omitempty"`
	MaterialsChanged int               `json:"materials_changed,omitempty"`
	ExitCode         int               `json:"exit_code"`
}
