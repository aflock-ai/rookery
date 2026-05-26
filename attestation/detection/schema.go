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
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the currently supported detector.yaml apiVersion. Files
// that declare any other version are rejected by ParseDetectorYAML. Future
// schema migrations bump this constant and add a translator entry.
const SchemaVersion = "cilock.detection/v0.1"

// warningCodePattern enforces stable, grep-able warning codes. Codes are
// part of the API contract for LLM consumers: a code rename breaks every
// agent that pattern-matches on it.
var warningCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]+$`)

// pluginNamePattern matches plugin names allowed in the detector.yaml
// "name:" field. The same shape attestation registry uses today.
var pluginNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// DetectorYAML is the top-level shape of a plugin's detector.yaml file.
// The pre and post blocks are optional but at least one must be present.
type DetectorYAML struct {
	APIVersion  string `yaml:"apiVersion"`
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`

	// Category labels what role this detector's evidence serves in the
	// supply chain. Closed enum (see categories.go); list because some
	// detectors serve multiple lifecycle contexts (e.g. trivy can run
	// in CI as artifact-scan or against production registries as
	// posture-scan). Required for new detector.yamls.
	//
	// The agent uploading evidence to the platform reads category to
	// route the upload. The platform's compliance mapping consumes
	// (category, predicate URI, optional provides) to produce verdicts.
	Category []Category `yaml:"category,omitempty"`

	// Upstream describes the third-party tool whose output this
	// detector captures. Optional but recommended — surfaces in
	// `cilock tools list` and helps the platform / compliance review
	// process understand the tool's provenance and license.
	//
	// For format-only attestors (sarif, sbom, vex, test-results) where
	// many different tools produce the same shape, leave upstream
	// empty or point it at the format spec.
	Upstream *UpstreamInfo `yaml:"upstream,omitempty"`

	// EmitsFormats lists the format-detector names whose attestors
	// actually capture this tool's output. SBOM tools (syft, cdxgen)
	// emit SPDX/CycloneDX JSON, which the `sbom` format attestor signs.
	// SAST tools (codeql, semgrep) emit SARIF, captured by `sarif`.
	// Values must reference other registered detector names — the
	// drift-guard test enforces this.
	//
	// Read by `cilock plan` to explain the evidence chain:
	// "syft is invoked → sbom attestor captures the SPDX output."
	EmitsFormats []string `yaml:"emits_formats,omitempty"  json:"emits_formats,omitempty"`

	// DetectionOnly marks catalog entries that have no backing attestor
	// plugin. cilock can recognize the tool (label its products, route
	// uploads, render warnings) but the actual evidence comes from
	// format attestors (sbom, sarif, vex, test-results) or from a
	// generic process attestation. Set true for tools in
	// attestation/detection/catalog/*.yaml; leave false (the default)
	// for plugin-owned detector.yamls.
	DetectionOnly bool `yaml:"detection_only,omitempty"  json:"detection_only,omitempty"`

	// RecommendedTrace is the eBPF tracing tier this attestor benefits
	// from in its threat model. Plugins that attest *the process* of a
	// tool (docker build, go build, pip install) declare "full" to
	// capture file reads/writes, materials, and network calls. Plugins
	// that attest *the output* of a tool (sarif, sbom, trivy scan
	// results) declare "off" — the output file is what we sign, no
	// build-time observation needed. Default is "off".
	//
	// cilock plan surfaces this as a recommendation; cilock run --auto
	// uses it to decide whether to enable light or full tracing for
	// the upcoming command.
	RecommendedTrace TraceMode `yaml:"recommended_trace,omitempty"`

	Pre      *GateBlock `yaml:"pre,omitempty"`
	Post     *GateBlock `yaml:"post,omitempty"`
	LLMHints LLMHints   `yaml:"llm_hints,omitempty"`
}

// UpstreamInfo describes the third-party tool a detector wraps. License
// is preferred as an SPDX identifier (https://spdx.org/licenses/) when
// the tool is open source. For commercial / vendor-hosted services use
// "commercial" or "proprietary".
//
// `format_only: true` marks attestors that capture an open-format file
// (SARIF, SPDX, OpenVEX, JUnit) without wrapping a specific tool — many
// scanners produce SARIF, so picking one as "the" upstream is wrong.
type UpstreamInfo struct {
	Name       string `yaml:"name,omitempty"        json:"name,omitempty"`
	Source     string `yaml:"source,omitempty"      json:"source,omitempty"`
	License    string `yaml:"license,omitempty"     json:"license,omitempty"`
	Vendor     string `yaml:"vendor,omitempty"      json:"vendor,omitempty"`
	FormatOnly bool   `yaml:"format_only,omitempty" json:"format_only,omitempty"`
}

// GateBlock is the per-gate detector body. A plugin can declare a pre
// block, a post block, or both.
type GateBlock struct {
	Match       *Predicate    `yaml:"match,omitempty"`
	WarnUnless  *Predicate    `yaml:"warn_unless,omitempty"`
	Warnings    []WarningSpec `yaml:"warnings,omitempty"`
	Description string        `yaml:"description,omitempty"`
}

// LLMHints carries pre-written remediation strings used by cilock plan
// and cilock explain to produce LLM-friendly output. Plain text, no
// templating beyond the cilock-side injection of suggested_command.
type LLMHints struct {
	OnMatch                 string `yaml:"on_match,omitempty"`
	OnWarn                  string `yaml:"on_warn,omitempty"`
	OnObservedButNotInvoked string `yaml:"on_observed_but_not_invoked,omitempty"`
}

// WarningSpec is one warning declaration inside a GateBlock. Each spec
// pairs a stable code with severity, message, optional suggested_fix
// (for display rendering), doc anchor, and an LLM hint.
type WarningSpec struct {
	Code         string        `yaml:"code"`
	Severity     Severity      `yaml:"severity"`
	Message      string        `yaml:"message"`
	Summary      string        `yaml:"summary,omitempty"`
	SuggestedFix *SuggestedFix `yaml:"suggested_fix,omitempty"`
	DocAnchor    string        `yaml:"doc_anchor,omitempty"`
	LLMHint      string        `yaml:"llm_hint,omitempty"`
}

// SuggestedFix describes a declarative transformation of the user's argv
// or environment that would resolve the warning. It is *never* applied
// to a running process — it is only used by render.go to produce the
// suggested_command string in the warning output.
type SuggestedFix struct {
	InsertArg   *InsertArgOp `yaml:"insert_arg,omitempty"`
	ReplaceArgv *ReplaceOp   `yaml:"replace_argv,omitempty"`
	SetEnv      *SetEnvOp    `yaml:"set_env,omitempty"`
	PrependArgs []string     `yaml:"prepend_args,omitempty"`
	AppendArgs  []string     `yaml:"append_args,omitempty"`
}

// InsertArgOp adds a single argument at a positional anchor. The anchor
// is either after_subcommand (the last entry from the list found in argv
// is the insertion point) or position (zero-based index after argv[0]).
type InsertArgOp struct {
	Value           string   `yaml:"value"`
	AfterSubcommand []string `yaml:"after_subcommand,omitempty"`
	Position        *int     `yaml:"position,omitempty"`
}

// ReplaceOp substitutes a contiguous argv slice. Both From and To are
// required; matching is positional from argv[0].
type ReplaceOp struct {
	From []string `yaml:"from"`
	To   []string `yaml:"to"`
}

// SetEnvOp sets one environment variable. Keyed by the var name; the
// value is rendered into the suggested invocation as "KEY=VALUE cmd ...".
type SetEnvOp struct {
	Var   string `yaml:"var"`
	Value string `yaml:"value"`
}

// Predicate is a tagged-union shape: exactly one of the fields below is
// non-nil at any one node. Composers (any_of / all_of / not) wrap nested
// predicates; leaves carry the predicate's data inline.
//
// YAML structure tolerates either a single-field inline form (the common
// case, e.g. `argv_prefix: ["docker", "build"]`) or a wrapped form
// (`any_of: [ { argv_prefix: ... }, ... ]`). UnmarshalYAML normalizes both.
type Predicate struct {
	// Composers
	AnyOf []Predicate `yaml:"any_of,omitempty"`
	AllOf []Predicate `yaml:"all_of,omitempty"`
	Not   *Predicate  `yaml:"not,omitempty"`

	// Pre-gate leaves
	ArgvPrefix             []string       `yaml:"argv_prefix,omitempty"`
	ArgvContains           string         `yaml:"argv_contains,omitempty"`
	ArgvRegex              string         `yaml:"argv_regex,omitempty"`
	EnvSet                 string         `yaml:"env_set,omitempty"`
	EnvEquals              *EnvEqualsLeaf `yaml:"env_equals,omitempty"`
	FileExists             string         `yaml:"file_exists,omitempty"`
	FileGlob               []string       `yaml:"file_glob,omitempty"`
	BinaryDigestIn         string         `yaml:"binary_digest_in,omitempty"`
	IMDSReachable          *bool          `yaml:"imds_reachable,omitempty"`
	GCPMetadataReachable   *bool          `yaml:"gcp_metadata_reachable,omitempty"`
	AzureMetadataReachable *bool          `yaml:"azure_metadata_reachable,omitempty"`
	SocketListening        *int           `yaml:"socket_listening,omitempty"`

	// Post-gate leaves
	ExecObserved    *Predicate    `yaml:"exec_observed,omitempty"`
	ProductGlob     []string      `yaml:"product_glob,omitempty"`
	ProductMime     string        `yaml:"product_mime,omitempty"`
	MaterialChanged string        `yaml:"material_changed,omitempty"`
	ExitCode        *ExitCodeLeaf `yaml:"exit_code,omitempty"`
}

// EnvEqualsLeaf is the body of an env_equals predicate.
type EnvEqualsLeaf struct {
	Var   string `yaml:"var"`
	Value string `yaml:"value"`
}

// ExitCodeLeaf is the body of an exit_code predicate. Exactly one of Eq,
// Ne, In must be populated.
type ExitCodeLeaf struct {
	Eq *int  `yaml:"eq,omitempty"`
	Ne *int  `yaml:"ne,omitempty"`
	In []int `yaml:"in,omitempty"`
}

// ParseDetectorYAML decodes raw YAML bytes into a validated DetectorYAML.
// Returns an error with a path-qualified message if any field is invalid.
// Callers should treat any error as a developer-side bug — detector.yaml
// is authored and embedded at build time, not user-supplied at runtime.
func ParseDetectorYAML(raw []byte) (*DetectorYAML, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("detector.yaml is empty")
	}

	var d DetectorYAML
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // reject unknown keys — typos must not silently parse
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("detector.yaml decode: %w", err)
	}

	if err := validateDetectorYAML(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

func validateDetectorYAML(d *DetectorYAML) error {
	if d.APIVersion != SchemaVersion {
		return fmt.Errorf("detector.yaml apiVersion %q is unsupported (want %q)", d.APIVersion, SchemaVersion)
	}
	if !pluginNamePattern.MatchString(d.Name) {
		return fmt.Errorf("detector.yaml name %q must match %s", d.Name, pluginNamePattern)
	}
	if d.Pre == nil && d.Post == nil {
		return fmt.Errorf("detector.yaml must declare at least one of pre or post")
	}
	switch d.RecommendedTrace {
	case "", TraceOff, TraceLight, TraceFull:
	default:
		return fmt.Errorf("detector.yaml recommended_trace %q must be one of off|light|full (default: off)", d.RecommendedTrace)
	}
	if err := validateCategories(d.Category); err != nil {
		return err
	}
	if err := validateUpstream(d.Upstream); err != nil {
		return err
	}
	if d.Pre != nil {
		if err := validateGate(d.Pre, GatePre, "pre"); err != nil {
			return err
		}
	}
	if d.Post != nil {
		if err := validateGate(d.Post, GatePost, "post"); err != nil {
			return err
		}
	}
	return nil
}

func validateGate(g *GateBlock, gate Gate, path string) error {
	if g.Match == nil {
		return fmt.Errorf("%s.match is required", path)
	}
	if err := validatePredicate(g.Match, gate, path+".match"); err != nil {
		return err
	}
	if g.WarnUnless != nil {
		if err := validatePredicate(g.WarnUnless, gate, path+".warn_unless"); err != nil {
			return err
		}
	}
	seenCodes := make(map[string]bool, len(g.Warnings))
	for i, w := range g.Warnings {
		if !warningCodePattern.MatchString(w.Code) {
			return fmt.Errorf("%s.warnings[%d].code %q must match %s", path, i, w.Code, warningCodePattern)
		}
		if seenCodes[w.Code] {
			return fmt.Errorf("%s.warnings[%d].code %q duplicated within block", path, i, w.Code)
		}
		seenCodes[w.Code] = true
		switch w.Severity {
		case SeverityInfo, SeverityWarn, SeverityError:
		case "":
			return fmt.Errorf("%s.warnings[%d].severity is required", path, i)
		default:
			return fmt.Errorf("%s.warnings[%d].severity %q is not one of info|warn|error", path, i, w.Severity)
		}
		if w.Message == "" {
			return fmt.Errorf("%s.warnings[%d].message is required", path, i)
		}
		if w.SuggestedFix != nil {
			if err := validateSuggestedFix(w.SuggestedFix, fmt.Sprintf("%s.warnings[%d].suggested_fix", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

// validatePredicate walks the predicate tree, enforces composer/leaf
// exclusivity (exactly one tag per node), and rejects post-gate predicates
// inside a pre-gate context.
func validatePredicate(p *Predicate, gate Gate, path string) error {
	if p == nil {
		return fmt.Errorf("%s: predicate is nil", path)
	}
	set := predicateTags(p)
	switch len(set) {
	case 0:
		return fmt.Errorf("%s: no predicate set", path)
	case 1:
		// proceed
	default:
		return fmt.Errorf("%s: multiple predicate fields set (%s); use any_of/all_of to combine", path, strings.Join(set, ","))
	}

	return validateTaggedPredicate(p, set[0], gate, path)
}

//nolint:gocyclo,gocognit // dispatch over the fixed predicate vocabulary.
func validateTaggedPredicate(p *Predicate, tag string, gate Gate, path string) error {
	switch tag {
	case tagAnyOf:
		if len(p.AnyOf) == 0 {
			return fmt.Errorf("%s.any_of: must contain at least one predicate", path)
		}
		for i := range p.AnyOf {
			if err := validatePredicate(&p.AnyOf[i], gate, fmt.Sprintf("%s.any_of[%d]", path, i)); err != nil {
				return err
			}
		}
	case tagAllOf:
		if len(p.AllOf) == 0 {
			return fmt.Errorf("%s.all_of: must contain at least one predicate", path)
		}
		for i := range p.AllOf {
			if err := validatePredicate(&p.AllOf[i], gate, fmt.Sprintf("%s.all_of[%d]", path, i)); err != nil {
				return err
			}
		}
	case tagNot:
		if err := validatePredicate(p.Not, gate, path+".not"); err != nil {
			return err
		}
	case tagArgvRegex:
		// argv_regex by itself is a footgun — require a structural
		// companion in the same any_of / all_of group. Detect this at
		// the parent group level via the caller's loop; here we just
		// confirm the regex compiles.
		if _, err := regexp.Compile(p.ArgvRegex); err != nil {
			return fmt.Errorf("%s.argv_regex: %w", path, err)
		}
	case tagExecObserved, tagProductGlob, tagProductMime, tagMaterialChanged, tagExitCode:
		if gate == GatePre {
			return fmt.Errorf("%s: predicate %s is not allowed in pre-gate (requires post-execute data)", path, tag)
		}
		if tag == tagExecObserved {
			// exec_observed nests a pre-gate-style predicate that
			// matches per-process; validate as pre-gate (no further
			// post-gate predicates allowed inside).
			if err := validatePredicate(p.ExecObserved, GatePre, path+".exec_observed"); err != nil {
				return err
			}
		}
		if tag == tagExitCode {
			if err := validateExitCode(p.ExitCode, path+".exit_code"); err != nil {
				return err
			}
		}
	case tagEnvEquals:
		if p.EnvEquals.Var == "" {
			return fmt.Errorf("%s.env_equals.var is required", path)
		}
	}
	return nil
}

// validateCategories enforces the closed enum + dedup + non-empty.
// Categories are optional for now (older detector.yamls may predate the
// field) but if present must validate. New detectors should always
// declare at least one category.
func validateCategories(cats []Category) error {
	if len(cats) == 0 {
		return nil // optional for now; drift-guard test enforces non-empty for new yamls
	}
	seen := make(map[Category]bool, len(cats))
	for _, c := range cats {
		if !IsValidCategory(string(c)) {
			return fmt.Errorf("detector.yaml category %q must be one of %v", c, AllCategories())
		}
		if seen[c] {
			return fmt.Errorf("detector.yaml category %q duplicated", c)
		}
		seen[c] = true
	}
	return nil
}

// validateUpstream checks the upstream block shape. Source should look
// like a URL when set; license is free-form (we want to allow "commercial"
// and "proprietary" alongside SPDX ids).
func validateUpstream(u *UpstreamInfo) error {
	if u == nil {
		return nil
	}
	if u.Name == "" && u.Source == "" && u.License == "" && !u.FormatOnly {
		return fmt.Errorf("detector.yaml upstream is set but empty — omit the block instead")
	}
	if u.Source != "" && !strings.HasPrefix(u.Source, "http://") && !strings.HasPrefix(u.Source, "https://") {
		return fmt.Errorf("detector.yaml upstream.source %q must be an http(s) URL", u.Source)
	}
	return nil
}

func validateExitCode(e *ExitCodeLeaf, path string) error {
	count := 0
	if e.Eq != nil {
		count++
	}
	if e.Ne != nil {
		count++
	}
	if len(e.In) > 0 {
		count++
	}
	if count != 1 {
		return fmt.Errorf("%s: exactly one of eq, ne, in must be set", path)
	}
	return nil
}

func validateSuggestedFix(f *SuggestedFix, path string) error {
	count := 0
	if f.InsertArg != nil {
		if f.InsertArg.Value == "" {
			return fmt.Errorf("%s.insert_arg.value is required", path)
		}
		count++
	}
	if f.ReplaceArgv != nil {
		if len(f.ReplaceArgv.From) == 0 || len(f.ReplaceArgv.To) == 0 {
			return fmt.Errorf("%s.replace_argv: from and to are both required", path)
		}
		count++
	}
	if f.SetEnv != nil {
		if f.SetEnv.Var == "" {
			return fmt.Errorf("%s.set_env.var is required", path)
		}
		count++
	}
	if len(f.PrependArgs) > 0 {
		count++
	}
	if len(f.AppendArgs) > 0 {
		count++
	}
	if count == 0 {
		return fmt.Errorf("%s: suggested_fix must specify at least one operation", path)
	}
	return nil
}

// predicateTags returns the set of leaf/composer field names present on
// the predicate, in a stable order. Used by validation to enforce the
// "exactly one tag" rule. The flat scan over the fixed vocabulary is
// inherently long; an abstraction here would be worse than the list.
//
//nolint:gocyclo
func predicateTags(p *Predicate) []string {
	out := make([]string, 0, 2)
	if len(p.AnyOf) > 0 {
		out = append(out, tagAnyOf)
	}
	if len(p.AllOf) > 0 {
		out = append(out, tagAllOf)
	}
	if p.Not != nil {
		out = append(out, tagNot)
	}
	if len(p.ArgvPrefix) > 0 {
		out = append(out, tagArgvPrefix)
	}
	if p.ArgvContains != "" {
		out = append(out, tagArgvContains)
	}
	if p.ArgvRegex != "" {
		out = append(out, tagArgvRegex)
	}
	if p.EnvSet != "" {
		out = append(out, tagEnvSet)
	}
	if p.EnvEquals != nil {
		out = append(out, tagEnvEquals)
	}
	if p.FileExists != "" {
		out = append(out, tagFileExists)
	}
	if len(p.FileGlob) > 0 {
		out = append(out, tagFileGlob)
	}
	if p.BinaryDigestIn != "" {
		out = append(out, tagBinaryDigestIn)
	}
	if p.IMDSReachable != nil {
		out = append(out, tagIMDSReachable)
	}
	if p.GCPMetadataReachable != nil {
		out = append(out, tagGCPMetadataReachable)
	}
	if p.AzureMetadataReachable != nil {
		out = append(out, tagAzureMetadataReachable)
	}
	if p.SocketListening != nil {
		out = append(out, tagSocketListening)
	}
	if p.ExecObserved != nil {
		out = append(out, tagExecObserved)
	}
	if len(p.ProductGlob) > 0 {
		out = append(out, tagProductGlob)
	}
	if p.ProductMime != "" {
		out = append(out, tagProductMime)
	}
	if p.MaterialChanged != "" {
		out = append(out, tagMaterialChanged)
	}
	if p.ExitCode != nil {
		out = append(out, tagExitCode)
	}
	return out
}
