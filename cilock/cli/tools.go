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
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

const (
	formatJSON           = "json"
	formatText           = "text"
	noDetectorYAML       = "(no detector.yaml)"
	sourceAttestorBacked = "attestor-backed"
	attestorCommandRun   = "command-run"
)

// ToolsCmd is `cilock tools` — discoverability surface for what cilock
// detects and how to test each detector.
//
// Subcommands:
//   - `cilock tools list`       — table or JSON of every registered detector
//   - `cilock tools test-plan`  — markdown / JSON test plan, one section per detector
//
// The LLM consumer uses `cilock tools test-plan --format=json` to learn
// what argv / env / file triggers each detector, then constructs a test
// matrix or wiring it into a CI gate.
func ToolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "tools",
		Short:             "List supported detectors and emit test plans for each",
		Long:              "tools introspects the in-binary detector registry. It does not require an outfile or signer — it's purely informational.",
		DisableAutoGenTag: true,
		SilenceErrors:     true,
	}
	cmd.AddCommand(toolsListCmd())
	cmd.AddCommand(toolsShowCmd())
	cmd.AddCommand(toolsTestPlanCmd())
	return cmd
}

// defaultOnAttestor reports whether an attestor is part of the default
// binary's always-run/default set (matches cilock/cli/run.go and the
// `cilock attestors list` table): product/material/command-run always run,
// and options.DefaultAttestors (environment, git) are on by default.
func defaultOnAttestor(name string) bool {
	switch name {
	case "product", "material", attestorCommandRun:
		return true
	}
	for _, d := range options.DefaultAttestors {
		if d == name {
			return true
		}
	}
	return false
}

// toolEntry is one row in the tools list / one section in the test plan.
type toolEntry struct {
	Name             string                  `json:"name"`
	PredicateType    string                  `json:"predicate_type,omitempty"`
	RunType          string                  `json:"run_type,omitempty"` // attestor lifecycle: prematerial|material|...|postproduct
	DefaultOn        bool                    `json:"default_on"`         // part of the default binary's always-run/default set
	Description      string                  `json:"description,omitempty"`
	Categories       []detection.Category    `json:"categories,omitempty"`
	Upstream         *detection.UpstreamInfo `json:"upstream,omitempty"`
	Source           string                  `json:"source"` // attestor-backed | catalog-only
	EmitsFormats     []string                `json:"emits_formats,omitempty"`
	Gates            []string                `json:"gates"`
	RecommendedTrace detection.TraceMode     `json:"recommended_trace"`
	Triggers         []toolTrigger           `json:"triggers"`
	Warnings         []toolWarningSummary    `json:"warnings,omitempty"`
	LLMHints         map[string]string       `json:"llm_hints,omitempty"`
}

type toolTrigger struct {
	Gate string `json:"gate"` // pre | post
	Kind string `json:"kind"` // argv_prefix | env_set | file_exists | probe | exec_observed | product_glob
	// Value is a human description of what triggers the rule.
	Value string `json:"value"`
}

type toolWarningSummary struct {
	Code             string `json:"code"`
	Severity         string `json:"severity"`
	Message          string `json:"message"`
	SuggestedExample string `json:"suggested_example,omitempty"`
}

func toolsListCmd() *cobra.Command {
	var (
		format   string
		source   string
		category string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List every detector cilock knows how to auto-fire",
		Example: `  # List every detector, as a table
  cilock tools list

  # Filter to one lexicon category, machine-readable
  cilock tools list --category vulnerability-scan --format json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries := buildToolEntries()
			if source != "" {
				entries = filterBySource(entries, source)
			}
			if category != "" {
				entries = filterByCategory(entries, category)
			}
			switch strings.ToLower(format) {
			case "", "table":
				return writeToolsTable(cmd.OutOrStdout(), entries)
			case formatJSON:
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(entries)
			default:
				return fmt.Errorf("unknown --format %q (want table|json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "table", "Output format: table (default) or json")
	cmd.Flags().StringVar(&source, "source", "", "Filter: attestor-backed | catalog-only")
	cmd.Flags().StringVar(&category, "category", "", "Filter by lexicon category (see docs/lexicon-v1.md). Examples: build, vulnerability-scan, ci-context, code-review, sbom-generate, image-build")
	return cmd
}

func filterBySource(in []toolEntry, want string) []toolEntry {
	out := make([]toolEntry, 0, len(in))
	for _, e := range in {
		src := e.Source
		if src == "" {
			src = sourceAttestorBacked
		}
		if src == want {
			out = append(out, e)
		}
	}
	return out
}

func filterByCategory(in []toolEntry, want string) []toolEntry {
	out := make([]toolEntry, 0, len(in))
	for _, e := range in {
		for _, c := range e.Categories {
			if string(c) == want {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

func toolsTestPlanCmd() *cobra.Command {
	var (
		format string
		only   string
	)
	cmd := &cobra.Command{
		Use:   "test-plan",
		Short: "Emit a per-detector test plan (markdown or JSON)",
		Long: `Generates a structured test plan describing how to validate each
detector. For each one, the plan covers what triggers it (argv, env, file,
or probe), the expected fire decision, and a negative case where the
detector should NOT fire.

LLM consumers can pipe --format=json into a test runner that exercises
each scenario against cilock plan.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			entries := buildToolEntries()
			if only != "" {
				filtered := make([]toolEntry, 0, 1)
				for _, e := range entries {
					if e.Name == only {
						filtered = append(filtered, e)
					}
				}
				entries = filtered
			}
			switch strings.ToLower(format) {
			case "", "markdown", "md":
				return writeTestPlanMarkdown(cmd.OutOrStdout(), entries)
			case formatJSON:
				plan := buildTestPlan(entries)
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(plan)
			default:
				return fmt.Errorf("unknown --format %q (want markdown|json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", "markdown", "Output format: markdown (default) or json")
	cmd.Flags().StringVar(&only, "only", "", "Limit the plan to a single detector name")
	return cmd
}

// buildToolEntries enumerates every registered attestor, looks up its
// detector.yaml in the detection registry, then adds catalog-only
// entries (tools cilock recognizes but doesn't have a Go attestor for).
//
//nolint:gocognit // sequential population of one struct per registry entry.
func buildToolEntries() []toolEntry {
	reg := detection.Default()
	out := make([]toolEntry, 0)
	seen := make(map[string]bool)

	// Pass 1: every plugin attestor known to the registry.
	for _, ent := range attestation.RegistrationEntries() {
		name := ent.Name
		seen[name] = true
		var te toolEntry
		d, _, err := reg.Lookup(name)
		if err != nil || d == nil {
			te = toolEntry{
				Name:        name,
				Source:      sourceAttestorBacked,
				Description: "(no detector.yaml; user-driven or always-on)",
			}
		} else {
			te = makeToolEntry(name, d, sourceAttestorBacked)
		}
		// Enrich from the attestor factory so `tools show --format json`
		// is self-sufficient (predicate type + lifecycle + default-on),
		// and the website doesn't need a second data source.
		f := ent.Factory()
		te.PredicateType = f.Type()
		te.RunType = fmt.Sprintf("%v", f.RunType())
		te.DefaultOn = defaultOnAttestor(name)
		out = append(out, te)
	}

	// Pass 2: detection-only catalog entries — registered via go:embed
	// in attestation/detection/catalog/. Skip anything a plugin already
	// claimed (defense-in-depth; the loader also panics on dup).
	for _, name := range reg.Names() {
		if seen[name] {
			continue
		}
		d, _, err := reg.Lookup(name)
		if err != nil || d == nil {
			continue
		}
		if !d.DetectionOnly {
			continue
		}
		out = append(out, makeToolEntry(name, d, "catalog-only"))
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func makeToolEntry(name string, d *detection.DetectorYAML, source string) toolEntry {
	entry := toolEntry{
		Name:             name,
		Source:           source,
		Description:      d.Description,
		Categories:       d.Category,
		Upstream:         d.Upstream,
		EmitsFormats:     d.EmitsFormats,
		RecommendedTrace: d.RecommendedTrace,
		LLMHints: map[string]string{
			"on_match":                    d.LLMHints.OnMatch,
			"on_warn":                     d.LLMHints.OnWarn,
			"on_observed_but_not_invoked": d.LLMHints.OnObservedButNotInvoked,
		},
	}
	if entry.RecommendedTrace == "" {
		entry.RecommendedTrace = detection.TraceOff
	}
	if d.Pre != nil {
		entry.Gates = append(entry.Gates, "pre")
		entry.Triggers = append(entry.Triggers, predicateTriggers("pre", d.Pre.Match)...)
		for _, w := range d.Pre.Warnings {
			entry.Warnings = append(entry.Warnings, summarizeWarning(name, w))
		}
	}
	if d.Post != nil {
		entry.Gates = append(entry.Gates, "post")
		entry.Triggers = append(entry.Triggers, predicateTriggers("post", d.Post.Match)...)
		for _, w := range d.Post.Warnings {
			entry.Warnings = append(entry.Warnings, summarizeWarning(name, w))
		}
	}
	for k, v := range entry.LLMHints {
		if v == "" {
			delete(entry.LLMHints, k)
		}
	}
	return entry
}

// predicateTriggers walks a predicate tree and emits one toolTrigger
// per leaf, flattening composers. Order is best-effort stable.
//
//nolint:gocyclo // tagged-union dispatch; complexity is inherent.
func predicateTriggers(gate string, p *detection.Predicate) []toolTrigger {
	if p == nil {
		return nil
	}
	out := []toolTrigger{}
	switch {
	case len(p.AnyOf) > 0:
		for i := range p.AnyOf {
			out = append(out, predicateTriggers(gate, &p.AnyOf[i])...)
		}
	case len(p.AllOf) > 0:
		for i := range p.AllOf {
			out = append(out, predicateTriggers(gate, &p.AllOf[i])...)
		}
	case p.Not != nil:
		// Negative predicates aren't surfaced as triggers (they describe
		// what *prevents* a match, not what causes one).
	case len(p.ArgvPrefix) > 0:
		out = append(out, toolTrigger{Gate: gate, Kind: "argv_prefix", Value: strings.Join(p.ArgvPrefix, " ")})
	case p.ArgvContains != "":
		out = append(out, toolTrigger{Gate: gate, Kind: "argv_contains", Value: p.ArgvContains})
	case p.ArgvRegex != "":
		out = append(out, toolTrigger{Gate: gate, Kind: "argv_regex", Value: p.ArgvRegex})
	case p.EnvSet != "":
		out = append(out, toolTrigger{Gate: gate, Kind: "env_set", Value: p.EnvSet})
	case p.EnvEquals != nil:
		out = append(out, toolTrigger{Gate: gate, Kind: "env_equals", Value: p.EnvEquals.Var + "=" + p.EnvEquals.Value})
	case p.FileExists != "":
		out = append(out, toolTrigger{Gate: gate, Kind: "file_exists", Value: p.FileExists})
	case len(p.FileGlob) > 0:
		out = append(out, toolTrigger{Gate: gate, Kind: "file_glob", Value: strings.Join(p.FileGlob, " | ")})
	case p.IMDSReachable != nil:
		out = append(out, toolTrigger{Gate: gate, Kind: "probe", Value: fmt.Sprintf("imds_reachable=%v", *p.IMDSReachable)})
	case p.GCPMetadataReachable != nil:
		out = append(out, toolTrigger{Gate: gate, Kind: "probe", Value: fmt.Sprintf("gcp_metadata_reachable=%v", *p.GCPMetadataReachable)})
	case p.AzureMetadataReachable != nil:
		out = append(out, toolTrigger{Gate: gate, Kind: "probe", Value: fmt.Sprintf("azure_metadata_reachable=%v", *p.AzureMetadataReachable)})
	case p.SocketListening != nil:
		out = append(out, toolTrigger{Gate: gate, Kind: "probe", Value: fmt.Sprintf("socket_listening=%d", *p.SocketListening)})
	case p.ExecObserved != nil:
		// exec_observed nests a pre-gate-style predicate against
		// observed child execs. Surface the nested triggers as
		// "exec_observed: <inner>".
		for _, t := range predicateTriggers(gate, p.ExecObserved) {
			out = append(out, toolTrigger{Gate: gate, Kind: "exec_observed_" + t.Kind, Value: t.Value})
		}
	case len(p.ProductGlob) > 0:
		out = append(out, toolTrigger{Gate: gate, Kind: "product_glob", Value: strings.Join(p.ProductGlob, " | ")})
	case p.ProductMime != "":
		out = append(out, toolTrigger{Gate: gate, Kind: "product_mime", Value: p.ProductMime})
	case p.MaterialChanged != "":
		out = append(out, toolTrigger{Gate: gate, Kind: "material_changed", Value: p.MaterialChanged})
	case p.ExitCode != nil:
		out = append(out, toolTrigger{Gate: gate, Kind: "exit_code", Value: "(see detector.yaml)"})
	}
	return out
}

func summarizeWarning(plugin string, w detection.WarningSpec) toolWarningSummary {
	out := toolWarningSummary{
		Code:     w.Code,
		Severity: string(w.Severity),
		Message:  w.Message,
	}
	// Render a suggested_command example by applying the suggested_fix
	// to a placeholder argv. Helps the LLM see what the fix looks like.
	if w.SuggestedFix != nil {
		placeholder := []string{plugin, "<args>"}
		fixed, env, _ := detection.RenderSuggestedCommand(placeholder, w.SuggestedFix)
		out.SuggestedExample = detection.FormatSuggestedCommand(fixed, env)
	}
	return out
}

// writeToolsTable emits a compact table. JSON has the full detail;
// the table is for at-a-glance grepping in the terminal.
func writeToolsTable(w interface{ Write([]byte) (int, error) }, entries []toolEntry) error {
	var b strings.Builder
	// Header: count summary and per-source breakdown.
	attBacked, catOnly := 0, 0
	for _, e := range entries {
		switch e.Source {
		case "catalog-only":
			catOnly++
		default:
			attBacked++
		}
	}
	fmt.Fprintf(&b, "%d tools known (%d attestor-backed, %d catalog-only).\n\n", len(entries), attBacked, catOnly)
	fmt.Fprintf(&b, "  %-22s  %-15s  %-26s  %-12s  %s\n", "NAME", "SOURCE", "CATEGORY", "LICENSE", "UPSTREAM")
	fmt.Fprintf(&b, "  %-22s  %-15s  %-26s  %-12s  %s\n", "----", "------", "--------", "-------", "--------")
	for _, e := range entries {
		cats := joinCategories(e.Categories)
		if cats == "" {
			cats = noDetectorYAML
		}
		if len(cats) > 26 {
			cats = cats[:23] + "..."
		}
		lic, upName := upstreamSummary(e.Upstream)
		if len(lic) > 12 {
			lic = lic[:9] + "..."
		}
		if len(upName) > 40 {
			upName = upName[:37] + "..."
		}
		src := e.Source
		if src == "" {
			src = sourceAttestorBacked
		}
		fmt.Fprintf(&b, "  %-22s  %-15s  %-26s  %-12s  %s\n", e.Name, src, cats, lic, upName)
	}
	_, err := w.Write([]byte(b.String()))
	return err
}

// upstreamSummary picks the license + display-name fields out of an
// UpstreamInfo for the tools-table row, with sensible defaults when
// any field is missing.
func upstreamSummary(u *detection.UpstreamInfo) (license, name string) {
	if u == nil {
		return "-", "-"
	}
	license = "-"
	name = "-"
	if u.License != "" {
		license = u.License
	}
	if u.Name != "" {
		name = u.Name
		if u.FormatOnly {
			name += " (format)"
		}
	}
	return license, name
}

func joinCategories(cats []detection.Category) string {
	if len(cats) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cats))
	for _, c := range cats {
		parts = append(parts, string(c))
	}
	return strings.Join(parts, ", ")
}

// testPlan is the JSON shape `cilock tools test-plan --format=json` emits.
type testPlan struct {
	SchemaVersion string         `json:"schema_version"`
	GeneratedFor  int            `json:"detectors_total"`
	Cases         []testPlanCase `json:"cases"`
}

type testPlanCase struct {
	Detector       string                  `json:"detector"`
	Description    string                  `json:"description,omitempty"`
	Categories     []detection.Category    `json:"categories,omitempty"`
	Upstream       *detection.UpstreamInfo `json:"upstream,omitempty"`
	Gates          []string                `json:"gates"`
	Trace          string                  `json:"recommended_trace"`
	PositiveSetup  string                  `json:"positive_setup"`
	PositiveAssert string                  `json:"positive_assert"`
	NegativeSetup  string                  `json:"negative_setup,omitempty"`
	NegativeAssert string                  `json:"negative_assert,omitempty"`
	CILockCommand  string                  `json:"cilock_command"`
	WarningCodes   []string                `json:"warning_codes,omitempty"`
}

func buildTestPlan(entries []toolEntry) testPlan {
	plan := testPlan{
		SchemaVersion: "cilock.tools.test-plan/v0.1",
		GeneratedFor:  len(entries),
		Cases:         make([]testPlanCase, 0, len(entries)),
	}
	for _, e := range entries {
		c := testPlanCase{
			Detector:    e.Name,
			Description: e.Description,
			Categories:  e.Categories,
			Upstream:    e.Upstream,
			Gates:       e.Gates,
			Trace:       string(e.RecommendedTrace),
		}
		// Pick the first trigger as the canonical positive setup.
		if len(e.Triggers) > 0 {
			t := e.Triggers[0]
			c.PositiveSetup, c.PositiveAssert, c.CILockCommand = describePositive(e.Name, t)
			c.NegativeSetup, c.NegativeAssert = describeNegative(e.Name, t)
		} else {
			c.PositiveSetup = "no detector.yaml; this attestor is always-on or user-driven"
			c.PositiveAssert = "(not auto-tested)"
		}
		for _, w := range e.Warnings {
			c.WarningCodes = append(c.WarningCodes, w.Code)
		}
		plan.Cases = append(plan.Cases, c)
	}
	return plan
}

func describePositive(detector string, t toolTrigger) (setup, assertion, command string) {
	switch t.Kind {
	case "argv_prefix":
		setup = fmt.Sprintf("Invoke cilock with argv starting %q", t.Value)
		command = fmt.Sprintf("cilock plan --format=json -- %s [...]", t.Value)
	case "argv_contains":
		setup = fmt.Sprintf("Invoke cilock with argv containing %q", t.Value)
		command = fmt.Sprintf("cilock plan --format=json -- <cmd> %s", t.Value)
	case "env_set":
		setup = fmt.Sprintf("Set env var %s (any value)", t.Value)
		command = fmt.Sprintf("%s=1 cilock plan --format=json -- echo hi", t.Value)
	case "env_equals":
		setup = fmt.Sprintf("Set env: %s", t.Value)
		command = fmt.Sprintf("%s cilock plan --format=json -- echo hi", t.Value)
	case "file_exists":
		setup = fmt.Sprintf("Create file %q in cwd", t.Value)
		command = fmt.Sprintf("touch %s && cilock plan --format=json -- echo hi", t.Value)
	case "file_glob":
		setup = fmt.Sprintf("Create any file matching %q", t.Value)
		command = "touch <matching-file> && cilock plan --format=json -- echo hi"
	case "probe":
		setup = fmt.Sprintf("Probe must return: %s. Run on the actual cloud (EC2/GCE/Azure); unit-test via detection.InjectProbeResult.", t.Value)
		command = "(real cloud only) cilock plan --format=json -- echo hi"
	case "exec_observed_argv_prefix":
		setup = fmt.Sprintf("Run cilock as a wrapper that observes the child exec %q via the eBPF trace", t.Value)
		command = fmt.Sprintf("cilock run --tracing -- make build  # where make invokes %q internally", strings.Split(t.Value, " ")[0])
	case "product_glob":
		setup = fmt.Sprintf("After the wrapped command runs, expect a product file matching %q to be present", t.Value)
		command = fmt.Sprintf("cilock run -o out.bundle -- <cmd-that-produces> %s", t.Value)
	default:
		setup = fmt.Sprintf("Match %s=%s", t.Kind, t.Value)
		command = "cilock plan --format=json -- <cmd>"
	}
	assertion = fmt.Sprintf(`jq -e '.plan.fire[] | select(.attestor=="%s")' shows a hit`, detector)
	return setup, assertion, command
}

func describeNegative(detector string, t toolTrigger) (setup, assertion string) {
	switch t.Kind {
	case "argv_prefix":
		setup = "Invoke cilock with unrelated argv (e.g. `echo unrelated`)"
	case "env_set", "env_equals":
		setup = fmt.Sprintf("Run with env var %s UNSET", strings.SplitN(t.Value, "=", 2)[0])
	case "file_exists":
		setup = "Run in a tempdir without that file"
	case "probe":
		setup = "Off-cloud / no metadata endpoint"
	case "product_glob":
		setup = "Run a command that does NOT produce the matching file"
	default:
		setup = "Inputs not matching the predicate"
	}
	assertion = fmt.Sprintf(`jq '.plan.fire[].attestor' shows no %q entry`, detector)
	return setup, assertion
}

//nolint:gocognit // sequential markdown rendering with one branch per detector field.
func writeTestPlanMarkdown(w interface{ Write([]byte) (int, error) }, entries []toolEntry) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# cilock detector test plan\n\n")
	fmt.Fprintf(&b, "Auto-generated from the in-binary detector registry. %d detectors.\n\n", len(entries))
	fmt.Fprintf(&b, "Each section gives a positive scenario (detector should fire), a negative scenario (it should NOT fire), and the `cilock plan` command an LLM agent can invoke to assert the result.\n\n")
	for _, e := range entries {
		fmt.Fprintf(&b, "## `%s`\n\n", e.Name)
		if e.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", e.Description)
		}
		gates := strings.Join(e.Gates, " + ")
		if gates == "" {
			gates = noDetectorYAML
		}
		fmt.Fprintf(&b, "- **Gates:** %s\n", gates)
		fmt.Fprintf(&b, "- **Recommended trace:** `%s`\n", e.RecommendedTrace)
		if len(e.Categories) > 0 {
			fmt.Fprintf(&b, "- **Category:** %s\n", joinCategories(e.Categories))
		}
		if e.Upstream != nil {
			fmt.Fprintf(&b, "- **Upstream tool:** %s", e.Upstream.Name)
			if e.Upstream.License != "" {
				fmt.Fprintf(&b, " (license: %s)", e.Upstream.License)
			}
			if e.Upstream.Source != "" {
				fmt.Fprintf(&b, " — [%s](%s)", e.Upstream.Source, e.Upstream.Source)
			}
			fmt.Fprintln(&b)
		}
		if len(e.Triggers) > 0 {
			fmt.Fprintf(&b, "- **Triggers:**\n")
			for _, t := range e.Triggers {
				fmt.Fprintf(&b, "  - `%s` (gate=%s) — `%s`\n", t.Kind, t.Gate, t.Value)
			}
		}
		if len(e.Warnings) > 0 {
			fmt.Fprintf(&b, "- **Warnings emitted on suboptimal invocation:**\n")
			for _, w := range e.Warnings {
				fmt.Fprintf(&b, "  - `%s` (severity %s) — %s\n", w.Code, w.Severity, w.Message)
				if w.SuggestedExample != "" {
					fmt.Fprintf(&b, "    - example fix: `%s`\n", w.SuggestedExample)
				}
			}
		}
		if len(e.Triggers) > 0 {
			t := e.Triggers[0]
			ps, pa, cmd := describePositive(e.Name, t)
			ns, na := describeNegative(e.Name, t)
			fmt.Fprintf(&b, "\n### Positive case\n\n")
			fmt.Fprintf(&b, "- Setup: %s\n", ps)
			fmt.Fprintf(&b, "- Assert: %s\n", pa)
			fmt.Fprintf(&b, "- Command:\n  ```bash\n  %s\n  ```\n", cmd)
			fmt.Fprintf(&b, "\n### Negative case\n\n")
			fmt.Fprintf(&b, "- Setup: %s\n", ns)
			fmt.Fprintf(&b, "- Assert: %s\n", na)
		}
		fmt.Fprintf(&b, "\n---\n\n")
	}
	_, err := w.Write([]byte(b.String()))
	return err
}
