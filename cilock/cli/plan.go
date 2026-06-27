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
	"os"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/spf13/cobra"
)

// planEnvelope is the JSON shape `cilock plan` emits. Keeping it
// separate from detection.PlanResult lets us add fields (trace
// recommendation, summary counts) without churning the core type.
type planEnvelope struct {
	Plan                detection.PlanResult          `json:"plan"`
	TraceRecommendation detection.TraceRecommendation `json:"trace_recommendation"`
	// IgnoreExitCodeRecommended is true when a fired tool exits non-zero on
	// findings; the suggested `to run:` command then includes
	// --ignore-command-exit-code so a captured report isn't lost to a gate exit.
	IgnoreExitCodeRecommended bool        `json:"ignore_exit_code_recommended"`
	Summary                   planSummary `json:"summary"`
}

type planSummary struct {
	Fired    []string `json:"fired"`
	Skipped  int      `json:"skipped"`
	Warnings int      `json:"warnings"`
}

// PlanCmd is the `cilock plan` subcommand. It evaluates the pre-gate
// detection plan against a hypothetical invocation — argv after `--`,
// the current environment, and the current working directory — without
// executing anything.
//
// Output modes:
//   - default human-readable (stderr-friendly summary)
//   - --format=json (LLM-friendly structured plan)
//
// This is the LLM consumer's primary tool: invoke plan, read warnings
// with their suggested_command, re-invoke cilock run with the corrected
// argv. One round-trip, no magic.
func PlanCmd() *cobra.Command {
	var (
		format  string
		verbose bool
	)
	cmd := &cobra.Command{
		Use:   "plan -- <command> [args...]",
		Short: "Show which attestors detection would fire for a command, without executing it",
		// TODO(#220): once 'cilock run --auto' lands, restore the
		// auto-run suggestion here. Until then we point users at the
		// explicit -a form, which is the only flag that actually exists
		// on 'cilock run' today.
		Long: `Plan runs cilock's pre-gate detection against a hypothetical command
invocation and prints what would fire, what would be skipped (with reasons),
and any warnings with rendered suggested_command strings.

It does NOT execute the command. Use 'cilock run -a <attestor>,...' to
actually run the planned set; pass the attestor names from the 'fire'
list above.`,
		Example: `  # Show which attestors would fire for a build, without running it
  cilock plan -- go build ./...

  # Machine-readable plan for an agent to consume
  cilock plan --format json -- docker build -t app .`,
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		Args:              cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cwd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("get cwd: %w", err)
			}
			plan := detection.RunPrePlan(detection.PrePlan{
				Argv: args,
				Env:  envSliceToMap(os.Environ()),
				Cwd:  cwd,
			})
			env := planEnvelope{
				Plan:                      plan,
				TraceRecommendation:       detection.RecommendTrace(detection.Default(), plan),
				IgnoreExitCodeRecommended: detection.RecommendIgnoreExitCode(detection.Default(), plan),
				Summary:                   buildPlanSummary(plan),
			}
			switch strings.ToLower(format) {
			case "json":
				return writePlanJSON(cmd.OutOrStdout(), env)
			case "", formatText, "human":
				return writePlanHuman(cmd.OutOrStdout(), env, verbose)
			default:
				return fmt.Errorf("unknown --format %q (want text|json)", format)
			}
		},
	}
	cmd.Flags().StringVar(&format, "format", formatText, "Output format: text (default) or json")
	cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Include the full skip list (every detector considered) in text output")
	return cmd
}

func buildPlanSummary(plan detection.PlanResult) planSummary {
	fired := make([]string, 0, len(plan.Fire))
	for _, f := range plan.Fire {
		fired = append(fired, f.Attestor)
	}
	sort.Strings(fired)
	return planSummary{
		Fired:    fired,
		Skipped:  len(plan.Skip),
		Warnings: len(plan.Warnings),
	}
}

func envSliceToMap(env []string) map[string]string {
	out := make(map[string]string, len(env))
	for _, kv := range env {
		eq := strings.IndexByte(kv, '=')
		if eq < 0 {
			out[kv] = ""
			continue
		}
		out[kv[:eq]] = kv[eq+1:]
	}
	return out
}

func writePlanJSON(w interface{ Write([]byte) (int, error) }, env planEnvelope) error {
	enc := json.NewEncoder(asWriter(w))
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// asWriter is a small adapter so we can accept either io.Writer or
// cobra's OutOrStdout (which already implements io.Writer). Kept tiny
// to avoid importing io in this file for one type assertion.
func asWriter(w interface{ Write([]byte) (int, error) }) interface {
	Write([]byte) (int, error)
} {
	return w
}

//nolint:gocognit,gocyclo // Output formatting branches are inherently linear.
func writePlanHuman(w interface{ Write([]byte) (int, error) }, env planEnvelope, verbose bool) error {
	plan := env.Plan
	var b strings.Builder
	fmt.Fprintf(&b, "cilock plan — %d attestor(s) would fire\n", len(plan.Fire))
	fmt.Fprintf(&b, "  argv: %s\n", strings.Join(plan.Inputs.Argv, " "))

	if len(plan.Fire) == 0 {
		fmt.Fprintln(&b, "  fire: (none — no detector matched this invocation)")
		fmt.Fprintln(&b, "         Hint: run from inside a project (`.git/`, `Dockerfile`, `package.json`, etc.)")
		fmt.Fprintln(&b, "         or pass attestors explicitly with `-a <name>`.")
	} else {
		writePlanFireSection(&b, env)
	}

	// TODO(#220): when 'cilock run --trace=<mode>' lands, re-emit a
	// per-mode recommendation line here. Until then the disclaimer-laden
	// "recommended tracing: light (informational only)" line was more
	// confusing than helpful — see the fix-3 batch. Fix-5 still uses
	// TraceRecommendation to drive the optional "to run (with tracing):"
	// hint above, but THIS line stays gone until the flag actually
	// exists on `cilock run`.

	if len(plan.Warnings) > 0 {
		fmt.Fprintln(&b, "  warnings:")
		for _, wn := range plan.Warnings {
			fmt.Fprintf(&b, "    [%s] %s\n", wn.Code, wn.Message)
			if wn.Summary != "" {
				fmt.Fprintf(&b, "      %s\n", wn.Summary)
			}
			if len(wn.SuggestedCommand) > 0 {
				fmt.Fprintf(&b, "      suggested: %s\n", detection.FormatSuggestedCommand(wn.SuggestedCommand, nil))
			}
		}
	}

	if verbose && len(plan.Skip) > 0 {
		fmt.Fprintf(&b, "  skipped (%d, use -v to hide):\n", len(plan.Skip))
		for _, s := range plan.Skip {
			if s.Reason != "" {
				fmt.Fprintf(&b, "    - %s  (%s: %s)\n", s.Attestor, s.Cause, s.Reason)
			} else {
				fmt.Fprintf(&b, "    - %s  (%s)\n", s.Attestor, s.Cause)
			}
		}
	} else if len(plan.Skip) > 0 {
		fmt.Fprintf(&b, "  (%d detectors skipped — pass -v to see why)\n", len(plan.Skip))
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

// writePlanFireSection renders the matched-attestor list plus the
// copy-pasteable `cilock run` suggestion(s). Split out of writePlanHuman so
// the empty-vs-fired branch there stays flat (nestif).
func writePlanFireSection(b *strings.Builder, env planEnvelope) {
	plan := env.Plan
	fmt.Fprintln(b, "  fire:")
	for _, f := range plan.Fire {
		fmt.Fprintf(b, "    - %s\n", f.Attestor)
		if f.LLMHint != "" {
			fmt.Fprintf(b, "        %s\n", f.LLMHint)
		}
	}
	// TODO(#220): once 'cilock run --auto' lands, replace this
	// explicit -a list with a '--auto' suggestion. Until then '-a'
	// is the only working way to actually fire the planned set.
	fired := make([]string, 0, len(plan.Fire))
	for _, f := range plan.Fire {
		fired = append(fired, f.Attestor)
	}
	sort.Strings(fired)
	// A fired tool that exits non-zero on findings (osv-scanner, gosec, …)
	// would abort the run despite writing its report; surface the escape hatch
	// in the suggested command so an agent pasting it verbatim still captures it.
	ignoreExit := ""
	if env.IgnoreExitCodeRecommended {
		ignoreExit = "--ignore-command-exit-code "
	}
	fmt.Fprintf(b, "  to run: cilock run %s-a %s -- %s\n",
		ignoreExit, strings.Join(fired, ","), strings.Join(plan.Inputs.Argv, " "))

	// Fix F7: when tracing would benefit at least one of the fired
	// attestors (per detector's recommended_trace field), also emit
	// the --trace variant so operators don't paste the plain "to
	// run:" line and silently miss tracing's value.
	//
	// The recommendation is non-empty + non-Off iff at least one
	// matched detector's recommended_trace fed into RecommendTrace
	// — i.e. tracing would actually help. We don't double-check
	// against the fired list because RecommendTrace already only
	// reports modes for matched detectors.
	if env.TraceRecommendation.Mode != "" && env.TraceRecommendation.Mode != detection.TraceOff {
		fmt.Fprintf(b, "  to run (with tracing): cilock run --trace %s-a %s -- %s\n",
			ignoreExit, strings.Join(fired, ","), strings.Join(plan.Inputs.Argv, " "))
	}
}
