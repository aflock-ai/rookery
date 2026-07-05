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
	"bytes"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runPrereqsWant mirrors the run-prerequisite placeholders plan renders into
// its "to run:" suggestions (issue #6094): `cilock run` requires --step and a
// signer, which `cilock plan` can't infer, so it emits them as fill-in
// placeholders. Kept here (not imported) so a drift in the rendered string is
// caught by these golden assertions.
const runPrereqsWant = "-s <step> --signer-file-key-path <key.pem> "

// Regression tests for issue #220: `cilock plan` used to recommend
// flags that don't exist on `cilock run` (--tracing=<mode>, --auto).
// Users would copy-paste the suggestions and immediately hit
// 'unknown flag' errors. These tests pin the output strings so future
// edits don't silently re-introduce the drift before M3d ships the
// real flags.

func TestPlanHelpLong_DoesNotReferenceAutoFlag(t *testing.T) {
	long := PlanCmd().Long
	assert.NotContains(t, long, "--auto",
		"`cilock run --auto` is not a real flag yet (issue #220); the long help must not advertise it")
	assert.Contains(t, long, "cilock run -a",
		"long help should point users at the working `-a` form")
}

// TestWritePlanHuman_NoTraceRecommendationLine pins the fix-3 behaviour:
// the disclaimer-laden "recommended tracing: <mode> (informational only)"
// line was more confusing than helpful and was dropped entirely. Fix-5 now
// surfaces tracing intent inline in the "to run (with tracing):" hint.
//
// Restore the standalone line only when `cilock run --trace=<mode>` (#220)
// actually lands and the line can advertise a runnable flag.
func TestWritePlanHuman_NoTraceRecommendationLine(t *testing.T) {
	env := planEnvelope{
		Plan: detection.PlanResult{
			Fire: []detection.FireDecision{
				{Attestor: "docker", MatchedRule: "docker-build"},
			},
			Inputs: detection.InputSnapshot{Argv: []string{"docker", "build", "."}},
		},
		TraceRecommendation: detection.TraceRecommendation{
			Mode: detection.TraceLight,
			Reasons: map[string]detection.TraceMode{
				"docker": detection.TraceLight,
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, writePlanHuman(&buf, env, false))
	out := buf.String()

	// Whole "recommended tracing" block must be gone — both the string
	// itself and the "informational only" disclaimer that came with it.
	assert.NotContains(t, out, "recommended tracing",
		"recommended tracing line is dropped until --trace=<mode> lands (#220)")
	assert.NotContains(t, out, "informational only",
		"the disclaimer that came with the dropped line must also be gone")

	// Old footguns still excluded.
	assert.NotContains(t, out, "--tracing=",
		"output must not advertise a non-existent --tracing=<mode> flag (#220)")
	assert.NotContains(t, out, "--auto",
		"output must not advertise a non-existent --auto flag (#220)")
}

func TestWritePlanHuman_FireSet_EmitsRunnableCilockRunCommand(t *testing.T) {
	env := planEnvelope{
		Plan: detection.PlanResult{
			Fire: []detection.FireDecision{
				{Attestor: "git"},
				{Attestor: "docker"},
			},
			Inputs: detection.InputSnapshot{Argv: []string{"docker", "build", "."}},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, writePlanHuman(&buf, env, false))
	out := buf.String()

	// Users should get a copy-pasteable next step that uses the
	// flags that *actually* exist on `cilock run`, including the
	// required --step and a signer (#6094).
	assert.Contains(t, out, "cilock run "+runPrereqsWant+"-a ",
		"plan should emit a runnable `cilock run -s <step> --signer-... -a ...` next-step (#220, #6094)")

	// Attestor list should be sorted and joined with commas; argv
	// should be passed after `--`.
	assert.True(t,
		strings.Contains(out, "cilock run "+runPrereqsWant+"-a docker,git -- docker build ."),
		"expected runnable line with -s/--step + signer, sorted attestors and argv; got:\n%s", out)
}

// TestWritePlanHuman_RecommendsTraceWhenAttestorBenefits pins fix F7: when
// at least one fired attestor benefits from tracing (per detector YAML's
// recommended_trace), plan emits a second runnable line with --trace
// inlined so operators don't paste the plain form and silently miss
// tracing's value.
func TestWritePlanHuman_RecommendsTraceWhenAttestorBenefits(t *testing.T) {
	env := planEnvelope{
		Plan: detection.PlanResult{
			Fire: []detection.FireDecision{
				{Attestor: "git"},
				{Attestor: "go-build"},
				{Attestor: "lockfiles"},
			},
			Inputs: detection.InputSnapshot{Argv: []string{"go", "build", "-o", "./bin/argocd", "./cmd"}},
		},
		TraceRecommendation: detection.TraceRecommendation{
			Mode: detection.TraceLight,
			Reasons: map[string]detection.TraceMode{
				"go-build": detection.TraceLight,
			},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, writePlanHuman(&buf, env, false))
	out := buf.String()

	// Plain line still there (back-compat for operators who don't care
	// about tracing).
	assert.Contains(t, out, "to run: cilock run "+runPrereqsWant+"-a git,go-build,lockfiles -- go build -o ./bin/argocd ./cmd",
		"plain 'to run:' line must still be present for back-compat")

	// New tracing line MUST be present and MUST use the real --trace
	// flag (not the fake --trace=<mode> from #220).
	assert.Contains(t, out, "to run (with tracing): cilock run --trace "+runPrereqsWant+"-a git,go-build,lockfiles -- go build -o ./bin/argocd ./cmd",
		"plan must emit a --trace variant when a fired attestor benefits (F7)")
	assert.NotContains(t, out, "--trace=",
		"F7 must use the real boolean --trace flag, not the unimplemented --trace=<mode> form")
}

// TestWritePlanHuman_NoTraceVariantWhenNoneBenefits asserts that when the
// TraceRecommendation is off / empty, only the plain "to run:" line is
// emitted — no spurious second line.
func TestWritePlanHuman_NoTraceVariantWhenNoneBenefits(t *testing.T) {
	env := planEnvelope{
		Plan: detection.PlanResult{
			Fire: []detection.FireDecision{
				{Attestor: "environment"},
			},
			Inputs: detection.InputSnapshot{Argv: []string{"true"}},
		},
		TraceRecommendation: detection.TraceRecommendation{
			Mode: detection.TraceOff,
		},
	}

	var buf bytes.Buffer
	require.NoError(t, writePlanHuman(&buf, env, false))
	out := buf.String()

	assert.Contains(t, out, "to run: cilock run "+runPrereqsWant+"-a environment -- true")
	assert.NotContains(t, out, "to run (with tracing)",
		"no fired attestor benefits from tracing → no --trace variant emitted")
}

// TestWritePlanHuman_RecommendsIgnoreExitCodeWhenToolGatesOnFindings pins the
// fix for the scanner-exit-code bug: when a fired tool exits non-zero on findings
// (ExitsNonzeroOnFindings), the suggested 'to run:' command must inline
// --ignore-command-exit-code so an agent pasting it verbatim captures the report
// instead of failing the run. It must compose with the --trace variant too.
func TestWritePlanHuman_RecommendsIgnoreExitCodeWhenToolGatesOnFindings(t *testing.T) {
	env := planEnvelope{
		Plan: detection.PlanResult{
			Fire: []detection.FireDecision{
				{Attestor: "osv-scanner"},
			},
			Inputs: detection.InputSnapshot{Argv: []string{"osv-scanner", "--output", "osv.sarif", "."}},
		},
		IgnoreExitCodeRecommended: true,
		TraceRecommendation:       detection.TraceRecommendation{Mode: detection.TraceLight},
	}

	var buf bytes.Buffer
	require.NoError(t, writePlanHuman(&buf, env, false))
	out := buf.String()

	assert.Contains(t, out, "to run: cilock run "+runPrereqsWant+"--ignore-command-exit-code -a osv-scanner -- osv-scanner --output osv.sarif .",
		"plan must inline --ignore-command-exit-code for a tool that exits non-zero on findings")
	assert.Contains(t, out, "to run (with tracing): cilock run --trace "+runPrereqsWant+"--ignore-command-exit-code -a osv-scanner -- osv-scanner --output osv.sarif .",
		"the --trace variant must also carry --ignore-command-exit-code")
}

// TestWritePlanHuman_NoIgnoreExitCodeWhenToolDoesNotGate is the negative guard:
// a tool that does not gate on findings must NOT get --ignore-command-exit-code.
func TestWritePlanHuman_NoIgnoreExitCodeWhenToolDoesNotGate(t *testing.T) {
	env := planEnvelope{
		Plan: detection.PlanResult{
			Fire:   []detection.FireDecision{{Attestor: "go-build"}},
			Inputs: detection.InputSnapshot{Argv: []string{"go", "build", "./..."}},
		},
		IgnoreExitCodeRecommended: false,
	}

	var buf bytes.Buffer
	require.NoError(t, writePlanHuman(&buf, env, false))
	out := buf.String()

	assert.Contains(t, out, "to run: cilock run "+runPrereqsWant+"-a go-build -- go build ./...")
	assert.NotContains(t, out, "--ignore-command-exit-code",
		"a non-gating tool must not get --ignore-command-exit-code")
}

// TestWritePlanHuman_ToRunIncludesStepAndSigner pins fix #6094: the "to run:"
// suggestion previously omitted the required --step and a signer, so pasting it
// verbatim failed with `--step is required` whenever the step couldn't be
// inferred from the command (e.g. `echo`). The line must now render both, so an
// operator sees the flags to fill in.
func TestWritePlanHuman_ToRunIncludesStepAndSigner(t *testing.T) {
	env := planEnvelope{
		Plan: detection.PlanResult{
			Fire:   []detection.FireDecision{{Attestor: "environment"}},
			Inputs: detection.InputSnapshot{Argv: []string{"echo", "hi"}},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, writePlanHuman(&buf, env, false))
	out := buf.String()

	assert.Contains(t, out, "-s <step>",
		"the 'to run:' suggestion must render the required --step (#6094)")
	assert.Contains(t, out, "--signer-file-key-path <key.pem>",
		"the 'to run:' suggestion must render a signer (#6094)")
	assert.Contains(t, out, "to run: cilock run "+runPrereqsWant+"-a environment -- echo hi",
		"the full suggested command must carry step + signer before -a; got:\n%s", out)
}

func TestWritePlanHuman_TraceOff_OmitsRecommendationLine(t *testing.T) {
	env := planEnvelope{
		Plan: detection.PlanResult{
			Fire: []detection.FireDecision{
				{Attestor: "environment"},
			},
			Inputs: detection.InputSnapshot{Argv: []string{"true"}},
		},
		TraceRecommendation: detection.TraceRecommendation{
			Mode: detection.TraceOff,
		},
	}

	var buf bytes.Buffer
	require.NoError(t, writePlanHuman(&buf, env, false))
	out := buf.String()

	// When nothing recommends tracing, the recommendation line is
	// suppressed entirely — no spurious "informational only" string.
	assert.NotContains(t, out, "recommended tracing")
	assert.NotContains(t, out, "--tracing=")
	assert.NotContains(t, out, "--auto")
}
