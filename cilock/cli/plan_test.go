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
	// flags that *actually* exist on `cilock run`.
	assert.Contains(t, out, "cilock run -a ",
		"plan should emit a runnable `cilock run -a ...` next-step (#220)")

	// Attestor list should be sorted and joined with commas; argv
	// should be passed after `--`.
	assert.True(t,
		strings.Contains(out, "cilock run -a docker,git -- docker build ."),
		"expected runnable line with sorted attestors and argv; got:\n%s", out)
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
