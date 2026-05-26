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

func TestWritePlanHuman_TraceRecommendation_DoesNotEmitFakeFlag(t *testing.T) {
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

	// The fake --tracing=<mode> flag must not appear anywhere in the
	// recommendation line. `cilock run` only has a boolean --trace.
	assert.NotContains(t, out, "--tracing=",
		"output must not advertise a non-existent --tracing=<mode> flag (#220)")
	assert.NotContains(t, out, "--auto",
		"output must not advertise a non-existent --auto flag (#220)")

	// The recommendation should still be visible, just labeled as
	// informational rather than as a copy-pasteable flag.
	assert.Contains(t, out, "recommended tracing: light",
		"the trace tier should still be surfaced for situational awareness")
	assert.Contains(t, out, "informational only",
		"output should make clear the recommendation is not a runnable flag")
	assert.Contains(t, out, "driven by: docker")
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
