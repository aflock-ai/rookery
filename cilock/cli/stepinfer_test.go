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
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func extractStepDiagJSON(t *testing.T, out string) stepDiag {
	t.Helper()
	const begin, end = "---BEGIN cilock-stepdiag---", "---END cilock-stepdiag---"
	i := strings.Index(out, begin)
	j := strings.Index(out, end)
	require.GreaterOrEqual(t, i, 0, "missing BEGIN sentinel")
	require.Greater(t, j, i, "missing END sentinel")
	var d stepDiag
	require.NoError(t, json.Unmarshal([]byte(out[i+len(begin):j]), &d))
	return d
}

func TestRenderStepDiagNoMatch(t *testing.T) {
	var b strings.Builder
	renderStepDiag(&b, codeStepInferNoMatch, []string{"./deploy.sh", "v1"}, detection.StepInference{Outcome: detection.StepNoMatch})
	out := b.String()

	// Prose: code, why, observed, the custom-name escape hatch.
	assert.Contains(t, out, "error["+codeStepInferNoMatch+"]")
	assert.Contains(t, out, "policy verifier binds evidence")
	assert.Contains(t, out, "./deploy.sh v1")
	assert.Contains(t, out, "custom kebab-case name")

	// Structured block round-trips and carries the full lexicon.
	d := extractStepDiagJSON(t, out)
	assert.Equal(t, codeStepInferNoMatch, d.Code)
	assert.Equal(t, stepDiagSchemaVersion, d.Schema)
	assert.Equal(t, []string{"./deploy.sh", "v1"}, d.ObservedArgv)
	assert.Contains(t, d.Lexicon["core"], "build")
	assert.Contains(t, d.Lexicon["specialized"], "image-build")
	assert.NotEmpty(t, d.Remediation)
}

func TestRenderStepDiagAmbiguousListsCandidates(t *testing.T) {
	var b strings.Builder
	inf := detection.StepInference{
		Outcome: detection.StepAmbiguous,
		Candidates: []detection.StepCandidate{
			{Detector: "maven", Category: detection.CategoryBuild},
			{Detector: "npm", Category: detection.CategoryDependencyResolve},
		},
	}
	renderStepDiag(&b, codeStepInferAmbig, []string{"make", "all"}, inf)
	out := b.String()

	assert.Contains(t, out, "error["+codeStepInferAmbig+"]")
	assert.Contains(t, out, "maven→build")
	assert.Contains(t, out, "npm→dependency-resolve")

	d := extractStepDiagJSON(t, out)
	assert.Len(t, d.Candidates, 2)
}

// shellQuoteArgs must quote elements with whitespace so user-controlled
// argv can't smuggle layout into the diagnostic an agent reads.
func TestShellQuoteArgs(t *testing.T) {
	assert.Equal(t, "go build ./...", shellQuoteArgs([]string{"go", "build", "./..."}))
	assert.Equal(t, `sh -c "echo hi"`, shellQuoteArgs([]string{"sh", "-c", "echo hi"}))
}
