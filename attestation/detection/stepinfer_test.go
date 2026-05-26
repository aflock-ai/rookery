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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stepInferRegistry(t *testing.T) *Registry {
	t.Helper()
	reg := NewRegistry()
	reg.Register("trivy", []byte(`apiVersion: cilock.detection/v0.1
name: trivy
category: [vulnerability-scan]
pre:
  match:
    argv_prefix: [trivy]`))
	reg.Register("grype", []byte(`apiVersion: cilock.detection/v0.1
name: grype
category: [vulnerability-scan]
pre:
  match:
    argv_prefix: [grype]`))
	reg.Register("git", []byte(`apiVersion: cilock.detection/v0.1
name: git
category: [source-checkout]
pre:
  match:
    file_exists: .git`))
	reg.Register("maven", []byte(`apiVersion: cilock.detection/v0.1
name: maven
category: [build, dependency-resolve]
primary_category: build
pre:
  match:
    argv_prefix: [mvn]`))
	reg.Register("docker", []byte(`apiVersion: cilock.detection/v0.1
name: docker
category: [image-build]
pre:
  match:
    argv_prefix: [docker, build]`))
	reg.Register("npm", []byte(`apiVersion: cilock.detection/v0.1
name: npm
category: [dependency-resolve]
pre:
  match:
    argv_prefix: [npm, ci]`))
	// Format adapter: no category — must never contribute.
	reg.Register("sarif", []byte(`apiVersion: cilock.detection/v0.1
name: sarif
pre:
  match:
    argv_prefix: [some-sarif-tool]`))
	return reg
}

func fire(attestor, rule string) FireDecision {
	return FireDecision{Attestor: attestor, Gate: GatePre, MatchedRule: rule}
}

func TestInferStep(t *testing.T) {
	reg := stepInferRegistry(t)

	tests := []struct {
		name        string
		fire        []FireDecision
		wantOutcome StepOutcome
		wantStep    Category
		wantSource  string
	}{
		{
			name:        "single argv match resolves",
			fire:        []FireDecision{fire("trivy", "argv_prefix:[trivy]")},
			wantOutcome: StepResolved,
			wantStep:    CategoryVulnerabilityScan,
			wantSource:  "trivy",
		},
		{
			name: "ambient file_exists match is ignored",
			fire: []FireDecision{
				fire("trivy", "argv_prefix:[trivy]"),
				fire("git", "file_exists:.git"),
			},
			wantOutcome: StepResolved,
			wantStep:    CategoryVulnerabilityScan,
			wantSource:  "trivy",
		},
		{
			name:        "only ambient matches → no match",
			fire:        []FireDecision{fire("git", "file_exists:.git")},
			wantOutcome: StepNoMatch,
		},
		{
			name:        "no fires → no match",
			fire:        nil,
			wantOutcome: StepNoMatch,
		},
		{
			name:        "multi-category detector uses primary_category",
			fire:        []FireDecision{fire("maven", "argv_prefix:[mvn]")},
			wantOutcome: StepResolved,
			wantStep:    CategoryBuild,
			wantSource:  "maven",
		},
		{
			name: "two argv tools, same category resolves",
			fire: []FireDecision{
				fire("trivy", "argv_prefix:[trivy]"),
				fire("grype", "argv_prefix:[grype]"),
			},
			wantOutcome: StepResolved,
			wantStep:    CategoryVulnerabilityScan,
			wantSource:  "trivy",
		},
		{
			name: "specialized (Tier 2) beats core (Tier 1)",
			fire: []FireDecision{
				fire("maven", "argv_prefix:[mvn]"),          // build (Tier 1)
				fire("docker", "any_of[0]:argv_prefix:..."), // image-build (Tier 2)
			},
			wantOutcome: StepResolved,
			wantStep:    CategoryImageBuild,
			wantSource:  "docker",
		},
		{
			name: "two distinct Tier 1 categories → ambiguous",
			fire: []FireDecision{
				fire("maven", "argv_prefix:[mvn]"),  // build
				fire("npm", "argv_prefix:[npm,ci]"), // dependency-resolve
			},
			wantOutcome: StepAmbiguous,
		},
		{
			name:        "format adapter (no category) never contributes",
			fire:        []FireDecision{fire("sarif", "argv_prefix:[some-sarif-tool]")},
			wantOutcome: StepNoMatch,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := PlanResult{Fire: tt.fire}
			got := InferStep(reg, plan)
			require.Equal(t, tt.wantOutcome, got.Outcome)
			if tt.wantOutcome == StepResolved {
				assert.Equal(t, tt.wantStep, got.Step)
				assert.Equal(t, tt.wantSource, got.Source)
			}
		})
	}
}

func TestInferStepAmbiguousListsCandidates(t *testing.T) {
	reg := stepInferRegistry(t)
	plan := PlanResult{Fire: []FireDecision{
		fire("maven", "argv_prefix:[mvn]"),
		fire("npm", "argv_prefix:[npm,ci]"),
	}}
	got := InferStep(reg, plan)
	require.Equal(t, StepAmbiguous, got.Outcome)
	require.Len(t, got.Candidates, 2)
	assert.Equal(t, "maven", got.Candidates[0].Detector)
	assert.Equal(t, CategoryBuild, got.Candidates[0].Category)
}
