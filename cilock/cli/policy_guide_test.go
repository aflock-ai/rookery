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

// jade:ring local

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/stretchr/testify/require"
)

// The goal ids are the product's (jade/factory/edge/git/policypairing.js
// PAIRING_GOALS), so a goal a human picked names a goal here.
func TestGuideGoalIDsAreThePairingGoals(t *testing.T) {
	require.ElementsMatch(t, []string{"tests", "secrets", "vulns", "quality", "app-build", "config", "config-security",
		"kubernetes", "dockerfile", "image-vulns", "provenance", "sbom", "docs", "migrations"}, goalIDs())
	require.Equal(t, []string{"tests", "quality", "app-build", "secrets", "provenance", "sbom"}, goalIDs()[:6],
		"the goals agents need most come first")
	require.Equal(t, "vulns", goalIDs()[len(goalIDs())-1], "vulnerability scanning comes last")
}

func TestGuideTextNamesTheFlowAndEveryGoal(t *testing.T) {
	stdout, _, err := executeCmdOutput("policy", "guide", "-d", t.TempDir())
	require.NoError(t, err)
	require.Contains(t, stdout, "You author the policy")
	require.Contains(t, stdout, "cilock policy template --goal")
	require.Contains(t, stdout, "cilock policy validate -p .pushgate/policy.json")
	for _, id := range goalIDs() {
		require.Contains(t, stdout, "\n  "+id+" ", "goal %s listed", id)
	}
	require.Contains(t, stdout, "command-pin*", "a rule with a slot is marked")
}

func TestGuideGoalDetailPrintsRunLineFieldsAndRego(t *testing.T) {
	stdout, _, err := executeCmdOutput("policy", "guide", "--goal", "tests", "-d", t.TempDir())
	require.NoError(t, err)
	require.Contains(t, stdout, "cilock run --step tests -a test-results -- <argv>")
	require.Contains(t, stdout, "predicate.summary.total")
	require.Contains(t, stdout, "JUnit XML or CTRF JSON")
	require.Contains(t, stdout, "package tests_pass")
	require.Contains(t, stdout, "zero tests passing is not tests passing")
	require.Contains(t, stdout, "pytest", "tools come from the detection catalog")
}

func TestGuideJSONIsStructured(t *testing.T) {
	stdout, _, err := executeCmdOutput("policy", "guide", "--format", "json", "-d", t.TempDir())
	require.NoError(t, err)
	var doc struct {
		Flow  string `json:"flow"`
		Goals []struct {
			ID           string `json:"id"`
			Run          string `json:"run"`
			Attestations []struct {
				Type  string `json:"type"`
				Rules []struct {
					ID     string `json:"id"`
					Module string `json:"module"`
				} `json:"rules"`
			} `json:"attestations"`
			Tools []catalogTool `json:"tools"`
		} `json:"goals"`
		Topics map[string]string `json:"topics"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &doc))
	require.Len(t, doc.Goals, len(catalogGoals))
	for _, topic := range guideTopicNames() {
		require.NotEmpty(t, doc.Topics[topic], "topic %s", topic)
	}
	var dockerfileTools []string
	for _, g := range doc.Goals {
		if g.ID == "dockerfile" {
			for _, tool := range g.Tools {
				dockerfileTools = append(dockerfileTools, tool.Name)
			}
		}
	}
	require.Contains(t, dockerfileTools, "hadolint", "derived from the catalog, not listed by hand")
}

// A detector added to the catalog for a new language shows up under its goal
// with no edit to guide.
func TestGuideDerivesToolsFromTheDetectionCatalog(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register("cargo-nextest", []byte(`apiVersion: cilock.detection/v0.1
name: cargo-nextest
detection_only: true
description: Rust test runner with JUnit output.
category: [unit-test]
emits_formats: [test-results]
pre:
  match:
    argv_prefix: [cargo, nextest]
`))
	orig := guideRegistry
	guideRegistry = func() *detection.Registry { return reg }
	t.Cleanup(func() { guideRegistry = orig })

	stdout, _, err := executeCmdOutput("policy", "guide", "--goal", "tests", "--format", "json", "-d", t.TempDir())
	require.NoError(t, err)
	var doc struct {
		Goals []struct {
			ID    string        `json:"id"`
			Tools []catalogTool `json:"tools"`
		} `json:"goals"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &doc))
	require.Len(t, doc.Goals, 1)
	require.Len(t, doc.Goals[0].Tools, 1)
	tool := doc.Goals[0].Tools[0]
	require.Equal(t, "cargo-nextest", tool.Name)
	require.Equal(t, []string{"cargo nextest"}, tool.Argv)
	require.Equal(t, []string{"test-results"}, tool.Captures)
	require.Equal(t, []string{typeTestResults}, tool.Types)
}

func TestGuideRefusesUnknownGoalAndTopic(t *testing.T) {
	_, _, err := executeCmdOutput("policy", "guide", "--goal", "nope")
	require.Error(t, err)
	require.Contains(t, err.Error(), "tests")
	_, _, err = executeCmdOutput("policy", "guide", "--topic", "nope")
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "chain") && strings.Contains(err.Error(), "trace"))
}
