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

package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// site/docs/reference/policy-schema.md tells policy authors what `input`
// looks like. It used to say a step's own attestations land at
// input.attestations.<predicateType>; nothing in the verifier ever put them
// there. EvaluateRegoPolicy hands rego json.Marshal(attestor) as the whole
// input, and buildRegoInput re-shapes that to {attestation, steps, external}
// only when the step declares attestationsFrom or externalFrom. These tests
// pull the rego fences out of the doc and run them through the real engine
// against the real context builder, so the prose and the bytes cannot drift
// apart again.

const (
	policySchemaDocPath = "../../site/docs/reference/policy-schema.md"
	commandRunTypeURI   = "https://aflock.ai/attestations/command-run/v0.2"
)

// commandRunLike marshals to the two command-run fields the doc examples
// read. The policy package cannot import the real plugin module, and the
// wire shape is all the engine sees anyway.
type commandRunLike struct {
	Cmd      []string `json:"cmd"`
	ExitCode int      `json:"exitcode"`
}

func (c *commandRunLike) Name() string                                   { return "command-run" }
func (c *commandRunLike) Type() string                                   { return commandRunTypeURI }
func (c *commandRunLike) RunType() attestation.RunType                   { return attestation.ExecuteRunType }
func (c *commandRunLike) Attest(_ *attestation.AttestationContext) error { return nil }
func (c *commandRunLike) Schema() *jsonschema.Schema                     { return nil }

// approvalLike stands in for an external attestation named in externalFrom.
type approvalLike struct {
	Approved bool `json:"approved"`
}

func (a *approvalLike) Name() string                                   { return "release-approval" }
func (a *approvalLike) Type() string                                   { return "https://example.com/release-approval/v1" }
func (a *approvalLike) RunType() attestation.RunType                   { return attestation.PostProductRunType }
func (a *approvalLike) Attest(_ *attestation.AttestationContext) error { return nil }
func (a *approvalLike) Schema() *jsonschema.Schema                     { return nil }

var docRegoFenceRE = regexp.MustCompile("(?s)```rego\n(.*?)\n```")

// policySchemaDocFence returns the ```rego fence in policy-schema.md whose
// first line declares the given package. Selecting by package keeps the test
// bound to the specific example rather than to fence order.
func policySchemaDocFence(t *testing.T, pkg string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(policySchemaDocPath))
	require.NoError(t, err, "policy-schema.md must be readable from the policy package")
	var found []string
	for _, m := range docRegoFenceRE.FindAllStringSubmatch(string(raw), -1) {
		body := m[1]
		first := strings.TrimSpace(strings.SplitN(body, "\n", 2)[0])
		found = append(found, first)
		if first == "package "+pkg {
			return []byte(body)
		}
	}
	t.Fatalf("policy-schema.md has no ```rego fence starting with %q; fences seen: %v", "package "+pkg, found)
	return nil
}

func passedCommandRun(step string, cmd []string, exit int) StepResult {
	return StepResult{
		Step: step,
		Passed: []PassedCollection{{
			Collection: source.CollectionVerificationResult{
				CollectionEnvelope: source.CollectionEnvelope{
					Collection: attestation.Collection{
						Name: step,
						Attestations: []attestation.CollectionAttestation{{
							Type:        commandRunTypeURI,
							Attestation: &commandRunLike{Cmd: cmd, ExitCode: exit},
						}},
					},
				},
			},
		}},
	}
}

func passedApproval(name string, approved bool) ExternalResult {
	return ExternalResult{
		Name: name,
		Passed: []PassedExternal{{
			Envelope: source.StatementEnvelope{Attestor: &approvalLike{Approved: approved}},
		}},
	}
}

// deployStep is the step the cross-step doc example is written for.
func deployStep() Step {
	return Step{
		Name:             "deploy",
		AttestationsFrom: []string{"build"},
		ExternalFrom:     []string{"releaseApproval"},
	}
}

func topLevelKeys(t *testing.T, v interface{}) []string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	var m map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestRegoInputShape_PlainStepIsTheAttestorJSON pins the shape the doc
// describes for a step with neither attestationsFrom nor externalFrom: the
// whole input is the attestor's JSON, and there is no `attestations` wrapper
// of any kind.
func TestRegoInputShape_PlainStepIsTheAttestorJSON(t *testing.T) {
	att := &commandRunLike{Cmd: []string{"go", "build"}, ExitCode: 0}
	step := Step{Name: "build"}
	ctx := buildStepRegoContext(step, map[string]StepResult{}, nil)
	require.Nil(t, ctx, "a step with no *From list must produce no context, so input stays the raw attestor JSON")

	var data interface{}
	raw, err := json.Marshal(att)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &data))

	input := buildRegoInput(data, nil)
	assert.Equal(t, []string{"cmd", "exitcode"}, topLevelKeys(t, input), "input must be the attestor JSON itself")
}

// TestRegoInputShape_CrossStepWrapsUnderAttestation pins the re-shaped
// input: exactly {attestation, steps, external}, the step's own attestor
// under `attestation` (singular), never `attestations.<predicateType>`.
func TestRegoInputShape_CrossStepWrapsUnderAttestation(t *testing.T) {
	results := map[string]StepResult{"build": passedCommandRun("build", []string{"go", "build"}, 0)}
	externals := map[string]ExternalResult{"releaseApproval": passedApproval("releaseApproval", true)}
	ctx := buildStepRegoContext(deployStep(), results, externals)
	require.NotNil(t, ctx)

	var data interface{}
	raw, err := json.Marshal(&commandRunLike{Cmd: []string{"kubectl", "apply"}, ExitCode: 0})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &data))

	input := buildRegoInput(data, []map[string]interface{}{ctx})
	assert.Equal(t, []string{"attestation", "external", "steps"}, topLevelKeys(t, input))

	wrapped, ok := input.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, []string{"cmd", "exitcode"}, topLevelKeys(t, wrapped["attestation"]), "input.attestation is the step's own attestor JSON")
	steps, ok := wrapped["steps"].(map[string]interface{})
	require.True(t, ok)
	build, ok := steps["build"].(map[string]interface{})
	require.True(t, ok, "input.steps.build must exist")
	assert.Contains(t, build, commandRunTypeURI, "cross-step attestors are keyed by predicate type URI")
	external, ok := wrapped["external"].(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, external, "releaseApproval", "externals are keyed by their externalAttestations name")
}

// TestRegoInputShape_DocPlainExampleEvaluates runs the doc's plain-step
// example through the real engine: a non-zero exit denies, zero does not.
func TestRegoInputShape_DocPlainExampleEvaluates(t *testing.T) {
	pol := []RegoPolicy{{Name: "policy-schema.md plain", Module: policySchemaDocFence(t, "commandrun.exitcode")}}

	err := EvaluateRegoPolicy(&commandRunLike{Cmd: []string{"go", "build"}, ExitCode: 2}, pol)
	require.Error(t, err, "documented plain example must deny a non-zero exit")
	assert.Contains(t, err.Error(), "exited with status 2")

	require.NoError(t, EvaluateRegoPolicy(&commandRunLike{Cmd: []string{"go", "build"}, ExitCode: 0}, pol))
}

// TestRegoInputShape_DocCrossStepExampleEvaluates runs the doc's cross-step
// example against a context built by the real buildStepRegoContext, so the
// input.attestation / input.steps.<step>.<type> / input.external.<name>
// paths the doc prints are the paths the verifier produces.
func TestRegoInputShape_DocCrossStepExampleEvaluates(t *testing.T) {
	pol := []RegoPolicy{{Name: "policy-schema.md cross-step", Module: policySchemaDocFence(t, "deploy.provenance")}}
	goodBuild := map[string]StepResult{"build": passedCommandRun("build", []string{"go", "build", "-o=app", "."}, 0)}
	granted := map[string]ExternalResult{"releaseApproval": passedApproval("releaseApproval", true)}
	deployOK := &commandRunLike{Cmd: []string{"kubectl", "apply", "-f", "release.yaml"}, ExitCode: 0}

	t.Run("all_conditions_met_allows", func(t *testing.T) {
		ctx := buildStepRegoContext(deployStep(), goodBuild, granted)
		require.NoError(t, EvaluateRegoPolicy(deployOK, pol, ctx))
	})

	t.Run("own_attestation_read_under_input_attestation", func(t *testing.T) {
		ctx := buildStepRegoContext(deployStep(), goodBuild, granted)
		err := EvaluateRegoPolicy(&commandRunLike{Cmd: deployOK.Cmd, ExitCode: 3}, pol, ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "deploy exited with status 3")
	})

	t.Run("cross_step_attestor_read_under_input_steps", func(t *testing.T) {
		badBuild := map[string]StepResult{"build": passedCommandRun("build", []string{"make", "all"}, 0)}
		ctx := buildStepRegoContext(deployStep(), badBuild, granted)
		err := EvaluateRegoPolicy(deployOK, pol, ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build step ran")
	})

	t.Run("missing_cross_step_attestor_denies", func(t *testing.T) {
		ctx := buildStepRegoContext(deployStep(), map[string]StepResult{}, granted)
		require.NotNil(t, ctx, "declaring attestationsFrom activates the wrapped shape even before the dependency is verified")
		err := EvaluateRegoPolicy(deployOK, pol, ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "build step provided no command-run attestation")
	})

	t.Run("external_read_under_input_external", func(t *testing.T) {
		denied := map[string]ExternalResult{"releaseApproval": passedApproval("releaseApproval", false)}
		ctx := buildStepRegoContext(deployStep(), goodBuild, denied)
		err := EvaluateRegoPolicy(deployOK, pol, ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "release approval missing or not granted")
	})

	t.Run("absent_external_denies_via_not", func(t *testing.T) {
		ctx := buildStepRegoContext(deployStep(), goodBuild, map[string]ExternalResult{})
		err := EvaluateRegoPolicy(deployOK, pol, ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "release approval missing or not granted")
	})
}

// TestRegoInputShape_TopLevelPathsGoSilentUnderCrossStep is the warning the
// doc now carries: once attestationsFrom/externalFrom is set, the plain
// example's input.exitcode is undefined, so a failing deploy passes without
// a sound. That silence is exactly why the doc must state the real shape.
func TestRegoInputShape_TopLevelPathsGoSilentUnderCrossStep(t *testing.T) {
	plain := []RegoPolicy{{Name: "policy-schema.md plain", Module: policySchemaDocFence(t, "commandrun.exitcode")}}
	results := map[string]StepResult{"build": passedCommandRun("build", []string{"go", "build"}, 0)}
	ctx := buildStepRegoContext(deployStep(), results, map[string]ExternalResult{})
	require.NotNil(t, ctx)

	failing := &commandRunLike{Cmd: []string{"kubectl", "apply"}, ExitCode: 3}
	require.Error(t, EvaluateRegoPolicy(failing, plain), "sanity: the plain example denies this attestor without context")
	assert.NoError(t, EvaluateRegoPolicy(failing, plain, ctx),
		"with cross-step context the plain example must NOT match; if it starts denying, the wrap changed and the doc must change with it")
}

// TestRegoInputShape_LegacyAttestationsPathNeverExisted pins the claim the
// old doc made, negatively: input.attestations.<predicateType> is undefined
// in both shapes, so a rule written against it can never fire.
func TestRegoInputShape_LegacyAttestationsPathNeverExisted(t *testing.T) {
	legacy := []RegoPolicy{{Name: "legacy.rego", Module: []byte(`package legacy

deny[msg] {
	input.attestations["` + commandRunTypeURI + `"].exitcode != 0
	msg := "would deny if the documented path existed"
}`)}}
	failing := &commandRunLike{Cmd: []string{"go", "build"}, ExitCode: 1}

	assert.NoError(t, EvaluateRegoPolicy(failing, legacy), "plain shape: input.attestations is undefined")

	results := map[string]StepResult{"build": passedCommandRun("build", []string{"go", "build"}, 0)}
	ctx := buildStepRegoContext(deployStep(), results, map[string]ExternalResult{})
	assert.NoError(t, EvaluateRegoPolicy(failing, legacy, ctx), "cross-step shape: input.attestations is still undefined")
}
