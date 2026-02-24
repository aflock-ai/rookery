// Copyright 2025 The Aflock Authors
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

package githubaction

import (
	"context"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	a := New()
	assert.Equal(t, Name, a.Name())
	assert.Equal(t, Type, a.Type())
	assert.Equal(t, RunType, a.RunType())
	assert.NotNil(t, a.ActionInputs)
	assert.NotNil(t, a.ActionOutputs)
}

func TestNewWithOptions(t *testing.T) {
	inputs := map[string]string{"token": "abc"}
	outputs := map[string]string{"result": "ok"}

	a := New(
		WithActionRef("actions/checkout@v4"),
		WithActionType("javascript"),
		WithActionName("Checkout"),
		WithActionInputs(inputs),
		WithActionOutputs(outputs),
		WithExitCode(0),
		WithActionDir("/tmp/actions/checkout"),
	)

	assert.Equal(t, "actions/checkout@v4", a.ActionRef)
	assert.Equal(t, "javascript", a.ActionType)
	assert.Equal(t, "Checkout", a.ActionName)
	assert.Equal(t, inputs, a.ActionInputs)
	assert.Equal(t, outputs, a.ActionOutputs)
	assert.Equal(t, 0, a.ExitCode)
	assert.Equal(t, "/tmp/actions/checkout", a.ActionDir)
}

func newTestContext(t *testing.T) *attestation.AttestationContext {
	t.Helper()
	actx, err := attestation.NewContext("test", nil, attestation.WithContext(context.Background()))
	require.NoError(t, err)
	return actx
}

func TestAttest(t *testing.T) {
	t.Setenv("GITHUB_RUN_ID", "12345")
	t.Setenv("GITHUB_WORKFLOW", "CI")
	t.Setenv("GITHUB_JOB", "build")

	a := New(WithActionRef("actions/checkout@v4"))
	err := a.Attest(newTestContext(t))
	require.NoError(t, err)

	assert.Equal(t, "12345", a.RunID)
	assert.Equal(t, "CI", a.WorkflowName)
	assert.Equal(t, "build", a.JobName)
}

func TestAttestNoEnv(t *testing.T) {
	a := New(WithActionRef("actions/checkout@v4"))
	err := a.Attest(newTestContext(t))
	require.NoError(t, err)

	assert.Empty(t, a.RunID)
	assert.Empty(t, a.WorkflowName)
	assert.Empty(t, a.JobName)
}

func TestAttestWithExecuteFunc(t *testing.T) {
	executed := false
	a := New(
		WithActionRef("actions/checkout@v4"),
		WithExecuteFunc(func(_ context.Context) (int, error) {
			executed = true
			return 0, nil
		}),
	)
	err := a.Attest(newTestContext(t))
	require.NoError(t, err)
	assert.True(t, executed)
	assert.Equal(t, 0, a.ExitCode)
}

func TestAttestWithExecuteFuncError(t *testing.T) {
	a := New(
		WithActionRef("test/action@v1"),
		WithExecuteFunc(func(_ context.Context) (int, error) {
			return 1, fmt.Errorf("action failed")
		}),
	)
	err := a.Attest(newTestContext(t))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "action execution failed")
	assert.Equal(t, 1, a.ExitCode)
}

func TestAttestWithoutExecuteFunc(t *testing.T) {
	// Attest should work fine without an execute function (metadata-only mode)
	a := New(WithActionRef("actions/checkout@v4"))
	err := a.Attest(newTestContext(t))
	require.NoError(t, err)
	assert.Equal(t, 0, a.ExitCode)
}

func TestSubjects(t *testing.T) {
	a := New(WithActionRef("actions/checkout@v4"))
	subjects := a.Subjects()
	assert.Len(t, subjects, 1)
	assert.Contains(t, subjects, "actionref:actions/checkout@v4")
}

func TestSubjectsEmpty(t *testing.T) {
	a := New()
	subjects := a.Subjects()
	assert.Empty(t, subjects)
}

func TestSchema(t *testing.T) {
	a := New()
	schema := a.Schema()
	assert.NotNil(t, schema)
}

func TestRegistration(t *testing.T) {
	// Verify the attestor registered itself via init()
	// This is implicitly tested by importing the package,
	// but we verify the constants are correct.
	assert.Equal(t, "github-action", Name)
	assert.Equal(t, "https://aflock.ai/attestations/github-action/v0.1", Type)
}
