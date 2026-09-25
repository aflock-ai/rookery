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

// Package githubaction implements an attestor that captures metadata about
// GitHub Action execution. Unlike commandrun which executes a subprocess,
// this attestor records pre-set action metadata. The actual action execution
// happens separately via the action runner.
package githubaction

import (
	"context"
	"crypto"
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	Name = "github-action"
	// Type is the current predicate: v0.1 plus the resolved action.yml digest
	// and the composite `run:` steps that executed.
	Type = "https://aflock.ai/attestations/github-action/v0.2"
	// LegacyV01Type is the predicate before steps were recorded. It stays
	// registered so every stored v0.1 envelope keeps decoding, and it is still
	// EMITTED for a body that carries none of the v0.2 fields (see Type()).
	LegacyV01Type = "https://aflock.ai/attestations/github-action/v0.1"
	RunType       = attestation.ExecuteRunType
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	// One attestor, two predicate URIs. v0.2 is v0.1 plus optional fields, so a
	// v0.1 body decodes into the same struct unchanged.
	attestation.RegisterAttestationWithTypes(Name, []string{Type, LegacyV01Type}, RunType, func() attestation.Attestor {
		return New()
	})
}

// ExecuteFunc is a function that executes the action and returns an exit code.
type ExecuteFunc func(ctx context.Context) (int, error)

// DockerContainerConfig records the Docker container configuration used to run an action.
// This is captured for attestation auditability so policy engines can verify
// the container was run with expected security settings.
type DockerContainerConfig struct {
	Image      string   `json:"image,omitempty"`
	Network    string   `json:"network,omitempty"`
	Workspace  string   `json:"workspace,omitempty"`
	Entrypoint string   `json:"entrypoint,omitempty"`
	EnvCount   int      `json:"envcount,omitempty"`
	Args       []string `json:"args,omitempty"`
}

// RunStep records one composite-action `run:` step, in execution order.
type RunStep struct {
	// Index is the step's position in its action's runs.steps.
	Index int `json:"index"`
	// Name is the step's name, or step-<n> when it has none.
	Name string `json:"name,omitempty"`
	// Action is the nested action the step belongs to; empty for a step of the
	// wrapped action itself.
	Action string `json:"action,omitempty"`
	// Shell is the shell the step declared, or the default it ran under.
	Shell string `json:"shell,omitempty"`
	// WorkingDirectory is the step's working-directory, as declared.
	WorkingDirectory string `json:"workingDirectory,omitempty"`
	// Digest is the digest of the exact bytes handed to the interpreter.
	// Absent for a skipped step, which handed nothing to anything.
	Digest cryptoutil.DigestSet `json:"digest,omitempty"`
	// Script is those bytes, present only under content capture.
	Script string `json:"script,omitempty"`
	// ExitCode is the interpreter's exit status.
	ExitCode int `json:"exitCode"`
	// Skipped reports that the step's `if:` evaluated false and it did not run.
	Skipped bool `json:"skipped,omitempty"`
}

// Attestor captures metadata about a GitHub Action execution.
type Attestor struct {
	ActionRef     string            `json:"actionref"`
	ActionType    string            `json:"actiontype"`
	ActionName    string            `json:"actionname,omitempty"`
	ActionInputs  map[string]string `json:"actioninputs,omitempty"`
	ActionOutputs map[string]string `json:"actionoutputs,omitempty"`
	ExitCode      int               `json:"exitcode"`
	ActionDir     string            `json:"actiondir,omitempty"`
	RefPinned     bool              `json:"refpinned,omitempty"`

	// Docker container configuration (populated for docker actions)
	Docker *DockerContainerConfig `json:"docker,omitempty"`

	// ActionYAMLDigest is the digest of the resolved action.yml, the file that
	// decided what ran. (v0.2)
	ActionYAMLDigest cryptoutil.DigestSet `json:"actionyamldigest,omitempty"`

	// Steps are the composite `run:` steps, in execution order. (v0.2)
	Steps []RunStep `json:"steps,omitempty"`

	// GitHub context (from env vars when available)
	RunID        string `json:"runid,omitempty"`
	WorkflowName string `json:"workflowname,omitempty"`
	JobName      string `json:"jobname,omitempty"`

	// executeFunc, if set, is called during Attest() to run the action.
	// This allows the attestor to execute code during the Execute phase
	// (between material and product attestors), similar to commandrun.
	executeFunc ExecuteFunc
}

// Option configures the attestor.
type Option func(*Attestor)

// WithActionRef sets the action reference (e.g. "actions/checkout@v4").
func WithActionRef(ref string) Option {
	return func(a *Attestor) {
		a.ActionRef = ref
	}
}

// WithActionType sets the action type (e.g. "javascript", "docker", "composite").
func WithActionType(t string) Option {
	return func(a *Attestor) {
		a.ActionType = t
	}
}

// WithActionName sets the action name from action.yml.
func WithActionName(name string) Option {
	return func(a *Attestor) {
		a.ActionName = name
	}
}

// WithActionInputs sets the user-provided action inputs.
func WithActionInputs(inputs map[string]string) Option {
	return func(a *Attestor) {
		a.ActionInputs = inputs
	}
}

// WithActionOutputs sets the captured action outputs.
func WithActionOutputs(outputs map[string]string) Option {
	return func(a *Attestor) {
		a.ActionOutputs = outputs
	}
}

// WithExitCode sets the exit code from action execution.
func WithExitCode(code int) Option {
	return func(a *Attestor) {
		a.ExitCode = code
	}
}

// WithActionDir sets the resolved local path of the action.
func WithActionDir(dir string) Option {
	return func(a *Attestor) {
		a.ActionDir = dir
	}
}

// WithDockerConfig records the Docker container configuration used to run the action.
func WithDockerConfig(cfg *DockerContainerConfig) Option {
	return func(a *Attestor) {
		a.Docker = cfg
	}
}

// WithActionYAMLDigest records the digest of the resolved action.yml.
func WithActionYAMLDigest(ds cryptoutil.DigestSet) Option {
	return func(a *Attestor) {
		a.ActionYAMLDigest = ds
	}
}

// WithRefPinned records whether the action ref was pinned to a commit SHA.
func WithRefPinned(pinned bool) Option {
	return func(a *Attestor) {
		a.RefPinned = pinned
	}
}

// WithExecuteFunc sets a function to execute during the Attest() phase.
// This is called between material and product attestors, allowing the
// action's file-system side effects to be captured by the product attestor.
func WithExecuteFunc(fn ExecuteFunc) Option {
	return func(a *Attestor) {
		a.executeFunc = fn
	}
}

// SetExecuteFunc sets the execute function after construction.
// This is needed when the execute function needs to capture the attestor
// itself (e.g., to set Docker config after execution).
func (a *Attestor) SetExecuteFunc(fn ExecuteFunc) {
	a.executeFunc = fn
}

// New creates a new github-action attestor.
func New(opts ...Option) *Attestor {
	a := &Attestor{
		ActionInputs:  make(map[string]string),
		ActionOutputs: make(map[string]string),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Attestor) Name() string { return Name }

// Type reports the predicate version of the body as it stands.
//
// It is v0.2 exactly when a v0.2 field is populated. The signed release
// policies (deploy/dist/release-policy-*.signed.json) require github-action/v0.1
// from `cilock run --attestations github-action`, which records no steps and no
// action.yml; labelling that unchanged body v0.2 would fail every release
// verification without the body changing at all. A body that does carry steps
// is never labelled v0.1, so no v0.1 consumer sees a shape it cannot read.
func (a *Attestor) Type() string {
	if len(a.ActionYAMLDigest) > 0 || len(a.Steps) > 0 {
		return Type
	}
	return LegacyV01Type
}

func (a *Attestor) RunType() attestation.RunType { return RunType }

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

// Attest executes the action (if an execute function is set) and populates
// GitHub context from environment variables.
func (a *Attestor) Attest(actx *attestation.AttestationContext) error {
	// If an execute function is set, run it during this phase.
	// This happens between material and product attestors, so file-system
	// side effects are captured properly.
	if a.executeFunc != nil {
		exitCode, err := a.executeFunc(actx.Context())
		a.ExitCode = exitCode
		if err != nil {
			return fmt.Errorf("action execution failed (exit code %d): %w", exitCode, err)
		}
	}

	// Populate GitHub context from environment
	if v := os.Getenv("GITHUB_RUN_ID"); v != "" {
		a.RunID = v
	}
	if v := os.Getenv("GITHUB_WORKFLOW"); v != "" {
		a.WorkflowName = v
	}
	if v := os.Getenv("GITHUB_JOB"); v != "" {
		a.JobName = v
	}
	return nil
}

// Subjects returns the action reference as a subject for indexing.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	if a.ActionRef != "" {
		hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.ActionRef), hashes)
		if err == nil {
			subjects["actionref:"+a.ActionRef] = ds
		}
	}
	return subjects
}
