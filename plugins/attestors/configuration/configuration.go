// Copyright 2025 The Witness Contributors
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

package configuration

import (
	"os"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/invopop/jsonschema"
)

const (
	Name = "configuration"
	// Type is v0.2: the v0.1 predicate additionally carried config_path /
	// config_digest / config_content captured from the legacy .witness.yaml
	// config file. cilock is args-only now, so those fields were removed —
	// an output-shape change, hence the version bump (same convention as
	// product/material). Policies keyed to v0.1 do not match v0.2 evidence.
	Type    = "https://aflock.ai/attestations/configuration/v0.2"
	RunType = attestation.PreMaterialRunType
)

var (
	_ attestation.Attestor = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

// Option configures an Attestor.
type Option func(*Attestor)

// WithCustomArgs overrides os.Args for testing.
func WithCustomArgs(args []string) Option {
	return func(a *Attestor) {
		a.osArgs = func() []string { return args }
	}
}

// Attestor captures the raw CLI flags that drove this run. cilock is
// args-only: there is no config file, so flags (plus the working
// directory) are the complete configuration surface this attestor can
// observe. Environment variables are captured by the `environment`
// attestor instead.
type Attestor struct {
	Flags      map[string]string `json:"flags,omitempty"`
	WorkingDir string            `json:"working_directory,omitempty"`

	osArgs func() []string
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		osArgs: func() []string { return os.Args },
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

func (a *Attestor) Data() *Attestor {
	return a
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	args := a.osArgs()

	// Extract witness args (everything before "--")
	witnessArgs := extractWitnessArgs(args)

	// Parse flags from witness args
	a.Flags = parseFlags(witnessArgs)

	// Capture working directory
	wd, err := os.Getwd()
	if err == nil {
		a.WorkingDir = wd
	}

	return nil
}

// extractWitnessArgs returns CLI args up to (but not including) the "--" separator.
// If no separator is found, returns all args after the program name.
func extractWitnessArgs(args []string) []string {
	if len(args) <= 1 {
		return nil
	}

	// Skip program name
	args = args[1:]

	for i, arg := range args {
		if arg == "--" {
			return args[:i]
		}
	}
	return args
}

// parseFlags extracts flag name/value pairs from CLI arguments.
// Handles: --flag value, -f value, --flag=value, -f=value, --flag (boolean).
func parseFlags(args []string) map[string]string {
	flags := make(map[string]string)

	for i := 0; i < len(args); i++ {
		arg := args[i]

		if !strings.HasPrefix(arg, "-") {
			continue
		}

		// Strip leading dashes
		arg = strings.TrimLeft(arg, "-")

		// Handle --flag=value or -f=value
		if idx := strings.Index(arg, "="); idx >= 0 {
			flags[arg[:idx]] = arg[idx+1:]
			continue
		}

		// Check if next arg is a value (doesn't start with -)
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			flags[arg] = args[i+1]
			i++
		} else {
			// Boolean flag
			flags[arg] = "true"
		}
	}

	return flags
}
