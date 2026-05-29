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

package attestation

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/invopop/jsonschema"
)

type optAttestor struct {
	plugin string
	export bool
	maxRow int
	tags   []string
}

func (a *optAttestor) Name() string                     { return "opt-test" }
func (a *optAttestor) Type() string                     { return "https://aflock.ai/test/opt/v0.1" }
func (a *optAttestor) RunType() RunType                 { return PostProductRunType }
func (a *optAttestor) Schema() *jsonschema.Schema       { return jsonschema.Reflect(a) }
func (a *optAttestor) Attest(*AttestationContext) error { return nil }

func registerOptAttestor() {
	RegisterAttestation("opt-test", "https://aflock.ai/test/opt/v0.1", PostProductRunType,
		func() Attestor { return &optAttestor{} },
		registry.StringConfigOption("plugin", "", "", func(a Attestor, v string) (Attestor, error) {
			a.(*optAttestor).plugin = v
			return a, nil
		}),
		registry.BoolConfigOption("export", "", false, func(a Attestor, v bool) (Attestor, error) {
			a.(*optAttestor).export = v
			return a, nil
		}),
		registry.IntConfigOption("max-rows", "", 0, func(a Attestor, v int) (Attestor, error) {
			a.(*optAttestor).maxRow = v
			return a, nil
		}),
		registry.StringSliceConfigOption("tags", "", nil, func(a Attestor, v []string) (Attestor, error) {
			a.(*optAttestor).tags = v
			return a, nil
		}),
	)
}

func TestApplyAttestorOptions(t *testing.T) {
	registerOptAttestor()

	t.Run("applies typed values through registered setters", func(t *testing.T) {
		at, err := GetAttestor("opt-test")
		if err != nil {
			t.Fatalf("GetAttestor: %v", err)
		}
		out, err := ApplyAttestorOptions("opt-test", at, map[string]any{
			"plugin":   "aws",
			"export":   true,
			"max-rows": 250,             // plain int (Go caller)
			"tags":     []any{"a", "b"}, // []any (YAML sequence shape)
		})
		if err != nil {
			t.Fatalf("ApplyAttestorOptions: %v", err)
		}
		oa := out.(*optAttestor)
		if oa.plugin != "aws" || !oa.export || oa.maxRow != 250 {
			t.Errorf("options not applied: %+v", oa)
		}
		if len(oa.tags) != 2 || oa.tags[0] != "a" || oa.tags[1] != "b" {
			t.Errorf("string-slice option not applied: %v", oa.tags)
		}
	})

	t.Run("nil/empty values is a no-op returning the same attestor", func(t *testing.T) {
		at, _ := GetAttestor("opt-test")
		out, err := ApplyAttestorOptions("opt-test", at, nil)
		if err != nil || out != at {
			t.Errorf("expected no-op for empty values; err=%v same=%v", err, out == at)
		}
	})

	t.Run("unknown option fails loudly", func(t *testing.T) {
		at, _ := GetAttestor("opt-test")
		if _, err := ApplyAttestorOptions("opt-test", at, map[string]any{"bogus": "x"}); err == nil {
			t.Error("expected error for unknown option, got nil")
		}
	})

	t.Run("type mismatch fails loudly", func(t *testing.T) {
		at, _ := GetAttestor("opt-test")
		if _, err := ApplyAttestorOptions("opt-test", at, map[string]any{"plugin": 123}); err == nil {
			t.Error("expected error for type mismatch (int into string option), got nil")
		}
	})
}
