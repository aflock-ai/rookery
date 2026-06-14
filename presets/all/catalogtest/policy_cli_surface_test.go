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

package catalogtest

import (
	"testing"

	"github.com/aflock-ai/rookery/cilock/cli"
	"github.com/spf13/cobra"
)

// TestPolicyCLISurface guards the build wiring that lets cilock-all expose the
// FULL policy CLI. cilock-all is built from presets/all (cmd/cilock-all), which
// imports github.com/aflock-ai/rookery/cilock/cli. If presets/all/go.mod pins a
// stale published cilock instead of locally replacing it with ../../cilock, the
// resolved cilock/cli predates the push/bind/from-commit/from-bundles policy
// subcommands and `cilock-all policy --help` regresses to only `validate`.
//
// This test compiles + resolves cli.New() through THIS module's go.mod, so it
// fails (compile error or assertion) whenever the cilock dependency drifts
// behind the in-tree cilock that ships those subcommands.
func TestPolicyCLISurface(t *testing.T) {
	root := cli.New()

	policy := findSubcommand(root.Commands(), "policy")
	if policy == nil {
		t.Fatal("cilock root command has no `policy` subcommand")
	}

	// The full policy authoring/release surface that the in-tree cilock ships.
	want := []string{"validate", "from-bundles", "from-commit", "push", "bind"}
	for _, name := range want {
		if findSubcommand(policy.Commands(), name) == nil {
			t.Errorf("policy subcommand %q is missing — presets/all is resolving a stale cilock; "+
				"ensure go.mod has `replace github.com/aflock-ai/rookery/cilock => ../../cilock`", name)
		}
	}
}

// findSubcommand returns the cobra command whose name equals name, or nil.
func findSubcommand(cmds []*cobra.Command, name string) *cobra.Command {
	for _, c := range cmds {
		if c.Name() == name {
			return c
		}
	}
	return nil
}
