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
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// The --attestor-* flags only exist when their attestor plugin is
	// registered (init() side-effect), exactly as cmd/cilock/main.go links
	// them in the shipped binary. Blank-import every plugin referenced by
	// an Example so the validator parses against the real flag set rather
	// than an empty registry. Add to this list when an example uses a new
	// --attestor-<name>-* flag.
	_ "github.com/aflock-ai/rookery/plugins/attestors/github-review"
)

// TestCommandExamplesAreValid enforces that every documented Example
// actually parses against the command it documents. This is the contract
// behind "all examples must be validated": rename a flag, and the example
// that used it fails CI here — the docs can't silently rot.
//
// Validation is parse-level (cobra ParseFlags): it proves every flag in
// the example exists, has the right type, and that the example invokes
// the command it's attached to. It deliberately does not execute the
// command (that needs keys, a toolchain, network) — execution is covered
// by the manual red-team pass recorded in the PR.
func TestCommandExamplesAreValid(t *testing.T) {
	var checked int
	walkCommands(New(), func(cmd *cobra.Command) {
		ex := strings.TrimSpace(cmd.Example)
		if ex == "" {
			return
		}
		lines := exampleCommandLines(ex)
		require.NotEmptyf(t, lines, "%s: Example block has no runnable `cilock ...` line", cmd.CommandPath())

		for _, line := range lines {
			checked++
			t.Run(cmd.CommandPath()+": "+line, func(t *testing.T) {
				tokens := tokenizeExample(t, line)

				// Resolve the example against a *fresh* tree so flag state
				// from one example never leaks into the next.
				target, rest, err := New().Find(tokens)
				require.NoErrorf(t, err, "could not resolve command for example: %s", line)

				assert.Equalf(t, cmd.CommandPath(), target.CommandPath(),
					"example is attached to %q but invokes %q", cmd.CommandPath(), target.CommandPath())

				// ParseFlags is the validation: unknown flag, wrong type, or
				// a missing value all surface here.
				err = target.ParseFlags(rest)
				assert.NoErrorf(t, err, "example failed to parse: %s", line)
			})
		}
	})

	assert.Positive(t, checked, "no examples were validated — did the Example fields disappear?")
}

// walkCommands invokes fn for cmd and every subcommand, depth-first.
func walkCommands(cmd *cobra.Command, fn func(*cobra.Command)) {
	fn(cmd)
	for _, c := range cmd.Commands() {
		walkCommands(c, fn)
	}
}

// exampleCommandLines returns the runnable command lines in an Example
// block: lines that (after trimming) begin with "cilock". Comment lines
// (`#`) and blanks are skipped.
func exampleCommandLines(example string) []string {
	var out []string
	for raw := range strings.SplitSeq(example, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "cilock ") || line == "cilock" {
			out = append(out, line)
		}
	}
	return out
}

// tokenizeExample turns one example line into the argv cobra would see,
// minus the leading "cilock". It strips any shell pipeline (everything
// from the first " | " onward) so examples may pipe into jq/grep without
// the downstream tool tripping the parser. It rejects quoting other than
// the empty-string argument `""` (used for opt-out flags like
// --platform-url ""), keeping the tokenizer trivial and the examples
// shell-simple.
func tokenizeExample(t *testing.T, line string) []string {
	t.Helper()

	if i := strings.Index(line, " | "); i >= 0 {
		line = line[:i]
	}

	fields := strings.Fields(line)
	require.NotEmpty(t, fields)
	require.Equal(t, "cilock", fields[0], "example must start with `cilock`")

	out := make([]string, 0, len(fields)-1)
	for _, f := range fields[1:] {
		require.NotContainsf(t, f, "'", "examples must avoid single-quotes (keep them shell-simple): %q", line)
		// Normalize the only quoted form we permit: an explicit empty arg.
		if f == `""` {
			out = append(out, "")
			continue
		}
		require.NotContainsf(t, f, `"`, "examples must avoid embedded double-quotes (keep them shell-simple): %q", line)
		out = append(out, f)
	}
	return out
}
