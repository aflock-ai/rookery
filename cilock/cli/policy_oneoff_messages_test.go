// jade:ring local
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
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// One-off friction items from the onboarding simulator. Each refusal must
// name the command or edit that fixes it, with the author's own values.

// mx-python-click-l3: the agent ran `template -o <new> --add-step push-checks
// --attestor ...` to start a one-step draft, and was told to add -p with a
// placeholder "..." and the default path, not its own.
func TestAddStepWithoutADraftNamesBothCommandsWithTheAuthorsFlags(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "-o", out, "--add-step", "push-checks",
		"--attestor", "command-run", "--attestor", "test-results", "--force")
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "--add-step appends a step to an existing draft named by -p")
	require.Contains(t, msg, "`cilock policy template --goal <id> -o '"+out+"'`")
	require.Contains(t, msg, "`cilock policy template -p '"+out+"' --add-step push-checks --attestor command-run --attestor test-results`")
	require.NotContains(t, msg, "...")
}

// A --fill on a rule that already holds a value named no path and no value.
func TestFillOnAFilledRuleNamesThePathAndTheCurrentPin(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "tests", "-o", out, "--fill", `tests.command-pin=["go","test","./..."]`)
	require.NoError(t, err)
	_, err = templateCmd(t, "-p", out, "--fill", `tests.command-pin=["pytest"]`)
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "rule command-pin is not an unfilled slot: it already holds a value")
	require.Contains(t, msg, `it pins ["go","test","./..."]`)
	require.Contains(t, msg, "steps.tests.attestations[0].regopolicies[1].module")
	require.Contains(t, msg, "Next:")
}

// mx-python-click-l3: `prove needs a command ... pass --run push-checks='<argv>'`
// left the argv syntax to guess.
func TestProveNeedsACommandShowsAConcreteArgv(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "app-build", "-o", e.draft, "--fill", `app-build.command-pin=["true"]`)
	// A hand-written step with no command-pin rule: nothing tells prove what to run.
	doc := readDraft(t, e.draft)
	app := asMap(draftSteps(doc)["app-build"])
	draftSteps(doc)["push-checks"] = map[string]any{
		"name":          "push-checks",
		"functionaries": app["functionaries"],
		"attestations":  []any{map[string]any{"type": typeCommandRun}},
	}
	require.NoError(t, saveDraft(e.draft, doc, false))
	err := e.prove(t)
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, "prove needs a command for step(s) push-checks")
	require.Contains(t, msg, `--run push-checks='["<command>","<arg>"]'`)
	require.Contains(t, msg, "a JSON array or plain words")
}
