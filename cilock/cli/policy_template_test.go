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
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	internalpolicy "github.com/aflock-ai/rookery/cilock/internal/policy"
	"github.com/stretchr/testify/require"
)

const (
	authoringPlatform = "https://platform.example.invalid"
	testTrustDomain   = "platform.example.invalid"
	testTenant        = "3f1c8a52-0000-4000-8000-00000000abcd"
)

// sandboxCredentials isolates the credential store; enrolled also stores a
// redeemed agent principal for authoringPlatform.
func sandboxCredentials(t *testing.T, enrolled bool) {
	t.Helper()
	dir := t.TempDir()
	state, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(state, 0o700))
	t.Setenv("HOME", state)
	t.Setenv("XDG_CONFIG_HOME", state)
	t.Setenv("CILOCK_STATE_DIR", state)
	t.Setenv("CILOCK_SKIP_VERSION_CHECK", "1")
	t.Setenv("CILOCK_NO_TELEMETRY", "1")
	if enrolled {
		require.NoError(t, auth.SaveAgent(auth.AgentCredential{
			PlatformURL: authoringPlatform, TenantID: testTenant, AgentID: "agent-1",
			TrustDomain: testTrustDomain, RefreshCredential: "synthetic-not-a-secret",
			ExpiresAt: time.Now().Add(time.Hour),
		}))
	}
	orig := discoverPushgateOrigin
	discoverPushgateOrigin = func(string) (string, error) { return "https://pushgate.example.invalid", nil }
	t.Cleanup(func() { discoverPushgateOrigin = orig })
}

func templateCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	stdout, _, err := executeCmdOutput(append([]string{"policy", "template", "--platform-url", authoringPlatform}, args...)...)
	return stdout, err
}

func readDraft(t *testing.T, path string) map[string]any {
	t.Helper()
	doc, err := loadDraft(path)
	require.NoError(t, err)
	return doc
}

func validateErrors(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	return internalpolicy.ValidateRawPolicy(context.Background(), raw).Errors
}

// requireOnlyPlatformPlaceholders asserts a draft validates as an unsigned
// draft whose only gap is the two platform trust placeholders. Before the
// validator learned the placeholder rule this was the one expected error
// "Root 'fulcio-root': missing certificate data".
func requireOnlyPlatformPlaceholders(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	res := internalpolicy.ValidateRawPolicy(context.Background(), raw)
	require.Empty(t, res.Errors)
	require.True(t, res.Valid)
	require.Equal(t, []string{"roots." + platformFulcioRoot, "timestampauthorities." + platformTSA}, res.Placeholders)
}

func TestTemplateRefusesWithoutAnEnrolledAgent(t *testing.T) {
	sandboxCredentials(t, false)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "tests", "-o", out)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no enrolled agent principal")
	require.Contains(t, err.Error(), "cilock enroll agent --repo <owner/repo>", "the error names the next command")
	require.NoFileExists(t, out)
}

func TestTemplateWritesThePartsAgentsGetWrong(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), ".pushgate", "policy.json")
	stdout, err := templateCmd(t, "--goal", "tests", "--goal", "quality", "--goal", "app-build", "--goal", "secrets", "-o", out)
	require.NoError(t, err)
	require.Contains(t, stdout, "slot(s) to fill")

	doc := readDraft(t, out)
	require.Equal(t, map[string]any{"fulcio-root": map[string]any{"certificate": ""}}, doc["roots"])
	require.Equal(t, map[string]any{"platform-tsa": map[string]any{"certificate": ""}}, doc["timestampauthorities"])
	expires, err := time.Parse(time.RFC3339, doc["expires"].(string))
	require.NoError(t, err)
	require.WithinDuration(t, time.Now().AddDate(1, 0, 0), expires, 48*time.Hour)
	require.Equal(t, 0, expires.Hour(), "expires is a UTC midnight, as the brief spells it")

	steps := draftSteps(doc)
	require.ElementsMatch(t, []string{"tests", "quality", "app-build", "secrets"}, sortedStepNames(doc))
	for _, name := range sortedStepNames(doc) {
		step := asMap(steps[name])
		require.Equal(t, name, step["name"])
		funcs := asList(step["functionaries"])
		require.Len(t, funcs, 1)
		cc := asMap(asMap(funcs[0])["certConstraint"])
		require.Equal(t, "root", asMap(funcs[0])["type"])
		require.Equal(t, "*", cc["commonname"])
		require.Equal(t, []any{"*"}, cc["dnsnames"])
		require.Equal(t, []any{"*"}, cc["emails"])
		require.Equal(t, []any{"*"}, cc["organizations"])
		require.Equal(t, []any{"spiffe://" + testTrustDomain + "/tenant/" + testTenant + "/agent/*"}, cc["uris"])
		require.Equal(t, []any{"fulcio-root"}, cc["roots"])
	}
	require.Equal(t, []string{typeCommandRun, typeTestResults}, stepAttestationTypes(asMap(steps["tests"])))
	require.Equal(t, []string{typeCommandRun, typeLeakScan}, stepAttestationTypes(asMap(steps["secrets"])))

	slots := findFillSlots(doc)
	require.Len(t, slots, 3, "tests, quality and app-build each pin a command; secrets needs none: %v", slots)
	for _, s := range slots {
		require.Contains(t, s, "__FILL__ command-pin:")
		require.Contains(t, s, "--fill ")
	}
	errs := validateErrors(t, out)
	require.NotEmpty(t, errs, "an unfilled slot must not validate")
	joined := strings.Join(errs, "\n")
	require.Contains(t, joined, "unfilled template slot")
}

func TestTemplateFilledDraftValidatesWithOnlyThePlatformPlaceholders(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "tests", "--goal", "secrets", "--goal", "vulns", "-o", out,
		"--fill", `tests.command-pin=["gotestsum","--junitfile","junit.xml","./..."]`,
		"--fill", `vulns.command-pin=["sh","-c","govulncheck -json ./... > govulncheck.json"]`)
	require.NoError(t, err)
	require.Empty(t, findFillSlots(readDraft(t, out)))
	requireOnlyPlatformPlaceholders(t, out)

	// The pinned argv is what prove will run.
	argv, ok := pinnedArgv(asMap(draftSteps(readDraft(t, out))["tests"]))
	require.True(t, ok)
	require.Equal(t, []string{"gotestsum", "--junitfile", "junit.xml", "./..."}, argv)
}

func TestTemplateNeverOverwritesADraft(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(out, []byte(`{"mine":true}`), 0o600))
	_, err := templateCmd(t, "--goal", "tests", "-o", out)
	require.Error(t, err)
	require.Contains(t, err.Error(), "--add-step")
	raw, _ := os.ReadFile(out)
	require.Equal(t, `{"mine":true}`, string(raw))
	_, err = templateCmd(t, "--goal", "tests", "-o", out, "--force")
	require.NoError(t, err)
}

func TestTemplateFillRefusesARuleThatIsNotASlot(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "tests", "-o", out)
	require.NoError(t, err)
	_, err = templateCmd(t, "-p", out, "--fill", `tests.command-succeeded=["x"]`)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not an unfilled slot")
	_, err = templateCmd(t, "-p", out, "--fill", `tests.command-pin=[]`)
	require.Error(t, err, "an empty argv pins nothing")
	_, err = templateCmd(t, "-p", out, "--fill", `tests.command-pin=["go","test","./..."]`)
	require.NoError(t, err)
	_, err = templateCmd(t, "-p", out, "--fill", `tests.command-pin=["other"]`)
	require.Error(t, err, "a filled slot is the model's rule now, and template never overwrites a rule")
}

// Step names may contain dots, so --fill resolves "<step>.<rule>" against the
// draft's own steps instead of splitting at the first dot: tests.unit's slot
// is filled, and step tests beside it is left alone.
func TestTemplateFillResolvesADottedStepName(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "tests", "-o", out)
	require.NoError(t, err)
	_, err = templateCmd(t, "-p", out, "--add-step", "tests.unit", "--goal", "tests")
	require.NoError(t, err)

	_, err = templateCmd(t, "-p", out, "--fill", `tests.unit.command-pin=["go","test","./unit/..."]`)
	require.NoError(t, err)
	steps := draftSteps(readDraft(t, out))
	argv, ok := pinnedArgv(asMap(steps["tests.unit"]))
	require.True(t, ok)
	require.Equal(t, []string{"go", "test", "./unit/..."}, argv)
	mod, _ := findRegoEntry(asMap(steps["tests"]), ruleCommandPin)["module"].(string)
	require.True(t, strings.HasPrefix(mod, fillMarker), "step tests must keep its own slot")

	_, err = templateCmd(t, "-p", out, "--fill", `tests.command-pin=["go","test","./..."]`)
	require.NoError(t, err)
	argv, ok = pinnedArgv(asMap(draftSteps(readDraft(t, out))["tests"]))
	require.True(t, ok)
	require.Equal(t, []string{"go", "test", "./..."}, argv)

	_, err = templateCmd(t, "-p", out, "--fill", `tests.unit.nope=["x"]`)
	require.ErrorContains(t, err, "step tests.unit has no rule named nope")
	_, err = templateCmd(t, "-p", out, "--fill", `other.command-pin=["x"]`)
	require.ErrorContains(t, err, "no step of the draft prefixes it")
}

func TestTemplateAddStep(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "app-build", "-o", out, "--fill", `app-build.command-pin=["make","build"]`)
	require.NoError(t, err)
	before := readDraft(t, out)
	buildBefore, err := json.Marshal(draftSteps(before)["app-build"])
	require.NoError(t, err)

	t.Run("a goal step", func(t *testing.T) {
		_, err := templateCmd(t, "-p", out, "--add-step", "tests", "--goal", "tests", "--artifacts-from", "app-build",
			"--fill", `tests.command-pin=["make","test"]`)
		require.NoError(t, err)
		doc := readDraft(t, out)
		step := asMap(draftSteps(doc)["tests"])
		require.Equal(t, []any{"app-build"}, step["artifactsFrom"])
		require.Equal(t, []string{typeCommandRun, typeTestResults}, stepAttestationTypes(step))
		buildAfter, err := json.Marshal(draftSteps(doc)["app-build"])
		require.NoError(t, err)
		require.JSONEq(t, string(buildBefore), string(buildAfter), "adding a step never touches another")
	})

	t.Run("a custom command-run step", func(t *testing.T) {
		_, err := templateCmd(t, "-p", out, "--add-step", "docs-build", "--attestor", "command-run",
			"--fill", `docs-build.command-pin=["mkdocs","build","--strict"]`)
		require.NoError(t, err)
		step := asMap(draftSteps(readDraft(t, out))["docs-build"])
		require.Equal(t, []string{typeCommandRun}, stepAttestationTypes(step))
		require.NotNil(t, findRegoEntry(step, ruleCommandSucceeded))
		argv, ok := pinnedArgv(step)
		require.True(t, ok)
		require.Equal(t, []string{"mkdocs", "build", "--strict"}, argv)
	})

	t.Run("a duplicate name is refused", func(t *testing.T) {
		_, err := templateCmd(t, "-p", out, "--add-step", "tests", "--goal", "tests")
		require.Error(t, err)
		require.Contains(t, err.Error(), "already has a step named tests")
	})

	t.Run("an edge to a missing step is refused", func(t *testing.T) {
		_, err := templateCmd(t, "-p", out, "--add-step", "package", "--attestor", "command-run", "--artifacts-from", "compile")
		require.Error(t, err)
		require.Contains(t, err.Error(), "does not have")
		_, err = templateCmd(t, "-p", out, "--add-step", "publish", "--attestor", "product", "--attestations-from", "nope")
		require.Error(t, err)
		_, err = templateCmd(t, "-p", out, "--add-step", "self", "--attestor", "product", "--artifacts-from", "self")
		require.Error(t, err)
		require.NotContains(t, sortedStepNames(readDraft(t, out)), "package")
	})

	t.Run("a cross-step products-from rule wires attestationsFrom", func(t *testing.T) {
		_, err := templateCmd(t, "-p", out, "--add-step", "publish", "--attestor", "command-run", "--rule", "products-from=app-build",
			"--fill", `publish.command-pin=["cp","bin/app","dist/app"]`)
		require.NoError(t, err)
		step := asMap(draftSteps(readDraft(t, out))["publish"])
		require.Equal(t, []any{"app-build"}, step["attestationsFrom"])
		entry := findRegoEntry(step, "products-from-app-build")
		require.NotNil(t, entry)
		src, err := base64.StdEncoding.DecodeString(entry["module"].(string))
		require.NoError(t, err)
		require.Contains(t, string(src), `upstream := "app-build"`)
	})

	requireOnlyPlatformPlaceholders(t, out)
}

func TestTemplateTracedAndVEX(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "app-build", "--traced", "--goal", "vulns", "--with-vex", "-o", out)
	require.NoError(t, err)
	doc := readDraft(t, out)
	build := asMap(draftSteps(doc)["app-build"])
	for _, id := range traceRuleIDs {
		require.NotNil(t, findRegoEntry(build, id), "trace rule %s", id)
	}
	slots := strings.Join(findFillSlots(doc), "\n")
	require.Contains(t, slots, "__FILL__ trace-network:")
	require.Contains(t, slots, "__FILL__ trace-exec:")
	require.Contains(t, slots, "__FILL__ trace-writes:")
	require.NotContains(t, slots, "trace-present:", "trace-present has nothing to fill")

	vulns := asMap(draftSteps(doc)["vulns"])
	require.Equal(t, []any{"vex"}, vulns["attestationsFrom"])
	require.NotNil(t, findRegoEntry(vulns, ruleGovulncheckVEX))
	require.Nil(t, findRegoEntry(vulns, ruleGovulncheckReachable), "with VEX, coverage replaces the reachability rule")
	require.Equal(t, []string{typeVEX}, stepAttestationTypes(asMap(draftSteps(doc)["vex"])))

	_, err = templateCmd(t, "-p", out, "--fill", `vulns.govulncheck-vex-covered={"vexStep":"vex","products":["pkg:golang/example.com/app"]}`,
		"--fill", `app-build.trace-network=[]`)
	require.NoError(t, err)
	require.NotContains(t, strings.Join(findFillSlots(readDraft(t, out)), "\n"), "govulncheck-vex-covered")
}

// Codex round 6 on #10195: a save that cannot complete must leave the draft
// as it was, never truncated. The draft's directory is made unwritable, so
// a save cannot create its temporary file; the draft itself stays writable,
// which is exactly the case a truncating write would have "succeeded" in.
func TestSaveDraftLeavesTheOriginalWhenItCannotComplete(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	original := []byte("{\n  \"expires\": \"2030-01-01T00:00:00Z\"\n}\n")
	require.NoError(t, os.WriteFile(path, original, 0o600))
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err := saveDraft(path, draftDoc{"expires": "2031-01-01T00:00:00Z"}, false)
	require.Error(t, err)
	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, string(original), string(after))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary file is left behind")
}

// Codex round 10 on #10195: a rule given with --rule attaches to the
// attestation already selected that carries it, not to the rule's canonical
// type as a second attestation the step would then also require.
func TestRuleAttachesToTheSelectedCompatibleAttestation(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "app-build", "-o", out)
	require.NoError(t, err)
	_, err = templateCmd(t, "-p", out, "--add-step", "inventory", "--attestor", typeSPDX, "--rule", ruleSBOMInventory)
	require.NoError(t, err)
	inventory := asMap(draftSteps(readDraft(t, out))["inventory"])
	require.Equal(t, []string{typeSPDX}, stepAttestationTypes(inventory), "SPDX alone; no CycloneDX requirement was added")
	require.NotNil(t, findRegoEntry(inventory, ruleSBOMInventory))
}

// Codex round 7 on #10195: creating a draft checked for an existing file
// and then renamed over whatever was there, so two creators racing past
// the check overwrote each other. A creating save is exclusive at the
// filesystem: it refuses a file that appeared since.
func TestCreateDraftNeverReplacesAFileThatAppeared(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	original := []byte("{\"expires\":\"first\"}\n")
	require.NoError(t, os.WriteFile(path, original, 0o600))
	err := saveDraft(path, draftDoc{"expires": "second"}, true)
	require.Error(t, err)
	require.ErrorIs(t, err, os.ErrExist)
	after, readErr := os.ReadFile(path)
	require.NoError(t, readErr)
	require.Equal(t, string(original), string(after))
	fresh := filepath.Join(t.TempDir(), "new.json")
	require.NoError(t, saveDraft(fresh, draftDoc{"expires": "x"}, true))
	require.Error(t, saveDraft(fresh, draftDoc{"expires": "y"}, true), "a second exclusive create refuses")
}

// Codex round 2 on #10195: inputs the template once accepted and then wrote
// a draft that did not say what was asked.
func TestTemplateRefusesAmbiguousSteps(t *testing.T) {
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "app-build", "--goal", "tests", "-o", out)
	require.NoError(t, err)
	before, err := os.ReadFile(out)
	require.NoError(t, err)

	t.Run("a scan step named vex collides with the VEX step --with-vex adds", func(t *testing.T) {
		_, err := templateCmd(t, "-p", out, "--add-step", "vex", "--goal", "vulns", "--with-vex")
		require.Error(t, err)
		require.Contains(t, err.Error(), "--with-vex adds a step named vex")
	})
	t.Run("a rule given twice is refused, not last-wins", func(t *testing.T) {
		_, err := templateCmd(t, "-p", out, "--add-step", "publish", "--attestor", "command-run",
			"--rule", "products-from=app-build", "--rule", "products-from=tests")
		require.Error(t, err)
		require.Contains(t, err.Error(), "--rule products-from is given twice")
	})
	t.Run("a draft whose steps is not an object is refused before any edit", func(t *testing.T) {
		// Codex round 9: --add-step replaced a non-object steps with an empty
		// map and saved, losing whatever the author had written there.
		bad := filepath.Join(t.TempDir(), "bad.json")
		doc := `{"expires":"2030-01-01T00:00:00Z","steps":[{"name":"build"}]}`
		require.NoError(t, os.WriteFile(bad, []byte(doc), 0o600))
		_, err := templateCmd(t, "-p", bad, "--add-step", "publish", "--attestor", "command-run")
		require.Error(t, err)
		require.Contains(t, err.Error(), "steps is not an object")
		after, err := os.ReadFile(bad)
		require.NoError(t, err)
		require.Equal(t, doc, string(after))
	})
	t.Run("a draft with a repeated key is refused before any edit", func(t *testing.T) {
		// Go's decoder keeps the last value, so an edit would drop what the
		// first "steps" held and the save would hide that it ever existed.
		dup := filepath.Join(t.TempDir(), "dup.json")
		doc := strings.TrimSpace(string(before))
		require.True(t, strings.HasSuffix(doc, "}"))
		require.NoError(t, os.WriteFile(dup, []byte(doc[:len(doc)-1]+`,"steps":{}}`), 0o600))
		dupBefore, err := os.ReadFile(dup)
		require.NoError(t, err)
		_, err = templateCmd(t, "-p", dup, "--add-step", "publish", "--attestor", "command-run")
		require.Error(t, err)
		require.Contains(t, err.Error(), "duplicate object key")
		dupAfter, err := os.ReadFile(dup)
		require.NoError(t, err)
		require.Equal(t, string(dupBefore), string(dupAfter))
	})
	after, err := os.ReadFile(out)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after), "a refused edit leaves the draft as it was")
}
