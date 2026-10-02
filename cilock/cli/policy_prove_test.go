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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func (e *proveEnv) template(t *testing.T, args ...string) {
	t.Helper()
	_, err := templateCmd(t, args...)
	require.NoError(t, err)
}

func (e *proveEnv) prove(t *testing.T, args ...string) error {
	t.Helper()
	full := append([]string{"policy", "prove", "--platform-url", authoringPlatform, "-p", e.draft, "-d", e.repo}, args...)
	stdout, stderr, err := executeCmdOutput(full...)
	e.stdout, e.stderr = stdout, stderr
	t.Logf("prove stdout:\n%s", stdout)
	return err
}

func (e *proveEnv) firstLine() string {
	line, _, _ := strings.Cut(e.stdout, "\n")
	return line
}

func (e *proveEnv) requireScratchGone(t *testing.T) {
	t.Helper()
	entries, err := os.ReadDir(e.tmp)
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, strings.HasPrefix(entry.Name(), "cilock-prove-"), "scratch dir %s left behind", entry.Name())
	}
}

// agentStep is a hand-written step: no template involved.
func agentStep(name string, attestations ...any) map[string]any {
	return map[string]any{
		"name":          name,
		"functionaries": []any{agentFunctionary(testTrustDomain, testTenant)},
		"attestations":  attestations,
	}
}

func TestProvePassingStep(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "app-build", "-o", e.draft,
		"--fill", `app-build.command-pin=["sh","-c","mkdir -p bin && printf app > bin/app"]`)
	require.NoError(t, e.prove(t))
	require.Equal(t, "Local verify: passed", e.firstLine())
	require.Contains(t, e.stdout, "step app-build: real run admitted; failing run refused (")
	require.Contains(t, e.stdout, "wrapped command exited 1, not 0")
	require.Contains(t, e.stdout, "validate: passed as an unsigned draft; roots.fulcio-root, timestampauthorities.platform-tsa are empty platform placeholders")
	require.Contains(t, e.stdout, "https://pushgate.example.invalid/policy/new?mode=manual")
	require.NotContains(t, e.stdout, "PROBLEM")
	e.requireScratchGone(t)
}

// The tests goal against a real JUnit report: one passing test admits, and a
// report with zero tests is refused, because zero tests passing is not tests
// passing.
func TestProveTestsGoalReadsTheRealReport(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "tests", "-o", e.draft,
		"--fill", `tests.command-pin=["sh","-c","printf '<testsuites><testsuite name=\"s\" tests=\"1\"><testcase name=\"a\"/></testsuite></testsuites>' > junit.xml"]`)
	require.NoError(t, e.prove(t))
	require.Equal(t, "Local verify: passed", e.firstLine())

	e2 := newProveEnv(t, true)
	e2.template(t, "--goal", "tests", "-o", e2.draft,
		"--fill", `tests.command-pin=["sh","-c","printf '<testsuites><testsuite name=\"s\" tests=\"0\"></testsuite></testsuites>' > junit.xml"]`)
	require.Error(t, e2.prove(t))
	require.Equal(t, "Local verify: REFUSED by tests: test-results: the report recorded 0 tests; zero tests passing is not tests passing", e2.firstLine())
}

func TestProveRefusedGoodEvidenceStillWritesTheDraft(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "app-build", "-o", e.draft, "--fill", `app-build.command-pin=["true"]`)
	out := filepath.Join(t.TempDir(), "handoff.json")
	err := e.prove(t, "-o", out)
	require.Error(t, err, "a refused real run exits non-zero")
	require.Equal(t, "Local verify: REFUSED by app-build: product: the step recorded no products; write the outputs under the working directory so they are recorded by digest", e.firstLine())
	require.FileExists(t, out, "the draft is written anyway, so the human can choose")
	requireOnlyPlatformPlaceholders(t, out)
	e.requireScratchGone(t)
}

func TestProveRefusesUnfilledSlots(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "tests", "-o", e.draft)
	err := e.prove(t)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unfilled slot")
	require.Contains(t, err.Error(), "steps.tests.attestations[0].regopolicies[1].module: __FILL__ command-pin:")
	require.Contains(t, err.Error(), "--fill <step>.<rule>=<json>")
	require.Empty(t, e.stdout, "nothing ran")
}

func TestProveNotEnrolledNamesTheNextCommand(t *testing.T) {
	e := newProveEnv(t, false)
	// A from-bundles style step: signed by a public key, not the agent.
	doc := draftDoc{"expires": "2099-01-01T00:00:00Z", "steps": map[string]any{"build": map[string]any{
		"name":          "build",
		"functionaries": []any{map[string]any{"type": "publickey", "publickeyid": "abc"}},
		"attestations":  []any{map[string]any{"type": typeCommandRun}},
	}}}
	require.NoError(t, saveDraft(e.draft, doc, false))
	err := e.prove(t, "--run", "build=true")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no enrolled agent principal")
	require.Contains(t, err.Error(), "cilock enroll agent")
}

func TestProveNormalizesAHandWrittenDraft(t *testing.T) {
	e := newProveEnv(t, true)
	doc := draftDoc{
		"steps": map[string]any{"build": map[string]any{
			"name":          "build",
			"functionaries": []any{map[string]any{"type": "publickey", "publickeyid": "abc"}},
			"attestations": []any{map[string]any{"type": typeCommandRun, "regopolicies": []any{
				map[string]any{"name": "exit", "module": module(commandSucceededModule)},
			}}},
		}},
		"publickeys": map[string]any{"abc": map[string]any{"keyid": "abc", "key": ""}},
		"roots":      map[string]any{"evidence-root": map[string]any{"certificate": "LS0tLS1CRUdJTg=="}},
	}
	require.NoError(t, saveDraft(e.draft, doc, false))
	require.NoError(t, e.prove(t, "--run", `build=["sh","-c","printf x > out.txt"]`))
	require.Equal(t, "Local verify: passed", e.firstLine())
	require.Contains(t, e.stdout, "normalized: step(s) build now name the enrolled agent")

	got := readDraft(t, e.draft)
	require.Equal(t, map[string]any{"fulcio-root": map[string]any{"certificate": ""}}, got["roots"])
	require.Equal(t, map[string]any{"platform-tsa": map[string]any{"certificate": ""}}, got["timestampauthorities"])
	require.NotContains(t, got, "publickeys")
	require.NotEmpty(t, got["expires"])
	funcs := asList(asMap(draftSteps(got)["build"])["functionaries"])
	require.Len(t, funcs, 1)
	require.Equal(t, []any{"spiffe://" + testTrustDomain + "/tenant/" + testTenant + "/agent/*"},
		asMap(asMap(funcs[0])["certConstraint"])["uris"])
	require.Equal(t, module(commandSucceededModule), asMap(asList(asMap(asList(asMap(draftSteps(got)["build"])["attestations"])[0])["regopolicies"])[0])["module"],
		"prove never rewrites a rule")
	requireOnlyPlatformPlaceholders(t, e.draft)
}

func TestProveHandWrittenStepBesideTemplatedOnesAndAStepWithNoRule(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "app-build", "-o", e.draft,
		"--fill", `app-build.command-pin=["sh","-c","mkdir -p bin && printf app > bin/app"]`)
	doc := readDraft(t, e.draft)
	steps := draftSteps(doc)
	steps["lint"] = agentStep("lint", map[string]any{"type": typeCommandRun, "regopolicies": []any{
		map[string]any{"name": "mine", "module": module("package mine\n\ndeny[msg] {\n\tinput.exitcode != 0\n\tmsg := \"lint failed\"\n}\n")},
	}})
	steps["unguarded"] = agentStep("unguarded", map[string]any{"type": typeCommandRun})
	require.NoError(t, saveDraft(e.draft, doc, false))

	err := e.prove(t, "--run", `lint=["sh","-c","exit 0"]`, "--step", "unguarded", "--", "true")
	require.Error(t, err, "a step that admits a failing run is a problem")
	require.Equal(t, "Local verify: passed", e.firstLine(), "the real evidence passes")
	require.Contains(t, e.stdout, "step lint: real run admitted; failing run refused (lint failed)")
	require.Contains(t, e.stdout, "PROBLEM: step unguarded admits a failing run: add a rule")
	e.requireScratchGone(t)
}

func TestProveNamesTheMissingCommand(t *testing.T) {
	e := newProveEnv(t, true)
	doc := draftDoc{"expires": "2099-01-01T00:00:00Z", "steps": map[string]any{
		"lint": agentStep("lint", map[string]any{"type": typeCommandRun, "regopolicies": []any{
			map[string]any{"name": ruleCommandSucceeded, "module": module(commandSucceededModule)}}}),
	}}
	require.NoError(t, saveDraft(e.draft, doc, false))
	err := e.prove(t)
	require.Error(t, err)
	require.Contains(t, err.Error(), `--run lint='["<command>","<arg>"]'`)
	require.Contains(t, err.Error(), "--step lint -- <command> <arg>...")
}

// build -> test chain with real evidence: the test step's materials must be
// the build step's products.
func TestProveChainBuildThenTest(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "app-build", "-o", e.draft,
		"--fill", `app-build.command-pin=["sh","-c","mkdir -p bin && printf v1 > bin/app"]`)
	e.template(t, "-p", e.draft, "--add-step", "test", "--attestor", "command-run", "--artifacts-from", "app-build",
		"--fill", `test.command-pin=["sh","-c","test -f bin/app"]`)
	require.NoError(t, e.prove(t))
	require.Equal(t, "Local verify: passed", e.firstLine())
	require.Contains(t, e.stderr, "recording the good run of step app-build")
	require.Less(t, strings.Index(e.stderr, "good run of step app-build"), strings.Index(e.stderr, "good run of step test"),
		"the producer is recorded before the step that consumes it")
	e.requireScratchGone(t)
}

func TestProveChainTamperedMaterialNamesTheEdge(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "app-build", "-o", e.draft,
		"--fill", `app-build.command-pin=["sh","-c","mkdir -p bin && printf v1 > bin/app"]`)
	// Runs between the build and the test (dependency order, then name):
	// rebuilds the binary the test step then consumes.
	e.template(t, "-p", e.draft, "--add-step", "rebuild", "--attestor", "command-run",
		"--fill", `rebuild.command-pin=["sh","-c","printf v2 > bin/app"]`)
	e.template(t, "-p", e.draft, "--add-step", "test", "--attestor", "command-run", "--artifacts-from", "app-build",
		"--fill", `test.command-pin=["sh","-c","test -f bin/app"]`)
	err := e.prove(t)
	require.Error(t, err)
	require.True(t, strings.HasPrefix(e.firstLine(), "Local verify: REFUSED by test: artifactsFrom app-build->test broken: "), e.firstLine())
	require.Contains(t, e.firstLine(), "bin/app")
	e.requireScratchGone(t)
}

func TestProveAttestationsFromRuleReadsTheProducer(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "app-build", "-o", e.draft,
		"--fill", `app-build.command-pin=["sh","-c","mkdir -p bin && printf v1 > bin/app"]`)
	e.template(t, "-p", e.draft, "--add-step", "publish", "--attestor", "command-run", "--rule", "products-from=app-build",
		"--fill", `publish.command-pin=["sh","-c","mkdir -p dist && cp bin/app dist/app"]`)
	require.NoError(t, e.prove(t))
	require.Equal(t, "Local verify: passed", e.firstLine())

	// The same chain, where publish ships bytes the build never made.
	e2 := newProveEnv(t, true)
	e2.template(t, "--goal", "app-build", "-o", e2.draft,
		"--fill", `app-build.command-pin=["sh","-c","mkdir -p bin && printf v1 > bin/app"]`)
	e2.template(t, "-p", e2.draft, "--add-step", "publish", "--attestor", "command-run", "--rule", "products-from=app-build",
		"--fill", `publish.command-pin=["sh","-c","mkdir -p dist && printf other > dist/app"]`)
	require.Error(t, e2.prove(t))
	require.Equal(t, "Local verify: REFUSED by publish: products-from: dist/app is not, by digest, a product of step app-build", e2.firstLine())
}

// A traced step is recorded with --trace. Where this machine can trace, an
// executable outside the allowlist is refused from the real process tree;
// where it cannot, prove says so and never reports a pass.
func TestProveTracedStep(t *testing.T) {
	e := newProveEnv(t, true)
	e.template(t, "--goal", "app-build", "-o", e.draft, "--rule", "trace-present", "--rule", `trace-exec=["/nonexistent/allowed"]`,
		"--fill", `app-build.command-pin=["sh","-c","mkdir -p bin && printf app > bin/app"]`)
	err := e.prove(t)
	require.Error(t, err, "an executable outside the allowlist, or no trace at all, is never a pass")
	require.NotEqual(t, "Local verify: passed", e.firstLine())
	if strings.Contains(e.stdout, "tracing unavailable") {
		require.Contains(t, e.stdout, "a tracing policy cannot be proved here")
		t.Skipf("tracing is unavailable on this machine (%s): the refusal is reported, which is what this checks", runtime.GOOS)
	}
	require.Contains(t, e.firstLine(), "REFUSED by app-build: ")
	require.Contains(t, e.firstLine(), "which is not in the allowlist")
}

// A network call the allowlist does not name is refused from the real trace.
func TestProveTracedNetworkCall(t *testing.T) {
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is not installed")
	}
	e := newProveEnv(t, true)
	e.template(t, "--goal", "app-build", "-o", e.draft, "--rule", "trace-present", "--rule", `trace-network=["10.0.0.1"]`,
		"--fill", `app-build.command-pin=["sh","-c","`+curl+` -s -m 2 http://127.0.0.1:9/ ; mkdir -p bin && printf app > bin/app"]`)
	err = e.prove(t)
	if strings.Contains(e.stdout, "tracing unavailable") {
		require.Error(t, err)
		t.Skipf("tracing is unavailable on this machine (%s)", runtime.GOOS)
	}
	require.Error(t, err, "a connection outside the allowlist must be refused")
	require.Contains(t, e.firstLine(), "REFUSED by app-build: network: connect to ")
	// Linux names the address; the macOS sandbox backend records the connect
	// with the host not observable, which no allowlist entry admits.
	require.Regexp(t, `127\.0\.0\.1|host-not-observable`, e.firstLine())
}

// Codex round 1 on #10985: the failing run used to wrap `false`, so a rule
// that only pins argv refused it for the wrong reason and prove called the
// step guarded. The failing evidence is now the real run with its exit
// status set to 1 and nothing else changed, so an argv-only rule is caught.
func TestProveArgvOnlyRuleAdmitsAFailingRun(t *testing.T) {
	e := newProveEnv(t, true)
	doc := draftDoc{"expires": "2099-01-01T00:00:00Z", "steps": map[string]any{
		"argv": agentStep("argv", map[string]any{"type": typeCommandRun, "regopolicies": []any{
			map[string]any{"name": "pin", "module": module("package pin\n\ndeny[msg] {\n\tinput.cmd != [\"sh\", \"-c\", \"exit 0\"]\n\tmsg := \"not the pinned command\"\n}\n")},
		}}),
	}}
	require.NoError(t, saveDraft(e.draft, doc, false))
	err := e.prove(t, "--run", `argv=["sh","-c","exit 0"]`)
	require.Error(t, err, "an argv-only rule admits the pinned command failing")
	require.Equal(t, "Local verify: passed", e.firstLine(), "the real run passes the pin")
	require.Contains(t, e.stdout, "PROBLEM: step argv admits a failing run")
	e.requireScratchGone(t)
}
