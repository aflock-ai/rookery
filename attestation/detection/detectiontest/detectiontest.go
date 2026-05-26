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

// Package detectiontest exposes shared test helpers so each plugin's
// detector_test.go can exercise its real predicates without copy-paste.
//
// Helpers create a fresh detection registry, register the plugin's
// detector.yaml, run the pre- or post-gate planner against synthetic
// inputs, and assert the plugin's behavior. Failure messages quote the
// full PlanResult so debugging a miss-match doesn't require re-running
// in verbose mode.
package detectiontest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// AssertParses checks the embedded detector.yaml round-trips through
// the schema and that its declared name matches the plugin's Name
// constant. Every plugin's TestDetectorYAMLParses delegates here.
func AssertParses(t *testing.T, pluginName string, yaml []byte) {
	t.Helper()
	d, err := detection.ParseDetectorYAML(yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.Name != pluginName {
		t.Fatalf("name mismatch: yaml=%q plugin=%q", d.Name, pluginName)
	}
}

// AssertPreGateFiresOnArgv constructs a fresh registry, registers the
// plugin, and asserts RunPrePlan with the given argv (and optional env
// + cwd) fires the named plugin. Use for argv_prefix and argv_contains
// predicates.
func AssertPreGateFiresOnArgv(t *testing.T, pluginName string, yaml []byte, argv []string) {
	t.Helper()
	reg := detection.NewRegistry()
	reg.Register(pluginName, yaml)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: argv,
		Cwd:  t.TempDir(),
	})
	assertFired(t, pluginName, res)
}

// AssertPreGateFiresInEnv asserts the plugin fires when the given env
// var is set to value. argv is "/bin/echo hi" by default.
func AssertPreGateFiresInEnv(t *testing.T, pluginName string, yaml []byte, envKey, envVal string) {
	t.Helper()
	reg := detection.NewRegistry()
	reg.Register(pluginName, yaml)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"echo", "hi"},
		Env:  map[string]string{envKey: envVal},
		Cwd:  t.TempDir(),
	})
	assertFired(t, pluginName, res)
}

// AssertPreGateFiresOnFile creates the named file inside a fresh
// tempdir, then asserts the plugin fires (file_exists predicate).
// filename may contain forward-slash subdirs; the helper creates
// them via MkdirAll. Contents are arbitrary; an empty byte body is
// enough for presence-only predicates.
func AssertPreGateFiresOnFile(t *testing.T, pluginName string, yaml []byte, filename string) {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, filepath.FromSlash(filename))
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
		t.Fatalf("write %s: %v", full, err)
	}
	reg := detection.NewRegistry()
	reg.Register(pluginName, yaml)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"echo", "hi"},
		Cwd:  dir,
	})
	assertFired(t, pluginName, res)
}

// AssertPreGateSkipsCleanly asserts the plugin does NOT fire on the
// given inputs (negative case). Useful for confirming that a detector
// rejects unrelated invocations.
func AssertPreGateSkipsCleanly(t *testing.T, pluginName string, yaml []byte, argv []string) {
	t.Helper()
	reg := detection.NewRegistry()
	reg.Register(pluginName, yaml)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: argv,
		Cwd:  t.TempDir(),
	})
	for _, f := range res.Fire {
		if f.Attestor == pluginName {
			t.Fatalf("expected %s to skip, but it fired: %+v", pluginName, f)
		}
	}
}

// AssertPostGateFiresOnExec asserts the plugin fires via the post-gate
// when the given argv was observed in the exec trace. Use for
// exec_observed predicates.
func AssertPostGateFiresOnExec(t *testing.T, pluginName string, yaml []byte, observedArgv []string) {
	t.Helper()
	reg := detection.NewRegistry()
	reg.Register(pluginName, yaml)
	pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"shell"}}}
	res := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre:       pre,
		ExecTrace: []detection.ExecEvent{{Argv: observedArgv}},
		TraceMode: detection.TraceLight,
		Cwd:       t.TempDir(),
	})
	assertFired(t, pluginName, res)
}

// AssertPostGateFiresOnProduct asserts the plugin fires via the
// post-gate when a product file with the given relative path is present.
// Use for product_glob predicates.
func AssertPostGateFiresOnProduct(t *testing.T, pluginName string, yaml []byte, productPath string) {
	t.Helper()
	reg := detection.NewRegistry()
	reg.Register(pluginName, yaml)
	pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"shell"}}}
	res := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre:       pre,
		Products:  map[string]detection.ProductRef{productPath: {Path: productPath}},
		TraceMode: detection.TraceLight,
		Cwd:       t.TempDir(),
	})
	assertFired(t, pluginName, res)
}

// AssertPostGateTraceUnavailable asserts that when the trace is
// unsupported (e.g. macOS) and no products are present, the plugin is
// skipped with the trace-unavailable cause — not silently misclassified
// as a clean no-match.
func AssertPostGateTraceUnavailable(t *testing.T, pluginName string, yaml []byte) {
	t.Helper()
	reg := detection.NewRegistry()
	reg.Register(pluginName, yaml)
	pre := &detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"shell"}}}
	res := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre:       pre,
		TraceMode: detection.TraceUnsupported,
		Cwd:       t.TempDir(),
	})
	for _, s := range res.Skip {
		if s.Attestor == pluginName && s.Cause == "trace-unavailable" {
			return
		}
	}
	t.Fatalf("expected %s to skip as trace-unavailable, got fire=%+v skip=%+v", pluginName, res.Fire, res.Skip)
}

func assertFired(t *testing.T, pluginName string, res detection.PlanResult) {
	t.Helper()
	for _, f := range res.Fire {
		if f.Attestor == pluginName {
			return
		}
	}
	t.Fatalf("expected %s to fire, got fire=%+v skip=%+v warnings=%+v", pluginName, res.Fire, res.Skip, res.Warnings)
}
