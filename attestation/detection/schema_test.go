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

package detection

import (
	"strings"
	"testing"
)

// sampleDockerYAML mirrors what plugins/attestors/docker/detector.yaml
// will eventually ship in M2. Used here to validate the schema and
// matcher against a realistic input.
const sampleDockerYAML = `
apiVersion: cilock.detection/v0.1
name: docker
description: "Captures docker build provenance and image materials."
pre:
  match:
    any_of:
      - argv_prefix: ["docker", "build"]
      - argv_prefix: ["docker", "buildx", "build"]
      - argv_prefix: ["buildah", "build"]
  warn_unless:
    argv_contains: "--provenance=true"
  warnings:
    - code: DOCKER_NO_PROVENANCE
      severity: warn
      message: "docker build invoked without --provenance=true"
      summary: "Captured attestation will lack SLSA build provenance."
      suggested_fix:
        insert_arg:
          value: "--provenance=true"
          after_subcommand: ["build"]
      doc_anchor: docker#provenance
      llm_hint: "User must add --provenance=true to docker build for SLSA build provenance."
post:
  match:
    any_of:
      - exec_observed:
          argv_prefix: ["docker", "build"]
      - product_glob: ["*.tar"]
llm_hints:
  on_match: "Docker build captured."
  on_warn: "User ran docker build without --provenance=true. Re-run with the suggested_command from the warning."
`

const sampleGitYAML = `
apiVersion: cilock.detection/v0.1
name: git
description: "Captures git repository state."
pre:
  match:
    file_exists: ".git/HEAD"
`

func TestParseSampleDocker(t *testing.T) {
	d, err := ParseDetectorYAML([]byte(sampleDockerYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.Name != "docker" {
		t.Errorf("name=%q", d.Name)
	}
	if d.Pre == nil || d.Post == nil {
		t.Fatalf("expected both pre and post blocks")
	}
	if len(d.Pre.Warnings) != 1 || d.Pre.Warnings[0].Code != "DOCKER_NO_PROVENANCE" {
		t.Errorf("warning code lost: %+v", d.Pre.Warnings)
	}
}

func TestParseSampleGit(t *testing.T) {
	d, err := ParseDetectorYAML([]byte(sampleGitYAML))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.Pre == nil || d.Post != nil {
		t.Fatalf("expected pre-only")
	}
	if d.Pre.Match.FileExists != ".git/HEAD" {
		t.Errorf("file_exists lost: %q", d.Pre.Match.FileExists)
	}
}

func TestRejectMissingAPIVersion(t *testing.T) {
	yaml := `
name: foo
pre:
  match:
    argv_prefix: ["foo"]
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "apiVersion") {
		t.Errorf("expected apiVersion error, got %v", err)
	}
}

func TestRejectUnsupportedAPIVersion(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v9.0
name: foo
pre:
  match:
    argv_prefix: ["foo"]
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected unsupported version error, got %v", err)
	}
}

func TestRejectInvalidName(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: HasUpperCase
pre:
  match:
    argv_prefix: ["foo"]
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "name") {
		t.Errorf("expected name error, got %v", err)
	}
}

func TestRejectNoGate(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: foo
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "pre or post") {
		t.Errorf("expected no-gate error, got %v", err)
	}
}

func TestRejectPostPredicateInPre(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: foo
pre:
  match:
    product_glob: ["*.tar"]
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "not allowed in pre-gate") {
		t.Errorf("expected pre-gate guard error, got %v", err)
	}
}

func TestRejectMultiplePredicateTags(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: foo
pre:
  match:
    argv_prefix: ["foo"]
    argv_contains: "bar"
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "multiple") {
		t.Errorf("expected multi-tag error, got %v", err)
	}
}

func TestRejectInvalidWarningCode(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: foo
pre:
  match:
    argv_prefix: ["foo"]
  warnings:
    - code: bad-code
      severity: warn
      message: "x"
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "code") {
		t.Errorf("expected warning code error, got %v", err)
	}
}

func TestRejectDuplicateWarningCodes(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: foo
pre:
  match:
    argv_prefix: ["foo"]
  warnings:
    - code: DUP_CODE
      severity: warn
      message: "x"
    - code: DUP_CODE
      severity: warn
      message: "y"
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Errorf("expected duplicate code error, got %v", err)
	}
}

func TestRejectInvalidExitCode(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: foo
post:
  match:
    exit_code: {}
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "exit_code") {
		t.Errorf("expected exit_code error, got %v", err)
	}
}

func TestParsedExecObservedNests(t *testing.T) {
	// exec_observed wraps a pre-gate-style predicate. Nesting a
	// post-gate predicate inside should fail.
	yaml := `
apiVersion: cilock.detection/v0.1
name: foo
post:
  match:
    exec_observed:
      product_glob: ["*.tar"]
`
	_, err := ParseDetectorYAML([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "not allowed in pre-gate") {
		t.Errorf("expected nested pre-gate guard error, got %v", err)
	}
}

func TestRunPrePlanFires(t *testing.T) {
	reg := NewRegistry()
	reg.Register("docker", []byte(sampleDockerYAML))
	reg.Register("git", []byte(sampleGitYAML))

	res := RunPrePlanWith(reg, PrePlan{
		Argv: []string{"docker", "build", "."},
		Env:  map[string]string{},
		Cwd:  t.TempDir(),
	})

	if len(res.Fire) != 1 {
		t.Fatalf("expected 1 attestor to fire, got %d (%+v)", len(res.Fire), res.Fire)
	}
	if res.Fire[0].Attestor != "docker" {
		t.Errorf("expected docker to fire, got %s", res.Fire[0].Attestor)
	}
	if len(res.Warnings) != 1 || res.Warnings[0].Code != "DOCKER_NO_PROVENANCE" {
		t.Fatalf("expected DOCKER_NO_PROVENANCE warning, got %+v", res.Warnings)
	}
	got := res.Warnings[0].SuggestedCommand
	want := []string{"docker", "build", "--provenance=true", "."}
	if !sliceEqual(got, want) {
		t.Errorf("suggested_command = %v, want %v", got, want)
	}
}

func TestRunPrePlanWarnUnlessSuppresses(t *testing.T) {
	reg := NewRegistry()
	reg.Register("docker", []byte(sampleDockerYAML))

	res := RunPrePlanWith(reg, PrePlan{
		Argv: []string{"docker", "build", "--provenance=true", "."},
		Env:  map[string]string{},
		Cwd:  t.TempDir(),
	})

	if len(res.Fire) != 1 {
		t.Fatalf("expected docker to fire, got %d", len(res.Fire))
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warn_unless should suppress the warning, got %+v", res.Warnings)
	}
}

func TestRunPostPlanFiresOnExecObserved(t *testing.T) {
	reg := NewRegistry()
	reg.Register("docker", []byte(sampleDockerYAML))

	pre := RunPrePlanWith(reg, PrePlan{
		Argv: []string{"make", "build"},
		Cwd:  t.TempDir(),
	})

	// Pre-gate didn't fire docker (argv was make, not docker). But
	// the post-gate sees docker in the trace and fires.
	post := RunPostPlanWith(reg, PostPlan{
		Pre:       &pre,
		ExecTrace: []ExecEvent{{Argv: []string{"docker", "build", "-t", "x", "."}}},
		TraceMode: TraceLight,
	})

	if len(post.Fire) != 1 || post.Fire[0].Attestor != "docker" {
		t.Fatalf("expected docker to fire post-gate, got %+v", post.Fire)
	}
}

func TestRunPostPlanTraceUnavailable(t *testing.T) {
	reg := NewRegistry()
	reg.Register("docker", []byte(sampleDockerYAML))

	post := RunPostPlanWith(reg, PostPlan{
		Pre:       &PlanResult{Inputs: InputSnapshot{Argv: []string{"make"}}},
		ExecTrace: nil,
		TraceMode: TraceUnsupported,
	})

	// docker post-gate has any_of[exec_observed, product_glob]. The
	// exec_observed is trace-unavailable; product_glob is no-match
	// (no products). any_of yields trace-unavailable.
	if len(post.Skip) == 0 {
		t.Fatalf("expected at least one skip, got %+v", post.Skip)
	}
	foundUnavailable := false
	for _, s := range post.Skip {
		if s.Attestor == "docker" && s.Cause == "trace-unavailable" {
			foundUnavailable = true
			break
		}
	}
	if !foundUnavailable {
		t.Errorf("expected docker skipped as trace-unavailable, got %+v", post.Skip)
	}
}

func TestRegistryLazyParseError(t *testing.T) {
	reg := NewRegistry()
	reg.Register("bogus", []byte("not: valid: yaml: ::"))
	_, ok, err := reg.Lookup("bogus")
	if !ok {
		t.Fatalf("expected ok=true for registered plugin")
	}
	if err == nil {
		t.Errorf("expected parse error for malformed YAML")
	}
	// Second lookup returns same error from cache; no re-parse.
	_, _, err2 := reg.Lookup("bogus")
	if err == nil || err2 == nil || err.Error() != err2.Error() {
		t.Errorf("expected cached parse error, got %v vs %v", err, err2)
	}
}

func TestRegistryNameMismatch(t *testing.T) {
	yaml := `
apiVersion: cilock.detection/v0.1
name: alpha
pre:
  match:
    argv_prefix: ["alpha"]
`
	reg := NewRegistry()
	reg.Register("beta", []byte(yaml))
	_, _, err := reg.Lookup("beta")
	if err == nil || !strings.Contains(err.Error(), "does not match registration") {
		t.Errorf("expected name-mismatch error, got %v", err)
	}
}

// TestEmbeddedCatalogParses round-trips every YAML in
// attestation/detection/catalog/. A failure here means the script that
// generates them produced something the parser rejects — re-run
// scripts/gen-detection-catalog.py after fixing.
func TestEmbeddedCatalogParses(t *testing.T) {
	// The default registry has init()-loaded the catalog already.
	parsed, failures := Default().LookupAll()
	if len(failures) > 0 {
		for n, e := range failures {
			t.Errorf("catalog entry %q failed to parse: %v", n, e)
		}
	}
	// Sanity: catalog has many entries; assert >40 to catch a regression
	// that empties the embed dir.
	if len(parsed) < 40 {
		t.Fatalf("expected >=40 catalog entries to be registered, got %d", len(parsed))
	}
	// Spot-check a known entry survived end-to-end.
	syft, ok := parsed["syft"]
	if !ok {
		t.Fatalf("expected syft in catalog, names=%v", Default().Names())
	}
	if !syft.DetectionOnly {
		t.Errorf("syft should be detection_only=true")
	}
	if len(syft.EmitsFormats) != 1 || syft.EmitsFormats[0] != "sbom" {
		t.Errorf("syft emits_formats=%v, want [sbom]", syft.EmitsFormats)
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
