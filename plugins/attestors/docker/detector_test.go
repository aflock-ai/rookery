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

package docker

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

func TestDetectorYAMLParses(t *testing.T) {
	d, err := detection.ParseDetectorYAML(detectorYAML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if d.Name != Name {
		t.Errorf("name mismatch: yaml=%q plugin=%q", d.Name, Name)
	}
	if d.Pre == nil {
		t.Errorf("expected pre block")
	}
	if d.Post == nil {
		t.Errorf("expected post block")
	}
}

func TestDetectorFiresOnDirectDockerBuild(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"docker", "build", "-t", "foo", "."},
		Cwd:  t.TempDir(),
	})

	if len(res.Fire) != 1 || res.Fire[0].Attestor != Name {
		t.Fatalf("expected docker to fire pre-gate, got %+v", res.Fire)
	}

	// Without --provenance=true, the warning should be present.
	if len(res.Warnings) != 1 || res.Warnings[0].Code != "DOCKER_NO_PROVENANCE" {
		t.Fatalf("expected DOCKER_NO_PROVENANCE warning, got %+v", res.Warnings)
	}
	// suggested_command rewrites `docker build` → `docker buildx build`
	// (because the legacy docker driver rejects --provenance) and then
	// inserts --provenance=true after the new "build" position.
	want := []string{"docker", "buildx", "build", "--provenance=true", "-t", "foo", "."}
	got := res.Warnings[0].SuggestedCommand
	if !argvEqual(got, want) {
		t.Errorf("suggested_command = %v, want %v", got, want)
	}
}

func TestDetectorSuppressesWarningWithProvenanceFlag(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"docker", "buildx", "build", "--provenance=true", "."},
		Cwd:  t.TempDir(),
	})

	if len(res.Fire) != 1 {
		t.Fatalf("expected docker to fire, got %+v", res.Fire)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warn_unless should suppress, got %+v", res.Warnings)
	}
}

func TestDetectorFiresPostGateOnObservedExec(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	// User typed `make build` — pre-gate sees no docker.
	pre := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"make", "build"},
		Cwd:  t.TempDir(),
	})
	if len(pre.Fire) != 0 {
		t.Errorf("pre-gate should not fire docker on 'make build', got %+v", pre.Fire)
	}

	// But the trace shows docker build ran as a child.
	post := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre:       &pre,
		ExecTrace: []detection.ExecEvent{{Argv: []string{"docker", "build", "-t", "x", "."}}},
		TraceMode: detection.TraceLight,
	})
	if len(post.Fire) != 1 || post.Fire[0].Attestor != Name {
		t.Fatalf("expected docker to fire post-gate via exec_observed, got %+v", post.Fire)
	}
}

func TestDetectorPostGateTraceUnavailable(t *testing.T) {
	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	pre := detection.PlanResult{Inputs: detection.InputSnapshot{Argv: []string{"make"}}}
	// macOS / Windows path: no trace.
	post := detection.RunPostPlanWith(reg, detection.PostPlan{
		Pre:       &pre,
		TraceMode: detection.TraceUnsupported,
	})

	foundTraceUnavailable := false
	for _, s := range post.Skip {
		if s.Attestor == Name && s.Cause == "trace-unavailable" {
			foundTraceUnavailable = true
		}
	}
	if !foundTraceUnavailable {
		t.Errorf("expected docker to be skipped as trace-unavailable, got skip=%+v", post.Skip)
	}
}

func argvEqual(a, b []string) bool {
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
