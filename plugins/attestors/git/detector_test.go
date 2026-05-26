// Copyright 2026 The Witness Contributors
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

package git

import (
	"os"
	"path/filepath"
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
	if d.Post != nil {
		t.Errorf("git is pre-only; post block should be absent")
	}
}

func TestDetectorFiresInGitWorkspace(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"go", "build", "./..."},
		Cwd:  dir,
	})

	if len(res.Fire) != 1 || res.Fire[0].Attestor != Name {
		t.Fatalf("expected git to fire, got %+v / skipped %+v", res.Fire, res.Skip)
	}
}

func TestDetectorSkipsWithoutGitDir(t *testing.T) {
	dir := t.TempDir() // no .git/

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)

	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"go", "build", "./..."},
		Cwd:  dir,
	})

	if len(res.Fire) != 0 {
		t.Fatalf("expected no fires, got %+v", res.Fire)
	}
	if len(res.Skip) != 1 || res.Skip[0].Cause != "no-match" {
		t.Errorf("expected no-match skip, got %+v", res.Skip)
	}
}
