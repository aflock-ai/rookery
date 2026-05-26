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

//go:build integration
// +build integration

package maven

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/detection"
)

// TestDetectorFiresOnMavenProject creates a workspace with a real
// pom.xml shape and asserts the maven detector fires (pre-gate
// file_exists). Bare pom.xml — no actual mvn invocation needed.
func TestDetectorFiresOnMavenProject(t *testing.T) {
	dir := t.TempDir()
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>0.0.1</version>
</project>`
	if err := os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o600); err != nil {
		t.Fatal(err)
	}

	reg := detection.NewRegistry()
	reg.Register(Name, detectorYAML)
	res := detection.RunPrePlanWith(reg, detection.PrePlan{
		Argv: []string{"mvn", "package"},
		Cwd:  dir,
	})
	for _, f := range res.Fire {
		if f.Attestor == Name {
			return
		}
	}
	t.Fatalf("maven detector did not fire: %+v", res)
}
