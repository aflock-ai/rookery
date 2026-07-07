// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package supplychain holds guards that assert cilock's release build links the
// TestifySec security-patch forks, not full upstream.
package supplychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSecurityForkReplacesPinnedInGoMod is a regression guard for #6383.
//
// The security-patch forks (gitleaks-slim, wk8-orderedmap) MUST be pinned via
// `replace` directives in cilock's own go.mod — NOT only in the repo go.work.
// Release builds run `GOWORK=off` (subtrees/rookery/.github/workflows/release.yml),
// which ignores go.work entirely; a replace that lives only in go.work is
// silently dropped, and the released binary links the FULL upstream gitleaks/v8
// plus its ~46-module heavy pile (viper/lipgloss/mholt-archives/sprig).
//
// This test parses cilock/go.mod directly (no build-graph dependency) and fails
// if either security-fork replace is missing or no longer targets the local
// slim fork. It is deliberately dependency-free so it can never be the thing
// that breaks the build it protects.
func TestSecurityForkReplacesPinnedInGoMod(t *testing.T) {
	goMod := readCilockGoMod(t)

	// Collapse whitespace so "replace  A  =>  B" and "replace A => B" both match.
	norm := strings.Join(strings.Fields(goMod), " ")

	required := []struct {
		name    string
		replace string
	}{
		{
			name:    "gitleaks/v8 slim fork",
			replace: "replace github.com/zricethezav/gitleaks/v8 => ../security-patches/gitleaks-slim",
		},
		{
			name:    "wk8 ordered-map fork",
			replace: "replace github.com/wk8/go-ordered-map/v2 => ../security-patches/wk8-orderedmap/v2",
		},
	}

	for _, r := range required {
		if !strings.Contains(norm, r.replace) {
			t.Errorf("cilock/go.mod is missing the %s replace (#6383):\n\n    %s\n\n"+
				"Without it, GOWORK=off release builds strand the go.work replace and ship full upstream.",
				r.name, r.replace)
		}
	}
}

// readCilockGoMod walks up from the test's working directory to the cilock
// module root and returns its go.mod contents.
func readCilockGoMod(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "go.mod")
		if data, err := os.ReadFile(candidate); err == nil {
			if strings.Contains(string(data), "module github.com/aflock-ai/rookery/cilock") {
				return string(data)
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate cilock/go.mod walking up from test dir")
		}
		dir = parent
	}
}
