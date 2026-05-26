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

func TestRenderInsertAfterSubcommand(t *testing.T) {
	argv := []string{"docker", "buildx", "build", "-t", "x", "."}
	fix := &SuggestedFix{
		InsertArg: &InsertArgOp{
			Value:           "--provenance=true",
			AfterSubcommand: []string{"build"},
		},
	}
	got, _, diff := RenderSuggestedCommand(argv, fix)
	want := []string{"docker", "buildx", "build", "--provenance=true", "-t", "x", "."}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if !strings.Contains(diff, "build") {
		t.Errorf("diff should mention anchor: %q", diff)
	}
}

func TestRenderInsertAfterSubcommandPicksLatest(t *testing.T) {
	// "buildx build" — the anchor "build" appears once. The function
	// should insert after the last occurrence, which is the build
	// subcommand (not buildx). This is the docker-specific case.
	argv := []string{"docker", "buildx", "build", "."}
	fix := &SuggestedFix{
		InsertArg: &InsertArgOp{
			Value:           "--provenance=true",
			AfterSubcommand: []string{"build", "buildx"},
		},
	}
	got, _, _ := RenderSuggestedCommand(argv, fix)
	want := []string{"docker", "buildx", "build", "--provenance=true", "."}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRenderInsertAnchorNotFoundAppends(t *testing.T) {
	argv := []string{"echo", "hi"}
	fix := &SuggestedFix{
		InsertArg: &InsertArgOp{
			Value:           "--flag",
			AfterSubcommand: []string{"never-matches"},
		},
	}
	got, _, diff := RenderSuggestedCommand(argv, fix)
	want := []string{"echo", "hi", "--flag"}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if !strings.Contains(diff, "anchor not found") {
		t.Errorf("diff should explain fallback: %q", diff)
	}
}

func TestRenderInsertAtPosition(t *testing.T) {
	argv := []string{"docker", "build", "."}
	pos := 1
	fix := &SuggestedFix{
		InsertArg: &InsertArgOp{
			Value:    "--debug",
			Position: &pos,
		},
	}
	got, _, _ := RenderSuggestedCommand(argv, fix)
	want := []string{"docker", "--debug", "build", "."}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRenderReplaceArgv(t *testing.T) {
	argv := []string{"docker", "build", "-t", "x", "."}
	fix := &SuggestedFix{
		ReplaceArgv: &ReplaceOp{
			From: []string{"docker", "build"},
			To:   []string{"docker", "buildx", "build"},
		},
	}
	got, _, _ := RenderSuggestedCommand(argv, fix)
	want := []string{"docker", "buildx", "build", "-t", "x", "."}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestRenderSetEnv(t *testing.T) {
	argv := []string{"go", "build"}
	fix := &SuggestedFix{
		SetEnv: &SetEnvOp{Var: "GOFLAGS", Value: "-trimpath"},
	}
	got, env, _ := RenderSuggestedCommand(argv, fix)
	if !sliceEqual(got, argv) {
		t.Errorf("set_env should not mutate argv: %v", got)
	}
	if env["GOFLAGS"] != "-trimpath" {
		t.Errorf("env override missing: %v", env)
	}
}

func TestRenderAppendArgs(t *testing.T) {
	argv := []string{"npm", "ci"}
	fix := &SuggestedFix{
		AppendArgs: []string{"--audit=false", "--fund=false"},
	}
	got, _, _ := RenderSuggestedCommand(argv, fix)
	want := []string{"npm", "ci", "--audit=false", "--fund=false"}
	if !sliceEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestFormatSuggestedCommand(t *testing.T) {
	argv := []string{"docker", "build", "-t", "name with spaces", "."}
	s := FormatSuggestedCommand(argv, nil)
	if !strings.Contains(s, "'name with spaces'") {
		t.Errorf("expected quoted whitespace arg: %q", s)
	}
	s2 := FormatSuggestedCommand(argv, map[string]string{"K": "V"})
	if !strings.HasPrefix(s2, "K=V ") {
		t.Errorf("expected env prefix: %q", s2)
	}
}

func TestRenderEmptyFix(t *testing.T) {
	argv := []string{"x"}
	got, env, diff := RenderSuggestedCommand(argv, &SuggestedFix{})
	if !sliceEqual(got, argv) || env != nil || diff != "" {
		t.Errorf("empty fix should be no-op, got %v / %v / %q", got, env, diff)
	}
}
