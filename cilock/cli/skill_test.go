// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/agentplugin"
	"github.com/spf13/cobra"
)

func runCilock(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := New()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func TestSkillShowPrintsTheEmbeddedSkill(t *testing.T) {
	got, err := runCilock(t, "skill", "show")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(agentplugin.SkillMarkdown()) {
		t.Error("`cilock skill show` differs from the embedded SKILL.md")
	}
	want, err := agentplugin.ReadFile("references/refusals.md")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := runCilock(t, "skill", "show", "references/refusals.md"); err != nil || got != string(want) {
		t.Errorf("show references/refusals.md: err=%v, match=%v", err, got == string(want))
	}
	if _, err := runCilock(t, "skill", "show", "../../etc/passwd"); err == nil || !strings.Contains(err.Error(), "SKILL.md") {
		t.Errorf("unknown file: err = %v, want a refusal listing the skill's files", err)
	}
}

func TestSkillInstallReportsWhatItWrote(t *testing.T) {
	dir := t.TempDir()
	out, err := runCilock(t, "skill", "install", "--dir", dir)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{filepath.Join(dir, "pushgate"), "wrote     SKILL.md", "wrote     references/refusals.md", agentplugin.RecordName, "cilock enroll agent"} {
		if !strings.Contains(out, want) {
			t.Errorf("install output lacks %q:\n%s", want, out)
		}
	}
	out, err = runCilock(t, "skill", "install", "--dir", dir)
	if err != nil {
		t.Fatalf("re-install: %v\n%s", err, out)
	}
	if strings.Contains(out, "wrote ") || !strings.Contains(out, "unchanged SKILL.md") {
		t.Errorf("re-install should change nothing:\n%s", out)
	}

	out, err = runCilock(t, "skill", "path", "--dir", dir)
	if err != nil {
		t.Fatal(err)
	}
	if first := strings.SplitN(out, "\n", 2)[0]; first != filepath.Join(dir, "pushgate") {
		t.Errorf("`skill path` first line = %q", first)
	}
	if !strings.Contains(out, string(agentplugin.StateCurrent)) {
		t.Errorf("`skill path` does not report the install:\n%s", out)
	}
}

func TestSkillInstallRefusesAForeignFileThroughTheCLI(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "pushgate"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pushgate", "SKILL.md"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runCilock(t, "skill", "install", "--dir", dir)
	if err == nil || !strings.Contains(err.Error(), "--force") || !strings.Contains(err.Error(), "Nothing was written") {
		t.Fatalf("err = %v", err)
	}
}

func TestSkillCommandsSendNoTelemetry(t *testing.T) {
	if SkillCmd().PersistentPostRun == nil {
		t.Fatal("the skill group must replace the root's telemetry post-run hook")
	}
}

// pendingSkillCommands are commands the skill names that another change is
// adding to cilock. The skill ships inside cilock, so every command it names
// must exist in the same binary; this list is the one allowed exception and it
// only shrinks. The test fails once a pending command exists, so the entry is
// removed in the change that lands it.
var pendingSkillCommands = map[string]bool{
	"policy guide":    true,
	"policy template": true,
	"policy prove":    true,
}

// Every `cilock ...` the skill tells an agent to run resolves to a real
// command in this binary, and every --flag it spells exists on that command.
// This is the drift guard between the skill and the CLI.
func TestSkillNamesOnlyCommandsThisBinaryHas(t *testing.T) {
	root := New()
	files, err := agentplugin.Files()
	if err != nil {
		t.Fatal(err)
	}
	span := regexp.MustCompile("`(cilock [^`]+)`")
	seen := 0
	for _, f := range files {
		for _, m := range span.FindAllStringSubmatch(string(f.Data), -1) {
			seen++
			words := strings.Fields(m[1])[1:]
			if len(words) == 0 || strings.HasPrefix(words[0], "<") {
				continue // `cilock <command> --help`: a placeholder, not a command
			}
			cmd, path := resolveSubcommand(root, words)
			if pendingSkillCommands[path] {
				continue
			}
			if cmd == root {
				t.Errorf("%s names `%s`, but cilock has no command %q", f.Path, m[1], words[0])
				continue
			}
			if cmd.HasSubCommands() && !cmd.Runnable() {
				t.Errorf("%s names `%s`, which is a command group, not a command", f.Path, m[1])
			}
			for _, w := range words {
				if w == "--" {
					break // the wrapped command's argv
				}
				if !strings.HasPrefix(w, "--") {
					continue
				}
				name := strings.SplitN(strings.TrimPrefix(w, "--"), "=", 2)[0]
				if cmd.Flags().Lookup(name) == nil && cmd.InheritedFlags().Lookup(name) == nil {
					t.Errorf("%s names `%s`, but `cilock %s` has no --%s flag", f.Path, m[1], path, name)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("found no cilock commands in the skill; the extractor is broken")
	}
	for p := range pendingSkillCommands {
		words := strings.Fields(p)
		if cmd, _ := resolveSubcommand(root, words); cmd.Name() == words[len(words)-1] {
			t.Errorf("`cilock %s` exists now: remove it from pendingSkillCommands", p)
		}
	}
}

// resolveSubcommand walks words down the command tree and returns the deepest
// command reached and its space-joined path. It stops at the first word that
// is not a subcommand (a flag, a placeholder, or an argument).
func resolveSubcommand(root *cobra.Command, words []string) (*cobra.Command, string) {
	cur := root
	var path []string
	for _, w := range words {
		var next *cobra.Command
		for _, c := range cur.Commands() {
			if c.Name() == w || c.HasAlias(w) {
				next = c
				break
			}
		}
		if next == nil {
			// An unresolved word right after the root is reported by path so
			// a pending two-word command still matches its entry.
			if cur == root || (len(path) > 0 && !cur.Runnable()) {
				return cur, strings.Join(append(path, w), " ")
			}
			break
		}
		cur = next
		path = append(path, w)
	}
	return cur, strings.Join(path, " ")
}
