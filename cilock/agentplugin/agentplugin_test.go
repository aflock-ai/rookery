// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package agentplugin

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// frontmatter splits SKILL.md into its YAML frontmatter and body. The
// opening fence must be the first line: Claude Code treats a file whose
// first line is not `---` as all body.
func frontmatter(t *testing.T, md []byte) (map[string]any, string) {
	t.Helper()
	s := string(md)
	if !strings.HasPrefix(s, "---\n") {
		t.Fatalf("SKILL.md must open with a --- fence on line 1")
	}
	end := strings.Index(s[4:], "\n---\n")
	if end < 0 {
		t.Fatalf("SKILL.md frontmatter has no closing --- fence")
	}
	var fm map[string]any
	if err := yaml.Unmarshal([]byte(s[4:4+end]), &fm); err != nil {
		t.Fatalf("SKILL.md frontmatter is not YAML: %v", err)
	}
	return fm, s[4+end+5:]
}

func TestFrontmatterHasRequiredFields(t *testing.T) {
	fm, body := frontmatter(t, SkillMarkdown())
	name, _ := fm["name"].(string)
	desc, _ := fm["description"].(string)
	if name != SkillName {
		t.Errorf("frontmatter name = %q, want %q (opencode requires it to equal the directory name)", name, SkillName)
	}
	// opencode's rule, the strictest of the three agents.
	if !regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`).MatchString(name) || len(name) > 64 {
		t.Errorf("name %q breaks opencode's name rule", name)
	}
	if desc == "" {
		t.Fatal("description is required by Codex and opencode")
	}
	// opencode caps the description at 1024 characters; Claude Code truncates
	// at 1536. The stricter bound wins.
	if n := len([]rune(desc)); n > 1024 {
		t.Errorf("description is %d characters; opencode allows 1024", n)
	}
	for k := range fm {
		if k != "name" && k != "description" {
			t.Errorf("unexpected frontmatter field %q: keep to the fields all three agents read", k)
		}
	}
	if lines := strings.Count(body, "\n"); lines > 500 {
		t.Errorf("SKILL.md body is %d lines; Claude Code and Codex both advise under 500", lines)
	}
}

// Every relative link in the skill resolves to an embedded file, so progressive
// disclosure never points an agent at a file that is not there.
func TestSkillLinksResolve(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, f := range files {
		have[f.Path] = true
	}
	link := regexp.MustCompile(`\]\(([^)#:]+\.md)\)`)
	for _, f := range files {
		for _, m := range link.FindAllStringSubmatch(string(f.Data), -1) {
			target := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(f.Path), m[1])))
			if !have[target] {
				t.Errorf("%s links to %s, which the skill does not contain", f.Path, m[1])
			}
		}
	}
}

// The embedded copy is the plugin directory on disk, byte for byte, and the
// rookery marketplace points at that same directory. This is what keeps the
// marketplace plugin and `cilock skill install` from drifting.
func TestEmbeddedSkillMatchesMarketplacePlugin(t *testing.T) {
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	err = filepath.WalkDir(SkillDir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(SkillDir, p)
		onDisk = append(onDisk, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(onDisk) != len(files) {
		t.Fatalf("plugin skill directory has %d files, embed has %d: %v (a dot or underscore file is not embedded; rename it)", len(onDisk), len(files), onDisk)
	}
	for _, f := range files {
		disk, err := os.ReadFile(filepath.Join(SkillDir, filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatalf("embedded %s is missing from the plugin directory: %v", f.Path, err)
		}
		if !bytes.Equal(disk, f.Data) {
			t.Errorf("embedded %s differs from the plugin copy", f.Path)
		}
	}

	var plugin struct {
		Name string `json:"name"`
	}
	readJSON(t, filepath.Join(PluginDir, ".claude-plugin", "plugin.json"), &plugin)
	if plugin.Name != SkillName {
		t.Errorf("plugin.json name = %q, want %q", plugin.Name, SkillName)
	}

	// The marketplace lives at the rookery root, outside the cilock module.
	// It exists in every rookery checkout (and in the judge monorepo's
	// subtree); only a copy of the module alone lacks it.
	marketplace := filepath.Join("..", "..", ".claude-plugin", "marketplace.json")
	if _, err := os.Stat(filepath.Join("..", "..", "go.work")); err != nil {
		t.Skipf("not inside a rookery checkout (no ../../go.work); cannot check %s", marketplace)
	}
	var mp struct {
		Name    string                `json:"name"`
		Owner   struct{ Name string } `json:"owner"`
		Plugins []struct {
			Name   string `json:"name"`
			Source any    `json:"source"`
		} `json:"plugins"`
	}
	readJSON(t, marketplace, &mp)
	if mp.Name == "" || mp.Owner.Name == "" {
		t.Error("marketplace.json requires name and owner.name")
	}
	found := false
	for _, p := range mp.Plugins {
		if p.Name != SkillName {
			continue
		}
		found = true
		src, ok := p.Source.(string)
		if !ok || !strings.HasPrefix(src, "./") || strings.Contains(src, "..") {
			t.Fatalf("marketplace source for %s = %v; want a ./relative path without ..", SkillName, p.Source)
		}
		want, _ := filepath.Abs(PluginDir)
		got, _ := filepath.Abs(filepath.Join("..", "..", filepath.FromSlash(src)))
		if got != want {
			t.Errorf("marketplace source %s resolves to %s, not the embedded plugin %s", src, got, want)
		}
	}
	if !found {
		t.Errorf("marketplace.json lists no %q plugin", SkillName)
	}
}

func readJSON(t *testing.T, p string, v any) {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", p, err)
	}
}

// sandbox is a temp HOME and a temp project (with a .git directory) whose
// working directory is a subdirectory, as an agent's often is.
func sandbox(t *testing.T) (Env, string) {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(root, "project")
	work := filepath.Join(project, "src", "pkg")
	for _, d := range []string{home, filepath.Join(project, ".git"), work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return Env{Home: home, WorkDir: work, Getenv: func(string) string { return "" }}, project
}

func assertInstalled(t *testing.T, dir string) {
	t.Helper()
	files, err := Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Path)))
		if err != nil {
			t.Fatalf("%s not installed: %v", f.Path, err)
		}
		if !bytes.Equal(got, f.Data) {
			t.Errorf("%s installed with different bytes", f.Path)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, RecordName)); err != nil {
		t.Errorf("install record missing: %v", err)
	}
}

func TestInstallForEachAgentAndScope(t *testing.T) {
	cases := []struct {
		agent Agent
		scope Scope
		want  func(home, project string) string
	}{
		{AgentClaude, ScopeUser, func(h, _ string) string { return filepath.Join(h, ".claude", "skills", "pushgate") }},
		{AgentClaude, ScopeProject, func(_, p string) string { return filepath.Join(p, ".claude", "skills", "pushgate") }},
		{AgentCodex, ScopeUser, func(h, _ string) string { return filepath.Join(h, ".agents", "skills", "pushgate") }},
		{AgentCodex, ScopeProject, func(_, p string) string { return filepath.Join(p, ".agents", "skills", "pushgate") }},
		{AgentOpenCode, ScopeUser, func(h, _ string) string {
			return filepath.Join(h, ".config", "opencode", "skills", "pushgate")
		}},
		{AgentOpenCode, ScopeProject, func(_, p string) string { return filepath.Join(p, ".opencode", "skills", "pushgate") }},
	}
	for _, tc := range cases {
		t.Run(string(tc.agent)+"/"+string(tc.scope), func(t *testing.T) {
			env, project := sandbox(t)
			target, err := ResolveTarget(tc.agent, tc.scope, "", env)
			if err != nil {
				t.Fatal(err)
			}
			if want := tc.want(env.Home, project); target.Dir != want {
				t.Fatalf("target = %s, want %s", target.Dir, want)
			}
			if target.Rule == "" || !strings.Contains(target.Rule, "https://") {
				t.Errorf("target carries no cited discovery rule: %q", target.Rule)
			}
			results, err := Install(target, false, "test")
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range results {
				if r.Action != ActionWrote {
					t.Errorf("fresh install: %s %s, want wrote", r.Action, r.Path)
				}
			}
			assertInstalled(t, target.Dir)
			// Nothing outside the target directory was created.
			assertOnlyUnder(t, filepath.Dir(env.Home), target.Dir)
		})
	}
}

// assertOnlyUnder walks root and fails on any file that is not under dir.
func assertOnlyUnder(t *testing.T, root, dir string) {
	t.Helper()
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasPrefix(p, dir+string(filepath.Separator)) {
			t.Errorf("install wrote %s, outside %s", p, dir)
		}
		return nil
	})
}

func TestInstallIsIdempotent(t *testing.T) {
	env, _ := sandbox(t)
	target, err := ResolveTarget(AgentClaude, ScopeUser, "", env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Install(target, false, "test"); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, target.Dir)
	results, err := Install(target, false, "test")
	if err != nil {
		t.Fatalf("re-install refused: %v", err)
	}
	for _, r := range results {
		if r.Action != ActionUnchanged {
			t.Errorf("re-install: %s %s, want unchanged", r.Action, r.Path)
		}
	}
	if after := snapshot(t, target.Dir); after != before {
		t.Errorf("re-install changed the directory:\nbefore %s\nafter  %s", before, after)
	}
}

func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, _ := d.Info()
		data, _ := os.ReadFile(p)
		b.WriteString(p + " " + info.ModTime().String() + " " + digest(data) + "\n")
		return nil
	})
	return b.String()
}

func TestInstallRefusesToClobberAForeignFile(t *testing.T) {
	env, _ := sandbox(t)
	target, _ := ResolveTarget(AgentCodex, ScopeUser, "", env)
	if err := os.MkdirAll(target.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := []byte("---\nname: pushgate\ndescription: someone else's skill\n---\n")
	skill := filepath.Join(target.Dir, "SKILL.md")
	if err := os.WriteFile(skill, foreign, 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := Install(target, false, "test")
	var conflict *ConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("Install over a foreign SKILL.md: err = %v, want ConflictError", err)
	}
	if !strings.Contains(err.Error(), "--force") || !strings.Contains(err.Error(), "SKILL.md") {
		t.Errorf("refusal does not name the file and the way out: %v", err)
	}
	// Nothing was written: the refusal is decided before any write.
	if got, _ := os.ReadFile(skill); !bytes.Equal(got, foreign) {
		t.Error("the foreign file was modified")
	}
	entries, _ := os.ReadDir(target.Dir)
	if len(entries) != 1 {
		t.Errorf("refused install left %d entries, want only the foreign file", len(entries))
	}

	results, err := Install(target, true, "test")
	if err != nil {
		t.Fatalf("--force: %v", err)
	}
	if !hasResult(results, "SKILL.md", ActionReplaced) {
		t.Errorf("--force did not report the replacement: %+v", results)
	}
	assertInstalled(t, target.Dir)
}

func TestInstallRefusesAFileEditedSinceItWasWritten(t *testing.T) {
	env, _ := sandbox(t)
	target, _ := ResolveTarget(AgentOpenCode, ScopeUser, "", env)
	if _, err := Install(target, false, "test"); err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(target.Dir, "SKILL.md")
	if err := os.WriteFile(skill, append(SkillMarkdown(), "\nmy local note\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	var conflict *ConflictError
	if _, err := Install(target, false, "test"); !errors.As(err, &conflict) {
		t.Fatalf("Install over an edited file: err = %v, want ConflictError", err)
	}
}

// An older cilock's copy, still byte-for-byte what it wrote, is updated in
// place; a file it wrote that this skill dropped is removed.
func TestInstallUpdatesAndPrunesWhatCilockWrote(t *testing.T) {
	env, _ := sandbox(t)
	target, _ := ResolveTarget(AgentClaude, ScopeUser, "", env)
	old := []byte("---\nname: pushgate\ndescription: an older release\n---\n")
	gone := []byte("dropped in a later release\n")
	kept := []byte("dropped, but edited by the user\n")
	write := func(rel string, data []byte) {
		p := filepath.Join(target.Dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("SKILL.md", old)
	write("references/old.md", gone)
	write("references/edited.md", kept)
	rec, _ := json.Marshal(record{Skill: SkillName, CilockVersion: "old", Files: map[string]string{
		"SKILL.md":             digest(old),
		"references/old.md":    digest(gone),
		"references/edited.md": digest([]byte("what cilock originally wrote\n")),
	}})
	write(RecordName, rec)

	results, err := Install(target, false, "new")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		path   string
		action Action
	}{
		{"SKILL.md", ActionUpdated},
		{"references/old.md", ActionRemoved},
		{"references/edited.md", ActionKept},
		{RecordName, ActionUpdated},
	} {
		if !hasResult(results, want.path, want.action) {
			t.Errorf("want %s %s in %+v", want.action, want.path, results)
		}
	}
	assertInstalled(t, target.Dir)
	if _, err := os.Stat(filepath.Join(target.Dir, "references", "old.md")); !os.IsNotExist(err) {
		t.Error("stale file cilock wrote was not removed")
	}
	if got, _ := os.ReadFile(filepath.Join(target.Dir, "references", "edited.md")); !bytes.Equal(got, kept) {
		t.Error("a user-edited stale file was touched")
	}
}

func TestInstallRefusesAnUnreadableRecord(t *testing.T) {
	env, _ := sandbox(t)
	target, _ := ResolveTarget(AgentClaude, ScopeUser, "", env)
	if err := os.MkdirAll(target.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target.Dir, RecordName), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(target, false, "test"); err == nil || !strings.Contains(err.Error(), "install record") {
		t.Fatalf("unreadable record: err = %v, want a refusal naming the record", err)
	}
}

func TestInstallNeverWritesThroughASymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	env, _ := sandbox(t)
	target, _ := ResolveTarget(AgentClaude, ScopeUser, "", env)
	elsewhere := t.TempDir()

	// The skill directory itself is a link.
	if err := os.MkdirAll(target.SkillsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, target.Dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(target, true, "test"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("skill dir is a symlink: err = %v, want a refusal", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("install wrote through the link: %v", entries)
	}

	// A subdirectory inside it is a link.
	if err := os.Remove(target.Dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(target.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(target.Dir, "references")); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(target, true, "test"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("references/ is a symlink: err = %v, want a refusal", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Fatalf("install wrote through the link: %v", entries)
	}
}

func TestProjectScopeOutsideARepositoryIsRefused(t *testing.T) {
	env := Env{Home: t.TempDir(), WorkDir: t.TempDir()}
	if _, err := ResolveTarget(AgentCodex, ScopeProject, "", env); err == nil || !strings.Contains(err.Error(), "not inside a Git repository") {
		t.Fatalf("err = %v, want a refusal naming the missing repository", err)
	}
}

func TestExplicitDir(t *testing.T) {
	dir := t.TempDir()
	target, err := ResolveTarget("", ScopeUser, dir, Env{})
	if err != nil {
		t.Fatal(err)
	}
	if target.Dir != filepath.Join(dir, SkillName) || target.Agent != AgentCustom {
		t.Fatalf("target = %+v", target)
	}
	if _, err := Install(target, false, "test"); err != nil {
		t.Fatal(err)
	}
	assertInstalled(t, target.Dir)
}

func TestDetectAgent(t *testing.T) {
	env := func(kv ...string) func(string) string {
		m := map[string]string{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return func(k string) string { return m[k] }
	}
	cases := []struct {
		getenv  func(string) string
		want    Agent
		wantErr string
	}{
		{env("CLAUDECODE", "1"), AgentClaude, ""},
		{env("CODEX_THREAD_ID", "abc"), AgentCodex, ""},
		{env("OPENCODE", "1"), AgentOpenCode, ""},
		{env(), "", "--agent"},
		{env("CLAUDECODE", "1", "CODEX_THREAD_ID", "abc"), "", "more than one agent"},
	}
	for _, tc := range cases {
		got, err := DetectAgent(tc.getenv)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want %q", err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("DetectAgent = %q, %v; want %q", got, err, tc.want)
		}
	}
}

func TestInspect(t *testing.T) {
	env, _ := sandbox(t)
	target, _ := ResolveTarget(AgentClaude, ScopeUser, "", env)
	if s, _ := Inspect(target); s != StateAbsent {
		t.Errorf("before install: %s", s)
	}
	if _, err := Install(target, false, "test"); err != nil {
		t.Fatal(err)
	}
	if s, _ := Inspect(target); s != StateCurrent {
		t.Errorf("after install: %s", s)
	}
	if err := os.WriteFile(filepath.Join(target.Dir, "SKILL.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if s, _ := Inspect(target); s != StateDiffers {
		t.Errorf("after edit: %s", s)
	}
}

func hasResult(results []Result, path string, action Action) bool {
	for _, r := range results {
		if r.Path == path && r.Action == action {
			return true
		}
	}
	return false
}
