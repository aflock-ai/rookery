// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package agentplugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Agent is a coding agent whose skill directory cilock knows.
type Agent string

const (
	AgentClaude   Agent = "claude"
	AgentCodex    Agent = "codex"
	AgentOpenCode Agent = "opencode"
	// AgentCustom is an explicit --dir with no known agent.
	AgentCustom Agent = "custom"
)

// Agents lists the agents in the order help text names them.
var Agents = []Agent{AgentClaude, AgentCodex, AgentOpenCode}

// DisplayName is the agent's product name.
func (a Agent) DisplayName() string {
	switch a {
	case AgentClaude:
		return "Claude Code"
	case AgentCodex:
		return "Codex"
	case AgentOpenCode:
		return "opencode"
	default:
		return "a custom directory"
	}
}

// ParseAgent accepts an agent name. "auto" and "" return "" so the caller
// detects.
func ParseAgent(s string) (Agent, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return "", nil
	case "claude", "claude-code":
		return AgentClaude, nil
	case "codex":
		return AgentCodex, nil
	case "opencode":
		return AgentOpenCode, nil
	}
	return "", fmt.Errorf("unknown agent %q: use claude, codex, opencode, or auto", s)
}

// Scope is where the skill is installed: for this user, or in this project.
type Scope string

const (
	ScopeUser    Scope = "user"
	ScopeProject Scope = "project"
)

// ParseScope accepts a scope name.
func ParseScope(s string) (Scope, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "user":
		return ScopeUser, nil
	case "project":
		return ScopeProject, nil
	}
	return "", fmt.Errorf("unknown scope %q: use user or project", s)
}

// agentSignals are environment variables each agent sets in the environment
// of the commands it runs. They are best-effort hints: an agent may stop
// setting one, and a user can set one by hand. Detection therefore picks an
// agent only when exactly one signal is present, and otherwise refuses and
// asks for --agent rather than guessing.
var agentSignals = map[Agent][]string{
	AgentClaude:   {"CLAUDECODE"},
	AgentCodex:    {"CODEX_THREAD_ID"},
	AgentOpenCode: {"OPENCODE"},
}

// DetectAgent names the agent this process runs under, from its environment.
func DetectAgent(getenv func(string) string) (Agent, error) {
	var found []Agent
	for _, a := range Agents {
		for _, name := range agentSignals[a] {
			if getenv(name) != "" {
				found = append(found, a)
				break
			}
		}
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return "", errors.New("could not tell which agent is running (none of CLAUDECODE, CODEX_THREAD_ID, OPENCODE is set): pass --agent claude, --agent codex, or --agent opencode")
	}
	names := make([]string, len(found))
	for i, a := range found {
		names[i] = string(a)
	}
	return "", fmt.Errorf("the environment looks like more than one agent (%s): pass --agent explicitly", strings.Join(names, ", "))
}

// Env is the part of the process environment target resolution reads. Tests
// supply their own.
type Env struct {
	Home    string
	WorkDir string
	Getenv  func(string) string
}

// Target is where the skill goes, and the discovery rule that makes the agent
// find it there.
type Target struct {
	Agent Agent
	Scope Scope
	// SkillsDir is the agent's skills directory; Dir is SkillsDir/pushgate.
	SkillsDir string
	Dir       string
	// Rule cites how the agent discovers a skill in SkillsDir.
	Rule string
	// Explicit is true when --dir chose the location.
	Explicit bool
	// AlsoReadBy names other agents documented to read the same directory,
	// so a second install for them would load the skill twice.
	AlsoReadBy []Agent
}

// discovery holds each agent's skill directory relative to the scope root
// (the home directory, or the project root) and the documented rule. Each was
// checked against the vendor's documentation on 2026-09-25; the Codex rows
// were also exercised against codex-cli 0.143.0 with `codex debug
// prompt-input`, which listed a skill from each location.
var discovery = map[Agent]map[Scope]struct {
	rel  []string
	rule string
	also []Agent
}{
	AgentClaude: {
		ScopeUser:    {[]string{".claude", "skills"}, "Claude Code loads personal skills from ~/.claude/skills/<name>/SKILL.md (https://code.claude.com/docs/en/skills).", []Agent{AgentOpenCode}},
		ScopeProject: {[]string{".claude", "skills"}, "Claude Code loads project skills from .claude/skills/<name>/SKILL.md in the repository (https://code.claude.com/docs/en/skills).", []Agent{AgentOpenCode}},
	},
	AgentCodex: {
		ScopeUser:    {[]string{".agents", "skills"}, "Codex loads user skills from $HOME/.agents/skills/<name>/SKILL.md (https://developers.openai.com/codex/skills).", []Agent{AgentOpenCode}},
		ScopeProject: {[]string{".agents", "skills"}, "Codex loads repository skills from .agents/skills in the working directory and each parent up to the repository root (https://developers.openai.com/codex/skills).", []Agent{AgentOpenCode}},
	},
	AgentOpenCode: {
		ScopeUser:    {[]string{".config", "opencode", "skills"}, "opencode loads global skills from ~/.config/opencode/skills/<name>/SKILL.md (https://opencode.ai/docs/skills/).", nil},
		ScopeProject: {[]string{".opencode", "skills"}, "opencode loads project skills from .opencode/skills/<name>/SKILL.md, walking up to the git worktree (https://opencode.ai/docs/skills/).", nil},
	},
}

// ResolveTarget picks the install directory. A non-empty dir overrides the
// agent's location and is used as the skills directory (the skill goes in
// dir/pushgate).
func ResolveTarget(agent Agent, scope Scope, dir string, env Env) (Target, error) {
	if dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return Target{}, fmt.Errorf("resolve --dir: %w", err)
		}
		if agent == "" {
			agent = AgentCustom
		}
		return Target{
			Agent:     agent,
			Scope:     scope,
			SkillsDir: abs,
			Dir:       filepath.Join(abs, SkillName),
			Rule:      "Installed to an explicit --dir; cilock did not check that any agent reads it.",
			Explicit:  true,
		}, nil
	}
	rows, ok := discovery[agent]
	if !ok {
		return Target{}, fmt.Errorf("no skill location known for agent %q", agent)
	}
	row := rows[scope]
	var root string
	switch scope {
	case ScopeUser:
		if env.Home == "" {
			return Target{}, errors.New("cannot find the home directory: pass --dir")
		}
		root = env.Home
	case ScopeProject:
		r, err := projectRoot(env.WorkDir)
		if err != nil {
			return Target{}, err
		}
		root = r
	default:
		return Target{}, fmt.Errorf("unknown scope %q", scope)
	}
	skills := filepath.Join(append([]string{root}, row.rel...)...)
	return Target{
		Agent:      agent,
		Scope:      scope,
		SkillsDir:  skills,
		Dir:        filepath.Join(skills, SkillName),
		Rule:       row.rule,
		AlsoReadBy: row.also,
	}, nil
}

// projectRoot walks up from dir to the nearest directory holding a .git entry
// (a directory in a normal clone, a file in a linked worktree). It reads the
// filesystem only; it never runs git.
func projectRoot(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("cannot find the working directory: pass --dir")
	}
	cur, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Lstat(filepath.Join(cur, ".git")); err == nil {
			return cur, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("look for the repository root: %w", err)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", fmt.Errorf("%s is not inside a Git repository: run from the repository, use --scope user, or pass --dir", dir)
		}
		cur = parent
	}
}

// RecordName is the install record cilock writes beside the skill. It lists
// the SHA-256 of every file cilock wrote, which is how a later install tells
// a file it may replace (unchanged since cilock wrote it) from one it must
// not (edited by someone, or never cilock's).
const RecordName = ".cilock-skill.json"

type record struct {
	Skill         string            `json:"skill"`
	CilockVersion string            `json:"cilock_version"`
	Files         map[string]string `json:"files"`
}

// Action is what an install did, or would do, to one file.
type Action string

const (
	ActionWrote     Action = "wrote"
	ActionUpdated   Action = "updated"
	ActionUnchanged Action = "unchanged"
	ActionReplaced  Action = "replaced"
	ActionRemoved   Action = "removed"
	ActionKept      Action = "kept"
)

// Result is one line of the install report. Path is relative to Target.Dir.
type Result struct {
	Path   string
	Action Action
	Note   string
}

// ConflictError lists files the install refused to overwrite.
type ConflictError struct {
	Dir   string
	Files []string
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("refusing to overwrite %d file(s) in %s that cilock did not write, or that were edited since: %s. Move them aside, or pass --force to replace them",
		len(e.Files), e.Dir, strings.Join(e.Files, ", "))
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Install writes the embedded skill into t.Dir. It is idempotent: files that
// already match are left alone and reported as unchanged. It never
// overwrites a file whose current bytes are neither this skill's nor recorded
// in the install record, unless force is set. It plans every file before it
// writes any, so a refusal leaves the directory untouched. It writes only
// inside t.Dir and never through a symbolic link.
func Install(t Target, force bool, cilockVersion string) ([]Result, error) {
	if !filepath.IsAbs(t.Dir) || filepath.Base(t.Dir) != SkillName {
		return nil, fmt.Errorf("install directory %q must be an absolute path ending in %s", t.Dir, SkillName)
	}
	files, err := Files()
	if err != nil {
		return nil, err
	}
	if err := checkNotLink(t.Dir); err != nil {
		return nil, err
	}
	rec, err := readRecord(t.Dir)
	if err != nil && !force {
		return nil, err
	}

	type op struct {
		rel    string
		data   []byte
		action Action
		note   string
	}
	var ops []op
	var conflicts []string
	embedded := map[string]bool{}
	for _, f := range files {
		embedded[f.Path] = true
		dst, err := within(t.Dir, f.Path)
		if err != nil {
			return nil, err
		}
		if err := checkParentsNotLinks(t.Dir, f.Path); err != nil {
			return nil, err
		}
		info, err := os.Lstat(dst)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			ops = append(ops, op{f.Path, f.Data, ActionWrote, ""})
			continue
		case err != nil:
			return nil, fmt.Errorf("inspect %s: %w", dst, err)
		}
		if !info.Mode().IsRegular() {
			if !force {
				conflicts = append(conflicts, f.Path+" (not a regular file)")
				continue
			}
			ops = append(ops, op{f.Path, f.Data, ActionReplaced, "was not a regular file; --force"})
			continue
		}
		current, err := os.ReadFile(dst)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", dst, err)
		}
		switch {
		case bytes.Equal(current, f.Data):
			ops = append(ops, op{f.Path, nil, ActionUnchanged, ""})
		case rec != nil && rec.Files[f.Path] == digest(current):
			ops = append(ops, op{f.Path, f.Data, ActionUpdated, ""})
		case force:
			ops = append(ops, op{f.Path, f.Data, ActionReplaced, "not written by cilock, or edited since; --force"})
		default:
			conflicts = append(conflicts, f.Path)
		}
	}
	if len(conflicts) > 0 {
		return nil, &ConflictError{Dir: t.Dir, Files: conflicts}
	}

	// Files an older cilock wrote that this skill no longer has: remove them
	// only when they are still byte-for-byte what cilock wrote.
	var stale []string
	if rec != nil {
		for rel := range rec.Files {
			if !embedded[rel] {
				stale = append(stale, rel)
			}
		}
		sort.Strings(stale)
	}

	var results []Result
	for _, o := range ops {
		if o.data != nil {
			dst, _ := within(t.Dir, o.rel)
			if err := writeFileAtomic(dst, o.data); err != nil {
				return results, err
			}
		}
		results = append(results, Result{Path: o.rel, Action: o.action, Note: o.note})
	}
	for _, rel := range stale {
		dst, err := within(t.Dir, rel)
		if err != nil {
			results = append(results, Result{Path: rel, Action: ActionKept, Note: "listed in the install record with an invalid path; left alone"})
			continue
		}
		info, err := os.Lstat(dst)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			results = append(results, Result{Path: rel, Action: ActionKept, Note: "no longer part of the skill; not a regular file, left alone"})
			continue
		}
		current, err := os.ReadFile(dst)
		if err != nil || digest(current) != rec.Files[rel] {
			results = append(results, Result{Path: rel, Action: ActionKept, Note: "no longer part of the skill, but edited since cilock wrote it; left alone"})
			continue
		}
		if err := os.Remove(dst); err != nil {
			return results, fmt.Errorf("remove stale %s: %w", dst, err)
		}
		results = append(results, Result{Path: rel, Action: ActionRemoved, Note: "no longer part of the skill"})
	}

	next := record{Skill: SkillName, CilockVersion: cilockVersion, Files: map[string]string{}}
	for _, f := range files {
		next.Files[f.Path] = digest(f.Data)
	}
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return results, err
	}
	data = append(data, '\n')
	recPath := filepath.Join(t.Dir, RecordName)
	if old, err := os.ReadFile(recPath); err == nil && bytes.Equal(old, data) {
		results = append(results, Result{Path: RecordName, Action: ActionUnchanged, Note: "install record"})
	} else {
		action := ActionWrote
		if err == nil {
			action = ActionUpdated
		}
		if err := writeFileAtomic(recPath, data); err != nil {
			return results, err
		}
		results = append(results, Result{Path: RecordName, Action: action, Note: "install record"})
	}
	return results, nil
}

// State reports whether the skill at t.Dir matches this binary's copy.
type State string

const (
	StateAbsent  State = "not installed"
	StateCurrent State = "installed, matches this cilock"
	StateDiffers State = "installed, differs from this cilock"
	StateNotDir  State = "present but not a plain directory (a file or a symbolic link)"
)

// Inspect reports the state of the skill at t.Dir without writing anything.
func Inspect(t Target) (State, error) {
	info, err := os.Lstat(t.Dir)
	if errors.Is(err, fs.ErrNotExist) {
		return StateAbsent, nil
	}
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return StateNotDir, nil
	}
	files, err := Files()
	if err != nil {
		return "", err
	}
	for _, f := range files {
		current, err := os.ReadFile(filepath.Join(t.Dir, filepath.FromSlash(f.Path)))
		if err != nil || !bytes.Equal(current, f.Data) {
			return StateDiffers, nil
		}
	}
	return StateCurrent, nil
}

func readRecord(dir string) (*record, error) {
	data, err := os.ReadFile(filepath.Join(dir, RecordName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read install record: %w", err)
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil || rec.Skill != SkillName || rec.Files == nil {
		return nil, fmt.Errorf("the install record %s is unreadable, so cilock cannot tell which files it wrote: move the directory aside, or pass --force", filepath.Join(dir, RecordName))
	}
	return &rec, nil
}

// within joins a slash-separated relative path under dir and refuses any
// path that would leave it.
func within(dir, rel string) (string, error) {
	local := filepath.FromSlash(rel)
	if !filepath.IsLocal(local) {
		return "", fmt.Errorf("skill file path %q escapes the install directory", rel)
	}
	return filepath.Join(dir, local), nil
}

func checkNotLink(p string) error {
	info, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", p, err)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link: cilock writes only into a real directory. Remove the link or pass --dir", p)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", p)
	}
	return nil
}

// checkParentsNotLinks refuses a symbolic link at any directory between the
// install directory and a file, so a write cannot be steered outside it.
func checkParentsNotLinks(dir, rel string) error {
	parts := strings.Split(filepath.Dir(filepath.FromSlash(rel)), string(filepath.Separator))
	cur := dir
	for _, part := range parts {
		if part == "." || part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		if err := checkNotLink(cur); err != nil {
			return err
		}
	}
	return nil
}

// writeFileAtomic writes through a temporary file in the same directory and
// renames it into place. Rename replaces a symbolic link rather than
// following it.
func writeFileAtomic(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".cilock-skill-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	if err := os.Rename(name, dst); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return nil
}
