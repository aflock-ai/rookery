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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
)

// evalArgvPrefix matches if the leading positions of ctx.Argv equal the
// given prefix. Strict positional match — no globbing, no skipping. For
// `docker --debug build`, an `argv_prefix: [docker, build]` does NOT
// match because argv[1] is "--debug". Plugins that need to skip global
// flags compose with argv_contains or argv_regex.
func evalArgvPrefix(prefix []string, ctx *EvalContext) EvalResult {
	if len(prefix) == 0 {
		return EvalResult{State: StateNoMatch, Rule: "argv_prefix:empty"}
	}
	if len(ctx.Argv) < len(prefix) {
		return EvalResult{State: StateNoMatch, Rule: "argv_prefix:short"}
	}
	for i, want := range prefix {
		got := ctx.Argv[i]
		if i == 0 {
			// argv[0] is the program path. Match against its basename
			// too, so "/usr/bin/docker" matches `argv_prefix: [docker]`.
			if got != want && filepath.Base(got) != want {
				return EvalResult{
					State: StateNoMatch,
					Rule:  fmt.Sprintf("argv_prefix:miss[0]:%s!=%s", got, want),
				}
			}
			continue
		}
		if got != want {
			return EvalResult{
				State: StateNoMatch,
				Rule:  fmt.Sprintf("argv_prefix:miss[%d]:%s!=%s", i, got, want),
			}
		}
	}
	return EvalResult{
		State: StateMatch,
		Rule:  "argv_prefix:" + strings.Join(prefix, "."),
	}
}

// evalArgvContains matches if any contiguous substring of the joined argv
// equals the needle. Joins with single spaces.
func evalArgvContains(needle string, ctx *EvalContext) EvalResult {
	if needle == "" {
		return EvalResult{State: StateNoMatch, Rule: "argv_contains:empty"}
	}
	if strings.Contains(joinArgv(ctx.Argv), needle) {
		return EvalResult{State: StateMatch, Rule: "argv_contains:" + needle}
	}
	return EvalResult{State: StateNoMatch, Rule: "argv_contains:miss"}
}

// evalArgvRegex matches if the regex matches the joined argv. Designed
// to be the escape hatch — the schema validator discourages it as a
// sole predicate in a group.
func evalArgvRegex(pattern string, ctx *EvalContext) EvalResult {
	if pattern == "" {
		return EvalResult{State: StateNoMatch, Rule: "argv_regex:empty"}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		// Validation should have caught this at parse time; defense
		// in depth: a runtime regex compile failure is a no-match.
		return EvalResult{State: StateNoMatch, Rule: "argv_regex:invalid:" + err.Error()}
	}
	if re.MatchString(joinArgv(ctx.Argv)) {
		return EvalResult{State: StateMatch, Rule: "argv_regex:" + pattern}
	}
	return EvalResult{State: StateNoMatch, Rule: "argv_regex:miss"}
}

// evalEnvSet matches if the named env var is present, regardless of value.
func evalEnvSet(name string, ctx *EvalContext) EvalResult {
	if name == "" {
		return EvalResult{State: StateNoMatch, Rule: "env_set:empty"}
	}
	ctx.observedEnv[name] = true
	if _, ok := ctx.Env[name]; ok {
		return EvalResult{State: StateMatch, Rule: "env_set:" + name}
	}
	return EvalResult{State: StateNoMatch, Rule: "env_set:" + name + ":miss"}
}

// evalEnvEquals matches if the named env var has the given value.
func evalEnvEquals(leaf *EnvEqualsLeaf, ctx *EvalContext) EvalResult {
	if leaf == nil || leaf.Var == "" {
		return EvalResult{State: StateNoMatch, Rule: "env_equals:empty"}
	}
	ctx.observedEnv[leaf.Var] = true
	got, ok := ctx.Env[leaf.Var]
	if !ok {
		return EvalResult{State: StateNoMatch, Rule: "env_equals:unset:" + leaf.Var}
	}
	if got == leaf.Value {
		return EvalResult{State: StateMatch, Rule: "env_equals:" + leaf.Var + "=" + leaf.Value}
	}
	return EvalResult{State: StateNoMatch, Rule: "env_equals:differ:" + leaf.Var}
}

// evalFileExists matches if the named path exists relative to the cwd.
// Path is normalized via filepath.FromSlash so detector.yaml authors
// can write forward-slash paths that work on Windows too.
func evalFileExists(path string, ctx *EvalContext) EvalResult {
	if path == "" {
		return EvalResult{State: StateNoMatch, Rule: "file_exists:empty"}
	}
	resolved := resolveWorkspacePath(ctx.Cwd, path)
	if _, err := os.Stat(resolved); err == nil {
		return EvalResult{State: StateMatch, Rule: "file_exists:" + path}
	}
	return EvalResult{State: StateNoMatch, Rule: "file_exists:miss:" + path}
}

// evalFileGlob matches if any file at or under cwd matches any of the
// glob patterns. Globs use gobwas/glob (the same library product.go
// uses) for consistent semantics across the codebase.
//
// Walking is bounded to a single level of cwd for now — descending the
// entire tree is too expensive for a planning step that may also run in
// `cilock plan` (dry-run) on every invocation. If plugins need recursive
// matching, the pattern should use "**/" prefix; the walk handles that
// case explicitly without scanning unrelated subtrees.
func evalFileGlob(patterns []string, ctx *EvalContext) EvalResult {
	if len(patterns) == 0 {
		return EvalResult{State: StateNoMatch, Rule: "file_glob:empty"}
	}
	cwd := ctx.Cwd
	if cwd == "" {
		cwd = "."
	}

	// Compile patterns; bail on first compile failure with no-match
	// (validation should have caught it).
	compiled := make([]glob.Glob, 0, len(patterns))
	hasRecursive := false
	for _, p := range patterns {
		g, err := glob.Compile(p, '/')
		if err != nil {
			return EvalResult{State: StateNoMatch, Rule: "file_glob:invalid:" + err.Error()}
		}
		compiled = append(compiled, g)
		if strings.Contains(p, "**") {
			hasRecursive = true
		}
	}

	if walkForGlobMatch(cwd, cwd, compiled, hasRecursive) {
		return EvalResult{State: StateMatch, Rule: "file_glob:" + strings.Join(patterns, ",")}
	}
	return EvalResult{State: StateNoMatch, Rule: "file_glob:miss"}
}

// walkForGlobMatch recursively scans root looking for any entry whose
// cwd-relative path (forward-slash normalized) matches any compiled
// pattern. Returns true on the first match. Descents are filtered by
// shouldDescend; symlinks are not followed.
func walkForGlobMatch(root, cwd string, compiled []glob.Glob, recursive bool) bool {
	entries, err := os.ReadDir(root)
	if err != nil {
		return false
	}
	for _, e := range entries {
		full := filepath.Join(root, e.Name())
		rel, err := filepath.Rel(cwd, full)
		if err != nil {
			continue
		}
		relSlash := filepath.ToSlash(rel)
		for _, g := range compiled {
			if matched, _ := safeGlobMatch(g, relSlash); matched {
				return true
			}
		}
		if recursive && e.IsDir() && shouldDescend(e.Name()) {
			if walkForGlobMatch(full, cwd, compiled, recursive) {
				return true
			}
		}
	}
	return false
}

// shouldDescend filters out directories that almost never carry signal
// for detection (node_modules, .git, vendor, etc.) and waste walk time.
// This is a heuristic — over-pruning costs a missed file_glob match,
// under-pruning costs walk time on huge trees.
func shouldDescend(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", ".tox", "target", "build", "dist":
		return false
	}
	if strings.HasPrefix(name, ".") {
		// hidden dirs other than the well-known ones above are
		// usually configuration; skip them for performance.
		return false
	}
	return true
}

// evalBinaryDigestIn evaluates the binary_digest_in predicate. The
// "tool_class:<name>" allowlist mechanism is reserved syntax in v0.1;
// no allowlist is shipped, so this predicate is currently a no-op that
// always returns no-match. The plumbing exists so schema validation
// accepts the field; the resolution mechanism lands in a later release.
// The ctx parameter is retained to keep the evaluator signature uniform.
func evalBinaryDigestIn(toolClass string, _ *EvalContext) EvalResult {
	if !strings.HasPrefix(toolClass, "tool_class:") {
		return EvalResult{State: StateNoMatch, Rule: "binary_digest_in:invalid:" + toolClass}
	}
	// Allowlist resolution is deferred; for now this always misses.
	return EvalResult{State: StateNoMatch, Rule: "binary_digest_in:reserved:" + toolClass}
}

// resolveWorkspacePath joins a cwd-relative path with cwd, normalizing
// forward-slash separators so detector.yaml authors can write paths
// portably. Absolute paths pass through untouched.
func resolveWorkspacePath(cwd, p string) string {
	if cwd == "" {
		cwd = "."
	}
	p = filepath.FromSlash(p)
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(cwd, p)
}

// safeGlobMatch wraps glob.Match with panic recovery. Mirrors the same
// helper in plugins/attestors/product/product.go — gobwas/glob can
// panic on certain pathological patterns; treat panics as non-matches.
func safeGlobMatch(g glob.Glob, s string) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched = false
			err = fmt.Errorf("glob match panicked: %v", r)
		}
	}()
	return g.Match(s), nil
}
