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
	"strings"
)

// RenderSuggestedCommand applies a SuggestedFix declaratively to the
// original argv and returns the resulting argv as a new slice. The
// original argv is never mutated. This function is the ONLY consumer
// of SuggestedFix — cilock never executes a fixed command, only
// displays one. Plugin authors describe the change; cilock formats it.
//
// Operations are applied in a stable order (replace_argv → insert_arg
// → prepend_args → append_args → set_env). set_env does not modify the
// argv but is recorded in extras for the warning's stderr line.
//
// Returns the fixed argv, an env override map (may be nil), and a
// human-readable one-line diff describing what changed.
func RenderSuggestedCommand(original []string, fix *SuggestedFix) (suggested []string, envOverride map[string]string, diff string) {
	if fix == nil || len(original) == 0 {
		return nil, nil, ""
	}

	// Work on a copy. Composition order is fixed so plugin authors
	// don't have to worry about reordering.
	out := append([]string{}, original...)
	diffParts := make([]string, 0, 4)

	if fix.ReplaceArgv != nil {
		newOut, ok := applyReplace(out, fix.ReplaceArgv.From, fix.ReplaceArgv.To)
		if ok {
			out = newOut
			diffParts = append(diffParts, fmt.Sprintf("replaced %v → %v", fix.ReplaceArgv.From, fix.ReplaceArgv.To))
		}
	}

	if fix.InsertArg != nil {
		newOut, where := applyInsert(out, fix.InsertArg)
		out = newOut
		if where != "" {
			diffParts = append(diffParts, fmt.Sprintf("inserted %q %s", fix.InsertArg.Value, where))
		}
	}

	if len(fix.PrependArgs) > 0 {
		// Prepend after argv[0] so we don't rewrite the program. If
		// callers really want to prepend before argv[0] (e.g. wrapper
		// scripts), the SuggestedFix vocabulary explicitly does not
		// support it — that's a different invocation, not a fix.
		head := append([]string{out[0]}, fix.PrependArgs...)
		out = append(head, out[1:]...)
		diffParts = append(diffParts, fmt.Sprintf("prepended %v after %q", fix.PrependArgs, out[0]))
	}

	if len(fix.AppendArgs) > 0 {
		out = append(out, fix.AppendArgs...)
		diffParts = append(diffParts, fmt.Sprintf("appended %v", fix.AppendArgs))
	}

	if fix.SetEnv != nil && fix.SetEnv.Var != "" {
		envOverride = map[string]string{fix.SetEnv.Var: fix.SetEnv.Value}
		diffParts = append(diffParts, fmt.Sprintf("set %s=%s", fix.SetEnv.Var, fix.SetEnv.Value))
	}

	if len(diffParts) == 0 {
		return original, nil, ""
	}
	return out, envOverride, strings.Join(diffParts, "; ")
}

// applyReplace finds the first contiguous occurrence of `from` in argv
// and replaces it with `to`. Returns the new argv and whether the
// replacement was applied. If `from` is not found, the original argv
// is returned unchanged and ok is false.
func applyReplace(argv, from, to []string) ([]string, bool) {
	if len(from) == 0 || len(argv) < len(from) {
		return argv, false
	}
	for i := 0; i+len(from) <= len(argv); i++ {
		if argvSliceEqual(argv[i:i+len(from)], from) {
			out := make([]string, 0, len(argv)-len(from)+len(to))
			out = append(out, argv[:i]...)
			out = append(out, to...)
			out = append(out, argv[i+len(from):]...)
			return out, true
		}
	}
	return argv, false
}

// applyInsert inserts the given value into argv according to the
// InsertArgOp's anchor. Returns the new argv and a short description
// of where the insertion happened (for the diff string). If no anchor
// matches, the argv is returned unchanged.
func applyInsert(argv []string, op *InsertArgOp) ([]string, string) {
	// Position-based insertion takes priority when set.
	if op.Position != nil {
		pos := *op.Position
		if pos < 0 {
			pos = 0
		}
		if pos > len(argv) {
			pos = len(argv)
		}
		out := make([]string, 0, len(argv)+1)
		out = append(out, argv[:pos]...)
		out = append(out, op.Value)
		out = append(out, argv[pos:]...)
		return out, fmt.Sprintf("at position %d", pos)
	}

	// after_subcommand: find the latest occurrence of any anchor
	// argument and insert immediately after it. "Latest" so that a
	// subcommand like "buildx build" inserts after "build", not after
	// "buildx".
	if len(op.AfterSubcommand) > 0 {
		anchorSet := make(map[string]bool, len(op.AfterSubcommand))
		for _, a := range op.AfterSubcommand {
			anchorSet[a] = true
		}
		insertAt := -1
		matched := ""
		for i, a := range argv {
			if anchorSet[a] {
				insertAt = i + 1
				matched = a
			}
		}
		if insertAt > 0 {
			out := make([]string, 0, len(argv)+1)
			out = append(out, argv[:insertAt]...)
			out = append(out, op.Value)
			out = append(out, argv[insertAt:]...)
			return out, fmt.Sprintf("after %q", matched)
		}
		// No anchor matched — fall back to appending at end. This is
		// less surprising than silently dropping the insert. Callers
		// notice via the diff string.
		out := append(append([]string{}, argv...), op.Value)
		return out, "appended (anchor not found)"
	}

	// No anchor specified at all: append.
	out := append(append([]string{}, argv...), op.Value)
	return out, "appended"
}

// argvSliceEqual compares two argv slices for exact positional equality.
func argvSliceEqual(a, b []string) bool {
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

// FormatSuggestedCommand returns the suggested command as a single
// shell-paste-ready string for the human stderr output. Env overrides
// are rendered as leading "KEY=VALUE" assignments. Argv entries that
// contain whitespace or shell-meaningful characters are quoted with
// single quotes (with embedded single quotes escaped).
//
// This is intentionally not "shell-safe quoting" in the security
// sense — the user is reading the line and re-typing it. We just want
// it to round-trip through a copy-paste.
func FormatSuggestedCommand(argv []string, envOverride map[string]string) string {
	parts := make([]string, 0, len(argv)+len(envOverride))
	for k, v := range envOverride {
		parts = append(parts, fmt.Sprintf("%s=%s", k, shellQuoteIfNeeded(v)))
	}
	for _, a := range argv {
		parts = append(parts, shellQuoteIfNeeded(a))
	}
	return strings.Join(parts, " ")
}

func shellQuoteIfNeeded(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t\n\"'\\$`&;|<>(){}[]*?#~!") {
		return s
	}
	// Single-quote with embedded-quote escape: ' → '\''
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
