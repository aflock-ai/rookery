// Copyright 2026 The Rookery Contributors
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

package attestation

import (
	"github.com/gobwas/glob"
)

// CachePathMatcher compiles a set of glob patterns and answers
// "is this path a cache/temp artifact?" per file. Built from the
// configured pattern list (defaults ∪ env-derived ∪ user additions,
// minus user allows, optionally with defaults disabled).
//
// Compiled once at attestor-start time and reused across every file
// the framework needs to classify. Pattern compilation is O(N) in
// the pattern count; matching is O(1) per file (linear scan over
// compiled globs, short-circuit on first match).
type CachePathMatcher struct {
	patterns []glob.Glob
}

// NewCachePathMatcher compiles the given patterns. Invalid globs are
// skipped with a soft failure (returned via the error sentinel slice)
// so a typo in one CLI flag doesn't block the whole attestation.
func NewCachePathMatcher(patterns []string) (*CachePathMatcher, []error) {
	m := &CachePathMatcher{patterns: make([]glob.Glob, 0, len(patterns))}
	var errs []error
	for _, p := range patterns {
		g, err := glob.Compile(p, '/')
		if err != nil {
			errs = append(errs, err)
			continue
		}
		m.patterns = append(m.patterns, g)
	}
	return m, errs
}

// Matches returns true if any compiled pattern matches the path.
// Used to classify a file as cache/temp during product attestation.
// Short-circuits on first match.
func (m *CachePathMatcher) Matches(path string) bool {
	if m == nil || len(m.patterns) == 0 {
		return false
	}
	for _, g := range m.patterns {
		if g.Match(path) {
			return true
		}
	}
	return false
}

// ResolveCachePatterns merges the configured sources into a single
// deduplicated pattern slice. Order:
//
//  1. Built-in defaults (DefaultCachePatterns) — unless disabled
//  2. System-discovered env-derived patterns (SystemCachePathsFromEnv)
//     — unless disabled
//  3. User-added patterns (additive)
//  4. User-allowed patterns are REMOVED from the final set (operator
//     opt-out for specific defaults/system patterns)
//
// The final list is passed to NewCachePathMatcher.
func ResolveCachePatterns(opts CachePatternOptions) []string {
	out := make(map[string]struct{}, 256)
	if !opts.DisableDefaults {
		for p := range DefaultCachePatterns() {
			out[p] = struct{}{}
		}
	}
	if !opts.DisableSystemQuery {
		for _, p := range SystemCachePathsFromEnv() {
			out[p] = struct{}{}
		}
	}
	for _, p := range opts.Add {
		out[p] = struct{}{}
	}
	for _, p := range opts.Allow {
		delete(out, p)
	}
	patterns := make([]string, 0, len(out))
	for p := range out {
		patterns = append(patterns, p)
	}
	return patterns
}

// CachePatternOptions controls how the framework constructs the
// effective cache pattern list. Wired from CLI flags + env vars on
// the cilock side; defaulted to "use built-ins + env query" for
// callers that don't customize.
type CachePatternOptions struct {
	// Add appends user-supplied patterns to the effective set.
	// Glob syntax (gobwas/glob): * matches any non-/ sequence;
	// ** matches any sequence including /. Repeatable via
	// --cache-add-pattern.
	Add []string

	// Allow removes patterns from the effective set. Useful when
	// a default classifies something the operator wants to treat
	// as a product instead. Matches exact pattern strings, not
	// paths — e.g., --cache-allow-pattern="**/target/release/**"
	// to keep release binaries as products on a Rust project.
	Allow []string

	// DisableDefaults drops the entire DefaultCachePatterns set
	// from the effective list. Operators who want full control
	// of classification (e.g., a sealed-environment compliance
	// build) use this + an explicit Add list.
	DisableDefaults bool

	// DisableSystemQuery drops env-var-derived patterns. Useful
	// in containerized builds where the host env should NOT
	// influence cache classification.
	DisableSystemQuery bool
}
