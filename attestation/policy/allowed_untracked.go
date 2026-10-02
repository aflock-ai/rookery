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

package policy

import (
	"fmt"
	"path"
	"regexp"
	"sort"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/gobwas/glob"
)

// allowedUntrackedMatcher is the compiled form of Step.AllowedUntracked.
//
// Semantics (pinned by TestMatchAllowedUntracked and, over every short pattern
// and path, TestAllowedUntrackedMatchesReference):
//   - each pattern is a gobwas/glob with '/' as the separator, so '*' stays
//     inside one path segment and '**' crosses segments. gobwas only decides
//     which patterns are valid. Matching is the RE2 translation cert
//     constraints use (certglob.go), because gobwas's matcher let the
//     literals on each side of '**' overlap: "a**a" admitted "a", and
//     "vendor/**/x.go" admitted "vendor/x.go" while "vendor/**/*.go" refused
//     "vendor/a.go". Here the literals never share bytes. The translation
//     also refuses a few patterns gobwas accepted (an unclosed '{', an
//     inverted range), and reads two that gobwas refused paths for as their
//     grammar says: a run of three or more '*' is '**' ("a***" admits "a"),
//     and an empty alternative matches nothing ("*{}" admits "a");
//   - the material path is matched exactly as the material attestor recorded
//     it after a lexical path.Clean. There is no absolute/relative
//     normalization, so "/vendor/**" never matches "vendor/a.go";
//   - path.Clean runs BEFORE matching so "vendor/../../etc/passwd" cannot
//     ride a "vendor/**" allowance out of its prefix.
type allowedUntrackedMatcher struct {
	globs []*regexp.Regexp
}

// compileAllowedUntracked compiles the patterns, failing on the first invalid
// or empty one. An empty pattern list yields a matcher that matches nothing,
// which is the documented strict default.
func compileAllowedUntracked(patterns []string) (allowedUntrackedMatcher, error) {
	m := allowedUntrackedMatcher{globs: make([]*regexp.Regexp, 0, len(patterns))}
	for i, p := range patterns {
		if p == "" {
			return allowedUntrackedMatcher{}, fmt.Errorf("allowedUntracked[%d]: empty pattern", i)
		}
		if _, err := glob.Compile(p, '/'); err != nil {
			return allowedUntrackedMatcher{}, fmt.Errorf("allowedUntracked[%d] %q: %w", i, p, err)
		}
		expr, err := globToRegexp(p, '/')
		if err != nil {
			return allowedUntrackedMatcher{}, fmt.Errorf("allowedUntracked[%d] %q: %w", i, p, err)
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return allowedUntrackedMatcher{}, fmt.Errorf("allowedUntracked[%d] %q: %w", i, p, err)
		}
		m.globs = append(m.globs, re)
	}
	return m, nil
}

func (m allowedUntrackedMatcher) matches(materialPath string) bool {
	if len(m.globs) == 0 || materialPath == "" {
		return false
	}
	cleaned := path.Clean(materialPath)
	for _, re := range m.globs {
		if re.MatchString(cleaned) {
			return true
		}
	}
	return false
}

// AllowsUntracked reports whether materialPath matches one of the step's
// AllowedUntracked globs, with exactly the semantics the verifier applies
// (see allowedUntrackedMatcher). It says nothing about coverage by an
// upstream step; it answers only "would the allow-list admit this path if no
// artifactsFrom step produced it". An invalid pattern returns an error.
func (s Step) AllowsUntracked(materialPath string) (bool, error) {
	m, err := compileAllowedUntracked(s.AllowedUntracked)
	if err != nil {
		return false, err
	}
	return m.matches(materialPath), nil
}

// untrackedMaterials returns the sorted material paths that no accepted
// upstream collection produced (covered) and no AllowedUntracked pattern
// admits.
//
// A material whose spelling differs from an upstream path but cleans to it
// ("./app.bin" vs "app.bin") is an ALIAS: compareArtifacts keys on the raw
// path, so it never digest-compared that material. It is reported as
// untracked and no glob may admit it, or a glob such as "*.bin" would let a
// substituted file ride in under an alternate spelling.
func untrackedMaterials(mats map[string]cryptoutil.DigestSet, covered map[string]struct{}, allowed allowedUntrackedMatcher) []string {
	cleanCovered := make(map[string]struct{}, len(covered))
	for p := range covered {
		cleanCovered[path.Clean(p)] = struct{}{}
	}
	var out []string
	for p := range mats {
		if _, ok := covered[p]; ok {
			continue
		}
		if _, alias := cleanCovered[path.Clean(p)]; alias {
			out = append(out, p)
			continue
		}
		if allowed.matches(p) {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// checkAllowedUntracked applies Step.AllowedUntracked (#9815) once every
// artifactsFrom edge has accepted at least one upstream collection. covered is
// the union of those collections' artifact paths; a covered path's digest was
// already checked by compareArtifacts.
//
// Under HardeningOptions.EnforceAllowedUntracked an untracked material rejects
// the collection. Without it the pre-#9815 behavior stands and the untracked
// paths are only logged.
func checkAllowedUntracked(step Step, mats map[string]cryptoutil.DigestSet, covered map[string]struct{}) error {
	if len(step.ArtifactsFrom) == 0 || len(mats) == 0 {
		return nil
	}
	allowed, err := compileAllowedUntracked(step.AllowedUntracked)
	if err != nil {
		// Validate rejects this at load time; fail closed if a caller skipped it.
		return ErrVerifyArtifactsFailed{Reasons: []string{fmt.Sprintf("step %s: %v", step.Name, err)}}
	}
	untracked := untrackedMaterials(mats, covered, allowed)
	if len(untracked) == 0 {
		return nil
	}
	uerr := ErrUntrackedMaterials{Step: step.Name, Paths: untracked}
	if !Hardening().EnforceAllowedUntracked {
		log.Warnf("%v (not enforced: set HardeningOptions.EnforceAllowedUntracked, or use cilock's default --policy-hardening=enforce)", uerr)
		return nil
	}
	return ErrVerifyArtifactsFailed{Reasons: []string{uerr.Error()}}
}
