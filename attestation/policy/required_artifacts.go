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
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/gobwas/glob"
)

// compileRequiredArtifacts compiles Step.RequiredArtifacts (#9946): gobwas
// globs with '/' as the separator. An empty or invalid pattern is an error, so
// a typo can never turn into a requirement nothing satisfies silently (or one
// everything satisfies).
func compileRequiredArtifacts(patterns []string) ([]glob.Glob, error) {
	out := make([]glob.Glob, 0, len(patterns))
	for i, p := range patterns {
		if p == "" {
			return nil, fmt.Errorf("requiredArtifacts[%d]: empty pattern", i)
		}
		g, err := glob.Compile(p, '/')
		if err != nil {
			return nil, fmt.Errorf("requiredArtifacts[%d] %q: %w", i, p, err)
		}
		out = append(out, g)
	}
	return out, nil
}

// validateRequiredArtifacts is the load-time check: the patterns compile, and
// the step has an artifactsFrom edge for them to be satisfied through.
func validateRequiredArtifacts(step Step) error {
	if len(step.RequiredArtifacts) == 0 {
		return nil
	}
	if len(step.ArtifactsFrom) == 0 {
		return fmt.Errorf("requiredArtifacts needs artifactsFrom: nothing upstream can satisfy it")
	}
	_, err := compileRequiredArtifacts(step.RequiredArtifacts)
	return err
}

// ErrRequiredArtifactMissing is returned when a step declares a
// requiredArtifacts pattern that no material consumed from an accepted
// artifactsFrom collection satisfies.
type ErrRequiredArtifactMissing struct {
	Step     string
	Patterns []string
}

func (e ErrRequiredArtifactMissing) Error() string {
	return fmt.Sprintf("step %q: requiredArtifacts %s matched no material consumed from an artifactsFrom step (the artifact must be recorded as a material at the path the upstream step produced it, with the same digest)",
		e.Step, strings.Join(e.Patterns, ", "))
}

// checkRequiredArtifacts enforces Step.RequiredArtifacts. covered holds the
// raw artifact paths of every upstream collection that passed the per-edge
// digest compare, so a material path found in covered was consumed with the
// upstream digest. Each pattern must match at least one such path.
func checkRequiredArtifacts(step Step, mats map[string]cryptoutil.DigestSet, covered map[string]struct{}) error {
	if len(step.RequiredArtifacts) == 0 {
		return nil
	}
	globs, err := compileRequiredArtifacts(step.RequiredArtifacts)
	if err != nil {
		return ErrVerifyArtifactsFailed{Reasons: []string{fmt.Sprintf("step %s: %v", step.Name, err)}}
	}
	var missing []string
	for i, g := range globs {
		found := false
		for p := range mats {
			if _, ok := covered[p]; !ok {
				continue
			}
			// A panicking match (err) counts as no match: fail closed.
			if ok, err := safeGlobMatch(g, path.Clean(p)); ok && err == nil {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, step.RequiredArtifacts[i])
		}
	}
	if len(missing) > 0 {
		return ErrVerifyArtifactsFailed{Reasons: []string{ErrRequiredArtifactMissing{Step: step.Name, Patterns: missing}.Error()}}
	}
	return nil
}
