// Copyright 2025 The Witness Contributors
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
	"math"
	"strconv"
	"strings"
)

// Validation of AI policies. EVERY rule here fails closed.
//
// The rule this file exists for is the vacuous one: a decision with no
// assertion on its answer has nothing to be false about, so it would PASS
// whatever the model replied. An unasserted gate that always says yes is
// worse than no gate, because it reads as coverage. The same reasoning drives
// the allow/deny membership rule — an assertion naming an option the model can
// never return is an assertion that never fires.

// Validate checks that this AI policy is well formed. It is called before any
// network round trip, so a malformed policy costs no inference.
func (p AiPolicy) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("AI policy name must not be empty")
	}

	// Rule 3 keeps the historical text from the generative path verbatim, so
	// a policy author sees the same message whichever entry point refuses.
	if p.Model == "" {
		return fmt.Errorf("AI policy %q must specify a model; the open-source policy engine does not ship a default", p.Name)
	}

	switch {
	case p.Prompt != "" && p.Decision != nil:
		return fmt.Errorf("AI policy %q must set exactly one of %q or %q; both are set", p.Name, "prompt", "decision")
	case p.Prompt == "" && p.Decision == nil:
		return fmt.Errorf("AI policy %q must set exactly one of %q or %q; neither is set", p.Name, "prompt", "decision")
	case p.Decision == nil:
		// Generative form: nothing further to check.
		return nil
	}

	return p.Decision.validate(p.Name)
}

// validate checks the typed-decision form. name is the owning policy's name,
// carried through so every message identifies the offending policy.
func (d *AiDecision) validate(name string) error {
	set := make([]string, 0, 3)
	if d.YesNo != nil {
		set = append(set, "yesNo")
	}
	if d.Choice != nil {
		set = append(set, "choice")
	}
	if d.Score != nil {
		set = append(set, "score")
	}

	switch len(set) {
	case 1:
	case 0:
		return fmt.Errorf("AI policy %q decision must set exactly one of %q, %q or %q; none is set",
			name, "yesNo", "choice", "score")
	default:
		return fmt.Errorf("AI policy %q decision must set exactly one of %q, %q or %q; %d are set (%s)",
			name, "yesNo", "choice", "score", len(set), strings.Join(set, ", "))
	}

	switch {
	case d.YesNo != nil:
		return d.YesNo.validate(name)
	case d.Choice != nil:
		return d.Choice.validate(name)
	default:
		return d.Score.validate(name)
	}
}

func (y *AiYesNo) validate(name string) error {
	if y.MinProbability == nil && y.MaxProbability == nil {
		return fmt.Errorf("AI policy %q yesNo decision must set at least one of %q or %q; a decision that asserts nothing about the answer passes vacuously",
			name, "minProbability", "maxProbability")
	}
	if err := inUnitInterval(name, "yesNo", "minProbability", y.MinProbability); err != nil {
		return err
	}
	if err := inUnitInterval(name, "yesNo", "maxProbability", y.MaxProbability); err != nil {
		return err
	}
	if y.MinProbability != nil && y.MaxProbability != nil && *y.MinProbability > *y.MaxProbability {
		return fmt.Errorf("AI policy %q yesNo decision %q (%s) must not exceed %q (%s)",
			name, "minProbability", formatBound(*y.MinProbability), "maxProbability", formatBound(*y.MaxProbability))
	}
	if strings.TrimSpace(y.Instructions) == "" {
		return fmt.Errorf("AI policy %q yesNo decision must provide nonempty instructions", name)
	}
	if len(y.Criteria) == 0 {
		return fmt.Errorf("AI policy %q yesNo decision must provide criteria", name)
	}
	for key, criterion := range y.Criteria {
		if strings.TrimSpace(key) == "" || strings.TrimSpace(criterion) == "" {
			return fmt.Errorf("AI policy %q yesNo decision criteria must have nonempty names and descriptions", name)
		}
	}
	return nil
}

func (c *AiChoice) validate(name string) error {
	if len(c.Options) == 0 {
		return fmt.Errorf("AI policy %q choice decision must define at least one option", name)
	}
	if len(c.Allow) == 0 && len(c.Deny) == 0 && c.MinConfidence == nil {
		return fmt.Errorf("AI policy %q choice decision must set at least one of %q, %q or %q; a decision that asserts nothing about the answer passes vacuously",
			name, "allow", "deny", "minConfidence")
	}
	// An allow/deny entry that is not a defined option can never match the
	// model's answer, so the assertion silently does nothing.
	for _, field := range []struct {
		key     string
		entries []string
	}{{"allow", c.Allow}, {"deny", c.Deny}} {
		for _, entry := range field.entries {
			if _, ok := c.Options[entry]; !ok {
				return fmt.Errorf("AI policy %q choice decision %q names option %q, which is not defined in %q",
					name, field.key, entry, "options")
			}
		}
	}
	return inUnitInterval(name, "choice", "minConfidence", c.MinConfidence)
}

func (s *AiScore) validate(name string) error {
	if len(s.Levels) == 0 {
		return fmt.Errorf("AI policy %q score decision must define at least one level", name)
	}
	if s.MinScore == nil && s.MaxScore == nil {
		return fmt.Errorf("AI policy %q score decision must set at least one of %q or %q; a decision that asserts nothing about the answer passes vacuously",
			name, "minScore", "maxScore")
	}
	// The score is an index into Levels, so the admissible range is fixed by
	// the ladder the policy itself declared.
	top := float64(len(s.Levels) - 1)
	for _, bound := range []struct {
		key   string
		value *float64
	}{{"minScore", s.MinScore}, {"maxScore", s.MaxScore}} {
		if bound.value == nil {
			continue
		}
		if math.IsNaN(*bound.value) || math.IsInf(*bound.value, 0) || *bound.value < 0 || *bound.value > top {
			return fmt.Errorf("AI policy %q score decision %q must be within [0, %d] for %d levels, got %s",
				name, bound.key, len(s.Levels)-1, len(s.Levels), formatBound(*bound.value))
		}
	}
	if s.MinScore != nil && s.MaxScore != nil && *s.MinScore > *s.MaxScore {
		return fmt.Errorf("AI policy %q score decision %q (%s) must not exceed %q (%s)",
			name, "minScore", formatBound(*s.MinScore), "maxScore", formatBound(*s.MaxScore))
	}
	return nil
}

// inUnitInterval enforces that a probability-like bound lies in [0, 1].
// A nil bound is "not asserted" and is always fine; the assertion-free case is
// caught separately.
func inUnitInterval(name, kind, key string, v *float64) error {
	if v == nil {
		return nil
	}
	if math.IsNaN(*v) || math.IsInf(*v, 0) || *v < 0 || *v > 1 {
		return fmt.Errorf("AI policy %q %s decision %q must be within [0, 1], got %s", name, kind, key, formatBound(*v))
	}
	return nil
}

// formatBound renders a bound the way a policy author wrote it: 0.9 not
// 0.900000, 2 not 2.000000, and without rounding away precision the author
// actually supplied.
func formatBound(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// Validate checks the AI policies declared on this attestation: each one on its
// own, plus the set-level rule that names are unique. The name is the question
// id once several questions are put to a model in one request, so a duplicate
// makes two different answers indistinguishable.
func (a Attestation) Validate() error {
	return validateAiPolicySet(a.AiPolicies, fmt.Sprintf("attestation %q", a.Type))
}

// validateAiPolicySet validates every policy in a batch and enforces name
// uniqueness across it. scope names the container for the error message.
func validateAiPolicySet(policies []AiPolicy, scope string) error {
	seen := make(map[string]struct{}, len(policies))
	for _, p := range policies {
		if err := p.Validate(); err != nil {
			return err
		}
		if _, dup := seen[p.Name]; dup {
			return fmt.Errorf("AI policy name %q is used more than once in %s; names must be unique", p.Name, scope)
		}
		seen[p.Name] = struct{}{}
	}
	return nil
}
