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

import "strings"

// StepOutcome is the result class of step-name inference.
type StepOutcome int

const (
	// StepNoMatch means no command-intent detector with a category fired.
	StepNoMatch StepOutcome = iota
	// StepResolved means inference settled on exactly one category.
	StepResolved
	// StepAmbiguous means multiple equally-specific categories matched and
	// no single one could be chosen.
	StepAmbiguous
)

// StepCandidate is one command-intent detector that contributed a
// category to inference. Detector is the plugin/catalog name; Category is
// the category that detector resolved to (its primary_category, or its
// sole category).
type StepCandidate struct {
	Detector string   `json:"detector"`
	Category Category `json:"category"`
}

// StepInference is the outcome of inferring a --step name from a pre-gate
// plan. On StepResolved, Step and Source are set. Candidates always lists
// the command-intent detectors considered (for the success-path audit log
// and the ambiguous-case diagnostic).
type StepInference struct {
	Outcome    StepOutcome
	Step       Category
	Source     string
	Candidates []StepCandidate
}

// InferStep derives a step-category name from a pre-gate plan.
//
// Only *command-intent* matches count: detectors that fired because the
// observed argv matched one of their argv predicates. Detectors that fired
// on ambient signal — file_exists (git on a .git dir), env_set, a metadata
// probe — are scaffolding that rides along with every command and would
// otherwise make every build "ambiguous". The matched-rule string records
// which predicate fired, so we filter on it.
//
// Among the command-intent candidates:
//   - zero            → StepNoMatch (the command is unknown to the catalog)
//   - one category    → StepResolved
//   - many, but exactly one is Tier 2 (specialized > core) → StepResolved
//   - otherwise       → StepAmbiguous
//
// A detector with multiple categories contributes its primary_category
// (the schema requires primary_category whenever a detector declares more
// than one). Detectors with no category (format adapters, scaffolding)
// never contribute.
func InferStep(reg *Registry, plan PlanResult) StepInference {
	var candidates []StepCandidate
	for _, f := range plan.Fire {
		if !ruleIsArgvMatch(f.MatchedRule) {
			continue
		}
		d, _, err := reg.Lookup(f.Attestor)
		if err != nil || d == nil || len(d.Category) == 0 {
			continue
		}
		cat := d.PrimaryCategory
		if cat == "" {
			cat = d.Category[0] // schema guarantees a single entry here
		}
		candidates = append(candidates, StepCandidate{Detector: f.Attestor, Category: cat})
	}

	if len(candidates) == 0 {
		return StepInference{Outcome: StepNoMatch}
	}

	// Distinct categories, remembering the first detector that supplied each
	// (plan.Fire is stably ordered, so "first" is deterministic).
	distinct := make(map[Category]string)
	order := make([]Category, 0, len(candidates))
	for _, c := range candidates {
		if _, seen := distinct[c.Category]; !seen {
			distinct[c.Category] = c.Detector
			order = append(order, c.Category)
		}
	}

	if len(distinct) == 1 {
		cat := order[0]
		return StepInference{Outcome: StepResolved, Step: cat, Source: distinct[cat], Candidates: candidates}
	}

	// More than one distinct category: prefer the specialized (Tier 2) one
	// when exactly one is specialized. Two tools that both resolve to Core
	// categories, or two distinct specialized categories, stay ambiguous.
	var tier2 []Category
	for _, cat := range order {
		if !IsTier1(cat) {
			tier2 = append(tier2, cat)
		}
	}
	if len(tier2) == 1 {
		cat := tier2[0]
		return StepInference{Outcome: StepResolved, Step: cat, Source: distinct[cat], Candidates: candidates}
	}

	return StepInference{Outcome: StepAmbiguous, Candidates: candidates}
}

// ruleIsArgvMatch reports whether a matched-rule string (as recorded on a
// FireDecision) reflects an argv predicate match. The matcher renders leaf
// rules like "argv_prefix:[trivy]" and composer rules like
// "any_of[0]:argv_prefix:...", so a substring test is sufficient and
// robust to nesting.
func ruleIsArgvMatch(rule string) bool {
	return strings.Contains(rule, "argv")
}
