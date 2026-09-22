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
	"encoding/json"
	"sort"
)

// PolicyPredicateV02 is the predicate type of a policy whose steps may declare
// Step.About. A policy that declares about on any step is signed under this
// type; one that does not keeps PolicyPredicate (or LegacyPolicyPredicate),
// byte for byte.
const PolicyPredicateV02 = "https://aflock.ai/policy/v0.2"

// StepAboutSource is the one Step.About value. It grants the step reach to
// evidence about the commit the verified artifact was built from, on top of
// every witness the step accepts without it; it never narrows what the step
// accepts. See Step.About for what it admits today.
const StepAboutSource = "source"

// IsPolicyV01Type reports whether payloadType is one of the two spellings of
// policy v0.1, the aflock type and the legacy witness alias. Neither can carry
// Step.About.
func IsPolicyV01Type(payloadType string) bool {
	return payloadType == PolicyPredicate || payloadType == LegacyPolicyPredicate
}

// StepsDeclaringAbout returns, sorted, the keys of the steps in a policy
// document that carry a non-empty "about", whatever its value. It reads only
// steps.<key>.about, so it works on a hand-authored source that is not yet a
// complete policy. A document that does not decode that far declares nothing.
func StepsDeclaringAbout(policyJSON []byte) []string {
	var doc struct {
		Steps map[string]struct {
			About string `json:"about"`
		} `json:"steps"`
	}
	if json.Unmarshal(policyJSON, &doc) != nil {
		return nil
	}
	var names []string
	for name, step := range doc.Steps {
		if step.About != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
