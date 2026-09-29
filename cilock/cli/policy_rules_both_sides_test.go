// jade:ring local
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

package cli

import "testing"

// fullblind49 and fullblind50 never delivered: a Pushgate refusal read
// "unexpected command argv: [...]" and the agent could not tell what its own
// rule wanted. Every seeded rule that compares evidence against a value the
// author pinned must print both sides: what the rule requires, and what the
// evidence held.

func TestCommandPinDenyPrintsExpectedAndGot(t *testing.T) {
	requireDenied(t,
		evalRule(t, ruleCommandPin, `["go","vet","./..."]`,
			map[string]any{"cmd": []any{"sh", "-c", "go vet ./... > vet.txt"}}, nil),
		`command must be ["go", "vet", "./..."]; got ["sh", "-c", "go vet ./... > vet.txt"]`)
}
