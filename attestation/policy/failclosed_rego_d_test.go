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
//
// Finding D (#5747, fork regression) — fail-closed acceptance test.
// Promoted from the redgate scaffold (//go:build redgate) to the default
// suite now that the fix has landed; this is the Green acceptance criterion.

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// D (#5747, HIGH) — rego.go EvaluateRegoPolicy :145-159 (non-string deny)
// Fail-closed contract: a genuine `deny` decision must NEVER depend on whether
// the deny element is a string. A Rego module that emits a non-string deny
// element (e.g. deny[42]) must FAIL verification, not silently pass because the
// element was skipped.
// ---------------------------------------------------------------------------
func TestRed_D_NonStringDenyMustFailClosed(t *testing.T) {
	// deny is a partial set whose single member is a NUMBER (non-string).
	// Pre-fix code's []interface{} case skipped non-strings -> empty reasons ->
	// PASS. Fail-closed direction: a non-empty deny set must reject.
	module := []byte(`package redgate_nonstring_deny

deny[x] {
	x := 42
}
`)
	att := &dummyAttestor{name: "x", typeStr: "https://example.com/att/v1"}
	err := EvaluateRegoPolicy(att, []RegoPolicy{{Name: "nonstring", Module: module}})
	assert.Error(t, err,
		"a Rego deny with a non-string element (deny[42]) is a genuine deny and must fail closed, not be silently dropped")
}
