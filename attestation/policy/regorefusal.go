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

import "errors"

// ErrRegoEvaluationRefused means a Rego evaluation produced no verdict: it ran
// out of its deadline ("timeout") or its context was cancelled ("cancelled").
// Like ErrAIEvaluationRefused, it is a refusal to answer, which Verify returns
// as an error (unsigned) when no other witness satisfied the step, never a
// FAILED verdict (#9820 E8, Pushgate contract: timeouts are unsigned).
type ErrRegoEvaluationRefused struct {
	Code  string
	cause error
}

func (e ErrRegoEvaluationRefused) Error() string { return "rego evaluation refused: " + e.Code }
func (e ErrRegoEvaluationRefused) Unwrap() error { return e.cause }

// evaluationRefusal returns the refusal inside err, AI or Rego, or nil when
// err is an ordinary rejection (a verdict).
func evaluationRefusal(err error) error {
	var ai ErrAIEvaluationRefused
	if errors.As(err, &ai) {
		return ai
	}
	var rego ErrRegoEvaluationRefused
	if errors.As(err, &rego) {
		return rego
	}
	return nil
}
