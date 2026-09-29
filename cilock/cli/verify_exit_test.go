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

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/stretchr/testify/require"
)

// A verification that could not read its evidence judged nothing: it must not
// read as a denial, to a person or to a gate reading the exit code.
func TestVerifyFailureClassification(t *testing.T) {
	unreadable := fmt.Errorf("%w: failed to search external attestation %q: %w", policy.ErrEvidenceUnavailable, "pushgate-vsa",
		errors.New("archivista graphql returned 401: Authentication required"))
	v, code := classifyVerifyFailure(fmt.Errorf("attestors failed: %w", unreadable))
	require.Equal(t, VerdictError, v)
	require.Equal(t, ExitError, code)

	denied := policy.ErrMissingExternalAttestation{Name: "pushgate-vsa"}
	v, code = classifyVerifyFailure(denied)
	require.Equal(t, VerdictDenied, v)
	require.Equal(t, ExitDenied, code)

	// An evaluator that refused to answer, or an assignment walk that stopped
	// short, judged nothing either: no verdict, never a denial.
	for _, noVerdict := range []error{
		fmt.Errorf("attestors failed: %w", policy.ErrAIEvaluationRefused{Code: "provider"}),
		fmt.Errorf("attestors failed: %w", policy.ErrRegoEvaluationRefused{Code: "deadline"}),
		fmt.Errorf("attestors failed: %w", policy.ErrExternalAssignmentsExceedBound{Externals: []string{"a", "b"}}),
	} {
		v, code = classifyVerifyFailure(noVerdict)
		require.Equal(t, VerdictError, v, "%v", noVerdict)
		require.Equal(t, ExitError, code, "%v", noVerdict)
	}

	var coded interface{ ExitCode() int }
	require.True(t, errors.As(error(&VerifyExitError{Code: ExitError, Err: unreadable}), &coded))
	require.Equal(t, 2, coded.ExitCode())
}
