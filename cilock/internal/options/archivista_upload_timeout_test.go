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

package options

import (
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// The retry budget cuts off an attempt still in flight, so a per-attempt
// deadline longer than the budget is dead: `--archivista-upload-timeout 9m`
// under the default 4m budget would still fail at 4m. These drive the flag
// parser the way `cilock run` does and pin that the budget never undercuts the
// deadline the operator asked for.
func TestUploadTimeout_DefaultBudgetFollowsTheTimeout(t *testing.T) {
	o := archivistaOptionsFromFlags(t, "--archivista-upload-timeout", "9m")
	policy, retry, err := o.uploadRetryPolicy()
	require.NoError(t, err)
	require.True(t, retry)
	require.Equal(t, 18*time.Minute, policy.Budget, "two full attempts, the same multiple as the default")
	require.Greater(t, policy.Budget, o.UploadTimeout)
}

func TestUploadTimeout_ShorterTimeoutKeepsTheDefaultBudget(t *testing.T) {
	o := archivistaOptionsFromFlags(t, "--archivista-upload-timeout", "30s")
	policy, _, err := o.uploadRetryPolicy()
	require.NoError(t, err)
	require.Equal(t, archivista.DefaultRetryPolicy().Budget, policy.Budget,
		"a shorter attempt deadline must not shrink the total upload window")
}

func TestUploadTimeout_ExplicitBudgetBelowTheTimeoutIsRefused(t *testing.T) {
	for _, budget := range []string{"5m", "9m"} {
		o := archivistaOptionsFromFlags(t,
			"--archivista-upload-timeout", "9m", "--archivista-upload-retry-budget", budget)
		_, _, err := o.uploadRetryPolicy()
		require.Error(t, err, "budget %s cannot fit one 9m attempt", budget)
		o.Enable = true
		o.Url = "https://archivista.example"
		_, err = o.Client()
		require.Error(t, err, "Client must refuse the contradiction too, budget %s", budget)
	}
}

// An explicit budget that happens to equal the default is still explicit.
// Comparing the value with the default cannot tell `--archivista-upload-retry-budget
// 4m` from omission, and would silently grow an operator's 4m limit to 18m.
func TestUploadTimeout_ExplicitBudgetEqualToTheDefaultIsNotScaled(t *testing.T) {
	def := archivista.DefaultRetryPolicy().Budget
	o := archivistaOptionsFromFlags(t,
		"--archivista-upload-timeout", "9m", "--archivista-upload-retry-budget", def.String())
	_, _, err := o.uploadRetryPolicy()
	require.Error(t, err, "an explicit %v budget cannot fit one 9m attempt and must be refused, not scaled", def)

	o = archivistaOptionsFromFlags(t,
		"--archivista-upload-timeout", "1m", "--archivista-upload-retry-budget", def.String())
	policy, _, err := o.uploadRetryPolicy()
	require.NoError(t, err)
	require.Equal(t, def, policy.Budget, "an explicit budget that fits is used exactly")
}

// A budget set in code, without the flag parser, is explicit too.
func TestUploadTimeout_BudgetSetInCodeIsExplicit(t *testing.T) {
	def := archivista.DefaultRetryPolicy().Budget
	o := &ArchivistaOptions{UploadRetries: 4, UploadRetryBudget: def, UploadTimeout: 9 * time.Minute}
	_, _, err := o.uploadRetryPolicy()
	require.Error(t, err)
}

// The flag still reads and prints as a duration with the shipped default.
func TestUploadRetryBudgetFlagKeepsItsDefault(t *testing.T) {
	o := &ArchivistaOptions{}
	cmd := &cobra.Command{Use: "run"}
	o.AddFlags(cmd)
	f := cmd.Flags().Lookup("archivista-upload-retry-budget")
	require.NotNil(t, f)
	require.Equal(t, "duration", f.Value.Type())
	require.Equal(t, archivista.DefaultRetryPolicy().Budget.String(), f.DefValue)
	require.Error(t, cmd.Flags().Set("archivista-upload-retry-budget", "soon"))
}

func TestUploadTimeout_ExplicitBudgetAboveTheTimeoutIsKept(t *testing.T) {
	o := archivistaOptionsFromFlags(t,
		"--archivista-upload-timeout", "9m", "--archivista-upload-retry-budget", "30m")
	policy, _, err := o.uploadRetryPolicy()
	require.NoError(t, err)
	require.Equal(t, 30*time.Minute, policy.Budget)
}

func TestUploadTimeout_UnsetLeavesTheShippedPolicy(t *testing.T) {
	o := archivistaOptionsFromFlags(t)
	policy, retry, err := o.uploadRetryPolicy()
	require.NoError(t, err)
	require.True(t, retry)
	require.Equal(t, archivista.DefaultRetryPolicy(), policy)

	o = archivistaOptionsFromFlags(t, "--archivista-upload-retries", "0", "--archivista-upload-timeout", "9m")
	_, retry, err = o.uploadRetryPolicy()
	require.NoError(t, err)
	require.False(t, retry, "no retry means no budget to undercut the deadline")
}
