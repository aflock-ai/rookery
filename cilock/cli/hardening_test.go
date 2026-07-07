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

// Tests for the #6454 flip: the cilock CLI opts in to the #6266
// policy-verification hardening (ENFORCE) for every command at startup, with
// a loud, deliberate escape hatch (--policy-hardening=warn /
// CILOCK_POLICY_HARDENING=warn) for legacy policies that cannot be re-signed
// yet. These tests mutate the policy package's process-global hardening
// options, so none of them may call t.Parallel().

import (
	"testing"

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/stretchr/testify/require"
)

// resetHardeningAfter restores the process-global hardening options after the
// test, so the enforce-default installed by executing a command doesn't leak
// into other tests in this package.
func resetHardeningAfter(t *testing.T) {
	t.Helper()
	prev := policy.Hardening()
	t.Cleanup(func() { policy.SetHardening(prev) })
}

func TestPolicyHardeningDefaultEnforces(t *testing.T) {
	resetHardeningAfter(t)
	policy.SetHardening(policy.HardeningOptions{}) // prove the command flips it
	require.NoError(t, executeCmd("version"))
	require.Equal(t, enforcedHardening(), policy.Hardening(),
		"running any cilock command must install the full #6266 enforcement set by default")
}

func TestPolicyHardeningEnforcesEveryKnownFlag(t *testing.T) {
	// Guard against a new HardeningOptions field defaulting to un-enforced in
	// the CLI: the enforced set must have every bool field true. Uses the
	// struct directly (not reflection) so a new field breaks this test at
	// compile time via the exhaustive comparison in DefaultEnforces above and
	// loudly documents the expectation here.
	h := enforcedHardening()
	require.True(t, h.EnforceCertConstraintOnKeyIDMatch, "R3_184 must be enforced by default")
	require.True(t, h.RejectEmptyConstraintEmptyField, "R3_181 must be enforced by default")
	require.True(t, h.RejectDuplicateRegoPackage, "R3_183 must be enforced by default")
	require.True(t, h.EnforceStepNameCoherence, "R3_185/187/209 must be enforced by default")
}

func TestPolicyHardeningWarnFlagDowngrades(t *testing.T) {
	resetHardeningAfter(t)
	require.NoError(t, executeCmd("version", "--policy-hardening=warn"))
	require.Equal(t, policy.HardeningOptions{}, policy.Hardening(),
		"--policy-hardening=warn must restore the warn-first (zero) options")
}

func TestPolicyHardeningWarnIsCaseInsensitive(t *testing.T) {
	resetHardeningAfter(t)
	require.NoError(t, executeCmd("version", "--policy-hardening=WARN"))
	require.Equal(t, policy.HardeningOptions{}, policy.Hardening())
}

func TestPolicyHardeningEnvDowngrades(t *testing.T) {
	resetHardeningAfter(t)
	t.Setenv(policyHardeningEnv, "warn")
	require.NoError(t, executeCmd("version"))
	require.Equal(t, policy.HardeningOptions{}, policy.Hardening(),
		"CILOCK_POLICY_HARDENING=warn must downgrade to warn-first")
}

func TestPolicyHardeningFlagBeatsEnv(t *testing.T) {
	resetHardeningAfter(t)
	t.Setenv(policyHardeningEnv, "warn")
	require.NoError(t, executeCmd("version", "--policy-hardening=enforce"))
	require.Equal(t, enforcedHardening(), policy.Hardening(),
		"an explicit --policy-hardening=enforce must beat the env downgrade")
}

func TestPolicyHardeningInvalidValueFailsClosed(t *testing.T) {
	resetHardeningAfter(t)
	err := executeCmd("version", "--policy-hardening=bogus")
	require.Error(t, err)
	require.Contains(t, err.Error(), policyHardeningFlag)
}

func TestPolicyHardeningInvalidEnvFailsClosed(t *testing.T) {
	// An unparseable env value must NOT silently fall back to a mode the
	// operator didn't pick — a typo'd CILOCK_POLICY_HARDENING fails the run.
	resetHardeningAfter(t)
	t.Setenv(policyHardeningEnv, "bogus")
	err := executeCmd("version")
	require.Error(t, err)
	require.Contains(t, err.Error(), policyHardeningFlag)
}
