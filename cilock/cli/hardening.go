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
	"fmt"
	"strings"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/policy"
)

// The cilock CLI is the embedder opt-in for the #6266 policy-verification
// hardening (see attestation/policy/hardening.go): the library defaults stay
// warn-first (zero value), and the CLI turns enforcement ON for every command
// at startup (#6454). The R3_181 vacuous-match and R3_184
// certConstraint-ignored classes are exactly what an attacker uses against a
// gate policy, so a gate CLI must reject them by default.
//
// Escape hatch: a legitimately-vacuous LEGACY verify (e.g. a policy that was
// signed before enforcement and cannot be re-signed on the spot) can downgrade
// deliberately with --policy-hardening=warn or CILOCK_POLICY_HARDENING=warn.
// The downgrade is loud (a WARN naming everything it turns off) and never
// silent. Note this is distinct from `cilock run --hardening`, which selects
// the runtime tracing profile (eBPF/fanotify), not policy verification.
const (
	policyHardeningFlag    = "policy-hardening"
	policyHardeningEnv     = "CILOCK_POLICY_HARDENING"
	policyHardeningEnforce = "enforce"
	policyHardeningWarn    = "warn"
)

// enforcedHardening is the full #6266 enforcement set — every hardening flag
// the policy library exposes. New HardeningOptions fields should be added here
// so the CLI default stays "everything enforced".
func enforcedHardening() policy.HardeningOptions {
	return policy.HardeningOptions{
		EnforceCertConstraintOnKeyIDMatch: true, // R3_184
		RejectEmptyConstraintEmptyField:   true, // R3_181
		RejectDuplicateRegoPackage:        true, // R3_183
		EnforceStepNameCoherence:          true, // R3_185/187/209
	}
}

// applyPolicyHardening installs the process-wide policy-hardening options for
// the resolved mode. Called once from the root PersistentPreRunE, before any
// command logic runs. An unknown mode fails closed.
func applyPolicyHardening(mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case policyHardeningEnforce:
		policy.SetHardening(enforcedHardening())
		return nil
	case policyHardeningWarn:
		policy.SetHardening(policy.HardeningOptions{})
		log.Warnf("policy-verification hardening DOWNGRADED to warn-only (--%s=%s / %s=%s): dangerous policy configurations (#6266 — vacuous empty cert constraints, certConstraint ignored on key-ID match, duplicate rego packages, incoherent step names) will be reported but will NOT fail verification. Fix or re-sign the policy and remove this downgrade.",
			policyHardeningFlag, policyHardeningWarn, policyHardeningEnv, policyHardeningWarn)
		return nil
	default:
		return fmt.Errorf("invalid --%s value %q (valid: %q, %q; also settable via %s)",
			policyHardeningFlag, mode, policyHardeningEnforce, policyHardeningWarn, policyHardeningEnv)
	}
}
