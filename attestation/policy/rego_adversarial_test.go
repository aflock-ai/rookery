//go:build audit

// Copyright 2024 The Witness Contributors
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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/source"
	"github.com/invopop/jsonschema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// 1. Rego Sandbox Escape: Builtins that SHOULD be blocked but might not be
// ===========================================================================

// TestAdversarial_RegoSandbox_TraceBuiltin tests whether trace() is available.
// trace() itself is not dangerous for exfiltration, but it can leak data to
// debug output channels in some OPA integrations.
func TestAdversarial_RegoSandbox_TraceBuiltin(t *testing.T) {
	policy := RegoPolicy{
		Name: "trace_probe.rego",
		Module: []byte(`package trace_probe
deny[msg] {
  trace("EXFILTRATING SECRETS VIA TRACE")
  msg := "trace worked"
}`),
	}
	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	// trace() is available in OPA by default and not blocked.
	// If this test shows trace() works (err contains "trace worked"),
	// that's a finding -- trace output could leak attestation data.
	if err != nil && strings.Contains(err.Error(), "trace worked") {
		t.Log("FINDING: trace() builtin is available in Rego sandbox. " +
			"While not directly exploitable for network exfiltration, " +
			"trace output may leak attestation data through OPA's " +
			"debug/trace collection mechanisms.")
	}
	// trace() is a no-op in most embedded contexts, but document it.
}

// TestAdversarial_RegoSandbox_TimeNowNs tests whether time.now_ns() is available.
// This can be used for timing-based side channels or fingerprinting.
func TestAdversarial_RegoSandbox_TimeNowNs(t *testing.T) {
	policy := RegoPolicy{
		Name: "time_probe.rego",
		Module: []byte(`package time_probe
deny[msg] {
  ts := time.now_ns()
  ts > 0
  msg := "time.now_ns available"
}`),
	}
	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	if err != nil && strings.Contains(err.Error(), "time.now_ns available") {
		t.Log("FINDING: time.now_ns() is available in the Rego sandbox. " +
			"This enables timing side-channel attacks and system fingerprinting.")
	} else if err != nil {
		// If it errors because the builtin is blocked, that's good.
		t.Logf("time.now_ns() appears to be blocked or errored: %v", err)
	} else {
		// deny was not triggered -- means time.now_ns returned 0 or false,
		// which would be unexpected.
		t.Log("time.now_ns() did not trigger deny -- possibly returned 0 or was blocked at eval time")
	}
}

// TestAdversarial_RegoSandbox_JWTDecode tests whether io.jwt.decode is available.
// This builtin parses JWTs which could be used to process attacker-controlled
// tokens within the policy engine.
func TestAdversarial_RegoSandbox_JWTDecode(t *testing.T) {
	// A minimal valid JWT (unsigned, just header.payload.signature)
	fakeJWT := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0."
	policy := RegoPolicy{
		Name: "jwt_probe.rego",
		Module: []byte(fmt.Sprintf(`package jwt_probe
deny[msg] {
  [header, payload, _] := io.jwt.decode("%s")
  msg := sprintf("jwt decoded: header=%%v", [header])
}`, fakeJWT)),
	}
	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	if err != nil && strings.Contains(err.Error(), "jwt decoded") {
		t.Log("FINDING: io.jwt.decode() is available in the Rego sandbox. " +
			"Attackers can use this to parse and process JWTs within policy evaluation. " +
			"Combined with other builtins, this expands the attack surface.")
	} else if err != nil {
		t.Logf("io.jwt.decode() result: %v", err)
	} else {
		t.Log("io.jwt.decode() did not produce a deny -- may have failed silently")
	}
}

// TestAdversarial_RegoSandbox_CryptoX509Parse tests whether crypto.x509.parse_certificates
// is available. This could be used to process attacker-controlled certificates.
func TestAdversarial_RegoSandbox_CryptoX509Parse(t *testing.T) {
	policy := RegoPolicy{
		Name: "x509_probe.rego",
		Module: []byte(`package x509_probe
deny[msg] {
  # Try to call the builtin -- if it's available, it will either succeed
  # or error on bad input, but OPA will not reject the module at compile time.
  certs := crypto.x509.parse_certificates("not-a-real-cert")
  msg := "x509 parse available"
}`),
	}
	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	// With StrictBuiltinErrors, a runtime error on bad input should surface.
	// The key question is: does the module COMPILE? If it does, the builtin
	// is available in the capability set.
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "x509 parse available") {
			t.Log("FINDING: crypto.x509.parse_certificates() is available and worked on bad input")
		} else if strings.Contains(errStr, "rego_type_error") || strings.Contains(errStr, "undefined function") {
			t.Log("crypto.x509.parse_certificates() is blocked at compile time -- good")
		} else {
			// Runtime error from bad cert data -- the builtin IS available
			// but failed on our garbage input. This means it's in the capability set.
			t.Logf("FINDING: crypto.x509.parse_certificates() is in the capability set "+
				"(got runtime error on bad input): %v", err)
		}
	} else {
		t.Log("crypto.x509.parse_certificates() produced no deny and no error -- may have been silently blocked at eval")
	}
}

// TestAdversarial_RegoSandbox_RegexFind tests whether regex.find_all_string_submatch_n
// is available. This itself isn't dangerous, but combined with catastrophic
// backtracking it could enable ReDoS.
func TestAdversarial_RegoSandbox_RegexFind(t *testing.T) {
	policy := RegoPolicy{
		Name: "regex_probe.rego",
		Module: []byte(`package regex_probe
deny[msg] {
  matches := regex.find_all_string_submatch_n("(a+)+$", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaab", -1)
  msg := "regex available"
}`),
	}

	start := time.Now()
	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	elapsed := time.Since(start)

	if elapsed > 5*time.Second {
		t.Logf("FINDING: ReDoS potential -- regex evaluation took %v", elapsed)
	}
	if err != nil {
		t.Logf("regex probe result: %v (took %v)", err, elapsed)
	}
}

// TestAdversarial_RegoSandbox_NetCIDRBlockedInUnsafeButNotCapabilities tests
// the asymmetry between disallowedBuiltins (used by restrictedCapabilities)
// and the UnsafeBuiltins map. net.cidr_* builtins are in UnsafeBuiltins but
// NOT in disallowedBuiltins/restrictedCapabilities.
func TestAdversarial_RegoSandbox_NetCIDR_AsymmetricBlocking(t *testing.T) {
	// net.cidr_contains is in UnsafeBuiltins but NOT in disallowedBuiltins
	// (which is used by restrictedCapabilities). Let's see what happens.
	builtinsToTest := []struct {
		name   string
		module string
	}{
		{
			name: "net.cidr_contains",
			module: `package cidr_test
deny[msg] {
  net.cidr_contains("10.0.0.0/8", "10.1.2.3")
  msg := "cidr_contains available"
}`,
		},
		{
			name: "net.cidr_intersects",
			module: `package cidr_intersects_test
deny[msg] {
  net.cidr_intersects("10.0.0.0/8", "10.0.0.0/16")
  msg := "cidr_intersects available"
}`,
		},
		{
			name: "net.cidr_merge",
			module: `package cidr_merge_test
deny[msg] {
  merged := net.cidr_merge(["10.0.0.0/24", "10.0.1.0/24"])
  count(merged) > 0
  msg := "cidr_merge available"
}`,
		},
		{
			name: "net.cidr_expand",
			module: `package cidr_expand_test
deny[msg] {
  expanded := net.cidr_expand("192.168.1.0/30")
  count(expanded) > 0
  msg := "cidr_expand available"
}`,
		},
	}

	for _, tc := range builtinsToTest {
		t.Run(tc.name, func(t *testing.T) {
			policy := RegoPolicy{
				Name:   tc.name + ".rego",
				Module: []byte(tc.module),
			}
			err := EvaluateRegoPolicy(
				&marshalableAttestor{AttName: "test", AttType: "test"},
				[]RegoPolicy{policy},
			)
			if err == nil {
				t.Logf("INFO: %s produced no error (rule body was not entered or no deny)", tc.name)
			} else if strings.Contains(err.Error(), "available") {
				t.Logf("FINDING: %s is available despite being in UnsafeBuiltins -- "+
					"the UnsafeBuiltins enforcement may not be working as expected, "+
					"or it is blocked at a different stage", tc.name)
			} else {
				t.Logf("GOOD: %s appears to be blocked: %v", tc.name, err)
			}
		})
	}
}

// ===========================================================================
// 2. Duplicate UnsafeBuiltins / StrictBuiltinErrors set twice
// ===========================================================================

// TestAdversarial_StrictBuiltinErrorsSetTwice demonstrates that
// rego.StrictBuiltinErrors(true) is set on lines 88 and 118 of rego.go.
// This test verifies whether the double-set causes any issue.
func TestAdversarial_StrictBuiltinErrorsSetTwice(t *testing.T) {
	// The concern: the second StrictBuiltinErrors(true) call might override
	// or conflict with the first. In OPA's implementation, each call to
	// rego.StrictBuiltinErrors appends to the options list. The last one
	// wins during Rego.New() processing.
	//
	// We test this by using a builtin that should error with strict mode ON
	// but would silently return undefined with strict mode OFF.
	//
	// If StrictBuiltinErrors were somehow set to false by the second call,
	// undefined builtins would not error -- they'd just return undefined.
	policy := RegoPolicy{
		Name: "strict_test.rego",
		Module: []byte(`package strict_test
deny[msg] {
  # This calls a builtin that IS in capabilities but with bad args.
  # With StrictBuiltinErrors(true), this should error.
  # With StrictBuiltinErrors(false), this would silently return undefined.
  x := json.unmarshal("{invalid json!!!")
  msg := "should not reach here"
}`),
	}
	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	if err != nil {
		t.Logf("StrictBuiltinErrors appears to be active (error on bad json.unmarshal): %v", err)
		// If the error is about invalid JSON, strict mode is working.
		// If the error is about "undefined", strict mode might not be working.
		if strings.Contains(err.Error(), "should not reach here") {
			t.Fatal("FINDING: json.unmarshal with invalid JSON did NOT error -- StrictBuiltinErrors may be off")
		}
	} else {
		// No error means the deny rule was never entered because json.unmarshal
		// returned undefined (strict mode OFF) or the rule body failed silently.
		t.Log("FINDING: No error from json.unmarshal with invalid JSON. " +
			"StrictBuiltinErrors may not be active, or the rule body " +
			"was never entered due to undefined propagation.")
	}
}

// TestAdversarial_DisallowedVsUnsafe_Asymmetry explicitly checks the
// asymmetry between the two blocking mechanisms.
func TestAdversarial_DisallowedVsUnsafe_Asymmetry(t *testing.T) {
	// disallowedBuiltins (used by restrictedCapabilities) blocks:
	//   http.send, opa.runtime, net.lookup_ip_addr
	//
	// UnsafeBuiltins (rego option) blocks:
	//   http.send, opa.runtime, net.lookup_ip_addr,
	//   net.cidr_contains, net.cidr_intersects, net.cidr_merge, net.cidr_expand
	//
	// The net.cidr_* builtins are ONLY in UnsafeBuiltins, not in
	// disallowedBuiltins. This means they are still in the capability set
	// but blocked at the "unsafe" layer.
	//
	// The question is: does OPA apply UnsafeBuiltins AFTER capabilities filtering?
	// If the builtin is in capabilities but also in UnsafeBuiltins, it should
	// be blocked. But the two mechanisms work differently:
	// - Capabilities: compile-time type checking (builtin unknown = type error)
	// - UnsafeBuiltins: compile-time rejection (builtin known but forbidden)

	t.Log("ANALYSIS: disallowedBuiltins and UnsafeBuiltins are asymmetric:")
	t.Log("  disallowedBuiltins (restrictedCapabilities): http.send, opa.runtime, net.lookup_ip_addr")
	t.Log("  UnsafeBuiltins: http.send, opa.runtime, net.lookup_ip_addr, net.cidr_contains, net.cidr_intersects, net.cidr_merge, net.cidr_expand")
	t.Log("  MISSING from UnsafeBuiltins: io.jwt.*, crypto.x509.*, time.now_ns, trace, rego.metadata.*")
	t.Log("  MISSING from disallowedBuiltins: net.cidr_* (but covered by UnsafeBuiltins)")
	t.Log("")
	t.Log("RECOMMENDATION: Consolidate to a single blocklist used by BOTH mechanisms, " +
		"and add io.jwt.*, crypto.x509.*, time.now_ns to the blocklist.")
}

// ===========================================================================
// 3. Rego Package Collision
// ===========================================================================

// TestAdversarial_RegoPackageCollision_SamePackageName tests what happens when
// two different RegoPolicies use the same package name. The code deduplicates
// the deny path, but OPA merges rules from modules with the same package.
func TestAdversarial_RegoPackageCollision_SamePackageName(t *testing.T) {
	// Two policies with the SAME package name "collision"
	policy1 := RegoPolicy{
		Name: "policy1.rego",
		Module: []byte(`package collision
deny[msg] {
  input.name == "test"
  msg := "policy1 denied"
}`),
	}
	policy2 := RegoPolicy{
		Name: "policy2.rego",
		Module: []byte(`package collision
deny[msg] {
  input.type == "test"
  msg := "policy2 denied"
}`),
	}

	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy1, policy2},
	)
	// Both policies should fire because the input matches both conditions.
	// OPA merges rules from the same package, so both deny rules should contribute.
	require.Error(t, err, "both collision policies should fire")
	assert.Contains(t, err.Error(), "policy1 denied", "policy1 deny should be in results")
	assert.Contains(t, err.Error(), "policy2 denied", "policy2 deny should be in results")
	t.Log("Package collision: OPA correctly merges deny rules from same-package modules")
}

// TestAdversarial_RegoPackageCollision_ConflictingRules tests what happens when
// two modules with the same package define CONFLICTING complete rules (not
// partial rules like deny[msg]).
func TestAdversarial_RegoPackageCollision_ConflictingCompleteRules(t *testing.T) {
	// Two modules define "allow" as a complete rule with different values.
	// In OPA, this should cause a conflict error.
	policy1 := RegoPolicy{
		Name: "conflict1.rego",
		Module: []byte(`package conflict
allow = true
deny[msg] {
  not allow
  msg := "not allowed"
}`),
	}
	policy2 := RegoPolicy{
		Name: "conflict2.rego",
		Module: []byte(`package conflict
allow = false`),
	}

	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy1, policy2},
	)
	if err != nil {
		t.Logf("Conflicting complete rules result: %v", err)
		if strings.Contains(err.Error(), "conflict") || strings.Contains(err.Error(), "multiple") {
			t.Log("GOOD: OPA detected conflicting complete rules and errored")
		} else if strings.Contains(err.Error(), "not allowed") {
			t.Log("FINDING: Conflicting complete rules -- one value silently won. " +
				"An attacker with a second policy module could override a security-critical rule.")
		}
	} else {
		t.Log("FINDING: No error from conflicting complete rules. The value of 'allow' " +
			"is ambiguous. An attacker could inject a module to override security rules.")
	}
}

// TestAdversarial_RegoPackageCollision_ShadowDeny tests whether a second module
// can shadow or override the deny rule from the first module.
func TestAdversarial_RegoPackageCollision_ShadowDeny(t *testing.T) {
	// First module defines a deny rule that should fire.
	legitimate := RegoPolicy{
		Name: "legitimate.rego",
		Module: []byte(`package shadow
deny[msg] {
  msg := "legitimate security check failed"
}`),
	}
	// Second module tries to "cancel" the deny by defining deny as an empty set.
	// In OPA, partial rules merge, so this should NOT cancel the first deny.
	malicious := RegoPolicy{
		Name: "malicious.rego",
		Module: []byte(`package shadow
# Attempt to override deny with a default empty set
default deny = set()
`),
	}

	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{legitimate, malicious},
	)
	if err != nil {
		if strings.Contains(err.Error(), "legitimate security check failed") {
			t.Log("GOOD: Malicious module could not shadow the legitimate deny rule")
		} else {
			t.Logf("Error (may be compile error from conflicting rule types): %v", err)
		}
	} else {
		t.Log("FINDING: The malicious module successfully suppressed the legitimate deny rule! " +
			"An attacker who can inject a policy module can bypass security checks.")
	}
}

// ===========================================================================
// 4. Cross-step context injection via JSON type confusion
// ===========================================================================

// TestAdversarial_CrossStepContext_JSONNumberType tests that json.Number is
// used (via decoder.UseNumber()) and that Rego policies see numbers as
// json.Number rather than float64, which could cause comparison issues.
func TestAdversarial_CrossStepContext_JSONNumberType(t *testing.T) {
	// The attestor has a field with a large integer that could lose precision
	// if converted to float64.
	type precisionAttestor struct {
		AttName   string `json:"name"`
		AttType   string `json:"type"`
		BigNumber int64  `json:"bignumber"`
	}

	attestor := &wrappedAttestor{
		inner: &precisionAttestor{
			AttName:   "test",
			AttType:   "test-type",
			BigNumber: 9007199254740993, // 2^53 + 1, loses precision in float64
		},
	}

	// Rego policy that checks the big number value
	policy := RegoPolicy{
		Name: "precision.rego",
		Module: []byte(`package precision
deny[msg] {
  # json.Number comparison in Rego
  input.bignumber != 9007199254740993
  msg := sprintf("bignumber precision lost: got %v", [input.bignumber])
}`),
	}

	err := EvaluateRegoPolicy(attestor, []RegoPolicy{policy})
	if err != nil {
		if strings.Contains(err.Error(), "precision lost") {
			t.Log("FINDING: Large integer precision is lost during JSON round-trip. " +
				"UseNumber() is set but Rego may still convert json.Number to float64 internally.")
		} else {
			t.Logf("Precision test result (may be comparison error): %v", err)
		}
	} else {
		t.Log("Big number precision preserved correctly through JSON round-trip")
	}
}

// TestAdversarial_CrossStepContext_NestedJSONInjection tests whether attestation
// data can contain JSON that, when re-marshaled/unmarshaled, produces unexpected
// structure in the step context.
func TestAdversarial_CrossStepContext_NestedJSONInjection(t *testing.T) {
	// Create an attestor whose JSON representation contains a field named
	// "steps" -- which mirrors the cross-step context key.
	type trickAttestor struct {
		AttName string                 `json:"name"`
		AttType string                 `json:"type"`
		Steps   map[string]interface{} `json:"steps"` // Mirrors the wrapper key
	}

	attestor := &wrappedAttestor{
		inner: &trickAttestor{
			AttName: "trick",
			AttType: "trick-type",
			Steps: map[string]interface{}{
				"injected_step": map[string]interface{}{
					"malicious": true,
				},
			},
		},
	}

	// With step context, input becomes {attestation: ..., steps: <real>}.
	// The attestor's own "steps" field is nested under input.attestation.steps.
	// Without step context, input IS the attestor, so input.steps would be
	// the injected data.
	policyWithContext := RegoPolicy{
		Name: "injection_with_ctx.rego",
		Module: []byte(`package injection_with_ctx
deny[msg] {
  # With step context wrapping, the injected steps should be at
  # input.attestation.steps, NOT input.steps
  input.steps.injected_step
  msg := "injected step data appeared at input.steps"
}`),
	}

	// Test with step context -- the wrapping should isolate the attestor's
	// "steps" field from the real step context.
	stepCtx := map[string]interface{}{
		"build": map[string]interface{}{
			"att": map[string]interface{}{"data": "real"},
		},
	}
	err := EvaluateRegoPolicy(attestor, []RegoPolicy{policyWithContext}, stepCtx)
	if err != nil && strings.Contains(err.Error(), "injected step data") {
		t.Fatal("FINDING: Attestor's 'steps' field leaked into input.steps, " +
			"overriding the real cross-step context. This is a critical injection vulnerability.")
	} else {
		t.Log("GOOD: With step context wrapping, attestor's 'steps' field is properly " +
			"isolated under input.attestation.steps")
	}

	// Test WITHOUT step context -- now the attestor IS input directly.
	policyNoContext := RegoPolicy{
		Name: "injection_no_ctx.rego",
		Module: []byte(`package injection_no_ctx
deny[msg] {
  input.steps.injected_step.malicious == true
  msg := "attestor controlled input.steps without context wrapping"
}`),
	}

	err = EvaluateRegoPolicy(attestor, []RegoPolicy{policyNoContext})
	if err != nil && strings.Contains(err.Error(), "attestor controlled input.steps") {
		t.Log("FINDING: Without step context, an attestor can place arbitrary data at " +
			"input.steps. If a Rego policy checks input.steps but step context was " +
			"accidentally omitted, the attestor controls what the policy sees. " +
			"Combined with the 'silent pass' issue, this is exploitable.")
	}
}

// ===========================================================================
// 5. The "Silent Pass" Security Issue
// ===========================================================================

// TestAdversarial_SilentPass_Exploitation demonstrates the security vulnerability
// where a Rego policy that checks input.steps silently passes when step context
// is nil (no wrapping), because the rule body is never entered.
func TestAdversarial_SilentPass_Exploitation(t *testing.T) {
	// This is a security-critical policy that should REQUIRE build step data.
	// It checks that the build step used a specific compiler version.
	securityPolicy := RegoPolicy{
		Name: "require_build_data.rego",
		Module: []byte(`package require_build
deny[msg] {
  build_data := input.steps.build["https://example.com/build-att/v1"]
  build_data.compiler_version != "gcc-13.2"
  msg := "build must use gcc-13.2"
}

deny[msg] {
  build_data := input.steps.build["https://example.com/build-att/v1"]
  not build_data.security_scan_passed
  msg := "build must pass security scan"
}`),
	}

	// Scenario 1: With proper step context containing wrong data -- should DENY
	t.Run("with_wrong_step_context_denies", func(t *testing.T) {
		stepCtx := map[string]interface{}{
			"build": map[string]interface{}{
				"https://example.com/build-att/v1": map[string]interface{}{
					"compiler_version":     "gcc-11.0",
					"security_scan_passed": false,
				},
			},
		}
		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy", AttType: "deploy-type"},
			[]RegoPolicy{securityPolicy},
			stepCtx,
		)
		require.Error(t, err, "wrong build data should trigger deny")
		assert.Contains(t, err.Error(), "gcc-13.2")
	})

	// Scenario 2: With correct step context -- should PASS
	t.Run("with_correct_step_context_passes", func(t *testing.T) {
		stepCtx := map[string]interface{}{
			"build": map[string]interface{}{
				"https://example.com/build-att/v1": map[string]interface{}{
					"compiler_version":     "gcc-13.2",
					"security_scan_passed": true,
				},
			},
		}
		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy", AttType: "deploy-type"},
			[]RegoPolicy{securityPolicy},
			stepCtx,
		)
		assert.NoError(t, err, "correct build data should pass")
	})

	// Scenario 3: WITHOUT step context (nil) -- THIS IS THE BUG
	// The policy silently passes because input.steps doesn't exist,
	// so the rule body is never entered, so deny is empty.
	t.Run("EXPLOIT_without_step_context_silently_passes", func(t *testing.T) {
		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy", AttType: "deploy-type"},
			[]RegoPolicy{securityPolicy},
			// No step context!
		)
		// This SHOULD fail -- but it silently passes.
		if err == nil {
			t.Log("CONFIRMED VULNERABILITY: Security policy that requires build step data " +
				"silently passes when step context is missing. An attacker who can prevent " +
				"step context from being built (e.g., by causing the dependency step to fail " +
				"verification) can bypass ALL cross-step Rego policies.")
		} else {
			t.Log("GOOD: Policy correctly denied when step context was missing")
		}
		// Document the expected vs actual behavior
		assert.NoError(t, err,
			"This assertion documents the current (vulnerable) behavior: "+
				"the policy silently passes without step context")
	})

	// Scenario 4: With empty non-nil step context -- wrapping happens but
	// input.steps is empty
	t.Run("EXPLOIT_with_empty_step_context_silently_passes", func(t *testing.T) {
		emptyCtx := map[string]interface{}{}
		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy", AttType: "deploy-type"},
			[]RegoPolicy{securityPolicy},
			emptyCtx,
		)
		if err == nil {
			t.Log("CONFIRMED VULNERABILITY: Security policy silently passes with empty step context. " +
				"input.steps exists but is empty, so input.steps.build is undefined, " +
				"and the deny rule body is never entered.")
		}
		assert.NoError(t, err,
			"Documents current behavior: empty step context also silently passes")
	})
}

// TestAdversarial_SilentPass_ProperMitigation shows how a policy SHOULD be
// written to avoid the silent pass issue, and demonstrates that even the
// mitigation has a gap.
func TestAdversarial_SilentPass_ProperMitigation(t *testing.T) {
	// A properly written policy should first check that steps exist.
	mitigatedPolicy := RegoPolicy{
		Name: "mitigated.rego",
		Module: []byte(`package mitigated

# Deny if steps context is missing entirely
deny[msg] {
  not input.steps
  msg := "cross-step context is required but missing"
}

# Deny if build step is missing from context
deny[msg] {
  not input.steps.build
  msg := "build step data is required"
}

# Actual security check
deny[msg] {
  build_data := input.steps.build["https://example.com/build-att/v1"]
  build_data.compiler_version != "gcc-13.2"
  msg := "build must use gcc-13.2"
}`),
	}

	// Without step context: input.steps doesn't exist, so first deny fires
	t.Run("mitigated_denies_without_context", func(t *testing.T) {
		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy", AttType: "deploy-type"},
			[]RegoPolicy{mitigatedPolicy},
		)
		// Without step context, input is the attestor directly.
		// input.steps might actually exist if the attestor has a "steps" field!
		// For marshalableAttestor, it does NOT have steps, so input.steps is undefined.
		// BUT: `not input.steps` evaluates to true ONLY when input.steps is undefined.
		// When there's no step context wrapping, input IS the attestor.
		// The attestor doesn't have "steps", so input.steps is undefined.
		// `not input.steps` -> true -> deny fires. This is the correct behavior.
		if err != nil {
			t.Log("GOOD: Mitigated policy correctly denies when step context is missing")
			assert.Contains(t, err.Error(), "missing")
		} else {
			t.Log("FINDING: Even the mitigation failed to catch missing context")
		}
	})

	// With empty step context: input.steps exists but is empty {}
	t.Run("mitigated_denies_with_empty_context", func(t *testing.T) {
		emptyCtx := map[string]interface{}{}
		err := EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "deploy", AttType: "deploy-type"},
			[]RegoPolicy{mitigatedPolicy},
			emptyCtx,
		)
		// input.steps exists (it's {}) so `not input.steps` is false.
		// But input.steps.build is undefined, so `not input.steps.build` is true.
		// The second deny rule fires.
		if err != nil {
			t.Log("GOOD: Mitigated policy correctly denies with empty step context")
			assert.Contains(t, err.Error(), "build step data is required")
		} else {
			t.Log("FINDING: Mitigation did not catch empty step context")
		}
	})
}

// ===========================================================================
// 6. Rego Denial of Service
// ===========================================================================

// TestAdversarial_RegoDoS_DeeplyNestedComprehension tests whether a deeply
// nested set comprehension can consume excessive CPU/memory.
func TestAdversarial_RegoDoS_DeeplyNestedComprehension(t *testing.T) {
	// Generate a set comprehension that creates a large set
	policy := RegoPolicy{
		Name: "dos_comprehension.rego",
		Module: []byte(`package dos_comprehension
deny[msg] {
  # Create a large set via nested comprehension
  s1 := {x | x := numbers.range(1, 1000)[_]}
  s2 := {y | y := numbers.range(1, 1000)[_]}
  # Cross product
  s3 := {[a, b] | a := s1[_]; b := s2[_]}
  count(s3) > 0
  msg := "dos attempt"
}`),
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "test", AttType: "test"},
			[]RegoPolicy{policy},
		)
	}()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		if elapsed > 10*time.Second {
			t.Logf("FINDING: Cross-product comprehension took %v -- potential DoS vector", elapsed)
		} else {
			t.Logf("Cross-product comprehension completed in %v (err: %v)", elapsed, err)
		}
	case <-time.After(30 * time.Second):
		t.Log("FINDING: Cross-product comprehension did not complete within 30s timeout -- " +
			"confirmed DoS vector via Rego policy")
	}
}

// TestAdversarial_RegoDoS_StringConcat tests whether string concatenation in
// a loop can consume excessive memory.
func TestAdversarial_RegoDoS_StringConcat(t *testing.T) {
	policy := RegoPolicy{
		Name: "dos_string.rego",
		Module: []byte(`package dos_string
deny[msg] {
  # Build a very large string by concatenating
  parts := [x | x := numbers.range(1, 10000)[_]; true]
  big_string := concat(",", [sprintf("%d", [p]) | p := parts[_]])
  count(big_string) > 0
  msg := "string dos"
}`),
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "test", AttType: "test"},
			[]RegoPolicy{policy},
		)
	}()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		t.Logf("String concat DoS completed in %v (err: %v)", elapsed, err)
		if elapsed > 5*time.Second {
			t.Logf("FINDING: String concatenation took %v -- potential DoS", elapsed)
		}
	case <-time.After(30 * time.Second):
		t.Log("FINDING: String concatenation did not complete within 30s -- DoS confirmed")
	}
}

// TestAdversarial_RegoDoS_Recursivelike tests whether a pattern that mimics
// recursion (via iterating over a growing set) can cause resource exhaustion.
func TestAdversarial_RegoDoS_RecursionPattern(t *testing.T) {
	// OPA doesn't support direct recursion, but you can simulate expensive
	// computation via comprehensions that iterate over large generated data.
	policy := RegoPolicy{
		Name: "dos_recurse.rego",
		Module: []byte(`package dos_recurse
deny[msg] {
  # Generate a large array and then sort it (O(n log n))
  arr := [x | x := numbers.range(1, 50000)[_]]
  sorted := sort(arr)
  count(sorted) > 0
  msg := "recurse dos"
}`),
	}

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		done <- EvaluateRegoPolicy(
			&marshalableAttestor{AttName: "test", AttType: "test"},
			[]RegoPolicy{policy},
		)
	}()

	select {
	case err := <-done:
		elapsed := time.Since(start)
		t.Logf("Recursive-like pattern completed in %v (err: %v)", elapsed, err)
		if elapsed > 5*time.Second {
			t.Logf("FINDING: Recursive-like pattern took %v -- DoS potential", elapsed)
		}
	case <-time.After(60 * time.Second):
		t.Log("FINDING: Recursive-like pattern timed out -- DoS confirmed")
	}
}

// ===========================================================================
// 7. validateAttestations: nil step context flows through to EvaluateRegoPolicy
// ===========================================================================

// TestAdversarial_ValidateAttestations_NilStepContext_FlowThrough tests the
// full flow where validateAttestations passes nil stepContext to
// EvaluateRegoPolicy, causing the silent pass issue.
func TestAdversarial_ValidateAttestations_NilStepContext_FlowThrough(t *testing.T) {
	attType := "https://example.com/deploy/v1"

	// A security-critical rego policy that requires cross-step data.
	securityRego := []byte(`package security
deny[msg] {
  build := input.steps.build["https://example.com/build/v1"]
  build.approved != true
  msg := "build not approved"
}`)

	step := Step{
		Name:             "deploy",
		AttestationsFrom: []string{"build"},
		Attestations: []Attestation{{
			Type:         attType,
			RegoPolicies: []RegoPolicy{{Module: securityRego, Name: "security.rego"}},
		}},
	}

	coll := attestation.Collection{
		Name: "deploy",
		Attestations: []attestation.CollectionAttestation{{
			Type:        attType,
			Attestation: &marshalableAttestor{AttName: "deploy", AttType: attType},
		}},
	}
	cvr := source.CollectionVerificationResult{
		CollectionEnvelope: source.CollectionEnvelope{Collection: coll},
	}

	// Pass nil stepContext -- simulates the case where checkDependencies failed
	// and the code skipped context building.
	result := step.validateAttestations(
		[]source.CollectionVerificationResult{cvr},
		"",
		nil, // nil step context!
	)

	if len(result.Passed) > 0 && len(result.Rejected) == 0 {
		t.Log("CONFIRMED VULNERABILITY: validateAttestations with nil step context " +
			"causes security rego policy to silently pass. The deploy step would be " +
			"marked as 'passed' even though the build approval check was never evaluated.")
	}
	// Document the vulnerable behavior
	assert.Len(t, result.Passed, 1,
		"Documents vulnerable behavior: nil context = silent pass")
	assert.Empty(t, result.Rejected,
		"Documents vulnerable behavior: no rejections")
}

// ===========================================================================
// 8. Edge cases in EvaluateRegoPolicy query building
// ===========================================================================

// TestAdversarial_RegoPolicy_EmptyPackageName tests what happens with
// unusual package names.
func TestAdversarial_RegoPolicy_EmptyDenyResult(t *testing.T) {
	// A policy where deny returns non-string values
	policy := RegoPolicy{
		Name: "bad_deny_type.rego",
		Module: []byte(`package bad_deny_type
deny[msg] {
  msg := 42
}`),
	}

	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	// The code at line 137 of rego.go checks `reason.(string)` and returns
	// ErrRegoInvalidData if the type assertion fails.
	require.Error(t, err, "non-string deny values should error")
	t.Logf("Non-string deny result: %v", err)
}

// TestAdversarial_RegoPolicy_DenyReturnsEmptyString tests what happens when
// deny returns an empty string -- is it still treated as a denial?
func TestAdversarial_RegoPolicy_DenyReturnsEmptyString(t *testing.T) {
	policy := RegoPolicy{
		Name: "empty_deny.rego",
		Module: []byte(`package empty_deny
deny[msg] {
  msg := ""
}`),
	}

	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	if err != nil {
		t.Log("Empty string deny is treated as a denial -- correct behavior")
	} else {
		t.Log("FINDING: Empty string deny was NOT treated as a denial. " +
			"This could be exploited to produce a 'deny' that doesn't actually deny.")
	}
	// An empty string is still a string, and the deny set is non-empty,
	// so it should still be treated as a denial.
	require.Error(t, err, "empty string deny should still be treated as denial")
}

// TestAdversarial_RegoPolicy_MultiplePoliciesDifferentPackages tests that
// deny results from different packages are all collected.
func TestAdversarial_RegoPolicy_MultiplePoliciesDifferentPackages(t *testing.T) {
	policy1 := RegoPolicy{
		Name: "pkg1.rego",
		Module: []byte(`package pkg1
deny[msg] {
  msg := "denied by pkg1"
}`),
	}
	policy2 := RegoPolicy{
		Name: "pkg2.rego",
		Module: []byte(`package pkg2
deny[msg] {
  msg := "denied by pkg2"
}`),
	}

	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy1, policy2},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "denied by pkg1")
	assert.Contains(t, err.Error(), "denied by pkg2")
	t.Log("Multiple packages correctly aggregate deny results")
}

// ===========================================================================
// 9. buildStepContext: attestation data overwrite race
// ===========================================================================

// TestAdversarial_BuildStepContext_LastWriterWins_SecurityImplication tests
// the security implication of the last-writer-wins behavior when multiple
// passed collections have the same attestation type.
func TestAdversarial_BuildStepContext_LastWriterWins_SecurityImplication(t *testing.T) {
	attType := "https://example.com/security-scan/v1"

	// First collection: legitimate security scan that PASSED
	// Second collection: attacker-controlled scan that LIES about passing
	results := map[string]StepResult{
		"scan": {
			Step: "scan",
			Passed: []PassedCollection{
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "scan",
								Attestations: []attestation.CollectionAttestation{{
									Type: attType,
									Attestation: &marshalableAttestor{
										AttName: "legit-scan",
										AttType: attType,
									},
								}},
							},
						},
					},
				},
				{
					Collection: source.CollectionVerificationResult{
						CollectionEnvelope: source.CollectionEnvelope{
							Collection: attestation.Collection{
								Name: "scan",
								Attestations: []attestation.CollectionAttestation{{
									Type: attType,
									Attestation: &marshalableAttestor{
										AttName: "attacker-scan",
										AttType: attType,
									},
								}},
							},
						},
					},
				},
			},
		},
	}

	ctx := buildStepContext([]string{"scan"}, results)
	require.NotNil(t, ctx)
	scanCtx := ctx["scan"].(map[string]interface{})
	attData := scanCtx[attType].(map[string]interface{})

	// The second collection overwrites the first
	actualName := attData["name"]
	assert.Equal(t, "attacker-scan", actualName,
		"CONFIRMED: Last writer wins -- attacker's scan data overwrites legitimate scan data. "+
			"If an attacker can get a second collection signed and verified, they can control "+
			"what downstream Rego policies see for this attestation type.")
	t.Log("SECURITY ISSUE: buildStepContext uses last-writer-wins for overlapping " +
		"attestation types across multiple passed collections")
}

// ===========================================================================
// 10. Rego policy with no deny rule at all
// ===========================================================================

// TestAdversarial_RegoPolicy_NoDenyRule tests what happens when a Rego policy
// has no deny rule at all. The query is "data.<pkg>.deny" which would be
// undefined, causing the result to have no expressions or an empty set.
func TestAdversarial_RegoPolicy_NoDenyRule(t *testing.T) {
	policy := RegoPolicy{
		Name: "no_deny.rego",
		Module: []byte(`package no_deny
# Intentionally no deny rule
allow = true
`),
	}

	err := EvaluateRegoPolicy(
		&marshalableAttestor{AttName: "test", AttType: "test"},
		[]RegoPolicy{policy},
	)
	// With no deny rule, data.no_deny.deny is undefined.
	// The Rego eval should return an empty result set for that expression.
	// The code iterates over expressions and their values.
	// If the expression value is not []interface{}, it returns ErrRegoInvalidData.
	if err != nil {
		t.Logf("Policy with no deny rule result: %v", err)
		if strings.Contains(err.Error(), "invalid data") {
			t.Log("A policy with no deny rule causes ErrRegoInvalidData. " +
				"This means an attacker can't easily create a policy that " +
				"silently passes by omitting the deny rule -- the error catches it.")
		}
	} else {
		t.Log("FINDING: A policy with no deny rule silently passes. " +
			"An attacker can inject a Rego module that does nothing, and it will " +
			"be treated as passing all checks.")
	}
}

// ===========================================================================
// Helpers for adversarial tests
// ===========================================================================

// wrappedAttestor wraps any struct to implement attestation.Attestor.
// Used for testing JSON serialization edge cases.
type wrappedAttestor struct {
	inner interface{}
}

func (w *wrappedAttestor) Name() string                                   { return "wrapped" }
func (w *wrappedAttestor) Type() string                                   { return "wrapped-type" }
func (w *wrappedAttestor) RunType() attestation.RunType                   { return "test" }
func (w *wrappedAttestor) Attest(_ *attestation.AttestationContext) error { return nil }
func (w *wrappedAttestor) Schema() *jsonschema.Schema                     { return nil }
func (w *wrappedAttestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.inner)
}
