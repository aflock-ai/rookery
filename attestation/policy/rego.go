// Copyright 2021 The Witness Contributors
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// regoEvalTimeout is the maximum duration allowed for a single Rego policy
// evaluation. This prevents malicious or poorly-written policies from causing
// denial of service through infinite loops or excessive computation.
const regoEvalTimeout = 30 * time.Second

// disallowedBuiltins lists OPA builtins that must not be available to policy
// Rego code. http.send allows data exfiltration, net.lookup_ip_addr enables
// DNS-based exfiltration, and opa.runtime leaks process metadata.
var disallowedBuiltins = map[string]struct{}{
	"http.send":          {},
	"opa.runtime":        {},
	"net.lookup_ip_addr": {},
}

// restrictedCapabilities returns OPA capabilities with dangerous builtins removed.
func restrictedCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	filtered := make([]*ast.Builtin, 0, len(caps.Builtins))
	for _, b := range caps.Builtins {
		if _, blocked := disallowedBuiltins[b.Name]; !blocked {
			filtered = append(filtered, b)
		}
	}
	caps.Builtins = filtered
	return caps
}

func EvaluateRegoPolicy(attestor attestation.Attestor, policies []RegoPolicy, stepContext ...map[string]interface{}) error {
	if len(policies) == 0 {
		return nil
	}

	if attestor == nil {
		return fmt.Errorf("attestor must not be nil")
	}

	attestorJSON, err := json.Marshal(attestor)
	if err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(attestorJSON))
	decoder.UseNumber()
	var attestorData interface{}
	if err := decoder.Decode(&attestorData); err != nil {
		return err
	}

	// When cross-step context is provided, wrap the input so Rego policies
	// can access other steps' attestation data via input.steps.<stepName>.
	var input interface{}
	if len(stepContext) > 0 && stepContext[0] != nil {
		input = map[string]interface{}{
			"attestation": attestorData,
			"steps":       stepContext[0],
		}
	} else {
		input = attestorData
	}

	query := ""
	denyPaths := map[string]struct{}{}
	regoOpts := []func(*rego.Rego){
		rego.Input(input),
		rego.Capabilities(restrictedCapabilities()),
		rego.StrictBuiltinErrors(true),
	}
	for _, policy := range policies {
		policyString := string(policy.Module)
		parsedModule, err := ast.ParseModule(policy.Name, policyString)
		if err != nil {
			return err
		}

		packageDenyPathStr := fmt.Sprintf("%v.deny", parsedModule.Package.Path)
		// if packages share the same name we only want the package to show up once in our query.  rego will merge their deny results
		if _, ok := denyPaths[packageDenyPathStr]; !ok {
			query += fmt.Sprintf("%v.deny\n", parsedModule.Package.Path)
			denyPaths[packageDenyPathStr] = struct{}{}
		}

		regoOpts = append(regoOpts, rego.ParsedModule(parsedModule))
	}

	// Block dangerous OPA builtins that could allow data exfiltration or
	// network access from within Rego policies.
	regoOpts = append(regoOpts, rego.UnsafeBuiltins(map[string]struct{}{
		"http.send":           {},
		"opa.runtime":         {},
		"net.lookup_ip_addr":  {},
		"net.cidr_contains":   {},
		"net.cidr_intersects": {},
		"net.cidr_merge":      {},
		"net.cidr_expand":     {},
	}))
	regoOpts = append(regoOpts, rego.StrictBuiltinErrors(true))

	regoOpts = append(regoOpts, rego.Query(query))
	r := rego.New(regoOpts...)

	// Use a timeout context to prevent DoS from malicious or poorly-written
	// Rego policies that loop indefinitely.
	ctx, cancel := context.WithTimeout(context.Background(), regoEvalTimeout)
	defer cancel()

	rs, err := r.Eval(ctx)
	if err != nil {
		return fmt.Errorf("rego policy evaluation error for attestor type %s: %w", attestor.Type(), err)
	}

	// Security: if the result set is empty, one or more Rego modules didn't
	// define a 'deny' rule. In OPA, querying an undefined rule returns no
	// results. Without this check, a policy module missing 'deny' silently
	// passes — an attacker could supply a module with an irrelevant rule name
	// to bypass policy enforcement entirely.
	if len(rs) == 0 && len(denyPaths) > 0 {
		return fmt.Errorf("rego policy evaluation returned no results for attestor type %s: one or more policy modules may be missing a 'deny' rule", attestor.Type())
	}

	allDenyReasons := []string{}
	for _, expression := range rs {
		for _, value := range expression.Expressions {
			denyReasons, ok := value.Value.([]interface{})
			if !ok {
				return ErrRegoInvalidData{Path: value.Text, Expected: "[]interface{}", Actual: value.Value}
			}

			for _, reason := range denyReasons {
				reasonStr, ok := reason.(string)
				if !ok {
					return ErrRegoInvalidData{Path: value.Text, Expected: "string", Actual: value.Value}
				}

				allDenyReasons = append(allDenyReasons, reasonStr)
			}
		}
	}

	if len(allDenyReasons) > 0 {
		return fmt.Errorf("rego policy evaluation failed for attestor type %s: %w", attestor.Type(), ErrPolicyDenied{Reasons: allDenyReasons})
	}

	return nil
}
