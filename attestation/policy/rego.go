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

	"github.com/aflock-ai/rookery/attestation"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

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

func EvaluateRegoPolicy(attestor attestation.Attestor, policies []RegoPolicy) error {
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
	var input interface{}
	if err := decoder.Decode(&input); err != nil {
		return err
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

	regoOpts = append(regoOpts, rego.Query(query))
	rego := rego.New(regoOpts...)
	rs, err := rego.Eval(context.Background())
	if err != nil {
		return err
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
