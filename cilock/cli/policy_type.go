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

	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/spf13/cobra"
)

// datatypeFlag is the flag `cilock sign`, `policy draft` and `policy publish`
// take the policy payload type from.
const datatypeFlag = "datatype"

// resolvePolicyPayloadType picks the payload type a policy document is signed
// or hydrated under. A document with no step declaring about keeps datatype,
// whatever it is, so a v0.1 policy is handled exactly as before. A document
// that declares about gets policy v0.2 when the caller left the type to
// cilock (explicit false). An explicit v0.1 type on such a document is
// refused before anything is sent or signed: it would produce a policy the
// verifier refuses on every run.
func resolvePolicyPayloadType(explicit bool, datatype string, document []byte) (string, error) {
	steps := policy.StepsDeclaringAbout(document)
	if len(steps) == 0 {
		return datatype, nil
	}
	if !explicit {
		return policy.PolicyPredicateV02, nil
	}
	if policy.IsPolicyV01Type(datatype) {
		return "", fmt.Errorf("about-needs-policy-v0.2: step(s) %s declare about, which a %s policy cannot carry; "+
			"drop --%s so cilock signs it as %s", strings.Join(steps, ", "), datatype, datatypeFlag, policy.PolicyPredicateV02)
	}
	return datatype, nil
}

// refuseUndecodableV02Policy refuses to sign bytes as policy v0.2 when the
// verifier's decoder would refuse them. Every verify decodes a v0.2 policy
// strictly (policy.DecodePolicyEnvelope), so a member the Policy type does
// not know would make the signed policy fail on every run. Other types are
// not checked here: v0.1 decodes leniently, and cilock sign also signs data
// that is not a policy.
func refuseUndecodableV02Policy(payloadType string, data []byte) error {
	if payloadType != policy.PolicyPredicateV02 {
		return nil
	}
	if _, err := policy.DecodePolicyEnvelope(payloadType, data); err != nil {
		return fmt.Errorf("refusing to sign: every verifier decodes a %s policy strictly and would refuse this one: %w",
			policy.PolicyPredicateV02, err)
	}
	return nil
}

// readTypedPolicySource reads a hand-authored policy source and resolves the
// payload type it is hydrated, approved and signed under (draft and publish).
func readTypedPolicySource(cmd *cobra.Command, file, datatype string) (string, string, error) {
	source, err := readPolicySource(file)
	if err != nil {
		return "", "", err
	}
	resolved, err := resolvePolicyPayloadType(cmd.Flags().Changed(datatypeFlag), datatype, []byte(source))
	if err != nil {
		return "", "", err
	}
	return source, resolved, nil
}
