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

package policy

import (
	"fmt"
	"strings"
	"testing"
)

// A policy whose whole gate is one external attestation (a Pushgate VSA) has
// no steps. The verifier has accepted that shape since #39; validation must
// too, but only when at least one external is REQUIRED, because a policy of
// optional externals alone verifies nothing.

const vsaBindingValidatePrefix = "https://pushgate.dev/v0.1/commithash:"

func vsaBindingExternalOnlyPolicy(externals string) string {
	return fmt.Sprintf(`{
  "expires": "2030-01-01T00:00:00Z",
  "roots": { "rootA": { "certificate": "Zm9v" } },
  "externalAttestations": %s
}`, externals)
}

func vsaBindingExternalJSON(required, commitSubject string) string {
	fields := []string{
		`"name":"pushgate-vsa"`,
		`"predicateType":"https://pushgate.dev/verification_summary/v0.5"`,
		`"functionaries":[{"type":"root","certConstraint":{"roots":["rootA"],"commonname":"*","emails":["judge-internal@testifysec.com"]}}]`,
	}
	if required != "" {
		fields = append(fields, `"required":`+required)
	}
	if commitSubject != "" {
		fields = append(fields, fmt.Sprintf(`"commitSubject":%q`, commitSubject))
	}
	return `{"pushgate-vsa":{` + strings.Join(fields, ",") + `}}`
}

func TestVsaBindingZeroStepsValidWithRequiredExternal(t *testing.T) {
	for name, required := range map[string]string{"required absent (defaults true)": "", "required true": "true"} {
		t.Run(name, func(t *testing.T) {
			res := validateRaw(t, vsaBindingExternalOnlyPolicy(vsaBindingExternalJSON(required, vsaBindingValidatePrefix)))
			if !res.Valid {
				t.Fatalf("a zero-step policy with a required external must validate, got %v", res.Errors)
			}
		})
	}
}

func TestVsaBindingZeroStepsInvalidWithoutRequiredExternal(t *testing.T) {
	cases := map[string]string{
		"only optional external": vsaBindingExternalOnlyPolicy(vsaBindingExternalJSON("false", "")),
		"empty externals":        vsaBindingExternalOnlyPolicy(`{}`),
		"no externals at all":    `{"expires":"2030-01-01T00:00:00Z","roots":{"rootA":{"certificate":"Zm9v"}}}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			res := validateRaw(t, doc)
			if res.Valid {
				t.Fatal("expected INVALID")
			}
			joined := strings.Join(res.Errors, " | ")
			if !strings.Contains(joined, "at least one step") || !strings.Contains(joined, "required external attestation") {
				t.Fatalf("error must name both remedies, got %q", joined)
			}
		})
	}
}

func TestVsaBindingValidateRefusesBadCommitSubject(t *testing.T) {
	for name, prefix := range map[string]string{
		"bare infix":     "commithash:",
		"trailing space": vsaBindingValidatePrefix + " ",
		"no commithash":  "https://pushgate.dev/v0.1/",
	} {
		t.Run(name, func(t *testing.T) {
			res := validateRaw(t, vsaBindingExternalOnlyPolicy(vsaBindingExternalJSON("", prefix)))
			if res.Valid {
				t.Fatal("expected INVALID")
			}
			if joined := strings.Join(res.Errors, " | "); !strings.Contains(joined, "commitSubject") {
				t.Fatalf("error must name commitSubject, got %q", joined)
			}
		})
	}
}

func TestVsaBindingValidateRefusesExternalWithoutFunctionaries(t *testing.T) {
	doc := vsaBindingExternalOnlyPolicy(`{"pushgate-vsa":{"name":"pushgate-vsa","predicateType":"https://pushgate.dev/verification_summary/v0.5","functionaries":[]}}`)
	res := validateRaw(t, doc)
	if res.Valid {
		t.Fatal("an external no signer can satisfy is a dead gate")
	}
}
