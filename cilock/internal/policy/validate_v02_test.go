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
	"context"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/require"
)

// Spelled literally: the test pins the wire strings, not the constants.
const (
	v02AflockV01 = "https://aflock.ai/policy/v0.1"
	v02AflockV02 = "https://aflock.ai/policy/v0.2"
	v02LegacyV01 = "https://witness.testifysec.com/policy/v0.1"
)

// v02Policy is a minimal valid policy whose "build" step carries the given
// about value; "" leaves the key out entirely.
func v02Policy(about string) []byte {
	aboutField := ""
	if about != "" {
		aboutField = `"about":"` + about + `",`
	}
	return []byte(`{"expires":"2030-01-01T00:00:00Z","steps":{"build":{"name":"build",` + aboutField +
		`"functionaries":[{"type":"publickey","publickeyid":"key-1"}],` +
		`"attestations":[{"type":"https://aflock.ai/attestations/command-run/v0.1"}]}},` +
		`"publickeys":{"key-1":{"keyid":"key-1","key":""}}}`)
}

func v02Envelope(payloadType string, payload []byte) dsse.Envelope {
	return dsse.Envelope{PayloadType: payloadType, Payload: payload}
}

func joined(r *ValidationResult) string {
	return strings.Join(r.Errors, "\n") + "\n" + strings.Join(r.Warnings, "\n")
}

// PV7 (validate): a v0.2 envelope is an expected policy type. It validates
// with no type warning, with or without a step declaring about.
func TestValidatePolicy_V02IsAnExpectedType(t *testing.T) {
	for _, about := range []string{"", "source"} {
		r := ValidatePolicy(context.Background(), v02Envelope(v02AflockV02, v02Policy(about)), nil)
		require.True(t, r.Valid, "about=%q: %s", about, joined(r))
		for _, w := range r.Warnings {
			require.NotContains(t, w, "PayloadType", "about=%q: a v0.2 envelope must not draw a type warning", about)
		}
	}
}

// PV1's rule, applied by cilock at authoring time: about needs the v0.2 type
// (under both v0.1 spellings), and source is the only value.
func TestValidatePolicy_AboutRules(t *testing.T) {
	cases := []struct {
		name        string
		payloadType string
		about       string
		wantCode    string
	}{
		{"aflock v0.1 with about", v02AflockV01, "source", "about-needs-policy-v0.2"},
		{"legacy v0.1 with about", v02LegacyV01, "source", "about-needs-policy-v0.2"},
		{"v0.2 with an unknown about", v02AflockV02, "seed", "about-unknown-value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ValidatePolicy(context.Background(), v02Envelope(tc.payloadType, v02Policy(tc.about)), nil)
			require.False(t, r.Valid, "must be refused")
			require.Contains(t, strings.Join(r.Errors, "\n"), tc.wantCode)
			require.Contains(t, strings.Join(r.Errors, "\n"), "build", "the refusal names the step")
		})
	}
}

// A raw policy has no type yet: signing picks it (v0.2 when a step declares
// about). So about is accepted on a raw policy, but its value is still checked.
func TestValidateRawPolicy_AboutValue(t *testing.T) {
	r := ValidateRawPolicy(context.Background(), v02Policy("source"))
	require.True(t, r.Valid, joined(r))

	r = ValidateRawPolicy(context.Background(), v02Policy("seed"))
	require.False(t, r.Valid)
	require.Contains(t, strings.Join(r.Errors, "\n"), "about-unknown-value")
}

// v0.1 without about is untouched: same verdict, same warnings as before.
func TestValidatePolicy_V01WithoutAboutUnchanged(t *testing.T) {
	for _, pt := range []string{v02AflockV01, v02LegacyV01} {
		r := ValidatePolicy(context.Background(), v02Envelope(pt, v02Policy("")), nil)
		require.True(t, r.Valid, "%s: %s", pt, joined(r))
		for _, w := range r.Warnings {
			require.NotContains(t, w, "PayloadType")
		}
	}
}

// Any type but exactly v0.2 is refused with about, not only the two v0.1
// spellings: a later type is not this validator's to accept.
func TestValidatePolicy_AboutUnderAnotherTypeIsRefused(t *testing.T) {
	r := ValidatePolicy(context.Background(), v02Envelope("https://aflock.ai/policy/v0.3", v02Policy("source")), nil)
	require.False(t, r.Valid)
	require.Contains(t, strings.Join(r.Errors, "\n"), "about-needs-policy-v0.2")
}

// validate agrees with the verifier: a v0.2 envelope is decoded strictly
// (policy.DecodePolicyEnvelope), so a member the Policy type does not know is
// an error here too, not a policy that validates and then fails every verify.
// v0.1 keeps its lenient decode.
func TestValidatePolicy_V02MustDecodeStrictly(t *testing.T) {
	withComment := append([]byte(`{"_comment":"reviewers read this",`), v02Policy("source")[1:]...)
	r := ValidatePolicy(context.Background(), v02Envelope(v02AflockV02, withComment), nil)
	require.False(t, r.Valid, joined(r))
	require.Contains(t, strings.Join(r.Errors, "\n"), `unknown field "_comment"`)

	plain := append([]byte(`{"_comment":"reviewers read this",`), v02Policy("")[1:]...)
	for _, pt := range []string{v02AflockV01, v02LegacyV01} {
		r := ValidatePolicy(context.Background(), v02Envelope(pt, plain), nil)
		require.True(t, r.Valid, "%s: %s", pt, joined(r))
	}
}
