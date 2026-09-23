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

// jade:ring local

package cli

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/aflock-ai/rookery/cilock/internal/embeddedtrust"
)

// bobApproval writes Bob's valid approval and returns the offline verify
// arguments that pass for it with no signer flag.
func bobApproval(t *testing.T) []string {
	t.Helper()
	sandboxVerifyEnv(t)
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) { return nil, nil })
	payload, _ := approvalTestStatement(t, "bob@example.com", nil)
	envPath, ca, tsa := newApprovalEnvelopeFixture(t, payload, withLeafEmails("bob@example.com")).files(t, t.TempDir())
	return []string{"--envelope", envPath, "--policy-ca-roots", ca, "--policy-timestamp-servers", tsa, "--platform-url", ""}
}

// An explicit --policy-emails reads as "only this approver", and envelope mode
// does not pin an approver (design open question 2 closed on "defer"). So any
// explicit value is refused, whatever its spelling and whether or not it names
// the signer: a refusal cannot be bypassed by case, whitespace or a list.
func TestVerifyEnvelope_ExplicitPolicyEmailsRefused(t *testing.T) {
	base := bobApproval(t)
	out, err := runEnvelopeVerify(t, base...)
	require.NoError(t, err, "control: Bob's approval verifies with no signer flag")
	require.Contains(t, out, "bob@example.com")

	for name, value := range map[string]string{
		"mismatched signer":          "alice@example.com",
		"case variant of mismatch":   "ALICE@Example.COM",
		"whitespace variant":         " alice@example.com ",
		"several, none match":        "alice@example.com,carol@example.com",
		"several, one matches":       "alice@example.com,bob@example.com",
		"exactly the signer":         "bob@example.com",
		"case variant of the signer": "BOB@example.com",
		"empty":                      "",
	} {
		t.Run(name, func(t *testing.T) {
			out, err := runEnvelopeVerify(t, append(append([]string{}, base...), "--policy-emails="+value)...)
			require.Error(t, err, "an explicit --policy-emails %q must never be silently ignored", value)
			require.ErrorContains(t, err, "--policy-emails")
			require.NotContains(t, out, "verified:", "a refusal prints no verdict")
		})
	}
}

// envelopeHonouredPolicyFlags are the policy-* flags envelope mode applies.
var envelopeHonouredPolicyFlags = map[string]bool{
	"policy-ca-roots": true, "policy-ca": true, "policy-ca-intermediates": true,
	"policy-timestamp-servers": true, "policy-fulcio-oidc-issuer": true,
}

// Every other signer constraint names identity an approval leaf does not carry
// (the platform Fulcio stamps one email SAN and the issuer). The list is read
// from the command, so a --policy-* flag added later is covered too.
func TestVerifyEnvelope_OtherSignerConstraintsRefused(t *testing.T) {
	var refused []string
	VerifyCmd().Flags().VisitAll(func(f *pflag.Flag) {
		if (strings.HasPrefix(f.Name, "policy-") && !envelopeHonouredPolicyFlags[f.Name]) || f.Name == "publickey" {
			refused = append(refused, f.Name)
		}
	})
	sort.Strings(refused)
	for _, want := range []string{
		"policy-commonname", "policy-dns-names", "policy-emails", "policy-organizations", "policy-uris",
		"policy-fulcio-build-trigger", "policy-fulcio-source-repository-uri", "policy-fulcio-build-config-uri",
		"policy-fulcio-runner-environment", "publickey",
	} {
		require.Contains(t, refused, want, "the enumeration must reach every known signer flag")
	}

	for _, name := range refused {
		t.Run(name, func(t *testing.T) {
			base := bobApproval(t)
			_, err := runEnvelopeVerify(t, append(base, "--"+name+"=bob@example.com")...)
			require.Error(t, err, "--%s must be refused, not ignored", name)
			require.ErrorContains(t, err, "--"+name)
		})
	}
}
