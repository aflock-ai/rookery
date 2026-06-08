// Copyright 2025 The Witness Contributors
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

package environment

import "testing"

// TestDefaultListObfuscatesGitHubPAT is the regression guard for the public
// GITHUB_PAT leak: a real GITHUB_PAT was captured in full in published cilock
// release attestations because the default sensitive list had *TOKEN*/*SECRET*/
// *KEY* globs but NOTHING matching "PAT". This exercises the exact attestor path
// (NewCapturer().Capture, which seeds attestation.DefaultSensitiveEnvList) and
// fails closed if the list is ever trimmed back below the leaked key.
func TestDefaultListObfuscatesGitHubPAT(t *testing.T) {
	const placeholder = "******"

	// Keys that MUST be obfuscated by the default list. Each pairs a realistic
	// secret-bearing key with why it has to be covered. A miss here is a public
	// credential leak, so the bar is "obfuscated", never "present in cleartext".
	mustObfuscate := []string{
		"GITHUB_PAT",          // the exact key that leaked (explicit + *PAT* glob)
		"GH_PAT",              // sibling personal-access-token env (explicit + glob)
		"BUILDKITE_AGENT_PAT", // arbitrary vendor *_PAT — caught by the *PAT* glob
		"MY_CREDENTIAL",       // *CREDENTIAL*
		"DB_CRED",             // *CRED*
		"REGISTRY_AUTH",       // *AUTH*
		"GCP_PRIVATE_KEY",     // *PRIVATE* / *KEY*
		"CODE_SIGNING_CERT",   // *SIGNING*
		"AWS_SESSION_TOKEN",   // *SESSION_TOKEN* / *TOKEN*
		"SLACK_WEBHOOK",       // *WEBHOOK*
		"SENTRY_DSN",          // *DSN*
		"DATABASE_URL",        // *DATABASE_URL*
		"OAUTH_BEARER",        // *OAUTH* / *BEARER*
	}

	for _, key := range mustObfuscate {
		t.Run(key, func(t *testing.T) {
			c := NewCapturer()
			got := c.Capture([]string{key + "=super-secret-value-do-not-leak"})
			if got[key] != placeholder {
				t.Fatalf("key %q leaked: Capture returned %q, want %q — the default sensitive list no longer covers it",
					key, got[key], placeholder)
			}
		})
	}

	// Sanity: a genuinely non-sensitive var must still pass through untouched,
	// so we're proving real obfuscation, not a list that masks everything.
	t.Run("non-sensitive passes through", func(t *testing.T) {
		c := NewCapturer()
		got := c.Capture([]string{"HOME=/home/runner", "CI=true"})
		if got["HOME"] != "/home/runner" {
			t.Errorf("HOME was obfuscated to %q; non-sensitive vars must pass through", got["HOME"])
		}
		if got["CI"] != "true" {
			t.Errorf("CI was obfuscated to %q; non-sensitive vars must pass through", got["CI"])
		}
	})
}
