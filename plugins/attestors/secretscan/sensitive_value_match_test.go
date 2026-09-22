// jade:ring local

// Copyright 2026 The Rookery Contributors
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

package secretscan

import (
	"encoding/base64"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// These tests pin which environment values become literal match rules. Found
// by the Pushgate onboarding acceptance run (2026-09-21): scanning cilock's own
// environment attestation reported the working directory as a leaked secret
// (witness-env-value-PWD) on a clean repository, --env-allow-sensitive-key PWD
// did not suppress it, and --env-capture-allowlist drove a clean scan to
// 10,296 findings because every value it did not capture, "http" included,
// became a rule.

// envValueRuleIDs scans content the way an attestation is scanned (depth 0,
// decoding on) and returns the sorted rule ids of the env-value findings.
func envValueRuleIDs(t *testing.T, a *Attestor, content string) []string {
	t.Helper()
	findings, err := a.scanBytes([]byte(content), "attestation_environment.json", "", createTestDetector(t), map[string]struct{}{}, 0)
	require.NoError(t, err)
	envFindings := envValueFindings(findings)
	ids := make([]string, 0, len(envFindings))
	for _, f := range envFindings {
		ids = append(ids, f.RuleID)
	}
	sort.Strings(ids)
	return ids
}

func contextWith(t *testing.T, opts ...attestation.AttestationContextOption) *attestation.AttestationContext {
	t.Helper()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{}, opts...)
	require.NoError(t, err)
	return ctx
}

// TestLocationAndIdentityVariablesAreNeverValueMatched: the obfuscation globs
// are broad on purpose (*PWD* is there for PASSWORD spellings, *PAT* for
// GITHUB_PAT, *AUTH* for bearer credentials), and over-matching is harmless
// when the action is to hide a value. It is not harmless when the action is to
// report every occurrence of the value as a leak: the working directory, the
// search path and the commit author are in every attestation by design.
// Even an operator who marks every key sensitive does not make them secrets.
func TestLocationAndIdentityVariablesAreNeverValueMatched(t *testing.T) {
	nonSecret := map[string]string{
		"PWD":              "/work/e2-probe/working-directory",
		"OLDPWD":           "/work/e2-probe/previous-directory",
		"HOME":             "/work/e2-probe/home-directory",
		"TMPDIR":           "/work/e2-probe/temporary-directory",
		"SHELL":            "/work/e2-probe/bin/probe-shell",
		"USER":             "e2-probe-user-name",
		"LOGNAME":          "e2-probe-login-name",
		"GOPATH":           "/work/e2-probe/go-module-path",
		"SSH_AUTH_SOCK":    "/work/e2-probe/agent.socket",
		"GIT_AUTHOR_NAME":  "E2 Probe Author Name",
		"GIT_AUTHOR_EMAIL": "e2-probe-author@example.invalid",
	}
	var content strings.Builder
	for k, v := range nonSecret {
		t.Setenv(k, v)
		content.WriteString(k + "-copy: " + v + "\n")
		content.WriteString(k + "-encoded: " + base64.StdEncoding.EncodeToString([]byte(v)) + "\n")
	}
	// PATH is read, not replaced: other code in this process resolves binaries with it.
	content.WriteString("path-copy: " + os.Getenv("PATH") + "\n")

	const control = "e2-control-secret-value-0099"
	t.Setenv("E2_PROBE_TOKEN", control)
	content.WriteString("control: " + control + "\n")
	// The exemption names PWD, not the *PWD* glob: a DB_PWD is still a password.
	const dbPwd = "db-pwd-secret-value-0007"
	t.Setenv("DB_PWD", dbPwd)
	content.WriteString("db: " + dbPwd + "\n")

	require.Equal(t, []string{"witness-env-value-DB-PWD", "witness-env-value-E2-PROBE-TOKEN"}, envValueRuleIDs(t, New(), content.String()),
		"only the control secrets may be reported; a location or identity value is not a secret")

	// With every key marked sensitive, whatever else this process's environment
	// holds may legitimately match (a GOROOT inside PATH); the listed keys may not.
	a := New()
	a.ctx = contextWith(t, attestation.WithEnvAdditionalKeys([]string{"*"}))
	ids := envValueRuleIDs(t, a, content.String())
	require.Contains(t, ids, "witness-env-value-E2-PROBE-TOKEN")
	for _, id := range ids {
		for k := range nonSecret {
			rule := strings.ReplaceAll(k, "_", "-")
			require.NotContains(t, []string{"witness-env-value-" + rule, "witness-encoded-env-value-" + rule, "witness-encoded-env-value-" + rule + "-partial"}, id)
		}
		require.NotEqual(t, "witness-env-value-PATH", id)
	}
}

// TestAllowSensitiveKeyIsHonouredByValueMatching: --env-allow-sensitive-key
// tells the environment attestor to record a key in the clear because its value
// is not a secret. The scan must agree, or the operator's one lever for a
// false positive does nothing.
func TestAllowSensitiveKeyIsHonouredByValueMatching(t *testing.T) {
	t.Setenv("E2_ALLOWED_TOKEN", "allowed-token-value-0001")
	t.Setenv("E2_OTHER_TOKEN", "other-token-value-0002")
	content := "a=allowed-token-value-0001 b=other-token-value-0002"

	a := New()
	require.Equal(t, []string{"witness-env-value-E2-ALLOWED-TOKEN", "witness-env-value-E2-OTHER-TOKEN"}, envValueRuleIDs(t, a, content),
		"without the allow flag both *TOKEN* values are secrets")

	a = New()
	a.ctx = contextWith(t, attestation.WithEnvExcludeKeys([]string{"E2_ALLOWED_TOKEN"}))
	require.Equal(t, []string{"witness-env-value-E2-OTHER-TOKEN"}, envValueRuleIDs(t, a, content),
		"the allowed key is not a secret; the other one still is")
}

// TestAddSensitiveKeyIsHonouredByValueMatching: the converse. A key the
// operator adds is a secret even when no default pattern names it, in the
// default obfuscation mode as well as in filter mode.
func TestAddSensitiveKeyIsHonouredByValueMatching(t *testing.T) {
	t.Setenv("E2_CUSTOM_CRYPTIC", "custom-cryptic-value-0003")
	content := "c=custom-cryptic-value-0003"

	require.Empty(t, envValueRuleIDs(t, New(), content), "no default pattern names this key")

	a := New()
	a.ctx = contextWith(t, attestation.WithEnvAdditionalKeys([]string{"E2_CUSTOM_*"}))
	require.Equal(t, []string{"witness-env-value-E2-CUSTOM-CRYPTIC"}, envValueRuleIDs(t, a, content))
}

// keepOnly is an environment capturer in capture-allowlist mode: it records
// only the named keys and drops the rest, as the environment attestor does
// under --env-capture-allowlist.
type keepOnly map[string]struct{}

func (k keepOnly) Capture(env []string) map[string]string {
	out := map[string]string{}
	for _, kv := range env {
		key, val, _ := strings.Cut(kv, "=")
		if _, ok := k[key]; ok {
			out[key] = val
		}
	}
	return out
}

// TestCaptureAllowlistDoesNotMakeUncapturedVariablesSensitive: a key the
// capture allowlist leaves out was left out of the RECORD, not classified as a
// secret. Inferring "sensitive" from "not captured" turned every ordinary
// variable into a literal match rule.
func TestCaptureAllowlistDoesNotMakeUncapturedVariablesSensitive(t *testing.T) {
	t.Setenv("E4_PLAIN_SETTING", "plain-setting-value-0001")
	t.Setenv("E4_REAL_TOKEN", "real-token-value-0002")
	content := "p=plain-setting-value-0001 t=real-token-value-0002"

	a := New()
	a.ctx = contextWith(t, attestation.WithEnvCaptureAllowlist([]string{"HOME"}))
	a.ctx.SetEnvironmentCapturer(keepOnly{"HOME": {}})
	require.Equal(t, []string{"witness-env-value-E4-REAL-TOKEN"}, envValueRuleIDs(t, a, content),
		"only the value of a key classified sensitive is a rule")
}

// TestShortSensitiveValuesAreNotValueMatched: a literal match of a short value
// is not evidence of a leak. CLOUDSDK_PROXY_TYPE=http under a *PROXY* key, or a
// "true"/"linux" CI flag on the explicit list, matches every URL and every
// boolean in the scanned bytes. The floor is the one the partial-match rule
// already applies to a leaked fragment.
func TestShortSensitiveValuesAreNotValueMatched(t *testing.T) {
	content := "proxy: http://example.invalid enabled: true os: linux pin: 1234567 pin8: 12345678"
	decoded := base64.StdEncoding.EncodeToString([]byte("decoded: http linux 1234567 12345678"))
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"http", false},
		{"true", false},
		{"linux", false},
		{"1234567", false},
		{"12345678", true},
	} {
		t.Setenv("E4_PROBE_TOKEN", tc.value)
		ids := envValueRuleIDs(t, New(), content+"\n"+decoded)
		require.Equal(t, tc.want, len(ids) > 0, "value %q (%d chars): got %v", tc.value, len(tc.value), ids)
		if tc.want {
			require.Contains(t, ids, "witness-env-value-E4-PROBE-TOKEN")
			require.Contains(t, ids, "witness-encoded-env-value-E4-PROBE-TOKEN", "the decoded path applies the same floor")
		}
	}
}
