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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// #9311: the short flags disagreed across commands. `-o` was --outfile on run
// and sign but --format on verify and --output (a format) on policy validate,
// so `cilock verify -o out.json` silently picked an unknown format and
// `cilock run -o json` wrote a file named "json". sign rejected --offline
// while run and verify accepted it. policy validate warned on every unsigned
// policy although validate-then-sign is the documented flow.
//
// The contract pinned here: -o, wherever it is live, is an output path; the
// two format spellings keep working as deprecated aliases that print one
// notice line; --format is the spelled-out format flag on both; sign takes
// --offline; validate warns about a missing signature only when one was
// expected (--require-signed, or a DSSE envelope with no signatures).

// parseFlagsCapturingNotices parses args on a fresh command and returns the
// deprecation notices pflag wrote. cobra prints these to stderr after a
// successful run; the flag set's own output is where they originate.
func parseFlagsCapturingNotices(t *testing.T, cmd *cobra.Command, args ...string) string {
	t.Helper()
	var notices bytes.Buffer
	cmd.Flags().SetOutput(&notices)
	require.NoError(t, cmd.ParseFlags(args))
	return notices.String()
}

func TestVerifyShortOIsADeprecatedAliasForFormat(t *testing.T) {
	cmd := VerifyCmd()
	notices := parseFlagsCapturingNotices(t, cmd, "-o", "json")
	require.Equal(t, "json", cmd.Flags().Lookup("format").Value.String(), "-o json must still select the JSON verdict")
	require.Contains(t, notices, "-o has been deprecated")
	require.Contains(t, notices, "--format")
	require.Equal(t, 1, strings.Count(strings.TrimRight(notices, "\n"), "\n")+1, "the notice is one line")

	cmd = VerifyCmd()
	notices = parseFlagsCapturingNotices(t, cmd, "--format", "json")
	require.Equal(t, "json", cmd.Flags().Lookup("format").Value.String())
	require.Empty(t, notices, "the spelled-out flag must not print a notice")
}

func TestVerifyHelpSpellsOutFormat(t *testing.T) {
	stdout, _, err := executeCmdOutput("verify", "--help")
	require.NoError(t, err)
	require.Contains(t, stdout, "--format", "verify --help must list --format in the concise flag set")
	require.NotContains(t, stdout, "-o, --format", "the deprecated -o shorthand must not be advertised")
	require.NotContains(t, stdout, " -o json", "the example must use the spelled-out flag")
	require.Contains(t, stdout, "--format json")
}

func TestVerifyRejectsUnknownFormatBeforeVerifying(t *testing.T) {
	// `-o out.json` was the issue's repro: a path passed where a format is
	// read. It must fail with a message that names the file flag, not fall
	// through to the text verdict.
	err := executeCmd("verify", "--format", "out.json", "-p", "policy.json")
	require.Error(t, err)
	require.Contains(t, err.Error(), `unknown --format "out.json"`)
	require.Contains(t, err.Error(), "--vsa-outfile", "the message must point at the flag that writes a file")
}

func TestPolicyValidateFormatFlagAndDeprecatedAliases(t *testing.T) {
	cmd := PolicyValidateCmd()
	notices := parseFlagsCapturingNotices(t, cmd, "--format", "json")
	require.Equal(t, "json", cmd.Flags().Lookup("format").Value.String())
	require.Empty(t, notices)

	for _, alias := range [][]string{{"-o", "json"}, {"--output", "json"}} {
		cmd = PolicyValidateCmd()
		notices = parseFlagsCapturingNotices(t, cmd, alias...)
		require.Equal(t, "json", cmd.Flags().Lookup("format").Value.String(), "%v must still select JSON output", alias)
		require.Contains(t, notices, "has been deprecated", "%v must print a deprecation notice", alias)
		require.Contains(t, notices, "--format", "%v notice must name the replacement", alias)
	}

	stdout, _, err := executeCmdOutput("policy", "validate", "--help")
	require.NoError(t, err)
	require.Contains(t, stdout, "--format")
	require.NotContains(t, stdout, "--output", "the deprecated spelling must not be advertised")
	require.Contains(t, stdout, "--require-signed")
	require.NotContains(t, stdout, " -o json", "the example must use the spelled-out flag")
}

// validRawPolicy is a structurally valid, unsigned policy: what an operator
// has in hand in the documented validate-then-sign flow.
const validRawPolicy = `{
  "expires": "2099-01-01T00:00:00Z",
  "roots": { "rootA": { "certificate": "Zm9v" } },
  "steps": {
    "build": {
      "name": "build",
      "functionaries": [
        { "type": "root", "certConstraint": { "roots": ["rootA"], "commonname": "*", "dnsnames": ["*"], "emails": ["dev@example.com"], "organizations": ["*"], "uris": ["spiffe://platform.example.test/tenant/t-1/*"] } }
      ],
      "attestations": [ { "type": "https://aflock.ai/attestations/product/v0.3" } ]
    }
  }
}`

func writePolicyEnvelope(t *testing.T, dir, name string, sigs int) string {
	t.Helper()
	env := dsse.Envelope{
		Payload:     []byte(validRawPolicy),
		PayloadType: "https://witness.testifysec.com/policy/v0.1",
	}
	for i := 0; i < sigs; i++ {
		env.Signatures = append(env.Signatures, dsse.Signature{KeyID: "k", Signature: []byte("sig")})
	}
	raw, err := json.Marshal(&env)
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func TestPolicyValidateWarnsAboutSignatureOnlyWhenOneWasExpected(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(raw, []byte(validRawPolicy), 0o600))

	stdout, _, err := executeCmdOutput("policy", "validate", "-p", raw)
	require.NoError(t, err)
	require.Contains(t, stdout, "PASSED")
	require.NotContains(t, stdout, "Warnings", "an unsigned raw policy is the normal validate-then-sign input; no warning: %s", stdout)
	require.NotContains(t, stdout, "DSSE")
	require.Contains(t, stdout, "signature: unsigned", "the signature status is still reported, as a fact rather than a warning")

	spelled, _, err := executeCmdOutput("policy", "validate", "-p", raw, "--format", "json")
	require.NoError(t, err)
	var structured struct {
		Valid     bool     `json:"valid"`
		Signature string   `json:"signature"`
		Warnings  []string `json:"warnings"`
	}
	require.NoError(t, json.Unmarshal([]byte(spelled), &structured))
	require.True(t, structured.Valid)
	require.Equal(t, "unsigned", structured.Signature, "a JSON consumer must be able to read the signature status without parsing warnings")
	require.Empty(t, structured.Warnings)

	unsigned := writePolicyEnvelope(t, dir, "unsigned.json", 0)
	stdout, _, err = executeCmdOutput("policy", "validate", "-p", unsigned)
	require.NoError(t, err)
	require.Contains(t, stdout, "not signed", "a DSSE envelope with no signatures declares a signature it does not carry: warn")

	err = executeCmd("policy", "validate", "-p", raw, "--require-signed")
	require.Error(t, err)
	require.Contains(t, err.Error(), "--require-signed")
	require.Contains(t, err.Error(), "cilock sign", "the refusal must name the command that produces a signed policy")

	err = executeCmd("policy", "validate", "-p", unsigned, "--require-signed")
	require.Error(t, err, "an envelope with zero signatures is not signed")

	signed := writePolicyEnvelope(t, dir, "signed.json", 1)
	require.NoError(t, executeCmd("policy", "validate", "-p", signed, "--require-signed"))
}

func TestSignAcceptsOfflineWithALocalKey(t *testing.T) {
	isolateAgentConfig(t)
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	in := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(in, []byte(validRawPolicy), 0o600))
	out := filepath.Join(dir, "policy.signed.json")

	require.NoError(t, executeCmd("sign", "--offline", "-k", keyPath, "-f", in, "-o", out))
	rawOut, err := os.ReadFile(out)
	require.NoError(t, err)
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(rawOut, &env))
	require.Len(t, env.Signatures, 1)
	require.Equal(t, validRawPolicy, string(env.Payload))
}

func TestSignOfflineWithoutALocalSignerSaysWhy(t *testing.T) {
	isolateAgentConfig(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(in, []byte(validRawPolicy), 0o600))

	err := executeCmd("sign", "--offline", "-f", in, "-o", filepath.Join(dir, "out.json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "--offline")
	require.Contains(t, err.Error(), "--signer-file-key-path", "the message must say which signer an offline sign needs")
	require.Contains(t, err.Error(), "keyless", "and why the platform path is not available offline")
}

// TestSignOfflineIgnoresAStoredSession: the point of --offline is that a
// stored `cilock login` session is not consulted. With a session present and
// no local signer, the command must refuse with the offline message before
// any exchange is attempted; the platform it would have talked to fails the
// test if it sees a request.
func TestSignOfflineIgnoresAStoredSession(t *testing.T) {
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("--offline sign reached the platform: %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	t.Cleanup(platform.Close)
	stubSession(t, platform.URL)

	dir := t.TempDir()
	in := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(in, []byte(validRawPolicy), 0o600))
	err := executeCmd("sign", "--offline", "--platform-url", platform.URL, "-f", in, "-o", filepath.Join(dir, "out.json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "--offline needs a local signer")
}

func TestSignHelpListsOffline(t *testing.T) {
	stdout, _, err := executeCmdOutput("sign", "--help")
	require.NoError(t, err)
	require.Contains(t, stdout, "--offline")
}

// TestShortOIsAnOutputPathWhereverItIsLive sweeps every command: a live -o
// shorthand (one that is not deprecated) must be bound to a string flag whose
// long name and usage describe a file to write. The two format aliases are
// deprecated and therefore skipped; a new command that binds -o to a format
// fails this sweep.
func TestShortOIsAnOutputPathWhereverItIsLive(t *testing.T) {
	pathWords := regexp.MustCompile(`(?i)\b(write|file|path|destination)\b`)
	seen := 0
	walkCommands(New(), func(cmd *cobra.Command) {
		f := cmd.LocalFlags().ShorthandLookup("o")
		if f == nil || f.Deprecated != "" || f.ShorthandDeprecated != "" {
			return
		}
		seen++
		require.Equal(t, "string", f.Value.Type(), "%s: -o must take a path", cmd.CommandPath())
		require.Contains(t, []string{"outfile", "output"}, f.Name, "%s: -o is --%s, not an output path", cmd.CommandPath(), f.Name)
		require.Regexp(t, pathWords, f.Usage, "%s: -o's usage must describe a file to write, got %q", cmd.CommandPath(), f.Usage)
	})
	require.GreaterOrEqual(t, seen, 6, "run, sign, bundle create, policy draft, from-bundles and from-commit all bind -o")
}

// TestDeprecatedFormatShorthandProducesTheSameJSON guards that the alias
// plumbing on policy validate did not disturb the JSON output path: `-o json`
// produces the same structured result as `--format json`.
func TestDeprecatedFormatShorthandProducesTheSameJSON(t *testing.T) {
	dir := t.TempDir()
	raw := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(raw, []byte(validRawPolicy), 0o600))
	spelled, _, err := executeCmdOutput("policy", "validate", "-p", raw, "--format", "json")
	require.NoError(t, err)
	aliased, _, err := executeCmdOutput("policy", "validate", "-p", raw, "-o", "json")
	require.NoError(t, err)
	// cobra prints the deprecation notice through OutOrStderr, which is the
	// captured stdout buffer under SetOut; the shipped binary never calls
	// SetOut, so there it lands on stderr and stdout stays pure JSON.
	notice, body, found := strings.Cut(aliased, "\n")
	require.True(t, found)
	require.Contains(t, notice, "has been deprecated")
	require.JSONEq(t, spelled, body, "exactly one notice line, then the same JSON")
	var result struct {
		Valid bool `json:"valid"`
	}
	require.NoError(t, json.Unmarshal([]byte(spelled), &result))
	require.True(t, result.Valid)
}
