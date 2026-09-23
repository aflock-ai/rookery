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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/canonicaljson"
	"github.com/aflock-ai/rookery/cilock/internal/embeddedtrust"
)

// Every test here starts from sandboxVerifyEnv: a fresh credential store, so
// no developer's `cilock login` session is read or re-pinned.

const approvalTestConnection = "0b7e9a52-3c1d-4f7e-9d41-6a2f0c8e1b35"

// historyVerifyCommand is the Go twin of verifyCommand in
// jade/factory/edge/git/approvalsign.js (origin/main :174-175, a5-chip
// :176-177; the text is the same on both):
//
//	const q = (v) => `'${String(v).replace(/'/g, `'\\''`)}'`;
//	return `cilock verify --envelope ${q(filename)} --platform-url ${q(platformBase(env))}`;
//
// Its JS half is approvalsign.test.mjs "the verify command quotes its
// arguments and names the platform, not a verdict". Change both or neither.
func historyVerifyCommand(filename, platformBase string) string {
	q := func(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }
	return "cilock verify --envelope " + q(filename) + " --platform-url " + q(platformBase)
}

// approvalTestStatement builds what the edge's approvalStatement builds, in
// the platform's canonical form, and returns it with the sealed digest. edit
// runs after the digest is taken.
func approvalTestStatement(t *testing.T, email string, edit func(st map[string]any)) ([]byte, string) {
	t.Helper()
	sealed := map[string]any{
		"version": "pushgate.policy-assignment-approval.v4", "connection_id": approvalTestConnection,
		"repository_id": "42", "connection_created_at": "2026-09-01T00:00:00Z", "generation": 3,
		"before": []any{}, "after": []any{}, "reason": "tighten the gate",
		"before_presets": []any{"signed"}, "after_presets": []any{"signed", "vulns"},
		"before_modes": map[string]any{"signed": "block"}, "after_modes": map[string]any{"signed": "block", "vulns": "warn"},
	}
	raw, err := json.Marshal(sealed)
	require.NoError(t, err)
	digest, err := canonicaljson.Digest(raw)
	require.NoError(t, err)
	st := map[string]any{
		"_type":         "https://in-toto.io/Statement/v1",
		"subject":       []any{map[string]any{"name": approvalTestConnection, "digest": map[string]any{"sha256": digest}}},
		"predicateType": "https://pushgate.dev/attestations/policy-assignment-approval/v1",
		"predicate": map[string]any{
			"sealed":   sealed,
			"approver": map[string]any{"user_id": "u-1", "email": email, "name": "Approver"},
			"reason":   "tighten the gate", "gate": "pushgate",
		},
	}
	if edit != nil {
		edit(st)
	}
	return approvalTestCanonical(t, st), digest
}

func approvalTestCanonical(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	out, err := canonicaljson.Canonical(raw)
	require.NoError(t, err)
	return out
}

func embedApprovalAnchors(t *testing.T, f *approvalEnvelopeFixture) {
	t.Helper()
	fulcio, tsa := string(certPEM(t, f.FulcioRoot)), string(certPEM(t, f.TSARoot))
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) {
		return &embeddedtrust.Trust{
			Roots: []embeddedtrust.Root{
				{Name: "fulcio", Kind: embeddedtrust.KindFulcioRoot, PEM: fulcio},
				{Name: "tsa", Kind: embeddedtrust.KindTSARoot, PEM: tsa},
			},
			PolicySigners: []policy.Functionary{releaseSigner()},
		}, nil
	})
}

func runEnvelopeVerify(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := VerifyCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return out.String(), err
}

// offlineApproval signs payload, lets rewrite (if any) change the stored
// envelope, and verifies it with only the two trust files.
func offlineApproval(t *testing.T, payload []byte, rewrite func(*dsse.Envelope), opts ...approvalEnvelopeOption) (string, error) {
	t.Helper()
	sandboxVerifyEnv(t)
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) { return nil, nil })
	f := newApprovalEnvelopeFixture(t, payload, opts...)
	envPath, ca, tsa := f.files(t, t.TempDir())
	if rewrite != nil {
		env := storedApprovalEnvelope(t, f)
		rewrite(&env)
		raw, err := json.Marshal(env)
		require.NoError(t, err)
		require.NotEqual(t, f.JSON, raw, "the rewrite must change the stored bytes")
		require.NoError(t, os.WriteFile(envPath, raw, 0o600))
	}
	return runEnvelopeVerify(t, "--envelope", envPath, "--policy-ca-roots", ca, "--policy-timestamp-servers", tsa, "--platform-url", "")
}

func TestVerifyEnvelope_HistoryCommandVerifiesAnApproval(t *testing.T) {
	sandboxVerifyEnv(t)
	payload, digest := approvalTestStatement(t, "approver@example.com", nil)
	f := newApprovalEnvelopeFixture(t, payload)
	embedApprovalAnchors(t, f)
	platform := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("verify --envelope without a session contacted the platform: %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusTeapot)
	}))
	defer platform.Close()
	file := filepath.Join(t.TempDir(), "0b7e9a52.approval.json")
	require.NoError(t, os.WriteFile(file, f.JSON, 0o600))

	require.Equal(t, `cilock verify --envelope 'ev'\''il.approval.json' --platform-url 'https://platform.example.test'`,
		historyVerifyCommand("ev'il.approval.json", "https://platform.example.test"), "the text the JS half pins")
	// Neither argument holds a quote or a space, so dropping the quotes and
	// splitting on spaces is exactly what a shell does with this line.
	words := strings.Fields(strings.ReplaceAll(historyVerifyCommand(file, platform.URL), "'", ""))
	require.Equal(t, []string{"cilock", "verify"}, words[:2])
	out, err := runEnvelopeVerify(t, words[2:]...)
	require.NoError(t, err)
	assert.Contains(t, out, "approver@example.com")
	assert.Contains(t, out, "sha256:"+digest)
	assert.Contains(t, out, "assurance: not recorded")
	assert.Contains(t, out, approvalTestConnection)
	assert.Contains(t, out, "signature check only")
}

func TestVerifyEnvelope_OfflineWithExplicitTrustFiles(t *testing.T) {
	sandboxVerifyEnv(t)
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) { return nil, nil })
	payload, digest := approvalTestStatement(t, "approver@example.com", nil)
	envPath, ca, tsa := newApprovalEnvelopeFixture(t, payload).files(t, t.TempDir())

	out, err := runEnvelopeVerify(t, "--envelope", envPath, "--policy-ca-roots", ca, "--policy-timestamp-servers", tsa, "--platform-url", "", "--format", "json")
	require.NoError(t, err)
	var verdict map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &verdict), "--format json prints only JSON: %s", out)
	assert.Equal(t, true, verdict["passed"])
	assert.Equal(t, "approver@example.com", verdict["signer"])
	assert.Equal(t, "sha256:"+digest, verdict["subjectDigest"])
	assert.Equal(t, []any{"signed", "vulns"}, verdict["afterPresets"])

	_, err = runEnvelopeVerify(t, "--envelope", envPath, "--policy-ca-roots", ca, "--platform-url", "")
	require.ErrorContains(t, err, "--policy-timestamp-servers", "no timestamp authority: refuse and name the flag, never fall back to the clock")
	_, err = runEnvelopeVerify(t, "--envelope", envPath, "--policy-timestamp-servers", tsa, "--platform-url", "")
	require.ErrorContains(t, err, "--policy-ca-roots")
}

func TestVerifyEnvelope_TamperedPayloadFails(t *testing.T) {
	payload, _ := approvalTestStatement(t, "approver@example.com", nil)
	_, err := offlineApproval(t, payload, func(env *dsse.Envelope) {
		var st map[string]any
		require.NoError(t, json.Unmarshal(env.Payload, &st))
		pred := st["predicate"].(map[string]any)
		reason := pred["reason"].(string)
		pred["reason"] = string(reason[0]^0x01) + reason[1:]
		env.Payload = approvalTestCanonical(t, st)
		require.NotEqual(t, payload, env.Payload)
	})
	require.ErrorContains(t, err, "does not chain to the trusted roots")
	assert.NotContains(t, err.Error(), "tampered", "a root rotation fails the same way; never guess the cause")
}

func TestVerifyEnvelope_SubjectDigestMustMatchSealed(t *testing.T) {
	payload, _ := approvalTestStatement(t, "approver@example.com", func(st map[string]any) {
		sealed := st["predicate"].(map[string]any)["sealed"].(map[string]any)
		sealed["after_presets"] = []any{"signed"}
	})
	_, err := offlineApproval(t, payload, nil)
	require.ErrorContains(t, err, "is not the digest of predicate.sealed")
}

func TestVerifyEnvelope_NoTimestampFails(t *testing.T) {
	payload, _ := approvalTestStatement(t, "approver@example.com", nil)
	_, err := offlineApproval(t, payload, func(env *dsse.Envelope) {
		require.NotEmpty(t, env.Signatures[0].Timestamps)
		env.Signatures[0].Timestamps = nil
	})
	require.ErrorContains(t, err, "does not chain to the trusted roots under a trusted timestamp",
		"a leaf still inside its validity must not verify on the wall clock")
}

func TestVerifyEnvelope_RefusesAgentSPIFFELeaf(t *testing.T) {
	const spiffe = "spiffe://td/tenant/t/agent/a"
	payload, _ := approvalTestStatement(t, "approver@example.com", nil)
	for name, tc := range map[string]struct {
		opts []approvalEnvelopeOption
		want string
	}{
		"agent leaf":       {[]approvalEnvelopeOption{withLeafEmails(), withLeafURIs(spiffe)}, "signed by an agent principal, not a human"},
		"email plus URI":   {[]approvalEnvelopeOption{withLeafURIs(spiffe)}, "signed by an agent principal, not a human"},
		"two email SANs":   {[]approvalEnvelopeOption{withLeafEmails("approver@example.com", "other@example.com")}, "exactly one email address"},
		"no SAN at all":    {[]approvalEnvelopeOption{withLeafEmails()}, "exactly one email address"},
		"the human signer": {nil, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := offlineApproval(t, payload, nil, tc.opts...)
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestVerifyEnvelope_ApproverEmailMustMatchSAN(t *testing.T) {
	for email, ok := range map[string]bool{
		"approver@example.com":     true,
		"APPROVER@Example.COM":     true,
		"someone-else@example.com": false,
		"":                         false,
	} {
		t.Run(email, func(t *testing.T) {
			payload, _ := approvalTestStatement(t, email, nil)
			out, err := offlineApproval(t, payload, nil)
			if ok {
				require.NoError(t, err)
				assert.Contains(t, out, "approver@example.com", "the SAN is what is printed, never the predicate's spelling")
				return
			}
			require.ErrorContains(t, err, "does not name the signer")
		})
	}
}

func TestVerifyEnvelope_IssuerPinnedWhenKnown(t *testing.T) {
	payload, _ := approvalTestStatement(t, "approver@example.com", nil)
	const agentIssuer = "https://platform.example.test/oidc/agents"

	t.Run("flag", func(t *testing.T) {
		sandboxVerifyEnv(t)
		swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) { return nil, nil })
		envPath, ca, tsa := newApprovalEnvelopeFixture(t, payload).files(t, t.TempDir())
		base := []string{"--envelope", envPath, "--policy-ca-roots", ca, "--policy-timestamp-servers", tsa, "--platform-url", ""}
		_, err := runEnvelopeVerify(t, append(base, "--policy-fulcio-oidc-issuer", agentIssuer)...)
		require.ErrorContains(t, err, agentIssuer)
		_, err = runEnvelopeVerify(t, append(base, "--policy-fulcio-oidc-issuer", approvalEnvelopeTestIssuer)...)
		require.NoError(t, err)
		_, err = runEnvelopeVerify(t, base...)
		require.NoError(t, err, "the flag's GitHub Actions default is never applied to an approval")
	})

	// A logged-in reader: the issuer the platform's discovery advertises is
	// enforced, and the session's own email (someone else's) is not applied.
	t.Run("discovered", func(t *testing.T) {
		require.NoError(t, os.Chmod(sandboxVerifyEnv(t), 0o700))
		f := newApprovalEnvelopeFixture(t, payload)
		embedApprovalAnchors(t, f)
		envPath, _, _ := f.files(t, t.TempDir())
		var advertised atomic.Value
		advertised.Store(approvalEnvelopeTestIssuer)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/judge-configuration" {
				t.Errorf("verify --envelope reached %s", r.URL.Path)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"signing": map[string]any{"fulcio_oidc_issuer": advertised.Load()}})
		}))
		defer srv.Close()
		require.NoError(t, auth.Save(auth.Credential{
			PlatformURL: srv.URL, Token: "reader-session", Email: "reader@example.com",
			AuthMode: auth.AuthModeBrowser, ExpiresAt: time.Now().Add(time.Hour),
		}))

		out, err := runEnvelopeVerify(t, "--envelope", envPath, "--platform-url", srv.URL)
		require.NoError(t, err, "the session's default --policy-emails (the reader) is neither applied nor refused")
		assert.Contains(t, out, "approver@example.com")
		advertised.Store(agentIssuer)
		_, err = runEnvelopeVerify(t, "--envelope", envPath, "--platform-url", srv.URL)
		require.ErrorContains(t, err, agentIssuer)
	})
}
