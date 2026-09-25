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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sigstore/fulcio/pkg/certificate"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/policy"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/canonicaljson"
	"github.com/aflock-ai/rookery/cilock/internal/embeddedtrust"
)

// Lane 3b of docs/design/approval-page-verify-command.md. Every test starts
// from sandboxVerifyEnv.

// approvalReaderSession logs reader@example.com (tenant and product set) in to
// a loopback platform that serves only discovery, advertising its email OIDC
// issuer. It returns the URL and a count of every other request it received.
func approvalReaderSession(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	require.NoError(t, os.Chmod(os.Getenv("CILOCK_STATE_DIR"), 0o700))
	t.Setenv("CILOCK_PLATFORM_URL", "") // ResolvePlatformDefaults exports it; restore it after
	var strays atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/judge-configuration" {
			strays.Add(1)
			http.Error(w, "not served", http.StatusTeapot)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"signing": map[string]any{"fulcio_oidc_issuer": approvalEnvelopeTestIssuer}})
	}))
	t.Cleanup(srv.Close)
	require.NoError(t, auth.Save(auth.Credential{
		PlatformURL: srv.URL, Token: "reader-session", Email: "reader@example.com", TenantID: "tenant-1", ProductID: "prod-1",
		AuthMode: auth.AuthModeBrowser, ExpiresAt: time.Now().Add(time.Hour),
	}))
	return srv.URL, &strays
}

func TestVerifyEnvelope_RefusesPolicyModeFlags(t *testing.T) {
	sandboxVerifyEnv(t)
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) { return nil, nil })
	payload, _ := approvalTestStatement(t, "approver@example.com", nil)
	dir := t.TempDir()
	envPath, ca, tsa := newApprovalEnvelopeFixture(t, payload).files(t, dir)
	offline := []string{"--envelope", envPath, "--policy-ca-roots", ca, "--policy-timestamp-servers", tsa, "--platform-url", ""}

	// Spelled out, not read from the production list, so a flag added there is
	// a flag this test sets and sees accepted.
	honoured := map[string]bool{
		"envelope": true, "format": true, "platform-url": true, "offline": true, "trust-discovery": true,
		"no-embedded-trust": true, "policy-ca-roots": true, "policy-ca": true, "policy-ca-intermediates": true,
		"policy-timestamp-servers": true, "policy-fulcio-oidc-issuer": true,
	}
	_, err := runEnvelopeVerify(t, "--envelope", envPath, "--policy-ca", ca, "--policy-ca-intermediates", ca,
		"--policy-timestamp-servers", tsa, "--offline", "--no-embedded-trust", "--trust-discovery", "--format", "text")
	require.NoError(t, err, "every honoured flag at once")

	// Every other verify flag, including one added later, is refused by name.
	var refused []string
	VerifyCmd().LocalFlags().VisitAll(func(f *pflag.Flag) {
		if honoured[f.Name] || f.Name == "help" {
			return
		}
		refused = append(refused, f.Name)
		value, ok := map[string]string{"bool": "true", "int": "1", "uint": "1", "duration": "1s"}[f.Value.Type()]
		if !ok {
			value = "x"
		}
		t.Run(f.Name, func(t *testing.T) {
			_, err := runEnvelopeVerify(t, append(offline, "--"+f.Name+"="+value)...)
			require.ErrorContains(t, err, "--"+f.Name)
			require.ErrorContains(t, err, "takes no policy-verification input")
		})
	})
	// §3's list, so the enumeration above is visibly a superset of it.
	for _, name := range []string{"policy", "publickey", "attestations", "bundle", "artifactfile", "directory-path",
		"subjects", "client", "commit", "vsa-outfile", "vsa-timestamp-servers", "output-bundle", "enable-archivista",
		"enable-archivist", "policy-commonname", "policy-dns-names", "policy-emails", "policy-organizations",
		"policy-uris", "policy-fulcio-build-config-uri", "signer-file-key-path", "verifier-kms-ref"} {
		assert.Contains(t, refused, name)
	}

	t.Run("a shorthand and the positional artifact", func(t *testing.T) {
		_, err := runEnvelopeVerify(t, append(offline, "-p", "policy.json")...)
		require.ErrorContains(t, err, "-p/--policy")
		_, err = runEnvelopeVerify(t, append(offline, dir)...)
		require.ErrorContains(t, err, "a positional artifact")
	})

	// The fail-closed answer to the design's open question 2: an explicit
	// --policy-emails is refused, never silently ignored, and says why.
	t.Run("an explicit --policy-emails says why", func(t *testing.T) {
		_, err := runEnvelopeVerify(t, append(offline, "--policy-emails", "approver@example.com")...)
		require.ErrorContains(t, err, "--policy-emails does not pin an approver here")
	})

	// A session turns Archivista on and defaults --policy-emails to the
	// reader. Neither is the operator's flag, so neither is refused.
	t.Run("a session's defaults are not flags", func(t *testing.T) {
		sandboxVerifyEnv(t)
		platformURL, strays := approvalReaderSession(t)
		f := newApprovalEnvelopeFixture(t, payload)
		embedApprovalAnchors(t, f)
		sessionEnv, _, _ := f.files(t, t.TempDir())
		_, err := runEnvelopeVerify(t, "--envelope", sessionEnv, "--platform-url", platformURL)
		require.NoError(t, err)
		_, err = runEnvelopeVerify(t, "--envelope", sessionEnv, "--platform-url", platformURL, "--enable-archivista")
		require.ErrorContains(t, err, "--enable-archivista")
		assert.Zero(t, strays.Load(), "envelope mode contacted the platform beyond discovery")
	})

	// Only verify's own flags are refused; -l is the root command's.
	t.Run("an inherited root flag", func(t *testing.T) {
		_, _, err := executeCmdOutput(append([]string{"verify", "-l", "info"}, offline...)...)
		require.NoError(t, err)
	})
}

// approvalRecordingACR is an approval whose predicate records acr, on the
// sealed version that licenses it (v5); acr nil leaves the field out.
func approvalRecordingACR(t *testing.T, version string, acr *string) []byte {
	t.Helper()
	payload, _ := approvalTestStatement(t, "approver@example.com", func(st map[string]any) {
		pred := st["predicate"].(map[string]any)
		sealed := pred["sealed"].(map[string]any)
		sealed["version"] = version
		raw, err := json.Marshal(sealed)
		require.NoError(t, err)
		digest, err := canonicaljson.Digest(raw)
		require.NoError(t, err)
		st["subject"].([]any)[0].(map[string]any)["digest"] = map[string]any{"sha256": digest}
		if acr != nil {
			pred["approver"].(map[string]any)["acr"] = *acr
		}
	})
	return payload
}

func TestVerifyEnvelope_AssuranceReportedAndBound(t *testing.T) {
	const (
		v4, v5 = "pushgate.policy-assignment-approval.v4", "pushgate.policy-assignment-approval.v5"
		urnAAL = "urn:testifysec:params:acr:nist-800-63b:"
	)
	str := func(s string) *string { return &s }
	for name, tc := range map[string]struct {
		leaf     string // the leaf's assurance extension; "" omits it
		version  string
		recorded *string // predicate.approver.acr
		want     string  // the assurance line, or the refusal
		refused  bool
	}{
		"the URN the platform mints":       {leaf: urnAAL + "aal2", version: v4, want: "assurance: aal2\n"},
		"the legacy bare form":             {leaf: "aal2", version: v4, want: "assurance: aal2\n"},
		"no extension is not a level":      {version: v4, want: "assurance: not recorded\n"},
		"a level this build does not know": {leaf: "high", version: v4, want: "assurance: unrecognised \"high\"\n"},
		"v5 records the leaf's level":      {leaf: urnAAL + "aal2", version: v5, recorded: str("aal2"), want: "assurance: aal2\n"},
		"v5 recording nothing":             {leaf: urnAAL + "aal1", version: v5, want: "assurance: aal1\n"},
		"v5 records more than the leaf":    {leaf: urnAAL + "aal1", version: v5, recorded: str("aal2"), refused: true},
		"v5 over a leaf recording none":    {version: v5, recorded: str("aal2"), refused: true},
		"equal strings but no known level": {leaf: "high", version: v5, recorded: str("high"), refused: true},
		"an empty level over no extension": {version: v5, recorded: str(""), refused: true},
		"a pre-v5 predicate recording acr": {leaf: urnAAL + "aal2", version: v4, recorded: str("aal3"), refused: true},
		"v5 records the URN not the level": {leaf: urnAAL + "aal2", version: v5, recorded: str(urnAAL + "aal2"), refused: true},
	} {
		t.Run(name, func(t *testing.T) {
			var opts []approvalEnvelopeOption
			if tc.leaf != "" {
				opts = append(opts, withLeafAssurance(tc.leaf))
			}
			out, err := offlineApproval(t, approvalRecordingACR(t, tc.version, tc.recorded), nil, opts...)
			if tc.refused {
				require.ErrorContains(t, err, "predicate.approver.acr records")
				return
			}
			require.NoError(t, err)
			assert.Contains(t, out, tc.want)
		})
	}
}

func TestVerifyEnvelope_NotAnApproval(t *testing.T) {
	for name, tc := range map[string]struct {
		edit    func(st map[string]any)
		rewrite func(env *dsse.Envelope)
		opts    []approvalEnvelopeOption
		want    string
	}{
		"another predicate type": {edit: func(st map[string]any) { st["predicateType"] = "https://slsa.dev/provenance/v1" },
			want: "not a Pushgate policy-assignment approval"},
		"another statement type": {edit: func(st map[string]any) { st["_type"] = "https://in-toto.io/Statement/v0.1" },
			want: "not a Pushgate policy-assignment approval"},
		"two subjects": {edit: func(st map[string]any) {
			subject := st["subject"].([]any)[0]
			st["subject"] = []any{subject, subject}
		}, want: "exactly one subject"},
		"two signatures": {rewrite: func(env *dsse.Envelope) { env.Signatures = append(env.Signatures, env.Signatures[0]) },
			want: "carries 2 signatures"},
		"no signature":         {rewrite: func(env *dsse.Envelope) { env.Signatures = nil }, want: "carries 0 signatures"},
		"another payload type": {opts: []approvalEnvelopeOption{withPayloadType("application/json")}, want: "payloadType"},
	} {
		t.Run(name, func(t *testing.T) {
			payload, _ := approvalTestStatement(t, "approver@example.com", tc.edit)
			_, err := offlineApproval(t, payload, tc.rewrite, tc.opts...)
			require.ErrorContains(t, err, tc.want)
		})
	}

	// Either side of the cap: a valid approval padded with trailing whitespace
	// to exactly 1 MiB verifies, and one byte more is refused unparsed.
	t.Run("the 1 MiB cap", func(t *testing.T) {
		sandboxVerifyEnv(t)
		swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) { return nil, nil })
		payload, _ := approvalTestStatement(t, "approver@example.com", nil)
		f := newApprovalEnvelopeFixture(t, payload)
		envPath, ca, tsa := f.files(t, t.TempDir())
		for size, ok := range map[int]bool{1 << 20: true, 1<<20 + 1: false} {
			padded := append(bytes.Clone(f.JSON), bytes.Repeat([]byte(" "), size-len(f.JSON))...)
			require.NoError(t, os.WriteFile(envPath, padded, 0o600))
			_, err := runEnvelopeVerify(t, "--envelope", envPath, "--policy-ca-roots", ca, "--policy-timestamp-servers", tsa, "--platform-url", "")
			if ok {
				require.NoError(t, err, "%d bytes", size)
				continue
			}
			require.ErrorContains(t, err, "larger than 1 MiB", "%d bytes", size)
		}
	})
}

// embedReleaseTrust embeds the approval's anchors with the policy signer every
// release bakes in (subtrees/rookery/.github/workflows/release.yml), whose
// GitHub Actions issuer is the field that matters here.
func embedReleaseTrust(t *testing.T, f *approvalEnvelopeFixture) {
	t.Helper()
	fulcio, tsa := string(certPEM(t, f.FulcioRoot)), string(certPEM(t, f.TSARoot))
	swapEmbeddedTrustLoader(t, func() (*embeddedtrust.Trust, error) {
		return &embeddedtrust.Trust{
			Roots: []embeddedtrust.Root{
				{Name: "testifysec-platform-fulcio", Kind: embeddedtrust.KindFulcioRoot, PEM: fulcio},
				{Name: "testifysec-platform-tsa", Kind: embeddedtrust.KindTSARoot, PEM: tsa},
			},
			PolicySigners: []policy.Functionary{{Type: "root", CertConstraint: policy.CertConstraint{
				Emails: []string{"release@example.test"}, URIs: []string{"*"}, Roots: []string{"testifysec-platform-fulcio"},
				Extensions: certificate.Extensions{Issuer: "https://token.actions.githubusercontent.com",
					BuildConfigURI: "https://github.com/aflock-ai/rookery/.github/workflows/release.yml@*"},
			}}},
		}, nil
	})
}

// The embedded signer is the release workflow and the session's email is the
// reader: neither names an approver. An approval signed by a third person
// verifies under both, and is reported as theirs.
func TestVerifyEnvelope_NeverAppliesEmbeddedSignerOrSessionEmail(t *testing.T) {
	sandboxVerifyEnv(t)
	platformURL, strays := approvalReaderSession(t)
	payload, _ := approvalTestStatement(t, "approver@example.com", nil)
	f := newApprovalEnvelopeFixture(t, payload)
	embedReleaseTrust(t, f)
	envPath, _, _ := f.files(t, t.TempDir())

	out, err := runEnvelopeVerify(t, "--envelope", envPath, "--platform-url", platformURL)
	require.NoError(t, err)
	assert.Contains(t, out, "approval signed by approver@example.com")
	assert.NotContains(t, out, "reader@example.com")
	assert.NotContains(t, out, "release@example.test")
	assert.Zero(t, strays.Load())
}

// The History chip's command, run through the root command as a shell would,
// by a reader logged in to a platform with a working product: the exact shape
// platform mode claims. It must verify locally and never reach the door.
func TestVerifyEnvelope_DoesNotRouteToPlatformDoor(t *testing.T) {
	sandboxVerifyEnv(t)
	platformURL, strays := approvalReaderSession(t)
	payload, _ := approvalTestStatement(t, "approver@example.com", nil)
	f := newApprovalEnvelopeFixture(t, payload)
	embedApprovalAnchors(t, f)
	file := filepath.Join(t.TempDir(), "0b7e9a52.approval.json")
	require.NoError(t, os.WriteFile(file, f.JSON, 0o600))

	// The instrument first: without --envelope, this session does go to the door.
	// It carries an anchor because an anchorless platform verify is refused
	// before any request is made, which would leave the instrument reading 0.
	_, _, err := executeCmdOutput("verify", "--platform-url", platformURL, "--commit", "0b7e9a52")
	require.Error(t, err)
	require.NotZero(t, strays.Load(), "the loopback platform must see a platform-mode verify")
	strays.Store(0)

	words := strings.Fields(strings.ReplaceAll(historyVerifyCommand(file, platformURL), "'", ""))
	stdout, _, err := executeCmdOutput(words[1:]...)
	require.NoError(t, err)
	assert.Contains(t, stdout, "approval signed by approver@example.com")
	assert.Zero(t, strays.Load(), "verify --envelope reached the platform door")
}
