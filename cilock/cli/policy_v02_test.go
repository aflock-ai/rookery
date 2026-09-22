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

package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/stretchr/testify/require"
)

// Spelled literally: these tests pin the wire strings a policy is signed and
// hydrated under, not whatever the constants say.
const (
	pv7AflockV01 = "https://aflock.ai/policy/v0.1"
	pv7AflockV02 = "https://aflock.ai/policy/v0.2"
	pv7LegacyV01 = "https://witness.testifysec.com/policy/v0.1"
)

// pv7Source is a hand-authored policy whose "secrets" step carries the given
// about value; "" leaves the key out entirely.
func pv7Source(about string) string {
	aboutField := ""
	if about != "" {
		aboutField = `"about":"` + about + `",`
	}
	return `{"expires":"2030-01-01T00:00:00Z","steps":{"build":{"name":"build"},"secrets":{"name":"secrets",` +
		aboutField + `"attestations":[]}}}`
}

func pv7Write(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

// pv7Sign runs `cilock sign` with a local key and returns the envelope it wrote.
func pv7Sign(t *testing.T, content string, extra ...string) (dsse.Envelope, error) {
	t.Helper()
	isolateAgentConfig(t)
	_, _, key := inventoryRunFixture(t)
	in := pv7Write(t, content)
	out := filepath.Join(t.TempDir(), "policy.signed.json")
	args := append([]string{"-k", key, "-f", in, "-o", out, "--platform-url", ""}, extra...)
	if _, err := runCmd(t, SignCmd(), args...); err != nil {
		return dsse.Envelope{}, err
	}
	raw, err := os.ReadFile(out) //nolint:gosec // test temp path
	require.NoError(t, err)
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))
	return env, nil
}

// PV7 (sign): with no --datatype, a policy with a step that declares about is
// signed as v0.2, over exactly the bytes in the file.
func TestSign_PolicyDeclaringAboutIsSignedAsV02(t *testing.T) {
	src := pv7Source("source")
	env, err := pv7Sign(t, src)
	require.NoError(t, err)
	require.Equal(t, pv7AflockV02, env.PayloadType)
	require.Equal(t, src, string(env.Payload), "sign signs the file's bytes, unchanged")
}

// A policy with no about is signed exactly as before: the default type, the
// file's bytes. This is the v0.1 round trip.
func TestSign_PolicyWithoutAboutIsUnchanged(t *testing.T) {
	src := pv7Source("")
	env, err := pv7Sign(t, src)
	require.NoError(t, err)
	require.Equal(t, pv7LegacyV01, env.PayloadType, "the default type is unchanged")
	require.Equal(t, src, string(env.Payload))

	env, err = pv7Sign(t, src, "-t", pv7AflockV01)
	require.NoError(t, err)
	require.Equal(t, pv7AflockV01, env.PayloadType, "an explicit v0.1 type is kept")
}

// An explicit v0.1 type on a policy that declares about is refused before
// anything is signed: the engine will refuse it on every verify.
func TestSign_ExplicitV01WithAboutIsRefused(t *testing.T) {
	for _, pt := range []string{pv7AflockV01, pv7LegacyV01} {
		_, err := pv7Sign(t, pv7Source("source"), "-t", pt)
		require.Error(t, err, pt)
		require.Contains(t, err.Error(), "about-needs-policy-v0.2", pt)
		require.Contains(t, err.Error(), "secrets", "the refusal names the step")
	}
	env, err := pv7Sign(t, pv7Source("source"), "-t", pv7AflockV02)
	require.NoError(t, err)
	require.Equal(t, pv7AflockV02, env.PayloadType)
}

// PV7 (draft): the hydration request carries v0.2 for a source that declares
// about, and the printed sign command names v0.2.
func TestPolicyDraft_AboutChoosesV02(t *testing.T) {
	const hydrated = `{"expires":"2030-01-01T00:00:00Z","steps":{"secrets":{"name":"secrets","about":"source"}}}`
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		return http.StatusOK, okHydration(req, hydrated)
	})
	stubSession(t, fake.URL)
	src := pv7Write(t, pv7Source("source"))
	out := filepath.Join(t.TempDir(), "hydrated.json")

	stdout, err := runCmd(t, PolicyDraftCmd(), "-f", src, "-o", out, "--platform-url", fake.URL)
	require.NoError(t, err, stdout)
	require.Equal(t, pv7AflockV02, fake.gotReq.PayloadType)
	require.Contains(t, stdout, " -t "+shellQuote(pv7AflockV02))
}

// Draft without about still asks for v0.1, and an explicit v0.1 with about is
// refused before any request is sent.
func TestPolicyDraft_V01Unchanged_ExplicitV01WithAboutRefused(t *testing.T) {
	fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
		return http.StatusOK, okHydration(req, `{"expires":"2030-01-01T00:00:00Z","steps":{}}`)
	})
	stubSession(t, fake.URL)

	out := filepath.Join(t.TempDir(), "hydrated.json")
	stdout, err := runCmd(t, PolicyDraftCmd(), "-f", pv7Write(t, pv7Source("")), "-o", out, "--platform-url", fake.URL)
	require.NoError(t, err, stdout)
	require.Equal(t, pv7AflockV01, fake.gotReq.PayloadType)

	hits := fake.hits
	out2 := filepath.Join(t.TempDir(), "hydrated.json")
	_, err = runCmd(t, PolicyDraftCmd(), "-f", pv7Write(t, pv7Source("source")), "-o", out2,
		"--platform-url", fake.URL, "-t", pv7AflockV01)
	require.Error(t, err)
	require.Contains(t, err.Error(), "about-needs-policy-v0.2")
	require.Equal(t, hits, fake.hits, "nothing is sent for a policy the type cannot carry")
}

// PV7 (publish): the ceremony hydrates, and so asks the human to approve,
// under v0.2 when the source declares about. The fake refuses the hydration so
// the test stops before the device approval.
func TestPolicyPublish_AboutChoosesV02(t *testing.T) {
	for _, tc := range []struct{ about, want string }{{"source", pv7AflockV02}, {"", pv7AflockV01}} {
		fake := newDraftFake(t, func(req draftReqWire) (int, draftRespWire) {
			return http.StatusOK, draftRespWire{Version: "pushgate.policy-hydration.v1", TenantID: "tenant-9",
				SourceSHA256: draftSHA256(req.Source), Valid: false, Errors: []string{"stop here"}}
		})
		stubSession(t, fake.URL)
		_, err := runCmd(t, PolicyPublishCmd(), "-f", pv7Write(t, pv7Source(tc.about)), "-d", "d", "-t", "v1",
			"--platform-url", fake.URL)
		require.Error(t, err)
		require.Equal(t, 1, fake.hits, "about=%q", tc.about)
		require.Equal(t, tc.want, fake.gotReq.PayloadType, "about=%q", tc.about)
	}
}

// PV7 (validate, through the command): a signed v0.2 policy passes with no
// type warning; the same policy signed as v0.1 fails with the about rule.
func TestPolicyValidate_V02EnvelopeHasNoTypeWarning(t *testing.T) {
	full := `{"expires":"2030-01-01T00:00:00Z","steps":{"build":{"name":"build","about":"source",` +
		`"functionaries":[{"type":"publickey","publickeyid":"key-1"}],` +
		`"attestations":[{"type":"https://aflock.ai/attestations/command-run/v0.1"}]}},` +
		`"publickeys":{"key-1":{"keyid":"key-1","key":""}}}`
	for _, tc := range []struct {
		pt      string
		wantErr bool
	}{{pv7AflockV02, false}, {pv7AflockV01, true}} {
		env, err := pv7Sign(t, full, "-t", pv7AflockV02)
		require.NoError(t, err)
		env.PayloadType = tc.pt // validate reads the type; the signature is not checked without -k
		raw, err := json.Marshal(env)
		require.NoError(t, err)
		var buf strings.Builder
		err = runValidatePolicy(t.Context(), options.PolicyValidateOptions{PolicyFilePath: pv7Write(t, string(raw))}, &buf)
		if tc.wantErr {
			require.Error(t, err, tc.pt)
			require.Contains(t, buf.String(), "about-needs-policy-v0.2", tc.pt)
			continue
		}
		require.NoError(t, err, buf.String())
		require.NotContains(t, buf.String(), "PayloadType", "a v0.2 envelope draws no type warning")
	}
}

// A v0.2 type is a policy type: the humans-sign-policies refusal must see it,
// whatever the bytes look like.
func TestIsWitnessPolicyInput_V02TypeIsAPolicy(t *testing.T) {
	require.True(t, isWitnessPolicyInput([]byte("not json"), pv7AflockV02))
	require.True(t, isWitnessPolicyInput([]byte("not json"), pv7AflockV01))
	require.True(t, isWitnessPolicyInput([]byte("not json"), pv7LegacyV01))
	require.False(t, isWitnessPolicyInput([]byte("not json"), "application/octet-stream"))
}

func TestResolvePolicyPayloadType(t *testing.T) {
	about, plain := []byte(pv7Source("source")), []byte(pv7Source(""))
	cases := []struct {
		name     string
		explicit bool
		datatype string
		doc      []byte
		want     string
		wantErr  bool
	}{
		{"plain, default kept", false, pv7LegacyV01, plain, pv7LegacyV01, false},
		{"plain, explicit kept", true, pv7AflockV01, plain, pv7AflockV01, false},
		{"about, default becomes v0.2", false, pv7LegacyV01, about, pv7AflockV02, false},
		{"about, explicit v0.2 kept", true, pv7AflockV02, about, pv7AflockV02, false},
		{"about, explicit aflock v0.1 refused", true, pv7AflockV01, about, "", true},
		{"about, explicit legacy v0.1 refused", true, pv7LegacyV01, about, "", true},
		{"not a policy, default kept", false, pv7LegacyV01, []byte("hello"), pv7LegacyV01, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolvePolicyPayloadType(tc.explicit, tc.datatype, tc.doc)
			if tc.wantErr {
				require.ErrorContains(t, err, "about-needs-policy-v0.2")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// A policy signed as v0.2 is decoded strictly by every verifier
// (policy.DecodePolicyEnvelope), so a member the Policy type does not know --
// an author's "_comment", a typo, a later version's clause -- would make the
// signed policy fail on every verify. Sign refuses it before anything is
// signed, whether v0.2 was chosen for the author or given with -t. A policy
// without about keeps its v0.1 type and signs as before, "_comment" and all.
func TestSign_V02PolicyTheVerifierWouldRefuseIsNotSigned(t *testing.T) {
	withComment := `{"_comment":"reviewers read this","expires":"2030-01-01T00:00:00Z","steps":{"secrets":{"name":"secrets","about":"source","attestations":[]}}}`
	for _, extra := range [][]string{nil, {"-t", pv7AflockV02}} {
		_, err := pv7Sign(t, withComment, extra...)
		require.Error(t, err, "extra=%v", extra)
		require.Contains(t, err.Error(), `unknown field "_comment"`, "extra=%v", extra)
	}

	plain := `{"_comment":"reviewers read this","expires":"2030-01-01T00:00:00Z","steps":{"secrets":{"name":"secrets","attestations":[]}}}`
	env, err := pv7Sign(t, plain)
	require.NoError(t, err, "v0.1 decoding is lenient; a v0.1 policy with a comment signs as before")
	require.Equal(t, pv7LegacyV01, env.PayloadType)
}
