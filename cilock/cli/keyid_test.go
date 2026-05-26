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
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeEd25519PEMs writes a matched ed25519 keypair (private + public)
// to the given directory and returns the paths and the expected keyid.
// The expected keyid is the one cilock's own cryptoutil derives, so
// any divergence between keyid_show and the rest of cilock is caught.
func writeEd25519PEMs(t *testing.T, dir string) (privPath, pubPath, expectedID string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	privPath = filepath.Join(dir, "signer.key")
	require.NoError(t, os.WriteFile(privPath, privPEM, 0o600))

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	pubPath = filepath.Join(dir, "signer.pub")
	require.NoError(t, os.WriteFile(pubPath, pubPEM, 0o600))

	// Compute the "ground truth" keyid via the same code path the rest
	// of cilock uses at sign / verify time.
	expectedID, err = cryptoutil.GeneratePublicKeyID(pub, crypto.SHA256)
	require.NoError(t, err)

	return privPath, pubPath, expectedID
}

func TestKeyidShow_PrivateAndPublicAgree(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, want := writeEd25519PEMs(t, dir)

	gotPriv, err := keyidForFile(privPath)
	require.NoError(t, err)
	assert.Equal(t, want, gotPriv, "keyid of private key must equal keyid of its public half")

	gotPub, err := keyidForFile(pubPath)
	require.NoError(t, err)
	assert.Equal(t, want, gotPub, "keyid of public key must match expected ground truth")
}

func TestKeyidShow_MatchesRuntimeSignerKeyID(t *testing.T) {
	// Use cilock's own Signer to derive the keyid and verify
	// keyidForFile yields the same value. This is the "no divergence"
	// regression guard: if anyone ever changes the cryptoutil keyid
	// algorithm, this test should catch it before the CLI lies to
	// users.
	dir := t.TempDir()
	privPath, _, _ := writeEd25519PEMs(t, dir)

	raw, err := os.ReadFile(privPath) //nolint:gosec // test fixture
	require.NoError(t, err)
	signer, err := cryptoutil.NewSignerFromReader(bytes.NewReader(raw))
	require.NoError(t, err)
	runtimeID, err := signer.KeyID()
	require.NoError(t, err)

	cliID, err := keyidForFile(privPath)
	require.NoError(t, err)

	assert.Equal(t, runtimeID, cliID, "cilock keyid show must equal the Signer.KeyID() used at sign time")
}

func TestKeyidShow_GarbageFileFails(t *testing.T) {
	dir := t.TempDir()
	badPath := filepath.Join(dir, "not-a-key.txt")
	require.NoError(t, os.WriteFile(badPath, []byte("hello world\n"), 0o600))

	_, err := keyidForFile(badPath)
	require.Error(t, err)
	// The error must mention both legs (private + public) so the user
	// knows we tried each path.
	assert.Contains(t, err.Error(), "not a recognized public or private PEM key")
}

func TestKeyidShow_MissingFileFails(t *testing.T) {
	_, err := keyidForFile("/does/not/exist/at/all.pem")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read")
}

func TestKeyidShowCmd_TextFormat(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, want := writeEd25519PEMs(t, dir)

	var out bytes.Buffer
	cmd := keyidShowCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{privPath, pubPath})
	require.NoError(t, cmd.Execute())

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], want)
	assert.Contains(t, lines[0], privPath)
	assert.Contains(t, lines[1], want)
	assert.Contains(t, lines[1], pubPath)
}

func TestKeyidShowCmd_JSONFormat(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, want := writeEd25519PEMs(t, dir)

	var out bytes.Buffer
	cmd := keyidShowCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--format", "json", privPath, pubPath})
	require.NoError(t, cmd.Execute())

	var got []struct {
		Path  string `json:"path"`
		KeyID string `json:"keyid"`
		Error string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	require.Len(t, got, 2)
	assert.Equal(t, want, got[0].KeyID)
	assert.Equal(t, privPath, got[0].Path)
	assert.Equal(t, want, got[1].KeyID)
	assert.Equal(t, pubPath, got[1].Path)
}

func TestKeyidShowCmd_UnknownFormatFails(t *testing.T) {
	dir := t.TempDir()
	privPath, _, _ := writeEd25519PEMs(t, dir)

	var out bytes.Buffer
	cmd := keyidShowCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"--format", "yaml", privPath})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown --format")
}

func TestKeyidShowCmd_MixedSuccessAndFailureReturnsError(t *testing.T) {
	dir := t.TempDir()
	privPath, _, want := writeEd25519PEMs(t, dir)
	missing := filepath.Join(dir, "ghost.pem")

	var out, errBuf bytes.Buffer
	cmd := keyidShowCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errBuf)
	cmd.SetArgs([]string{privPath, missing})
	err := cmd.Execute()
	require.Error(t, err, "one good + one bad must yield a non-zero exit")
	// stdout still contains the successful keyid…
	assert.Contains(t, out.String(), want)
	// …and stderr names the failing file.
	assert.Contains(t, errBuf.String(), "ghost.pem")
}

// TestKeyidShow_AcceptsDashKFlag pins fix F5: -k/--key works as an
// alternative to positional, matching the convention used by every other
// cilock subcommand (run, sign, verify, policy from-bundles).
func TestKeyidShow_AcceptsDashKFlag(t *testing.T) {
	dir := t.TempDir()
	_, pubPath, want := writeEd25519PEMs(t, dir)

	var out bytes.Buffer
	cmd := keyidShowCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-k", pubPath})
	require.NoError(t, cmd.Execute(), "-k <file> must be accepted (F5 fix)")

	got := strings.TrimSpace(out.String())
	assert.Contains(t, got, want, "keyid for -k input must match expected")
	assert.Contains(t, got, pubPath, "output line must reference the supplied path")
}

// TestKeyidShow_AcceptsPositional pins backward-compatibility: pre-F5
// scripts that pass keys positionally must continue to work unchanged.
func TestKeyidShow_AcceptsPositional(t *testing.T) {
	dir := t.TempDir()
	_, pubPath, want := writeEd25519PEMs(t, dir)

	var out bytes.Buffer
	cmd := keyidShowCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{pubPath})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), want)
}

// TestKeyidShow_RejectsBoth: mixing -k with positional args is ambiguous
// (which set wins?), so it's rejected with a clear message.
func TestKeyidShow_RejectsBoth(t *testing.T) {
	dir := t.TempDir()
	_, pubPath, _ := writeEd25519PEMs(t, dir)

	var out bytes.Buffer
	cmd := keyidShowCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"-k", pubPath, pubPath})
	err := cmd.Execute()
	require.Error(t, err, "-k together with positional must be rejected")
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// TestKeyidShow_RejectsNeither: zero positional args AND no -k must
// produce a clear "supply something" error, not panic or do nothing.
func TestKeyidShow_RejectsNeither(t *testing.T) {
	var out bytes.Buffer
	cmd := keyidShowCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "required")
}

// TestResolveKeyidShowInputs covers the validator directly so each branch
// of the (positional, flag) cross-product is pinned independently of the
// cobra plumbing.
func TestResolveKeyidShowInputs(t *testing.T) {
	cases := []struct {
		name        string
		positional  []string
		keyFlag     string
		wantPaths   []string
		wantErrLike string
	}{
		{name: "only positional", positional: []string{"a.pem", "b.pem"}, wantPaths: []string{"a.pem", "b.pem"}},
		{name: "only flag", keyFlag: "a.pem", wantPaths: []string{"a.pem"}},
		{name: "both rejected", positional: []string{"a.pem"}, keyFlag: "b.pem", wantErrLike: "mutually exclusive"},
		{name: "neither rejected", wantErrLike: "required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveKeyidShowInputs(tc.positional, tc.keyFlag)
			if tc.wantErrLike != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErrLike)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantPaths, got)
		})
	}
}
