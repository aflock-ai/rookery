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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/policy"
	_ "github.com/aflock-ai/rookery/plugins/attestors/policyverify"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	gitSHA1Hex = "cf12d38eb1e8513c00f13313ca95bd2c7769f72a"                         // 40 hex — a git commit
	sha256Hex  = "7b8c52c06dad0eb1cf800bb3343525b78e3dff07a076aac566d52beff2b7e38d" // 64 hex
)

// TestParseSubjectDigest_HonorsDeclaredSHA1 pins the /free-page bug: a
// "sha1:<gitsha>" subject must be stored under SHA-1 — NOT silently relabeled
// sha256, which could never match the git attestor's sha1 commithash subject.
func TestParseSubjectDigest_HonorsDeclaredSHA1(t *testing.T) {
	set, hex, err := parseSubjectDigest("sha1:" + gitSHA1Hex)
	if err != nil {
		t.Fatalf("parseSubjectDigest: %v", err)
	}
	if hex != gitSHA1Hex {
		t.Fatalf("hex = %q, want %q", hex, gitSHA1Hex)
	}
	if got := set[cryptoutil.DigestValue{Hash: crypto.SHA1, GitOID: false}]; got != gitSHA1Hex {
		t.Fatalf("sha1-declared digest stored as %v, want it under crypto.SHA1", set)
	}
	if _, hasSHA256 := set[cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}]; hasSHA256 {
		t.Fatal("sha1-declared digest must not also claim sha256")
	}
}

// TestParseSubjectDigest_SHA256Declared stores under SHA-256 with exact length.
func TestParseSubjectDigest_SHA256Declared(t *testing.T) {
	set, _, err := parseSubjectDigest("sha256:" + sha256Hex)
	if err != nil {
		t.Fatalf("parseSubjectDigest: %v", err)
	}
	if got := set[cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}]; got != sha256Hex {
		t.Fatalf("sha256-declared digest stored as %v", set)
	}
}

// TestParseSubjectDigest_BareHexKeepsLegacyBehavior: no prefix → sha256, with
// the historical lenient length rule (>=32 even-length hex), so existing
// callers of bare --subjects values keep working byte-for-byte.
func TestParseSubjectDigest_BareHexKeepsLegacyBehavior(t *testing.T) {
	for _, bare := range []string{sha256Hex, gitSHA1Hex} { // 64 and 40 hex both pass the lenient rule
		set, hex, err := parseSubjectDigest(bare)
		if err != nil {
			t.Fatalf("parseSubjectDigest(%q): %v", bare, err)
		}
		if hex != bare {
			t.Fatalf("hex = %q, want %q", hex, bare)
		}
		if got := set[cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}]; got != bare {
			t.Fatalf("bare digest must stay sha256 for backward compat, got %v", set)
		}
	}
}

// TestParseSubjectDigest_UnsupportedAlgorithmErrors: the error names the
// supported set instead of silently mislabeling the digest.
func TestParseSubjectDigest_UnsupportedAlgorithmErrors(t *testing.T) {
	_, _, err := parseSubjectDigest("md5:d41d8cd98f00b204e9800998ecf8427e")
	if err == nil {
		t.Fatal("want an error for an unsupported algorithm prefix")
	}
	if !strings.Contains(err.Error(), "sha1") || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("error should name the supported algorithms, got %q", err.Error())
	}
}

// TestParseSubjectDigest_DeclaredLengthEnforced: a declared algorithm demands
// the exact digest length — sha1:<64hex> and sha256:<40hex> are user error.
func TestParseSubjectDigest_DeclaredLengthEnforced(t *testing.T) {
	if _, _, err := parseSubjectDigest("sha1:" + sha256Hex); err == nil {
		t.Fatal("sha1 with 64 hex chars must error")
	}
	if _, _, err := parseSubjectDigest("sha256:" + gitSHA1Hex); err == nil {
		t.Fatal("sha256 with 40 hex chars must error")
	}
}

// TestParseSubjectDigest_NonHexRejected keeps the injection guard.
func TestParseSubjectDigest_NonHexRejected(t *testing.T) {
	for _, bad := range []string{"sha1:zz12d38eb1e8513c00f13313ca95bd2c7769f72a", "not-a-digest", "sha256:"} {
		if _, _, err := parseSubjectDigest(bad); err == nil {
			t.Fatalf("want an error for %q", bad)
		}
	}
}

// This exercises the real command and verifier with local, ephemeral-key DSSE
// fixtures. Set CILOCK_VERIFY_TEST_BINARY to replay through a built CLI instead.
func TestVerifyCmd_OfflineSubjectAlgorithms(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	stateDir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	t.Setenv("CILOCK_STATE_DIR", stateDir)
	t.Setenv("CILOCK_SKIP_VERSION_CHECK", "1")
	t.Setenv("CILOCK_NO_TELEMETRY", "1")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithHash(crypto.SHA256))
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	keyID, err := verifier.KeyID()
	require.NoError(t, err)
	publicKey, err := verifier.Bytes()
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "test.pub")
	require.NoError(t, os.WriteFile(keyPath, publicKey, 0o600))
	writeSigned := func(name, payloadType string, payload []byte) string {
		env, err := dsse.Sign(payloadType, bytes.NewReader(payload), dsse.SignWithSigners(signer))
		require.NoError(t, err)
		data, err := json.Marshal(env)
		require.NoError(t, err)
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, data, 0o600))
		return path
	}
	const gitType = "https://aflock.ai/attestations/git/v0.1"
	payload := fmt.Sprintf(`{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://aflock.ai/attestation-collection/v0.1",
		"subject": [
			{"name": "%s/commithash:%s", "digest": {"sha1": "%s"}},
			{"name": "artifact", "digest": {"sha256": "%s"}}
		],
		"predicate": {"name": "source", "attestations": [{
			"type": "%s", "attestation": {"commithash": "%s", "commithashverified": true},
			"starttime": "2026-01-01T00:00:00Z", "endtime": "2026-01-01T00:00:01Z"
		}]}
	}`, gitType, gitSHA1Hex, gitSHA1Hex, sha256Hex, gitType, gitSHA1Hex)
	evidencePath := writeSigned("evidence.dsse.json", intoto.PayloadType, []byte(payload))
	p := policy.Policy{
		Expires:    metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: map[string]policy.PublicKey{keyID: {KeyID: keyID, Key: publicKey}},
		Steps: map[string]policy.Step{"source": {
			Name:          "source",
			Functionaries: []policy.Functionary{{Type: "PublicKey", PublicKeyID: keyID}},
			Attestations:  []policy.Attestation{{Type: gitType}},
		}},
	}
	policyJSON, err := json.Marshal(p)
	require.NoError(t, err)
	policyPath := writeSigned("policy.dsse.json", policy.PolicyPredicate, policyJSON)
	for _, tc := range []struct {
		name      string
		subjects  []string
		matched   string
		unmatched string
		wantErr   bool
	}{
		{"sha1 verified commit", []string{"sha1:" + gitSHA1Hex}, "sha1:" + gitSHA1Hex, "", false},
		{"sha256 explicit", []string{"sha256:" + sha256Hex}, "sha256:" + sha256Hex, "", false},
		{"sha256 bare", []string{sha256Hex}, "sha256:" + sha256Hex, "", false},
		{"unmatched sha1", []string{"sha1:" + strings.Repeat("a", 40), sha256Hex}, "sha256:" + sha256Hex, "sha1:" + strings.Repeat("a", 40), false},
		{"bare 40 hex remains sha256", []string{gitSHA1Hex, sha256Hex}, "sha256:" + sha256Hex, "sha256:" + gitSHA1Hex, false},
		{"wrong commit fails", []string{"sha1:" + strings.Repeat("a", 40)}, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := os.CreateTemp(dir, "stdout-")
			require.NoError(t, err)
			t.Cleanup(func() { _ = out.Close() })
			stderr, err := os.CreateTemp(dir, "stderr-")
			require.NoError(t, err)
			t.Cleanup(func() { _ = stderr.Close() })
			args := []string{"-p", policyPath, "-k", keyPath, "-a", evidencePath,
				"--platform-url", "", "--enable-archivista=false", "--no-embedded-trust", "-o", "json"}
			for _, subject := range tc.subjects {
				args = append(args, "--subjects", subject)
			}
			if bin := os.Getenv("CILOCK_VERIFY_TEST_BINARY"); bin != "" {
				cmd := exec.CommandContext(t.Context(), bin, append([]string{"verify"}, args...)...)
				cmd.Stdout, cmd.Stderr = out, stderr
				err = cmd.Run()
			} else {
				cmd := VerifyCmd()
				cmd.SetArgs(args)
				err = func() error {
					oldOut, oldErr := os.Stdout, os.Stderr
					os.Stdout, os.Stderr = out, stderr
					defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
					return cmd.ExecuteContext(t.Context())
				}()
			}
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			data, err := os.ReadFile(out.Name())
			require.NoError(t, err)
			var verdict VerifyVerdict
			require.NoError(t, json.Unmarshal(data, &verdict), "%s", data)
			assert.Equal(t, !tc.wantErr, verdict.Passed)
			assert.Equal(t, tc.matched, verdict.MatchedSubject)
			data, err = os.ReadFile(stderr.Name())
			require.NoError(t, err)
			if tc.matched != "" {
				assert.Equal(t, "source", verdict.Step)
				assert.Contains(t, string(data), "verified: "+tc.matched+` bound to step "source"`)
				if strings.HasPrefix(tc.matched, "sha1:") {
					assert.Equal(t, gitType+"/commithash:"+gitSHA1Hex, verdict.ObservedSubjectName)
				} else {
					assert.Equal(t, "artifact", verdict.ObservedSubjectName)
				}
			} else {
				assert.Empty(t, verdict.Step)
				assert.Empty(t, verdict.ObservedSubjectName)
			}
			if tc.unmatched != "" {
				assert.Contains(t, string(data), "supplied artifact "+tc.unmatched+" did NOT match")
				assert.NotContains(t, string(data), "verified: "+tc.unmatched)
			} else {
				assert.NotContains(t, string(data), "did NOT match")
			}
		})
	}
}
