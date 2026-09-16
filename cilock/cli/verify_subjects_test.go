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
	"sync"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/log"
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

// offlineVerifyFixture is the scaffolding for tests that exercise the real
// `cilock verify` command with local, ephemeral-key DSSE fixtures: an isolated
// state dir, an ECDSA key the policy trusts, and a signer for evidence and
// policy envelopes. Set CILOCK_VERIFY_TEST_BINARY to replay a run through a
// built CLI instead of the in-process command.
type offlineVerifyFixture struct {
	dir       string
	keyPath   string
	keyID     string
	publicKey []byte
	signer    cryptoutil.Signer
}

func newOfflineVerifyFixture(t *testing.T) *offlineVerifyFixture {
	t.Helper()
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
	return &offlineVerifyFixture{dir: dir, keyPath: keyPath, keyID: keyID, publicKey: publicKey, signer: signer}
}

// writeSigned signs payload into a DSSE envelope at <dir>/<name> and returns
// the path.
func (f *offlineVerifyFixture) writeSigned(t *testing.T, name, payloadType string, payload []byte) string {
	t.Helper()
	env, err := dsse.Sign(payloadType, bytes.NewReader(payload), dsse.SignWithSigners(f.signer))
	require.NoError(t, err)
	data, err := json.Marshal(env)
	require.NoError(t, err)
	path := filepath.Join(f.dir, name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

// collection writes a signed single-step collection envelope carrying the
// given attestation types and in-toto subjects.
func (f *offlineVerifyFixture) collection(t *testing.T, name, step string, types []string, subjects string) string {
	t.Helper()
	atts := make([]string, 0, len(types))
	for _, typ := range types {
		atts = append(atts, fmt.Sprintf(`{"type": %q, "attestation": {"commithash": %q, "commithashverified": true}, "starttime": "2026-01-01T00:00:00Z", "endtime": "2026-01-01T00:00:01Z"}`, typ, gitSHA1Hex))
	}
	payload := fmt.Sprintf(`{
		"_type": "https://in-toto.io/Statement/v0.1",
		"predicateType": "https://aflock.ai/attestation-collection/v0.1",
		"subject": [%s],
		"predicate": {"name": %q, "attestations": [%s]}
	}`, subjects, step, strings.Join(atts, ","))
	return f.writeSigned(t, name, intoto.PayloadType, []byte(payload))
}

// policy writes a signed policy trusting the fixture key, with one step per
// entry requiring the listed attestation types.
func (f *offlineVerifyFixture) policy(t *testing.T, name string, steps map[string][]string) string {
	t.Helper()
	p := policy.Policy{
		Expires:    metav1.Time{Time: time.Now().Add(time.Hour)},
		PublicKeys: map[string]policy.PublicKey{f.keyID: {KeyID: f.keyID, Key: f.publicKey}},
		Steps:      map[string]policy.Step{},
	}
	for step, types := range steps {
		atts := make([]policy.Attestation, 0, len(types))
		for _, typ := range types {
			atts = append(atts, policy.Attestation{Type: typ})
		}
		p.Steps[step] = policy.Step{
			Name:          step,
			Functionaries: []policy.Functionary{{Type: "PublicKey", PublicKeyID: f.keyID}},
			Attestations:  atts,
		}
	}
	policyJSON, err := json.Marshal(p)
	require.NoError(t, err)
	return f.writeSigned(t, name, policy.PolicyPredicate, policyJSON)
}

// verifyLogCapture records every line the cilock logger emits during one
// in-process verify. The command's evidence report ("Step: ...",
// "verification failure: Reason: ...") goes through the log package, whose
// global logger another test may have left silent, so the fixture installs
// this and folds the lines into the stderr it returns.
type verifyLogCapture struct {
	mu    sync.Mutex
	lines []string
}

func (c *verifyLogCapture) add(format string, args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, fmt.Sprintf(format, args...))
}
func (c *verifyLogCapture) Errorf(format string, args ...interface{}) { c.add(format, args...) }
func (c *verifyLogCapture) Error(args ...interface{})                 { c.add("%s", fmt.Sprint(args...)) }
func (c *verifyLogCapture) Warnf(format string, args ...interface{})  { c.add(format, args...) }
func (c *verifyLogCapture) Warn(args ...interface{})                  { c.add("%s", fmt.Sprint(args...)) }
func (c *verifyLogCapture) Debugf(format string, args ...interface{}) { c.add(format, args...) }
func (c *verifyLogCapture) Debug(args ...interface{})                 { c.add("%s", fmt.Sprint(args...)) }
func (c *verifyLogCapture) Infof(format string, args ...interface{})  { c.add(format, args...) }
func (c *verifyLogCapture) Info(args ...interface{})                  { c.add("%s", fmt.Sprint(args...)) }

func (c *verifyLogCapture) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.lines, "\n")
}

// verify runs `cilock verify` offline with the fixture key against policyPath
// and returns stdout, stderr (with the logger's lines appended, for the
// in-process path) and the command error.
func (f *offlineVerifyFixture) verify(t *testing.T, policyPath string, args ...string) (string, string, error) {
	t.Helper()
	logs := &verifyLogCapture{}
	prev := log.GetLogger()
	log.SetLogger(logs)
	t.Cleanup(func() { log.SetLogger(prev) })
	out, err := os.CreateTemp(f.dir, "stdout-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	stderr, err := os.CreateTemp(f.dir, "stderr-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = stderr.Close() })
	args = append([]string{"-p", policyPath, "-k", f.keyPath,
		"--platform-url", "", "--enable-archivista=false", "--no-embedded-trust", "-o", "json"}, args...)
	var runErr error
	if bin := os.Getenv("CILOCK_VERIFY_TEST_BINARY"); bin != "" {
		cmd := exec.CommandContext(t.Context(), bin, append([]string{"verify"}, args...)...)
		cmd.Stdout, cmd.Stderr = out, stderr
		runErr = cmd.Run()
	} else {
		cmd := VerifyCmd()
		cmd.SetArgs(args)
		runErr = func() error {
			oldOut, oldErr := os.Stdout, os.Stderr
			os.Stdout, os.Stderr = out, stderr
			defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
			return cmd.ExecuteContext(t.Context())
		}()
	}
	stdoutData, err := os.ReadFile(out.Name())
	require.NoError(t, err)
	stderrData, err := os.ReadFile(stderr.Name())
	require.NoError(t, err)
	return string(stdoutData), string(stderrData) + "\n" + logs.text(), runErr
}

// This exercises the real command and verifier with local, ephemeral-key DSSE
// fixtures. Set CILOCK_VERIFY_TEST_BINARY to replay through a built CLI instead.
func TestVerifyCmd_OfflineSubjectAlgorithms(t *testing.T) {
	f := newOfflineVerifyFixture(t)
	const gitType = "https://aflock.ai/attestations/git/v0.1"
	evidencePath := f.collection(t, "evidence.dsse.json", "source", []string{gitType}, fmt.Sprintf(
		`{"name": "%s/commithash:%s", "digest": {"sha1": "%s"}}, {"name": "artifact", "digest": {"sha256": "%s"}}`,
		gitType, gitSHA1Hex, gitSHA1Hex, sha256Hex))
	policyPath := f.policy(t, "policy.dsse.json", map[string][]string{"source": {gitType}})
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
			args := []string{"-a", evidencePath}
			for _, subject := range tc.subjects {
				args = append(args, "--subjects", subject)
			}
			stdout, stderr, err := f.verify(t, policyPath, args...)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			var verdict VerifyVerdict
			require.NoError(t, json.Unmarshal([]byte(stdout), &verdict), "%s", stdout)
			assert.Equal(t, !tc.wantErr, verdict.Passed)
			assert.Equal(t, tc.matched, verdict.MatchedSubject)
			if tc.matched != "" {
				assert.Equal(t, "source", verdict.Step)
				assert.Contains(t, stderr, "verified: "+tc.matched+` bound to step "source"`)
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
				assert.Contains(t, stderr, "supplied artifact "+tc.unmatched+" did NOT match")
				assert.NotContains(t, stderr, "verified: "+tc.unmatched)
			} else {
				assert.NotContains(t, stderr, "did NOT match")
			}
		})
	}
}

// TestVerifyCmd_LoadedButFilteredEnvelopeIsNamed pins testifysec/judge#9309
// at the command level: an envelope passed with -a whose collection matches
// the step but lacks a required attestation type — or carries none of the
// supplied subjects — is named in the failure, with the predicate that
// dropped it, instead of the generic "Likely causes" block that opens with
// "the attestation wasn't loaded". The generic block is kept, and pinned,
// for the step nothing was loaded for.
func TestVerifyCmd_LoadedButFilteredEnvelopeIsNamed(t *testing.T) {
	f := newOfflineVerifyFixture(t)
	const (
		gitType    = "https://aflock.ai/attestations/git/v0.1"
		cmdRunType = "https://aflock.ai/attestations/command-run/v0.2"
	)
	// Minted like the issue's pt.json: git only, no command-run.
	evidencePath := f.collection(t, "pt.json", "push-tests", []string{gitType}, fmt.Sprintf(
		`{"name": "%s/commithash:%s", "digest": {"sha1": "%s"}}`, gitType, gitSHA1Hex, gitSHA1Hex))
	needsCmdRun := f.policy(t, "policy-cmdrun.dsse.json", map[string][]string{"push-tests": {gitType, cmdRunType}})

	t.Run("missing attestation type", func(t *testing.T) {
		stdout, stderr, err := f.verify(t, needsCmdRun, "-a", evidencePath, "--subjects", "sha1:"+gitSHA1Hex)
		require.Error(t, err)
		assert.Contains(t, stdout, `"passed": false`)
		assert.Contains(t, stderr, "pt.json is missing required attestation "+cmdRunType+" (has: git/v0.1)")
		assert.Contains(t, stderr, "1 envelope loaded but not eligible")
		assert.NotContains(t, stderr, "Likely causes")
		assert.NotContains(t, stderr, "wasn't loaded")
	})

	t.Run("missing attestation type and subject", func(t *testing.T) {
		other := strings.Repeat("a", 40)
		_, stderr, err := f.verify(t, needsCmdRun, "-a", evidencePath, "--subjects", "sha1:"+other)
		require.Error(t, err)
		assert.Contains(t, stderr, "pt.json is missing required attestation "+cmdRunType)
		assert.Contains(t, stderr, "carries none of the supplied digest(s) ["+other+"]")
		assert.Contains(t, stderr, "subjects present: "+gitType+"/commithash:"+gitSHA1Hex+" (sha1:"+gitSHA1Hex+")")
		assert.NotContains(t, stderr, "Likely causes")
	})

	t.Run("nothing loaded for the step keeps the generic causes", func(t *testing.T) {
		nothing := f.policy(t, "policy-nothing.dsse.json", map[string][]string{"nothing": {gitType}})
		_, stderr, err := f.verify(t, nothing, "-a", evidencePath, "--subjects", "sha1:"+gitSHA1Hex)
		require.Error(t, err)
		assert.Contains(t, stderr, "no collection passed verification for step nothing. Likely causes, in order:")
		assert.NotContains(t, stderr, "not eligible")
	})
}
