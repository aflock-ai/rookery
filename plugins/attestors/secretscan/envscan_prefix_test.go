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
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// These tests pin the rule for PARTIAL matches on the decoded-content path
// (#9315). Decoded content is whatever a base64/hex/URL candidate turns into,
// and a large share of it is not text at all: every sha256 in a material
// inventory, every `h1:` line in go.sum, every integrity hash in a lockfile
// decodes to 32 bytes of noise. Matching a 3-character prefix of a sensitive
// environment value against that noise is a lottery whose odds go to 1 as the
// tree grows, and whose outcome depends on the caller's environment — which
// is exactly the "refused, re-minted, accepted" non-determinism seen at the
// Pushgate.

// envValueFindings filters to the findings produced by the env-value scan,
// which is the only path under test here. Gitleaks may or may not flag the
// same bytes under its own rules; that is orthogonal and not asserted on.
func envValueFindings(findings []Finding) []Finding {
	var out []Finding
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "witness-encoded-env-value-") || strings.HasPrefix(f.RuleID, "witness-env-value-") {
			out = append(out, f)
		}
	}
	return out
}

// TestHexDigestsDoNotPartialMatchEnvValuePrefix reproduces the Pushgate
// false positive with the real shape: testdata/material-v0.3-excerpt.json is
// a 40-leaf excerpt of the material/v0.3 predicate minted over
// kubernetes/kubernetes@7f3e1a85b8ea (pushgate-bench task k8s-140108). Leaf 7's
// fileDigest, 001da7eaee2de15767540b7fdd979dba..., hex-decodes to bytes whose
// offsets 7..9 are 0x57 0x67 0x54 = "WgT". A caller whose environment holds a
// *TOKEN* value starting with those three characters was refused; a caller
// without it was accepted, on the same commit.
func TestHexDigestsDoNotPartialMatchEnvValuePrefix(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "material-v0.3-excerpt.json"))
	require.NoError(t, err)
	require.Contains(t, string(fixture), "001da7eaee2de15767540b7fdd979dba555c57f1714a52885777249725fc79b7",
		"fixture must still carry the digest the test is built around")
	decoded, err := hex.DecodeString("001da7eaee2de15767540b7fdd979dba555c57f1714a52885777249725fc79b7")
	require.NoError(t, err)
	require.Equal(t, "WgT", string(decoded[7:10]), "the digest bytes must contain the 3-char prefix the token starts with")

	// Matches the *TOKEN* glob in the default sensitive list. The value is
	// synthetic; only its first three characters matter to the bug.
	t.Setenv("CLAUDE_CODE_MESSAGING_TOKEN", "WgT7Qx9mKp2LzR4vN8bH")

	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)
	a := New()

	findings, err := a.scanBytes(fixture, "attestation_material.json", "", detector, map[string]struct{}{}, 0)
	require.NoError(t, err)

	for _, f := range envValueFindings(findings) {
		t.Errorf("hex-decoded digest bytes reported as a leaked env value: rule=%s encoding=%v match=%q",
			f.RuleID, f.EncodingPath, f.Match)
	}
}

// TestGoSumHashesDoNotPartialMatchEnvValuePrefix: the same mechanism through
// the base64 decoder on a file that is a product of every Go build. The lines
// are real go.sum entries; the h1: hash on the v0.38.0 line decodes to bytes
// whose offsets 27..29 are "wWo".
func TestGoSumHashesDoNotPartialMatchEnvValuePrefix(t *testing.T) {
	goSum := strings.Join([]string{
		"cloud.google.com/go v0.26.0/go.mod h1:aQUYkXzVsufM+DwF1aE+0xfcU+56JwCaLick0ClmMTw=",
		"cloud.google.com/go v0.34.0/go.mod h1:aQUYkXzVsufM+DwF1aE+0xfcU+56JwCaLick0ClmMTw=",
		"cloud.google.com/go v0.38.0/go.mod h1:990N+gfupTy94rShfmMCWGDn0LpTmnzTp2qbd1dvSRU=",
		"cloud.google.com/go v0.44.1/go.mod h1:iSa0KzasP4Uvy3f1mN/7PiObzGgflwredwwASm/v6AU=",
		"cloud.google.com/go v0.44.2/go.mod h1:60680Gw3Yr4ikxnPRS/oxxkBccT6SA1yMk63TGekxKY=",
		"",
	}, "\n")
	decoded, err := base64.StdEncoding.DecodeString("990N+gfupTy94rShfmMCWGDn0LpTmnzTp2qbd1dvSRU=")
	require.NoError(t, err)
	require.Equal(t, "wWo", string(decoded[27:30]))

	t.Setenv("NPM_TOKEN", "wWoK3v8Qz2Lm9Xp4Rt6Y")

	detector, err := detect.NewDetectorDefaultConfig()
	require.NoError(t, err)
	a := New()

	findings, err := a.scanBytes([]byte(goSum), "go.sum", "", detector, map[string]struct{}{}, 0)
	require.NoError(t, err)

	for _, f := range envValueFindings(findings) {
		t.Errorf("base64-decoded go.sum hash reported as a leaked env value: rule=%s encoding=%v match=%q",
			f.RuleID, f.EncodingPath, f.Match)
	}
}

// TestDecodedPartialMatchRequiresMostOfTheSecret pins the rule that replaces
// the 3-character prefix: a partial match on decoded content counts only when
// the decoded bytes carry at least half of the secret and at least
// minPartialMatchLength characters of it. The half is what rules out
// structural prefixes that every secret of a type shares (the 36-character
// HS256 JWT header, "-----BEGIN RSA PRIVATE KEY-----", "ghp_", "AKIA"); the
// floor is what rules out short values whose half is still guessable.
func TestDecodedPartialMatchRequiresMostOfTheSecret(t *testing.T) {
	const pat = "ghp_0123456789abcdefghijABCDEFGHIJ012345" // 40 chars, classic PAT shape
	require.Len(t, pat, 40)
	t.Setenv("GITHUB_TOKEN", pat)

	// Two JWTs sharing the standard HS256 header but with different payloads.
	// The header alone is 36 characters: long enough to beat any plausible
	// length floor, which is why length alone is not the rule.
	const jwtHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
	mine := jwtHeader + "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	other := jwtHeader + "eyJzdWIiOiI5ODc2NTQzMjEwIiwibmFtZSI6IkphbmUgUm9lIiwiaWF0IjoxNzAwMDAwMDAwfQ.9zXN0k3sWq2Ff2Q5G5Y8hE0jVb6yqJ7wTNzq8ZB5R4M"
	t.Setenv("SERVICE_JWT_TOKEN", mine)

	sensitive := map[string]struct{}{"GITHUB_TOKEN": {}, "SERVICE_JWT_TOKEN": {}}
	a := New()

	cases := []struct {
		name    string
		decoded string
		want    string // expected rule id, "" for no env-value finding
	}{
		{"whole token", "token: " + pat + "\n", "witness-encoded-env-value-GITHUB-TOKEN"},
		{"whole token with echo newline", pat + "\n", "witness-encoded-env-value-GITHUB-TOKEN"},
		{"first 24 of 40 chars (most of the secret)", "prefix=" + pat[:24], "witness-encoded-env-value-GITHUB-TOKEN-partial"},
		{"exactly half, 20 of 40", pat[:20] + "\n", "witness-encoded-env-value-GITHUB-TOKEN-partial"},
		{"19 of 40 is less than half", pat[:19] + "\n", ""},
		{"first 12 chars, the debugging idiom", "token starts with " + pat[:12], ""},
		{"3-char prefix in noise", "\x00\x1d\xa7ghp\xee\x2d\xe1", ""},
		{"a different JWT sharing the 36-char header", "bearer " + other, ""},
		{"the same JWT", "bearer " + mine, "witness-encoded-env-value-SERVICE-JWT-TOKEN"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := envValueFindings(a.checkDecodedContentForSensitiveValues(
				tc.decoded, "source", "base64", sensitive, map[string]struct{}{}))
			if tc.want == "" {
				for _, f := range findings {
					t.Errorf("unexpected env-value finding: rule=%s match=%q", f.RuleID, f.Match)
				}
				return
			}
			require.Len(t, findings, 1, "findings=%+v", findings)
			require.Equal(t, tc.want, findings[0].RuleID)
		})
	}
}

// TestShortSecretsHaveAPartialFloor: half of an 8-character value is 4
// characters, which is not evidence of anything. The floor applies even when
// half would be shorter.
func TestShortSecretsHaveAPartialFloor(t *testing.T) {
	const short = "p4ssw0rd!x" // 10 chars; half is 5, below the floor
	require.Less(t, len(short)/2, minPartialMatchLength)
	t.Setenv("DB_PASSWORD", short)
	sensitive := map[string]struct{}{"DB_PASSWORD": {}}
	a := New()

	got := envValueFindings(a.checkDecodedContentForSensitiveValues(
		"pw="+short[:6], "source", "base64", sensitive, map[string]struct{}{}))
	require.Empty(t, got, "6 of 10 chars is more than half but below the %d-char floor", minPartialMatchLength)

	got = envValueFindings(a.checkDecodedContentForSensitiveValues(
		"pw="+short[:8], "source", "base64", sensitive, map[string]struct{}{}))
	require.Len(t, got, 1, "8 of 10 chars clears both the half and the floor")
	require.Equal(t, "witness-encoded-env-value-DB-PASSWORD-partial", got[0].RuleID)
}
