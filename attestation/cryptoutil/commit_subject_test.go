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

package cryptoutil

import (
	"strings"
	"testing"
)

// A policy-declared commit subject (ExternalAttestation.commitSubject) is the
// second, narrower door to the SHA-1 subject arm: the POLICY names the exact
// subject-name prefix that names a commit for one external, and only a
// subject spelled exactly <prefix><40-hex> with a sha1 digest of that same
// value may anchor a match. These tests enumerate the value space around it.

const (
	vsaBindingPrefix = "https://pushgate.dev/v0.1/commithash:"
	vsaBindingCommit = "ef2115760123456789abcdef0123456789abcdef"
)

func TestVsaBindingValidateCommitSubjectPrefix(t *testing.T) {
	good := []string{
		vsaBindingPrefix,
		"https://example.com/commithash:",
		"http://example.com/a/b/commithash:",
		"https://aflock.ai/attestations/git/v0.1/commithash:",
	}
	for _, p := range good {
		if err := ValidateCommitSubjectPrefix(p); err != nil {
			t.Errorf("ValidateCommitSubjectPrefix(%q) = %v, want nil", p, err)
		}
	}
	bad := map[string]string{
		"empty":                "",
		"bare infix":           "commithash:",
		"no slash before":      "https://pushgate.dev/v0.1commithash:",
		"no commithash suffix": "https://pushgate.dev/v0.1/",
		"trailing space":       vsaBindingPrefix + " ",
		"leading space":        " " + vsaBindingPrefix,
		"inner space":          "https://pushgate.dev/v0 .1/commithash:",
		"tab":                  "https://pushgate.dev/v0.1/\tcommithash:",
		"newline":              "https://pushgate.dev/v0.1/commithash:\n",
		"nul":                  "https://pushgate.dev/v0.1/\x00commithash:",
		"non-ascii":            "https://pushgäte.dev/v0.1/commithash:",
		"no scheme":            "pushgate.dev/v0.1/commithash:",
		"no host":              "https:///v0.1/commithash:",
		"query":                "https://pushgate.dev/v0.1?x=/commithash:",
		"fragment":             "https://pushgate.dev/v0.1#/commithash:",
		"userinfo":             "https://u@pushgate.dev/v0.1/commithash:",
		"uppercase infix":      "https://pushgate.dev/v0.1/COMMITHASH:",
		"too long":             "https://pushgate.dev/" + strings.Repeat("a", 300) + "/commithash:",
		"upper scheme":         "HTTPS://pushgate.dev/v0.1/commithash:",
	}
	for name, p := range bad {
		if err := ValidateCommitSubjectPrefix(p); err == nil {
			t.Errorf("%s: ValidateCommitSubjectPrefix(%q) = nil, want error", name, p)
		}
	}
}

func TestVsaBindingIsDeclaredCommitSubject(t *testing.T) {
	upper := strings.ToUpper(vsaBindingCommit)
	cases := []struct {
		name                    string
		prefix, subject, alg, v string
		want                    bool
	}{
		{"exact", vsaBindingPrefix, vsaBindingPrefix + vsaBindingCommit, "sha1", vsaBindingCommit, true},
		{"hex in name upper-cased only", vsaBindingPrefix, vsaBindingPrefix + upper, "sha1", vsaBindingCommit, true},
		{"hex in value upper-cased only", vsaBindingPrefix, vsaBindingPrefix + vsaBindingCommit, "sha1", upper, true},
		{"no prefix declared", "", vsaBindingPrefix + vsaBindingCommit, "sha1", vsaBindingCommit, false},
		{"invalid declared prefix", "commithash:", "commithash:" + vsaBindingCommit, "sha1", vsaBindingCommit, false},
		{"other prefix", vsaBindingPrefix, "https://evil.example/v0.1/commithash:" + vsaBindingCommit, "sha1", vsaBindingCommit, false},
		{"case-variant prefix", vsaBindingPrefix, "https://PUSHGATE.dev/v0.1/commithash:" + vsaBindingCommit, "sha1", vsaBindingCommit, false},
		{"prefix plus whitespace", vsaBindingPrefix, vsaBindingPrefix + " " + vsaBindingCommit, "sha1", vsaBindingCommit, false},
		{"trailing whitespace", vsaBindingPrefix, vsaBindingPrefix + vsaBindingCommit + " ", "sha1", vsaBindingCommit, false},
		{"longer prefix", vsaBindingPrefix, "x" + vsaBindingPrefix + vsaBindingCommit, "sha1", vsaBindingCommit, false},
		{"bare git form", vsaBindingPrefix, "commithash:" + vsaBindingCommit, "sha1", vsaBindingCommit, false},
		{"null oid", vsaBindingPrefix, vsaBindingPrefix + gitNullOID, "sha1", gitNullOID, false},
		{"short", vsaBindingPrefix, vsaBindingPrefix + vsaBindingCommit[:39], "sha1", vsaBindingCommit[:39], false},
		{"long", vsaBindingPrefix, vsaBindingPrefix + vsaBindingCommit + "a", "sha1", vsaBindingCommit + "a", false},
		{"non-hex", vsaBindingPrefix, vsaBindingPrefix + "zz" + vsaBindingCommit[2:], "sha1", "zz" + vsaBindingCommit[2:], false},
		{"name names another commit", vsaBindingPrefix, vsaBindingPrefix + "a" + vsaBindingCommit[1:], "sha1", vsaBindingCommit, false},
		{"not sha1", vsaBindingPrefix, vsaBindingPrefix + vsaBindingCommit, "gitoid:sha1", vsaBindingCommit, false},
		{"sha256 alg", vsaBindingPrefix, vsaBindingPrefix + vsaBindingCommit, "sha256", vsaBindingCommit, false},
	}
	for _, tc := range cases {
		if got := IsDeclaredCommitSubject(tc.prefix, tc.subject, tc.alg, tc.v); got != tc.want {
			t.Errorf("%s: IsDeclaredCommitSubject = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The scope arm: only a scope carrying the declared prefix admits the SHA-1
// subject, and the declared prefix never widens the hardened-git arm or the
// allowlisted algorithms.
func TestVsaBindingScopeArm(t *testing.T) {
	name := vsaBindingPrefix + vsaBindingCommit
	if (SubjectMatchScope{}).IsMatchableSubjectDigest(name, "sha1", vsaBindingCommit) {
		t.Fatal("zero scope must not admit a declared-prefix SHA-1 subject")
	}
	if (SubjectMatchScope{HardenedGitAttested: true}).IsMatchableSubjectDigest(name, "sha1", vsaBindingCommit) {
		t.Fatal("the hardened git arm must not admit a pushgate-named SHA-1 subject")
	}
	scope := SubjectMatchScope{CommitSubjectPrefix: vsaBindingPrefix}
	if !scope.IsMatchableSubjectDigest(name, "sha1", vsaBindingCommit) {
		t.Fatal("declared prefix must admit its exact subject")
	}
	if scope.IsMatchableSubjectDigest("commithash:"+vsaBindingCommit, "sha1", vsaBindingCommit) {
		t.Fatal("declared prefix must not admit the bare git form")
	}
	if scope.IsMatchableSubjectDigest("pkg:x", "sha1", vsaBindingCommit) {
		t.Fatal("declared prefix must not admit an arbitrary SHA-1 subject")
	}
	// Allowlisted algorithms are unaffected.
	sha := strings.Repeat("ab", 32)
	if !scope.IsMatchableSubjectDigest("pkg:x", "sha256", sha) {
		t.Fatal("sha256 must stay matchable")
	}
}
