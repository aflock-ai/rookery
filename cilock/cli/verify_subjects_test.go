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
	"crypto"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
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
