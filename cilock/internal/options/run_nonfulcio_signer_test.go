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

package options

import (
	"testing"

	// Register both signer providers so AddFlags wires --signer-fulcio-* AND
	// --signer-file-* — the conflict this test guards against.
	_ "github.com/aflock-ai/rookery/plugins/signers/file"
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

// TestFulcioSignerNeedsToken_NonFulcioSignerSuppresses pins the fix for the Codex
// finding on #5367: when the operator explicitly selects a non-fulcio signer
// (--signer-file-key-path / KMS / SPIFFE), the ambient/session keyless wiring must
// NOT also attach a fulcio token. cilock accepts exactly one signer, so a second
// (fulcio) signer would fail "only one signer is supported" in any CI job that
// runs with id-token: write present. fulcioSignerNeedsToken is the single gate
// both keyless paths (run + sign, session + workflow OIDC) consult.
func TestFulcioSignerNeedsToken_NonFulcioSignerSuppresses(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{
			name: "bare run wants the keyless token",
			args: []string{"--platform-url", "https://platform.example.com"},
			want: true,
		},
		{
			name: "explicit file signer suppresses the keyless token",
			args: []string{"--signer-file-key-path", "/tmp/key.pem"},
			want: false,
		},
		{
			name: "file signer alongside platform-url still suppresses",
			args: []string{"--platform-url", "https://platform.example.com", "--signer-file-key-path", "/tmp/key.pem"},
			want: false,
		},
		{
			name: "explicit fulcio token already chosen ⇒ no auto-fill",
			args: []string{"--signer-fulcio-token", "operator-token"},
			want: false,
		},
		{
			name: "fulcio-url alone (selecting fulcio) still wants the token",
			args: []string{"--signer-fulcio-url", "https://platform.example.com"},
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, _ := newRunCmd(t)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags(%v): %v", tc.args, err)
			}
			if got := fulcioSignerNeedsToken(cmd); got != tc.want {
				t.Fatalf("fulcioSignerNeedsToken(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

// TestNonFulcioSignerSelected covers the provider classifier directly, including
// the boundary cases: a fulcio-prefixed flag must NOT count as a non-fulcio
// signer, and unrelated flags (--platform-url) must be ignored.
func TestNonFulcioSignerSelected(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{name: "nothing selected", args: nil, want: false},
		{name: "only platform-url", args: []string{"--platform-url", "https://p.example.com"}, want: false},
		{name: "fulcio token is not non-fulcio", args: []string{"--signer-fulcio-token", "t"}, want: false},
		{name: "fulcio url is not non-fulcio", args: []string{"--signer-fulcio-url", "https://p.example.com"}, want: false},
		{name: "file signer is non-fulcio", args: []string{"--signer-file-key-path", "/tmp/k.pem"}, want: true},
		{name: "file + fulcio ⇒ non-fulcio present", args: []string{"--signer-file-key-path", "/tmp/k.pem", "--signer-fulcio-url", "https://p.example.com"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, _ := newRunCmd(t)
			if err := cmd.ParseFlags(tc.args); err != nil {
				t.Fatalf("ParseFlags(%v): %v", tc.args, err)
			}
			if got := nonFulcioSignerSelected(cmd); got != tc.want {
				t.Fatalf("nonFulcioSignerSelected(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}
