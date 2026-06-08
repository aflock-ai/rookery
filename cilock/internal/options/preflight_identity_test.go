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
	"strings"
	"testing"

	// Register both signer providers so AddFlags wires --signer-fulcio-* AND
	// --signer-file-* (the -k local-key path the gate must stand down for).
	_ "github.com/aflock-ai/rookery/plugins/signers/file"
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

// clearAmbientOIDC removes the GitHub Actions OIDC env vars so a test runner that
// happens to be inside Actions doesn't accidentally satisfy the CI stand-down
// branch of PreflightIdentity.
func clearAmbientOIDC(t *testing.T) {
	t.Helper()
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
}

// TestPreflightIdentity_ColdRunNoSessionNoCI is the headline first-run case: a
// brand-new operator runs `cilock run --platform-url <url>` with no `cilock
// login`, no local key, and no ambient CI OIDC identity. PreflightIdentity must
// return an actionable error that names `cilock login` BEFORE signer
// construction, instead of the opaque Fulcio dead-end the run would otherwise
// hit ("failed to load any signers" / "no token provided").
func TestPreflightIdentity_ColdRunNoSessionNoCI(t *testing.T) {
	isolateCredentialStore(t) // no stored session
	clearAmbientOIDC(t)       // not in CI

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", "https://platform.example.com"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	ro.ResolvePlatformDefaults(cmd)

	err := ro.PreflightIdentity(cmd)
	if err == nil {
		t.Fatal("cold run with no session and no CI identity must be gated with a friendly error, got nil")
	}
	msg := err.Error()
	for _, want := range []string{"not signed in", "cilock login", "https://platform.example.com"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("gate error %q missing expected substring %q", msg, want)
		}
	}
}

// TestPreflightIdentity_ColdRunExplicitFulcioURL covers the OTHER cold dead-end:
// the operator explicitly selected the fulcio signer (--signer-fulcio-url) but is
// not logged in, which without the gate dies in Fulcio with "no token provided".
// The gate fires here too because there is still no usable signing identity.
func TestPreflightIdentity_ColdRunExplicitFulcioURL(t *testing.T) {
	isolateCredentialStore(t)
	clearAmbientOIDC(t)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", "https://platform.example.com",
		"--signer-fulcio-url", "https://platform.example.com",
	}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if err := ro.PreflightIdentity(cmd); err == nil {
		t.Fatal("explicit --signer-fulcio-url with no session/CI identity must be gated, got nil")
	}
}

// TestPreflightIdentity_StandsDown enumerates every path that CAN sign — the gate
// must return nil for all of them so it never blocks a working invocation.
func TestPreflightIdentity_StandsDown(t *testing.T) {
	t.Run("local key (-k) needs no platform identity", func(t *testing.T) {
		isolateCredentialStore(t)
		clearAmbientOIDC(t)
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{
			"--platform-url", "https://platform.example.com",
			"--signer-file-key-path", "/tmp/key.pem",
		}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if err := ro.PreflightIdentity(cmd); err != nil {
			t.Fatalf("local-key run must NOT be gated, got %v", err)
		}
	})

	t.Run("explicit --signer-fulcio-token (CI OIDC / interactive)", func(t *testing.T) {
		isolateCredentialStore(t)
		clearAmbientOIDC(t)
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{
			"--platform-url", "https://platform.example.com",
			"--signer-fulcio-token", "operator-supplied-token",
		}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if err := ro.PreflightIdentity(cmd); err != nil {
			t.Fatalf("explicit-token run must NOT be gated, got %v", err)
		}
	})

	t.Run("offline (--platform-url \"\") has no platform signing to gate", func(t *testing.T) {
		isolateCredentialStore(t)
		clearAmbientOIDC(t)
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", ""}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if err := ro.PreflightIdentity(cmd); err != nil {
			t.Fatalf("offline run must NOT be gated, got %v", err)
		}
	})

	t.Run("--offline alias is not gated", func(t *testing.T) {
		isolateCredentialStore(t)
		clearAmbientOIDC(t)
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--offline"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if err := ro.PreflightIdentity(cmd); err != nil {
			t.Fatalf("--offline run must NOT be gated, got %v", err)
		}
	})

	t.Run("ambient CI workflow OIDC signs keyless, no login needed", func(t *testing.T) {
		isolateCredentialStore(t)
		// Ambient GitHub Actions OIDC identity present.
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.example/req")
		t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "bearer-xyz")
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", "https://platform.example.com"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if err := ro.PreflightIdentity(cmd); err != nil {
			t.Fatalf("ambient CI run must NOT be gated, got %v", err)
		}
	})

	t.Run("logged-in session is not gated", func(t *testing.T) {
		isolateCredentialStore(t)
		clearAmbientOIDC(t)
		resolveSeedCredential(t, "https://platform.example.com")
		cmd, ro := newRunCmd(t)
		if err := cmd.ParseFlags([]string{"--platform-url", "https://platform.example.com"}); err != nil {
			t.Fatalf("ParseFlags: %v", err)
		}
		ro.ResolvePlatformDefaults(cmd)
		if err := ro.PreflightIdentity(cmd); err != nil {
			t.Fatalf("logged-in run must NOT be gated, got %v", err)
		}
	})
}
