// Copyright 2025 The Aflock Authors
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

// Package telemetry sends best-effort cilock CLI usage telemetry to the
// cross-property analytics hub (analytics.testifysec.com/cli/t), so CLI usage
// can be stitched to the same user's cilock.dev / testifysec.com web activity.
//
// IDENTITY / AUTH GATE: telemetry is sent ONLY when the user holds a usable
// platform session BEARER — a non-expired credential with a non-empty Token (see
// internal/auth). An offline / unauthenticated cilock sends nothing. The platform
// session JWT is the bearer (the hub verifies it platform-side; we never send the
// user's GitHub token). The cross-property join key is the authenticated user's
// Email.
//
// AMBIENT GitHub Actions OIDC (keyless CI) is a deliberate exception: cilock IS
// interacting with a platform, but `cilock login` in CI stores only a workflow-
// identity marker with no bearer, and the only platform-acceptable credential is
// the raw GHA OIDC token — whose claims embed repo/org/ref/sha, the very
// identifiers this package never transmits. So the ambient path sends NOTHING
// today (it does not weaken the redaction invariant). See the Report no-bearer
// branch for the full blocker analysis and the seam where a future telemetry-
// scoped bearer would be wired.
//
// USAGE METADATA ONLY: command verb, os/arch, version, CI flags, outcome. It
// NEVER transmits artifact/file digests, paths, repo/org names, signer subjects,
// secrets, tokens (other than the user's own platform bearer), or attestation
// contents. Opt out with CILOCK_NO_TELEMETRY=1 or DO_NOT_TRACK=1.
package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// endpoint is the cross-property analytics hub URL. It is a var rather than a
// const purely so tests can redirect it to a local httptest server; production
// builds never reassign it.
var endpoint = "https://analytics.testifysec.com/cli/t"

func optedOut() bool {
	for _, k := range []string{"CILOCK_NO_TELEMETRY", "DO_NOT_TRACK"} {
		switch strings.ToLower(strings.TrimSpace(os.Getenv(k))) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

func detectCI() (bool, string) {
	switch {
	case os.Getenv("GITHUB_ACTIONS") != "":
		return true, "github_actions"
	case os.Getenv("GITLAB_CI") != "":
		return true, "gitlab"
	case os.Getenv("JENKINS_URL") != "":
		return true, "jenkins"
	case os.Getenv("CIRCLECI") != "":
		return true, "circleci"
	case strings.EqualFold(os.Getenv("CI"), "true"), os.Getenv("CI") == "1":
		return true, "unknown"
	}
	return false, "local"
}

// Report sends one best-effort usage event for a completed command. It enforces
// a short timeout and swallows every error — telemetry must never change the
// CLI's behavior or exit code. It no-ops when opted out or unauthenticated.
func Report(commandName, version, outcome string) {
	if optedOut() || commandName == "" {
		return
	}

	// Attribute the event to the platform the command actually interacted with:
	// run/verify set CILOCK_PLATFORM_URL when they bind to a logged-in platform
	// session, so telemetry follows the platform the user is really using
	// (staging, self-hosted, or any --platform-url). Falls back to the compiled-in
	// default. Without this, usage against a non-default platform was silently
	// dropped because the lookup only ever checked the default (production) URL.
	platformURL := strings.TrimSpace(os.Getenv(config.PlatformURLEnv))
	if platformURL == "" {
		platformURL = config.DefaultPlatformURL
	}

	cred, err := auth.Lookup(platformURL)
	if err != nil || cred == nil || cred.Token == "" {
		// No usable bearer token for the resolved platform. This covers three
		// distinct states, all of which must send nothing:
		//
		//   - not logged in at all (offline / own-keys);
		//   - an expired/empty stored credential;
		//   - AMBIENT GitHub Actions OIDC (keyless CI). `cilock login` in CI
		//     stores only a workflow-identity MARKER (auth.AuthModeWorkflowOIDC,
		//     empty Token); the platform-acceptable bearer in that mode is the
		//     raw GitHub Actions OIDC token, sourced fresh per call by run/sign.
		//
		// We deliberately do NOT emit telemetry in the ambient case today, even
		// though cilock IS interacting with a TestifySec platform: the only
		// bearer available is the GHA OIDC token, whose claims embed repo / org /
		// ref / sha — exactly the identifiers this package promises never to
		// transmit. Sending it to the analytics hub (which may log the bearer)
		// would weaken the redaction invariant, and the hub's acceptance of a
		// foreign-issuer OIDC bearer is unverified. Emitting nothing is the
		// honest, privacy-preserving choice until a telemetry-scoped, identity-
		// only platform bearer exists for the ambient path. See the package
		// doc comment and the TestReportAmbient* cases for the full analysis;
		// when a telemetry-scoped, identity-only platform bearer exists for the
		// ambient case, resolve it here and call postEvent.
		return
	}

	account := cred.TenantName
	if account == "" {
		account = cred.TenantID
	}
	postEvent(cred.Token, account, cred.Email, commandName, version, outcome)
}

// postEvent builds and sends a single usage event. The bearer travels ONLY in
// the Authorization header — never in the JSON body — preserving the redaction
// invariant. It swallows every error so telemetry never affects the CLI.
func postEvent(bearer, account, userRef, commandName, version, outcome string) {
	ci, provider := detectCI()

	body, err := json.Marshal(map[string]any{
		"account":     account,
		"user_ref":    userRef, // cross-property identity join key
		"command":     commandName,
		"cli_version": version,
		"os":          runtime.GOOS,
		"arch":        runtime.GOARCH,
		"ci":          ci,
		"ci_provider": provider,
		"outcome":     outcome,
	})
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
