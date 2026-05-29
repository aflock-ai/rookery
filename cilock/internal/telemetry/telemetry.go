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
// IDENTITY / AUTH GATE: telemetry is sent ONLY when the user is authenticated to
// a Judge platform — i.e. a non-expired credential exists (see internal/auth).
// An offline / unauthenticated cilock sends nothing. The platform session JWT is
// the bearer (the hub verifies it platform-side; we never send the user's
// GitHub token). The cross-property join key is the authenticated user's Email.
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

	cred, err := auth.Lookup(config.DefaultPlatformURL)
	if err != nil || cred == nil || cred.Token == "" {
		return // no authenticated platform session -> send nothing
	}

	ci, provider := detectCI()
	account := cred.TenantName
	if account == "" {
		account = cred.TenantID
	}

	body, err := json.Marshal(map[string]any{
		"account":     account,
		"user_ref":    cred.Email, // cross-property identity join key
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
	req.Header.Set("Authorization", "Bearer "+cred.Token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
