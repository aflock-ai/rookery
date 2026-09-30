// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aflock-ai/rookery/attestation/cijobtoken"
)

// CIProvider is the CI a process runs in, as cilock's own code decides it.
type CIProvider string

const (
	CINone      CIProvider = "none"
	CIGitHub    CIProvider = "github"
	CIGitLab    CIProvider = "gitlab"
	CIBuildkite CIProvider = "buildkite"
	CICircleCI  CIProvider = "circleci"
)

// envTrue is how every CI marker variable says "set".
const envTrue = "true"

// CIProviderFromEnv is the one place cilock decides which CI it is in. It is
// the model's `provider` (formal/cilock-ci, CilockCi/Automode.lean).
//
// GitLab is checked first: its tokens are the ones cilock would select, and a
// real job cannot carry both vendors' markers. GitHub counts on its
// GITHUB_ACTIONS marker OR its token endpoint; whether it can mint is
// GitHubCanMint.
func CIProviderFromEnv(getenv func(string) string) CIProvider {
	switch {
	case getenv("GITLAB_CI") == envTrue:
		return CIGitLab
	case getenv("GITHUB_ACTIONS") == envTrue || getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "":
		return CIGitHub
	case getenv("BUILDKITE") == envTrue:
		return CIBuildkite
	case getenv("CIRCLECI") == envTrue:
		return CICircleCI
	}
	return CINone
}

// InCI reports whether cilock runs in CI: CI=true, or any detected provider.
// There is no browser there, so nothing may start an interactive flow (the
// model's `inCI`, formal/cilock-ci CilockCi/Login.lean).
func InCI(getenv func(string) string) bool {
	return getenv("CI") == envTrue || CIProviderFromEnv(getenv) != CINone
}

// ErrBrowserInCI is returned by BrowserLogin in CI instead of waiting on a
// browser nobody will open.
var ErrBrowserInCI = errors.New("refusing to start a browser login in CI (CI=true or a CI provider detected): nobody can approve it, and the job would hang to its timeout; use workflow identity or --token")

// GitHubCanMint reports whether the GitHub Actions token endpoint is usable
// (`permissions: id-token: write`).
func GitHubCanMint(getenv func(string) string) bool {
	return getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" && getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != ""
}

// nowUnix is the clock the GitLab token expiry check reads; a var for tests.
var nowUnix = func() int64 { return time.Now().Unix() }

// environ is the process environment the GitLab token selection scans; a var
// for tests.
var environ = os.Environ

// GitLabJobToken selects this GitLab job's ID token for audience (see
// cijobtoken.Select): issued by CI_SERVER_URL to CI_JOB_ID, for exactly that
// audience, not expired. It never falls back to another source.
func GitLabJobToken(audience string) (cijobtoken.Token, error) {
	job, ok := cijobtoken.JobFromEnv(os.Getenv)
	if !ok {
		return cijobtoken.Token{}, fmt.Errorf("not a GitLab CI job (GITLAB_CI is not \"true\")")
	}
	return cijobtoken.Select(environ(), job, audience, "", nowUnix())
}

// FetchCIOIDCToken returns this CI job's OIDC token for audience: minted by
// the GitHub Actions endpoint, or selected from the GitLab job's declared
// id_tokens. It is the only token source cilock's workflow identity uses, and
// it never returns a token minted for another audience. The token is a
// credential and must not be logged.
func FetchCIOIDCToken(audience string) (string, error) {
	switch CIProviderFromEnv(os.Getenv) {
	case CIGitLab:
		tok, err := GitLabJobToken(audience)
		if err != nil {
			return "", err
		}
		return tok.Raw, nil
	case CIGitHub:
		return fetchWorkflowOIDCToken(audience)
	}
	return "", fmt.Errorf("no CI job identity: not in GitHub Actions (with `permissions: id-token: write`) or a GitLab CI job")
}

// GitLabJob returns the GitLab job this process runs in (CI_SERVER_URL,
// CI_JOB_ID), and false when it is not a GitLab CI job.
func GitLabJob() (cijobtoken.Job, bool) { return cijobtoken.JobFromEnv(os.Getenv) }
