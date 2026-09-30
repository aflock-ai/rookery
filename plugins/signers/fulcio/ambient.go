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

package fulcio

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/cijobtoken"
)

// DefaultGitLabOIDCVariable is the id_tokens variable CI/lock reads on GitLab when
// --signer-fulcio-token-env is not set. It is the name GitLab's own Sigstore
// example uses: "The token can be used by Cosign automatically when it is set
// in the SIGSTORE_ID_TOKEN environment variable."
// (https://docs.gitlab.com/ci/yaml/signing_examples/)
const DefaultGitLabOIDCVariable = cijobtoken.DefaultFulcioVar

// fulcioAudience is the audience every Fulcio CA (public Sigstore and the
// TestifySec platform) requires; a token minted for another audience is refused.
const fulcioAudience = "sigstore"

const ambientFetchTimeout = 30 * time.Second

// envTrue is the exact value GitHub, GitLab, Buildkite and CircleCI set in
// their CI marker variables; any other value does not count.
const envTrue = "true"

// ambientSource is the process environment, a command runner and a clock,
// injected so the detection can be tested without a real CI.
type ambientSource struct {
	getenv  func(string) string
	environ func() []string
	now     func() int64
	run     func(ctx context.Context, name string, args ...string) (string, error)
}

func osAmbientSource() ambientSource {
	return ambientSource{getenv: os.Getenv, environ: os.Environ, now: func() int64 { return time.Now().Unix() }, run: runTokenCommand}
}

func runTokenCommand(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, ambientFetchTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // fixed vendor CLI and arguments, no shell
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return "", fmt.Errorf("%w: %s", err, msg)
	}
	return stdout.String(), nil
}

// ambientCIToken fetches the job's OIDC token, with the sigstore audience, on
// the non-GitHub CIs a Fulcio CA maps (#9839). It returns ci == "" and no
// error when the process is not on one of them. On one of them it returns
// the token or a refusal naming the fix; it never falls through to another
// token source, because a CI job has no browser for the interactive flow.
//
// It runs in the cilock process at signing time, reading cilock's own
// environment, so it does not depend on what the wrapped command's
// environment contains.
func ambientCIToken(ctx context.Context, src ambientSource, gitlabTokenEnv string) (token, ci string, err error) {
	switch {
	case src.getenv("GITLAB_CI") == envTrue:
		// GitLab sets GITLAB_CI=true in every job; the ID token exists only if
		// the job declares it with id_tokens.
		// https://docs.gitlab.com/ci/secrets/id_token_authentication/
		// cijobtoken.Select takes only a token this job's GitLab issued to this
		// job for exactly aud "sigstore", under any variable name (or only the
		// one named with --signer-fulcio-token-env).
		ci = "GitLab CI"
		job, _ := cijobtoken.JobFromEnv(src.getenv)
		tok, selErr := cijobtoken.Select(src.environ(), job, fulcioAudience, gitlabTokenEnv, src.now())
		if selErr != nil {
			return "", ci, fmt.Errorf("%w (or pass --signer-fulcio-token)", selErr)
		}
		return tok.Raw, ci, nil
	case src.getenv("BUILDKITE") == envTrue:
		// https://buildkite.com/docs/agent/v3/cli-oidc
		ci = "Buildkite"
		out, runErr := src.run(ctx, "buildkite-agent", "oidc", "request-token", "--audience", fulcioAudience)
		if runErr != nil {
			return "", ci, fmt.Errorf("buildkite: `buildkite-agent oidc request-token --audience %s` failed: %w", fulcioAudience, runErr)
		}
		token, err = checkJWT(ci, out)
		return token, ci, err
	case src.getenv("CIRCLECI") == envTrue:
		// $CIRCLE_OIDC_TOKEN and $CIRCLE_OIDC_TOKEN_V2 carry aud=<org id>, which
		// Fulcio refuses, so the token is minted with the sigstore audience.
		// https://circleci.com/docs/guides/permissions-authentication/oidc-tokens-with-custom-claims/
		ci = "CircleCI"
		claims := `{"aud":"` + fulcioAudience + `"}`
		out, runErr := src.run(ctx, "circleci", "run", "oidc", "get", "--claims", claims)
		if runErr != nil {
			return "", ci, fmt.Errorf("circleci: `circleci run oidc get --claims '%s'` failed: %w", claims, runErr)
		}
		token, err = checkJWT(ci, out)
		return token, ci, err
	}
	return "", "", nil
}

// AmbientCIDetected reports whether ambientCIToken would act, so Signer can
// route to it without fetching anything.
func AmbientCIDetected(getenv func(string) string) bool {
	return getenv("GITLAB_CI") == envTrue || getenv("BUILDKITE") == envTrue || getenv("CIRCLECI") == envTrue
}

// checkJWT trims the fetched value and refuses anything that is not a compact
// JWT, so a vendor CLI's error text is never sent to Fulcio as a token. The
// value itself is never echoed.
func checkJWT(ci, raw string) (string, error) {
	tok := strings.TrimSpace(raw)
	if strings.Count(tok, ".") != 2 || strings.ContainsAny(tok, " \t\r\n") {
		return "", fmt.Errorf("%s: the OIDC token fetched for Fulcio is not a JWT", ci)
	}
	return tok, nil
}
