// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"os"
	"time"

	"github.com/aflock-ai/rookery/attestation/cijobtoken"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	fulciosigner "github.com/aflock-ai/rookery/plugins/signers/fulcio"
	"github.com/spf13/cobra"
)

// osGetenv is the process environment, read by cilock itself (never the
// wrapped command's), for selectAmbientCIFulcio.
var osGetenv = os.Getenv

// osEnviron and nowUnix feed the GitLab ID token selection; vars for tests.
var (
	osEnviron = os.Environ
	nowUnix   = func() int64 { return time.Now().Unix() }
)

// selectAmbientCIFulcio selects the platform Fulcio signer on Buildkite and
// CircleCI (#9839), so a bare `cilock run --platform-url X` signs keyless there
// as it does on GitHub Actions and GitLab CI. It only points the signer at
// fulcioURL; the signer itself asks the CI agent for the job's OIDC token at
// signing time (plugins/signers/fulcio/ambient.go) and refuses with the fix
// when it cannot. GitLab CI takes the workflow-identity path instead
// (resolvePlatformIdentity), because its tokens are already in the
// environment and can be checked before the build.
//
// It never overrides a choice: an explicit non-fulcio signer or a
// user-supplied --signer-fulcio-url is left alone. Returns whether it selected
// the signer.
func selectAmbientCIFulcio(cmd *cobra.Command, fulcioURL string, getenv func(string) string) bool {
	if fulcioURL == "" || !fulciosigner.AmbientCIDetected(getenv) || nonFulcioSignerSelected(cmd) {
		return false
	}
	f := cmd.Flags().Lookup("signer-fulcio-url")
	if f == nil || f.Changed {
		return false
	}
	return cmd.Flags().Set("signer-fulcio-url", fulcioURL) == nil
}

// gitlabFulcioTokenVar is the --signer-fulcio-token-env value, or "" when the
// operator named no variable (the token is then found by its claims).
func gitlabFulcioTokenVar(cmd *cobra.Command) string {
	if f := cmd.Flags().Lookup("signer-fulcio-token-env"); f != nil {
		return f.Value.String()
	}
	return ""
}

// selectGitLabToken selects this GitLab job's ID token for aud (see
// cijobtoken.Select). explicitVar restricts it to one variable.
func selectGitLabToken(aud, explicitVar string) (cijobtoken.Token, error) {
	job, _ := cijobtoken.JobFromEnv(osGetenv)
	return cijobtoken.Select(osEnviron(), job, aud, explicitVar, nowUnix())
}

// ciOIDCToken is this CI job's OIDC token for audience: selected from a GitLab
// job's id_tokens, or minted by the GitHub Actions endpoint. Never a token
// minted for another audience.
func ciOIDCToken(audience string) (string, error) {
	if auth.CIProviderFromEnv(osGetenv) == auth.CIGitLab {
		tok, err := selectGitLabToken(audience, "")
		return tok.Raw, err
	}
	return fetchGitHubOIDCToken(audience)
}

// ciFulcioToken is ciOIDCToken for the Fulcio signer, honouring
// --signer-fulcio-token-env on GitLab.
func ciFulcioToken(cmd *cobra.Command, audience string) (string, error) {
	if auth.CIProviderFromEnv(osGetenv) == auth.CIGitLab {
		tok, err := selectGitLabToken(audience, gitlabFulcioTokenVar(cmd))
		return tok.Raw, err
	}
	return fetchGitHubOIDCToken(audience)
}

// signingInputsFor reads decideSigningRoute's inputs from the command, the
// resolved run options and the process environment.
func (ro *RunOptions) signingInputsFor(cmd *cobra.Command) signingInputs {
	in := signingInputs{
		PlatformDisabled: (cmd.Flags().Changed("platform-url") || ro.Offline) && ro.PlatformURL == "",
		LocalSigner:      nonFulcioSignerSelected(cmd),
		// A token cilock installed itself (the CI identity) is not the
		// operator's: that case is the CI route below.
		ExplicitToken: explicitFulcioTokenSource(cmd) && !ro.signerWorkflowIdentity,
		Session:       sessionNone,
		Provider:      auth.CIProviderFromEnv(osGetenv),
		GitHubCanMint: auth.GitHubCanMint(osGetenv),
	}
	if cred, err := auth.LookupAny(ro.PlatformURL); err == nil && cred != nil {
		in.Session = sessionBearer
		if cred.AuthMode == auth.AuthModeWorkflowOIDC {
			in.Session = sessionWorkflow
		}
	}
	if in.Provider == auth.CIGitLab {
		in.GitLabFulcio, in.GitLabFulcioErr = selectGitLabToken(cijobtoken.FulcioAudience, gitlabFulcioTokenVar(cmd))
	}
	return in
}

// useGitLabJobTokens finishes the GitLab side of the workflow identity. GitHub
// mints the Archivista upload token on demand and --archivista-oidc defaults
// on there; a GitLab job has one only if it declared one for exactly the
// platform Archivista audience, so --archivista-oidc turns on when (and only
// when) that token is selectable and the operator did not set the flag. It
// also says which variables the run uses (names, never values), so a job log
// shows what signed and what uploaded.
func (ro *RunOptions) useGitLabJobTokens(cmd *cobra.Command) {
	if auth.CIProviderFromEnv(osGetenv) != auth.CIGitLab {
		return
	}
	job, _ := cijobtoken.JobFromEnv(osGetenv)
	if tok, err := selectGitLabToken(cijobtoken.FulcioAudience, gitlabFulcioTokenVar(cmd)); err == nil && ro.signerWorkflowIdentity {
		log.Infof("GitLab CI job %s: signing keyless with $%s (aud %s)", job.JobID, tok.Var, cijobtoken.FulcioAudience)
	}
	if cmd.Flags().Changed("archivista-oidc") || ro.ArchivistaOptions.Audience == "" {
		return
	}
	tok, err := selectGitLabToken(ro.ArchivistaOptions.Audience, "")
	if err != nil {
		log.Infof("GitLab CI job %s: no ID token for the Archivista upload (%v)", job.JobID, err)
		return
	}
	ro.ArchivistaOptions.OIDC = true
	// The upload itself is switched on, and held by the evidence gate, by
	// holdAmbientIdentityToStore once the binding is marked (run.go).
	log.Infof("GitLab CI job %s: authenticating the Archivista upload with $%s (aud %s)", job.JobID, tok.Var, ro.ArchivistaOptions.Audience)
}

// markAmbientPlatformBinding exposes the platform URL to the platform attestor
// so it binds a run authenticated by a CI workflow identity (with or without
// a `cilock login` marker) to its tenant: the CI job's own OIDC token
// authenticates the Archivista upload (ArchivistaOptions.OIDC), and the
// platform resolves the tenant and product server-side from that credential.
// Same-origin guard: never advertise the platform binding for an upload aimed
// at a third-party --archivista-server (the OIDC token, and the binding it
// implies, only make sense against the platform's own Archivista).
//
// CILOCK_PLATFORM_URL alone is user-controllable (inheritable env), so the
// attestor also requires the in-process trust mark set here, after the
// same-origin check. That closes the confused-deputy gap where a hostile CI
// step exports CILOCK_PLATFORM_URL to forge a platform binding.
//
// It reports whether it marked the binding: the upload authenticates with the
// job's token at the platform's own Archivista.
func (ro *RunOptions) markAmbientPlatformBinding(pc platformconfig.PlatformConfig) bool {
	if !ro.ArchivistaOptions.OIDC || !sameOrigin(ro.ArchivistaOptions.Url, pc.Archivista) {
		return false
	}
	normalized := auth.NormalizeURL(ro.PlatformURL)
	_ = os.Setenv(platformURLEnv, normalized)
	platformconfig.MarkTrustedPlatformBinding(normalized)
	return true
}
