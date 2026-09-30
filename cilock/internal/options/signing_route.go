// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"fmt"

	"github.com/aflock-ai/rookery/attestation/cijobtoken"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// sessionKind is the stored platform credential for the run's platform URL.
type sessionKind string

const (
	sessionNone     sessionKind = "none"
	sessionBearer   sessionKind = "bearer"   // browser login or --token
	sessionWorkflow sessionKind = "workflow" // a workflow-identity marker; the CI identity signs
)

// signingInputs is everything decideSigningRoute reads.
type signingInputs struct {
	PlatformDisabled bool
	LocalSigner      bool // -k, --signer-file-*, KMS, Vault, SPIFFE
	ExplicitToken    bool // an operator-supplied --signer-fulcio-token / -token-path / -oidc-issuer
	Session          sessionKind
	Provider         auth.CIProvider
	GitHubCanMint    bool
	// GitLabFulcio is this GitLab job's token selected for aud "sigstore", or
	// the refusal. Read only when Provider is GitLab.
	GitLabFulcio    cijobtoken.Token
	GitLabFulcioErr error
}

// Signing route kinds, one per constructor of the model's `Route`.
const (
	routeOffline         = "offline"
	routeLocalKey        = "localKey"
	routeExplicitToken   = "explicitToken"
	routeSessionExchange = "sessionExchange"
	routeGitHubMint      = "githubMint"
	routeGitLabToken     = "gitlabToken"
	routeSignerFetch     = "signerFetch"
	routeRefuse          = "refuse"
)

type signingRoute struct {
	Kind string
	Var  string // routeGitLabToken: the id_tokens variable sent to Fulcio
	Why  string // routeRefuse: "notSignedIn" or "gitlab:<refusal kind>"
	Err  error  // routeRefuse: the message the operator sees
}

// decideSigningRoute is how `cilock run` will sign, decided before the wrapped
// command runs. It is the model's `route` (formal/cilock-ci,
// CilockCi/Plan.lean), and the theorems there hold of it while the
// differential test agrees: a CI-identity keyless route always has a job token
// behind it (GitHub's endpoint, or a GitLab token issued to this job for
// exactly "sigstore"), and GitHub and GitLab jobs in equivalent states take
// the same kind of route.
// refusalKindUnknown names a GitLab token refusal that is not a cijobtoken.Refusal.
const refusalKindUnknown = "unknown"

func decideSigningRoute(in signingInputs, platformURL string) signingRoute {
	switch {
	case in.PlatformDisabled:
		return signingRoute{Kind: routeOffline}
	case in.LocalSigner:
		return signingRoute{Kind: routeLocalKey}
	case in.ExplicitToken:
		return signingRoute{Kind: routeExplicitToken}
	case in.Session == sessionBearer:
		return signingRoute{Kind: routeSessionExchange}
	}
	switch in.Provider {
	case auth.CIGitHub:
		if in.GitHubCanMint {
			return signingRoute{Kind: routeGitHubMint}
		}
	case auth.CIGitLab:
		if in.GitLabFulcioErr == nil {
			return signingRoute{Kind: routeGitLabToken, Var: in.GitLabFulcio.Var}
		}
		kind := refusalKindUnknown
		if r, ok := in.GitLabFulcioErr.(*cijobtoken.Refusal); ok {
			kind = r.Kind
		}
		return signingRoute{Kind: routeRefuse, Why: "gitlab:" + kind,
			Err: fmt.Errorf("cannot sign keyless in this GitLab CI job: %w; or pass -k/--signer-file-key-path for a local key (or --offline to skip platform signing)", in.GitLabFulcioErr)}
	case auth.CIBuildkite, auth.CICircleCI:
		return signingRoute{Kind: routeSignerFetch}
	}
	return signingRoute{Kind: routeRefuse, Why: "notSignedIn",
		Err: fmt.Errorf("not signed in to %s; run 'cilock login' first, "+
			"or pass -k/--signer-file-key-path for a local key (or --offline to skip platform signing)", platformURL)}
}
