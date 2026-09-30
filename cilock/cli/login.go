// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// LoginCmd signs in to a TestifySec platform and stores a session credential.
func LoginCmd() *cobra.Command {
	var platformURL, token, tenant, product string
	var tenantID, tenantName, productID, productName string
	var interactive, workflowIdentity, allowTrust bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to the TestifySec platform and store a session credential",
		Long: "Sign in to the TestifySec platform and store a session credential, so subsequent\n" +
			"cilock platform calls (attestation storage, signing-token exchange) are\n" +
			"authenticated. The browser approve page binds a working tenant AND product\n" +
			"(creating a default tenant/product if you have none) so every attestation is\n" +
			"scoped to one; switch them later with `cilock use`, or override per-command.\n\n" +
			"Identity is resolved by precedence:\n" +
			"  1. --token            an explicit JWT (CI/headless; '-' reads from stdin)\n" +
			"  2. workflow identity  the CI job's own OIDC identity; no browser, no stored secret.\n" +
			"                        GitHub Actions: auto-detected on the default platform, and\n" +
			"                        cilock run mints a fresh token per call. GitLab CI: the job's\n" +
			"                        id_tokens entry for <platform-url>/login, on any platform\n" +
			"                        (a token's audience is fixed by the pipeline); a GitLab job\n" +
			"                        never falls back to the browser.\n" +
			"  3. browser            interactive loopback login (default for local use)\n\n" +
			"--interactive forces the browser. --workflow-identity forces ambient OIDC (and on\n" +
			"GitHub Actions is required to send a workflow token to a non-default --platform-url).",
		Example: "  # Interactive browser login (binds tenant+product on the approve page)\n" +
			"  cilock login\n\n" +
			"  # CI on GitHub Actions: use the ambient workflow identity (auto-detected)\n" +
			"  cilock login   # with `permissions: id-token: write`\n\n" +
			"  # CI on GitLab: declare `id_tokens: {CILOCK_LOGIN_ID_TOKEN: {aud: $PLATFORM_URL/login}}`\n" +
			"  cilock login --platform-url https://platform.example.com --product <uuid>\n\n" +
			"  # CI/headless: provide a JWT plus the tenant+product to bind\n" +
			"  cilock login --platform-url https://platform.example.com --token $TESTIFYSEC_TOKEN \\\n" +
			"    --tenant-id <uuid> --product-id <uuid>",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			// Reject a non-loopback http:// platform URL before any login flow
			// runs or a session bearer is stored/sent (#5997): a typo, copy-paste,
			// or MITM downgrade must not be able to leak a replayable bearer over
			// cleartext to an attacker host.
			if err := config.RequireSecurePlatformURL(url); err != nil {
				return err
			}
			cred, err := resolveLoginCredential(cmd, url, token, tenant, product, interactive, workflowIdentity, allowTrust)
			if err != nil {
				return err
			}
			// Headless (--token) login binds tenant+product from flags — the browser
			// approve page supplies them for the interactive path. cilock binds every
			// attestation to a tenant+product, so the contract is enforced here too.
			if cred.AuthMode == auth.AuthModeToken {
				applyScopeFlags(cred, tenantID, tenantName, productID, productName)
				if cred.TenantID == "" || cred.ProductID == "" {
					return fmt.Errorf("--token login requires --tenant-id and --product-id " +
						"(cilock binds every attestation to a tenant+product); pass them, " +
						"run `cilock login` interactively, or set them later with `cilock use`")
				}
			}
			if err := auth.Save(*cred); err != nil {
				return err
			}
			printLoginResult(cmd.OutOrStdout(), url, cred)
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	cmd.Flags().StringVar(&token, "token", "", "JWT for CI/headless login (skips the browser); '-' reads it from stdin")
	cmd.Flags().StringVar(&tenant, "tenant", "", "Tenant id or name to pre-select on the approve page")
	cmd.Flags().StringVar(&product, "product", "", "Product id or name to pre-select on the approve page")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Tenant UUID to bind for a headless --token login")
	cmd.Flags().StringVar(&tenantName, "tenant-name", "", "Tenant name to record with --tenant-id")
	cmd.Flags().StringVar(&productID, "product-id", "", "Product UUID to bind for a headless --token login")
	cmd.Flags().StringVar(&productName, "product-name", "", "Product name to record with --product-id")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Force the interactive browser login (skip ambient CI workflow identity)")
	cmd.Flags().BoolVar(&workflowIdentity, "workflow-identity", false, "Use the CI job's own OIDC identity (GitHub Actions: auto-detected on the default platform, and required to send a workflow token to a non-default --platform-url; GitLab CI: the job's id_tokens entry for <platform-url>/login, used on any platform)")
	cmd.Flags().BoolVar(&allowTrust, "allow-trust", false, "Also grant the narrow oidc:write scope so this session can register CI trust with `cilock trust` (off by default)")
	return cmd
}

// loginTier is the resolved login method (see decideLoginTier).
type loginTier int

const (
	tierToken loginTier = iota
	tierWorkflow
	tierBrowser
)

// decideLoginTier resolves the login precedence — a pure function so the
// precedence and its security gates are unit-testable without I/O:
//
//  1. explicit --token            (highest)
//  2. ambient workflow OIDC       (auto only on the compiled-in default platform;
//     a non-default --platform-url requires an explicit
//     --workflow-identity opt-in)
//  3. interactive browser         (default for local use)
//
// Security gates: ambient auto-fire is limited to the default platform so a
// hostile --platform-url cannot harvest a replayable workflow token. A request
// that cannot be satisfied (--workflow-identity with no ambient identity, or
// ambient present against a non-default platform without opt-in) is a hard
// error — never a silent browser fallback, which in CI just hangs until timeout.
func decideLoginTier(token string, interactive, workflowIdentity, ambientAvailable bool, url, defaultURL string) (loginTier, error) {
	if token != "" {
		return tierToken, nil
	}
	if interactive {
		return tierBrowser, nil
	}
	if ambientAvailable {
		if url == defaultURL || workflowIdentity {
			return tierWorkflow, nil
		}
		return tierBrowser, fmt.Errorf("ambient workflow OIDC identity detected but --platform-url %q is not the default (%s); pass --workflow-identity to send a workflow-identity token to it, or use --token / --interactive", url, defaultURL)
	}
	if workflowIdentity {
		return tierBrowser, fmt.Errorf("--workflow-identity requested but no ambient OIDC identity is present (GitHub Actions needs `permissions: id-token: write`; a GitLab CI job needs `id_tokens:` with the platform login audience)")
	}
	return tierBrowser, nil
}

// loginTierInput is everything decideLoginTierCI reads, so the decision is a
// pure function the model can be compared against.
type loginTierInput struct {
	token                         string
	interactive, workflowIdentity bool
	provider                      auth.CIProvider
	githubCanMint                 bool
	// gitlabLoginErr is the result of selecting this GitLab job's token for the
	// platform's login audience (nil: one was selected). Read only for GitLab.
	gitlabLoginErr  error
	url, defaultURL string
	// ci is auth.InCI: CI=true or a detected provider. Nothing interactive
	// starts in CI.
	ci bool
}

var (
	errCINoIdentity    = errors.New("cilock login in CI found no workflow identity")
	errInteractiveInCI = errors.New("cilock login --interactive refused in CI")
)

// ciNoIdentityError names what to add, per provider; the model's
// `.refuse .ciNoIdentity`.
func ciNoIdentityError(p auth.CIProvider) error {
	switch p {
	case auth.CIGitHub:
		return fmt.Errorf("%w: GitHub Actions cannot mint an OIDC token for this job; add to the job:\n  permissions:\n    id-token: write\nor pass --token", errCINoIdentity)
	default:
		return fmt.Errorf("%w (CI=true): this CI has no workflow identity cilock can use, and there is no browser to approve a login; pass --token (a platform token from a CI secret) with --tenant-id and --product-id", errCINoIdentity)
	}
}

// decideLoginTierCI is decideLoginTier with GitLab CI. It is the model's
// `tier` (formal/cilock-ci, CilockCi/Login.lean).
//
// A GitLab job has no browser, so it never falls back to one: with no --token
// and no --interactive it signs in with the job token declared for exactly
// <platform>/login, or refuses naming the `id_tokens:` entry to add. Unlike
// GitHub it needs no --workflow-identity for a non-default --platform-url:
// GitHub mints a token for whatever audience cilock asks, so a hostile URL
// could harvest one, but a GitLab token's audience is fixed by the pipeline,
// so a URL the pipeline did not name finds no token to take.
func decideLoginTierCI(in loginTierInput) (loginTier, error) {
	if in.token != "" {
		return tierToken, nil
	}
	if in.interactive {
		if in.ci {
			return tierBrowser, fmt.Errorf("%w: there is no browser in CI (CI=true or a CI provider detected) and the job would hang to its timeout; drop --interactive and use the job's workflow identity or --token", errInteractiveInCI)
		}
		return tierBrowser, nil
	}
	if in.provider == auth.CIGitLab {
		if in.gitlabLoginErr != nil {
			return tierBrowser, fmt.Errorf("cilock login in a GitLab CI job: %w", in.gitlabLoginErr)
		}
		return tierWorkflow, nil
	}
	tier, err := decideLoginTier(in.token, in.interactive, in.workflowIdentity,
		in.provider == auth.CIGitHub && in.githubCanMint, in.url, in.defaultURL)
	if err == nil && tier == tierBrowser && in.ci {
		return tierBrowser, ciNoIdentityError(in.provider)
	}
	return tier, err
}

// loginTierInputFromEnv reads the CI identity decideLoginTierCI needs from the
// process environment.
func loginTierInputFromEnv(url, token string, interactive, workflowIdentity bool) loginTierInput {
	in := loginTierInput{token: token, interactive: interactive, workflowIdentity: workflowIdentity,
		provider: auth.CIProviderFromEnv(os.Getenv), githubCanMint: auth.GitHubCanMint(os.Getenv),
		url: url, defaultURL: config.DefaultPlatformURL, ci: auth.InCI(os.Getenv)}
	if in.provider == auth.CIGitLab && token == "" && !interactive {
		_, in.gitlabLoginErr = auth.GitLabJobToken(config.Derive(url).OIDCLoginAudience)
	}
	return in
}

// resolveLoginCredential obtains a session credential per decideLoginTierCI.
func resolveLoginCredential(cmd *cobra.Command, url, token, tenant, product string, interactive, workflowIdentity, allowTrust bool) (*auth.Credential, error) {
	tier, err := decideLoginTierCI(loginTierInputFromEnv(url, token, interactive, workflowIdentity))
	if err != nil {
		return nil, err
	}
	switch tier {
	case tierToken:
		return tokenCredential(cmd, url, token)
	case tierWorkflow:
		// Pass the --product selector so a monorepo repository (repo→multiple
		// products) can bind exactly one product at login.
		return auth.AmbientWorkflowLogin(url, config.Derive(url).OIDCLoginAudience, product)
	default: // tierBrowser
		return auth.BrowserLogin(url, auth.LoginParams{
			Tenant:     tenant,
			Product:    product,
			Purpose:    "cilock CLI",
			AllowTrust: allowTrust,
		})
	}
}

// printLoginResult reports the stored session after a successful login: the
// workflow-identity marker, or the logged-in tenant + bound product (nudging to
// `cilock use` when no product is bound).
func printLoginResult(out io.Writer, url string, cred *auth.Credential) {
	if cred.AuthMode == auth.AuthModeWorkflowOIDC {
		_, _ = fmt.Fprintf(out, "✓ workflow identity active for %s (%s)\n", auth.NormalizeURL(url), workflowIdentityLabel())
		if cred.TenantName != "" || cred.TenantID != "" {
			_, _ = fmt.Fprintf(out, "  tenant:  %s %s\n", cred.TenantName, cred.TenantID)
			_, _ = fmt.Fprintf(out, "  product: %s %s\n", cred.ProductName, cred.ProductID)
		} else {
			_, _ = fmt.Fprintf(out, "  ⚠ the platform's binding endpoint did not answer; cilock run resolves the tenant and product itself\n")
		}
		return
	}
	_, _ = fmt.Fprintf(out, "✓ logged in to %s\n", auth.NormalizeURL(url))
	if cred.TenantName != "" || cred.TenantID != "" {
		_, _ = fmt.Fprintf(out, "  tenant:  %s %s\n", cred.TenantName, cred.TenantID)
	}
	if cred.ProductName != "" || cred.ProductID != "" {
		_, _ = fmt.Fprintf(out, "  product: %s %s\n", cred.ProductName, cred.ProductID)
	} else {
		_, _ = fmt.Fprintf(out, "  ⚠ no working product bound — set one with `cilock use`\n")
	}
}

// applyScopeFlags binds an explicit --tenant-id/--product-id (and their name
// labels) onto a headless (--token) credential before it is stored. Empty flags
// leave existing values unchanged. Mirrors the scope the browser approve page
// would otherwise negotiate.
func applyScopeFlags(c *auth.Credential, tenantID, tenantName, productID, productName string) {
	if tenantID != "" {
		c.TenantID = tenantID
	}
	if tenantName != "" {
		c.TenantName = tenantName
	}
	if productID != "" {
		c.ProductID = productID
	}
	if productName != "" {
		c.ProductName = productName
	}
}

// tokenCredential builds a credential from an explicit --token (or stdin).
func tokenCredential(cmd *cobra.Command, url, token string) (*auth.Credential, error) {
	t := token
	if t == "-" {
		data, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return nil, fmt.Errorf("read token from stdin: %w", err)
		}
		t = string(data)
	} else {
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: a token passed via --token may be recorded in shell history; prefer '-' (stdin).")
	}
	// Validate the JWT client-side (exp/aud) before storing it as a session —
	// a server-expired or wrong-audience token must not be replayed as a live
	// bearer for a synthetic 30-day window (GHSA #5991).
	return auth.TokenCredential(url, t, config.Derive(url).OIDCLoginAudience)
}

// LogoutCmd removes a stored session credential.
func LogoutCmd() *cobra.Command {
	var platformURL string
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove the stored TestifySec platform session credential",
		Example: "  # Remove the stored session for the default platform\n" +
			"  cilock logout\n" +
			"\n" +
			"  # ... for another platform\n" +
			"  cilock logout --platform-url https://platform.example.com\n",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			removed, err := auth.Delete(url)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if removed {
				_, _ = fmt.Fprintf(out, "✓ logged out of %s\n", auth.NormalizeURL(url))
			} else {
				_, _ = fmt.Fprintf(out, "no stored credential for %s\n", auth.NormalizeURL(url))
			}
			// Don't lie about being logged out: cilock removed only its OWN stored
			// credential. If a session STILL resolves for this platform, it is coming
			// from another source (a `jctl login` read through ~/.jctl/config.yaml +
			// keychain). cilock must NEVER write jctl's files, so it cannot remove
			// that session — warn instead, so the operator isn't misled into thinking
			// the platform can no longer authenticate them.
			if still, _ := auth.Resolve(url, auth.ForBearer); still != nil {
				_, _ = fmt.Fprintf(out,
					"! still authenticated to %s via %s; run 'jctl auth logout' to fully sign out\n",
					auth.NormalizeURL(url), still.Source)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	return cmd
}

// whoamiNoSession reports a platform with no human session. An enrolled agent
// read "run: cilock login" here, the human's login (onbsim, 2026-09-25), so a
// stored agent is named instead. Either way it is an error: there is still no
// human session.
func whoamiNoSession(out io.Writer, url string) error {
	if agent, pending := storedAgent(url); agent != nil {
		state := "signs as"
		if pending {
			state = "has a not-yet-activated delivery for"
		}
		_, _ = fmt.Fprintf(out, "no human session on %s; this machine %s the enrolled agent %s in tenant %s (see `cilock agent status`)\n",
			auth.NormalizeURL(url), state, agent.AgentID, agent.TenantID)
		return fmt.Errorf("no human session: attestations sign as the enrolled agent, and policy sessions are a human's `cilock login`")
	}
	_, _ = fmt.Fprintf(out, "not logged in to %s (run: cilock login --platform-url %s)\n", auth.NormalizeURL(url), auth.NormalizeURL(url))
	return fmt.Errorf("no active session")
}

// WhoamiCmd shows the current stored session for a platform.
func WhoamiCmd() *cobra.Command {
	var platformURL string
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Show the current TestifySec platform session",
		Example: "  # The session for the default platform\n" +
			"  cilock whoami\n" +
			"\n" +
			"  # The session for another platform (sessions are stored per platform)\n" +
			"  cilock whoami --platform-url https://platform.example.com\n",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			// Resolve through the provider seam (not the bare-Credential LookupAny
			// shim) so whoami can report the resolving SOURCE and its capability
			// posture — provenance the operator needs to understand why, e.g., a
			// jctl session is refused trust-pinning by `cilock verify`. Display-only:
			// no trust decision branches on Source or the posture string.
			resolved, err := auth.Resolve(url, auth.ForDisplay)
			if err != nil {
				return err
			}
			if resolved == nil {
				return whoamiNoSession(cmd.OutOrStdout(), url)
			}
			cred := resolved.Credential
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "platform: %s\n", cred.PlatformURL)
			// Provenance: which source vouched for this session + its capability
			// posture (trust-pinning / expiry / audience). The trust gate in
			// `cilock verify` keys on these capabilities, so surfacing them here
			// explains its verdict without the operator reverse-engineering it.
			_, _ = fmt.Fprintf(out, "session:  %s\n", resolved.Posture())
			if cred.AuthMode == auth.AuthModeWorkflowOIDC {
				_, _ = fmt.Fprintf(out, "auth:     workflow identity (%s)\n", workflowIdentityLabel())
			}
			if cred.TenantName != "" || cred.TenantID != "" {
				_, _ = fmt.Fprintf(out, "tenant:   %s %s\n", cred.TenantName, cred.TenantID)
			}
			if cred.ProductName != "" || cred.ProductID != "" {
				_, _ = fmt.Fprintf(out, "product:  %s %s\n", cred.ProductName, cred.ProductID)
			}
			if cred.Email != "" {
				_, _ = fmt.Fprintf(out, "email:    %s\n", cred.Email)
			}
			if !cred.ExpiresAt.IsZero() {
				_, _ = fmt.Fprintf(out, "expires:  %s\n", cred.ExpiresAt.Format("2006-01-02 15:04 MST"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	return cmd
}

// workflowIdentityLabel says which CI identity a workflow-identity session
// signs with, for login and whoami output.
func workflowIdentityLabel() string {
	if auth.CIProviderFromEnv(os.Getenv) == auth.CIGitLab {
		return "GitLab CI job ID tokens; cilock run reads the job's id_tokens"
	}
	return "GitHub Actions OIDC; cilock run mints a token per call"
}
