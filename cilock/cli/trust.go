// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// trustScope is the narrow capability `cilock trust` requires: it lets a session
// register an OIDC federated upload identity (and nothing else). A session only
// carries it when the user opted in via `cilock login --allow-trust`.
const trustScope = "oidc:write"

// TrustCmd registers a CI/OIDC identity the platform will trust for attestation
// upload. It only ever creates OIDC (federated) credentials — never an OAUTH
// bearer secret. The complement to keyless `cilock run`: it registers the same
// audience cilock run mints, so uploads stop 401'ing with "identity maps to no
// tenant".
func TrustCmd() *cobra.Command {
	o := &options.TrustOptions{}
	var platformURL string
	var yes, dryRun bool

	cmd := &cobra.Command{
		Use:   "trust [provider] [owner/repo]",
		Short: "Trust a CI/OIDC identity to upload attestations (federated, no secrets)",
		Long: "Register an OIDC federated identity the TestifySec platform will trust for\n" +
			"attestation upload — the keyless complement to `cilock run`. It creates an\n" +
			"OIDC credential only; cilock never mints a long-lived API-token secret.\n\n" +
			"Run it as a tenant admin (after `cilock login`). The audience defaults to the\n" +
			"same `${platform}/archivista` that `cilock run` mints for, and the subject is\n" +
			"templated from the provider's claim convention, so trust and run can't drift.\n\n" +
			"Providers: " + strings.Join(options.KnownProviders(), ", ") + " (or --issuer + --subject for any other).\n" +
			"On-prem (GHES / self-hosted GitLab): add --host <instance-host>.",
		Example: "  # Trust a GitHub repo's Actions to upload (most common)\n" +
			"  cilock trust github testifysec/judge\n\n" +
			"  # Interactive: auto-detect the current repo and confirm\n" +
			"  cilock trust\n\n" +
			"  # On-prem GitHub Enterprise Server\n" +
			"  cilock trust github acme/app --host github.acme.com\n\n" +
			"  # Any OIDC provider (generic escape hatch)\n" +
			"  cilock trust --issuer https://oidc.corp/foo --subject sub:acme:prod",
		Args:          cobra.MaximumNArgs(2),
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTrust(cmd, args, o, platformURL, yes, dryRun)
		},
	}

	f := cmd.Flags()
	f.StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	f.StringVar(&o.Host, "host", "", "On-prem instance host for the provider (e.g. github.acme.com)")
	f.StringVar(&o.Issuer, "issuer", "", "OIDC issuer URL (generic provider; use with --subject)")
	f.StringVar(&o.Subject, "subject", "", "OIDC subject-match glob (generic provider; overrides the provider default)")
	f.StringVar(&o.Audience, "audience", "", "OIDC audience (default ${platform-url}/archivista — matches `cilock run`)")
	f.StringSliceVar(&o.Scopes, "scope", nil, "Scope to grant (repeatable; default attestation:upload). Only attestation:{upload,read,verify} allowed")
	f.BoolVar(&o.Verify, "verify", false, "Also grant attestation:read (for `cilock verify --enable-archivista`)")
	f.BoolVar(&o.SkipIssuerCheck, "skip-issuer-check", false, "Skip the local check that the issuer hostname resolves (for split-horizon/on-prem DNS)")
	f.StringSliceVar(&o.AllowedIPs, "allowed-ip", nil, "Source IP/CIDR allowlist (repeatable; e.g. the runner egress). Empty = any IP")
	f.StringSliceVar(&o.Tags, "tag", nil, "Tag for categorization (repeatable, e.g. tag:ci)")
	f.StringVar(&o.Name, "name", "", "Credential name (default <provider>:<slug>)")
	f.StringVar(&o.Description, "description", "", "Human-readable description")
	f.StringVar(&o.TenantID, "tenant", "", "Tenant ID (default: the logged-in working tenant)")
	f.BoolVarP(&yes, "yes", "y", false, "Skip the interactive confirmation")
	f.BoolVar(&dryRun, "dry-run", false, "Print what would be created without calling the platform")
	return cmd
}

// resolveTrustTarget fills o.Provider/o.Slug (or leaves the generic issuer path)
// from the positional args, auto-detecting the current repo when run
// interactively with none.
func resolveTrustTarget(o *options.TrustOptions, args []string) error {
	switch len(args) {
	case 2:
		o.Provider, o.Slug = args[0], args[1]
	case 1:
		return fmt.Errorf("specify the repository too: cilock trust %s <owner/repo> (e.g. cilock trust %s acme/app)", args[0], args[0])
	case 0:
		if o.Issuer != "" { // generic escape hatch → no repo needed
			return nil
		}
		if !isInteractive() {
			return fmt.Errorf("no repository specified and stdin is not a TTY.\n" +
				"specify it explicitly (format: <owner>/<repo>):\n" +
				"  cilock trust github <owner>/<repo>   e.g.  cilock trust github testifysec/judge")
		}
		prov, slug, host, err := detectCurrentRepo()
		if err != nil {
			return fmt.Errorf("%w\nspecify it explicitly: cilock trust github <owner>/<repo>", err)
		}
		o.Provider, o.Slug, o.Host = prov, slug, host
	}
	return nil
}

// runTrust executes `cilock trust`: resolve the identity, require an admin
// session, then create (or dry-run) the OIDC credential and report it.
func runTrust(cmd *cobra.Command, args []string, o *options.TrustOptions, platformURL string, yes, dryRun bool) error {
	out := cmd.OutOrStdout()

	if err := resolveTrustTarget(o, args); err != nil {
		return err
	}

	o.PlatformURL = platformURL
	if o.PlatformURL == "" {
		// Default to the platform you logged into, not the compiled prod default.
		if active := auth.ActivePlatformURL(); active != "" {
			o.PlatformURL = active
		} else {
			o.PlatformURL = config.DefaultPlatformURL
		}
	}

	cred, err := requireTrustSession(o.PlatformURL)
	if err != nil {
		return err
	}

	resolved, err := o.Resolve(cred.TenantID)
	if err != nil {
		return err
	}

	// Pre-flight the ISSUER before the plan is printed and before the user is
	// asked to confirm. A trust registration naming a hostname that does not
	// exist cannot ever work, and round-tripping it only to have the platform
	// refuse wastes the user's confirmation on a doomed request.
	if !o.SkipIssuerCheck {
		if err := preflightIssuerResolvable(cmd.Context(), resolved.IssuerURL); err != nil {
			return err
		}
	}

	// Interactive confirmation (skipped with --yes or when non-TTY+explicit).
	if !yes && isInteractive() {
		_, _ = fmt.Fprintf(out, "Trust this identity on %s?\n", auth.NormalizeURL(o.PlatformURL))
		printPlan(out, resolved)
		if !confirm(cmd) {
			return fmt.Errorf("aborted")
		}
	}

	if dryRun {
		_, _ = fmt.Fprintln(out, "dry-run — would create OIDC credential:")
		printPlan(out, resolved)
		return nil
	}

	graphqlURL := resolveGraphQLURL(o.PlatformURL)
	created, err := options.CreateOIDCCredential(cmd.Context(), graphqlURL, cred.Token, resolved)
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(out, "✓ trusted %q (id %s)\n", created.Name, created.ID)
	_, _ = fmt.Fprintf(out, "  issuer:   %s\n  subject:  %s\n  audience: %s\n  scopes:   %s\n",
		created.IssuerURL, created.Subject, created.Audience, strings.Join(created.Scopes, ", "))
	_, _ = fmt.Fprintf(out, "\nWorkflows matching %q can now upload attestations. Verify with:\n"+
		"  cilock run --platform-url %s -- <build>\n",
		created.Subject, auth.NormalizeURL(o.PlatformURL))
	return nil
}

// requireTrustSession loads the stored session for platformURL and enforces
// that it is a real, token-bearing session carrying the narrow oidc:write
// capability.
//
// The scope pre-flight is the sibling of preflightIssuerResolvable and exists
// for the same reason: a session only carries oidc:write when the user opted in
// at login, and without this check the platform rejects createCredential with
// an opaque error the user cannot act on. Both checks run locally, before any
// mutation, and name the exact remedy.
func requireTrustSession(platformURL string) (*auth.Credential, error) {
	cred, err := auth.Lookup(platformURL)
	if err != nil {
		return nil, fmt.Errorf("read session: %w", err)
	}
	if cred == nil || cred.Token == "" {
		return nil, fmt.Errorf("not logged in to %s — run `cilock login` first (trust needs an admin session)", auth.NormalizeURL(platformURL))
	}
	if !auth.TokenAuthorizedForScope(cred.Token, trustScope) {
		return nil, fmt.Errorf("this session can't register CI trust — it lacks the %q permission.\n"+
			"Re-authenticate with the trust opt-in, then run `cilock trust` again:\n\n"+
			"  cilock login --platform-url %s --allow-trust",
			trustScope, auth.NormalizeURL(platformURL))
	}
	return cred, nil
}

// issuerPreflightTimeout bounds the pre-flight lookup. It is short on purpose:
// the check is advisory, so a slow or wedged resolver must cost the operator a
// moment, never the command.
const issuerPreflightTimeout = 3 * time.Second

// lookupIssuerHost is the DNS seam the issuer pre-flight resolves through.
// A package var so tests can drive every DNS outcome hermetically; production
// always uses the system resolver.
var lookupIssuerHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// preflightIssuerResolvable refuses, locally and before any platform call, an
// issuer whose hostname authoritatively does not exist.
//
// IT FAILS OPEN, AND THAT IS THE DESIGN. This is a usability check, not a
// security control — the authority over which issuers may be registered is and
// stays the platform's server-side safehttp gate. Two facts force fail-open:
//
//  1. The CLI resolves from the OPERATOR'S network; the platform resolves from
//     ITS OWN. They are different vantage points, so a local lookup failure is
//     not evidence about what the platform will see.
//  2. Blocking on any lookup error would break an operator behind a captive
//     portal, a flaky VPN resolver, or a restricted-egress runner, for an
//     issuer the platform resolves perfectly well.
//
// So ONLY an authoritative "this name does not exist" blocks. Go reports that
// as *net.DNSError with IsNotFound for both NXDOMAIN and NODATA (NOERROR with
// zero answers — the shape a live zone returns for a retired label, and
// precisely the customer's case). Timeouts, temporary failures, a missing
// resolver, and a cancelled context are all INCONCLUSIVE and proceed.
//
// The one case this can get wrong is split-horizon DNS, where a name exists
// only in the platform's private view. That combination cannot succeed anyway:
// such a name resolves to a private address, which the platform's SSRF
// blocklist rejects regardless.
func preflightIssuerResolvable(ctx context.Context, issuerURL string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	u, err := url.Parse(issuerURL)
	if err != nil || u.Hostname() == "" {
		// A malformed issuer is the platform's to judge, with its own message.
		return nil
	}
	host := u.Hostname()
	if net.ParseIP(host) != nil {
		// A literal IP has nothing to resolve.
		return nil
	}

	lookupCtx, cancel := context.WithTimeout(ctx, issuerPreflightTimeout)
	defer cancel()

	if _, lookupErr := lookupIssuerHost(lookupCtx, host); lookupErr != nil {
		var dnsErr *net.DNSError
		if errors.As(lookupErr, &dnsErr) && dnsErr.IsNotFound {
			return fmt.Errorf(
				"issuer %q cannot be trusted: its hostname %q does not resolve, so the platform can never "+
					"fetch its OpenID configuration to verify tokens from it.\n\n"+
					"This almost always means the setup instructions you are following are out of date and name "+
					"an issuer that has since been renamed or retired. Regenerate your setup instructions and "+
					"re-run `cilock trust` with the issuer they name now.\n\n"+
					"If you believe this hostname is correct, confirm it from a network that can reach it:\n"+
					"  curl %s/.well-known/openid-configuration\n\n"+
					"On-prem with split-horizon DNS (the issuer resolves from the platform but not from here)? "+
					"Re-run with --skip-issuer-check",
				issuerURL, host, strings.TrimRight(issuerURL, "/"),
			)
		}
		// Inconclusive — say nothing and let the platform decide.
	}
	return nil
}

// isInteractive reports whether stdin is a real terminal (a human), vs a
// pipe / /dev/null / CI / AI agent. Uses the TTY ioctl (not a ModeCharDevice
// heuristic, which would treat /dev/null as interactive).
func isInteractive() bool {
	// os.Stdin.Fd() returns a small, valid descriptor; the uintptr→int
	// conversion cannot overflow in practice.
	return term.IsTerminal(int(os.Stdin.Fd())) //nolint:gosec // G115: stdin fd is a small int, no overflow
}

// detectCurrentRepo reads the origin remote of the CWD git repo and infers the
// provider + slug (+ on-prem host).
func detectCurrentRepo() (provider, slug, host string, err error) {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	b, runErr := cmd.Output()
	if runErr != nil {
		return "", "", "", fmt.Errorf("could not read git origin remote (not in a git repo with an 'origin'?)")
	}
	return options.ParseOriginRemote(strings.TrimSpace(string(b)))
}

func confirm(cmd *cobra.Command) bool {
	_, _ = fmt.Fprint(cmd.OutOrStdout(), "Proceed? [y/N] ")
	sc := bufio.NewScanner(cmd.InOrStdin())
	if !sc.Scan() {
		return false
	}
	ans := strings.ToLower(strings.TrimSpace(sc.Text()))
	return ans == "y" || ans == "yes"
}

func printPlan(w interface{ Write([]byte) (int, error) }, r *options.ResolvedTrust) {
	_, _ = fmt.Fprintf(w, "  name:     %s\n  issuer:   %s\n  subject:  %s\n  audience: %s\n  scopes:   %s\n  tenant:   %s\n",
		r.Name, r.IssuerURL, r.Subject, r.Audience, strings.Join(r.Scopes, ", "), r.TenantID)
}

// resolveGraphQLURL prefers the discovery-advertised graphql endpoint, falling
// back to ${platform}/query when discovery is unavailable. A discovery URL whose
// origin (scheme+host) differs from the platform is withheld (#5987): the session
// bearer is scoped to the platform origin and must never be sent to a host the
// discovery document — which may be MITM'd or misconfigured — points elsewhere.
func resolveGraphQLURL(platformURL string) string {
	fallback := auth.NormalizeURL(platformURL) + "/query"
	if d, err := config.Discover(platformURL); err == nil && d.GraphQLURL != "" {
		if config.SameOrigin(d.GraphQLURL, platformURL) {
			return d.GraphQLURL
		}
	}
	return fallback
}
