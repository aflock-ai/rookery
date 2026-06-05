// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// LoginCmd signs in to a TestifySec platform and stores a session credential.
func LoginCmd() *cobra.Command {
	var platformURL, token, tenant, product string
	var interactive, workflowIdentity, allowTrust bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to the TestifySec platform and store a session credential",
		Long: "Sign in to the TestifySec platform and store a session credential, so subsequent\n" +
			"cilock platform calls (attestation storage, signing-token exchange) are\n" +
			"authenticated. login establishes identity only; choose the working tenant/product\n" +
			"separately with `cilock use` or per-command flags.\n\n" +
			"Identity is resolved by precedence:\n" +
			"  1. --token            an explicit JWT (CI/headless; '-' reads from stdin)\n" +
			"  2. workflow identity  ambient CI OIDC (GitHub Actions) — auto-detected on the\n" +
			"                        default platform; no browser, no stored secret. cilock run\n" +
			"                        mints a fresh OIDC token per call.\n" +
			"  3. browser            interactive loopback login (default for local use)\n\n" +
			"--interactive forces the browser. --workflow-identity forces ambient OIDC (and is\n" +
			"required to send a workflow token to a non-default --platform-url).",
		Example: "  # Interactive browser login to the default TestifySec platform\n" +
			"  cilock login\n\n" +
			"  # CI on GitHub Actions: use the ambient workflow identity (auto-detected)\n" +
			"  cilock login   # with `permissions: id-token: write`\n\n" +
			"  # CI/headless: provide a JWT directly (or '-' to read from stdin)\n" +
			"  cilock login --platform-url https://platform.example.com --token $TESTIFYSEC_TOKEN",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			cred, err := resolveLoginCredential(cmd, url, token, tenant, product, interactive, workflowIdentity, allowTrust)
			if err != nil {
				return err
			}
			if err := auth.Save(*cred); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			switch {
			case cred.AuthMode == auth.AuthModeWorkflowOIDC:
				_, _ = fmt.Fprintf(out, "✓ workflow identity active for %s (GitHub Actions OIDC; cilock run mints a token per call)\n", auth.NormalizeURL(url))
			case cred.TenantName != "":
				_, _ = fmt.Fprintf(out, "✓ logged in to %s (tenant: %s)\n", auth.NormalizeURL(url), cred.TenantName)
			default:
				_, _ = fmt.Fprintf(out, "✓ logged in to %s\n", auth.NormalizeURL(url))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	cmd.Flags().StringVar(&token, "token", "", "JWT for CI/headless login (skips the browser); '-' reads it from stdin")
	cmd.Flags().StringVar(&tenant, "tenant", "", "Tenant id or name to pre-select on the approve page")
	cmd.Flags().StringVar(&product, "product", "", "Product id or name to pre-select on the approve page")
	cmd.Flags().BoolVar(&interactive, "interactive", false, "Force the interactive browser login (skip ambient CI workflow identity)")
	cmd.Flags().BoolVar(&workflowIdentity, "workflow-identity", false, "Use the ambient CI workflow OIDC identity (auto-detected on the default platform; required to send a workflow token to a non-default --platform-url)")
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
		return tierBrowser, fmt.Errorf("--workflow-identity requested but no ambient OIDC identity is present (need ACTIONS_ID_TOKEN_REQUEST_URL and `permissions: id-token: write`)")
	}
	return tierBrowser, nil
}

// resolveLoginCredential obtains a session credential per decideLoginTier.
func resolveLoginCredential(cmd *cobra.Command, url, token, tenant, product string, interactive, workflowIdentity, allowTrust bool) (*auth.Credential, error) {
	tier, err := decideLoginTier(token, interactive, workflowIdentity, auth.WorkflowOIDCAvailable(), url, config.DefaultPlatformURL)
	if err != nil {
		return nil, err
	}
	switch tier {
	case tierToken:
		return tokenCredential(cmd, url, token)
	case tierWorkflow:
		return auth.AmbientWorkflowLogin(url, config.Derive(url).OIDCLoginAudience)
	default: // tierBrowser
		return auth.BrowserLogin(url, auth.LoginParams{
			Tenant:     tenant,
			Product:    product,
			Purpose:    "cilock CLI",
			AllowTrust: allowTrust,
		})
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
	cred := &auth.Credential{PlatformURL: url, Token: strings.TrimSpace(t), AuthMode: auth.AuthModeToken}
	if cred.Token == "" {
		return nil, fmt.Errorf("empty token")
	}
	return cred, nil
}

// LogoutCmd removes a stored session credential.
func LogoutCmd() *cobra.Command {
	var platformURL string
	cmd := &cobra.Command{
		Use:           "logout",
		Short:         "Remove the stored TestifySec platform session credential",
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
			if removed {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "✓ logged out of %s\n", auth.NormalizeURL(url))
			} else {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "no stored credential for %s\n", auth.NormalizeURL(url))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	return cmd
}

// WhoamiCmd shows the current stored session for a platform.
func WhoamiCmd() *cobra.Command {
	var platformURL string
	cmd := &cobra.Command{
		Use:           "whoami",
		Short:         "Show the current TestifySec platform session",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			cred, err := auth.LookupAny(url)
			if err != nil {
				return err
			}
			if cred == nil {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "not logged in to %s (run: cilock login --platform-url %s)\n", auth.NormalizeURL(url), auth.NormalizeURL(url))
				return fmt.Errorf("no active session")
			}
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "platform: %s\n", cred.PlatformURL)
			if cred.AuthMode == auth.AuthModeWorkflowOIDC {
				_, _ = fmt.Fprintf(out, "auth:     workflow identity (GitHub Actions OIDC)\n")
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
