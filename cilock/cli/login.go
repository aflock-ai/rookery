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
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to the TestifySec platform and store a session credential",
		Long: "Sign in to the TestifySec platform via an interactive browser flow and store a\n" +
			"session token locally, so subsequent cilock platform calls (attestation storage,\n" +
			"signing-token exchange) are authenticated. login establishes identity only; choose\n" +
			"the working tenant/product separately with `cilock use` or per-command flags.\n" +
			"Use --token for CI/headless logins. --tenant/--product pre-fill the approve page.",
		Example: "  # Interactive browser login to the default TestifySec platform\n" +
			"  cilock login\n\n" +
			"  # Log in to a specific TestifySec platform, pre-selecting a tenant\n" +
			"  cilock login --platform-url https://platform.example.com --tenant acme\n\n" +
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

			var cred *auth.Credential
			if token != "" {
				t := token
				if t == "-" {
					data, err := io.ReadAll(cmd.InOrStdin())
					if err != nil {
						return fmt.Errorf("read token from stdin: %w", err)
					}
					t = string(data)
				} else {
					fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: a token passed via --token may be recorded in shell history; prefer '-' (stdin).")
				}
				cred = &auth.Credential{PlatformURL: url, Token: strings.TrimSpace(t)}
				if cred.Token == "" {
					return fmt.Errorf("empty token")
				}
			} else {
				var err error
				cred, err = auth.BrowserLogin(url, auth.LoginParams{
					Tenant:  tenant,
					Product: product,
					Purpose: "cilock CLI",
				})
				if err != nil {
					return err
				}
			}

			if err := auth.Save(*cred); err != nil {
				return err
			}
			if cred.TenantName != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ logged in to %s (tenant: %s)\n", auth.NormalizeURL(url), cred.TenantName)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "✓ logged in to %s\n", auth.NormalizeURL(url))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	cmd.Flags().StringVar(&token, "token", "", "JWT for CI/headless login (skips the browser); '-' reads it from stdin")
	cmd.Flags().StringVar(&tenant, "tenant", "", "Tenant id or name to pre-select on the approve page")
	cmd.Flags().StringVar(&product, "product", "", "Product id or name to pre-select on the approve page")
	return cmd
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
				fmt.Fprintf(cmd.OutOrStdout(), "✓ logged out of %s\n", auth.NormalizeURL(url))
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "no stored credential for %s\n", auth.NormalizeURL(url))
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
			cred, err := auth.Lookup(url)
			if err != nil {
				return err
			}
			if cred == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "not logged in to %s (run: cilock login --platform-url %s)\n", auth.NormalizeURL(url), auth.NormalizeURL(url))
				return fmt.Errorf("no active session")
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "platform: %s\n", cred.PlatformURL)
			if cred.TenantName != "" || cred.TenantID != "" {
				fmt.Fprintf(out, "tenant:   %s %s\n", cred.TenantName, cred.TenantID)
			}
			if cred.ProductName != "" || cred.ProductID != "" {
				fmt.Fprintf(out, "product:  %s %s\n", cred.ProductName, cred.ProductID)
			}
			if cred.Email != "" {
				fmt.Fprintf(out, "email:    %s\n", cred.Email)
			}
			if !cred.ExpiresAt.IsZero() {
				fmt.Fprintf(out, "expires:  %s\n", cred.ExpiresAt.Format("2006-01-02 15:04 MST"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	return cmd
}
