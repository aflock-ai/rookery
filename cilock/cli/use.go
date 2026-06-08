// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// UseCmd sets the working tenant + product bound to the stored cilock session —
// the scope every `cilock run` attestation binds to. It is cilock's analog of
// jctl's `config set-product` (plus tenant): the kubectl-style "switch the
// working context" verb the login help points users at.
func UseCmd() *cobra.Command {
	var platformURL, tenant, product string
	var tenantID, tenantName, productID, productName string
	cmd := &cobra.Command{
		Use:   "use",
		Short: "Set the working tenant and product for the stored session",
		Long: "Set the working tenant and product bound to the stored cilock session, so\n" +
			"`cilock run` binds every attestation to that product without re-prompting.\n" +
			"Requires an existing session — run `cilock login` first.\n\n" +
			"Two modes:\n" +
			"  by id (no browser):  --product-id (and optionally --tenant-id, plus their\n" +
			"                       --*-name labels) write the binding directly.\n" +
			"  by name (browser):   --tenant/--product, or no flags, re-open the approve\n" +
			"                       page to resolve names to ids and auto-create a default\n" +
			"                       tenant/product if you have none, then persist the choice.",
		Example: "  # Switch the working product by id (no browser)\n" +
			"  cilock use --product-id 5664d4f5-9003-41e8-90e4-035c51d09b45 --product-name \"My Product\"\n\n" +
			"  # Pick or create tenant+product interactively\n" +
			"  cilock use\n\n" +
			"  # Pre-select by name on the approve page\n" +
			"  cilock use --tenant acme --product \"My Product\"",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			// Fast path: an explicit id binds directly against the stored session —
			// no browser, no re-auth (mirrors `jctl config set-product`).
			if productID != "" || tenantID != "" {
				if err := auth.SetScope(url, tenantID, tenantName, productID, productName); err != nil {
					return err
				}
				return printScope(cmd, url)
			}
			// Otherwise re-drive the approve page, which resolves names to ids and
			// auto-provisions a default tenant/product when the user has none. cilock
			// has no GraphQL client of its own, so the page is the resolver.
			cred, err := auth.BrowserLogin(url, auth.LoginParams{
				Tenant:  tenant,
				Product: product,
				Purpose: "cilock use",
			})
			if err != nil {
				return err
			}
			if err := auth.Save(*cred); err != nil {
				return err
			}
			return printScope(cmd, url)
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	cmd.Flags().StringVar(&tenant, "tenant", "", "Tenant id or name to select on the approve page")
	cmd.Flags().StringVar(&product, "product", "", "Product id or name to select on the approve page")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Tenant UUID to bind directly (no browser)")
	cmd.Flags().StringVar(&tenantName, "tenant-name", "", "Tenant name to record alongside --tenant-id")
	cmd.Flags().StringVar(&productID, "product-id", "", "Product UUID to bind directly (no browser)")
	cmd.Flags().StringVar(&productName, "product-name", "", "Product name to record alongside --product-id")
	return cmd
}

// printScope reports the working tenant/product after a use/login change.
// Shared with `cilock login` so both surface the bound product, not just tenant.
func printScope(cmd *cobra.Command, url string) error {
	cred, err := auth.LookupAny(url)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if cred == nil {
		_, _ = fmt.Fprintf(out, "no stored session for %s (run: cilock login --platform-url %s)\n",
			auth.NormalizeURL(url), auth.NormalizeURL(url))
		return nil
	}
	_, _ = fmt.Fprintf(out, "✓ working scope for %s\n", auth.NormalizeURL(url))
	if cred.TenantName != "" || cred.TenantID != "" {
		_, _ = fmt.Fprintf(out, "  tenant:  %s %s\n", cred.TenantName, cred.TenantID)
	}
	if cred.ProductName != "" || cred.ProductID != "" {
		_, _ = fmt.Fprintf(out, "  product: %s %s\n", cred.ProductName, cred.ProductID)
	} else {
		_, _ = fmt.Fprintf(out, "  product: (none — set one with `cilock use`)\n")
	}
	return nil
}
