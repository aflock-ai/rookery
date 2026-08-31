// Copyright 2026 The Aflock Authors
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

// AgentCmd groups the enrolled-agent principal commands. An agent principal is
// a tenant-scoped, revocable identity a human enrolled at AAL2 on the platform;
// it signs under its own SPIFFE ID and is stored apart from `cilock login`, so
// an agent never presents the operator's human account.
func AgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "agent",
		Short:             "Manage this machine's enrolled agent principal",
		Long:              "Store and inspect the enrolled agent credential this machine signs with.\n\nAn agent principal is separate from `cilock login`: it has its own SPIFFE identity,\nits own credential file, and it takes precedence over the human session when both\nare present for a platform.",
		DisableAutoGenTag: true,
	}
	cmd.AddCommand(AgentLoginCmd())
	cmd.AddCommand(AgentStatusCmd())
	cmd.AddCommand(AgentLogoutCmd())
	return cmd
}

// AgentLoginCmd accepts a refresh credential minted by the platform's
// enrollment ceremony and stores it for this platform.
func AgentLoginCmd() *cobra.Command {
	var platformURL, tenantID, agentID string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store the enrolled agent credential this machine signs with",
		Long: "Store the refresh credential a human minted for this agent at enrollment.\n\n" +
			"The credential is read from STDIN by default so it never lands in shell history or a\n" +
			"process listing. It is written 0600 to cilock's own agent store, kept apart from the\n" +
			"`cilock login` session, and never printed again. The tenant and agent ids are NOT\n" +
			"secret — they are the SPIFFE path segments\n" +
			"(spiffe://<trust-domain>/tenant/<tenant-id>/agent/<agent-id>) every certificate this\n" +
			"credential buys will carry — so they are ordinary flags.",
		Example: "  # Read the credential from stdin (preferred)\n" +
			"  cilock agent login --platform-url https://platform.example.com \\\n" +
			"    --tenant-id <uuid> --agent-id <uuid> < credential.txt",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			// Refuse a cleartext non-loopback platform before the credential is
			// stored against it: this bearer mints signing certificates, and a
			// stored URL is the address every later exchange sends it to.
			if err := config.RequireSecurePlatformURL(url); err != nil {
				return err
			}
			// STDIN IS THE ONLY CHANNEL, deliberately. A --credential flag puts a
			// long-lived signing secret in argv, where it is readable by any
			// process on the host via /proc or `ps`, and is written verbatim into
			// shell history. Neither is recoverable after the fact: the operator
			// cannot un-log it, and rotating means re-enrolling. A flag that is
			// merely discouraged still gets used in a hurry, so the safe channel
			// is the only channel.
			read, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 1<<20))
			if err != nil {
				return fmt.Errorf("read the agent credential from stdin: %w", err)
			}
			credential := strings.TrimSpace(string(read))
			if credential == "" {
				return fmt.Errorf("no agent credential supplied; pipe the enrollment credential on stdin")
			}
			if tenantID == "" || agentID == "" {
				return fmt.Errorf("--tenant-id and --agent-id are required; they are the SPIFFE path segments this agent signs under")
			}
			if err := auth.SaveAgent(auth.AgentCredential{
				PlatformURL:       url,
				TenantID:          tenantID,
				AgentID:           agentID,
				RefreshCredential: credential,
			}); err != nil {
				return err
			}
			// The credential is deliberately absent from this output. It was
			// accepted once and is never shown again.
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Stored agent credential for %s\n", auth.NormalizeURL(url))
			_, _ = fmt.Fprintf(out, "  tenant: %s\n  agent:  %s\n", tenantID, agentID)
			_, _ = fmt.Fprintf(out, "`cilock run --platform-url %s` now signs as this agent principal, not as your login.\n", auth.NormalizeURL(url))
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	cmd.Flags().StringVar(&tenantID, "tenant-id", "", "Tenant UUID this agent is enrolled in (SPIFFE path segment)")
	cmd.Flags().StringVar(&agentID, "agent-id", "", "Agent principal UUID minted at enrollment (SPIFFE path segment)")
	return cmd
}

// AgentStatusCmd reports which agent principal this machine would sign as.
func AgentStatusCmd() *cobra.Command {
	var platformURL string
	cmd := &cobra.Command{
		Use:           "status",
		Short:         "Show the agent principal this machine would sign as",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			cred, err := auth.LookupAgent(url)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if cred == nil {
				_, _ = fmt.Fprintf(out, "No agent principal enrolled for %s.\n", auth.NormalizeURL(url))
				return nil
			}
			// Identifiers only. The refresh credential is never displayed.
			_, _ = fmt.Fprintf(out, "Agent principal for %s\n", cred.PlatformURL)
			_, _ = fmt.Fprintf(out, "  tenant: %s\n  agent:  %s\n", cred.TenantID, cred.AgentID)
			_, _ = fmt.Fprintln(out, "  runs against this platform sign as this agent, taking precedence over `cilock login`.")
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	return cmd
}

// AgentLogoutCmd removes this machine's copy of the agent credential.
func AgentLogoutCmd() *cobra.Command {
	var platformURL string
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove this machine's agent credential",
		Long: "Remove this machine's copy of the agent credential.\n\n" +
			"This is a local delete, not a revocation: the principal stays valid on the\n" +
			"platform until a human revokes it there.",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			removed, err := auth.DeleteAgent(url)
			if err != nil {
				return err
			}
			if !removed {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "No agent credential stored for %s.\n", auth.NormalizeURL(url))
				return nil
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed the local agent credential for %s; revoke the principal on the platform to end its authority.\n", auth.NormalizeURL(url))
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	return cmd
}
