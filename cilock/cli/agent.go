// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// agentCommandName is the noun both `cilock agent …` and `cilock enroll agent`
// spell: the same thing, from two directions.
const agentCommandName = "agent"

// AgentCmd groups the enrolled-agent principal commands. An agent principal is
// a tenant-scoped, revocable identity a human enrolled at AAL2 on the platform;
// it signs under its own SPIFFE ID and is stored apart from `cilock login`, so
// an agent never presents the operator's human account.
func AgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               agentCommandName,
		Short:             "Manage this machine's enrolled agent principal",
		Long:              "Store and inspect the enrolled agent credential this machine signs with.\n\nAn agent principal is separate from `cilock login`: it has its own SPIFFE identity,\nits own credential file, and it takes precedence over the human session when both\nare present for a platform.",
		DisableAutoGenTag: true,
	}
	cmd.AddCommand(AgentEnrollCmd())
	cmd.AddCommand(AgentLoginCmd())
	cmd.AddCommand(AgentStatusCmd())
	cmd.AddCommand(AgentLogoutCmd())
	return cmd
}

// browserEnroll and activateEnrolledAgent are the two halves of the ceremony
// the command sequences: the browser approval (needs a human and a browser)
// and the redemption exchange (needs the platform). Package variables so the
// command's own decisions — flag validation, ordering, what it prints and
// when — are executed by tests without either.
var (
	browserEnroll         = auth.BrowserEnroll
	activateEnrolledAgent = auth.ActivateEnrolledAgent
)

// The platform's bounds on a principal's lifetime (judge-api's
// createAgentPrincipal refuses the same). Checked here too so a value the
// platform would refuse never opens a browser tab the human then approves for
// nothing.
const (
	agentTTLMin = 15 * time.Minute
	agentTTLMax = 7 * 24 * time.Hour
)

// EnrollCmd groups the enrollment ceremonies: `cilock enroll agent`.
func EnrollCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "enroll",
		Short:             "Enroll an identity on the platform — a human approves in the browser",
		DisableAutoGenTag: true,
	}
	cmd.AddCommand(EnrollAgentCmd())
	return cmd
}

// EnrollAgentCmd runs the whole enrollment ceremony in one command: a browser
// opens, a human signs in and approves at AAL2, the minted credential lands in
// the agent store without ever being displayed, and the command REDEEMS it
// with the platform before it reports success.
func EnrollAgentCmd() *cobra.Command {
	var platformURL, displayName, repo string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   agentCommandName,
		Short: "Enroll this machine's agent identity — a human approves in the browser",
		Long: "Enroll an agent principal for this machine in one ceremony.\n\n" +
			"A browser window opens on the platform's enrollment page. Your human signs in,\n" +
			"reviews what is being minted — name, tenant, repository scope, lifetime —\n" +
			"steps up to AAL2 (their passkey / second factor — required afresh for every\n" +
			"ceremony, not once per session), and confirms. The passkey locks in exactly\n" +
			"what was reviewed: the platform refuses anything else on that ceremony. It\n" +
			"then mints the principal\n" +
			"inside that very session and hands the one-time credential straight back to this\n" +
			"command, which stores it 0600 in the agent store and then redeems it with the\n" +
			"platform. Only that first exchange ACTIVATES the principal: a ceremony whose\n" +
			"credential never arrives leaves nothing the platform will ever accept.\n\n" +
			"The identity is TIME-BOUND. It stops signing at the lifetime the human confirmed\n" +
			"(eight hours by default, seven days at most) and cannot be extended; a new\n" +
			"ceremony mints a new principal. Nothing is pasted, nothing is printed, and\n" +
			"afterwards `cilock run` signs as the agent, never as the human.\n\n" +
			"An agent may run this command; it cannot complete it. The mutation only executes\n" +
			"behind a human session whose assurance level the PLATFORM observed, so there is\n" +
			"no flag, environment variable, or input that substitutes for the person.",
		Example: "  # Enroll for a working day, with a browser approval by your human\n" +
			"  cilock enroll agent\n\n" +
			"  # Pre-fill the label, repository scope and lifetime shown on the approve page\n" +
			"  cilock enroll agent --name claude-on-coles-mbp --repo testifysec/judge --ttl 4h",
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			url := platformURL
			if url == "" {
				url = config.DefaultPlatformURL
			}
			// Same rule as login and agent login: refuse a cleartext non-loopback
			// platform before any flow runs — the callback this ceremony opens
			// will receive a long-lived signing secret.
			if err := config.RequireSecurePlatformURL(url); err != nil {
				return err
			}
			if cmd.Flags().Changed("ttl") && (ttl < agentTTLMin || ttl > agentTTLMax) {
				return fmt.Errorf("--ttl %s is outside what the platform accepts: between %s and %s", ttl, agentTTLMin, agentTTLMax)
			}
			// The ceremony's callback stores the delivered credential PENDING,
			// beside whatever this machine already signs with — never over it.
			// A working identity is superseded only by one the platform has
			// redeemed.
			cred, err := browserEnroll(url, auth.EnrollParams{DisplayName: displayName, Repo: repo, TTL: ttl})
			if err != nil {
				return err
			}
			// REDEEM BEFORE CLAIMING. The platform created the principal pending;
			// this exchange is what activates it, and only then is the delivered
			// credential promoted to the one this machine signs with. A refusal
			// means the ceremony did not produce an identity and the command
			// fails, so nothing downstream believes otherwise; a transient
			// failure keeps the credential pending for the next run to redeem.
			activated, err := activateEnrolledAgent(url, *cred)
			if err != nil {
				return err
			}
			// Identifiers only — the credential was stored inside the callback
			// and is deliberately not available here to print. What is printed
			// is the identity the PLATFORM answered with at redemption, not the
			// callback's claim about itself.
			out := cmd.OutOrStdout()
			_, _ = fmt.Fprintf(out, "Enrolled. Agent principal for %s\n", auth.NormalizeURL(url))
			_, _ = fmt.Fprintf(out, "  tenant: %s\n  agent:  %s\n  spiffe: %s\n", cred.TenantID, cred.AgentID, activated.SPIFFEID)
			if !cred.ExpiresAt.IsZero() {
				_, _ = fmt.Fprintf(out, "  expires: %s (%s from now; not extendable — a new ceremony mints a new principal)\n",
					cred.ExpiresAt.Local().Format("2006-01-02 15:04 MST"), time.Until(cred.ExpiresAt).Round(time.Minute))
			}
			_, _ = fmt.Fprintf(out, "`cilock run` against this platform now signs as this agent, not as your human's login.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&platformURL, "platform-url", "", "TestifySec platform URL (default "+config.DefaultPlatformURL+")")
	cmd.Flags().StringVar(&displayName, "name", "", "Pre-fill the principal's display label on the approve page")
	cmd.Flags().StringVar(&repo, "repo", "", "Pre-select a repository scope on the approve page (owner/name)")
	cmd.Flags().DurationVar(&ttl, "ttl", 0, "Pre-select the principal's lifetime on the approve page (15m to 168h; the platform defaults to 8h)")
	return cmd
}

// AgentEnrollCmd is the pre-rename spelling, `cilock agent enroll`. Kept so a
// setup document or a shell history that names it still works, hidden so
// nothing new learns it.
func AgentEnrollCmd() *cobra.Command {
	cmd := EnrollAgentCmd()
	cmd.Use = "enroll"
	cmd.Hidden = true
	cmd.Deprecated = "use `cilock enroll agent`"
	// The examples belong to the canonical spelling; an alias that showed
	// them would teach the very name it exists to retire.
	cmd.Example = ""
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
			pending, err := auth.LookupPendingAgent(url)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			// A delivered credential the platform has not yet redeemed is not
			// an identity this machine signs with; it is named as what it is,
			// beside (or instead of) the one that does.
			if pending != nil {
				_, _ = fmt.Fprintf(out, "Pending for %s: agent %s (tenant %s) — delivered by a ceremony, not yet redeemed; the next `cilock run` (within ten minutes of enrollment) will try again.\n",
					auth.NormalizeURL(url), pending.AgentID, pending.TenantID)
			}
			if cred == nil {
				if pending == nil {
					_, _ = fmt.Fprintf(out, "No agent principal enrolled for %s.\n", auth.NormalizeURL(url))
				}
				return nil
			}
			// Identifiers only. The refresh credential is never displayed.
			_, _ = fmt.Fprintf(out, "Agent principal for %s\n", cred.PlatformURL)
			_, _ = fmt.Fprintf(out, "  tenant: %s\n  agent:  %s\n", cred.TenantID, cred.AgentID)
			// The active slot holds only what the platform has redeemed, and a
			// redemption pins the trust domain; a credential handed over by
			// `cilock agent login` has not been exchanged yet, and says so.
			if cred.TrustDomain == "" {
				_, _ = fmt.Fprintln(out, "  not yet redeemed: the platform has not answered this credential; the next `cilock run` will present it.")
			} else {
				_, _ = fmt.Fprintf(out, "  spiffe: spiffe://%s/tenant/%s/agent/%s\n", cred.TrustDomain, cred.TenantID, cred.AgentID)
			}
			// ONE READING OF ELIGIBILITY, TAKEN ONCE. CheckSigningEligibility is
			// the same function the pre-command gate in `cilock run` refuses on,
			// and its message is the same message, so the report an operator
			// reads and the gate that stops their build cannot drift apart. One
			// call, one clock read: two would be two verdicts.
			ineligible := cred.CheckSigningEligibility(time.Now())
			switch {
			// EXIT NON-ZERO, on the `cilock doctor` pattern: the human report
			// goes to stdout and a terse rollup error sets the code, so a script
			// can gate on a dead identity without parsing prose.
			case ineligible != nil:
				_, _ = fmt.Fprintf(out, "  EXPIRED: %s\n", ineligible)
				return fmt.Errorf("cilock agent status: the enrolled agent principal for %s is expired", auth.NormalizeURL(url))
			case !cred.ExpiresAt.IsZero():
				_, _ = fmt.Fprintf(out, "  expires: %s (%s from now)\n",
					cred.ExpiresAt.Local().Format("2006-01-02 15:04 MST"), time.Until(cred.ExpiresAt).Round(time.Minute))
			}
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
