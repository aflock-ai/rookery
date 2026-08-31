// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	platformconfig "github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
)

// agentPrincipal is the SPIFFE ID of the enrolled agent that signed, as of the
// most recent exchange.
//
// It is a heap cell shared by pointer for the same reason keylessAssurance is:
// cli/run.go hands RunOptions to runRun BY VALUE, while the signing-time
// refresher re-exchanges AFTER the wrapped command. A value field would leave
// the summary reporting the principal of the initial, unused token.
type agentPrincipal struct {
	spiffeID string
}

// applyAgentKeylessFulcioToken exchanges this machine's enrolled agent
// credential for a short-lived signing token and installs it on
// --signer-fulcio-token, so `cilock run` signs as the agent principal rather
// than as the human who is logged in.
//
// It FAILS CLOSED, unlike the human session path beside it. That path may fail
// open because a failed exchange there means "this run is not keyless after all"
// and some other identity legitimately signs. Here the operator has declared an
// agent principal for this platform, so the only identity left to fall through
// to is the human's — the borrowed-identity result the agent principal exists to
// remove. Every failure is therefore returned, and the caller aborts the run.
//
// The refresh credential never reaches Fulcio: it goes to the credential-exchange
// endpoint, which returns the token Fulcio sees.
//
// The second return is the signing-time refresher every keyless path owes,
// because the certificate is minted at first signature, after the wrapped
// command. It re-exchanges and updates the recorded principal so the summary
// describes the credential that actually bought the certificate.
func applyAgentKeylessFulcioToken(cmd *cobra.Command, platformURL, fulcioURL string, cred auth.AgentCredential) (*agentPrincipal, func() error, error) {
	if !fulcioSignerNeedsToken(cmd) {
		// The operator chose the Fulcio token source themselves
		// (--signer-fulcio-token / -token-path / -oidc-issuer), or selected a
		// non-fulcio signer. That explicit choice wins, exactly as it does on the
		// human path — and it is not a fallback to the human session, so nothing
		// silently borrows an identity here. The summary claims no agent
		// principal, because none signed.
		return nil, nil, nil
	}
	if cur := fulcioFlagURL(cmd); cur != "" && !sameOrigin(cur, fulcioURL) {
		return nil, nil, fmt.Errorf(
			"an enrolled agent credential is configured for %s but --signer-fulcio-url points at %s; "+
				"the agent signing token is only valid at that platform's own Fulcio (%s). "+
				"Drop --signer-fulcio-url, or run without the agent credential",
			platformURL, cur, fulcioURL)
	}
	id, err := auth.ExchangeAgentCredential(platformURL, cred)
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Flags().Set("signer-fulcio-token", id.Token); err != nil {
		return nil, nil, fmt.Errorf("installing the agent signing token: %w", err)
	}
	principal := &agentPrincipal{spiffeID: id.SPIFFEID}

	// CARRY THE PIN INTO THE REFRESH, or the run defeats its own pin.
	//
	// On first use the credential arrives here with an empty TrustDomain, the
	// exchange pins what the platform answered TO DISK, and `cred` — captured by
	// the closure below — still holds the empty value. The refresh would then be
	// an unpinned exchange again and would accept a DIFFERENT trust domain,
	// signing under it mid-run, minutes after the first exchange established
	// what this agent's authority is. The pin would be perfectly recorded and
	// completely bypassed for the run that created it.
	//
	// Updating the captured copy is what makes the invariant hold WITHIN a run
	// as well as across runs: every exchange after the first is checked against
	// the first. Reading it back from disk would work too and costs I/O on every
	// refresh; the value is the same one that was just written.
	if cred.TrustDomain == "" {
		cred.TrustDomain = id.TrustDomain
	}

	refresh := func() error {
		fresh, err := auth.ExchangeAgentCredential(platformURL, cred)
		if err != nil {
			return fmt.Errorf("re-exchanging the agent credential: %w", err)
		}
		if err := cmd.Flags().Set("signer-fulcio-token", fresh.Token); err != nil {
			return fmt.Errorf("installing the refreshed agent signing token: %w", err)
		}
		principal.spiffeID = fresh.SPIFFEID
		return nil
	}
	return principal, refresh, nil
}

// applyAgentCredential wires an enrolled agent principal into the run: the
// keyless Fulcio token and the platform-attestor binding.
//
// What it deliberately does NOT do is touch resolvedSignerEmail. That field is
// the human account's identity; leaving it untouched is what keeps the run
// summary from naming a human for a signature the agent produced.
//
// It also does not attach an Archivista bearer or flip Archivista on. The agent
// credential authenticates the credential exchange only, and the human session's
// bearer is not the agent's to spend — so an agent run uploads when the operator
// asks for it with --enable-archivista and the store accepts the identity.
func (ro *RunOptions) applyAgentCredential(cmd *cobra.Command, cred auth.AgentCredential, pc platformconfig.PlatformConfig) error {
	principal, refresh, err := applyAgentKeylessFulcioToken(cmd, ro.PlatformURL, pc.Fulcio, cred)
	if err != nil {
		return err
	}
	if principal == nil {
		return nil
	}
	ro.agentPrincipal = principal
	ro.refreshFulcioToken = refresh
	_ = os.Setenv(platformURLEnv, auth.NormalizeURL(ro.PlatformURL))
	return nil
}
