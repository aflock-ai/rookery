// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"fmt"
	"os"
	"time"

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
	// uploadToken is the Archivista bearer the exchange handed back; "" when
	// the platform minted none.
	uploadToken string
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
	// REFUSE A DEAD IDENTITY BEFORE THE COMMAND, NOT AFTER IT.
	//
	// This is the earliest point at which the run has decided the agent
	// principal is the identity that signs, and the credential's ceiling is a
	// LOCAL fact — recorded at enrollment, readable with no network. Discovering
	// it at signing time instead spends the whole wrapped command (a full test
	// run, minutes to tens of minutes) to produce a refusal that was knowable
	// before the first attestor ran. Observed three times on 2026-09-02.
	//
	// Two precedents make this the established shape rather than a new one:
	// cli/run.go's preRunGates refuses BEFORE the build when a stored principal
	// would store nothing (EnforceEvidenceStorage), and cli/keyloader.go refuses
	// an already-expired identity token up front "so long builds cannot outlive
	// their signing certificate". Same rule, one layer up: the credential that
	// buys the token is checked on the same terms as the token.
	//
	// It does NOT fall back to the human session. An enrolled agent credential
	// pre-empts the human session machine-wide; falling back would put a human's
	// name on an agent's work, which is the borrowed-identity result the agent
	// principal exists to remove. The error names both remedies instead and the
	// operator picks one.
	//
	// CheckSigningEligibility is the same predicate `cilock agent status`
	// reports, so the report and the gate cannot disagree. It runs after the
	// fulcioSignerNeedsToken return above on purpose: when the operator supplied
	// their own signer, no agent identity is claimed by this run, and a stale
	// enrollment on the machine is not that run's business.
	if err := cred.CheckSigningEligibility(time.Now()); err != nil {
		return nil, nil, fmt.Errorf("this run would sign against %s as an enrolled agent, but %w", platformURL, err)
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
	principal := &agentPrincipal{spiffeID: id.SPIFFEID, uploadToken: id.UploadToken}

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
		principal.uploadToken = fresh.UploadToken
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
// Archivista: the human session's bearer is not the agent's to spend, so the
// agent presents the UPLOAD TOKEN the exchange minted for it — its own
// identity, scoped to attestation:upload — and uploads BY DEFAULT, exactly as
// a human session does (ResolvePlatformDefaults). The first prod ceremony
// (2026-09-02) signed as the agent, printed "upload DISABLED", exited 0, and
// the push was refused for having no evidence: an agent whose evidence stays
// on its own disk has not produced evidence. So a platform that hands back no
// upload token is a FAILURE of the identity path, not a quieter success —
// unless the operator explicitly asked for sign-only (--enable-archivista=false)
// or supplied their own Archivista Authorization header.
func (ro *RunOptions) applyAgentCredential(cmd *cobra.Command, cred auth.AgentCredential, pc platformconfig.PlatformConfig) error {
	principal, refresh, err := applyAgentKeylessFulcioToken(cmd, ro.PlatformURL, pc.Fulcio, cred)
	if err != nil {
		return err
	}
	if principal == nil {
		return nil
	}
	ro.agentPrincipal = principal
	// The evidence gate (EnforceEvidenceStorage) reads this, not agentPrincipal:
	// a run that signs as the agent and stores nothing must not exit 0 — the
	// 2026-09-02 incident — whatever this path decides about the upload below.
	ro.platformPrincipal = &platformPrincipal{Kind: "agent", Name: principal.spiffeID}
	ro.refreshFulcioToken = refresh
	_ = os.Setenv(platformURLEnv, auth.NormalizeURL(ro.PlatformURL))

	explicitOff := (cmd.Flags().Changed("enable-archivista") || cmd.Flags().Changed("enable-archivist")) && !ro.ArchivistaOptions.Enable
	if explicitOff {
		return nil
	}
	if !hasAuthorizationHeader(ro.ArchivistaOptions.Headers) && sameOrigin(ro.ArchivistaOptions.Url, pc.Archivista) {
		if principal.uploadToken == "" {
			return fmt.Errorf("the platform at %s minted a signing token for agent %s but no upload token, so this run's evidence could not reach it; "+
				"the platform must issue agent upload tokens (no JWT signer configured?), or pass --enable-archivista=false to sign without uploading",
				ro.PlatformURL, principal.spiffeID)
		}
		ro.ArchivistaOptions.Headers = append(ro.ArchivistaOptions.Headers, "Authorization: Bearer "+principal.uploadToken)
	}
	if !cmd.Flags().Changed("enable-archivista") && !cmd.Flags().Changed("enable-archivist") {
		ro.ArchivistaOptions.Enable = true
	}
	return nil
}
