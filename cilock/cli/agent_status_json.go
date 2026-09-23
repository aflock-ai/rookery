// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// An explicit public projection prevents credential-store additions from
// silently becoming CLI output. Never marshal AgentCredential here.
type agentStatusJSON struct {
	PlatformURL     string    `json:"platform_url"`
	PrincipalKind   string    `json:"principal_kind"`
	TenantID        string    `json:"tenant_id"`
	AgentID         string    `json:"agent_id"`
	SPIFFEID        string    `json:"spiffe_id"`
	Active          bool      `json:"active"`
	Pending         bool      `json:"pending"`
	Eligible        bool      `json:"eligible"`
	Status          string    `json:"status"`
	ExpiresAt       time.Time `json:"expires_at,omitzero"`
	Source          string    `json:"source"`
	PlatformChecked bool      `json:"platform_checked"`
	// Scope is ALWAYS emitted: an absent key must never be read as a scope.
	Scope agentStatusScope `json:"scope"`
}

// agentStatusScope projects the recorded scope. "unknown" exists only here
// and is never stored. It never changes the exit code.
type agentStatusScope struct {
	Mode         string                  `json:"mode"`
	Repositories []auth.ScopedRepository `json:"repositories,omitzero"`
	AnsweredAt   time.Time               `json:"answered_at,omitzero"`
}

// projectAgentScope reads only the ACTIVE credential's record: a pending
// delivery has signed nothing, and not_enrolled has nothing to report. A
// stored mode other than the two known ones reads unknown, and a listed
// record without its list reads as listing none, never as all.
func projectAgentScope(cred *auth.AgentCredential) agentStatusScope {
	if cred == nil || cred.Scope == nil {
		return agentStatusScope{Mode: "unknown"}
	}
	switch cred.Scope.Mode {
	case auth.AgentScopeAll:
		return agentStatusScope{Mode: auth.AgentScopeAll, AnsweredAt: cred.Scope.AnsweredAt}
	case auth.AgentScopeListed:
		repos := cred.Scope.Repositories
		if repos == nil {
			repos = []auth.ScopedRepository{}
		}
		return agentStatusScope{Mode: auth.AgentScopeListed, Repositories: repos, AnsweredAt: cred.Scope.AnsweredAt}
	}
	return agentStatusScope{Mode: "unknown"}
}

// writeAgentScopeText is the one human rendering of the scope, shared by
// `agent status` and `enroll agent` so the two cannot disagree.
func writeAgentScopeText(out io.Writer, cred *auth.AgentCredential) {
	scope := projectAgentScope(cred)
	answered := scope.AnsweredAt.UTC().Format("2006-01-02 15:04 UTC")
	switch {
	case scope.Mode == auth.AgentScopeAll:
		_, _ = fmt.Fprintf(out, "  scope:  all repositories in the tenant, as answered %s\n", answered)
	case scope.Mode == auth.AgentScopeListed && len(scope.Repositories) == 0:
		_, _ = fmt.Fprintln(out, "  scope:  listed, NO repositories: every push this agent signs is refused (signer-out-of-scope)")
	case scope.Mode == auth.AgentScopeListed:
		_, _ = fmt.Fprintf(out, "  scope:  listed, as answered %s\n", answered)
		for _, r := range scope.Repositories {
			_, _ = fmt.Fprintf(out, "            repository %s  %s\n", r.ID, r.URL)
		}
	default:
		_, _ = fmt.Fprintln(out, "  scope:  unknown: the platform has not answered one to this machine; the gate decides at push")
	}
}

func writeAgentStatusJSON(out io.Writer, platformURL string, cred, pending *auth.AgentCredential, now time.Time) error {
	status := agentStatusJSON{
		PlatformURL: auth.NormalizeURL(platformURL),
		Pending:     pending != nil,
		Status:      "not_enrolled",
		Source:      "local_store",
		Scope:       projectAgentScope(cred),
	}
	identity := cred
	if identity == nil && pending != nil {
		identity = pending
		status.Status = "pending"
	}
	if identity != nil {
		status.PrincipalKind = "agent"
		status.TenantID = identity.TenantID
		status.AgentID = identity.AgentID
		status.ExpiresAt = identity.ExpiresAt
	}
	var ineligible error
	if cred != nil {
		ineligible = cred.CheckSigningEligibility(now)
		status.Eligible = ineligible == nil
		status.Active = cred.TrustDomain != ""
		status.Status = "unredeemed"
		if status.Active {
			status.SPIFFEID = fmt.Sprintf("spiffe://%s/tenant/%s/agent/%s", cred.TrustDomain, cred.TenantID, cred.AgentID)
			status.Status = "eligible"
		}
		if ineligible != nil {
			status.Status = "expired"
		}
	}
	if err := json.NewEncoder(out).Encode(status); err != nil {
		return fmt.Errorf("write agent status JSON: %w", err)
	}
	if ineligible != nil {
		return fmt.Errorf("cilock agent status: the enrolled agent principal for %s is expired", auth.NormalizeURL(platformURL))
	}
	return nil
}
