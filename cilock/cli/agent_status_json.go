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
}

func writeAgentStatusJSON(out io.Writer, platformURL string, cred, pending *auth.AgentCredential, now time.Time) error {
	status := agentStatusJSON{
		PlatformURL: auth.NormalizeURL(platformURL),
		Pending:     pending != nil,
		Status:      "not_enrolled",
		Source:      "local_store",
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
