// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Agent principal credentials live in their own file, their own type, and their
// own functions, deliberately separate from the human session store above. The
// separation is the security property, not a filing convenience: the pushgate
// agent-policy contract requires an agent to present an agent subject and never
// borrow the human's email subject, so the two credentials share no lookup, no
// type, and no fallback. Nothing here touches the human session store (legacy
// file or shared keyring), and nothing in the human path reads this file.
//
// The refresh credential is a bearer secret (RFC 6750 §5): stored 0600, sent
// only to the platform's own credential-exchange endpoint over TLS, and never
// printed after the one command that accepts it. The tenant and agent UUIDs are
// NOT secret — they are SPIFFE path segments that appear in every certificate
// this credential buys — and are shown freely.

// AgentCredential is the enrolled agent principal for one platform: the two
// SPIFFE path segments that name it plus the opaque refresh credential the
// platform issued at enrollment.
type AgentCredential struct {
	PlatformURL string `json:"platform_url"`
	// TenantID and AgentID are the `tenant/<id>/agent/<id>` segments of the
	// SPIFFE ID this principal signs under. Not secret.
	TenantID string `json:"tenant_id"`
	AgentID  string `json:"agent_id"`
	// RefreshCredential is the opaque bearer credential minted at enrollment.
	// SECRET. It goes to the credential-exchange endpoint and nowhere else — in
	// particular never to Fulcio, which sees only the short-lived token the
	// exchange returns.
	RefreshCredential string `json:"refresh_credential"`
	// TrustDomain is the SPIFFE authority this principal signs under — the
	// remaining third of the identity, and the only part the operator does NOT
	// supply at enrollment.
	//
	// It is stored because without it the exchange can only check the tenant and
	// agent segments, which leaves the trust domain entirely the server's choice:
	// `spiffe://someone-elses-factory/tenant/<mine>/agent/<mine>` would satisfy a
	// tenant+agent comparison while naming a principal in a namespace this
	// operator never enrolled in. A SPIFFE ID is the WHOLE path including its
	// authority, so checking two thirds of it is not checking the identity.
	//
	// TRUST ON FIRST USE, and the limitation is real: empty means "not yet
	// pinned", the first successful exchange records what the platform answered,
	// and every exchange after that must match it exactly. So a platform that is
	// hostile or misconfigured at the moment of FIRST use pins the wrong value
	// and nothing here detects it. What this does close is every subsequent
	// change — the case where an enrolled agent silently starts signing under a
	// different authority — and it makes the pinned value visible in a file an
	// operator can read and correct.
	TrustDomain string `json:"trust_domain,omitempty"`
}

// String renders the credential with the secret replaced, so a stray %v, %s or
// error wrap cannot spill the bearer into a log line or a run summary. The
// identifying fields stay visible because they are what an operator needs to
// read. It is on the value receiver so %v on an *AgentCredential picks it up too.
func (c AgentCredential) String() string {
	return fmt.Sprintf("agent{platform:%s tenant:%s agent:%s credential:REDACTED}",
		c.PlatformURL, c.TenantID, c.AgentID)
}

// agentFileStore is the on-disk shape: agent credentials keyed by normalized
// platform URL. There is no active-platform pointer — an agent is enrolled
// against a specific platform and is selected by the URL the run targets.
type agentFileStore struct {
	Agents map[string]AgentCredential `json:"agents"`
}

// AgentStorePath is cilock's agent-credential file, a sibling of StorePath in
// the same cilock-owned config directory. A distinct filename so an operator
// (and `ls -l`) can tell the agent principal from the human session.
func AgentStorePath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "cilock", "agent-credentials.json"), nil
}

func loadAgents() (*agentFileStore, error) {
	path, err := AgentStorePath()
	if err != nil {
		return nil, err
	}
	var s agentFileStore
	if err := readStoreFile(path, "agent credential store", &s); err != nil {
		return nil, err
	}
	// A store file that exists but carries a null map, and a store file that does
	// not exist at all, both arrive here as the zero value — so the nil-map fill
	// covers both and there is no "missing file" branch to get wrong.
	if s.Agents == nil {
		s.Agents = map[string]AgentCredential{}
	}
	return &s, nil
}

func saveAgents(s *agentFileStore) error {
	path, err := AgentStorePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeStoreFile0600(path, data)
}

// SaveAgent stores (or replaces) the agent credential for its platform URL.
func SaveAgent(c AgentCredential) error {
	c.PlatformURL = NormalizeURL(c.PlatformURL)
	if c.PlatformURL == "" || c.TenantID == "" || c.AgentID == "" || c.RefreshCredential == "" {
		return fmt.Errorf("agent credential needs a platform URL, tenant id, agent id, and refresh credential")
	}
	path, err := AgentStorePath()
	if err != nil {
		return err
	}
	// Locked for the same reason as the pin: an unlocked read-modify-write here
	// lets a concurrent DeleteAgent be undone — this save rewrites the whole
	// store from a snapshot taken before the logout, resurrecting a credential
	// the operator just removed.
	return withStoreLock(path, func() error {
		s, err := loadAgents()
		if err != nil {
			return err
		}
		s.Agents[c.PlatformURL] = c
		return saveAgents(s)
	})
}

// LookupAgent returns the enrolled agent credential for platformURL, or nil
// when this machine has none for that platform.
//
// A non-nil error means the store exists but could not be read. Callers on a
// signing path MUST treat that as a hard stop rather than continuing to the
// human session: an unreadable agent store is exactly the case where falling
// through would sign as the human while the operator believes they are signing
// as the agent.
func LookupAgent(platformURL string) (*AgentCredential, error) {
	s, err := loadAgents()
	if err != nil {
		return nil, err
	}
	c, ok := s.Agents[NormalizeURL(platformURL)]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

// PinAgentTrustDomain is a COMPARE-AND-SET on the SPIFFE authority an enrolled
// agent signs under: it records trustDomain when nothing is pinned yet, and
// REFUSES when something else already is.
//
// An earlier version returned nil whenever a pin already existed, without
// looking at it. That was a fail-open with a race behind it: two first-use
// exchanges running concurrently both start unpinned, the first records domain
// X, and the second — answered with domain Y — found a non-empty pin, called it
// success, and signed under Y. "Write-once" protected the stored value and not
// the decision, which is the half that matters.
//
// EVERY FAILURE HERE IS THE CALLER'S REFUSAL, and that is a deliberate change
// from treating a pin as bookkeeping. If the store cannot be written, the pin
// never lands, so the NEXT run is unpinned too and the protection silently never
// engages — the operator learns nothing and the control they believe they have
// does not exist. A run that cannot record which authority it trusted is a run
// whose successor cannot detect that authority changing, and this whole path
// exists to stop signing under an authority nobody verified.
//
// A missing credential stays a non-error: the agent can be logged out between
// the exchange and this call, and there is nothing left to protect.
//
// THE RESIDUAL RACE IS NARROWED, NOT ELIMINATED, and the store has no file
// locking to eliminate it with. Two processes can both read an empty pin before
// either writes, and the loser's value is overwritten. What the comparison
// removes is the case that actually signs under the wrong authority: after
// either write lands, every later exchange — including the refresher inside the
// same run — compares against it and refuses. The exposure is therefore one
// exchange wide, and it requires two first-use runs concurrent against a
// platform that answers them differently.
func PinAgentTrustDomain(platformURL, trustDomain string) error {
	path, err := AgentStorePath()
	if err != nil {
		return err
	}
	return withStoreLock(path, func() error {
		s, err := loadAgents()
		if err != nil {
			return err
		}
		key := NormalizeURL(platformURL)
		c, ok := s.Agents[key]
		if !ok {
			return nil
		}
		if c.TrustDomain != "" {
			if c.TrustDomain != trustDomain {
				return fmt.Errorf(
					"this agent is pinned to the trust domain %q but the platform answered %q",
					c.TrustDomain, trustDomain)
			}
			return nil
		}
		c.TrustDomain = trustDomain
		s.Agents[key] = c
		return saveAgents(s)
	})
}

// DeleteAgent removes the agent credential for a platform URL and reports
// whether one existed. It removes only this machine's copy; the principal on
// the platform stays valid until a human revokes it there.
func DeleteAgent(platformURL string) (bool, error) {
	path, err := AgentStorePath()
	if err != nil {
		return false, err
	}
	var existed bool
	err = withStoreLock(path, func() error {
		s, lerr := loadAgents()
		if lerr != nil {
			return lerr
		}
		key := NormalizeURL(platformURL)
		if _, ok := s.Agents[key]; !ok {
			return nil
		}
		delete(s.Agents, key)
		existed = true
		return saveAgents(s)
	})
	return existed, err
}
