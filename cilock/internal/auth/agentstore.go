// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
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
	// ExpiresAt is the hard ceiling the platform answered with at enrollment —
	// the TTL the human confirmed (8h by default, 7d at most). It is a COPY of
	// the platform's decision, kept so `agent status` can say when this identity
	// stops signing and so an exchange the platform would certainly refuse is
	// not attempted. It is not authority: the platform re-checks its own copy
	// at every exchange, and a zero value here means "not recorded", never
	// "unbounded".
	ExpiresAt time.Time `json:"expires_at,omitzero"`
}

// Expired reports whether this credential is past the ceiling it recorded. A
// credential with no recorded ceiling is NOT reported expired: the platform
// holds the authoritative copy and answers for itself.
func (c AgentCredential) Expired(now time.Time) bool {
	return !c.ExpiresAt.IsZero() && !now.Before(c.ExpiresAt)
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
//
// TWO SLOTS PER PLATFORM. Agents holds the credential this machine SIGNS
// WITH: redeemed by the platform at least once. Pending holds a credential a
// ceremony DELIVERED that the platform has not yet redeemed. They are kept
// apart because redemption can fail transiently (the signer down, a proxy
// in the way), and a delivery that overwrote the active slot turned that
// outage into a lost identity: the new credential unredeemable once its
// window closed, the old one gone. A pending credential is promoted into
// the active slot by the exchange that redeems it, discarded by the
// platform's own refusal, and otherwise left for the next run to try again.
type agentFileStore struct {
	Agents  map[string]AgentCredential `json:"agents"`
	Pending map[string]AgentCredential `json:"pending,omitempty"`
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
	if s.Pending == nil {
		s.Pending = map[string]AgentCredential{}
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

func normalizeStoredAgent(c AgentCredential) (AgentCredential, error) {
	c.PlatformURL = NormalizeURL(c.PlatformURL)
	if c.PlatformURL == "" || c.TenantID == "" || c.AgentID == "" || c.RefreshCredential == "" {
		return c, fmt.Errorf("agent credential needs a platform URL, tenant id, agent id, and refresh credential")
	}
	return c, nil
}

// SaveAgent stores (or replaces) the ACTIVE agent credential for its platform
// URL — the one this machine signs with. `cilock agent login` (a credential
// minted elsewhere and handed over) lands here; a ceremony's delivery does
// not (SavePendingAgent), and a redeemed pending credential is moved here by
// PromotePendingAgentIf.
//
// An explicit active write SUPERSEDES anything pending for the platform, in
// the same locked write. The operator choosing an identity now is a later
// decision than a ceremony that delivered earlier and never redeemed; left
// in place, that older credential would be promoted over the login by the
// next run, and a promotion racing the login would find its slot still
// there. Clearing it here makes both impossible: the promotion's
// compare-and-swap finds the slot gone and refuses.
func SaveAgent(c AgentCredential) error {
	c, err := normalizeStoredAgent(c)
	if err != nil {
		return err
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
		delete(s.Pending, c.PlatformURL)
		return saveAgents(s)
	})
}

// SavePendingAgent stores (or replaces) the PENDING credential for its
// platform URL: delivered by a ceremony, not yet redeemed. The active slot is
// untouched — until the platform has answered for this credential, the
// identity this machine signs with is whatever it was.
func SavePendingAgent(c AgentCredential) error {
	c, err := normalizeStoredAgent(c)
	if err != nil {
		return err
	}
	path, err := AgentStorePath()
	if err != nil {
		return err
	}
	return withStoreLock(path, func() error {
		s, err := loadAgents()
		if err != nil {
			return err
		}
		s.Pending[c.PlatformURL] = c
		return saveAgents(s)
	})
}

// LookupPendingAgent returns the delivered-but-unredeemed credential for
// platformURL, or nil when there is none. Same error contract as LookupAgent.
func LookupPendingAgent(platformURL string) (*AgentCredential, error) {
	s, err := loadAgents()
	if err != nil {
		return nil, err
	}
	c, ok := s.Pending[NormalizeURL(platformURL)]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

// PromotePendingAgentIf moves the pending credential for expect's platform
// into the active slot — pin, ceiling and all — only if what is pending IS
// expect (sameIdentity). This is the one write that changes which identity
// the machine signs with as a result of a ceremony, and it happens only
// after the platform redeemed that exact credential. A pending slot that is
// empty or holds another ceremony's credential is ErrAgentCredentialReplaced.
func PromotePendingAgentIf(expect AgentCredential) error {
	path, err := AgentStorePath()
	if err != nil {
		return err
	}
	return withStoreLock(path, func() error {
		s, err := loadAgents()
		if err != nil {
			return err
		}
		key := NormalizeURL(expect.PlatformURL)
		c, ok := s.Pending[key]
		if !ok || !c.sameIdentity(expect) {
			return ErrAgentCredentialReplaced
		}
		s.Agents[key] = c
		delete(s.Pending, key)
		return saveAgents(s)
	})
}

// DeletePendingAgentIf removes the pending credential for expect's platform
// only if it IS expect. Reports whether it was removed; an absent or
// different pending credential is left alone and reported as not removed.
func DeletePendingAgentIf(expect AgentCredential) (bool, error) {
	path, err := AgentStorePath()
	if err != nil {
		return false, err
	}
	var removed bool
	err = withStoreLock(path, func() error {
		s, lerr := loadAgents()
		if lerr != nil {
			return lerr
		}
		key := NormalizeURL(expect.PlatformURL)
		c, ok := s.Pending[key]
		if !ok || !c.sameIdentity(expect) {
			return nil
		}
		delete(s.Pending, key)
		removed = true
		return saveAgents(s)
	})
	return removed, err
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

// sameIdentity reports whether two stored credentials are THE SAME
// credential: same platform, tenant, agent, and bearer. Everything an
// exchange derives — a pin, a ceiling — belongs to exactly the credential
// that was presented, and a store entry that differs in any of these is a
// different identity another command put there.
func (c AgentCredential) sameIdentity(o AgentCredential) bool {
	return NormalizeURL(c.PlatformURL) == NormalizeURL(o.PlatformURL) &&
		c.TenantID == o.TenantID && c.AgentID == o.AgentID && c.RefreshCredential == o.RefreshCredential
}

// ErrAgentCredentialReplaced is returned by the compare-and-swap mutators when
// the store no longer holds the credential the caller derived its update
// from: another enroll or login replaced it in the meantime.
var ErrAgentCredentialReplaced = errors.New("the stored agent credential was replaced by another command")

// updateAgentIf applies fn to the stored credential for expect's platform, but
// ONLY if what is stored is expect itself (sameIdentity) — in WHICHEVER slot
// holds it: a pending credential is exchanged at redemption, and the pin and
// ceiling that exchange answers belong to it just as they would to an active
// one. Under the store lock, so the read and the write are one decision.
// Absent from both slots is a no-op (the agent was logged out in between;
// nothing left to protect); present-but-different in the slot that matches
// its platform is ErrAgentCredentialReplaced, never a write onto someone
// else's credential.
func updateAgentIf(expect AgentCredential, fn func(c *AgentCredential) (changed bool)) error {
	path, err := AgentStorePath()
	if err != nil {
		return err
	}
	return withStoreLock(path, func() error {
		s, err := loadAgents()
		if err != nil {
			return err
		}
		key := NormalizeURL(expect.PlatformURL)
		for _, slot := range []map[string]AgentCredential{s.Agents, s.Pending} {
			c, ok := slot[key]
			if !ok || !c.sameIdentity(expect) {
				continue
			}
			if !fn(&c) {
				return nil
			}
			slot[key] = c
			return saveAgents(s)
		}
		// Neither slot holds this credential. Nothing at all for the platform
		// is a logout in between — nothing left to protect. Anything else for
		// the platform means the store moved under the caller.
		_, active := s.Agents[key]
		_, pending := s.Pending[key]
		if active || pending {
			return ErrAgentCredentialReplaced
		}
		return nil
	})
}

// DeleteAgentIf removes the stored credential for expect's platform only if
// it IS expect. Reports whether it was removed.
func DeleteAgentIf(expect AgentCredential) (bool, error) {
	path, err := AgentStorePath()
	if err != nil {
		return false, err
	}
	var removed bool
	err = withStoreLock(path, func() error {
		s, lerr := loadAgents()
		if lerr != nil {
			return lerr
		}
		key := NormalizeURL(expect.PlatformURL)
		c, ok := s.Agents[key]
		if !ok {
			return nil
		}
		if !c.sameIdentity(expect) {
			return ErrAgentCredentialReplaced
		}
		delete(s.Agents, key)
		removed = true
		return saveAgents(s)
	})
	return removed, err
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
//
// It pins onto THE CREDENTIAL THAT WAS EXCHANGED (expect), never onto whatever
// the store holds now: a concurrent enroll or login can have replaced the
// entry during the exchange, and a pin derived from one identity's answer
// must not land on another's.
func PinAgentTrustDomain(expect AgentCredential, trustDomain string) error {
	var mismatch error
	err := updateAgentIf(expect, func(c *AgentCredential) bool {
		if c.TrustDomain != "" {
			if c.TrustDomain != trustDomain {
				mismatch = fmt.Errorf(
					"this agent is pinned to the trust domain %q but the platform answered %q",
					c.TrustDomain, trustDomain)
			}
			return false
		}
		c.TrustDomain = trustDomain
		return true
	})
	if err != nil {
		return err
	}
	return mismatch
}

// RecordAgentExpiry overwrites the stored ceiling for platformURL with the one
// the platform answered at exchange. Unlike the trust-domain pin this is not
// first-use-only: the platform's copy is authoritative every time, and a
// mismatch with what the callback carried is corrected, not refused. No
// credential stored is a no-op.
//
// Same rule as the pin: the ceiling belongs to the credential that was
// exchanged, and is written only if that credential is still what is stored.
func RecordAgentExpiry(expect AgentCredential, expiresAt time.Time) error {
	return updateAgentIf(expect, func(c *AgentCredential) bool {
		if c.ExpiresAt.Equal(expiresAt) {
			return false
		}
		c.ExpiresAt = expiresAt
		return true
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
		_, active := s.Agents[key]
		_, pending := s.Pending[key]
		if !active && !pending {
			return nil
		}
		delete(s.Agents, key)
		delete(s.Pending, key)
		existed = true
		return saveAgents(s)
	})
	return existed, err
}
