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
	"sort"
	"time"
)

// Agent principal credentials live in their own file, their own type, and their
// own functions, deliberately separate from the human session store above. The
// separation is the security property, not a filing convenience: the pushgate
// agent-policy contract requires an agent to present an agent subject and never
// borrow the human's email subject, so for every path that presents an
// identity the two credentials share no lookup, no type, and no fallback.
// Nothing here touches the human session store (legacy file or shared keyring).
// The one reader of both stores is the Git verifier, and it reads them for a
// trust pin only, never for a bearer or a principal: agent first, and a pin in
// either store binds (cli/git_verify.go).
//
// The refresh credential is a bearer secret (RFC 6750 §5): stored 0600, sent
// only to the platform's own credential-exchange endpoint over TLS, and never
// printed after the one command that accepts it. The tenant and agent UUIDs are
// NOT secret — they are SPIFFE path segments that appear in every certificate
// this credential buys — and are shown freely.

// AgentCredential is one enrolled agent principal for a platform: the two
// SPIFFE path segments that name it plus the opaque refresh credential the
// platform issued at enrollment.
type AgentCredential struct {
	// EnrolledAt orders local enrollments; migrated credentials retain zero.
	EnrolledAt  time.Time `json:"enrolled_at,omitzero"`
	PlatformURL string    `json:"platform_url"`
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
	// TrustBundleSPKI is the Git verifier's trust-on-first-use pin: the SHA-256
	// hex of the platform's discovery trust_bundle_pem, the same value the human
	// session pins (Credential.TrustBundleSPKI). It lets an enrolled agent verify
	// platform Git signatures without a human login. Same TOFU limit as
	// TrustDomain. A 4.4.x binary rewriting this file drops it, and the next
	// verification pins again.
	TrustBundleSPKI string `json:"trust_bundle_spki,omitempty"`
	// Scope is the repository scope the platform answered at this
	// credential's most recent successful exchange. A REPORT for `agent
	// status`, never authority: nothing on this machine enforces it, and the
	// gate re-resolves scope at every push. Nil means UNKNOWN (an older store,
	// an older platform, a credential not yet exchanged, or an answer cilock
	// could not read), never "all".
	Scope *AgentScope `json:"scope,omitempty"`
}

// AgentScope is one answered repository scope. Mode is "listed" or "all";
// Repositories is non-nil exactly when Mode is "listed" (empty means the
// agent may sign for no repository). AnsweredAt dates the answer, so a stale
// record says how stale it is.
type AgentScope struct {
	Mode         string             `json:"mode"`
	Repositories []ScopedRepository `json:"repositories,omitzero"`
	AnsweredAt   time.Time          `json:"answered_at"`
}

// The two scope modes the platform answers. "unknown" is never stored.
const (
	AgentScopeAll    = "all"
	AgentScopeListed = "listed"
)

// ScopedRepository is one repository a listed scope names: the immutable
// GitHub repository id the gate binds, and a display-only URL.
type ScopedRepository struct {
	ID  string `json:"id"`
	URL string `json:"url,omitempty"`
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

// agentFileStore keys each slot by the JSON tuple [normalized platform, agent
// ID] in memory. Tuple encoding avoids delimiter collisions. Pending redemption
// and active signing credentials remain separate.
//
// The on-disk format is never changed implicitly: version 1 (no "version",
// platform-keyed slots) is what older cilock binaries read, git's signer
// included, and a plain read rewriting it as v2 cut them all off on
// 2026-09-30. Writers keep the format they found; only MigrateAgentStore
// produces version 2.
type agentFileStore struct {
	Agents  map[string]AgentCredential
	Pending map[string]AgentCredential
	format  int
}

// agentFileStoreV1 is the version 1 encoding: no version field at all, so an
// older binary reads it exactly as it always has.
type agentFileStoreV1 struct {
	Agents  map[string]AgentCredential `json:"agents"`
	Pending map[string]AgentCredential `json:"pending,omitempty"`
}

// agentFileStoreV2 stores slots as LISTS: a version 1 binary decodes slots
// as platform-keyed maps without checking the version, so a map would read as
// "no agent" and sign as the human. A list fails that decode, closed.
type agentFileStoreV2 struct {
	Version int               `json:"version"`
	Agents  []AgentCredential `json:"agents"`
	Pending []AgentCredential `json:"pending,omitempty"`
}

// ErrAgentStoreNeedsMigration refuses a write a version 1 store cannot hold
// without evicting a live agent.
var ErrAgentStoreNeedsMigration = errors.New("this machine's agent credential store is version 1, which holds one agent per platform")

func agentKey(platform, id string) string {
	key, _ := json.Marshal([2]string{NormalizeURL(platform), id})
	return string(key)
}

// AgentStorePath is cilock's agent-credential file, a sibling of StorePath in
// the same cilock-owned config directory. A distinct filename so an operator
// (and `ls -l`) can tell the agent principal from the human session.
func AgentStorePath() (string, error) {
	dir, err := cilockStateDirectory()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(dir, "agent-credentials.json"), nil
}

func loadAgents() (*agentFileStore, error) { return readAgents() }

// loadAgentsLocked is loadAgents for a read-modify-write under the store lock.
func loadAgentsLocked() (*agentFileStore, error) { return readAgents() }

// readAgents never writes: it reports the store and the format it found. A
// missing file is an empty version 1 store.
func readAgents() (*agentFileStore, error) {
	path, err := AgentStorePath()
	if err != nil {
		return nil, err
	}
	var raw struct {
		Version int             `json:"version"`
		Agents  json.RawMessage `json:"agents"`
		Pending json.RawMessage `json:"pending"`
	}
	if err := readStoreFile(path, "agent credential store", &raw); err != nil {
		return nil, err
	}
	if raw.Version != 0 && raw.Version != 1 && raw.Version != 2 {
		return nil, fmt.Errorf("unsupported agent credential store version %d; upgrade all local Cilock callers", raw.Version)
	}
	s := agentFileStore{format: 1}
	if raw.Version == 2 {
		s.format = 2
	}
	if s.Agents, err = decodeAgentSlot(raw.Agents, s.format); err != nil {
		return nil, err
	}
	if s.Pending, err = decodeAgentSlot(raw.Pending, s.format); err != nil {
		return nil, err
	}
	return &s, nil
}

// decodeAgentSlot reads one slot in the given format and keys it by
// (platform, agent ID). A v1 key must name its entry's platform; a v2 list
// must not hold the same identity twice.
func decodeAgentSlot(raw json.RawMessage, format int) (map[string]AgentCredential, error) {
	stored, err := slotEntries(raw, format)
	if err != nil {
		return nil, err
	}
	entries := map[string]AgentCredential{}
	for _, c := range stored {
		c, err = normalizeStoredAgent(c)
		if err != nil {
			return nil, fmt.Errorf("invalid stored agent identity: %w", err)
		}
		key := agentKey(c.PlatformURL, c.AgentID)
		if _, dup := entries[key]; dup {
			return nil, fmt.Errorf("agent credential store holds agent %s twice", c.AgentID)
		}
		entries[key] = c
	}
	return entries, nil
}

func slotEntries(raw json.RawMessage, format int) ([]AgentCredential, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	if format == 2 {
		var stored []AgentCredential
		if err := json.Unmarshal(raw, &stored); err != nil {
			return nil, fmt.Errorf("parse agent credential store: %w", err)
		}
		return stored, nil
	}
	var keyed map[string]AgentCredential
	if err := json.Unmarshal(raw, &keyed); err != nil {
		return nil, fmt.Errorf("parse agent credential store: %w", err)
	}
	stored := make([]AgentCredential, 0, len(keyed))
	for key, c := range keyed {
		if NormalizeURL(key) != NormalizeURL(c.PlatformURL) {
			return nil, fmt.Errorf("agent credential store key does not match its identity")
		}
		stored = append(stored, c)
	}
	return stored, nil
}

// sortedAgents lists a slot in (platform, agent ID) order, so a save writes
// the same bytes for the same store.
func sortedAgents(slot map[string]AgentCredential) []AgentCredential {
	out := make([]AgentCredential, 0, len(slot))
	for _, c := range slot {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PlatformURL != out[j].PlatformURL {
			return out[i].PlatformURL < out[j].PlatformURL
		}
		return out[i].AgentID < out[j].AgentID
	})
	return out
}

func saveAgents(s *agentFileStore) error {
	path, err := AgentStorePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	var doc any
	if s.format == 2 {
		v2 := agentFileStoreV2{Version: 2, Agents: sortedAgents(s.Agents)}
		if len(s.Pending) > 0 {
			v2.Pending = sortedAgents(s.Pending)
		}
		doc = v2
	} else {
		v1, err := encodeV1(s)
		if err != nil {
			return err
		}
		doc = v1
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return writeStoreFile0600(path, data)
}

// encodeV1 writes one entry per platform per slot, as version 1 readers expect.
func encodeV1(s *agentFileStore) (agentFileStoreV1, error) {
	v1 := agentFileStoreV1{Agents: map[string]AgentCredential{}, Pending: map[string]AgentCredential{}}
	for _, pair := range []struct{ from, to map[string]AgentCredential }{{s.Agents, v1.Agents}, {s.Pending, v1.Pending}} {
		for _, c := range pair.from {
			if _, dup := pair.to[c.PlatformURL]; dup {
				return v1, ErrAgentStoreNeedsMigration
			}
			pair.to[c.PlatformURL] = c
		}
	}
	return v1, nil
}

func normalizeStoredAgent(c AgentCredential) (AgentCredential, error) {
	c.PlatformURL = NormalizeURL(c.PlatformURL)
	if c.PlatformURL == "" || c.TenantID == "" || c.AgentID == "" || c.RefreshCredential == "" {
		return c, fmt.Errorf("agent credential needs a platform URL, tenant id, agent id, and refresh credential")
	}
	return c, nil
}

// admitV1 makes room for c in a version 1 slot (one agent per platform). A
// different live agent in the active slot is refused, never evicted (the
// 2026-09-30 14:31Z outage); an expired or pending one is replaced.
func (s *agentFileStore) admitV1(c AgentCredential, slot map[string]AgentCredential) error {
	if s.format == 2 {
		return nil
	}
	for _, other := range s.Agents {
		if other.PlatformURL == c.PlatformURL && other.AgentID != c.AgentID && !other.Expired(time.Now()) {
			return fmt.Errorf("%w, and agent %s is still live there. To keep both, run `cilock agent migrate` "+
				"after upgrading every local cilock caller (installed cilock, git signing, jade, mint workers); "+
				"to replace it, run `cilock agent remove %s` first: %w",
				ErrAgentStoreNeedsMigration, other.AgentID, other.AgentID, errAgentStoreUnchanged)
		}
	}
	for key, other := range slot {
		if other.PlatformURL == c.PlatformURL && other.AgentID != c.AgentID {
			delete(slot, key)
		}
	}
	return nil
}

var errAgentStoreUnchanged = errors.New("the store was not changed")

// MigrateAgentStore explicitly rewrites the store as version 2 and reports a
// change; v2 is left alone. Older binaries cannot read the result.
func MigrateAgentStore() (bool, error) {
	path, err := AgentStorePath()
	if err != nil {
		return false, err
	}
	var migrated bool
	err = withStoreLock(path, func() error {
		s, err := loadAgentsLocked()
		if err != nil {
			return err
		}
		if s.format == 2 {
			return nil
		}
		s.format = 2
		migrated = true
		return saveAgents(s)
	})
	return migrated, err
}

// SaveAgent adds an active identity or replaces only that ID. An explicit
// login supersedes a pending credential only for the same ID under this platform.
func SaveAgent(c AgentCredential) error {
	c, err := normalizeStoredAgent(c)
	if err != nil {
		return err
	}
	if c.EnrolledAt.IsZero() {
		c.EnrolledAt = time.Now().UTC()
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
		s, err := loadAgentsLocked()
		if err != nil {
			return err
		}
		if err := s.admitV1(c, s.Agents); err != nil {
			return err
		}
		s.Agents[agentKey(c.PlatformURL, c.AgentID)] = c
		delete(s.Pending, agentKey(c.PlatformURL, c.AgentID))
		if s.format != 2 {
			// v1: supersede every pending credential, or an old cilock promotes it.
			for key, p := range s.Pending {
				if p.PlatformURL == c.PlatformURL {
					delete(s.Pending, key)
				}
			}
		}
		return saveAgents(s)
	})
}

// SavePendingAgent stores (or replaces) the PENDING credential for its
// platform and agent ID: delivered by a ceremony, not yet redeemed. The active slot is
// untouched — until the platform has answered for this credential, the
// identity this machine signs with is whatever it was.
func SavePendingAgent(c AgentCredential) error {
	c, err := normalizeStoredAgent(c)
	if err != nil {
		return err
	}
	if c.EnrolledAt.IsZero() {
		c.EnrolledAt = time.Now().UTC()
	}
	path, err := AgentStorePath()
	if err != nil {
		return err
	}
	return withStoreLock(path, func() error {
		s, err := loadAgentsLocked()
		if err != nil {
			return err
		}
		if err := s.admitV1(c, s.Pending); err != nil {
			return err
		}
		s.Pending[agentKey(c.PlatformURL, c.AgentID)] = c
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
	return newestAgent(s.Pending, platformURL), nil
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
		s, err := loadAgentsLocked()
		if err != nil {
			return err
		}
		key := agentKey(expect.PlatformURL, expect.AgentID)
		c, ok := s.Pending[key]
		if !ok || !c.sameIdentity(expect) {
			return ErrAgentCredentialReplaced
		}
		if err := s.admitV1(c, s.Agents); err != nil {
			return err
		}
		if c.EnrolledAt.IsZero() { // a legacy entry: promotion makes it the newest
			c.EnrolledAt = time.Now().UTC()
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
		s, lerr := loadAgentsLocked()
		if lerr != nil {
			return lerr
		}
		key := agentKey(expect.PlatformURL, expect.AgentID)
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
// EnrolledAgentPlatforms returns the normalized platform URLs this machine
// holds ANY agent credential for — redeemed or still pending — sorted for
// stable messages. A pending credential counts: the next exchange against its
// platform will redeem it, so for "which platform should this signature target"
// it is as enrolled as an active one.
//
// This exists so signing paths can resolve their platform agent-first instead
// of env-first (judge#8738): a signer that consults only an env var or the
// compiled default silently falls through to the human session whenever the
// enrolled platform is anything else.
func EnrolledAgentPlatforms() ([]string, error) {
	s, err := loadAgents()
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var urls []string
	for _, c := range s.Agents {
		u := c.PlatformURL
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			urls = append(urls, u)
		}
	}
	for _, c := range s.Pending {
		u := c.PlatformURL
		if _, ok := seen[u]; !ok {
			seen[u] = struct{}{}
			urls = append(urls, u)
		}
	}
	sort.Strings(urls)
	return urls, nil
}

func LookupAgent(platformURL string) (*AgentCredential, error) {
	s, err := loadAgents()
	if err != nil {
		return nil, err
	}
	return newestAgent(s.Agents, platformURL), nil
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
		s, err := loadAgentsLocked()
		if err != nil {
			return err
		}
		key := agentKey(expect.PlatformURL, expect.AgentID)
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
		s, lerr := loadAgentsLocked()
		if lerr != nil {
			return lerr
		}
		key := agentKey(expect.PlatformURL, expect.AgentID)
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

// PinAgentTrustBundle is a COMPARE-AND-SET on the Git verifier's trust pin for
// expect, in whichever slot holds it: empty records spki, equal is a no-op,
// different refuses. persisted is false with a nil error when no credential
// for the platform is stored (logged out in between); the caller MUST refuse
// then, or it would adopt a network bundle with no pin on disk. That is why
// this does not use updateAgentIf, which treats absence as success. Expiry is
// not checked: verification is not signing authority.
func PinAgentTrustBundle(expect AgentCredential, spki string) (persisted bool, err error) {
	path, err := AgentStorePath()
	if err != nil {
		return false, err
	}
	err = withStoreLock(path, func() error {
		s, lerr := loadAgentsLocked()
		if lerr != nil {
			return lerr
		}
		key := agentKey(expect.PlatformURL, expect.AgentID)
		for _, slot := range []map[string]AgentCredential{s.Agents, s.Pending} {
			c, ok := slot[key]
			if !ok || !c.sameIdentity(expect) {
				continue
			}
			switch {
			case c.TrustBundleSPKI == spki:
				persisted = true
				return nil
			case c.TrustBundleSPKI != "":
				return fmt.Errorf("this agent pinned platform signing trust %s but the platform now serves %s; "+
					"have your human validate the rotation, then re-enroll (`cilock enroll agent`)", c.TrustBundleSPKI, spki)
			}
			c.TrustBundleSPKI = spki
			slot[key] = c
			if serr := saveAgents(s); serr != nil {
				return serr
			}
			persisted = true
			return nil
		}
		_, active := s.Agents[key]
		_, pending := s.Pending[key]
		if active || pending {
			return ErrAgentCredentialReplaced
		}
		return nil
	})
	return persisted && err == nil, err
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

// RecordAgentScope overwrites the scope recorded for the credential that was
// exchanged; nil records UNKNOWN. Same compare-and-swap as the pin and the
// ceiling: an answer for one credential never lands on a replacement.
func RecordAgentScope(expect AgentCredential, scope *AgentScope) error {
	return updateAgentIf(expect, func(c *AgentCredential) bool {
		if c.Scope == nil && scope == nil {
			return false
		}
		c.Scope = scope
		return true
	})
}

// DeleteAgent removes ALL local agent credentials for a platform URL and reports
// whether one existed. It removes only this machine's copy; the principal on
// the platform stays valid until a human revokes it there.
func DeleteAgent(platformURL string) (bool, error) {
	path, err := AgentStorePath()
	if err != nil {
		return false, err
	}
	var existed bool
	err = withStoreLock(path, func() error {
		s, lerr := loadAgentsLocked()
		if lerr != nil {
			return lerr
		}
		for _, slot := range []map[string]AgentCredential{s.Agents, s.Pending} {
			for key, c := range slot {
				if c.PlatformURL == NormalizeURL(platformURL) {
					delete(slot, key)
					existed = true
				}
			}
		}
		if !existed {
			return nil
		}
		return saveAgents(s)
	})
	return existed, err
}

// Compatibility lookup until repository-aware selection is wired into signing.
// Map iteration must never choose an identity.
func newestAgent(slot map[string]AgentCredential, platform string) *AgentCredential {
	var best *AgentCredential
	for _, c := range slot {
		if c.PlatformURL != NormalizeURL(platform) {
			continue
		}
		if best == nil || c.EnrolledAt.After(best.EnrolledAt) || (c.EnrolledAt.Equal(best.EnrolledAt) && c.AgentID < best.AgentID) {
			copy := c
			best = &copy
		}
	}
	return best
}

// ListAgents returns active or pending credentials for one platform in stable
// ID order. Callers must never serialize these bearer-bearing values for output.
func ListAgents(platform string, pending bool) ([]AgentCredential, error) {
	s, err := loadAgents()
	if err != nil {
		return nil, err
	}
	slot := s.Agents
	if pending {
		slot = s.Pending
	}
	var out []AgentCredential
	for _, c := range slot {
		if c.PlatformURL == NormalizeURL(platform) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out, nil
}

// LookupAgentID binds management and enrollment readback to exactly one ID.
func LookupAgentID(platform, id string, pending bool) (*AgentCredential, error) {
	s, err := loadAgents()
	if err != nil {
		return nil, err
	}
	slot := s.Agents
	if pending {
		slot = s.Pending
	}
	c, ok := slot[agentKey(platform, id)]
	if !ok {
		return nil, nil
	}
	return &c, nil
}
