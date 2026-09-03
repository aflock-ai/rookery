// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"fmt"
	"time"
)

// AgentSigningRemedies is the tail EVERY refusal on the enrolled-agent signing
// path carries, whether the credential died on this machine's clock or the
// platform refused it.
//
// There are exactly two ways out, and naming only the first is what made the
// refusals confusing: an operator told to re-enroll, on a machine where
// re-enrollment is not what they want, has no visible way to get back to their
// own session — and cilock will not take it for them. An enrolled agent
// credential pre-empts the human session machine-wide by design, so falling
// back to `cilock login` on a dead agent credential would put a human's name on
// an agent's work. The operator chooses; these are the two choices.
const AgentSigningRemedies = "run `cilock enroll agent` for a new ceremony, " +
	"or `cilock agent logout` to sign as your own session"

// ExpiredAgentCredentialError is the refusal for a credential past the ceiling
// it recorded at enrollment. It is a type, not a string, so `cilock run` and
// `cilock agent status` can be tested for agreement by identity rather than by
// substring, and so a caller can tell this LOCAL verdict apart from a platform
// refusal it had to ask for.
type ExpiredAgentCredentialError struct {
	AgentID   string
	ExpiresAt time.Time
	Now       time.Time
}

func (e *ExpiredAgentCredentialError) Error() string {
	return fmt.Sprintf(
		"the agent principal %s expired at %s (%s ago) — this identity no longer signs; "+
			"its authority was time-bound at enrollment and cannot be extended: %s",
		e.AgentID, e.ExpiresAt.Format(time.RFC3339), e.Now.Sub(e.ExpiresAt).Round(time.Second),
		AgentSigningRemedies)
}

// CheckSigningEligibility is THE reading of whether this machine's stored agent
// credential may still be presented, and the only one. `cilock agent status`
// reports it, the pre-command gate in `cilock run` refuses on it, and the
// credential exchange re-checks it before spending a round trip — one function,
// so the report an operator reads and the gate that stops their build cannot
// disagree about the same stored credential.
//
// It is a purely LOCAL judgment: no network, no clock but the one passed in.
// Only a RECORDED ceiling counts. A zero ExpiresAt means "not recorded", never
// "unbounded" — the platform holds the authoritative copy and answers for
// itself, so an unrecorded ceiling is eligible here and refused there.
//
// nil means "nothing this machine knows disqualifies it", NOT "the platform
// will accept it". Revocation and containment are not locally knowable and stay
// where they are, at the exchange.
func (c AgentCredential) CheckSigningEligibility(now time.Time) error {
	if !c.Expired(now) {
		return nil
	}
	return &ExpiredAgentCredentialError{AgentID: c.AgentID, ExpiresAt: c.ExpiresAt, Now: now}
}
