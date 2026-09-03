// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// CheckSigningEligibility is the ONE reading of local eligibility, so it is
// swept over the whole value space its inputs can take rather than over the
// cases the implementation happens to handle: a ceiling in the future, the
// instant of the ceiling itself (the boundary — "at" is past, not within), a
// ceiling behind us, and NO ceiling at all.
//
// The last row is the one that would fail dangerously in the other direction:
// a zero ExpiresAt means "not recorded", never "unbounded". Treating it as
// expired would ground every credential enrolled before the ceiling was ever
// stored; the platform holds the authoritative copy and answers for itself.
func TestCheckSigningEligibilitySweepsTheCeiling(t *testing.T) {
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		expiresAt time.Time
		expired   bool
	}{
		{name: "ceiling ahead", expiresAt: now.Add(time.Minute)},
		{name: "one nanosecond before the ceiling", expiresAt: now.Add(time.Nanosecond)},
		{name: "exactly at the ceiling", expiresAt: now, expired: true},
		{name: "ceiling behind", expiresAt: now.Add(-time.Hour), expired: true},
		{name: "no recorded ceiling", expiresAt: time.Time{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cred := AgentCredential{AgentID: "a-1", ExpiresAt: tc.expiresAt}
			err := cred.CheckSigningEligibility(now)

			assert.Equal(t, tc.expired, err != nil, "eligibility verdict")
			// The predicate and the refusal must be the SAME reading. Two
			// functions that could disagree is the defect this replaces.
			assert.Equal(t, cred.Expired(now), err != nil,
				"CheckSigningEligibility and Expired must be one reading, not two")
			if !tc.expired {
				return
			}
			var typed *ExpiredAgentCredentialError
			require.True(t, errors.As(err, &typed), "the refusal is matchable by type, not by substring")
			assert.Equal(t, "a-1", typed.AgentID)
			assert.Contains(t, err.Error(), "cilock enroll agent")
			assert.Contains(t, err.Error(), "cilock agent logout")
		})
	}
}

// Both ways out are named in one place, so a refusal cannot ship with only one
// of them. `cilock enroll agent` alone leaves an operator who does not want a
// new agent principal with no stated route back to their own session — and
// cilock will not silently take that route for them, because an enrolled agent
// pre-empts the human session machine-wide and a silent fallback would put a
// human's name on an agent's work.
func TestAgentSigningRemediesNameBothWaysOut(t *testing.T) {
	assert.Contains(t, AgentSigningRemedies, "cilock enroll agent")
	assert.Contains(t, AgentSigningRemedies, "cilock agent logout")
}

// A platform-side refusal — revoked, contained, unknown — is NOT locally
// knowable, so it stays at the exchange. But the operator's options are the
// same two, and the platform's refusal body is uniform by design and names
// none of them. The remedies are appended after redaction, so the credential
// still cannot come back in the text.
func TestPlatformRefusalCarriesTheSameTwoRemedies(t *testing.T) {
	isolateConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"agent_credential_rejected"}`))
	}))
	defer srv.Close()

	_, err := ExchangeAgentCredential(srv.URL, AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	})
	require.Error(t, err)
	require.True(t, IsAgentCredentialRejected(err))
	assert.Contains(t, err.Error(), "cilock enroll agent")
	assert.Contains(t, err.Error(), "cilock agent logout")
	assert.NotContains(t, err.Error(), theSecret)
}

// A refusal that is NOT the platform's own verdict — an outage, a proxy, a
// response that failed our checks — must not be dressed up with remedies that
// assume the identity is dead. The credential may be perfectly good, and
// telling an operator to re-enroll (or to log the agent out) during a platform
// outage is advice that destroys a working identity.
func TestATransientFailureIsNotGivenTheDeadIdentityRemedies(t *testing.T) {
	isolateConfig(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := ExchangeAgentCredential(srv.URL, AgentCredential{
		PlatformURL: srv.URL, TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	})
	require.Error(t, err)
	require.False(t, IsAgentCredentialRejected(err))
	assert.NotContains(t, err.Error(), "cilock agent logout")
}
