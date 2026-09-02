// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// `cilock enroll agent` is the validator of the whole agent-identity path: a
// human approves in the browser, the platform mints, the credential lands in
// the store, and — new — the command REDEEMS it before it claims success. The
// ceremony itself is stubbed here (it needs a browser); what these tests pin
// is what the command does with its outcome.

func stubEnrollCeremony(t *testing.T, cred *auth.AgentCredential, ceremonyErr error) *auth.EnrollParams {
	t.Helper()
	var got auth.EnrollParams
	prev := browserEnroll
	browserEnroll = func(_ string, p auth.EnrollParams) (*auth.AgentCredential, error) {
		got = p
		return cred, ceremonyErr
	}
	t.Cleanup(func() { browserEnroll = prev })
	return &got
}

func stubActivation(t *testing.T, err error) *int {
	t.Helper()
	calls := 0
	prev := activateEnrolledAgent
	activateEnrolledAgent = func(string, auth.AgentCredential) (auth.AgentSigningIdentity, error) {
		calls++
		return auth.AgentSigningIdentity{SPIFFEID: "spiffe://platform.example.com/tenant/t-1/agent/a-1"}, err
	}
	t.Cleanup(func() { activateEnrolledAgent = prev })
	return &calls
}

func TestEnrollAgentIsTheCanonicalSpellingAndAgentEnrollIsHidden(t *testing.T) {
	root := New()
	enroll, _, err := root.Find([]string{"enroll", "agent"})
	require.NoError(t, err)
	assert.Equal(t, "agent", enroll.Name())
	assert.False(t, enroll.Hidden)

	legacy, _, err := root.Find([]string{"agent", "enroll"})
	require.NoError(t, err, "the old spelling keeps working for documents that already name it")
	assert.True(t, legacy.Hidden, "but it no longer advertises itself")
	assert.NotEmpty(t, legacy.Deprecated, "and says which spelling replaced it")
	assert.Contains(t, legacy.Deprecated, "cilock enroll agent")
}

func TestEnrollAgentPassesTheTTLAndActivatesBeforeReportingSuccess(t *testing.T) {
	expires := time.Now().Add(90 * time.Minute)
	params := stubEnrollCeremony(t, &auth.AgentCredential{
		PlatformURL: "https://platform.example.com", TenantID: "t-1", AgentID: "a-1", ExpiresAt: expires,
	}, nil)
	calls := stubActivation(t, nil)

	var out bytes.Buffer
	cmd := EnrollAgentCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--platform-url", "https://platform.example.com", "--ttl", "90m"})
	require.NoError(t, cmd.Execute())

	assert.Equal(t, 90*time.Minute, params.TTL, "--ttl reaches the ceremony as the page hint")
	assert.Equal(t, 1, *calls, "success is claimed only after the platform redeemed the credential")
	assert.Contains(t, out.String(), "a-1")
	assert.Contains(t, out.String(), "spiffe://platform.example.com/tenant/t-1/agent/a-1", "the identity reported is the one the platform redeemed")
	assert.Contains(t, out.String(), "expires", "the operator is told the identity is time-bound")
	assert.Contains(t, out.String(), expires.Local().Format("2006-01-02 15:04"))
}

func TestEnrollAgentFailsWhenActivationIsRefused(t *testing.T) {
	stubEnrollCeremony(t, &auth.AgentCredential{
		PlatformURL: "https://platform.example.com", TenantID: "t-1", AgentID: "a-1",
	}, nil)
	stubActivation(t, errors.New("the agent principal was not activated"))

	var out bytes.Buffer
	cmd := EnrollAgentCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--platform-url", "https://platform.example.com"})
	err := cmd.Execute()
	require.Error(t, err, "a ceremony whose credential the platform will not redeem is not an enrollment")
	assert.Contains(t, err.Error(), "not activated")
	assert.NotContains(t, out.String(), "Enrolled", "no success line for a principal that cannot sign")
}

func TestEnrollAgentRefusesATTLThePlatformWouldReject(t *testing.T) {
	params := stubEnrollCeremony(t, nil, nil)
	calls := stubActivation(t, nil)
	for _, ttl := range []string{"5m", "8d", "0s", "-1h"} {
		cmd := EnrollAgentCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"--platform-url", "https://platform.example.com", "--ttl", ttl})
		err := cmd.Execute()
		require.Error(t, err, "ttl=%s", ttl)
		assert.Contains(t, err.Error(), "--ttl", "ttl=%s: the refusal names the flag", ttl)
	}
	assert.Zero(t, params.TTL, "no ceremony was started for a TTL the platform would refuse")
	assert.Zero(t, *calls)
}

func TestEnrollAgentNeverTouchesTheActiveCredentialBeforeRedemption(t *testing.T) {
	// The ceremony delivers PENDING; the command never reads, replaces, or
	// restores the active credential itself. A refused or stalled redemption
	// leaves the identity that was working exactly as it was.
	isolateAgentConfig(t)
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL: "https://platform.example.com", TenantID: "t-1", AgentID: "a-old", RefreshCredential: "old-secret",
	}))
	stubEnrollCeremony(t, &auth.AgentCredential{PlatformURL: "https://platform.example.com", TenantID: "t-1", AgentID: "a-new"}, nil)
	var expected auth.AgentCredential
	prev := activateEnrolledAgent
	activateEnrolledAgent = func(_ string, exp auth.AgentCredential) (auth.AgentSigningIdentity, error) {
		expected = exp
		return auth.AgentSigningIdentity{}, errors.New("the platform did not answer")
	}
	t.Cleanup(func() { activateEnrolledAgent = prev })

	cmd := EnrollAgentCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"--platform-url", "https://platform.example.com"})
	require.Error(t, cmd.Execute())
	assert.Equal(t, "a-new", expected.AgentID, "activation is told which principal THIS ceremony minted")
	active, err := auth.LookupAgent("https://platform.example.com")
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.Equal(t, "a-old", active.AgentID, "still the identity this machine signs with")
}

func TestAgentStatusReportsExpiry(t *testing.T) {
	isolateAgentConfig(t)
	expires := time.Now().Add(2 * time.Hour)
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL: "https://platform.example.com", TenantID: "t-1", AgentID: "a-1",
		RefreshCredential: "s3cret", ExpiresAt: expires,
	}))
	var out bytes.Buffer
	cmd := AgentStatusCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--platform-url", "https://platform.example.com"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "expires")
	assert.Contains(t, out.String(), expires.Local().Format("2006-01-02 15:04"))
	assert.NotContains(t, out.String(), "s3cret")

	// And once past the ceiling, status says so instead of claiming an identity
	// that does not sign.
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL: "https://platform.example.com", TenantID: "t-1", AgentID: "a-1",
		RefreshCredential: "s3cret", ExpiresAt: time.Now().Add(-time.Minute),
	}))
	out.Reset()
	cmd = AgentStatusCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--platform-url", "https://platform.example.com"})
	require.NoError(t, cmd.Execute())
	assert.Contains(t, out.String(), "EXPIRED")
	assert.Contains(t, out.String(), "cilock enroll agent")
}
