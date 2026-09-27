// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// jade:ring local

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/stretchr/testify/require"
)

// Onbsim 2026-09-25: an enrolled agent ran `cilock verify` without -p and was
// told "not logged in to <url>, run `cilock login` first". That is the human's
// login. A policy session (platform verify, bind, publish) is the human's; the
// enrolled agent cannot open one, and the error must say so instead of steering
// the agent into a human credential flow.
func TestPolicySessionTellsAnEnrolledAgentItIsTheHumansStep(t *testing.T) {
	isolateAgentConfig(t)
	const platform = "https://platform.example.com"
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       platform,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: agentTestSecret,
	}))
	_, err := resolvePolicySession(platform)
	require.Error(t, err)
	msg := err.Error()
	for _, want := range []string{"human", "enrolled agent", "cannot open"} {
		require.Contains(t, msg, want)
	}
	require.NotContains(t, msg, "run `cilock login` first", "an agent is never told to log in as the human")
	require.NotContains(t, msg, agentTestSecret)
}

// Sibling of the policy session: `cilock trust` needs an admin's session, and
// an enrolled agent reaching it must hear the same thing.
func TestTrustSessionTellsAnEnrolledAgentItIsTheHumansStep(t *testing.T) {
	isolateAgentConfig(t)
	const platform = "https://platform.example.com"
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       platform,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: agentTestSecret,
	}))
	_, err := requireTrustSession(platform)
	require.Error(t, err)
	require.Contains(t, err.Error(), "enrolled agent cannot open")
	require.NotContains(t, err.Error(), "run `cilock login` first")
}

// Sibling: `cilock whoami` in 4 onbsim runs printed "not logged in ... (run:
// cilock login ...)" to an agent that was enrolled. It names the agent.
func TestWhoamiNamesTheEnrolledAgentInsteadOfSayingLogIn(t *testing.T) {
	isolateAgentConfig(t)
	const platform = "https://platform.example.com"
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       platform,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: agentTestSecret,
	}))
	cmd := WhoamiCmd()
	cmd.SetArgs([]string{"--platform-url", platform})
	var out bytes.Buffer
	cmd.SetOut(&out)
	err := cmd.Execute()
	require.Error(t, err, "there is still no human session")
	got := out.String() + err.Error()
	for _, want := range []string{"no human session", "enrolled agent", "a-1", "t-1", "cilock agent status"} {
		require.Contains(t, got, want)
	}
	require.NotContains(t, got, "run: cilock login")
	require.NotContains(t, got, agentTestSecret)
}

func TestPolicySessionWithoutAnyCredentialStillSaysLogIn(t *testing.T) {
	isolateAgentConfig(t)
	_, err := resolvePolicySession("https://platform.example.com")
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "run `cilock login` first"), err.Error())
}
