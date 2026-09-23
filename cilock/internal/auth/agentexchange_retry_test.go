// jade:ring local

// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type agentExchangeRoundTripFunc func(*http.Request) (*http.Response, error)

func (f agentExchangeRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func setAgentExchangeTransport(t *testing.T, roundTrip agentExchangeRoundTripFunc) {
	t.Helper()
	previous := agentExchangeClient
	client := *previous
	client.Transport = roundTrip
	agentExchangeClient = &client
	t.Cleanup(func() { agentExchangeClient = previous })
}

func agentExchangeResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestAgentExchangeRetriesOnlyTransportTimeouts(t *testing.T) {
	isolateConfig(t)
	const principal = "spiffe://platform.example.com/tenant/t-1/agent/a-1"
	var requests []map[string]string
	setAgentExchangeTransport(t, func(req *http.Request) (*http.Response, error) {
		var body map[string]string
		require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
		requests = append(requests, body)
		if len(requests) < 3 {
			return nil, context.DeadlineExceeded
		}
		answer, err := json.Marshal(map[string]string{
			"token": jwtWithSubject(t, principal), "token_type": "oidc", "spiffe_id": principal,
		})
		require.NoError(t, err)
		return agentExchangeResponse(http.StatusOK, string(answer)), nil
	})

	identity, err := ExchangeAgentCredential("https://platform.example.com", AgentCredential{
		TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	})
	require.NoError(t, err)
	assert.Equal(t, principal, identity.SPIFFEID)
	assert.Equal(t, jwtWithSubject(t, principal), identity.Token)
	require.Len(t, requests, 3)
	for _, body := range requests {
		assert.Equal(t, map[string]string{
			"tenant_id": "t-1", "agent_id": "a-1", "refresh_credential": theSecret,
		}, body)
	}
}

func TestAgentExchangeTimeoutRetryIsBoundedAndRedacted(t *testing.T) {
	var requests int
	setAgentExchangeTransport(t, func(*http.Request) (*http.Response, error) {
		requests++
		return nil, context.DeadlineExceeded
	})

	_, err := ExchangeAgentCredential("https://platform.example.com", AgentCredential{
		TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	})
	require.Error(t, err)
	assert.Equal(t, 3, requests)
	assert.False(t, IsAgentCredentialRejected(err))
	assert.NotContains(t, err.Error(), theSecret)
}

func TestAgentExchangeDoesNotRetryResponseBodyTimeout(t *testing.T) {
	var requests int
	setAgentExchangeTransport(t, func(*http.Request) (*http.Response, error) {
		requests++
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(iotest.ErrReader(context.DeadlineExceeded)),
			Header:     make(http.Header),
		}, nil
	})

	_, err := ExchangeAgentCredential("https://platform.example.com", AgentCredential{
		TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
	})
	require.Error(t, err)
	assert.Equal(t, 1, requests)
	assert.Contains(t, err.Error(), "decode agent credential-exchange response")
	assert.NotContains(t, err.Error(), theSecret)
}

func TestAgentExchangeDoesNotRetryPermanentAnswers(t *testing.T) {
	for _, test := range []struct {
		name     string
		status   int
		body     string
		rejected bool
	}{
		{name: "credential refusal", status: http.StatusUnauthorized, body: `{"error":"agent_credential_rejected"}`, rejected: true},
		{name: "malformed success", status: http.StatusOK, body: `{"token":"bad","spiffe_id":"spiffe://platform.example.com/tenant/t-1/agent/a-1"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			isolateConfig(t)
			var requests int
			setAgentExchangeTransport(t, func(*http.Request) (*http.Response, error) {
				requests++
				return agentExchangeResponse(test.status, test.body), nil
			})
			_, err := ExchangeAgentCredential("https://platform.example.com", AgentCredential{
				TenantID: "t-1", AgentID: "a-1", RefreshCredential: theSecret,
			})
			require.Error(t, err)
			assert.Equal(t, 1, requests)
			assert.Equal(t, test.rejected, IsAgentCredentialRejected(err))
			assert.NotContains(t, err.Error(), theSecret)
		})
	}
}
