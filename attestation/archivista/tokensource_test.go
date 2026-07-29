// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package archivista

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/require"
)

// TestAuthTokenSourcePerRequest pins the contract WithAuthTokenSource exists
// for: the source is consulted on EVERY request, so a token that expires
// mid-lifetime (GitHub Actions OIDC, ~5-minute exp — the v4.1.2 release
// verify 401) can be re-minted instead of riding a header frozen at client
// construction.
func TestAuthTokenSourcePerRequest(t *testing.T) {
	var got []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "ok"})
	}))
	defer server.Close()

	calls := 0
	client := New(server.URL, WithAuthTokenSource(func() (string, error) {
		calls++
		return fmt.Sprintf("tok-%d", calls), nil
	}))

	env := dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"}
	_, err := client.Store(context.Background(), env)
	require.NoError(t, err)
	_, err = client.Store(context.Background(), env)
	require.NoError(t, err)

	require.Equal(t, 2, calls, "token source must be consulted once per request")
	require.Equal(t, []string{"Bearer tok-1", "Bearer tok-2"}, got)
}

// TestAuthTokenSourceStaticHeaderWins pins precedence: an explicit
// Authorization header (WithHeaders — cilock's --archivista-headers / stored
// session bearer) suppresses the token source entirely.
func TestAuthTokenSourceStaticHeaderWins(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "Bearer static", r.Header.Get("Authorization"))
		json.NewEncoder(w).Encode(storeResponse{Gitoid: "ok"})
	}))
	defer server.Close()

	headers := http.Header{}
	headers.Set("Authorization", "Bearer static")
	client := New(server.URL,
		WithHeaders(headers),
		WithAuthTokenSource(func() (string, error) {
			t.Fatal("token source must not be consulted when a static Authorization header is set")
			return "", nil
		}))

	_, err := client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.NoError(t, err)
}

// TestAuthTokenSourceErrorFailsClosed pins fail-closed: a source error aborts
// the request rather than sending it anonymously (which would demote an
// authenticated read to an anonymous one and surface as a confusing
// server-side auth error).
func TestAuthTokenSourceErrorFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("no request must be sent when the token source errors")
	}))
	defer server.Close()

	client := New(server.URL, WithAuthTokenSource(func() (string, error) {
		return "", errors.New("mint failed")
	}))

	_, err := client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.ErrorContains(t, err, "mint failed")

	err = client.graphqlQuery(context.Background(), "query {}", nil, &struct{}{})
	require.ErrorContains(t, err, "mint failed")

	_, err = client.Download(context.Background(), "gitoid")
	require.ErrorContains(t, err, "mint failed")
}
