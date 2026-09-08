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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
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

// TestAuthTokenSourceWithdrawnGrantIsTerminal pins the fail-CLOSED half: a
// source that declared its credential permanently unavailable has answered for
// good, so the upload retry must not ask it again. Without this the
// classifier's default-retryable branch spends the whole budget re-asking a
// source for a grant the platform already withdrew.
//
// Declaring it is what makes it terminal. The wrapper type alone does not, and
// must not — see TestEveryTransientTokenSourceFailurePreservesRetries for the
// other half, which this test exists in tension with on purpose.
func TestAuthTokenSourceWithdrawnGrantIsTerminal(t *testing.T) {
	installFakeClock(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("no request must be sent when the token source errors")
	}))
	defer server.Close()

	calls := 0
	client := New(server.URL,
		WithRetry(fastRetry(5)),
		WithAuthTokenSource(func() (string, error) {
			calls++
			return "", fmt.Errorf("upload grant revoked: %w", ErrCredentialUnavailable)
		}))

	_, err := client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.ErrorContains(t, err, "upload grant revoked")

	var ae *AuthTokenError
	require.ErrorAs(t, err, &ae)
	require.True(t, ae.Permanent(), "a declared-unavailable credential is permanent")
	require.ErrorIs(t, err, ErrCredentialUnavailable, "the sentinel must stay reachable to callers")
	require.False(t, IsRetryable(context.Background(), err), "a withdrawn grant is not a transient condition")
	require.Equal(t, 1, calls, "the token source must be asked once, not once per retry attempt")
}

// TestAuthTokenSourceTransientFailureThenSucceeds is the regression the round-1
// review asked for, and it is the defect in one line: a source that fails ONCE
// and then succeeds must complete the upload.
//
// Before the fix, AuthTokenError was read as uniformly terminal, so this upload
// aborted on the first blip with the retry budget untouched and the signed
// envelope already produced but never stored — a whole gate run's evidence
// thrown away because an OIDC mint timed out for one second.
func TestAuthTokenSourceTransientFailureThenSucceeds(t *testing.T) {
	installFakeClock(t)

	var uploads atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads.Add(1)
		require.Equal(t, "Bearer minted-on-the-second-try", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(storeResponse{Gitoid: "ok"})
	}))
	defer server.Close()

	calls := 0
	client := New(server.URL,
		WithRetry(fastRetry(5)),
		WithAuthTokenSource(func() (string, error) {
			calls++
			if calls == 1 {
				// The shape fetchGitHubOIDCToken actually returns when the
				// runner's token endpoint stalls: a *url.Error carrying the
				// client's own timeout.
				return "", fmt.Errorf("mint github actions oidc token: %w",
					&url.Error{Op: "Get", URL: "https://token.actions.example/", Err: context.DeadlineExceeded})
			}
			return "minted-on-the-second-try", nil
		}))

	gitoid, err := client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.NoError(t, err, "a token source that failed once must not abort the upload")
	require.Equal(t, "ok", gitoid)
	require.Equal(t, 2, calls, "the source must be re-asked on the retry")
	require.EqualValues(t, 1, uploads.Load(), "exactly one upload reaches the server: the first attempt never left the process")
}

// TestEveryTransientTokenSourceFailurePreservesRetries sweeps the WHOLE
// token-source error space rather than the one shape that was reported.
//
// The class of defect here is a wrapper type read as a verdict: AuthTokenError
// wraps every failure a token source can have, and the round-1 code answered
// "terminal" for all of them. Patching the reported instance would leave the
// same conflation reachable through every other cause, so the terminal set is
// enumerated here explicitly and everything outside it must retry.
//
// Both predicates are asserted on every row. IsRetryable and classify are two
// separate implementations of one decision — a caller asks the first, the retry
// loop obeys the second — and a table that exercised only one would let them
// drift apart silently.
func TestEveryTransientTokenSourceFailurePreservesRetries(t *testing.T) {
	type row struct {
		name   string
		cause  error
		reason string
	}

	// The TERMINAL set, stated as a closed list. A row may only be added here
	// when re-asking the same source genuinely cannot change the answer.
	terminal := []row{
		{"declared permanently unavailable", ErrCredentialUnavailable, reasonAuthUnavailable},
		{"declared, wrapped once", fmt.Errorf("no upload token for agent: %w", ErrCredentialUnavailable), reasonAuthUnavailable},
		{"declared, nested two deep", fmt.Errorf("exchange: %w", fmt.Errorf("refresh: %w", ErrCredentialUnavailable)), reasonAuthUnavailable},
		{"declared alongside a transient shape", fmt.Errorf("%w (while %w)", ErrCredentialUnavailable, context.DeadlineExceeded), reasonAuthUnavailable},
		// Not a token-source verdict at all: the source handed back a typed
		// status and the StatusError branch owns it. A 403 from an identity
		// provider is a statement about the request, so it stays terminal — but
		// it gets there by its CODE, not by being wrapped.
		{"identity provider 403 as a typed status", &StatusError{Op: "oidc", StatusCode: 403}, "client_error"},
	}

	// Everything else. Each of these is a source that could not answer RIGHT
	// NOW; the source is re-asked on every attempt (applyHeaders runs inside
	// storeOnce), so a retry can genuinely succeed.
	transient := []row{
		{"bare unmarked error", errors.New("mint failed"), reasonAuthSource},
		{"nil cause", nil, reasonAuthSource},
		{"dial failure", &url.Error{Op: "Get", URL: "https://idp.example/", Err: errors.New("connection refused")}, reasonAuthSource},
		{"client timeout", &url.Error{Op: "Get", URL: "https://idp.example/", Err: context.DeadlineExceeded}, reasonAuthSource},
		{"bare deadline exceeded", context.DeadlineExceeded, reasonAuthSource},
		{"the source's own context was cancelled", context.Canceled, reasonAuthSource},
		{"net deadline exceeded", os.ErrDeadlineExceeded, reasonAuthSource},
		{"truncated response body", io.ErrUnexpectedEOF, reasonAuthSource},
		// The exact text fetchGitHubOIDCToken produces for a failing token
		// endpoint. It is a plain fmt.Errorf carrying NO transient shape, which
		// is why a classifier that sniffed for net.Error or *url.Error instead
		// of reading a declaration would re-create this bug at a new line.
		{"identity provider 500 as plain text", errors.New("OIDC token request returned 500: upstream unavailable"), reasonAuthSource},
		{"identity provider 429 as plain text", errors.New("OIDC token request returned 429: slow down"), reasonAuthSource},
		{"identity provider 503 as a typed status", &StatusError{Op: "oidc", StatusCode: 503}, "server_error"},
		// Classification is not string matching in this direction either: a
		// message that merely MENTIONS revocation has declared nothing.
		{"message merely mentions a revoked grant", errors.New("upstream said the grant was revoked"), reasonAuthSource},
	}

	require.Len(t, terminal, 5, "the terminal set is a closed allowlist; adding to it is a deliberate act")
	require.Len(t, transient, 12)

	ctx := context.Background()
	for _, tc := range terminal {
		t.Run("terminal/"+tc.name, func(t *testing.T) {
			err := error(&AuthTokenError{Err: tc.cause})
			require.False(t, IsRetryable(ctx, err), "IsRetryable must refuse to retry this")
			bucket, reason := classify(ctx, ctx, err)
			require.Equal(t, classTerminal, bucket, "classify must agree with IsRetryable")
			require.Equal(t, tc.reason, reason, "the log label must say WHY, so an operator can grep for it")
		})
	}
	for _, tc := range transient {
		t.Run("transient/"+tc.name, func(t *testing.T) {
			err := error(&AuthTokenError{Err: tc.cause})
			require.True(t, IsRetryable(ctx, err), "a source that could not answer this time must keep its retries")
			bucket, reason := classify(ctx, ctx, err)
			require.Equal(t, classRetryable, bucket, "classify must agree with IsRetryable")
			require.Equal(t, tc.reason, reason)
		})
	}
}

// TestTransientTokenSourceSpendsTheWholeRetryBudget is the counted proof that
// the table above describes runtime behaviour and not merely a predicate.
//
// A predicate test can pass while the retry loop ignores it, so this drives the
// real client: a source that fails transiently on every call must be re-asked
// once per attempt up to MaxAttempts, and the run must end carrying the
// source's own error rather than a classification artefact.
func TestTransientTokenSourceSpendsTheWholeRetryBudget(t *testing.T) {
	installFakeClock(t)
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("no request leaves the process when the token source fails")
	}))
	defer server.Close()

	calls := 0
	client := New(server.URL,
		WithRetry(fastRetry(4)),
		WithAuthTokenSource(func() (string, error) {
			calls++
			return "", errors.New("OIDC token request returned 503: upstream unavailable")
		}))

	_, err := client.Store(context.Background(), dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"})
	require.Error(t, err)
	require.ErrorContains(t, err, "upstream unavailable", "the source's own error must survive to the caller")
	require.Equal(t, 4, calls, "a transient source failure gets every configured attempt")
}
