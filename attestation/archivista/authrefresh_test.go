// jade:ring local
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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/stretchr/testify/require"
)

// refreshHarness serves an upload endpoint that refuses every bearer except
// goodBearer with refuseStatus, and counts requests and refreshes.
func refreshHarness(t *testing.T, refuseStatus int, goodBearer string, refresh func(cur *atomic.Value) error) (*Client, *int64, *int64) {
	t.Helper()
	var requests, refreshes int64
	var cur atomic.Value
	cur.Store("stale")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&requests, 1)
		if r.Header.Get("Authorization") != "Bearer "+goodBearer {
			http.Error(w, "Invalid API credential", refuseStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(storeResponse{Gitoid: "stored"})
	}))
	t.Cleanup(srv.Close)
	opts := []Option{WithAuthTokenSource(func() (string, error) { return cur.Load().(string), nil })}
	if refresh != nil {
		opts = append(opts, WithAuthRefresh(func() error {
			atomic.AddInt64(&refreshes, 1)
			return refresh(&cur)
		}))
	}
	return New(srv.URL, opts...), &requests, &refreshes
}

var refreshEnv = dsse.Envelope{Payload: []byte(`{}`), PayloadType: "test"}

// A 401 that a renewed credential cures is cured: one refresh, one retry.
func TestStoreRenewsCredentialOnceAfter401(t *testing.T) {
	c, requests, refreshes := refreshHarness(t, http.StatusUnauthorized, "fresh",
		func(cur *atomic.Value) error { cur.Store("fresh"); return nil })
	id, err := c.Store(context.Background(), refreshEnv)
	require.NoError(t, err)
	require.Equal(t, "stored", id)
	require.EqualValues(t, 1, atomic.LoadInt64(refreshes))
	require.EqualValues(t, 2, atomic.LoadInt64(requests))
}

// A renewal that does not help is attempted once; the server's refusal is not
// hidden and there is no loop.
func TestStoreRenewsAtMostOnce(t *testing.T) {
	c, requests, refreshes := refreshHarness(t, http.StatusUnauthorized, "never",
		func(cur *atomic.Value) error { cur.Store("still-wrong"); return nil })
	_, err := c.Store(context.Background(), refreshEnv)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	require.Equal(t, http.StatusUnauthorized, se.StatusCode)
	require.EqualValues(t, 1, atomic.LoadInt64(refreshes))
	require.EqualValues(t, 2, atomic.LoadInt64(requests))
}

// Could not renew is not renewed: the failure is reported next to the original
// refusal, and nothing is retried with the stale credential.
func TestStoreRenewalFailureKeepsBothErrors(t *testing.T) {
	boom := errors.New("exchange unavailable")
	c, requests, _ := refreshHarness(t, http.StatusUnauthorized, "fresh",
		func(*atomic.Value) error { return boom })
	_, err := c.Store(context.Background(), refreshEnv)
	require.ErrorIs(t, err, boom)
	var se *StatusError
	require.ErrorAs(t, err, &se)
	require.EqualValues(t, 1, atomic.LoadInt64(requests))
}

// Only 401 renews: a 403 is an authorization verdict on a credential the
// server understood, and re-exchanging cannot change it. A client with no
// refresh behaves as before.
func TestStoreDoesNotRenewOtherRefusals(t *testing.T) {
	c, requests, refreshes := refreshHarness(t, http.StatusForbidden, "fresh",
		func(cur *atomic.Value) error { cur.Store("fresh"); return nil })
	_, err := c.Store(context.Background(), refreshEnv)
	require.Error(t, err)
	require.EqualValues(t, 0, atomic.LoadInt64(refreshes))
	require.EqualValues(t, 1, atomic.LoadInt64(requests))

	c2, requests2, _ := refreshHarness(t, http.StatusUnauthorized, "fresh", nil)
	_, err = c2.Store(context.Background(), refreshEnv)
	require.Error(t, err)
	require.EqualValues(t, 1, atomic.LoadInt64(requests2))
}
