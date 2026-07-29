// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package options

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGitHubOIDCTokenSourceCachesWithinWindow pins the mint economy: within
// githubOIDCRefreshAfter the cached token is served without re-minting.
func TestGitHubOIDCTokenSourceCachesWithinWindow(t *testing.T) {
	mints := 0
	source := newGitHubOIDCTokenSource("aud", func(audience string) (string, error) {
		require.Equal(t, "aud", audience)
		mints++
		return "tok", nil
	})

	for range 3 {
		tok, err := source()
		require.NoError(t, err)
		require.Equal(t, "tok", tok)
	}
	require.Equal(t, 1, mints, "a fresh token must be served from cache")
}

// TestGitHubOIDCTokenSourceErrorFailsClosed pins that a mint failure is
// returned as an error — never papered over with a stale token, which would
// reproduce the mid-operation 401 the source exists to prevent (v4.1.2
// release verify).
func TestGitHubOIDCTokenSourceErrorFailsClosed(t *testing.T) {
	source := newGitHubOIDCTokenSource("aud", func(string) (string, error) {
		return "", errors.New("endpoint unavailable")
	})
	_, err := source()
	require.ErrorContains(t, err, "endpoint unavailable")
}
