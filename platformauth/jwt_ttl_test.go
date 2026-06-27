// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSessionTTL_OverrideAndClamp exercises the JUDGE_SESSION_TTL operator
// override and its tighten-only clamp. The fallback window for a token with no
// decodable `exp` is a security ceiling: operators may TIGHTEN it (shorter), but
// a value that would LOOSEN it (longer than defaultSessionTTL) — or any
// invalid/out-of-range value — must silently fall back to defaultSessionTTL.
func TestSessionTTL_OverrideAndClamp(t *testing.T) {
	tests := []struct {
		name string
		env  string // "" means leave the var unset
		set  bool
		want time.Duration
	}{
		{name: "unset falls back to default", set: false, want: defaultSessionTTL},
		{name: "valid shorter value is honored", set: true, env: "8h", want: 8 * time.Hour},
		{name: "longer value is clamped to default (not loosened)", set: true, env: "720h", want: defaultSessionTTL},
		{name: "equal to default is honored", set: true, env: defaultSessionTTL.String(), want: defaultSessionTTL},
		{name: "garbage value falls back to default", set: true, env: "not-a-duration", want: defaultSessionTTL},
		{name: "zero falls back to default", set: true, env: "0s", want: defaultSessionTTL},
		{name: "negative falls back to default", set: true, env: "-5h", want: defaultSessionTTL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set {
				t.Setenv(sessionTTLEnvVar, tt.env)
			} else {
				// Ensure a previously-exported value can't leak in.
				t.Setenv(sessionTTLEnvVar, "")
			}
			assert.Equal(t, tt.want, sessionTTL())
		})
	}
}
