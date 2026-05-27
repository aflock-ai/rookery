// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package fanotify

import (
	"testing"
)

// TestDefaultMaxDigestsFromEnv asserts the env-var override
// hierarchy for CILOCK_FANOTIFY_MAX_DIGESTS. The function must
// never silently return zero — that would make MaxDigests
// effectively unbounded under adversarial workloads.
func TestDefaultMaxDigestsFromEnv(t *testing.T) {
	cases := []struct {
		name, env string
		want      int
	}{
		{"unset uses default", "", DefaultMaxDigests},
		{"valid override", "12345", 12345},
		{"large valid override", "5000000", 5000000},
		{"empty falls back to default", "", DefaultMaxDigests},
		{"zero is invalid, fall back to default", "0", DefaultMaxDigests},
		{"negative is invalid, fall back to default", "-1", DefaultMaxDigests},
		{"non-numeric is invalid, fall back to default", "lots", DefaultMaxDigests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvVarFanotifyMaxDigests, tc.env)
			got := defaultMaxDigestsFromEnv()
			if got != tc.want {
				t.Fatalf("env=%q: got %d, want %d", tc.env, got, tc.want)
			}
		})
	}
}
