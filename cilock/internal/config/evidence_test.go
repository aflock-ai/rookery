// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

// jade:ring local

package config

import "testing"

func TestEvidenceDefaults(t *testing.T) {
	profile, budget := DefaultEvidenceProfile, DefaultProductInlineBytes
	t.Cleanup(func() { DefaultEvidenceProfile, DefaultProductInlineBytes = profile, budget })
	for _, tt := range []struct {
		profile, budget string
		compact         bool
		bytes           int
		invalid         bool
	}{
		{"compact", "131072", true, 131072, false},
		{"compact", "0", true, 0, false},
		{"compact-chain", "131072", true, 131072, false},
		{"compact-chain", "0", true, 0, false},
		{"legacy", "131072", false, 131072, false},
		{"", "131072", false, 0, true},
		{"COMPACT", "131072", false, 0, true},
		{"future", "131072", false, 0, true},
		{"compact", "-1", false, 0, true},
		{"compact", "", false, 0, true},
		{"compact", "1.5", false, 0, true},
		{"compact", " 1", false, 0, true},
		{"compact", "2147483648", false, 0, true},
		{"legacy", "bad", false, 0, true},
		{"compact-chain", "bad", false, 0, true},
	} {
		t.Run(tt.profile+"/"+tt.budget, func(t *testing.T) {
			DefaultEvidenceProfile, DefaultProductInlineBytes = tt.profile, tt.budget
			compact, bytes, err := EvidenceDefaults()
			if (err != nil) != tt.invalid {
				t.Fatalf("error = %v, invalid = %v", err, tt.invalid)
			}
			if !tt.invalid && (compact != tt.compact || bytes != tt.bytes) {
				t.Fatalf("got (%v, %d), want (%v, %d)", compact, bytes, tt.compact, tt.bytes)
			}
		})
	}
}

func TestEvidenceRetentionDefaults(t *testing.T) {
	profile, budget := DefaultEvidenceProfile, DefaultProductInlineBytes
	t.Cleanup(func() { DefaultEvidenceProfile, DefaultProductInlineBytes = profile, budget })
	for _, tt := range []struct {
		profile, budget  string
		enabled, invalid bool
	}{
		{"compact", "131072", false, false},
		{"compact-chain", "131072", true, false},
		{"legacy", "131072", false, false},
		{"unknown", "131072", false, true},
		{"compact-chain", "invalid", false, true},
	} {
		t.Run(tt.profile+"/"+tt.budget, func(t *testing.T) {
			DefaultEvidenceProfile, DefaultProductInlineBytes = tt.profile, tt.budget
			retain, upload, err := EvidenceRetentionDefaults()
			if (err != nil) != tt.invalid || retain != tt.enabled || upload != tt.enabled {
				t.Fatalf("got retain=%v upload=%v err=%v; want enabled=%v invalid=%v", retain, upload, err, tt.enabled, tt.invalid)
			}
		})
	}
}
