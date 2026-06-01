// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package config

import "testing"

// TestDerive_OIDCLoginAudience pins the dedicated login audience and, crucially,
// that it is DISTINCT from the Archivista-upload audience and the Fulcio signing
// client id — reusing either would be a confused-deputy hazard.
func TestDerive_OIDCLoginAudience(t *testing.T) {
	pc := Derive("https://platform.example.com/")
	if got, want := pc.OIDCLoginAudience, "https://platform.example.com/login"; got != want {
		t.Fatalf("OIDCLoginAudience = %q, want %q", got, want)
	}
	if pc.OIDCLoginAudience == pc.OIDCAudience {
		t.Fatalf("login audience must differ from Archivista audience (%q) — confused-deputy", pc.OIDCAudience)
	}
	if pc.OIDCLoginAudience == pc.OIDCClientID {
		t.Fatalf("login audience must not be the Fulcio client id %q", pc.OIDCClientID)
	}

	if got, want := Derive("").OIDCLoginAudience, DefaultPlatformURL+"/login"; got != want {
		t.Fatalf("default OIDCLoginAudience = %q, want %q", got, want)
	}
}
