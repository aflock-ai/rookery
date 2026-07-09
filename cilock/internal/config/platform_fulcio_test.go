// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package config

import "testing"

// TestDerive_FulcioUnderFulcioSubpath pins that the derived Fulcio REST base
// lives under the platform's /fulcio prefix, so every embedded-Fulcio endpoint
// shares one namespace: the OIDC server at /fulcio/oidc/ and the signing
// gRPC-gateway at /fulcio/api/v2/. The fulcio signer appends /api/v2/signingCert
// to this base, so the resulting request targets the platform's canonical
// /fulcio/api/v2/signingCert mount rather than the deprecated root /api/v2/.
// Regression pin for issue #5122.
func TestDerive_FulcioUnderFulcioSubpath(t *testing.T) {
	if got, want := Derive("https://platform.example.com").Fulcio, "https://platform.example.com/fulcio"; got != want {
		t.Fatalf("Fulcio = %q, want %q", got, want)
	}
	// A trailing slash on the platform URL must not double up into //fulcio.
	if got, want := Derive("https://platform.example.com/").Fulcio, "https://platform.example.com/fulcio"; got != want {
		t.Fatalf("Fulcio (trailing slash) = %q, want %q", got, want)
	}
	// An empty platform URL falls back to the compiled-in default, still
	// /fulcio-suffixed.
	if got, want := Derive("").Fulcio, DefaultPlatformURL+"/fulcio"; got != want {
		t.Fatalf("default Fulcio = %q, want %q", got, want)
	}
}
