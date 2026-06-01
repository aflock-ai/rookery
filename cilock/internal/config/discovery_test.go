// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDiscover_RequiresHTTPS pins the security fix: discovery establishes
// verification trust (CA roots, OIDC issuer), so it must refuse to fetch over
// plaintext on a non-loopback host. A plain-http platform URL must NOT be
// fetched at all — otherwise an on-path attacker substitutes the trust bundle
// and a verify PASSes against attacker-signed evidence.
func TestDiscover_RequiresHTTPS(t *testing.T) {
	t.Run("http non-loopback is refused before any fetch", func(t *testing.T) {
		_, err := Discover("http://platform.attacker.example.com")
		if err == nil {
			t.Fatal("expected http (non-loopback) discovery to be refused")
		}
		if !strings.Contains(err.Error(), "https") {
			t.Fatalf("error should explain the https requirement, got: %v", err)
		}
	})

	t.Run("schemeless url is refused", func(t *testing.T) {
		if _, err := Discover("platform.attacker.example.com"); err == nil {
			t.Fatal("expected a schemeless platform url to be refused (not https)")
		}
	})

	t.Run("http loopback is allowed (standalone/dev)", func(t *testing.T) {
		// httptest serves on 127.0.0.1 over http — the loopback exception must let
		// the local standalone/dev flow keep working.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != discoveryPath {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"archivista_url": "http://x/archivista"})
		}))
		defer srv.Close()

		d, err := Discover(srv.URL) // http://127.0.0.1:PORT
		if err != nil {
			t.Fatalf("loopback http discovery must be allowed, got: %v", err)
		}
		if d == nil || d.ArchivistaURL == "" {
			t.Fatalf("expected a parsed discovery doc, got %+v", d)
		}
	})

	t.Run("localhost host is allowed", func(t *testing.T) {
		// No server need answer — we only assert the scheme gate does not reject
		// localhost (the resulting error, if any, must be a transport error, not
		// the https-required refusal).
		_, err := Discover("http://localhost:65535")
		if err != nil && strings.Contains(err.Error(), "must be https") {
			t.Fatalf("localhost must not be rejected by the https gate, got: %v", err)
		}
	})
}
