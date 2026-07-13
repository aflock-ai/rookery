// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResolveBinding_Success(t *testing.T) {
	const (
		wantTenant  = "11111111-1111-1111-1111-111111111111"
		wantProduct = "22222222-2222-2222-2222-222222222222"
	)
	var gotAuth, gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		if r.URL.Path != resolveBindingPath {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bindingOKBody{
			TenantID: wantTenant, TenantName: "Acme", ProductID: wantProduct, ProductName: "Widget",
		})
	}))
	defer srv.Close()

	b, err := resolveBindingWithClient(srv.Client(), srv.URL, "tok-abc", "")
	if err != nil {
		t.Fatalf("ResolveBinding: %v", err)
	}
	if b.TenantID != wantTenant || b.ProductID != wantProduct {
		t.Fatalf("binding = %+v", b)
	}
	if b.TenantName != "Acme" || b.ProductName != "Widget" {
		t.Fatalf("names not carried: %+v", b)
	}
	if gotAuth != "Bearer tok-abc" {
		t.Fatalf("Authorization = %q, want Bearer tok-abc", gotAuth)
	}
	if strings.Contains(gotBody, "product_id") {
		t.Fatalf("empty selector must be omitted from body, got %q", gotBody)
	}
}

func TestResolveBinding_SelectorForwardedAndValidated(t *testing.T) {
	const selector = "22222222-2222-2222-2222-222222222222"
	var gotBody string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_ = json.NewEncoder(w).Encode(bindingOKBody{
			TenantID: "11111111-1111-1111-1111-111111111111", ProductID: selector,
		})
	}))
	defer srv.Close()

	if _, err := resolveBindingWithClient(srv.Client(), srv.URL, "tok", selector); err != nil {
		t.Fatalf("ResolveBinding: %v", err)
	}
	if !strings.Contains(gotBody, selector) {
		t.Fatalf("selector not forwarded, body=%q", gotBody)
	}

	// A malformed selector is rejected before any request is sent.
	if _, err := ResolveBinding("https://platform.example", "tok", "not-a-uuid"); err == nil {
		t.Fatal("expected error for malformed selector")
	}
}

func TestResolveBinding_RepositoryNotMapped(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(bindingErrorBody{
			Error:       "repository_not_mapped",
			TenantID:    "11111111-1111-1111-1111-111111111111",
			TenantName:  "Acme",
			Repository:  "acme/widget",
			Remediation: "connect the repo to a product",
		})
	}))
	defer srv.Close()

	_, err := resolveBindingWithClient(srv.Client(), srv.URL, "tok", "")
	if !errors.Is(err, ErrRepositoryNotMapped) {
		t.Fatalf("expected ErrRepositoryNotMapped, got %v", err)
	}
	var rnm *RepositoryNotMappedError
	if !errors.As(err, &rnm) {
		t.Fatalf("expected *RepositoryNotMappedError, got %T", err)
	}
	if rnm.Repository != "acme/widget" || rnm.TenantID == "" {
		t.Fatalf("identifiers not carried: %+v", rnm)
	}
	if !strings.Contains(rnm.Error(), "acme/widget") {
		t.Fatalf("message not actionable: %q", rnm.Error())
	}
}

func TestResolveBinding_Ambiguous(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(bindingErrorBody{
			Error:      "ambiguous_product",
			TenantID:   "11111111-1111-1111-1111-111111111111",
			TenantName: "Acme",
			Repository: "acme/monorepo",
			Candidates: []bindingCandidate{
				{ProductID: "22222222-2222-2222-2222-222222222222", ProductName: "A"},
				{ProductID: "33333333-3333-3333-3333-333333333333", ProductName: "B"},
			},
			Remediation: "pass exactly one product",
		})
	}))
	defer srv.Close()

	_, err := resolveBindingWithClient(srv.Client(), srv.URL, "tok", "")
	if !errors.Is(err, ErrAmbiguousProduct) {
		t.Fatalf("expected ErrAmbiguousProduct, got %v", err)
	}
	var amb *AmbiguousProductError
	if !errors.As(err, &amb) {
		t.Fatalf("expected *AmbiguousProductError, got %T", err)
	}
	if len(amb.Candidates) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(amb.Candidates))
	}
	msg := amb.Error()
	for _, want := range []string{"22222222-2222-2222-2222-222222222222", "33333333-3333-3333-3333-333333333333", "acme/monorepo"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("message missing %q: %q", want, msg)
		}
	}
}

func TestResolveBinding_RejectsCleartextNonLoopback(t *testing.T) {
	_, err := ResolveBinding("http://platform.example", "tok", "")
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("expected cleartext refusal, got %v", err)
	}
}

func TestResolveBinding_RejectsMalformedTenantUUID(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(bindingOKBody{TenantID: "not-a-uuid", ProductID: "22222222-2222-2222-2222-222222222222"})
	}))
	defer srv.Close()

	if _, err := resolveBindingWithClient(srv.Client(), srv.URL, "tok", ""); err == nil {
		t.Fatal("expected rejection of malformed tenant UUID")
	}
}

func TestResolveBinding_EmptyToken(t *testing.T) {
	if _, err := ResolveBinding("https://platform.example", "", ""); err == nil {
		t.Fatal("expected error for empty bearer token")
	}
}

func TestIsValidUUID(t *testing.T) {
	valid := []string{
		"11111111-1111-1111-1111-111111111111",
		"abcdefAB-1234-5678-9abc-def012345678",
	}
	for _, s := range valid {
		if !isValidUUID(s) {
			t.Errorf("isValidUUID(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "not-a-uuid", "1111111111111111111111111111111111111", "11111111_1111-1111-1111-111111111111", "gggggggg-1111-1111-1111-111111111111"}
	for _, s := range invalid {
		if isValidUUID(s) {
			t.Errorf("isValidUUID(%q) = true, want false", s)
		}
	}
}
