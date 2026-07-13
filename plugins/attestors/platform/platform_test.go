// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platform

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/intoto"
)

const (
	testTenant  = "11111111-1111-1111-1111-111111111111"
	testProduct = "22222222-2222-2222-2222-222222222222"
)

func TestAttest_StaticBinding_EmitsSubjects(t *testing.T) {
	a := New(WithBinding(Binding{
		PlatformURL: "https://platform.testifysec.com",
		TenantID:    testTenant,
		TenantName:  "Acme",
		ProductID:   testProduct,
		ProductName: "Widget",
		Email:       "ci@acme.example",
	}))
	if err := a.Attest(nil); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if a.ProductID != testProduct || a.TenantID != testTenant {
		t.Fatalf("binding not applied: %+v", a)
	}
	// Reproducibility: the marshaled predicate must be identical across runs —
	// an attestor must carry no wall-clock (no signed-at); identical inputs yield
	// identical signed output. The DSSE signature / TSA carry the signing time.
	first, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	b := New(WithBinding(Binding{
		PlatformURL: "https://platform.testifysec.com",
		TenantID:    testTenant,
		TenantName:  "Acme",
		ProductID:   testProduct,
		ProductName: "Widget",
		Email:       "ci@acme.example",
	}))
	if err := b.Attest(nil); err != nil {
		t.Fatalf("Attest (second): %v", err)
	}
	second, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal predicate (second): %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("attestor is not reproducible:\n first=%s\nsecond=%s", first, second)
	}
	subs := a.Subjects()
	if _, ok := subs["testifysec-product:"+testProduct]; !ok {
		t.Fatalf("missing product subject, got keys %v", subjectKeys(subs))
	}
	if _, ok := subs["testifysec-tenant:"+testTenant]; !ok {
		t.Fatalf("missing tenant subject, got keys %v", subjectKeys(subs))
	}
}

// TestEnvelopeDecode_SignedSubjectNamesPresent builds the in-toto statement the
// way the workflow would (predicate = attestor, subjects = attestor.Subjects())
// then decodes the envelope payload and asserts the signed subject names are the
// testifysec-product/tenant convention the platform re-authorizes on upload.
func TestEnvelopeDecode_SignedSubjectNamesPresent(t *testing.T) {
	a := New(WithBinding(Binding{
		PlatformURL: "https://platform.testifysec.com",
		TenantID:    testTenant,
		ProductID:   testProduct,
	}))
	if err := a.Attest(nil); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	predicateJSON, err := json.Marshal(a)
	if err != nil {
		t.Fatalf("marshal predicate: %v", err)
	}
	stmt, err := intoto.NewStatement(Type, predicateJSON, a.Subjects())
	if err != nil {
		t.Fatalf("NewStatement: %v", err)
	}
	payload, err := json.Marshal(&stmt)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	// Decode the payload the way an upload/verify consumer would, and confirm
	// the signed subject NAMES carry the product/tenant binding.
	var decoded struct {
		Subject []struct {
			Name string `json:"name"`
		} `json:"subject"`
		Predicate map[string]any `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	names := map[string]bool{}
	for _, s := range decoded.Subject {
		names[s.Name] = true
	}
	if !names["testifysec-product:"+testProduct] {
		t.Fatalf("signed subjects missing product binding; got %v", names)
	}
	if !names["testifysec-tenant:"+testTenant] {
		t.Fatalf("signed subjects missing tenant binding; got %v", names)
	}
	if decoded.Predicate["product_id"] != testProduct {
		t.Fatalf("predicate product_id = %v, want %s", decoded.Predicate["product_id"], testProduct)
	}
}

func TestAttest_NoBinding_SoftSkip(t *testing.T) {
	err := New().Attest(nil)
	if err == nil || !strings.Contains(err.Error(), "skipping platform binding") {
		t.Fatalf("expected soft skip, got %v", err)
	}
	// Empty static binding is also a soft skip.
	err = New(WithBinding(Binding{})).Attest(nil)
	if err == nil || !strings.Contains(err.Error(), "skipping platform binding") {
		t.Fatalf("expected soft skip on empty binding, got %v", err)
	}
}

func TestAttest_ResolverError_Propagates(t *testing.T) {
	want := attestation.NewSoftError("skipping platform binding (resolver said so)")
	a := New(WithBindingResolver(func() (Binding, error) { return Binding{}, want }))
	err := a.Attest(nil)
	if !errors.Is(err, want) {
		t.Fatalf("expected resolver error to propagate, got %v", err)
	}
}

func TestAttest_WorkflowIdentity_NoIDs_NoSubjects(t *testing.T) {
	a := New(WithBinding(Binding{PlatformURL: "https://platform.testifysec.com", WorkflowIdentity: true}))
	if err := a.Attest(nil); err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if !a.WorkflowIdentity || a.PlatformURL == "" {
		t.Fatalf("workflow identity binding not applied: %+v", a)
	}
	if len(a.Subjects()) != 0 {
		t.Fatalf("no tenant/product means no binding subjects, got %v", subjectKeys(a.Subjects()))
	}
}

func subjectKeys(m map[string]cryptoutil.DigestSet) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
