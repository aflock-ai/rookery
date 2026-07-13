// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package platform provides a rookery attestor that binds an attestation to the
// TestifySec platform tenant and product it was produced under, and records
// audit info about the signing identity.
//
// It is a PUBLIC, importable package (unlike the cilock-internal adapter that
// wraps it) so a separate module — e.g. cilock-action — can add it to its
// attestor set. The attestor is a pure CONSUMER of an already-resolved binding:
// the caller resolves the tenant/product (via platformauth.ResolveBinding, or a
// cilock session lookup) and constructs the attestor WITH that binding. The
// attestor does not itself decide authentication or soft-vs-hard — the run-entry
// gate does that before any command runs.
//
// It emits in-toto subjects `testifysec-product:<uuid>` / `testifysec-tenant:<uuid>`
// — the `testifysec-product` subject is the convention the platform's ingestion
// autodiscovery re-authorizes to create a high-confidence Dsse↔Product link.
// With no binding (not platform-authenticated) it returns a SoftError and is
// skipped.
package platform

import (
	"crypto"
	"fmt"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

const (
	// Name is the attestor name.
	Name = "platform"
	// Type is the predicate type URI for the platform binding attestation.
	Type = "https://testifysec.com/attestations/platform/v0.1"
	// RunType: prematerial — the subjects are static platform identifiers, so
	// they can be contributed before materials are collected.
	RunType = attestation.PreMaterialRunType
)

// Binding is the resolved tenant/product the attestation is bound to, plus the
// signing-identity audit info. The caller resolves it (server-side exchange or
// session lookup) and hands it to the attestor; the attestor never resolves it
// itself. A zero Binding (no platform URL, no ids, not a workflow identity)
// means "no binding" and the attestor soft-skips.
type Binding struct {
	PlatformURL string
	TenantID    string
	TenantName  string
	ProductID   string
	ProductName string
	Email       string
	// WorkflowIdentity records that the run authenticated via an ambient CI
	// workflow OIDC identity (rather than a stored login session).
	WorkflowIdentity bool
}

func (b Binding) isEmpty() bool {
	return b.PlatformURL == "" && b.TenantID == "" && b.ProductID == "" && !b.WorkflowIdentity
}

// Attestor records the platform tenant/product the attestation was produced
// under plus audit info about the signing identity. The marshaled struct is the
// attestation predicate. The unexported binding source (static value or
// resolver) is not marshaled.
type Attestor struct {
	PlatformURL string `json:"platform_url"`
	TenantID    string `json:"tenant_id,omitempty"`
	TenantName  string `json:"tenant_name,omitempty"`
	ProductID   string `json:"product_id,omitempty"`
	ProductName string `json:"product_name,omitempty"`
	Email       string `json:"email,omitempty"`
	// WorkflowIdentity is true when the run authenticated via an ambient CI
	// workflow OIDC identity.
	WorkflowIdentity bool `json:"workflow_identity,omitempty"`

	// binding source (never marshaled): a resolver takes precedence over a
	// static binding, so the cilock-internal adapter can defer the session
	// lookup to Attest time.
	static   *Binding
	resolver func() (Binding, error)
}

// Interface assertions.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

// Option configures a new Attestor.
type Option func(*Attestor)

// WithBinding constructs the attestor with an already-resolved static binding.
// This is the primary path for callers (e.g. cilock-action) that resolve the
// binding at run-entry and hand it to the attestor.
func WithBinding(b Binding) Option {
	return func(a *Attestor) {
		bb := b
		a.static = &bb
	}
}

// WithBindingResolver constructs the attestor with a resolver called at Attest
// time to obtain the binding. Used by the cilock-internal adapter to defer the
// session lookup + freshness check until the attestation runs. The resolver may
// return a SoftError (via attestation.NewSoftError) to skip the attestor.
func WithBindingResolver(fn func() (Binding, error)) Option {
	return func(a *Attestor) { a.resolver = fn }
}

// New returns a platform attestor. With no options it soft-skips at Attest time
// (no binding).
func New(opts ...Option) *Attestor {
	a := &Attestor{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Name returns the attestor name.
func (a *Attestor) Name() string { return Name }

// Type returns the predicate type URI.
func (a *Attestor) Type() string { return Type }

// RunType returns the run phase.
func (a *Attestor) RunType() attestation.RunType { return RunType }

// Schema returns the JSON schema for the predicate.
func (a *Attestor) Schema() *jsonschema.Schema { return jsonschema.Reflect(&Attestor{}) }

// Attest populates the attestor from its resolved binding. When the binding
// source yields an empty binding (not platform-authenticated), it returns a
// SoftError so the run skips this attestor.
func (a *Attestor) Attest(_ *attestation.AttestationContext) error {
	b, err := a.resolveBinding()
	if err != nil {
		return err
	}
	a.apply(b)
	return nil
}

func (a *Attestor) resolveBinding() (Binding, error) {
	if a.resolver != nil {
		b, err := a.resolver()
		if err != nil {
			return Binding{}, err
		}
		// An empty binding from the resolver (e.g. a session with no product, or
		// an unauthenticated run) must be treated exactly like the no-binding
		// case — otherwise Attest would succeed and emit a platform predicate with
		// no tenant/product subjects. Fail closed to a skip.
		if b.isEmpty() {
			return Binding{}, attestation.NewSoftError(
				"no platform binding — resolver returned an empty binding; skipping platform binding")
		}
		return b, nil
	}
	if a.static != nil && !a.static.isEmpty() {
		return *a.static, nil
	}
	return Binding{}, attestation.NewSoftError(
		"no platform binding — skipping platform binding (not authenticated to a platform, or no product resolved)")
}

func (a *Attestor) apply(b Binding) {
	a.PlatformURL = b.PlatformURL
	a.TenantID = b.TenantID
	a.TenantName = b.TenantName
	a.ProductID = b.ProductID
	a.ProductName = b.ProductName
	a.Email = b.Email
	a.WorkflowIdentity = b.WorkflowIdentity
	// Deliberately NO wall-clock signed-at: an attestor must be reproducible so
	// identical inputs yield identical signed output. The DSSE envelope's own
	// signature timestamp / the TSA carry the authoritative signing time.
}

// Subjects emits the platform tenant/product as in-toto subjects. The
// `testifysec-product:<id>` name is the convention the platform's ingestion
// autodiscovery re-authorizes to bind this attestation to the product (HIGH
// confidence); `testifysec-tenant:<id>` is additive self-description. The
// `testifysec-` namespace avoids collision with the in-toto product/material
// attestor vocabulary.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet)
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}

	if a.ProductID != "" {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.ProductID), hashes); err == nil {
			subjects[fmt.Sprintf("testifysec-product:%s", a.ProductID)] = ds
		}
	}
	if a.TenantID != "" {
		if ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(a.TenantID), hashes); err == nil {
			subjects[fmt.Sprintf("testifysec-tenant:%s", a.TenantID)] = ds
		}
	}
	return subjects
}
