// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// Package platform is the cilock-internal adapter around the public platform
// attestor (github.com/aflock-ai/rookery/plugins/attestors/platform). It owns
// the cilock-specific binding source — the stored `cilock login` session lookup
// plus the ambient-CI workflow-identity trust handshake — and registers the
// "platform" attestor so the CLI's DefaultAttestors keeps working unchanged.
//
// The predicate, subject generation, and attestor interface live in the public
// package (so a separate module like cilock-action can import them); this
// adapter only supplies HOW the binding is resolved on the cilock CLI.
package platform

import (
	"fmt"
	"os"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	pubplatform "github.com/aflock-ai/rookery/plugins/attestors/platform"
)

// Name is the attestor name (re-exported from the public package).
const Name = pubplatform.Name

// PlatformURLEnv lets `cilock run` tell the attestor which platform session to
// bind to. Falls back to the default platform when unset.
const PlatformURLEnv = config.PlatformURLEnv

func init() {
	attestation.RegisterAttestation(pubplatform.Name, pubplatform.Type, pubplatform.RunType,
		func() attestation.Attestor { return New() })
}

// New returns a platform attestor wired to the cilock session/ambient binding
// resolver. The binding is resolved lazily at Attest time (the CLI registers
// this via the factory before a session may exist).
func New() *pubplatform.Attestor {
	return pubplatform.New(pubplatform.WithBindingResolver(resolveSessionBinding))
}

// resolveSessionBinding produces the ephemeral platform binding the attestor
// stamps, from cilock's own credential sources:
//
//   - A stored `cilock login` session (auth.Lookup, bearer-only) supplies the
//     full tenant/product binding.
//   - Failing that, an ambient CI workflow OIDC identity — signalled by `cilock
//     run` setting CILOCK_PLATFORM_URL after its same-origin check AND marking
//     the in-process trust binding — records a platform binding. If the
//     run-entry gate resolved concrete tenant/product server-side (threaded via
//     config.ResolvedBinding), those are emitted for a strong link; otherwise a
//     workflow-identity marker is recorded and the server resolves them on upload.
//   - With neither, it returns a SoftError so the attestor is skipped.
func resolveSessionBinding() (pubplatform.Binding, error) {
	rawPlatformURL := os.Getenv(config.PlatformURLEnv)
	platformURL := rawPlatformURL
	if platformURL == "" {
		platformURL = config.DefaultPlatformURL
	}

	cred, err := auth.Lookup(platformURL)
	if err != nil {
		return pubplatform.Binding{}, fmt.Errorf("look up platform session: %w", err)
	}
	if cred != nil {
		return pubplatform.Binding{
			PlatformURL: cred.PlatformURL,
			TenantID:    cred.TenantID,
			TenantName:  cred.TenantName,
			ProductID:   cred.ProductID,
			ProductName: cred.ProductName,
			Email:       cred.Email,
		}, nil
	}

	// No stored session. The keyless-CI case: `cilock run` authenticated an upload
	// to the platform's OWN Archivista under an ambient workflow OIDC identity.
	//
	// Trust gate: CILOCK_PLATFORM_URL alone is NOT sufficient — it is an inheritable,
	// user-controllable env var. We additionally require the in-process trust marker
	// that ResolvePlatformDefaults sets (only after a same-origin + ambient-OIDC
	// check) and that it matches the URL we are about to bind. An externally-injected
	// env var cannot flip that marker, so it cannot forge a binding on its own.
	if rawPlatformURL != "" && auth.WorkflowOIDCAvailable() {
		bound := auth.NormalizeURL(platformURL)
		if trusted, ok := config.TrustedPlatformBinding(); ok && trusted == bound {
			b := pubplatform.Binding{PlatformURL: bound, WorkflowIdentity: true}
			// If the run-entry gate resolved the concrete tenant/product for this
			// url (fresh per run, never persisted), emit them for a strong link.
			if rb, ok := config.ResolvedBinding(bound); ok {
				b.TenantID = rb.TenantID
				b.TenantName = rb.TenantName
				b.ProductID = rb.ProductID
				b.ProductName = rb.ProductName
			}
			return b, nil
		}
		return pubplatform.Binding{}, attestation.NewSoftError("untrusted CILOCK_PLATFORM_URL for ambient workflow binding — skipping platform binding (the binding is set by `cilock run` after a same-origin check, not by a raw environment variable)")
	}

	return pubplatform.Binding{}, attestation.NewSoftError("no platform session — skipping platform binding (run `cilock login`, or in CI grant `id-token: write` for ambient workflow identity)")
}
