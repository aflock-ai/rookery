// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
)

// These tests pin the issuer pre-flight — the client-side half of the fix for
// the customer incident behind prod correlation id
// 3c8183a4-7c0e-49f9-abb4-f853d6ab2d83.
//
// A customer followed stale setup instructions naming a retired issuer
// hostname. `cilock trust` printed the plan, asked "Proceed? [y/N]", they
// answered y, and only THEN did the platform reject it — with an opaque
// "internal server error (correlation id: …)". The server-side half makes that
// refusal explain itself; this half stops the doomed round-trip entirely, so
// the user is never asked to confirm something that cannot work.
//
// DESIGN CONSTRAINT — this pre-flight must fail OPEN, and that is deliberate.
// It is a usability check, not a security control: the authority over which
// issuers may be registered is the platform's safehttp gate, which is
// unchanged. The CLI resolves DNS from the OPERATOR'S network, while the
// platform resolves from ITS OWN. Hard-failing on any lookup error would
// break a laptop behind a captive portal, a flaky VPN resolver, or an
// air-gapped operator, for a name the platform can resolve perfectly well.
// So ONLY an authoritative "this name does not exist" (NXDOMAIN / NODATA,
// which Go reports as *net.DNSError with IsNotFound) blocks; every other
// outcome — timeout, temporary failure, no resolver at all — is treated as
// inconclusive and proceeds.

// stubIssuerLookup replaces the DNS seam for one test, so the pre-flight is
// hermetic and never depends on the machine's resolver.
func stubIssuerLookup(t *testing.T, fn func(ctx context.Context, host string) ([]string, error)) {
	t.Helper()
	prev := lookupIssuerHost
	lookupIssuerHost = fn
	t.Cleanup(func() { lookupIssuerHost = prev })
}

// notFoundLookup mimics an authoritative "no such host" — what Go returns for
// both NXDOMAIN and NODATA (verified against the real retired hostname).
func notFoundLookup(t *testing.T) {
	t.Helper()
	stubIssuerLookup(t, func(_ context.Context, host string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	})
}

// trustCmdWithOutput returns a command whose stdout is captured, so a test can
// prove the plan / confirmation prompt was never reached.
func trustCmdWithOutput() (*cobra.Command, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	cmd := &cobra.Command{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetIn(strings.NewReader(""))
	return cmd, buf
}

// genericIssuerOpts drives the `--issuer` / `--subject` escape hatch so the
// test pins one exact hostname instead of a provider default.
func genericIssuerOpts(issuer string) *options.TrustOptions {
	return &options.TrustOptions{
		Issuer:  issuer,
		Subject: "spiffe://example.com/repo/acme/app",
	}
}

// TestRunTrust_RefusesUnresolvableIssuerLocally is the headline: a retired
// issuer hostname is caught locally, with a message that names the host, the
// cause, and the remedy — and no platform round-trip.
func TestRunTrust_RefusesUnresolvableIssuerLocally(t *testing.T) {
	platformURL := seedSession(t, sessionJWT(t, []string{"attestation:upload", "oidc:write"}))
	notFoundLookup(t)

	cmd, out := trustCmdWithOutput()
	// dryRun=false: this is the real path the customer took.
	err := runTrust(cmd, nil, genericIssuerOpts("https://factory.stale-instructions.invalid"), platformURL, true, false)
	if err == nil {
		t.Fatal("expected a local refusal for an issuer hostname that does not resolve, got nil")
	}
	msg := err.Error()
	t.Logf("customer-visible message: %s", msg)

	for _, want := range []string{"factory.stale-instructions.invalid", "does not resolve", "out of date", "regenerate"} {
		if !strings.Contains(strings.ToLower(msg), strings.ToLower(want)) {
			t.Errorf("message missing %q; got: %s", want, msg)
		}
	}
	// It must be a LOCAL refusal — never the opaque platform error it replaces.
	if strings.Contains(msg, "platform rejected trust") || strings.Contains(msg, "internal server error") {
		t.Errorf("pre-flight must refuse locally, not surface a platform error: %s", msg)
	}
	// And the user must never have been shown a plan or asked to confirm
	// something that cannot work.
	if got := out.String(); strings.Contains(got, "Proceed?") || strings.Contains(got, "issuer:") {
		t.Errorf("pre-flight must run BEFORE the plan/confirmation is printed; stdout was:\n%s", got)
	}
}

// TestRunTrust_InconclusiveDNSDoesNotBlock is the FAIL-OPEN guard. A resolver
// timeout says nothing about whether the platform can resolve the issuer, so
// it must not block the operator. Regressing this to a hard failure would
// break every restricted-network and air-gapped operator.
func TestRunTrust_InconclusiveDNSDoesNotBlock(t *testing.T) {
	platformURL := seedSession(t, sessionJWT(t, []string{"attestation:upload", "oidc:write"}))

	for name, stubErr := range map[string]error{
		"timeout":       &net.DNSError{Err: "i/o timeout", Name: "idp.example.com", IsTimeout: true},
		"temporary":     &net.DNSError{Err: "server misbehaving", Name: "idp.example.com", IsTemporary: true},
		"no resolver":   errors.New("dial udp 127.0.0.53:53: connect: network is unreachable"),
		"ctx cancelled": context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			stubIssuerLookup(t, func(_ context.Context, _ string) ([]string, error) { return nil, stubErr })

			cmd, _ := trustCmdWithOutput()
			// dryRun=true stops before the platform call; reaching it means the
			// pre-flight let us through.
			if err := runTrust(cmd, nil, genericIssuerOpts("https://idp.example.com"), platformURL, true, true); err != nil {
				t.Fatalf("an inconclusive DNS result must NOT block the operator, got: %v", err)
			}
		})
	}
}

// TestRunTrust_ResolvableIssuerProceeds is the happy path: a live issuer
// passes the pre-flight untouched.
func TestRunTrust_ResolvableIssuerProceeds(t *testing.T) {
	platformURL := seedSession(t, sessionJWT(t, []string{"attestation:upload", "oidc:write"}))
	stubIssuerLookup(t, func(_ context.Context, _ string) ([]string, error) {
		return []string{"172.67.167.187"}, nil
	})

	cmd, out := trustCmdWithOutput()
	if err := runTrust(cmd, nil, genericIssuerOpts("https://pushgate.dev"), platformURL, true, true); err != nil {
		t.Fatalf("a resolvable issuer must pass the pre-flight, got: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "pushgate.dev") {
		t.Errorf("expected the dry-run plan to be printed for a resolvable issuer, got:\n%s", got)
	}
}

// TestRunTrust_SkipIssuerCheckBypassesPreflight covers the split-horizon
// escape hatch. An on-prem issuer (GHES, self-hosted GitLab — an explicitly
// documented `cilock trust --host` flow) can resolve from the platform's
// network and NXDOMAIN from an operator's laptop off-VPN. Without an opt-out
// the pre-flight would refuse a registration that would actually succeed,
// which would make this check a regression for on-prem users.
func TestRunTrust_SkipIssuerCheckBypassesPreflight(t *testing.T) {
	platformURL := seedSession(t, sessionJWT(t, []string{"attestation:upload", "oidc:write"}))
	notFoundLookup(t)

	o := genericIssuerOpts("https://oidc.corp.invalid")
	o.SkipIssuerCheck = true

	cmd, out := trustCmdWithOutput()
	if err := runTrust(cmd, nil, o, platformURL, true, true); err != nil {
		t.Fatalf("--skip-issuer-check must bypass the DNS pre-flight, got: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "oidc.corp.invalid") {
		t.Errorf("expected the dry-run plan to be printed once the pre-flight is skipped, got:\n%s", got)
	}
}

// TestRunTrust_UnresolvableRefusalNamesTheEscapeHatch makes sure the refusal
// tells an on-prem operator how to proceed. A block with no documented way
// past it is what turns a helpful check into a support ticket.
func TestRunTrust_UnresolvableRefusalNamesTheEscapeHatch(t *testing.T) {
	platformURL := seedSession(t, sessionJWT(t, []string{"attestation:upload", "oidc:write"}))
	notFoundLookup(t)

	cmd, _ := trustCmdWithOutput()
	err := runTrust(cmd, nil, genericIssuerOpts("https://oidc.corp.invalid"), platformURL, true, false)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "--skip-issuer-check") {
		t.Errorf("refusal must name the on-prem escape hatch, got: %v", err)
	}
}

// TestRunTrust_PreflightRunsBeforeScopeCheckDoesNotRegress keeps the two
// pre-flights ordered sensibly: a session lacking oidc:write is still rejected
// on SCOPE (the cheaper, network-free check) rather than on DNS, so the
// existing remedy message is not displaced by this new one.
func TestRunTrust_PreflightRunsBeforeScopeCheckDoesNotRegress(t *testing.T) {
	platformURL := seedSession(t, sessionJWT(t, []string{"attestation:upload"}))
	notFoundLookup(t)

	cmd, _ := trustCmdWithOutput()
	err := runTrust(cmd, nil, genericIssuerOpts("https://factory.stale-instructions.invalid"), platformURL, true, true)
	if err == nil {
		t.Fatal("expected a refusal for a session lacking oidc:write")
	}
	if !strings.Contains(err.Error(), "--allow-trust") {
		t.Errorf("the scope pre-flight must still win for a scope-less session, got: %v", err)
	}
}
