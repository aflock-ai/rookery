// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"fmt"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/spf13/cobra"
)

// platformPrincipal is the stored platform credential a run signs as: an
// enrolled agent (its SPIFFE ID) or a `cilock login` session (its account).
// It is the ONE definition of "a principal that could have stored evidence" —
// the evidence gate below reads it rather than inferring the same fact from
// whichever resolved* fields a given path happens to fill in.
//
// nil for every run with no stored credential: local key, --offline, or an
// ambient CI identity with no login. Those runs never had upload authority to
// begin with, so the gate has nothing to hold them to.
type platformPrincipal struct {
	Kind string // "agent" | "session"
	Name string // SPIFFE ID, or the session's account
}

// uploadScope is the platform scope storing an attestation needs. It is the
// scope `cilock trust` grants by default, so the two cannot drift apart.
var uploadScope = DefaultTrustScopes[0]

// sessionPrincipalName names a login session for the evidence gate's messages:
// the account email when the session records one, else the tenant, else the
// platform it was logged into — never empty, so a refusal always names
// something the operator can act on.
func sessionPrincipalName(cred *auth.Credential, platformURL string) string {
	switch {
	case cred.Email != "":
		return cred.Email
	case cred.TenantName != "":
		return "tenant " + cred.TenantName
	default:
		return "login session for " + platformURL
	}
}

// EvidenceNotStoredError is the evidence gate's refusal: a stored platform
// principal signs this run, and the attestation it produces would not be
// stored. Typed so a caller can tell it from a signer or attestor failure.
type EvidenceNotStoredError struct {
	Principal   platformPrincipal
	PlatformURL string
}

func (e *EvidenceNotStoredError) Error() string {
	return fmt.Sprintf("refusing to run: this run would sign as %s %s but store NO evidence on %s\n"+
		"  Archivista upload is off for this run, and storing the attestation needs the %s scope for that principal\n"+
		"  pass --enable-archivista to store it (the platform must grant %s to %s),\n"+
		"  or --enable-archivista=false to sign locally on purpose — that run stores no evidence and a push gated on it will be refused",
		e.Principal.Kind, e.Principal.Name, e.PlatformURL, uploadScope, uploadScope, e.Principal.Name)
}

// EnforceEvidenceStorage is the fail-closed evidence gate. It runs at run
// START, before the wrapped command, because everything it decides on is known
// once the platform identity has resolved — and a refusal after a 30-minute
// test gate wastes the gate.
//
// Incident 2026-09-02: an enrolled agent credential resolved for `cilock run
// --step push-tests`, the agent path does not enable the upload, the summary
// printed "upload DISABLED", the process exited 0 with nothing stored, and the
// next push was refused for having no test attestation. A green exit that
// stored nothing is the same failure class as a gate that signs a run that
// compiled nothing: the exit code claimed evidence that does not exist.
//
// Rule:
//   - no stored principal (local key, --offline, ambient CI only) → proceed;
//     nothing here could have uploaded, and the "signed locally; not uploaded"
//     warning after the run covers it.
//   - principal + upload enabled → proceed; an upload that then fails is a
//     hard error on its own (uploadError in cli/run.go).
//   - principal + upload off + explicit --enable-archivista=false → proceed,
//     and say plainly that no evidence will be stored. The operator asked.
//   - principal + upload off, nothing explicit → REFUSE, naming the principal
//     and the scope storing evidence needs.
//
// Must run AFTER ResolvePlatformDefaults, which is what sets the principal.
func (ro *RunOptions) EnforceEvidenceStorage(cmd *cobra.Command) error {
	return ro.enforceEvidenceStorage(archivistaFlagExplicit(cmd))
}

// enforceEvidenceStorage is EnforceEvidenceStorage with the cobra-derived
// "the operator set --enable-archivista themselves" bit passed in, so the
// decision is unit-testable across its whole value space.
func (ro *RunOptions) enforceEvidenceStorage(uploadFlagExplicit bool) error {
	p := ro.platformPrincipal
	if p == nil || ro.ArchivistaOptions.Enable {
		return nil
	}
	if uploadFlagExplicit {
		log.Warnf("--enable-archivista=false: signing as %s %s with NO evidence stored on %s — a push gated on this run will be refused",
			p.Kind, p.Name, ro.PlatformURL)
		return nil
	}
	return &EvidenceNotStoredError{Principal: *p, PlatformURL: ro.PlatformURL}
}

// archivistaFlagExplicit reports whether the operator set the upload switch on
// the command line (either spelling). Only an explicit choice may turn the
// evidence gate's refusal into a warned exit 0.
func archivistaFlagExplicit(cmd *cobra.Command) bool {
	return cmd.Flags().Changed("enable-archivista") || cmd.Flags().Changed("enable-archivist")
}
