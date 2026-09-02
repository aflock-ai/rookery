// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Incident 2026-09-02: an enrolled agent credential resolved for a `cilock run
// --step push-tests`, the agent path never enabled the Archivista upload, the
// summary printed "upload DISABLED", the process exited 0, and the next push
// was refused for having no test attestation. A green exit that stored nothing
// is the same failure class as a gate that signs a run that compiled nothing.
//
// The rule these tests pin: when a stored platform principal signs the run and
// the attestation will not be stored, `cilock run` refuses BEFORE the wrapped
// command runs, naming the principal and the scope that storing evidence needs.
// Only an explicit --enable-archivista=false lets it proceed, and then the
// warning and the summary both say no evidence is stored.
//
// Since #8732 the agent path uploads by default (and fails on its own when the
// platform mints no upload bearer), and the session path has always uploaded by
// default — so today no credential path reaches the refusing cell on its own.
// The gate is the invariant that keeps it that way: a future path that resolves
// a principal without enabling the upload is refused here, not exited 0.

// TestEnforceEvidenceStorage_PrincipalWithoutUploadRefuses is the incident
// shape as the gate sees it: a resolved principal, upload off, and no explicit
// opt-out on the real flag set. The state is composed directly because no
// current credential path produces it (see the file comment) — which is what
// the resolution-path tests below establish with their Enable preconditions.
func TestEnforceEvidenceStorage_PrincipalWithoutUploadRefuses(t *testing.T) {
	const platform = "https://platform.example.com"
	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", platform}); err != nil {
		t.Fatal(err)
	}
	ro.PlatformURL = platform
	ro.platformPrincipal = &platformPrincipal{Kind: "agent", Name: agentSPIFFEID}
	ro.ArchivistaOptions.Enable = false

	err := ro.EnforceEvidenceStorage(cmd)
	if err == nil {
		t.Fatal("run signed by an agent principal with no upload configured exited clean; it must refuse")
	}
	var notStored *EvidenceNotStoredError
	if !errors.As(err, &notStored) {
		t.Fatalf("error is %T, want *EvidenceNotStoredError so a caller can classify it", err)
	}
	msg := err.Error()
	for _, want := range []string{agentSPIFFEID, "agent", "attestation:upload", "--enable-archivista", platform} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal must name %q; got:\n%s", want, msg)
		}
	}
}

// TestEnforceEvidenceStorage_AgentDefaultIsQuietBecauseUploadIsOn: after #8732
// the agent path turns the upload on, so the gate is quiet by default. The
// Enable precondition is what makes "quiet" mean "upload on" and not "no
// principal resolved".
func TestEnforceEvidenceStorage_AgentDefaultIsQuietBecauseUploadIsOn(t *testing.T) {
	isolateCredentialStore(t)
	srv := agentExchangeServer(t)
	seedAgent(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("precondition: agent path failed: %v", err)
	}
	if ro.platformPrincipal == nil || ro.platformPrincipal.Kind != "agent" {
		t.Fatalf("precondition: agent did not resolve as the run's principal: %+v", ro.platformPrincipal)
	}
	if !ro.ArchivistaOptions.Enable {
		t.Fatal("precondition: the agent path left the upload off; the gate would refuse for the wrong reason")
	}
	if err := ro.EnforceEvidenceStorage(cmd); err != nil {
		t.Fatalf("upload is on, yet the gate refused: %v", err)
	}
}

// TestEnforceEvidenceStorage_ExplicitOptOutProceedsAndSaysSo: the ONE thing
// that may turn the refusal into exit 0 is the operator saying, on the command
// line, that they do not want the evidence stored — and the run still says so.
func TestEnforceEvidenceStorage_ExplicitOptOutProceedsAndSaysSo(t *testing.T) {
	isolateCredentialStore(t)
	srv := agentExchangeServer(t)
	seedAgent(t, srv.URL)
	logs := captureLogs(t)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL, "--enable-archivista=false"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("precondition: agent path failed: %v", err)
	}

	if err := ro.EnforceEvidenceStorage(cmd); err != nil {
		t.Fatalf("explicit --enable-archivista=false must proceed; got %v", err)
	}
	out := logs.all()
	if !strings.Contains(out, "no evidence") && !strings.Contains(out, "NO evidence") {
		t.Fatalf("opt-out must warn that no evidence is stored; logged:\n%s", out)
	}
	if !strings.Contains(out, agentSPIFFEID) {
		t.Fatalf("opt-out warning must name the principal that signs unstored; logged:\n%s", out)
	}
}

// TestEnforceEvidenceStorage_HumanSession: a `cilock login` session is a
// stored principal too. Its path auto-enables the upload, so the gate is quiet
// by default and only an explicit opt-out reaches the "proceed, warned" branch.
func TestEnforceEvidenceStorage_HumanSession(t *testing.T) {
	for _, tc := range []struct {
		name        string
		flags       []string
		wantEnabled bool
		wantErr     bool
	}{
		{name: "default — upload auto-enabled, gate quiet", flags: nil, wantEnabled: true, wantErr: false},
		{name: "explicit opt-out — proceeds", flags: []string{"--enable-archivista=false"}, wantEnabled: false, wantErr: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateCredentialStore(t)
			srv := signTokenStub(t)
			t.Cleanup(srv.Close)
			seedHumanSession(t, srv.URL)

			cmd, ro := newRunCmd(t)
			if err := cmd.ParseFlags(append([]string{"--platform-url", srv.URL}, tc.flags...)); err != nil {
				t.Fatal(err)
			}
			ro.ResolvePlatformDefaults(cmd)
			// Precondition, so the quiet case is quiet for the right reason —
			// the upload is on — and not because no principal resolved.
			if ro.platformPrincipal == nil {
				t.Fatal("precondition: the session did not resolve as a principal, so this case proves nothing")
			}
			if ro.ArchivistaOptions.Enable != tc.wantEnabled {
				t.Fatalf("precondition: ArchivistaOptions.Enable = %v, want %v", ro.ArchivistaOptions.Enable, tc.wantEnabled)
			}
			err := ro.EnforceEvidenceStorage(cmd)
			if (err != nil) != tc.wantErr {
				t.Fatalf("EnforceEvidenceStorage = %v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

// TestEnforceEvidenceStorage_NoPrincipalStandsDown: with no stored platform
// principal (a local-key run against the hosted defaults, or --offline) there is
// no identity that could have uploaded, so the gate has nothing to enforce and
// the existing "signed locally; not uploaded" warning keeps that job.
func TestEnforceEvidenceStorage_NoPrincipalStandsDown(t *testing.T) {
	for _, flags := range [][]string{
		{"--platform-url", "https://platform.example.com"},
		{"--offline"},
	} {
		t.Run(strings.Join(flags, " "), func(t *testing.T) {
			isolateCredentialStore(t)
			cmd, ro := newRunCmd(t)
			if err := cmd.ParseFlags(flags); err != nil {
				t.Fatal(err)
			}
			ro.ResolvePlatformDefaults(cmd)
			if err := ro.EnforceEvidenceStorage(cmd); err != nil {
				t.Fatalf("no principal resolved, yet the gate refused: %v", err)
			}
		})
	}
}

// TestEnforceEvidenceStorage_ValueSpace sweeps the pure decision over every
// combination of (principal, upload enabled, explicit opt-out), so the refusal
// is a property of the rule and not of the two incident-shaped cases above.
// The only cell that refuses: a principal, upload off, and no explicit opt-out.
func TestEnforceEvidenceStorage_ValueSpace(t *testing.T) {
	principals := map[string]*platformPrincipal{
		"none":    nil,
		"agent":   {Kind: "agent", Name: agentSPIFFEID},
		"session": {Kind: "session", Name: "cole@example.com"},
	}
	for pname, p := range principals {
		for _, enabled := range []bool{false, true} {
			for _, optOut := range []bool{false, true} {
				name := pname + "/enabled=" + boolStr(enabled) + "/optout=" + boolStr(optOut)
				t.Run(name, func(t *testing.T) {
					ro := &RunOptions{PlatformURL: "https://platform.example.com", platformPrincipal: p}
					ro.ArchivistaOptions.Enable = enabled
					err := ro.enforceEvidenceStorage(optOut)
					wantRefuse := p != nil && !enabled && !optOut
					if (err != nil) != wantRefuse {
						t.Fatalf("enforceEvidenceStorage(principal=%s, enabled=%v, optOut=%v) = %v, want refuse=%v",
							pname, enabled, optOut, err, wantRefuse)
					}
				})
			}
		}
	}
}

// TestRunSummary_NotUploadedSaysNoEvidenceStored: the human summary for a run
// whose attestation was not stored must say so in those words — "upload
// DISABLED" reads as a setting, "no evidence stored" reads as the outcome the
// next push will be judged on.
func TestRunSummary_NotUploadedSaysNoEvidenceStored(t *testing.T) {
	s := sampleSummary()
	s.Uploaded = false
	s.Gitoid = ""
	var buf bytes.Buffer
	s.WriteHuman(&buf)
	out := strings.ToLower(buf.String())
	if !strings.Contains(out, "no evidence stored") {
		t.Fatalf("summary for an unstored attestation must say \"no evidence stored\"; got:\n%s", buf.String())
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
