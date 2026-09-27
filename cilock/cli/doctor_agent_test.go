// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// jade:ring local

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
)

// The pushgate skill tells an agent to preflight with `cilock doctor`. With an
// enrolled agent and no human session, doctor warned "no stored session" and
// hinted `cilock login` twice: the human's login, which an agent must not use
// (onbsim, 2026-09-25). The enrolled agent is the identity; say so.
func TestDoctorNamesTheEnrolledAgentAndNeverHintsLogin(t *testing.T) {
	agent := &auth.AgentCredential{TenantID: "t-1", AgentID: "a-1", RefreshCredential: "secret-do-not-print"}
	r := &DoctorReport{OK: true}
	checkIdentity(r, "https://platform.example.com", nil, agent, false, "", nil,
		"https://platform.example.com/archivista", "https://platform.example.com/archivista")

	logged := findCheck(r, checkNameLoggedIn)
	if logged == nil || logged.Status != doctorPass {
		t.Fatalf("an enrolled agent is this machine's identity: want pass, got %#v", logged)
	}
	if !strings.Contains(logged.Detail, "a-1") || !strings.Contains(logged.Detail, "t-1") {
		t.Errorf("name the agent and tenant: %q", logged.Detail)
	}
	upload := findCheck(r, checkNameUploadAuth)
	if upload == nil {
		t.Fatal("upload-auth must still be reported")
	}
	if upload.Status == doctorPass {
		t.Error("doctor does not exchange the credential, so it cannot claim the upload is authorized")
	}
	if !strings.Contains(upload.Hint, "cilock agent status") {
		t.Errorf("point at the agent's own check: %q", upload.Hint)
	}
	for _, c := range r.Checks {
		if strings.Contains(c.Hint, "cilock login") || strings.Contains(c.Detail, "secret-do-not-print") {
			t.Errorf("check %s steers an agent to the human login or prints its secret: %#v", c.Name, c)
		}
	}
}

// With a human session the agent changes nothing: the human checks run.
func TestDoctorWithAHumanSessionIgnoresTheAgent(t *testing.T) {
	agent := &auth.AgentCredential{TenantID: "t-1", AgentID: "a-1"}
	cred := &auth.Credential{Token: "abc", TenantName: "acme", ExpiresAt: time.Now().Add(time.Hour)}
	r := &DoctorReport{OK: true}
	checkIdentity(r, "https://platform.example.com", cred, agent, false, "", nil,
		"https://platform.example.com/archivista", "https://platform.example.com/archivista")
	if c := findCheck(r, checkNameUploadAuth); c == nil || c.Status != doctorPass {
		t.Fatalf("a same-origin human session authorizes uploads: %#v", c)
	}
}

// With neither, the human hint stands.
func TestDoctorWithNoIdentityStillHintsLogin(t *testing.T) {
	r := &DoctorReport{OK: true}
	checkIdentity(r, "https://platform.example.com", nil, nil, false, "", nil,
		"https://platform.example.com/archivista", "https://platform.example.com/archivista")
	if c := findCheck(r, checkNameLoggedIn); c == nil || !strings.Contains(c.Hint, "cilock login") {
		t.Fatalf("no identity at all: the fix is cilock login, got %#v", c)
	}
}

// A pending agent was delivered but never redeemed, so it signs nothing yet:
// doctor must not pass it, and still never hints the human's login.
func TestDoctorWarnsOnAPendingAgentWithoutHintingLogin(t *testing.T) {
	agent := &auth.AgentCredential{TenantID: "t-1", AgentID: "a-1"}
	r := &DoctorReport{OK: true}
	checkIdentity(r, "https://platform.example.com", nil, agent, true, "", nil,
		"https://platform.example.com/archivista", "https://platform.example.com/archivista")
	logged := findCheck(r, checkNameLoggedIn)
	if logged == nil || logged.Status == doctorPass {
		t.Fatalf("a pending agent signs nothing yet: want a warning, got %#v", logged)
	}
	if !strings.Contains(logged.Detail, "not yet activated") {
		t.Errorf("say the agent is not yet activated: %q", logged.Detail)
	}
	for _, c := range r.Checks {
		if strings.Contains(c.Hint, "cilock login") {
			t.Errorf("check %s steers an agent to the human login: %#v", c.Name, c)
		}
	}
}
