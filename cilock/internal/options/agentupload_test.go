// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The first prod mint under an enrolled agent signed as the agent, printed
// "archivista: upload DISABLED", exited 0, and the push was refused for having
// no evidence. Explicitly enabling upload got 401: the agent had a Fulcio
// token and nothing Archivista could authenticate. The exchange now returns
// an upload bearer beside the signing token; an agent run presents it and
// uploads BY DEFAULT, exactly as a human session does. An agent whose
// evidence stays on its own disk has not produced evidence.
// Design: docs/design/agent-enroll-ceremony.md, addendum 2026-09-02.

const agentUploadBearer = "agent-upload-bearer-do-not-print-41c2"

func agentExchangeServerWithUpload(t *testing.T, uploadToken string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/agent/credential-exchange" {
			w.Header().Set("Content-Type", "application/json")
			body := map[string]string{
				"token": testAgentJWT(agentSPIFFEID, 1), "token_type": "oidc", "spiffe_id": agentSPIFFEID,
			}
			if uploadToken != "" {
				body["upload_token"] = uploadToken
				body["upload_token_type"] = "bearer"
			}
			_ = json.NewEncoder(w).Encode(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestAgentRunUploadsWithTheAgentsOwnBearerByDefault(t *testing.T) {
	isolateCredentialStore(t)
	srv := agentExchangeServerWithUpload(t, agentUploadBearer)
	seedHumanSession(t, srv.URL) // present, and must NOT be the bearer that uploads
	seedAgent(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("agent path failed: %v", err)
	}

	if !ro.ArchivistaOptions.Enable {
		t.Fatal("an agent run must upload by default; sign-only is the silent failure the prod ceremony hit")
	}
	if got := ro.ArchivistaOptions.Url; got != srv.URL+"/archivista" {
		t.Fatalf("archivista url = %q, want the platform's own store", got)
	}
	var bearer string
	for _, h := range ro.ArchivistaOptions.Headers {
		if strings.HasPrefix(strings.ToLower(h), "authorization:") {
			bearer = h
		}
	}
	if bearer != "Authorization: Bearer "+agentUploadBearer {
		t.Fatalf("archivista bearer = %q, want the agent's upload token", bearer)
	}
	if strings.Contains(bearer, "stored-human-session") {
		t.Fatal("the human session's bearer is not the agent's to spend")
	}
}

func TestAgentRunWithoutAnUploadBearerFailsClosed(t *testing.T) {
	// A platform that hands back no upload token (no PKI) cannot take the
	// agent's evidence. That is a run that must not quietly succeed sign-only:
	// the identity path reports it and the run aborts, unless the operator
	// explicitly asked for sign-only with --enable-archivista=false.
	isolateCredentialStore(t)
	srv := agentExchangeServerWithUpload(t, "")
	seedAgent(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	err := ro.AgentIdentityError()
	if err == nil {
		t.Fatal("an agent run the platform cannot accept evidence from must fail, not sign into the void")
	}
	if !strings.Contains(err.Error(), "upload") {
		t.Fatalf("the error must name the missing upload authority: %v", err)
	}

	cmd, ro = newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL, "--enable-archivista=false"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("an explicit sign-only run is the operator's choice and must proceed: %v", err)
	}
	if ro.ArchivistaOptions.Enable {
		t.Fatal("--enable-archivista=false must be honoured")
	}
}

func TestAgentRunRespectsAnExplicitAuthorizationHeader(t *testing.T) {
	// An operator-supplied Archivista Authorization header wins over the
	// exchanged bearer, exactly as it does on the human path.
	isolateCredentialStore(t)
	srv := agentExchangeServerWithUpload(t, agentUploadBearer)
	seedAgent(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL, "--archivista-headers", "Authorization: Bearer operator-chosen"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("agent path failed: %v", err)
	}
	joined := strings.Join(ro.ArchivistaOptions.Headers, "\n")
	if strings.Contains(joined, agentUploadBearer) {
		t.Fatalf("the exchanged bearer must not be added beside an explicit Authorization header: %q", joined)
	}
}
