// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation/archivista"
	"github.com/aflock-ai/rookery/attestation/dsse"
)

// An agent run mints its Archivista upload bearer during option resolution and
// re-exchanges it at FIRST SIGNATURE, after the wrapped command. The bearer the
// upload actually presents must be the one the refresh produced: a build longer
// than the upload token's lifetime otherwise uploads with a credential that was
// silently renewed underneath it, and a 401 is not retryable (issue #8740).
//
// These tests assert on the header the Archivista server RECEIVES, not on the
// contents of ArchivistaOptions.Headers. The defect lives between the two --
// cli/run.go hands RunOptions to runRun BY VALUE and builds the client from the
// copy -- so a test that reads the option struct cannot see it.

const (
	agentUploadBearerFirst  = "agent-upload-bearer-exchange-1-do-not-print"
	agentUploadBearerSecond = "agent-upload-bearer-exchange-2-do-not-print"
)

// agentUploadRecorder is the in-process stand-in for the platform: it answers
// the agent credential exchange with a DIFFERENT upload token each call and
// records the Authorization header of every Archivista upload it receives.
type agentUploadRecorder struct {
	srv       *httptest.Server
	exchanges int64

	mu      sync.Mutex
	uploads []string
}

// newAgentUploadRecorder serves both the credential exchange and the platform's
// own Archivista from one origin, which is what the same-origin bearer guard
// requires. uploadTokens supplies the upload token for the Nth exchange; the
// last entry is reused if more exchanges happen than tokens were given.
func newAgentUploadRecorder(t *testing.T, uploadTokens ...string) *agentUploadRecorder {
	t.Helper()
	rec := &agentUploadRecorder{}
	rec.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/agent/credential-exchange":
			i := atomic.AddInt64(&rec.exchanges, 1)
			tok := uploadTokens[len(uploadTokens)-1]
			if int(i) <= len(uploadTokens) {
				tok = uploadTokens[i-1]
			}
			body := map[string]string{
				"token": testAgentJWT(agentSPIFFEID, i), "token_type": "oidc", "spiffe_id": agentSPIFFEID,
			}
			if tok != "" {
				body["upload_token"] = tok
				body["upload_token_type"] = "bearer"
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		case r.Method == http.MethodPost && r.URL.Path == "/archivista/upload":
			rec.mu.Lock()
			rec.uploads = append(rec.uploads, r.Header.Get("Authorization"))
			rec.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"gitoid": testStoreGitoid})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(rec.srv.Close)
	return rec
}

// testStoreGitoid is the syntactically-shaped gitoid the stub upload endpoint
// returns. Nothing under test parses it.
const testStoreGitoid = "0000000000000000000000000000000000000000000000000000000000000000"

func (r *agentUploadRecorder) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.uploads...)
}

// resolveAgentRun builds the RunOptions the way production does -- real flags,
// real ResolvePlatformDefaults -- rather than hand-wiring the struct. A defect
// that enters through construction is invisible to a hand-wired fixture.
func resolveAgentRun(t *testing.T, platformURL string, extraArgs ...string) *RunOptions {
	t.Helper()
	cmd, ro := newRunCmd(t)
	args := append([]string{"--platform-url", platformURL}, extraArgs...)
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("agent path failed: %v", err)
	}
	return ro
}

// uploadOnce performs one Archivista store through a BY-VALUE copy of
// RunOptions, exactly as cli/run.go does (runRun takes options.RunOptions, not
// a pointer).
func uploadOnce(t *testing.T, ro RunOptions) error {
	t.Helper()
	client, err := ro.ArchivistaOptions.Client()
	if err != nil {
		return err
	}
	if client == nil {
		t.Fatal("archivista upload is disabled, so this test would assert nothing")
	}
	_, err = client.Store(context.Background(), dsse.Envelope{Payload: []byte("{}"), PayloadType: "application/vnd.in-toto+json"})
	return err
}

// TestAgentUploadBearerTracksTheSigningTimeRefresh is the regression for #8740.
// The refresher runs before the certificate is bought; every upload after it
// must present the token that refresh produced.
func TestAgentUploadBearerTracksTheSigningTimeRefresh(t *testing.T) {
	isolateCredentialStore(t)
	rec := newAgentUploadRecorder(t, agentUploadBearerFirst, agentUploadBearerSecond)
	seedAgent(t, rec.srv.URL)

	ro := resolveAgentRun(t, rec.srv.URL)
	// The by-value copy is taken BEFORE the refresh, which is the ordering
	// cli/run.go has: options are resolved, the command runs, the deferred
	// signer refreshes, and only then is the client built from the copy.
	copied := *ro

	refresh := ro.FulcioTokenRefresher()
	if refresh == nil {
		t.Fatal("an agent run must carry a signing-time refresher")
	}
	if err := refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	if err := uploadOnce(t, copied); err != nil {
		t.Fatalf("upload: %v", err)
	}
	seen := rec.seen()
	if len(seen) != 1 {
		t.Fatalf("uploads = %d, want 1", len(seen))
	}
	if seen[0] != "Bearer "+agentUploadBearerSecond {
		t.Fatalf("upload presented %q, want the bearer the signing-time refresh minted; "+
			"a token frozen at option resolution 401s on a run longer than its lifetime", seen[0])
	}
}

// TestAgentUploadBearerBeforeAnyRefresh pins the unrefreshed case: with no
// refresh the initial exchange's bearer is the right one, and the fix must not
// break it.
func TestAgentUploadBearerBeforeAnyRefresh(t *testing.T) {
	isolateCredentialStore(t)
	rec := newAgentUploadRecorder(t, agentUploadBearerFirst, agentUploadBearerSecond)
	seedAgent(t, rec.srv.URL)

	ro := resolveAgentRun(t, rec.srv.URL)
	if err := uploadOnce(t, *ro); err != nil {
		t.Fatalf("upload: %v", err)
	}
	seen := rec.seen()
	if len(seen) != 1 || seen[0] != "Bearer "+agentUploadBearerFirst {
		t.Fatalf("upload headers = %v, want the initial exchange's bearer", seen)
	}
}

// TestAgentUploadBearerAcrossTwoUploads pins a refresh BETWEEN two uploads:
// cli/run.go builds a client per envelope, so the second must pick the new
// bearer up while the first legitimately carried the old one.
func TestAgentUploadBearerAcrossTwoUploads(t *testing.T) {
	isolateCredentialStore(t)
	rec := newAgentUploadRecorder(t, agentUploadBearerFirst, agentUploadBearerSecond)
	seedAgent(t, rec.srv.URL)

	ro := resolveAgentRun(t, rec.srv.URL)
	copied := *ro

	if err := uploadOnce(t, copied); err != nil {
		t.Fatalf("first upload: %v", err)
	}
	if err := ro.FulcioTokenRefresher()(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := uploadOnce(t, copied); err != nil {
		t.Fatalf("second upload: %v", err)
	}

	seen := rec.seen()
	if len(seen) != 2 {
		t.Fatalf("uploads = %d, want 2", len(seen))
	}
	if seen[0] != "Bearer "+agentUploadBearerFirst {
		t.Fatalf("first upload presented %q, want the initial bearer", seen[0])
	}
	if seen[1] != "Bearer "+agentUploadBearerSecond {
		t.Fatalf("second upload presented %q, want the refreshed bearer", seen[1])
	}
}

// TestAgentUploadRefusesWhenTheRefreshDropsTheUploadBearer is the fail-closed
// dimension. A platform that answers the re-exchange with NO upload token has
// withdrawn the agent's upload authority; "could not renew" is not "renewed",
// and the previous bearer must not be spent as though it were fresh.
func TestAgentUploadRefusesWhenTheRefreshDropsTheUploadBearer(t *testing.T) {
	isolateCredentialStore(t)
	rec := newAgentUploadRecorder(t, agentUploadBearerFirst, "")
	seedAgent(t, rec.srv.URL)

	ro := resolveAgentRun(t, rec.srv.URL)
	copied := *ro

	if err := ro.FulcioTokenRefresher()(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	err := uploadOnce(t, copied)
	if err == nil {
		t.Fatal("an upload with no renewed bearer must fail closed, not present the stale one")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "upload") {
		t.Fatalf("the refusal must name the missing upload authority: %v", err)
	}
	for _, h := range rec.seen() {
		if strings.Contains(h, agentUploadBearerFirst) {
			t.Fatalf("the stale bearer was sent after the platform withdrew it: %q", h)
		}
	}
}

// TestAgentUploadBearerNeverTravelsToAThirdPartyArchivista pins the same-origin
// guard through the client: the agent's bearer is scoped to the platform's own
// store and must not reach an operator-chosen third-party server.
func TestAgentUploadBearerNeverTravelsToAThirdPartyArchivista(t *testing.T) {
	isolateCredentialStore(t)
	rec := newAgentUploadRecorder(t, agentUploadBearerFirst)
	seedAgent(t, rec.srv.URL)

	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("the agent bearer leaked to a third-party Archivista: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"gitoid": testStoreGitoid})
	}))
	t.Cleanup(foreign.Close)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", rec.srv.URL, "--archivista-server", foreign.URL, "--enable-archivista=true"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("agent path failed: %v", err)
	}
	if err := ro.FulcioTokenRefresher()(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := uploadOnce(t, *ro); err != nil {
		t.Fatalf("upload: %v", err)
	}
}

// TestAgentUploadBearerWinsOverAmbientWorkflowOIDC pins the precedence for an
// enrolled agent running INSIDE GitHub Actions, where the ambient workflow OIDC
// source is auto-enabled too. An enrolled agent credential pre-empts every other
// identity for the run, so the upload must carry the agent's own bearer and not
// the runner's workflow token — the borrowed-identity result the agent principal
// exists to remove.
func TestAgentUploadBearerWinsOverAmbientWorkflowOIDC(t *testing.T) {
	isolateCredentialStore(t)

	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "ambient-workflow-oidc-do-not-print"})
	}))
	t.Cleanup(oidc.Close)
	// Set before newRunCmd: ArchivistaOptions.OIDC defaults off this env var at
	// flag-registration time.
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-request-token-do-not-print")

	rec := newAgentUploadRecorder(t, agentUploadBearerFirst, agentUploadBearerSecond)
	seedAgent(t, rec.srv.URL)

	ro := resolveAgentRun(t, rec.srv.URL)
	if !ro.ArchivistaOptions.OIDC {
		t.Fatal("this test is only meaningful with the ambient workflow OIDC source also enabled")
	}
	copied := *ro
	if err := ro.FulcioTokenRefresher()(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := uploadOnce(t, copied); err != nil {
		t.Fatalf("upload: %v", err)
	}
	seen := rec.seen()
	if len(seen) != 1 || seen[0] != "Bearer "+agentUploadBearerSecond {
		t.Fatalf("upload headers = %v, want the agent's refreshed bearer, not the runner's ambient workflow token", seen)
	}
}

// TestAgentUploadSurvivesABrokenAmbientOIDCEndpoint pins the other half of that
// precedence. The ambient mint is EAGER, so a runner whose OIDC endpoint is
// unhappy would fail client construction for a token the agent run was never
// going to present. Standing the branch down when an agent bearer is installed
// is what keeps an unrelated runner fault from destroying the agent's evidence.
func TestAgentUploadSurvivesABrokenAmbientOIDCEndpoint(t *testing.T) {
	isolateCredentialStore(t)

	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "id-token endpoint unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(oidc.Close)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-request-token-do-not-print")

	rec := newAgentUploadRecorder(t, agentUploadBearerFirst, agentUploadBearerSecond)
	seedAgent(t, rec.srv.URL)

	ro := resolveAgentRun(t, rec.srv.URL)
	if !ro.ArchivistaOptions.OIDC {
		t.Fatal("this test is only meaningful with the ambient workflow OIDC source also enabled")
	}
	copied := *ro
	if err := ro.FulcioTokenRefresher()(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := uploadOnce(t, copied); err != nil {
		t.Fatalf("a broken ambient OIDC endpoint must not fail an upload the agent bearer authenticates: %v", err)
	}
	seen := rec.seen()
	if len(seen) != 1 || seen[0] != "Bearer "+agentUploadBearerSecond {
		t.Fatalf("upload headers = %v, want the agent's refreshed bearer", seen)
	}
}

// TestAmbientWorkflowOIDCStillUploadsWithNoAgentEnrolled is the positive
// control for the branch above: with no agent credential on the machine the
// ambient CI workflow token is still what authenticates the upload. Without
// this, a change that simply disabled the OIDC branch would pass every agent
// test in this file.
func TestAmbientWorkflowOIDCStillUploadsWithNoAgentEnrolled(t *testing.T) {
	isolateCredentialStore(t) // no agent, no human session

	const workflowToken = "ambient-workflow-oidc-do-not-print"
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"value": workflowToken})
	}))
	t.Cleanup(oidc.Close)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", oidc.URL)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "runner-request-token-do-not-print")

	rec := newAgentUploadRecorder(t, agentUploadBearerFirst)

	cmd, ro := newRunCmd(t)
	// The ambient-only path leaves Enable false (nothing calls the
	// logged-in default), so CI asks for the upload explicitly.
	if err := cmd.ParseFlags([]string{"--platform-url", rec.srv.URL, "--enable-archivista=true"}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("no agent is enrolled, so the agent path must not have run: %v", err)
	}
	if ro.ArchivistaOptions.AuthTokenSource != nil {
		t.Fatal("no agent bearer may be installed when no agent is enrolled")
	}
	if err := uploadOnce(t, *ro); err != nil {
		t.Fatalf("upload: %v", err)
	}
	seen := rec.seen()
	if len(seen) != 1 || seen[0] != "Bearer "+workflowToken {
		t.Fatalf("upload headers = %v, want the ambient workflow OIDC token", seen)
	}
}

// TestAgentUploadKeepsTheOperatorsExplicitAuthorization pins the precedence the
// header path already had: an operator-supplied Authorization wins outright and
// the refresh must not overwrite it.
func TestAgentUploadKeepsTheOperatorsExplicitAuthorization(t *testing.T) {
	isolateCredentialStore(t)
	rec := newAgentUploadRecorder(t, agentUploadBearerFirst, agentUploadBearerSecond)
	seedAgent(t, rec.srv.URL)

	ro := resolveAgentRun(t, rec.srv.URL, "--archivista-headers", "Authorization: Bearer operator-chosen-do-not-print")
	copied := *ro
	if err := ro.FulcioTokenRefresher()(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := uploadOnce(t, copied); err != nil {
		t.Fatalf("upload: %v", err)
	}
	seen := rec.seen()
	if len(seen) != 1 || seen[0] != "Bearer operator-chosen-do-not-print" {
		t.Fatalf("upload headers = %v, want the operator's explicit Authorization", seen)
	}
}

// TestAgentWithdrawnUploadGrantDeclaresItselfPermanent is the WIRING half of
// the classification, as distinct from the mechanism.
//
// The archivista package's own table proves that a credential DECLARED
// permanently unavailable classifies terminal. It cannot prove that cilock's
// agent source actually declares it — that marking lives in agentsigning.go and
// reaches the classifier through ArchivistaOptions.Client() and a BY-VALUE copy
// of RunOptions. A hand-wired fixture in the other package would keep passing
// with the marking deleted, and the withdrawn grant would quietly go back to
// spending the whole retry budget re-reading the same empty token.
//
// So the refusal here is produced by the real refresher against the real
// constructor, exactly as cli/run.go builds it.
func TestAgentWithdrawnUploadGrantDeclaresItselfPermanent(t *testing.T) {
	isolateCredentialStore(t)
	rec := newAgentUploadRecorder(t, agentUploadBearerFirst, "")
	seedAgent(t, rec.srv.URL)

	ro := resolveAgentRun(t, rec.srv.URL)
	copied := *ro

	if err := ro.FulcioTokenRefresher()(); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	err := uploadOnce(t, copied)
	if err == nil {
		t.Fatal("an upload with no renewed bearer must fail closed")
	}
	if !errors.Is(err, archivista.ErrCredentialUnavailable) {
		t.Fatalf("a withdrawn grant must declare itself permanent, or the upload spends its whole retry budget re-reading an empty token: %v", err)
	}
	if archivista.IsRetryable(context.Background(), err) {
		t.Fatal("a withdrawn upload grant must classify terminal, not retryable")
	}
	if got := len(rec.seen()); got != 0 {
		t.Fatalf("no upload may reach the server without a bearer, saw %d", got)
	}
}
