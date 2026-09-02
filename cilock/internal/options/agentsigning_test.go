// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package options

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/auth"

	// Register the fulcio signer provider so AddFlags wires up the
	// --signer-fulcio-* flags the agent exchange targets.
	_ "github.com/aflock-ai/rookery/plugins/signers/fulcio"
)

// agentRefreshCredential is the bearer every test here seeds. No log line, run
// summary, or error message cilock produces may contain it.
const agentRefreshCredential = "refresh-credential-do-not-print-9d3f"

const agentSPIFFEID = "spiffe://platform.example.com/tenant/t-1/agent/a-1"

// capturingLogger records every line the attestation logger emits so a test can
// assert on what was actually written rather than on what the source looks like.
type capturingLogger struct{ lines []string }

func (l *capturingLogger) record(format string, args ...interface{}) {
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}
func (l *capturingLogger) recordArgs(args ...interface{}) {
	l.lines = append(l.lines, fmt.Sprint(args...))
}

func (l *capturingLogger) Errorf(f string, a ...interface{}) { l.record(f, a...) }
func (l *capturingLogger) Error(a ...interface{})            { l.recordArgs(a...) }
func (l *capturingLogger) Warnf(f string, a ...interface{})  { l.record(f, a...) }
func (l *capturingLogger) Warn(a ...interface{})             { l.recordArgs(a...) }
func (l *capturingLogger) Debugf(f string, a ...interface{}) { l.record(f, a...) }
func (l *capturingLogger) Debug(a ...interface{})            { l.recordArgs(a...) }
func (l *capturingLogger) Infof(f string, a ...interface{})  { l.record(f, a...) }
func (l *capturingLogger) Info(a ...interface{})             { l.recordArgs(a...) }

func (l *capturingLogger) all() string { return strings.Join(l.lines, "\n") }

// captureLogs routes the attestation logger into a buffer for the duration of
// one test, restoring the previous logger afterwards.
func captureLogs(t *testing.T) *capturingLogger {
	t.Helper()
	c := &capturingLogger{}
	log.SetLogger(c)
	t.Cleanup(func() { log.SetLogger(log.SilentLogger{}) })
	return c
}

// agentExchangeServer answers the credential-exchange contract with a DIFFERENT
// token on every call, so a refresher that genuinely re-exchanges is
// distinguishable from one that reinstalls a stale value.
func agentExchangeServer(t *testing.T) *httptest.Server {
	t.Helper()
	var n int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/agent/credential-exchange" {
			i := atomic.AddInt64(&n, 1)
			w.Header().Set("Content-Type", "application/json")
			// The token's subject MUST be the principal the response names: the
			// exchange binds the two, so a placeholder string is refused. The
			// counter varies the header so each exchange still yields a DISTINCT
			// token and the refresher case can tell them apart.
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token":        testAgentJWT(agentSPIFFEID, i),
				"token_type":   "oidc",
				"spiffe_id":    agentSPIFFEID,
				"upload_token": "test-upload-bearer",
			})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func seedAgent(t *testing.T, platformURL string) {
	t.Helper()
	if err := auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       platformURL,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: agentRefreshCredential,
	}); err != nil {
		t.Fatalf("seed agent credential: %v", err)
	}
}

func seedHumanSession(t *testing.T, platformURL string) {
	t.Helper()
	if err := auth.Save(auth.Credential{
		PlatformURL: platformURL,
		Token:       "stored-human-session",
		Email:       "cole@example.com",
		AuthMode:    auth.AuthModeBrowser,
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed human session: %v", err)
	}
}

// TestAgentCredentialWinsOverTheHumanSession is the precedence rule: with both
// credentials present for a platform, the enrolled agent signs, the human
// session is not exchanged, and the summary names the agent.
func TestAgentCredentialWinsOverTheHumanSession(t *testing.T) {
	isolateCredentialStore(t)

	var humanExchanges int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/credential-exchange":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"token": testAgentJWT(agentSPIFFEID, 1), "token_type": "oidc", "spiffe_id": agentSPIFFEID, "upload_token": "test-upload-bearer",
			})
		case "/oauth/sign-token":
			atomic.AddInt64(&humanExchanges, 1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "human-token", "email": "cole@example.com"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	seedHumanSession(t, srv.URL)
	seedAgent(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("agent path failed: %v", err)
	}
	// Assert the installed token is the one minted for the AGENT principal, not a
	// literal fixture string. The token is a JWT now, and the property under test
	// is that what reaches Fulcio names the agent — pinning a spelling would test
	// the fixture instead.
	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != testAgentJWT(agentSPIFFEID, 1) {
		t.Fatalf("signer-fulcio-token = %q, want the AGENT token for %s", got, agentSPIFFEID)
	}
	if n := atomic.LoadInt64(&humanExchanges); n != 0 {
		t.Fatalf("the human sign-token exchange ran %d times; the agent credential must win outright", n)
	}
	if got := ro.ResolvedAgentPrincipal(); got != agentSPIFFEID {
		t.Fatalf("ResolvedAgentPrincipal = %q, want %q", got, agentSPIFFEID)
	}
	if got := ro.ResolvedSignerEmail(); got != "" {
		t.Fatalf("the human email leaked into an agent run: %q", got)
	}
	if got := ro.ResolvedTenantName(); got != "" {
		t.Fatalf("the human session's tenant leaked into an agent run: %q", got)
	}
	// Selecting the signer by installing a token is only half the wiring; the
	// signer still needs the platform's own Fulcio URL, which ResolvePlatformDefaults
	// fills in after the identity paths.
	if got := fulcioURL(t, cmd); got != srv.URL+"/fulcio" {
		t.Fatalf("signer-fulcio-url = %q, want the platform's own Fulcio", got)
	}
}

// TestRefusedAgentExchangeFailsClosed is the load-bearing test in this set. A
// refused exchange must end the run with the server's message. Falling back to
// the human session would recreate the borrowed-identity bug the enrolled
// principal exists to remove.
func TestRefusedAgentExchangeFailsClosed(t *testing.T) {
	isolateCredentialStore(t)

	var humanExchanges int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth/sign-token" {
			atomic.AddInt64(&humanExchanges, 1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"token": "human-token", "email": "cole@example.com"})
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("agent credential not accepted"))
	}))
	defer srv.Close()

	seedHumanSession(t, srv.URL)
	seedAgent(t, srv.URL)
	logs := captureLogs(t)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	err := ro.AgentIdentityError()
	if err == nil {
		t.Fatal("a refused agent exchange must fail the run, not fall through")
	}
	if !strings.Contains(err.Error(), "agent credential not accepted") {
		t.Fatalf("the error must carry the server's own message, got %q", err)
	}
	if n := atomic.LoadInt64(&humanExchanges); n != 0 {
		t.Fatalf("the human sign-token exchange ran %d times after an agent refusal; that is the borrowed-identity bug", n)
	}
	if got := cmd.Flags().Lookup("signer-fulcio-token").Value.String(); got != "" {
		t.Fatalf("a refused agent exchange installed a signing token anyway: %q", got)
	}
	if got := ro.ResolvedSignerEmail(); got != "" {
		t.Fatalf("a refused agent exchange resolved the human identity: %q", got)
	}
	// The secret must not appear anywhere the failure is reported.
	if strings.Contains(err.Error(), agentRefreshCredential) {
		t.Fatal("the refresh credential leaked into the error message")
	}
	if strings.Contains(logs.all(), agentRefreshCredential) {
		t.Fatalf("the refresh credential leaked into a log line: %s", logs.all())
	}
}

// TestAgentRunSummaryNamesThePrincipalAndNotTheSecret asserts on captured
// output: the summary names the SPIFFE principal, never the human email that is
// also stored on this machine, and never the bearer.
func TestAgentRunSummaryNamesThePrincipalAndNotTheSecret(t *testing.T) {
	isolateCredentialStore(t)
	srv := agentExchangeServer(t)
	seedHumanSession(t, srv.URL)
	seedAgent(t, srv.URL)
	logs := captureLogs(t)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)
	if err := ro.AgentIdentityError(); err != nil {
		t.Fatalf("agent path failed: %v", err)
	}

	// The summary a run would print for this resolution. AgentPrincipal and
	// SignerEmail are exclusive by construction in cli.buildRunSummary; this
	// pins the rendering of the agent case.
	s := &RunSummary{
		Step:           "build",
		PlatformURL:    srv.URL,
		Signer:         "fulcio",
		AgentPrincipal: ro.ResolvedAgentPrincipal(),
		PrincipalKind:  "agent",
	}
	var human strings.Builder
	s.WriteHuman(&human)
	out := human.String()

	if !strings.Contains(out, agentSPIFFEID) {
		t.Fatalf("the summary must name the SPIFFE principal that signed:\n%s", out)
	}
	if !strings.Contains(out, "enrolled agent") {
		t.Fatalf("the summary must say plainly that an agent signed:\n%s", out)
	}
	if strings.Contains(out, "cole@example.com") {
		t.Fatalf("the summary named the human account for an agent signature:\n%s", out)
	}
	jsonOut, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"human summary": out, "json summary": string(jsonOut), "logs": logs.all()} {
		if strings.Contains(text, agentRefreshCredential) {
			t.Fatalf("the refresh credential leaked into the %s: %s", name, text)
		}
	}
}

// An explicit --signer-fulcio-url pointing somewhere other than the platform's
// own Fulcio is refused rather than quietly degraded: the agent token is only
// valid at the issuing platform, and a silent no-op would leave the operator
// signing by some other route while believing the agent signed.
func TestAgentCredentialRefusesAForeignFulcioURL(t *testing.T) {
	isolateCredentialStore(t)
	srv := agentExchangeServer(t)
	seedAgent(t, srv.URL)

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{
		"--platform-url", srv.URL,
		"--signer-fulcio-url", "https://fulcio.elsewhere.example.com",
	}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	err := ro.AgentIdentityError()
	if err == nil {
		t.Fatal("an agent token aimed at a third-party Fulcio must be refused")
	}
	if !strings.Contains(err.Error(), "fulcio.elsewhere.example.com") {
		t.Fatalf("the error must name the origin it refused, got %q", err)
	}
}

// An unreadable agent store is a hard stop, not a fall-through to the human
// session: it is precisely the case where continuing signs as the wrong
// principal while the operator believes an agent is configured.
func TestUnreadableAgentStoreFailsClosed(t *testing.T) {
	isolateCredentialStore(t)
	srv := agentExchangeServer(t)
	seedHumanSession(t, srv.URL)

	path, err := auth.AgentStorePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeCorruptAgentStore(path); err != nil {
		t.Fatal(err)
	}

	cmd, ro := newRunCmd(t)
	if err := cmd.ParseFlags([]string{"--platform-url", srv.URL}); err != nil {
		t.Fatal(err)
	}
	ro.ResolvePlatformDefaults(cmd)

	if ro.AgentIdentityError() == nil {
		t.Fatal("an unreadable agent store must fail the run")
	}
	if got := ro.ResolvedSignerEmail(); got != "" {
		t.Fatalf("an unreadable agent store fell through to the human session: %q", got)
	}
}

// writeCorruptAgentStore lands unparseable bytes where the agent store lives.
func writeCorruptAgentStore(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("not json"), 0o600)
}

// testAgentJWT builds an unsigned JWT whose `sub` is the given principal.
//
// The exchange checks the subject, never the signature — Fulcio verifies that —
// so an unsigned token is the correct fixture. n varies the header so
// successive exchanges return distinct tokens.
func testAgentJWT(subject string, n int64) string {
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"none","kid":"` + strconv.FormatInt(n, 10) + `"}`))
	payload := enc([]byte(`{"sub":"` + subject + `"}`))
	return header + "." + payload + "." + enc([]byte("sig"))
}
