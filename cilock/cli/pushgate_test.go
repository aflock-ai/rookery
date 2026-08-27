// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const statusTestCommit = "0123456789abcdef0123456789abcdef01234567"

func TestParsePushgateRemoteRequiresDiscoveredOrigin(t *testing.T) {
	endpoint, user, password, err := parsePushgateRemote(
		"https://pushgate:secret@edge.example/gh/acme/api.git",
		"https://edge.example",
	)
	require.NoError(t, err)
	require.Equal(t, "https://edge.example/gh/acme/api.git/delivery-status", endpoint)
	require.Equal(t, "pushgate", user)
	require.Equal(t, "secret", password)
	require.NotContains(t, endpoint, "secret")

	_, _, _, err = parsePushgateRemote(
		"https://pushgate:secret@attacker.example/gh/acme/api.git",
		"https://edge.example",
	)
	require.ErrorContains(t, err, "does not match")

	_, _, _, err = parsePushgateRemote(
		"https://pushgate:secret@edge.example/gh/acme/api.git",
		"https://edge.example/path",
	)
	require.ErrorContains(t, err, "invalid Pushgate origin")
}

func TestPushgateStatusInfersCurrentPushAndAuthenticatesToExactRemote(t *testing.T) {
	originalGit := runPushgateGit
	originalDiscover := discoverPushgateOrigin
	originalClient := pushgateStatusHTTPClient
	t.Cleanup(func() {
		runPushgateGit = originalGit
		discoverPushgateOrigin = originalDiscover
		pushgateStatusHTTPClient = originalClient
	})

	var gotAuth, gotRef, gotCommit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/gh/acme/api.git/delivery-status", r.URL.Path)
		user, pass, ok := r.BasicAuth()
		require.True(t, ok)
		gotAuth = user + ":" + pass
		gotRef, gotCommit = r.URL.Query().Get("ref"), r.URL.Query().Get("commit")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "v1", "push_id": "push-1", "ref": gotRef, "commit": gotCommit,
			"verdict": "accepted", "state": "delivered", "terminal": true,
			"attempts": 1, "delivered_at": "2026-08-26T12:00:05Z",
		})
	}))
	defer srv.Close()
	base, err := url.Parse(srv.URL)
	require.NoError(t, err)
	discoverPushgateOrigin = func(string) (string, error) { return srv.URL, nil }
	pushgateStatusHTTPClient = srv.Client()
	pushgateStatusHTTPClient.CheckRedirect = originalClient.CheckRedirect
	runPushgateGit = func(_ context.Context, args ...string) (string, error) {
		switch strings.Join(args, " ") {
		case "symbolic-ref --quiet HEAD":
			return "refs/heads/feature", nil
		case "rev-parse HEAD^{commit}":
			return statusTestCommit, nil
		case "remote get-url --push pushgate":
			u := *base
			u.User = url.UserPassword("pushgate", "repository-secret")
			u.Path = "/gh/acme/api.git"
			return u.String(), nil
		default:
			return "", fmt.Errorf("not configured")
		}
	}

	cmd := pushgateStatusCmd()
	cmd.SetArgs([]string{"--remote", "pushgate", "--json"})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	require.NoError(t, cmd.Execute())
	require.Equal(t, "pushgate:repository-secret", gotAuth)
	require.Equal(t, "refs/heads/feature", gotRef)
	require.Equal(t, statusTestCommit, gotCommit)
	require.NotContains(t, stdout.String(), "repository-secret")
	var status pushgateDeliveryStatus
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &status))
	require.Equal(t, "delivered", status.State)
}

func TestPushgateStatusWaitsThroughQueuedDelivery(t *testing.T) {
	originalGit := runPushgateGit
	originalDiscover := discoverPushgateOrigin
	originalClient := pushgateStatusHTTPClient
	t.Cleanup(func() {
		runPushgateGit = originalGit
		discoverPushgateOrigin = originalDiscover
		pushgateStatusHTTPClient = originalClient
	})
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state, terminal := "queued", false
		if calls.Add(1) > 1 {
			state, terminal = "delivered", true
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "v1", "ref": "refs/heads/main", "commit": statusTestCommit,
			"verdict": "accepted", "state": state, "terminal": terminal,
		})
	}))
	defer srv.Close()
	base, err := url.Parse(srv.URL)
	require.NoError(t, err)
	discoverPushgateOrigin = func(string) (string, error) { return srv.URL, nil }
	runPushgateGit = func(_ context.Context, args ...string) (string, error) {
		if strings.Join(args, " ") != "remote get-url --push pushgate" {
			return "", fmt.Errorf("unexpected git call")
		}
		u := *base
		u.User = url.UserPassword("pushgate", "secret")
		u.Path = "/gh/acme/api.git"
		return u.String(), nil
	}
	pushgateStatusHTTPClient = srv.Client()
	pushgateStatusHTTPClient.CheckRedirect = originalClient.CheckRedirect
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	require.NoError(t, runPushgateStatus(cmd, &pushgateStatusOptions{
		remote: "pushgate", ref: "refs/heads/main", commit: statusTestCommit,
		wait: true, timeout: time.Second, pollInterval: time.Millisecond, json: true,
	}))
	require.Equal(t, int32(2), calls.Load())
	var status pushgateDeliveryStatus
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &status))
	require.Equal(t, "delivered", status.State)
}

func TestPushgateStatusJSONTerminalFailureIsOneDocument(t *testing.T) {
	originalGit := runPushgateGit
	originalDiscover := discoverPushgateOrigin
	originalClient := pushgateStatusHTTPClient
	t.Cleanup(func() {
		runPushgateGit = originalGit
		discoverPushgateOrigin = originalDiscover
		pushgateStatusHTTPClient = originalClient
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "v1", "push_id": "push-refused", "ref": "refs/heads/main", "commit": statusTestCommit,
			"verdict": "refused", "state": "refused", "terminal": true,
			"detail": "tests did not pass",
		})
	}))
	defer srv.Close()
	base, err := url.Parse(srv.URL)
	require.NoError(t, err)
	discoverPushgateOrigin = func(string) (string, error) { return srv.URL, nil }
	runPushgateGit = func(_ context.Context, args ...string) (string, error) {
		if strings.Join(args, " ") != "remote get-url --push pushgate" {
			return "", fmt.Errorf("unexpected git call")
		}
		u := *base
		u.User = url.UserPassword("pushgate", "secret")
		u.Path = "/gh/acme/api.git"
		return u.String(), nil
	}
	pushgateStatusHTTPClient = srv.Client()
	pushgateStatusHTTPClient.CheckRedirect = originalClient.CheckRedirect

	cmd := pushgateStatusCmd()
	cmd.SetArgs([]string{
		"--remote", "pushgate", "--ref", "refs/heads/main", "--commit", statusTestCommit,
		"--wait", "--timeout", "1s", "--poll-interval", "1ms", "--json",
	})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	require.ErrorContains(t, cmd.Execute(), "state refused")

	decoder := json.NewDecoder(&stdout)
	var status pushgateDeliveryStatus
	require.NoError(t, decoder.Decode(&status))
	require.Equal(t, "refused", status.State)
	var extra any
	require.ErrorIs(t, decoder.Decode(&extra), io.EOF, "JSON mode must emit exactly one document")
}

func TestValidStatusTextCountsUTF8Bytes(t *testing.T) {
	within := strings.Repeat("é", 150)
	over := strings.Repeat("é", 151)
	require.True(t, validStatusText(&within, 300))
	require.False(t, validStatusText(&over, 300))
}

func TestFetchPushgateStatusRejectsAuthorityConfusion(t *testing.T) {
	originalClient := pushgateStatusHTTPClient
	t.Cleanup(func() { pushgateStatusHTTPClient = originalClient })
	for name, body := range map[string]string{
		"wrong commit":     `{"version":"v1","ref":"refs/heads/main","commit":"ffffffffffffffffffffffffffffffffffffffff","state":"delivered","terminal":true}`,
		"unknown field":    `{"version":"v1","ref":"refs/heads/main","commit":"` + statusTestCommit + `","state":"delivered","terminal":true,"authority":"caller"}`,
		"two documents":    `{"version":"v1","ref":"refs/heads/main","commit":"` + statusTestCommit + `","state":"delivered","terminal":true}{}`,
		"verdict mismatch": `{"version":"v1","ref":"refs/heads/main","commit":"` + statusTestCommit + `","verdict":"refused","state":"delivered","terminal":true}`,
		"terminal escape":  `{"version":"v1","ref":"refs/heads/main","commit":"` + statusTestCommit + `","verdict":"accepted","state":"failed","terminal":true,"detail":"bad\u001b[31m"}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			pushgateStatusHTTPClient = srv.Client()
			pushgateStatusHTTPClient.CheckRedirect = originalClient.CheckRedirect
			_, err := fetchPushgateStatus(context.Background(), srv.URL, "pushgate", "secret", "refs/heads/main", statusTestCommit)
			require.Error(t, err)
		})
	}
}

func TestPushgateStatusClientNeverFollowsRedirects(t *testing.T) {
	originalClient := pushgateStatusHTTPClient
	t.Cleanup(func() { pushgateStatusHTTPClient = originalClient })
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer source.Close()
	pushgateStatusHTTPClient = source.Client()
	pushgateStatusHTTPClient.CheckRedirect = originalClient.CheckRedirect
	_, err := fetchPushgateStatus(context.Background(), source.URL, "pushgate", "secret", "refs/heads/main", statusTestCommit)
	require.ErrorContains(t, err, "HTTP 302")
	require.Zero(t, targetCalls.Load())
}

func TestPushgateCommandIsRegistered(t *testing.T) {
	cmd, _, err := New().Find([]string{"pushgate", "status"})
	require.NoError(t, err)
	require.Equal(t, "status", cmd.Name())
}

func TestPushgateStatusJSONFailureHasStableCode(t *testing.T) {
	cmd := pushgateStatusCmd()
	cmd.SetArgs([]string{"--json", "--timeout", "0s"})
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	require.Error(t, cmd.Execute())
	var body struct {
		Version string `json:"version"`
		Error   struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &body))
	require.Equal(t, "v1", body.Version)
	require.Equal(t, "pushgate_status_failed", body.Error.Code)
}

// TestPushgateStatusDetachedHeadRequiresRef pins the DOCUMENTED default. Ref
// discovery runs `git symbolic-ref HEAD`, which resolves a branch and nothing
// else, so a checked-out tag -- a detached HEAD -- has no branch to find. The
// CLI help and docs/reference/cli.md both state that a tag needs an explicit
// --ref; this is the executable form of that statement, so the promise and the
// behavior cannot drift apart unnoticed. The command must say so plainly
// rather than reporting on some other ref it guessed at.
func TestPushgateStatusDetachedHeadRequiresRef(t *testing.T) {
	originalGit := runPushgateGit
	originalDiscover := discoverPushgateOrigin
	t.Cleanup(func() {
		runPushgateGit = originalGit
		discoverPushgateOrigin = originalDiscover
	})

	// Discovery must never run before the ref is known, so it fails the test
	// loudly instead of being stubbed permissively.
	discoverPushgateOrigin = func(string) (string, error) {
		t.Error("platform discovery must not run before the ref is resolved")
		return "", fmt.Errorf("must not be called")
	}
	// A detached HEAD: symbolic-ref exits non-zero, exactly as it does when a
	// tag is checked out.
	var symbolicRefCalls int
	runPushgateGit = func(_ context.Context, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		if strings.HasPrefix(joined, "symbolic-ref") {
			symbolicRefCalls++
			return "", fmt.Errorf("git metadata is unavailable")
		}
		t.Errorf("unexpected git call: %s", joined)
		return "", fmt.Errorf("unexpected git call")
	}

	cmd := pushgateStatusCmd()
	cmd.SetArgs([]string{"--remote", "pushgate"})
	cmd.SetOut(&bytes.Buffer{})
	err := cmd.Execute()

	require.Error(t, err)
	require.ErrorContains(t, err, "--ref")
	require.Equal(t, 1, symbolicRefCalls, "ref discovery must be attempted exactly once")
}

// TestPushgateRefTableMatchesTheEdge is the CLIENT half of a table duplicated
// verbatim in jade/factory/edge/git/deliverystatus.test.mjs. The two are
// duplicated rather than shared because this subtree is mirrored to a
// standalone public repository and cannot read a path from the Judge tree.
//
// The point of pinning them together: the CLI refuses a ref locally before it
// ever queries, so a client stricter than the edge silently hides deliveries
// that succeeded, and a client looser than the edge sends lookups the edge
// throws away. Either way the operator is told something untrue about a push.
//
// The accepted set is deliberately NARROWER than `git check-ref-format` -- see
// the comment on pushgateRefPunctuation. Cases below marked "git-legal" are
// refs git accepts and this protocol declines on purpose, listed explicitly so
// the narrowing stays a recorded decision rather than an accident.
func TestPushgateRefTableMatchesTheEdge(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		// --- accepted ---------------------------------------------------
		{"refs/heads/main", true},
		{"refs/heads/feature/my-work", true},
		{"refs/heads/a_b-c.d", true},
		{"refs/tags/v1.0.0", true},
		// The regression this table exists for: SemVer build metadata is an
		// ordinary tag shape that git accepts and Pushgate delivers, and the
		// original allowlist made its status unreadable.
		{"refs/tags/v1.2.3+build.5", true},
		{"refs/tags/v1.2.3-rc.1+build.5", true},

		// --- refused: not a fully-qualified branch or tag ----------------
		{"", false},
		{"main", false},
		{"refs/heads/", false},
		{"refs/remotes/origin/main", false},
		{"refs/notes/commits", false},

		// --- refused: git's own structural rules -------------------------
		{"refs/heads/a..b", false},
		{"refs/heads/a/", false},
		{"refs/heads/a//b", false},
		{"refs/heads/.hidden", false},
		{"refs/heads/a/.b", false},
		{"refs/heads/a.lock", false},
		{"refs/heads/a/b.lock", false},
		{"refs/heads/a.", false},
		{"refs/heads/a~b", false},
		{"refs/heads/a^b", false},
		{"refs/heads/a:b", false},
		{"refs/heads/a?b", false},
		{"refs/heads/a*b", false},
		{"refs/heads/a[b", false},
		{"refs/heads/a b", false},

		// --- refused by policy, though git would allow them --------------
		{"refs/heads/a&b", false},
		{"refs/heads/a|b", false},
		{"refs/heads/a<b", false},
		{"refs/heads/a>b", false},
		{"refs/heads/a$b", false},
		{"refs/heads/a'b", false},
		{"refs/heads/a;b", false},
		{"refs/heads/a@b", false},
		{"refs/heads/a%b", false},
		{"refs/heads/a#b", false},
		{"refs/heads/a(b)", false},
		{"refs/heads/ünïcode", false},
		{"refs/heads/-flag", false},
		{"refs/heads/_release", true},

		// --- refused: length ---------------------------------------------
		{"refs/heads/" + strings.Repeat("a", 245), true},
		{"refs/heads/" + strings.Repeat("a", 400), false},
	}
	for _, tc := range cases {
		require.Equal(t, tc.want, validPushgateRef(tc.ref), "validPushgateRef(%q)", tc.ref)
	}
}
