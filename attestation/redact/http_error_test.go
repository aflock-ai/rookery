// jade:ring local
//
// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package redact

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorChain is the text of err and of every error it wraps, to the bottom.
func errorChain(err error) []string {
	if err == nil {
		return nil
	}
	out := []string{err.Error()}
	switch e := err.(type) {
	case interface{ Unwrap() error }:
		out = append(out, errorChain(e.Unwrap())...)
	case interface{ Unwrap() []error }:
		for _, inner := range e.Unwrap() {
			out = append(out, errorChain(inner)...)
		}
	}
	return out
}

// get fetches rawURL with a client that follows redirects, as net/http's
// default one does, and returns its error.
func get(rawURL string) error {
	resp, err := http.Get(rawURL)
	if err == nil {
		_ = resp.Body.Close()
	}
	return err
}

// A redirect puts a URL the caller never configured into net/http's error: a
// Location that does not parse is quoted whole, and one that parses becomes
// the URL the *url.Error names, with its username kept. So a request whose
// own URL holds no credential still carried one into its error.
func TestHTTPErrorWithholdsRedirectDetail(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closedAddr := closed.Listener.Addr().String()
	closed.Close()
	for _, tc := range []struct {
		name, location string
		leaks          []string
	}{
		{"a location that does not parse", "http://ci:p12secret-badport@host:bad/keys", []string{"p12secret-badport", "ci:"}},
		{"a location with a password", "http://ci:p12secret-password@" + closedAddr + "/keys", []string{"p12secret-password", "ci:"}},
		{"a location with a username token", "http://glpat-p12secrettoken@" + closedAddr + "/keys", []string{"glpat-p12secrettoken"}},
		// Go dials 127.0.0.1:1, which Python's proxy parser reads as a user
		// and the start of a password.
		{"a location whose dialed host is another parser's user", "http://127.0.0.1:1/p12secret@host/keys", []string{"tcp 127.0.0.1:1:", "p12secret"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.RedirectHandler(tc.location, http.StatusFound))
			defer server.Close()
			endpoint := server.URL + "/keys"
			getErr := get(endpoint)
			require.Error(t, getErr)
			require.True(t, slices.ContainsFunc(tc.leaks, func(leak string) bool {
				return strings.Contains(strings.Join(errorChain(getErr), "\n"), leak)
			}), "net/http no longer puts the redirect in its error, so this probes nothing: %v", getErr)

			for name, err := range map[string]error{
				"as returned":         HTTPError(endpoint, getErr),
				"wrapped, no url":     HTTPError("", fmt.Errorf("operation error CodeBuild: BatchGetBuilds, %w", getErr)),
				"as returned, no url": HTTPError("", getErr),
			} {
				for _, text := range errorChain(err) {
					for _, leak := range tc.leaks {
						assert.NotContains(t, text, leak, "%s: the error chain carries the redirect's userinfo", name)
					}
				}
			}
			err := HTTPError(endpoint, getErr)
			assert.Contains(t, err.Error(), "withheld")
			assert.NoError(t, HTTPError(endpoint, nil))
			var urlErr *url.Error
			require.ErrorAs(t, err, &urlErr)
			assert.Equal(t, endpoint, urlErr.URL)
		})
	}
}

// errorText is a library error that is not a *url.Error but whose text can
// quote one, as a client library that formats with %v instead of %w does.
type errorText struct{ text string }

func (e errorText) Error() string { return e.text }

// credentialLeaks is every string that names part of the credential
// user:password: the username as written and decoded, every prefix of the
// password of two bytes or more, and every run of four bytes of it.
func credentialLeaks(user, password string) []string {
	leaks := []string{user}
	if decoded, err := url.PathUnescape(user); err == nil {
		leaks = append(leaks, decoded)
	}
	for end := 2; end <= len(password); end++ {
		leaks = append(leaks, password[:end])
	}
	for start := 0; start+4 <= len(password); start++ {
		leaks = append(leaks, password[start:start+4])
	}
	return leaks
}

// url.Parse cuts the fragment off before it parses, and names only what it
// parsed: "http://uxuser:px#pass/part@proxy:3128" fails as
// `parse "http://uxuser:px": invalid port ":px" after host`. That text holds
// no at-sign, so nothing in it reads as a userinfo, yet it is the username and
// the start of the password. When the caller does not know the URL, nothing
// can say what the quoted text was cut from, so neither the URL nor the
// detail may be kept.
func TestHTTPErrorWithholdsUnknownURLParseErrors(t *testing.T) {
	for _, tc := range []struct {
		name, rawURL, user, password string
	}{
		{"a fragment cuts the userinfo", "http://uxuser:px#pass/part@proxy:3128", "uxuser", "px#pass/part"},
		{"a query cuts the userinfo", "http://qyuser:qy?pass/part@proxy:3128", "qyuser", "qy?pass/part"},
		{"a fragment cuts before a query", "http://fquser:fq#pa?ss@proxy:3128", "fquser", "fq#pa?ss"},
		{"a percent-encoded colon in the username", "http://pc%3Auser:pc#pass@proxy:3128", "pc%3Auser", "pc#pass"},
		{"a percent-encoded at-sign in the username", "http://pa%40user:p%3Ax#pass%40x@proxy:3128", "pa%40user", "p%3Ax#pass%40x"},
		{"an IPv6 host after the cut", "http://v6user:v6#pass@[::1]:3128", "v6user", "v6#pass"},
		{"an IPv6 zone host after a path", "http://z6user:z6/pass@[fe80::1%25en0]:3128", "z6user", "z6/pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, parseErr := url.Parse(tc.rawURL)
			require.Error(t, parseErr)
			var parsed *url.Error
			require.ErrorAs(t, parseErr, &parsed)
			require.Equal(t, "parse", parsed.Op)
			leaks := credentialLeaks(tc.user, tc.password)
			require.True(t, slices.ContainsFunc(leaks, func(leak string) bool {
				return strings.Contains(parseErr.Error(), leak)
			}), "url.Parse no longer quotes the userinfo, so this probes nothing: %v", parseErr)

			for name, err := range map[string]error{
				"as returned":              parseErr,
				"inside a *url.Error":      &url.Error{Op: "Get", URL: parsed.URL, Err: parseErr},
				"joined":                   errors.Join(errors.New("proxy setup failed"), parseErr),
				"joined after":             errors.Join(parseErr, errors.New("proxy setup failed")),
				"wrapped with %w":          fmt.Errorf("operation error CodeBuild: BatchGetBuilds, %w", parseErr),
				"wrapped twice":            fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", parseErr)),
				"flattened to text":        errorText{"proxy: " + parseErr.Error()},
				"flattened, wrapped":       fmt.Errorf("fetch: %w", errorText{parseErr.Error()}),
				"text beside a *url.Error": errors.Join(&url.Error{Op: "Get", URL: "https://example.com/x", Err: errors.New("EOF")}, errorText{parseErr.Error()}),
			} {
				got := HTTPError("", err)
				require.Error(t, got, name)
				for _, text := range errorChain(got) {
					for _, leak := range leaks {
						assert.NotContains(t, text, leak, "%s: the error chain carries the credential", name)
					}
				}
				assert.Contains(t, got.Error(), "withheld", name)
			}
			assert.EqualError(t, HTTPError("", parseErr), "request URL could not be parsed (withheld)")
		})
	}
}

// The known-URL path names the redacted URL and withholds the detail; it is
// here so the unknown-URL branch cannot be widened into it by accident.
func TestHTTPErrorKnownURLParseErrorNamesTheRedactedURL(t *testing.T) {
	// A variable, so that staticcheck does not flag a literal it knows fails.
	rawURL := strings.Join([]string{"http://uxuser:px", "#pass/part@proxy:3128"}, "")
	_, parseErr := url.Parse(rawURL)
	require.Error(t, parseErr)
	got := HTTPError(rawURL, parseErr)
	for _, text := range errorChain(got) {
		for _, leak := range credentialLeaks("uxuser", "px#pass/part") {
			assert.NotContains(t, text, leak)
		}
	}
	var urlErr *url.Error
	require.ErrorAs(t, got, &urlErr)
	assert.Equal(t, URLCredentials(rawURL), urlErr.URL)
}

// Fail closed: an error of a type HTTPError does not know, whose text quotes
// a URL, may quote one cut short, so its detail is withheld whatever URL the
// caller knows. That holds for a scheme-less URL url.Parse quoted too.
func TestHTTPErrorWithholdsURLTextOutsideURLError(t *testing.T) {
	for name, err := range map[string]error{
		"a proxy url":               errorText{"dial proxy socks5://skuser:sk"},
		"a quoted parse, no scheme": errorText{`parse "//nsuser:ns": invalid port ":ns" after host`},
		"wrapped":                   fmt.Errorf("fetch: %w", errorText{"bad endpoint https://wkuser:wk"}),
		"inside a *url.Error":       &url.Error{Op: "Get", URL: "https://example.com/keys", Err: errorText{`parse "http://iuuser:iu": invalid port ":iu" after host`}},
	} {
		for _, rawURL := range []string{"", "https://example.com/keys"} {
			got := HTTPError(rawURL, err)
			require.Error(t, got, name)
			for _, leak := range []string{"skuser", ":sk", "nsuser", ":ns", "wkuser", ":wk", "iuuser", ":iu"} {
				for _, text := range errorChain(got) {
					assert.NotContains(t, text, leak, "%s (url %q)", name, rawURL)
				}
			}
			assert.Contains(t, got.Error(), "withheld", "%s (url %q)", name, rawURL)
		}
	}
	// An error that quotes no URL is kept as it is.
	plain := errors.New("connection refused")
	assert.Same(t, plain, HTTPError("", plain))
}
