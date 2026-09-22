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

package environment

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Pushgate onboarding acceptance run (2026-09-21) signed a sandbox proxy
// password into every environment predicate: CLOUDSDK_PROXY_PASSWORD was
// obfuscated because its KEY matched *PASSWORD*, while the same password inside
// http://user:pass@host URLs in HTTP_PROXY, ALL_PROXY and ten siblings went out
// verbatim, because those keys match nothing. The credential is in the VALUE,
// so the key list cannot be the only control. Every capture mode runs below,
// including the ones where the operator switched the key list off or allowed
// the key by name: none of them is a statement that a URL password is public.
func TestAttestRedactsCredentialsInURLShapedValues(t *testing.T) {
	env := []string{
		"HTTP_PROXY=http://u:s3cr3t-proxy-pw@localhost:1234",
		"https_proxy=http://u:s3cr3t-proxy-pw@localhost:1234",
		"ALL_PROXY=socks5h://u:s3cr3t-proxy-pw@localhost:1234",
		// Scheme-less, with a Windows domain user; Python's urllib sends it.
		`HTTPS_PROXY=DOMAIN\user:p1sec-domain-pw@proxy:8080`,
		// The same with a password that starts with a backslash, which must not
		// read as the next entry of a Windows path list.
		`FTP_PROXY=DOMAIN\user:\p1sec-bs-domain-pw@proxy:8080`,
		"FOO_ENDPOINT=https://x:tok1234567890@example.com/path",
		"CI_REPOSITORY_URL=https://gitlab-ci-token:glcbt-job-token-value@gitlab.example.com/g/p.git",
		"PLAIN=https://proxy.golang.org,direct",
		// A path list under a key the name list does not match (PATH itself
		// matches *PAT*), so every mode below reaches the value rule.
		"PKG_CONFIG_LIBDIR=/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/opt/icu4c@76/lib/pkgconfig",
		// Scheme-relative: no "://", and a user that starts with "//", which
		// the path-list reading alone would keep. Python's urllib sends it.
		"PIP_PROXY=//u:p1sec-scheme-relative-pw@proxy:3128",
		// Quoted, as docker --env-file keeps it, with a space in the password,
		// where a URL inside text would end.
		`NPM_CONFIG_HTTPS_PROXY="http://u:p1sec quoted-pw@proxy:3128"`,
	}
	secrets := []string{
		"s3cr3t-proxy-pw", "p1sec-domain-pw", "p1sec-bs-domain-pw", "tok1234567890", "glcbt-job-token-value",
		"p1sec-scheme-relative-pw", "quoted-pw",
	}

	modes := []struct {
		name string
		opts []attestation.AttestationContextOption
	}{
		{"default", nil},
		{"filter mode", []attestation.AttestationContextOption{attestation.WithEnvFilterVarsEnabled()}},
		{"default key list disabled", []attestation.AttestationContextOption{attestation.WithEnvDisableDefaultSensitiveList()}},
		{"keys allowed by name", []attestation.AttestationContextOption{attestation.WithEnvExcludeKeys([]string{"HTTP_PROXY", "FOO_ENDPOINT", "CI_REPOSITORY_URL", "PIP_PROXY", "NPM_CONFIG_HTTPS_PROXY"})}},
		{"capture allowlist", []attestation.AttestationContextOption{attestation.WithEnvCaptureAllowlist([]string{"*PROXY*", "FOO_*", "CI_*", "PLAIN", "PKG_CONFIG_*"})}},
	}
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			attestor := New(WithCustomEnv(func() []string { return env }))
			ctx, err := attestation.NewContext("env-url-credentials", []attestation.Attestor{attestor}, mode.opts...)
			require.NoError(t, err)
			require.NoError(t, attestor.Attest(ctx))
			predicate, err := json.Marshal(attestor)
			require.NoError(t, err)

			for _, secret := range secrets {
				assert.NotContains(t, string(predicate), secret, "signed predicate carries a credential")
			}
			for _, kept := range []string{"localhost:1234", "example.com/path", "gitlab.example.com/g/p.git"} {
				assert.Contains(t, string(predicate), kept, "redaction removed what is not a credential")
			}
			assert.Equal(t, "http://******@localhost:1234", attestor.Variables["HTTP_PROXY"])
			assert.Equal(t, "******@", attestor.Variables["HTTPS_PROXY"])
			assert.Equal(t, "******@", attestor.Variables["FTP_PROXY"])
			assert.Equal(t, "https://******@example.com/path", attestor.Variables["FOO_ENDPOINT"])
			assert.Equal(t, "https://******@gitlab.example.com/g/p.git", attestor.Variables["CI_REPOSITORY_URL"])
			assert.Equal(t, "https://proxy.golang.org,direct", attestor.Variables["PLAIN"])
			assert.Equal(t, "//******@proxy:3128", attestor.Variables["PIP_PROXY"])
			assert.Equal(t, `"http://******@proxy:3128"`, attestor.Variables["NPM_CONFIG_HTTPS_PROXY"])
			assert.Equal(t, "/opt/homebrew/opt/openssl@3/lib/pkgconfig:/opt/homebrew/opt/icu4c@76/lib/pkgconfig",
				attestor.Variables["PKG_CONFIG_LIBDIR"], "a path list is not a URL and carries no credential")
		})
	}
}

// hostReadings returns the host that each reading of s names, "" where that
// reading finds none or fails. Index 0 and 1 are Go's url.Parse of the value
// and of "http://" + value, which is how net/http's ProxyFromEnvironment and
// curl read a proxy value with no scheme. Index 2 and 3 are the same two
// inputs read by authorityHost, the unvalidated RFC 3986 reading that WHATWG,
// Python's urlsplit and Go share. After those come the four readings of each
// whitespace-separated field, because a URL inside text ends at whitespace.
//
// Python's proxy parser is not one of the readings: it takes the host after
// the at-sign of "//evil.example/x@proxy.golang.org", where the others take
// the one before the '/', so a redaction that keeps a host where they
// disagree fails against one of them anyway.
func hostReadings(s string) []string {
	read := func(s string) []string {
		host := ""
		if u, err := url.Parse(s); err == nil {
			host = u.Host
		}
		prefixed := ""
		if u, err := url.Parse("http://" + s); err == nil {
			prefixed = u.Host
		}
		return []string{host, prefixed, authorityHost(s), authorityHost("http://" + s)}
	}
	hosts := read(s)
	for _, field := range strings.Fields(s) {
		hosts = append(hosts, read(field)...)
	}
	return hosts
}

// authorityHost returns the host of the authority that s opens with "//" (a
// network-path reference), or else of its first "://": the authority runs to
// the first '/', '?', '#' or '\' (WHATWG ends a special scheme's authority at
// a backslash), and the host follows its last at-sign. The host is checked
// only for bytes no parser accepts in one (space, control bytes, quotes, '<',
// '>'), so that the text after a URL inside prose is not read as its host.
func authorityHost(s string) string {
	rest, ok := strings.CutPrefix(s, "//")
	if !ok {
		_, rest, ok = strings.Cut(s, "://")
	}
	if !ok {
		return ""
	}
	if end := strings.IndexAny(rest, "/?#\\"); end >= 0 {
		rest = rest[:end]
	}
	if at := strings.LastIndexByte(rest, '@'); at >= 0 {
		rest = rest[at+1:]
	}
	if strings.ContainsFunc(rest, func(r rune) bool { return r <= ' ' || strings.ContainsRune(`"'<>`, r) }) {
		return ""
	}
	return rest
}

// checkNamesNoOtherHost fails when signed, the redacted form of real, names a
// host that real does not. The authority readings must name no host or the
// same one. Go's strict readings may also name the authority host of real,
// because Go refuses some values that WHATWG and Python dial
// ("http://u:my secret@proxy:3128"). A field of the redacted value may name
// any host that some reading of the original names, because redaction may
// change the number of fields.
func checkNamesNoOtherHost(t *testing.T, real, signed string) {
	t.Helper()
	want, got := hostReadings(real), hostReadings(signed)
	for i, host := range got[:4] {
		allowed := []string{"", want[i]}
		if i < 2 {
			allowed = append(allowed, want[i+2])
		}
		if !slices.Contains(allowed, host) {
			t.Errorf("reading %d: %q names host %q, %q names %q", i, signed, host, real, allowed[1:])
		}
	}
	for _, host := range got[4:] {
		if host != "" && !slices.Contains(want, host) {
			t.Errorf("%q names host %q, which no reading of %q names", signed, host, real)
		}
	}
}

// The same property through the public path: New, then Attest, in the default
// and filter capture modes. The three values are the verifier's repro; each
// one dials evil.example, and before this rule each was signed naming the host
// after its last at-sign.
func TestAttestNamesNoForgedHost(t *testing.T) {
	env := []string{
		"GOPROXY=https://evil.example/x@proxy.golang.org",
		"NPM_CONFIG_REGISTRY=https://evil.example/?a=@registry.npmjs.org",
		"PIP_INDEX_URL=https://evil.example#@pypi.org/simple",
		"HTTPS_PROXY=evil.example:8080/x@proxy.golang.org",
	}
	for _, mode := range []struct {
		name string
		opts []attestation.AttestationContextOption
	}{
		{"default", nil},
		{"filter mode", []attestation.AttestationContextOption{attestation.WithEnvFilterVarsEnabled()}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			attestor := New(WithCustomEnv(func() []string { return env }))
			ctx, err := attestation.NewContext("env-forged-host", []attestation.Attestor{attestor}, mode.opts...)
			require.NoError(t, err)
			require.NoError(t, attestor.Attest(ctx))
			predicate, err := json.Marshal(attestor)
			require.NoError(t, err)
			for _, forged := range []string{"proxy.golang.org", "registry.npmjs.org", "pypi.org"} {
				assert.NotContains(t, string(predicate), forged, "signed predicate names a host the value does not dial")
			}
			for _, kv := range env {
				key, value := splitVariable(kv)
				signed, ok := attestor.Variables[key]
				require.True(t, ok, "%s not captured", key)
				checkNamesNoOtherHost(t, value, signed)
			}
		})
	}
}

// A scheme-less proxy value is read by Python's urllib (_parse_proxy) with no
// character rule at all: the userinfo runs to the last at-sign, the password
// from the first colon, spaces and tabs included. HTTP_PROXY=u:my secret@proxy:3128
// sends "my secret" to proxy:3128, so it is a working credential even though Go
// and curl refuse it. Go and curl send the user of a scheme-less "tok@proxy:3128"
// with an empty password, so a token in the username slot is a credential too
// once a port says the value is a proxy; without a port the value is an email
// address, which no reading can tell from one. Every capture mode runs.
func TestAttestRedactsSchemelessUserinfoWithWhitespace(t *testing.T) {
	cases := []struct{ key, value, want string }{
		{"HTTP_PROXY", "u:my secret@proxy:3128", "******@proxy:3128"},
		{"HTTPS_PROXY", "u:my\tsecret@proxy:3128", "******@proxy:3128"},
		{"ALL_PROXY", "u:my   secret@proxy:3128", "******@proxy:3128"},
		// A second at-sign: curl refuses the host Go and Python read, so
		// none is named.
		{"http_proxy", "u:my s@cret@proxy:3128", "******@"},
		{"https_proxy", "u:my:s ecret@proxy:3128", "******@proxy:3128"},
		{"all_proxy", "u:my%20secret@proxy:3128", "******@proxy:3128"},
		{"FTP_PROXY", "my user:my secret@proxy:3128", "******@proxy:3128"},
		{"GRPC_PROXY", `"u:my secret@proxy:3128"`, `"******@proxy:3128"`},
		{"SOCKS_PROXY", "ghp_usertoken@proxy:3128", "******@proxy:3128"},
		{"PLAIN_TEXT", "plain value with spaces", "plain value with spaces"},
		{"MAINTAINER_EMAIL", "alice@example.com", "alice@example.com"},
	}
	env := make([]string, 0, len(cases))
	keys := make([]string, 0, len(cases))
	for _, c := range cases {
		env = append(env, c.key+"="+c.value)
		keys = append(keys, c.key)
	}
	for _, mode := range []struct {
		name string
		opts []attestation.AttestationContextOption
	}{
		{"default", nil},
		{"filter mode", []attestation.AttestationContextOption{attestation.WithEnvFilterVarsEnabled()}},
		{"default key list disabled", []attestation.AttestationContextOption{attestation.WithEnvDisableDefaultSensitiveList()}},
		{"keys allowed by name", []attestation.AttestationContextOption{attestation.WithEnvExcludeKeys(keys)}},
		{"capture allowlist", []attestation.AttestationContextOption{attestation.WithEnvCaptureAllowlist(keys)}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			attestor := New(WithCustomEnv(func() []string { return env }))
			ctx, err := attestation.NewContext("env-schemeless-whitespace", []attestation.Attestor{attestor}, mode.opts...)
			require.NoError(t, err)
			require.NoError(t, attestor.Attest(ctx))
			predicate, err := json.Marshal(attestor)
			require.NoError(t, err)
			for _, secret := range []string{"my secret", "secret", "s@cret", "s ecret", "ghp_usertoken", "my user"} {
				assert.NotContains(t, string(predicate), secret, "signed predicate carries a credential")
			}
			for _, c := range cases {
				assert.Equal(t, c.want, attestor.Variables[c.key], "%s=%q", c.key, c.value)
			}
		})
	}
}

// Python's proxy parser (urllib.request._parse_proxy) ends a URL's authority
// at the first '/' after its FIRST at-sign, not at '?' or '#', and takes the
// userinfo to the last at-sign before that. With no '/' between the userinfo's
// at-sign and a later one, it sends everything up to the later one as the
// password: HTTP_PROXY=http://u:first@proxy-a?tail@proxy-b:3128 sends
// "first@proxy-a?tail" to proxy-b:3128, while Go and curl send "first" to
// proxy-a. The tail is a credential to Python, so it goes, and no host is
// named. A '/' first ends the authority for every one of them, so that value
// keeps its host and path. Every capture mode runs.
func TestAttestRedactsUserinfoTailPythonReadsPastAQuery(t *testing.T) {
	cases := []struct{ key, value, want string }{
		{"HTTP_PROXY", "http://u:first@proxy-a?p1sec-query-tail@proxy-b:3128", "http://******@"},
		{"HTTPS_PROXY", "http://u:first@proxy-a#p1sec-fragment-tail@proxy-b:3128", "http://******@"},
		{"ALL_PROXY", `"http://u:first@proxy-a?p1sec-quoted-tail@proxy-b:3128"`, `"http://******@/"`},
		{"FTP_PROXY", "//u:first@proxy-a?p1sec-relative-tail@proxy-b:3128", "//******@"},
		{"NO_SCHEME_PROXY", "u:first@proxy-a?p1sec-schemeless-tail@proxy-b:3128", "******@"},
		{"SOCKS_PROXY", "http://u:first@proxy-a/tail@proxy-b:3128", "http://******@proxy-a/tail@proxy-b:3128"},
		// An empty userinfo does not end Python's search: it still sends
		// the later userinfo's password to proxy-b.
		{"EMPTY_USER_PROXY", "http://@proxy-a?u:p1sec-after-empty@proxy-b:3128", "http://******@"},
		{"EMPTY_USER_FRAGMENT_PROXY", "http://@proxy-a#u:p1sec-after-empty-fragment@proxy-b:3128", "http://******@"},
		{"EMPTY_USER_SLASH_PROXY", "http://@proxy-a/tail@proxy-b:3128", "http://@proxy-a/tail@proxy-b:3128"},
	}
	env := make([]string, 0, len(cases))
	keys := make([]string, 0, len(cases))
	for _, c := range cases {
		env = append(env, c.key+"="+c.value)
		keys = append(keys, c.key)
	}
	for _, mode := range []struct {
		name string
		opts []attestation.AttestationContextOption
	}{
		{"default", nil},
		{"filter mode", []attestation.AttestationContextOption{attestation.WithEnvFilterVarsEnabled()}},
		{"default key list disabled", []attestation.AttestationContextOption{attestation.WithEnvDisableDefaultSensitiveList()}},
		{"keys allowed by name", []attestation.AttestationContextOption{attestation.WithEnvExcludeKeys(keys)}},
		{"capture allowlist", []attestation.AttestationContextOption{attestation.WithEnvCaptureAllowlist(keys)}},
	} {
		t.Run(mode.name, func(t *testing.T) {
			attestor := New(WithCustomEnv(func() []string { return env }))
			ctx, err := attestation.NewContext("env-userinfo-query-tail", []attestation.Attestor{attestor}, mode.opts...)
			require.NoError(t, err)
			require.NoError(t, attestor.Attest(ctx))
			predicate, err := json.Marshal(attestor)
			require.NoError(t, err)
			for _, secret := range []string{"first", "p1sec"} {
				assert.NotContains(t, string(predicate), secret, "signed predicate carries a credential")
			}
			for _, c := range cases {
				assert.Equal(t, c.want, attestor.Variables[c.key], "%s=%q", c.key, c.value)
				checkNamesNoOtherHost(t, c.value, attestor.Variables[c.key])
			}
		})
	}
}
