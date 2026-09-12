// jade:ring local
// Copyright 2024 The Witness Contributors
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

package git

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/require"
)

// This file is the MODULE SWEEP for testifysec/judge#8950: no field this
// attestor persists may carry a credential out of the working copy.
//
// The attestation is signed and uploaded to a store, so every string in it
// outlives the build and is readable by anything that can read the envelope. A
// CI checkout's remote routinely carries a live token — GitHub Actions writes
// https://x-access-token:ghs_TOKEN@github.com/owner/repo — so the remote list
// is where a secret escapes if anything on that path can be talked into
// recording the raw string.
//
// The sweep is deliberately NOT "assert Remotes[0] equals X". It marshals the
// whole attestation and walks EVERY string in it, so a future field that
// happens to hold a URL is covered on the day it is added rather than on the
// day somebody remembers to extend a list.

// schemeAuthorityUserinfo returns the userinfo of a scheme'd URL, or "".
//
// Written here, in the test, rather than imported from the redactor it checks:
// a test that asks the production code whether the production code worked
// cannot see the production code stop working.
var schemeAuthorityUserinfo = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.\-]*://([^/?#]*)`)

// carriesSchemeUserinfo reports whether a scheme'd URL puts anything before an
// '@' in its authority — the literal "@ before the host" #8950 names.
func carriesSchemeUserinfo(v string) bool {
	m := schemeAuthorityUserinfo.FindStringSubmatch(v)
	return m != nil && strings.Contains(m[1], "@")
}

// A "does the recorded host look like a DNS name" check used to live here,
// mirroring a production regexp that required a DOT. Round 2 of the #9177
// review retired that rule, and the reason is worth keeping written down: a
// dotted USERNAME and a dotted HOST are the same characters, so the test passed
// "alice.smith:TOKEN@github.com:acme/api.git" with a live credential intact
// while failing "git@myserver:repo.git", an ordinary internal remote carrying
// nothing. It was wrong in both directions at once, which is not a tradeoff.
//
// recordedRemoteCarriesUserinfo in git_remote_grammar_sweep_test.go replaces
// it, and asks a question about the RECORDED string rather than about the
// spelling of one of its components.

// attestationStrings walks the MARSHALLED attestation and returns every string
// in it, at any depth. Marshalling is the point: it is exactly the set of
// values that reaches the signed envelope, so a field excluded from JSON is
// correctly out of scope and a field added to JSON is automatically in it.
func attestationStrings(t *testing.T, a *Attestor) []string {
	t.Helper()
	raw, err := json.Marshal(a)
	require.NoError(t, err, "the attestation must marshal; the sweep reads what gets signed")

	var tree any
	require.NoError(t, json.Unmarshal(raw, &tree))

	out := []string{}
	var walk func(any)
	walk = func(node any) {
		switch v := node.(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, e := range v {
				walk(e)
			}
		case map[string]any:
			for k, e := range v {
				// Keys travel in the envelope too, and a remote can end up as
				// one (Status is keyed by path).
				out = append(out, k)
				walk(e)
			}
		}
	}
	walk(tree)
	return out
}

// runWithRemote builds a one-commit repository whose origin is remoteURL and
// returns the attestor that observed it.
func runWithRemote(t *testing.T, remoteURL string) *Attestor {
	t.Helper()
	_, dir, cleanup := createTestRepo(t, true)
	t.Cleanup(cleanup)

	repo, err := git.PlainOpen(dir)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{remoteURL}})
	require.NoError(t, err, "go-git must accept the spelling under test; a rejected fixture tests nothing")

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return attestor
}

// TestNoAttestedFieldCarriesARemoteCredential is the sweep. Each case plants a
// KNOWN secret in the remote and then asserts the secret appears nowhere in the
// signed attestation — the strongest form available, because it cannot be
// satisfied by a redactor that merely reshapes the string.
func TestNoAttestedFieldCarriesARemoteCredential(t *testing.T) {
	const secret = "ghs_s3cr3tTOKENvalue"

	cases := []struct {
		name   string
		remote string
		// dropped says the remote names no repository once the credential is
		// gone, so nothing at all may be recorded. Without this the refusal
		// branches are unpinned: returning "https:///acme/api.git" carries no
		// secret either, so the sweep alone cannot tell a refusal from a
		// redaction that produced a value naming nothing.
		dropped bool
	}{
		{
			// The GitHub Actions default checkout, verbatim. url.Parse
			// SUCCEEDS here, and the success path already strips it — this is
			// the control that says the mechanism under test is the one that
			// was already right.
			name:   "actions checkout token, parseable",
			remote: "https://x-access-token:" + secret + "@github.com/acme/api.git",
		},
		{
			// A PAT as the WHOLE username, no password at all. The most common
			// mirror spelling, and the one a password-only redactor misses.
			name:   "a token as the entire username",
			remote: "https://" + secret + "@github.com/acme/api.git",
		},
		{
			// url.Parse FAILS: "%zz" is not a valid escape. This is #8950's
			// actual defect — the branch that could not look appended the raw
			// string, so an UNPARSEABLE credential leaked while a parseable one
			// did not.
			name:   "a credential the URL parser cannot reach past",
			remote: "https://x-access-token:" + secret + "@github.com/acme/api%zz.git",
		},
		{
			// url.Parse FAILS: a control character. Same branch, different
			// reason to fail.
			name:   "a credential behind a control character",
			remote: "https://x-access-token:" + secret + "@github.com/acme/api.git\x7f",
		},
		{
			// TWO at-signs in the authority. Cutting at the FIRST one leaves
			// the rest of the credential behind, which is why the redactor cuts
			// at the last.
			name:   "a credential containing an at-sign",
			remote: "https://user:p@" + secret + "@github.com/acme/api%zz.git",
		},
		{
			// url.Parse SUCCEEDS here and does nothing: "alice" is a valid
			// scheme, so this parses as an OPAQUE URL whose User is already
			// nil. Clearing User is then a no-op and String() returns the
			// credential verbatim — a success that proves nothing.
			name:    "a credential the parser accepts as an opaque scheme",
			remote:  "alice:" + secret + "@github.com/acme/api.git",
			dropped: true,
		},
		{
			// url.Parse FAILS: "first path segment in URL cannot contain
			// colon". scp syntax has no password field, so this is an https
			// userinfo pasted without its scheme — and GIT would read the host
			// as "alice", never "github.com". An earlier pass "redacted" it to
			// github.com/acme/api.git, which invented a host git would never
			// use: fabricated identity in signed evidence. The two readings
			// disagree about whether TOKEN is secret, so nothing is recorded.
			name:    "a password pasted into an scp-like remote",
			remote:  "alice:" + secret + "@github.com:acme/api.git",
			dropped: true,
		},
		{
			// The DOTTED-USERNAME variant of the case above (#9177 round 2). It
			// is here end-to-end, not because a fixture closes the class — the
			// grammar sweep does that — but because this exact string was
			// recorded VERBATIM by the previous head, and a regression this
			// specific deserves to fail at the attestor boundary and not only
			// at the function's.
			name:    "a dotted username that is not a host",
			remote:  "alice.smith:" + secret + "@github.com:acme/api.git",
			dropped: true,
		},
		{
			// ONE SLASH after the scheme (#9177 round 2). url.Parse reads this
			// as a hierarchical URL with a scheme and no authority, so clearing
			// User was a no-op and String() handed the token straight back; git
			// reads it as scp syntax whose host is "https". Neither reading
			// finds an authority holding the token.
			name:    "a scheme with one slash instead of two",
			remote:  "https:/alice:" + secret + "@github.com/acme/api.git",
			dropped: true,
		},
		{
			// The other half of the URL. The owner/path check never reads a
			// query, so a token parked there rode along untouched.
			name:   "a token in the query string",
			remote: "https://github.com/acme/api.git?token=" + secret,
		},
		{
			name:   "a token in the fragment",
			remote: "https://github.com/acme/api.git#" + secret,
		},
		{
			// Same, on the branch url.Parse refuses.
			name:   "a token in the query of an unparseable URL",
			remote: "https://github.com/acme/api%zz.git?token=" + secret,
		},
		{
			// The slash-before-colon rule with a HOST-SHAPED name after the '@',
			// which is the only arrangement where that rule changes the answer:
			// "example.com" would pass the host check, so without git's rule the
			// whole string — secret included — would be recorded as a valid scp
			// remote. git reads this as a relative path, and so must we.
			name:    "a path that only looks like scp once you ignore the slash",
			remote:  "a/b@example.com:" + secret + ".git",
			dropped: true,
		},
		{
			// A SLASH BEFORE THE COLON. git reads scp syntax only when the colon
			// comes first; with a slash in front, this is a path, not [user@]host.
			// The authority reader would otherwise find a real-looking host after
			// the last '@' and record the whole string as though it had parsed —
			// classifying as scp something git never would.
			name:    "a slash before the colon, which is not scp syntax",
			remote:  "acme/alice:" + secret + "@github.com:repo.git",
			dropped: true,
		},
		{
			// A LEADING SPACE. url.Parse refuses it and the space is not a
			// legal scheme character, so it reaches the scheme-less reader —
			// where the credential's '@' sits AFTER the first '/', past
			// anything a naive "cut at the last @ before the slash" looks at.
			// The authority here is " https", which is not a host, and a
			// string whose authority cannot be identified cannot be redacted:
			// nothing is recorded.
			name:    "a credential behind a leading space",
			remote:  " https://alice:" + secret + "@github.com/acme/api.git",
			dropped: true,
		},
		{
			// Userinfo and nothing else. There is no host left to name the
			// repository once the credential goes, so there is nothing worth
			// recording — this is the case where dropping IS the answer.
			name:    "an authority that is only a credential",
			remote:  "https://alice:" + secret + "%zz@/acme/api.git",
			dropped: true,
		},
		{
			name:    "an scp-like remote that is only a credential",
			remote:  "alice:" + secret + "@",
			dropped: true,
		},
		{
			// git's REMOTE HELPER form, `transport::address` (#9188). The
			// classifier could not reach it — the URL branch needs a literal
			// "://" and this carries "::" with no slashes — so it fell through
			// to scp, where "ext" read as a host and `--token SECRET` was
			// ordinary path text. This exact string was measured returning
			// UNCHANGED with ok=true from the previous head, so like the dotted
			// username above it belongs at the attestor boundary and not only
			// at the function's. The grammar sweep closes the class.
			name:    "a token on a remote helper's command line",
			remote:  "ext::helper --token " + secret,
			dropped: true,
		},
		{
			// The same form with the secret in an address that is itself a URL.
			// This one was already refused before #9188, but for a reason that
			// does not generalise: an '@' happened to sit downstream of a colon.
			// It is kept as the near-miss beside the case above.
			name:    "a remote helper invoking a transport with a credential",
			remote:  "ext::git-remote-https https://u:" + secret + "@github.com/acme/api.git",
			dropped: true,
		},
		{
			// THE SCHEME-RELATIVE AUTHORITY, username-only (Codex 2026-09-12).
			// RFC 3986 §4.2 calls "//host/path" a network-path reference and
			// every URL reader finds an authority in it; git's connect.c finds
			// a local path. classifyRemote agreed with git and then handed the
			// string to a path rule that looks for ':' or '[' — and a PAT
			// pasted as the WHOLE username carries neither. Measured on the
			// previous head of this branch, recordRemote returned this string
			// VERBATIM with verdict=clean, i.e. the token went into signed
			// evidence. It is here at the attestor boundary, and not only at
			// the function's, because "reaches signed evidence" is the claim.
			name:    "a scheme-relative authority whose username is the token",
			remote:  "//" + secret + "@github.com/acme/api.git",
			dropped: true,
		},
		{
			// The password-bearing sibling. This one was ALREADY refused before
			// the fix, and for a reason that does not generalise — the colon
			// happened to trip the path rule — so it is kept as the near-miss
			// that shows why the colon could not be the test.
			name:    "a scheme-relative authority with a password",
			remote:  "//x-access-token:" + secret + "@github.com/acme/api.git",
			dropped: true,
		},
		{
			// PERCENT-ENCODED DELIMITERS in a scheme-relative authority: there
			// is no literal '@' in this string at all, so an at-sign test never
			// fires. "%40" is the at-sign the userinfo cut cannot find.
			name:    "a scheme-relative authority whose delimiters are encoded",
			remote:  "//alice%3A" + secret + "%40github.com/acme/api.git",
			dropped: true,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			attestor := runWithRemote(t, tt.remote)

			if tt.dropped {
				require.Empty(t, attestor.Remotes,
					"nothing but a credential is left, so nothing may be recorded")
			} else {
				require.NotEmpty(t, attestor.Remotes,
					"the redacted remote must still identify the repository it came from")
			}

			// The two SHAPE assertions run BEFORE the value assertion, and that
			// ordering is load-bearing. require stops the subtest at the first
			// failure, so with the value check first these two never ran on a
			// failing case — decoration rather than coverage. Ordered this way,
			// a redactor that leaves userinfo behind fails on the shape even
			// when the leftover happens not to contain the planted secret.
			// Every RECORDED remote must present an authority this could
			// identify — the invariant the boundary establishes. Scoped to
			// Remotes because the shape test is crude enough to match prose.
			for _, remote := range attestor.Remotes {
				require.False(t, recordedRemoteCarriesUserinfo(remote),
					"a remote was recorded with userinfo still in front of its host: %q", remote)
			}

			for _, v := range attestationStrings(t, attestor) {
				require.False(t, carriesSchemeUserinfo(v),
					"a signed field carries userinfo before its host: %q", v)
				require.NotContains(t, v, secret,
					"a signed field carried the credential out of the working copy: %q", v)
			}
		})
	}
}

// TestCredentialFreeRemotesSurviveRedaction is the CONTROL for the sweep
// above. Dropping every remote, or mangling the ones that clone, would satisfy
// every case there — and would take the attestation's whole discovery surface
// with it, since judge links a DSSE to a product by these strings.
func TestCredentialFreeRemotesSurviveRedaction(t *testing.T) {
	cases := []struct {
		name   string
		remote string
		want   string
	}{
		{
			name:   "an ordinary https clone URL is recorded as typed",
			remote: "https://github.com/acme/api.git",
			want:   "https://github.com/acme/api.git",
		},
		{
			// url.Parse fails on this, and the login is load-bearing: ssh
			// routes on it and gitlab/github both require git@. It must
			// survive whatever the parse failure triggers.
			name:   "an scp-like ssh remote keeps its login",
			remote: "git@github.com:acme/api.git",
			want:   "git@github.com:acme/api.git",
		},
		{
			// The spelling git_test.go's TestRemotesParsing already pins.
			name:   "an scp-like ssh remote with an absolute path",
			remote: "user@github.com:/example/repo.git",
			want:   "user@github.com:/example/repo.git",
		},
		{
			// A PLAIN LOCAL PATH. `git remote add origin /srv/git/repo.git` is a
			// real remote and must survive untouched; it has no colon, so it can
			// be neither scp syntax nor an authority in disguise.
			name:   "a local filesystem path",
			remote: "/srv/git/repo.git",
			want:   "/srv/git/repo.git",
		},
		{
			// An '@' in a plain path is part of the NAME, not userinfo — there is
			// no colon, so there is no authority for it to belong to.
			name:   "a local path containing an at-sign",
			remote: "/srv/git/a@b.git",
			want:   "/srv/git/a@b.git",
		},
		{
			// TWO at-signs in the AUTHORITY. git resolves [user@]host at the LAST
			// '@' before the colon, so the host is example.com and the remote is
			// kept. Reading the first '@' would make the host "host@example.com",
			// which is not a hostname, and the remote would be dropped — evidence
			// lost to a rule git does not use.
			name:   "an scp-like remote with two at-signs in its authority",
			remote: "user@host@example.com:repo.git",
			want:   "user@host@example.com:repo.git",
		},
		{
			// An '@' INSIDE THE REPOSITORY PATH. The authority ends at the
			// first colon, so this '@' is part of the path and is not a
			// credential delimiter. Reading the LAST '@' instead cut here and
			// produced "release.git" — the host and the repository identity
			// destroyed inside something we then signed.
			name:   "an scp-like remote whose path contains an at-sign",
			remote: "git@example.com:repo@release.git",
			want:   "git@example.com:repo@release.git",
		},
		{
			// The same, with a path separator as well, so the boundary is
			// exercised with both a colon and a slash in play.
			name:   "an scp-like remote with an at-sign deeper in the path",
			remote: "git@example.com:team/repo@release.git",
			want:   "git@example.com:team/repo@release.git",
		},
		{
			name:   "an ssh:// URL keeps its host and path",
			remote: "ssh://git@github.com/acme/api.git",
			want:   "ssh://github.com/acme/api.git",
		},
		{
			// A BRACKETED IPv6 LITERAL (#9177 round 2). The path delimiter is
			// the colon OUTSIDE the brackets; taking the first colon made the
			// host "[2001" and the whole remote vanished from the attestation.
			name:   "an scp-like remote on a bracketed IPv6 host",
			remote: "git@[2001:db8::1]:acme/api.git",
			want:   "git@[2001:db8::1]:acme/api.git",
		},
		{
			// A SINGLE-LABEL HOST. `git@myserver:repo.git` is what an internal
			// remote looks like, and the retired dot rule dropped every one of
			// them — a fail-CLOSED loss of the discovery edge that no review
			// finding named, because dropped evidence is silent.
			name:   "an scp-like remote on a single-label host",
			remote: "git@myserver:repo.git",
			want:   "git@myserver:repo.git",
		},
		{
			// A SCHEME-RELATIVE PATH WITH NO CREDENTIAL. This is the control
			// for the scheme-relative refusal: `//fileserver/share/repo.git` is
			// a UNC path on Windows and an ordinary path elsewhere, and
			// refusing every string beginning with "//" would satisfy the
			// credential sweep while taking a real discovery edge with it.
			name:   "a scheme-relative path with no userinfo",
			remote: "//fileserver/share/repo.git",
			want:   "//fileserver/share/repo.git",
		},
		{
			// An '@' AFTER the would-be authority belongs to the repository
			// NAME under both readings, so the refusal must not reach it. A
			// blanket "'//' together with an at-sign" rule would lose this one.
			name:   "a scheme-relative path whose repository name has an at-sign",
			remote: "//fileserver/share/repo@release.git",
			want:   "//fileserver/share/repo@release.git",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			attestor := runWithRemote(t, tt.remote)
			require.Equal(t, []string{tt.want}, attestor.Remotes,
				"a credential-free remote must still identify the repository it came from")
		})
	}
}
