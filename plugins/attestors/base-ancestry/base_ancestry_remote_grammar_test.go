// jade:ring local
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

package baseancestry

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// THE GRAMMAR SWEEP — testifysec/judge#9181.
//
// This attestor's remote sanitiser has now been through two rounds of the same
// defect. Round one: an unparseable URL was appended RAW, so the input we
// understood least was the one we published unchanged. Round two (#9181): three
// measured failures at once — `https:/alice:TOKEN@github.com/acme/api.git` (ONE
// slash) returned UNCHANGED with the token intact, while
// `git@[2001:db8::1]:acme/api.git` and `git@example.com:repo@release.git` were
// both DROPPED, valid remotes silently missing from signed evidence.
//
// Every one of those is the same mistake: a local LEXICAL test standing in for
// a STRUCTURAL boundary, because url.Parse was being asked a question about
// git's grammar and each disagreement between RFC 3986 and connect.c was
// patched one at a time.
//
// Fixtures cannot close a class of defect, because a fixture is an existential
// ("this string is handled") and the property under test is a universal ("NO
// string carries a secret out, and NO credential-free remote is dropped"). So
// this file enumerates the GRAMMAR rather than the examples: every prefix a
// remote can begin with, crossed with every spelling of a userinfo, crossed
// with every host shape git accepts, crossed with both separators and every
// path shape — a few thousand strings — and asserts one property over ALL of
// them.
//
// It is a PORT of subtrees/rookery/plugins/attestors/git/git_remote_grammar_sweep_test.go
// (PR #9177), deliberately, because the two attestors record the same evidence
// and a divergence between them is a bug in one of them. The three rules that
// differ are called out where they are exercised: the remote-HELPER form, the
// whitespace refusal on an scp path, and the host allowlist.

// sweepSecret is the value planted in every hostile spelling below. The
// assertions look for THIS, not for a shape, because a redactor that merely
// reshapes a credential still leaks it.
const sweepSecret = "ghs_s3cr3tTOKENvalue"

// remotePrefixes enumerates every way a remote has been shown beginning. The
// interesting entries are the near-misses: a scheme that url.Parse accepts but
// git does not, a scheme with one slash instead of two, a leading space, and a
// slash that arrives before the colon.
var remotePrefixes = []string{
	"",         // bare scp syntax
	" ",        // a leading space defeats both scheme detection and url.Parse
	"https://", // the ordinary network form
	"HTTPS://", // schemes are case-insensitive
	"ssh://",
	"git://",
	"git+ssh://", // a '+' is a legal scheme character
	"https:/",    // ONE slash. url.Parse calls this a hierarchical URL with no
	//               authority; git calls it scp syntax with the host "https".
	//               This is #9181's leak, measured returning UNCHANGED.
	"https:", // no slash at all
	"acme/",  // a slash BEFORE the colon: git reads a path, not [user@]host
	"/srv/",  // an absolute path
	"./",     // a relative path
	// A pasted authority parked INSIDE the path of an otherwise-legitimate
	// remote. The authority here is real and credential-free, so the authority
	// checks all pass and only the path is left holding the secret.
	"git@host:",
	"git@example.com:",
	"https://github.com/",
	// A BRACKET-BEARING LOGIN, #9186 round 2. The '[' opens before the
	// delimiter, so a colon after it is hidden from the delimiter search and
	// lands inside the login — the one span of an scp authority that used to be
	// preserved without being looked at.
	"alice[",
	"[",
	// The remote-HELPER prefix. `transport::address` is the form this package
	// has already leaked through once, and the one the sibling git attestor
	// does not model.
	"ext::",
	"ext::git-remote-https ",
}

// credentialUsers enumerates the left half of a `user:secret@host` pair. Every
// one of these is hostile by construction: an scp login can never contain a
// colon (the first colon ends the authority), so a colon before the '@' is
// userinfo in every reading of the string that exists.
var credentialUsers = []string{
	"alice",       // a single label
	"alice.smith", // a DOTTED label. Lexically identical to a host, which is why
	//                "does it contain a dot" was never a test — it is wrong in
	//                both directions at once and was deleted, not extended.
	"a.b.c",          // several dots, in case one was special
	"x-access-token", // what GitHub Actions actually writes
	"oauth2",         // what GitLab writes
	"gitlab-ci-token",
	"",         // Azure DevOps writes https://:PAT@dev.azure.com/... — no username
	"user:p@x", // a colon AND an at-sign already inside the userinfo
	// EMAIL-SHAPED usernames, #9186 review round 1. These are the reason the
	// ambiguity refusal cannot be gated on hasLogin: the '@' inside the
	// username lands in the scp AUTHORITY, so cutSCPAuthority reports a login
	// and the login-less rule never fires. Every one of these was recorded
	// verbatim, secret intact, before pathReadsAsAnAuthority existed.
	"alice@example.com",
	"a@b",
	"first.last@sub.example.co.uk",
}

// remoteHosts enumerates the host shapes git accepts. "myserver" and
// "[2001:db8::1]" are the two a dot-based host rule would get wrong in opposite
// directions; scpHost matches both, and matches "alice.smith" too, which is
// exactly why scpHost can never be the thing that decides whether a prefix is a
// credential.
var remoteHosts = []string{
	"github.com",
	"myserver", // a SINGLE label. `git@myserver:repo.git` is an ordinary
	//             internal remote.
	"localhost",
	"[2001:db8::1]", // a bracketed IPv6 literal, whose colons are not path
	//                  delimiters
	"10.0.0.1",
	"gitlab.example.co.uk",
}

// remoteSeparators is what follows the host: ':' in scp syntax, '/' in a URL.
var remoteSeparators = []string{":", "/"}

// remotePaths enumerates the repository half. "repo@release.git" is the
// at-sign that belongs to the repository NAME and must survive.
var remotePaths = []string{
	"acme/api.git",
	"repo@release.git",
	"api%zz.git", // an invalid percent escape: url.Parse refuses the whole string
	"team/repo.git",
	"repo.git",
	"",
}

// recordedRemoteCarriesUserinfo reports whether a RECORDED remote still puts a
// ':' before ANY '@' — the literal shape of `user:password@host`, wherever in
// the string it sits.
//
// THIS PREDICATE WAS THE REASON THE SWEEP MISSED #9186 ROUND 6, and both of the
// things it used to do wrong were concessions to the implementation it judges:
//
//   - It asked about the FIRST at-sign only, because a later one lived inside
//     `git@example.com:repo@release.git`, which #9181 asked be preserved.
//   - It RESET at the last '/' before the at-sign, on the RFC argument that a
//     userinfo may not contain a slash — the same argument that lived in the
//     implementation as the clause rounds 5 and 6 walked through.
//
// The second is what actually passed the round-6 string. Scanning every
// at-sign does not help while the reset stands:
// `alice@example.com:ghs_TOKEN/part@github.com/acme/api.git` resets to "part"
// at the second at-sign and reports clean either way. Measured — the
// "scan every at-sign" version alone was still green on it.
//
// So the reset is gone and the SCHEME is stripped instead, which is the one
// thing it was really there for: without it "ssh://git@example.com/repo.git"
// reads its own "ssh:" as a password introducer. That leaves a predicate whose
// two remaining assumptions are both about the grammar rather than about what
// the sanitiser happens to keep.
//
// It is written here, in the test, rather than imported from the sanitiser it
// checks: a test that asks the production code whether the production code
// worked cannot see the production code stop working.
func recordedRemoteCarriesUserinfo(v string) bool {
	if sep := strings.Index(v, "://"); sep >= 0 {
		v = v[sep+len("://"):]
	}
	for at := range len(v) {
		if v[at] == '@' && strings.IndexByte(v[:at], ':') >= 0 {
			return true
		}
	}
	return false
}

// TestEverySpellingOfUserColonSecretAtHostIsRefusedOrStripped is the sweep.
//
// FOR EVERY string in prefixes x users x hosts x separators x paths, the
// sanitiser must either refuse the remote outright or return one that does not
// contain the planted secret. There is no third answer, and no exemption list.
// TestTheSweepsVerdictFunctionCanActuallySeeALeak tests the TEST, and it is
// here because a sweep is worth exactly what its verdict function is worth.
//
// recordedRemoteCarriesUserinfo is the predicate every sweep in this file
// judges its results with, and for six review rounds it could not see the
// strings those rounds were about. Asserting that directly — on both sides —
// is the only thing that stops it being quietly weakened again the next time a
// legitimate remote trips it.
//
// The first loop is the one that matters: these are the exact spellings the
// pre-change predicate reported CLEAN.
func TestTheSweepsVerdictFunctionCanActuallySeeALeak(t *testing.T) {
	for _, recorded := range []string{
		"alice@example.com:" + sweepSecret + "/part@github.com/acme/api.git", // round 6
		"alice@example.com:" + sweepSecret + "/part@github.com:acme/api.git", // round 5
		"alice@example.com:" + sweepSecret + "@github.com",                   // never reported
		"alice@example.com:" + sweepSecret + "@github.com:acme/api.git",      // round 1
		"alice:" + sweepSecret + "@github.com/acme/api.git",
		"https://alice:" + sweepSecret + "@github.com/acme/api.git",
	} {
		require.True(t, recordedRemoteCarriesUserinfo(recorded),
			"the sweep's verdict function cannot see a credential in %q, so no sweep using it can either", recorded)
	}

	// THE OTHER HALF. A verdict function that answered "leak" to everything
	// would satisfy the loop above and make every sweep vacuous in the other
	// direction, so each of these is a remote the sanitiser really does record
	// and the predicate must call clean. The scheme colon is the one that
	// forces the "://" strip.
	for _, recorded := range []string{
		"git@github.com:acme/api.git",
		"ssh://git@example.com/acme/api.git",
		"git@[2001:db8::1]:acme/api.git",
		"user@host@[2001:db8::1]:repo.git",
		"/srv/git/a@b.git",
		"https://github.com/acme/api.git",
		"git@example.com:github.com:acme/api.git",
	} {
		require.False(t, recordedRemoteCarriesUserinfo(recorded),
			"the sweep's verdict function calls an ordinary remote a credential: %q", recorded)
		// And each one really is a remote the sanitiser keeps, so the loop
		// cannot drift into asserting "clean" about strings nothing records.
		out, ok := sanitizeRemoteURL(recorded)
		require.True(t, ok, "this list must hold remotes the sanitiser actually records: %q", recorded)
		require.False(t, recordedRemoteCarriesUserinfo(out),
			"the recorded form must be clean too: %q -> %q", recorded, out)
	}
}

func TestEverySpellingOfUserColonSecretAtHostIsRefusedOrStripped(t *testing.T) {
	checked := 0

	for _, prefix := range remotePrefixes {
		for _, user := range credentialUsers {
			for _, host := range remoteHosts {
				for _, sep := range remoteSeparators {
					for _, path := range remotePaths {
						raw := prefix + user + ":" + sweepSecret + "@" + host + sep + path
						checked++

						out, ok := sanitizeRemoteURL(raw)
						if !ok {
							require.Empty(t, out,
								"a refused remote must yield no value: %q", raw)
							continue
						}

						require.NotContains(t, out, sweepSecret,
							"a credential reached the attestation: %q -> %q", raw, out)
						require.False(t, recordedRemoteCarriesUserinfo(out),
							"a recorded remote still carries userinfo: %q -> %q", raw, out)
					}
				}
			}
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 3000,
		"the sweep must enumerate its space; a shrunken cross product is not a sweep")
}

// TestEverySchemedURLWithATokenForItsWholeUserinfoIsStripped covers the other
// credential spelling: a PAT as the ENTIRE username, with no password half at
// all. A sanitiser that looks for a colon misses every one of these.
//
// Restricted to scheme'd forms on purpose. Without a scheme, "TOKEN@host:path"
// is scp syntax whose login is an ssh USER — `git@github.com:acme/api.git` has
// exactly that shape — and no property of the string tells the two apart. The
// scp login is therefore kept by design, and TestAnScpLoginIsNotACredential
// below pins that choice so it stays a decision rather than an oversight.
func TestEverySchemedURLWithATokenForItsWholeUserinfoIsStripped(t *testing.T) {
	schemes := []string{"https://", "HTTPS://", "http://", "ssh://", "git://", "git+ssh://"}
	// A LOGIN IN FRONT puts a SECOND at-sign in the authority, and that is what
	// pins the userinfo cut to the LAST one. With a single at-sign both choices
	// agree; with "alice@SECRET@github.com" the first-at-sign cut leaves
	// "SECRET@github.com" — an authority with no colon in it, so the port rule
	// waves it through and the token is recorded. That mutant survived every
	// other test in this file once the port rule started masking the shapes
	// that used to catch it.
	logins := []string{"", "alice@", "git@", "a@b@"}
	checked := 0

	for _, scheme := range schemes {
		for _, login := range logins {
			for _, host := range remoteHosts {
				for _, path := range remotePaths {
					raw := scheme + login + sweepSecret + "@" + host + "/" + path
					checked++

					out, ok := sanitizeRemoteURL(raw)
					if !ok {
						continue
					}
					require.NotContains(t, out, sweepSecret,
						"a token-as-username reached the attestation: %q -> %q", raw, out)
					require.False(t, recordedRemoteCarriesUserinfo(out),
						"a recorded remote still carries userinfo: %q -> %q", raw, out)
				}
			}
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 400, "the sweep must enumerate its space")
}

// TestAUrlAuthoritySplitsAtItsLastAtSign pins the userinfo cut directly, because
// the sweep above can only see it through an end-to-end value.
//
// "https://alice@SECRET@github.com/repo.git" is the discriminator: cutting at
// the LAST at-sign leaves "github.com"; cutting at the FIRST leaves
// "SECRET@github.com", which holds no colon, so the port rule accepts it and
// the token is recorded. Before the port rule existed the sweep caught this on
// other shapes; afterwards those shapes were refused for a different reason and
// the choice went unpinned.
func TestAUrlAuthoritySplitsAtItsLastAtSign(t *testing.T) {
	for _, tt := range []struct{ raw, want string }{
		{"https://alice@" + sweepSecret + "@github.com/repo.git", "https://github.com/repo.git"},
		{"https://a@b@" + sweepSecret + "@github.com/repo.git", "https://github.com/repo.git"},
		{"ssh://git@" + sweepSecret + "@github.com:22/repo.git", "ssh://github.com:22/repo.git"},
	} {
		out, ok := sanitizeRemoteURL(tt.raw)
		require.True(t, ok, "the host survives the userinfo cut: %q", tt.raw)
		require.Equal(t, tt.want, out)
		require.NotContains(t, out, sweepSecret)
	}
}

// TestEveryCredentialFreeSCPRemoteKeepsItsHostAndPath is the CONTROL, and it is
// the half that makes the sweep above mean anything: refusing every remote
// satisfies "no secret escaped" perfectly, and takes with it the whole reason
// this predicate names remotes at all — a reader has to be able to tell which
// repository the observation is about.
//
// FOR EVERY credential-free scp spelling — a login, any host shape, any path
// that holds no at-sign — the remote must be recorded exactly as typed. Not
// reshaped, not normalized: an scp remote is not a URL and there is nothing in
// it to redact.
//
// THE AT-SIGN PATHS STAY IN THE TABLE AND MOVED SIDES. They are swept here
// rather than deleted, because deleting them would shrink the space this
// control ranges over and a sweep whose domain shrinks with the rule it checks
// cannot fail. `git@example.com:repo@release.git` is #9181's third measured
// failure; it is now an accepted over-refusal, on the same terms
// `https://github.com/acme/repo@release.git` already is in the URL branch, and
// the assertion below records that rather than hiding it.
func TestEveryCredentialFreeSCPRemoteKeepsItsHostAndPath(t *testing.T) {
	// Non-empty logins only. The login-less case is split out below because a
	// login-less authority followed by an at-sign is genuinely ambiguous.
	logins := []string{"git@", "user@", "hg@", "user@host@"}
	paths := []string{
		"acme/api.git", "repo@release.git", "team/repo@release.git", "repo.git", "/example/repo.git",
		// BRACKETS PAST THE BOUNDARY (#9186 round 1). '[' is a filename byte in
		// a repository name, and carrying the authority's bracket check to the
		// end of the string dropped every one of these.
		"repo[1.git", "repo[1].git", "team/a[b.git",
	}
	kept, refused := 0, 0

	for _, login := range logins {
		for _, host := range remoteHosts {
			for _, path := range paths {
				raw := login + host + ":" + path

				out, ok := sanitizeRemoteURL(raw)
				if strings.ContainsRune(path, '@') {
					refused++
					require.False(t, ok,
						"an at-sign past the scp authority must not be recorded: %q -> %q", raw, out)
					require.Empty(t, out)
					continue
				}
				kept++
				require.True(t, ok,
					"a credential-free scp remote was dropped, taking its repository identity with it: %q", raw)
				require.Equal(t, raw, out,
					"an scp remote has nothing to redact and must be recorded as typed: %q", raw)
			}
		}
	}

	t.Logf("swept %d spellings: %d kept, %d refused for an at-sign past the authority", kept+refused, kept, refused)
	require.Greater(t, kept, 100, "the control must enumerate its space")
	require.Greater(t, refused, 0, "the over-refusal half must not have emptied itself")
}

// TestEveryLoginLessSCPRemoteWithNoAtSignSurvives covers the other half of the
// scp control: no login at all. `myserver:repo.git` is what a remote looks like
// when ~/.ssh/config supplies the user.
func TestEveryLoginLessSCPRemoteWithNoAtSignSurvives(t *testing.T) {
	paths := []string{"acme/api.git", "team/repo.git", "repo.git", "/example/repo.git"}
	checked := 0

	for _, host := range remoteHosts {
		for _, path := range paths {
			raw := host + ":" + path
			checked++

			out, ok := sanitizeRemoteURL(raw)
			require.True(t, ok, "a login-less scp remote was dropped: %q", raw)
			require.Equal(t, raw, out, "a login-less scp remote must be recorded as typed: %q", raw)
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 20, "the control must enumerate its space")
}

// TestEveryCredentialFreeSchemedURLKeepsItsHostAndPath is the URL-form control.
// The login IS dropped here — that is pre-existing behaviour and what
// url.URL.User = nil always did — so the assertion is on IDENTITY rather than
// on the literal string: whatever comes back must still name the host and the
// path.
func TestEveryCredentialFreeSchemedURLKeepsItsHostAndPath(t *testing.T) {
	schemes := []string{"https://", "http://", "ssh://", "git://", "git+ssh://"}
	logins := []string{"", "git@", "user@"}
	paths := []string{"acme/api.git", "repo@release.git", "team/repo.git", "api%zz.git"}
	checked := 0

	for _, scheme := range schemes {
		for _, login := range logins {
			for _, host := range remoteHosts {
				for _, path := range paths {
					raw := scheme + login + host + "/" + path
					checked++

					out, ok := sanitizeRemoteURL(raw)

					// A URL whose PATH holds an at-sign reads two ways —
					// host-then-path, or a credential whose delimiter is that
					// at-sign — and the ambiguity was measured leaking a bare
					// PAT. A login in the authority does NOT resolve it: round 4
					// showed that consuming one userinfo says nothing about the
					// span that was kept, so the refusal applies with or without
					// one. Refusing here is the URL twin of the scp cost pinned
					// in TestAnAmbiguousLoginLessRemoteIsRefused; the scp form
					// keeps its login exemption because #9181 requires
					// `git@example.com:repo@release.git` to survive.
					if strings.ContainsRune(path, '@') {
						require.False(t, ok,
							"a login-less URL whose path holds an at-sign is ambiguous: %q -> %q", raw, out)
						require.Empty(t, out)
						continue
					}

					require.True(t, ok, "a credential-free URL remote was dropped: %q", raw)
					require.Contains(t, out, host,
						"the recorded remote no longer names its host: %q -> %q", raw, out)
					require.Contains(t, out, path,
						"the recorded remote no longer names its path: %q -> %q", raw, out)
					require.True(t, strings.HasPrefix(strings.ToLower(out), strings.ToLower(scheme)),
						"the recorded remote lost its scheme: %q -> %q", raw, out)
				}
			}
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 300, "the control must enumerate its space")
}

// TestEveryRemoteFormDropsAQueryAndFragment is the other half of the credential
// surface, swept across EVERY form rather than only the scheme'd one.
//
// "?access_token=…" is a credential in the part of the string userinfo
// redaction never looks at, and the form split makes that a trap: the scp and
// local branches hand their input back UNMODIFIED, so a token parked after a
// '?' rides along on both unless the cut happens at the single entry point,
// before the split. The sibling port measured a per-branch cut leaking 20 of 36
// planted inputs — every scp and local case — and `/srv/git/repo.git?token=…`
// is also a REGRESSION in that arrangement, because url.Parse used to clear
// RawQuery on the old fast path.
func TestEveryRemoteFormDropsAQueryAndFragment(t *testing.T) {
	bases := []struct{ remote, want string }{
		{"https://github.com/acme/api.git", "https://github.com/acme/api.git"},
		{"http://github.com/acme/api.git", "http://github.com/acme/api.git"},
		{"ssh://git@github.com/acme/api.git", "ssh://github.com/acme/api.git"},
		{"file:///srv/git/repo.git", "file:///srv/git/repo.git"},
		{"git@github.com:acme/api.git", "git@github.com:acme/api.git"},
		{"github.com:acme/api.git", "github.com:acme/api.git"},
		{"git@[2001:db8::1]:acme/api.git", "git@[2001:db8::1]:acme/api.git"},
		{"/srv/git/repo.git", "/srv/git/repo.git"},
		{"../mirror", "../mirror"},
	}
	suffixes := []string{
		"?access_token=" + sweepSecret,
		"#" + sweepSecret,
		"?a=1&b=2#" + sweepSecret,
		"?" + sweepSecret,
	}

	checked := 0
	for _, base := range bases {
		for _, suffix := range suffixes {
			raw := base.remote + suffix
			checked++

			out, ok := sanitizeRemoteURL(raw)
			require.True(t, ok,
				"dropping a query must not cost the whole remote: %q", raw)
			require.NotContains(t, out, sweepSecret,
				"a token in the query or fragment reached the attestation: %q -> %q", raw, out)
			require.Equal(t, base.want, out,
				"the repository identity must survive the query being dropped: %q", raw)
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 30, "the sweep must enumerate its space")
}

// TestARemoteThatIsOnlyAQueryIsRefused is the boundary case of the rule above:
// once the query goes there is nothing left to name a repository, and an empty
// remote is not a remote.
func TestARemoteThatIsOnlyAQueryIsRefused(t *testing.T) {
	for _, raw := range []string{"?access_token=" + sweepSecret, "#" + sweepSecret, "?", "   "} {
		out, ok := sanitizeRemoteURL(raw)
		require.False(t, ok, "nothing is left to record: %q", raw)
		require.Empty(t, out)
	}
}

// TestEveryRemoteHelperInvocationIsRefused is a DIVERGENCE from the sibling git
// attestor, and it is here because THIS package has already shipped the leak it
// closes.
//
// git's `transport::address` runs an arbitrary helper. The address is a command
// line, not a URL: `ext::git-remote-https https://u:tok@h/r.git` and
// `ext::helper --token SECRET` are both legal, and a first version of this
// file's sanitiser accepted any opaque string with a colon and returned it
// UNCHANGED. Under the grammar decomposition alone a helper reads as an scp
// remote whose host is the TRANSPORT ("ext") and whose path is the whole
// address, which passes every authority check there is — so the form has to be
// recognised, and it is routed to the same refusal seam as everything else.
//
// FOR EVERY transport x address, nothing is recorded.
func TestEveryRemoteHelperInvocationIsRefused(t *testing.T) {
	transports := []string{"ext", "fd", "transport", "my-helper", "a.b"}
	addresses := []string{
		"helper --token " + sweepSecret,
		"send-pack-" + sweepSecret,
		"git-remote-https https://u:" + sweepSecret + "@h/r.git",
		"github.com/acme/api.git",
		"",
		sweepSecret,
	}

	checked := 0
	for _, transport := range transports {
		for _, address := range addresses {
			raw := transport + "::" + address
			checked++

			out, ok := sanitizeRemoteURL(raw)
			require.False(t, ok,
				"a remote-helper invocation carries an arbitrary command line and must not be recorded: %q", raw)
			require.Empty(t, out)
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 20, "the sweep must enumerate its space")
}

// TestEveryScpRemoteWithWhitespaceIsRefused is the second DIVERGENCE from the
// sibling attestor, and the reason it survives the port is that removing it
// would LOOSEN a credential refusal this package currently ships.
//
// `github.com:path --upload-pack=SECRET` has one colon, a host-shaped
// authority and no at-sign, so every other check in sanitizeSCPRemote passes
// it. Whitespace in a remote is where a helper COMMAND LINE lives, and a
// command line is the shape this package leaked through once already. Nothing
// available here can show dropping the rule to be safe, so it stays.
//
// The rule is NOT applied to local paths — see
// TestALocalPathKeepsWhatCannotHideAnAuthority, where "/srv/git/My Repos/x.git"
// is kept as typed. That is a strict improvement on url.Parse, which used to
// percent-encode it into a spelling git never wrote.
