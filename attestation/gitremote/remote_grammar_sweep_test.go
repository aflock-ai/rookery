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

package gitremote

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// THE GRAMMAR SWEEP — testifysec/judge#8950, PR #9177 round 3.
//
// Two review rounds produced five findings and every one of them was the same
// mistake: a local LEXICAL test standing in for a STRUCTURAL boundary. Which
// '@' delimits the credential, decided without computing the authority. Whether
// a prefix is a host, decided by looking for a dot. Where the path starts,
// decided by taking the first colon with no regard for bracket nesting. Each
// round the fix was another fixture and another special case, and each round
// produced a new spelling that walked around it.
//
// Fixtures cannot close a class of defect, because a fixture is an existential
// ("this string is handled") and the property under test is a universal ("NO
// string carries a secret out"). So this file enumerates the GRAMMAR instead of
// the examples: every prefix a remote can begin with, crossed with every
// spelling of a userinfo, crossed with every host shape git accepts, crossed
// with both separators and every path shape — a few thousand strings — and
// asserts one property over ALL of them.
//
// If a sixth variant of this class exists, it is in this space, and it fails
// here rather than in the next review.

// sweepSecret is the value planted in every hostile spelling below. The
// assertions look for THIS, not for a shape, because a redactor that merely
// reshapes a credential still leaks it.
const sweepSecret = "ghs_s3cr3tTOKENvalue"

// remotePrefixes enumerates every way the reviews and the wild have shown a
// remote beginning. The interesting entries are the near-misses: a scheme that
// url.Parse accepts but git does not, a scheme with one slash instead of two, a
// leading space, and a slash that arrives before the colon.
var remotePrefixes = []string{
	"",           // bare scp syntax
	" ",          // round 1: a leading space defeats both scheme detection and url.Parse
	"https://",   // the ordinary network form
	"HTTPS://",   // schemes are case-insensitive
	"ssh://",     //
	"git://",     //
	"git+ssh://", // a '+' is a legal scheme character
	"https:/",    // round 2 finding 1: ONE slash. url.Parse calls this a hierarchical
	//              URL with no authority; git calls it scp syntax with the host "https"
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
}

// credentialUsers enumerates the left half of a `user:secret@host` pair. Every
// one of these is hostile by construction: an scp login can never contain a
// colon (the first colon ends the authority), so a colon before the '@' is
// userinfo in every reading of the string that exists.
var credentialUsers = []string{
	"alice",       // round 1: a single label
	"alice.smith", // round 2 finding 2: a DOTTED label. Lexically identical to a
	//                   host, which is why "does it contain a dot" was never a test
	"a.b.c",          // several dots, in case one was special
	"x-access-token", // what GitHub Actions actually writes
	"oauth2",         // what GitLab writes
	"gitlab-ci-token",
	"",         // Azure DevOps writes https://:PAT@dev.azure.com/... — no username at all
	"user:p@x", // a colon AND an at-sign already inside the userinfo
}

// remoteHosts enumerates the host shapes git accepts. "myserver" and
// "[2001:db8::1]" are the two the retired dot rule got wrong in opposite
// directions — it dropped both while passing "alice.smith".
var remoteHosts = []string{
	"github.com",
	"myserver", // a SINGLE label. `git@myserver:repo.git` is an ordinary
	//             internal remote and the dot rule silently discarded it
	"localhost",
	"[2001:db8::1]", // round 2 finding 3: a bracketed IPv6 literal, whose
	//                  colons are not path delimiters
	"10.0.0.1",
	"gitlab.example.co.uk",
}

// remoteSeparators is what follows the host: ':' in scp syntax, '/' in a URL.
var remoteSeparators = []string{":", "/"}

// remotePaths enumerates the repository half. "repo@release.git" is the round-1
// finding: an at-sign that belongs to the repository NAME and must survive.
var remotePaths = []string{
	"acme/api.git",
	"repo@release.git",
	"api%zz.git", // an invalid percent escape: url.Parse refuses the whole string
	"team/repo.git",
	"repo.git",
	"",
}

// recordedRemoteCarriesUserinfo reports whether a RECORDED remote still puts a
// ':' before its first '@' with no '/' between them — the literal shape of
// `user:password@host`, wherever in the string it sits.
//
// It asks about the FIRST at-sign only. A later one is inside a repository path
// ("git@example.com:repo@release.git"), which the round-1 review requires be
// preserved intact, so a predicate that scanned every '@' would forbid a remote
// the reviews demand we keep.
//
// It is written here, in the test, rather than imported from the redactor it
// checks: a test that asks the production code whether the production code
// worked cannot see the production code stop working.
func recordedRemoteCarriesUserinfo(v string) bool {
	at := strings.IndexByte(v, '@')
	if at < 0 {
		return false
	}
	head := v[:at]
	if slash := strings.LastIndexByte(head, '/'); slash >= 0 {
		head = head[slash+1:]
	}
	return strings.IndexByte(head, ':') >= 0
}

// TestEverySpellingOfUserColonSecretAtHostIsRefusedOrStripped is the sweep.
//
// FOR EVERY string in prefixes x users x hosts x separators x paths, the
// redactor must either refuse the remote outright or return one that does not
// contain the planted secret. There is no third answer, and no exemption list.
func TestEverySpellingOfUserColonSecretAtHostIsRefusedOrStripped(t *testing.T) {
	checked := 0

	for _, prefix := range remotePrefixes {
		for _, user := range credentialUsers {
			for _, host := range remoteHosts {
				for _, sep := range remoteSeparators {
					for _, path := range remotePaths {
						raw := prefix + user + ":" + sweepSecret + "@" + host + sep + path
						checked++

						out, ok := redactRemoteURL(raw)
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
// all. A redactor that looks for a colon misses every one of these.
//
// Restricted to scheme'd forms on purpose. Without a scheme, "TOKEN@host:path"
// is scp syntax whose login is an ssh USER — `git@github.com:acme/api.git` has
// exactly that shape — and no property of the string tells the two apart. The
// scp login is therefore kept by design, and TestAnScpLoginIsNotACredential
// below pins that choice so it stays a decision rather than an oversight.
func TestEverySchemedURLWithATokenForItsWholeUserinfoIsStripped(t *testing.T) {
	schemes := []string{"https://", "HTTPS://", "http://", "ssh://", "git://", "git+ssh://"}
	checked := 0

	for _, scheme := range schemes {
		for _, host := range remoteHosts {
			for _, path := range remotePaths {
				raw := scheme + sweepSecret + "@" + host + "/" + path
				checked++

				out, ok := redactRemoteURL(raw)
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

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 100, "the sweep must enumerate its space")
}

// TestEveryCredentialFreeSCPRemoteKeepsItsHostAndPath is the CONTROL, and it is
// the half that makes the sweep above mean anything: refusing every remote
// satisfies "no secret escaped" perfectly, and takes the attestation's entire
// discovery surface with it, since judge links a DSSE to a product by these
// strings.
//
// FOR EVERY credential-free scp spelling — a login, any host shape, any path,
// including a path with an at-sign in it — the remote must be recorded exactly
// as typed. Not reshaped, not normalized: an scp remote is not a URL and there
// is nothing in it to redact.
func TestEveryCredentialFreeSCPRemoteKeepsItsHostAndPath(t *testing.T) {
	// Non-empty logins only. The login-less case is split out below because a
	// login-less authority followed by an at-sign is genuinely ambiguous.
	logins := []string{"git@", "user@", "hg@", "user@host@"}
	paths := []string{"acme/api.git", "repo@release.git", "team/repo@release.git", "repo.git", "/example/repo.git"}
	checked := 0

	for _, login := range logins {
		for _, host := range remoteHosts {
			for _, path := range paths {
				raw := login + host + ":" + path
				checked++

				out, ok := redactRemoteURL(raw)
				require.True(t, ok,
					"a credential-free scp remote was dropped, taking its discovery edge with it: %q", raw)
				require.Equal(t, raw, out,
					"an scp remote has nothing to redact and must be recorded as typed: %q", raw)
			}
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 100, "the control must enumerate its space")
}

// TestEveryLoginLessSCPRemoteWithNoAtSignSurvives covers the other half of the
// scp control: no login at all. `myserver:repo.git` is what a remote looks like
// when ~/.ssh/config supplies the user, and the retired dot rule dropped every
// single-label spelling of it.
func TestEveryLoginLessSCPRemoteWithNoAtSignSurvives(t *testing.T) {
	paths := []string{"acme/api.git", "team/repo.git", "repo.git", "/example/repo.git"}
	checked := 0

	for _, host := range remoteHosts {
		for _, path := range paths {
			raw := host + ":" + path
			checked++

			out, ok := redactRemoteURL(raw)
			require.True(t, ok, "a login-less scp remote was dropped: %q", raw)
			require.Equal(t, raw, out, "a login-less scp remote must be recorded as typed: %q", raw)
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 20, "the control must enumerate its space")
}

// TestEveryCredentialFreeSchemedURLKeepsItsHostAndPath is the URL-form control.
// The login is dropped here — that is pre-existing behaviour and what
// url.URL.User = nil always did — so the assertion is on IDENTITY rather than
// on the literal string: whatever comes back must still name the host and the
// path, because that is what judge builds its product edge from.
//
// A COMBINATION FLIPPED IN ROUND 5 AND WIDENED IN ROUND 6, AND IT IS ASSERTED
// HERE RATHER THAN DELETED. A URL whose PATH holds an at-sign is refused,
// WITH a login as well as without, so neither
// "https://github.com/repo@release.git" nor
// "https://git@github.com/repo@release.git" survives.
//
// Round 5 exempted the login-bearing spelling, and round 6 removed that
// exemption because it was unsound: consuming one userinfo says something about
// the span REMOVED and nothing about the span KEPT, which is how
// "https://alice@ghs_TOKEN/part@github.com/…" recorded a token as its host.
//
// The scp form deliberately KEEPS its login exemption — #9181 measured
// "git@example.com:repo@release.git" as must-survive, and scp settles its
// authority at the first colon before any at-sign is read. The two grammars
// differ on purpose; TestOrdinaryCredentialBearingRemotesStillSurviveRound5
// pins the scp side, and the count assertion below pins this one so the rule
// cannot quietly widen further.
func TestEveryCredentialFreeSchemedURLKeepsItsHostAndPath(t *testing.T) {
	schemes := []string{"https://", "http://", "ssh://", "git://", "git+ssh://"}
	logins := []string{"", "git@", "user@"}
	paths := []string{"acme/api.git", "repo@release.git", "team/repo.git", "api%zz.git"}
	checked := 0
	refusedAsAmbiguous := 0

	for _, scheme := range schemes {
		for _, login := range logins {
			for _, host := range remoteHosts {
				for _, path := range paths {
					raw := scheme + login + host + "/" + path
					checked++

					out, ok := redactRemoteURL(raw)

					if strings.ContainsRune(path, '@') {
						require.False(t, ok,
							"a URL whose path holds an at-sign is ambiguous and must be refused, login or not: %q -> %q", raw, out)
						refusedAsAmbiguous++
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

	t.Logf("swept %d spellings, %d refused as ambiguous", checked, refusedAsAmbiguous)
	require.Greater(t, checked, 300, "the control must enumerate its space")
	require.Equal(t, len(schemes)*len(logins)*len(remoteHosts), refusedAsAmbiguous,
		"exactly the at-sign-path combinations may be refused, no more")
}

// TestABracketedIPv6SCPRemoteSplitsAtTheColonOutsideTheBrackets pins round 2
// finding 3 at the boundary itself rather than only through the sweep.
//
// Taking the FIRST colon makes the host "[2001", which is not a host under any
// rule, so the whole remote vanished from the attestation — evidence lost to a
// delimiter chosen without regard to bracket nesting. git advances past the
// closing ']' before it looks for the delimiter (connect.c), and so does this.
func TestABracketedIPv6SCPRemoteSplitsAtTheColonOutsideTheBrackets(t *testing.T) {
	for _, raw := range []string{
		"git@[2001:db8::1]:acme/api.git",
		"[2001:db8::1]:acme/api.git",
		"git@[::1]:repo.git",
		"user@host@[2001:db8::1]:repo@release.git",
		"git@[2001:db8::1]:/absolute/repo.git",
	} {
		out, ok := redactRemoteURL(raw)
		require.True(t, ok, "a bracketed IPv6 scp remote was dropped: %q", raw)
		require.Equal(t, raw, out, "a bracketed IPv6 scp remote must survive as typed: %q", raw)
	}
}

// TestAnUnterminatedBracketIsRefused is the fail-closed companion to the test
// above. Advancing past ']' is only safe when there IS one; a '[' that never
// closes leaves no boundary to compute, and a string whose boundary cannot be
// computed is exactly the thing this attestor must not record.
func TestAnUnterminatedBracketIsRefused(t *testing.T) {
	for _, raw := range []string{
		"git@[2001:db8::1:acme/api.git",
		"[2001:db8::1:" + sweepSecret + "@github.com:acme/api.git",
		// No at-sign anywhere, so nothing else in the pipeline objects to this
		// one: dropping the bracket guard records it as an ordinary path. It is
		// the case that tells the guard apart from the checks around it.
		"[2001:db8::1:repo.git",
	} {
		out, ok := redactRemoteURL(raw)
		require.False(t, ok, "an unterminated bracket leaves no computable boundary: %q", raw)
		require.Empty(t, out)
	}
}

// TestAnScpLoginIsNotACredential pins the one thing in scp syntax that looks
// like userinfo and is not.
//
// The login lies wholly before the first colon, so it can never contain one:
// scp syntax has no password field. It is a routing value — ssh dials on it,
// and github and gitlab both require `git@` — and a remote stripped of it can
// no longer clone. It is kept deliberately, and the cost is stated out loud: a
// token pasted as a bare scp login is indistinguishable from an ssh user and is
// therefore recorded. Nothing in the string can tell them apart; the scheme'd
// spelling, which is what tooling actually writes, is stripped by the sweep
// above.
func TestAnScpLoginIsNotACredential(t *testing.T) {
	out, ok := redactRemoteURL("git@github.com:acme/api.git")
	require.True(t, ok)
	require.Equal(t, "git@github.com:acme/api.git", out,
		"the ssh login is routing information, not a credential")
}

// TestAnAmbiguousLoginLessRemoteIsRefused states the one preservation cost this
// design accepts, so that it is a recorded decision rather than a surprise in
// the next review.
//
// `github.com:repo@release.git` has no login, and its path holds an at-sign. It
// reads two ways that disagree about whether anything in it is secret: as scp
// syntax (host github.com, a repository named repo@release.git) and as an https
// authority that lost its scheme (user github.com, password repo, host
// release.git). Nothing in the string decides between them — which is precisely
// the shape of round 2's `alice.smith:TOKEN@github.com:acme/api.git`. When the
// readings disagree the redactor refuses, because recording an unredactable
// string is the fail-OPEN direction.
//
// A login removes the ambiguity — `git@example.com:repo@release.git` is kept,
// pinned in TestEveryCredentialFreeSCPRemoteKeepsItsHostAndPath — so the cost
// is confined to a remote with NO login AND an at-sign in its path.
func TestAnAmbiguousLoginLessRemoteIsRefused(t *testing.T) {
	for _, raw := range []string{
		"github.com:repo@release.git",
		"alice.smith:" + sweepSecret + "@github.com:acme/api.git",
		"alice:" + sweepSecret + "@github.com:acme/api.git",
	} {
		out, ok := redactRemoteURL(raw)
		require.False(t, ok, "an ambiguous login-less remote must not be recorded: %q", raw)
		require.Empty(t, out)
	}
}

// TestANetworkURLWithNoAuthorityIsRefused pins round 2 finding 1 at the
// boundary. url.Parse reads "https:/alice:TOKEN@github.com/acme/api.git" as a
// hierarchical URL with a scheme and NO authority, so clearing User was a no-op
// and String() handed the token back. git reads the same string as scp syntax
// with the host "https"; either way there is no authority holding the token,
// and either way it must not be recorded.
func TestANetworkURLWithNoAuthorityIsRefused(t *testing.T) {
	for _, raw := range []string{
		"https:/alice:" + sweepSecret + "@github.com/acme/api.git",
		"https://alice:" + sweepSecret + "@/acme/api.git",
		"https:///acme/api.git",
		"ssh://" + sweepSecret + "@/repo.git",
	} {
		out, ok := redactRemoteURL(raw)
		require.False(t, ok, "a network URL with no identifiable authority must not be recorded: %q", raw)
		require.Empty(t, out)
	}
}

// TestEveryCurlFamilyURLDropsAQueryAndFragment is the other half of #8950's
// credential surface: "?token=…" is a credential living in the one part of the
// string that userinfo redaction never reads, so it has to come off the value
// that gets recorded.
//
// IT SWEEPS THE CURL-FAMILY SCHEMES ONLY, and the narrowing happened twice. An
// earlier head ran the cut across every FORM, so it renamed scp and local
// repositories. The head after that ran it for every remoteFormURL, which was
// still wrong: git hands only http/https/ftp/ftps to a transport that parses a
// query, so "ssh://host/repo#release.git" and "file:///srv/git/repo#release.git"
// had their filenames cut too. This test pinned each wrong behaviour in turn,
// which is what made it complicit rather than protective — a test that asserts
// the implementation cannot notice the implementation is wrong.
//
// The other schemes are swept in git_remote_form_query_sweep_test.go, which
// keys its expectation on schemeHasQueryGrammar and asserts the HARM rather
// than the remedy.
func TestEveryCurlFamilyURLDropsAQueryAndFragment(t *testing.T) {
	bases := []struct{ remote, want string }{
		{"https://github.com/acme/api.git", "https://github.com/acme/api.git"},
		{"http://github.com/acme/api.git", "http://github.com/acme/api.git"},
		{"ftp://github.com/acme/api.git", "ftp://github.com/acme/api.git"},
		{"ftps://github.com/acme/api.git", "ftps://github.com/acme/api.git"},
	}
	suffixes := []string{
		"?token=" + sweepSecret,
		"#" + sweepSecret,
		"?a=1&b=2#" + sweepSecret,
		"?" + sweepSecret,
	}

	checked := 0
	for _, base := range bases {
		// The sweep is only meaningful if git really would hand these to a
		// query-parsing transport, which is the distinction the cut turns on.
		form, scheme, _ := classifyRemote(base.remote)
		require.Equal(t, remoteFormURL, form, "%q must be the URL form for this sweep to mean anything", base.remote)
		require.True(t, schemeHasQueryGrammar(scheme), "%q must be a curl-family scheme for this sweep to mean anything", base.remote)

		for _, suffix := range suffixes {
			raw := base.remote + suffix
			checked++

			out, ok := redactRemoteURL(raw)
			require.True(t, ok,
				"dropping a query must not cost the whole remote: %q", raw)
			require.NotContains(t, out, sweepSecret,
				"a token in the query or fragment reached the attestation: %q -> %q", raw, out)
			require.Equal(t, base.want, out,
				"the repository identity must survive the query being dropped: %q", raw)
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 15, "the sweep must enumerate its space")
}

// TestANativeTransportURLKeepsItsDelimitersOrIsRefused is the counterpart the
// round-8 finding asked for: the schemes git does NOT hand to curl must never
// have their path bytes cut.
func TestANativeTransportURLKeepsItsDelimitersOrIsRefused(t *testing.T) {
	for _, raw := range []string{
		"ssh://git@github.com/acme/repo#release.git",
		"ssh://git@github.com/acme/repo?v=1.git",
		"file:///srv/git/repo#release.git",
		"git://github.com/acme/repo#release.git",
	} {
		out, ok := redactRemoteURL(raw)
		if ok {
			require.Equal(t, raw, out,
				"git passes this path to its transport verbatim, so %q must not be shortened: %q", raw, out)
			continue
		}
		require.Empty(t, out, "a refusal records nothing: %q", raw)
	}
}

// TestARemoteThatIsOnlyAQueryIsRefused is the boundary case of the rule above:
// once the query goes there is nothing left to name a repository, and an empty
// remote is not a remote.
func TestARemoteThatIsOnlyAQueryIsRefused(t *testing.T) {
	for _, raw := range []string{"?token=" + sweepSecret, "#" + sweepSecret, "?"} {
		out, ok := redactRemoteURL(raw)
		require.False(t, ok, "nothing is left to record: %q", raw)
		require.Empty(t, out)
	}
}

// TestAnScpAuthoritySplitsAtItsLastAtSign pins the boundary inside the
// authority, at the function rather than through the attestor.
//
// It has to be pinned here because the scp branch records its input unmodified,
// so flipping the split from the last '@' to the first changes nothing any
// end-to-end assertion can see — a mutation doing exactly that survived every
// other test in this package until this one existed.
func TestAnScpAuthoritySplitsAtItsLastAtSign(t *testing.T) {
	for _, tt := range []struct {
		authority string
		login     string
		host      string
		hasLogin  bool
	}{
		{"git@github.com", "git", "github.com", true},
		{"user@host@example.com", "user@host", "example.com", true}, // ssh splits here too
		{"github.com", "", "github.com", false},
		{"git@[2001:db8::1]", "git", "[2001:db8::1]", true},
		{"@github.com", "", "github.com", true}, // an empty login is still a login
		{"[ghs_TOKEN]@github.com", "[ghs_TOKEN]", "github.com", true},
	} {
		login, host, hasLogin := cutSCPAuthority(tt.authority)
		require.Equal(t, tt.login, login, "authority %q", tt.authority)
		require.Equal(t, tt.host, host, "authority %q", tt.authority)
		require.Equal(t, tt.hasLogin, hasLogin, "authority %q", tt.authority)

		// THE TWO HALVES MUST BE PINNED TO AGREE. redactSCPRemote tests the
		// login for brackets and the host for brackets and whitespace; if the
		// two ever came from different splits, a component could be tested
		// under one boundary and used under another. Reassembling is the
		// cheapest statement that exactly one boundary exists.
		if tt.hasLogin {
			require.Equal(t, tt.authority, login+"@"+host, "halves must reassemble: %q", tt.authority)
		} else {
			require.Equal(t, tt.authority, host, "a login-less authority is all host: %q", tt.authority)
		}
	}
}

// TestAHostThatCannotBeAHostIsRefused pins the ONE property still asked about
// the host, and its narrowness is the point.
//
// The retired rule asked whether the host LOOKED like a DNS name, which is a
// question about spelling that a dotted username answers as well as a host does.
// This asks only whether the value is structurally impossible: empty, or holding
// a space or control character that no host may contain. "myserver" passes,
// because a single label is a host.
func TestAHostThatCannotBeAHostIsRefused(t *testing.T) {
	for _, raw := range []string{
		":repo.git",             // no authority at all before the delimiter
		" myserver:repo.git",    // a leading space is not part of any host
		"my\tserver:repo.git",   // nor is a tab
		"my\x7fserver:repo.git", // nor is a control character
	} {
		out, ok := redactRemoteURL(raw)
		require.False(t, ok, "a value that cannot be a host must not be recorded as one: %q", raw)
		require.Empty(t, out)
	}
}

// TestAFileURLKeepsItsEmptyAuthority is the carve-out the rule above needs.
// "file:///srv/git/repo.git" is a real local remote whose authority is empty by
// definition; git reads it as PROTO_FILE, not as a network endpoint, and it has
// no place to put a credential. Refusing every empty authority would drop it.
func TestAFileURLKeepsItsEmptyAuthority(t *testing.T) {
	out, ok := redactRemoteURL("file:///srv/git/repo.git")
	require.True(t, ok, "a file:// remote is local, not a network URL with a missing host")
	require.Equal(t, "file:///srv/git/repo.git", out)
}

// TestALocalPathKeepsWhatCannotHideAnAuthority covers the third form. A path
// with no colon has no authority to hide a credential in, so an at-sign in it
// belongs to the NAME and must survive; a path holding both a colon and an
// at-sign is the same ambiguity as above and is refused.
func TestALocalPathKeepsWhatCannotHideAnAuthority(t *testing.T) {
	kept := []string{
		"/srv/git/repo.git",
		"/srv/git/a@b.git",
		"../mirror",
		"/srv/git/a:b.git", // a colon, but no at-sign: nothing here can be userinfo
	}
	for _, raw := range kept {
		out, ok := redactRemoteURL(raw)
		require.True(t, ok, "a local path with no authority to hide must survive: %q", raw)
		require.Equal(t, raw, out)
	}

	refused := []string{
		"acme/alice:" + sweepSecret + "@github.com:repo.git",
		"a/b@example.com:" + sweepSecret + ".git",
	}
	for _, raw := range refused {
		out, ok := redactRemoteURL(raw)
		require.False(t, ok, "a path holding both a colon and an at-sign is unclassifiable: %q", raw)
		require.Empty(t, out)
	}
}

// THE REMOTE-HELPER FORM — testifysec/judge#9188.
//
// `transport::address` is git's fourth remote spelling and the classifier could
// not reach it: the URL branch requires a literal "://" and this form carries
// "::" with no slashes, so `ext::helper --token SECRET` fell through to scp,
// where "ext" read as a host and `--token SECRET` was ordinary path text with
// no colon before an at-sign for pathIsCredentialFree to object to. Measured on
// the head before the fix, in this package:
//
//	redactRemoteURL("ext::helper --token SECRET")
//	  -> "ext::helper --token SECRET", ok=true
//
// The failure direction is fail-OPEN — nothing errors, the token is simply
// recorded — and evidence is the one artifact that cannot be retracted after
// publication.
//
// It is enumerated rather than fixtured for the reason the file header already
// records: every earlier finding in this class arrived as a NEW SPELLING that
// walked around the last fixture. A case on the one string the issue quotes
// would pass and the class would come back at `fd::`, at a tab instead of a
// space, or at the secret in a different argument position. The property
// asserted below is a universal over the whole form, not an example of it.

// remoteHelperTransports enumerates the left half of `transport::address`: git
// reads any token before "::" as a helper name and execs `git-remote-<name>`,
// so the set is open and the classifier must not depend on recognising members
// of it.
var remoteHelperTransports = []string{
	"ext",            // git's own generic helper: the address IS a command line
	"fd",             // git's other built-in helper
	"transport",      // the literal form name, as documentation spells it
	"hg",             // git-remote-hg, the most common third-party helper
	"bzr",            // git-remote-bzr
	"gcrypt",         // git-remote-gcrypt
	"myhelper",       // a single label with no dots — nothing host-shaped about it
	"EXT",            // case must not change the answer in either direction
	"git-remote-foo", // hyphens are legal in a helper name
	"a",              // one character
	"h2",             // digits
	" ext",           // a leading space, which defeats scheme detection outright
}

// remoteHelperAddresses enumerates the right half. For `ext::` and `fd::` the
// address is an arbitrary COMMAND LINE, which is exactly where a long-lived
// token gets pasted — so the secret is planted at the front, the middle and the
// end of the argument list, attached to its flag three different ways, and
// separated by spaces, by tabs and by nothing at all.
var remoteHelperAddresses = []string{
	"helper --token " + sweepSecret,            // the string #9188 reports
	"--token " + sweepSecret + " helper",       // the secret in the FIRST argument
	"helper " + sweepSecret,                    // a bare positional secret
	"helper --password=" + sweepSecret,         // attached to its flag by '='
	"helper -p" + sweepSecret,                  // attached with no separator at all
	"helper\t--token\t" + sweepSecret,          // tabs rather than spaces
	"helper --token " + sweepSecret + " %G %S", // the secret in the MIDDLE
	sweepSecret,                            // no command at all, just the secret
	"'helper --token " + sweepSecret + "'", // quoted as one shell word
	"\"helper --token " + sweepSecret + "\"",
	"git-remote-https https://u:" + sweepSecret + "@github.com/acme/api.git",
	"ssh -o Password=" + sweepSecret + " %S acme/api.git",
	"https://u:" + sweepSecret + "@github.com/acme/api.git", // an address that IS a URL
	"/usr/local/bin/helper --token " + sweepSecret,          // an absolute helper path
	"7," + sweepSecret,            // the fd:: shape
	"helper[" + sweepSecret + "]", // balanced brackets in an argument
}

// TestNoTransportAddressRemoteReachesEvidenceWithItsCommandLineIntact is the
// sweep.
//
// FOR EVERY string in transports x addresses, two things must hold: the string
// is classified as the helper form rather than falling through to scp or local,
// and it is REFUSED rather than recorded.
//
// The CLASSIFICATION assertion is not decoration, and it is why this sweep is
// sensitive to the fix rather than partly green without it. Several of these
// spellings were already refused before the helper form existed — but for an
// unrelated reason, because an '@' happened to sit downstream of a colon in the
// helper's arguments. Asserting the form distinguishes "refused because git
// calls this a helper" from "refused by coincidence", and only the first
// survives the next spelling that has no '@' in it.
//
// REFUSED, not stripped, consistent with the rest of #9177: the address is an
// arbitrary helper invocation, so there is no authority in it to locate and
// nothing in it that can be shown to be credential-free. A redactor that cannot
// name the credential's boundary has nothing to strip.
func TestNoTransportAddressRemoteReachesEvidenceWithItsCommandLineIntact(t *testing.T) {
	checked := 0

	for _, transport := range remoteHelperTransports {
		for _, address := range remoteHelperAddresses {
			raw := transport + "::" + address
			checked++

			form, _, _ := classifyRemote(raw)
			require.Equal(t, remoteFormHelper, form,
				"a transport::address remote must be classified as the helper form, not fall "+
					"through to scp or local: %q", raw)

			out, ok := redactRemoteURL(raw)
			require.False(t, ok,
				"a remote helper's command line reached the attestation: %q -> %q", raw, out)
			require.Empty(t, out,
				"a refused remote must yield no value: %q", raw)
		}
	}

	t.Logf("swept %d spellings", checked)
	require.Greater(t, checked, 150,
		"the sweep must enumerate its space; a shrunken cross product is not a sweep")
}

// TestADoubleColonThatIsNotAHelperKeepsItsRemote is the OVER-refusal control,
// and the sweep above is worthless without it.
//
// "::" appears in two ordinary remotes that have nothing to do with helpers: a
// bracketed IPv6 literal is full of them, and a filename may simply contain
// one. A fix written as `strings.Contains(raw, "::")` passes every case in the
// sweep and silently deletes `git@[2001:db8::1]:acme/api.git` from the
// evidence — dropping a real remote is the other way this function fails, and
// the reason the helper test sits AFTER the local-path rule in classifyRemote
// rather than before it.
//
// The forms are asserted, not just the acceptance, so a string that survives
// for the wrong reason is still a failure.
func TestADoubleColonThatIsNotAHelperKeepsItsRemote(t *testing.T) {
	for _, tt := range []struct {
		raw  string
		form remoteForm
	}{
		// A leading slash has already settled the question: git reads a path,
		// and "a::b.git" is a filename (#9186 review round 2 reached this from
		// the other direction, with an unterminated bracket).
		{"/srv/git/a::b.git", remoteFormLocal},
		{"./a::b.git", remoteFormLocal},
		{"acme/a::b.git", remoteFormLocal},
		// The colons here are inside an IPv6 literal, where they are address
		// bytes rather than delimiters of anything.
		{"git@[2001:db8::1]:acme/api.git", remoteFormSCP},
		{"git@[::1]:repo.git", remoteFormSCP},
		{"ssh://git@[2001:db8::1]/acme/api.git", remoteFormURL},
	} {
		form, _, _ := classifyRemote(tt.raw)
		require.Equal(t, tt.form, form,
			"a '::' that is not git's helper separator must not change the form: %q", tt.raw)

		out, ok := redactRemoteURL(tt.raw)
		require.True(t, ok,
			"an ordinary remote that merely contains '::' must still be recorded: %q", tt.raw)
		require.NotEmpty(t, out)
	}
}
