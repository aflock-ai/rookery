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
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// THE AUTHORITY-INTRODUCER SWEEP — testifysec/judge#9177, Codex 2026-09-12.
//
// The finding: "//ghp_SECRET@github.com/acme/api.git" reached signed evidence
// UNCHANGED. classifyRemote sent it to the local-path branch, and
// pathIsCredentialFree accepted it because the string holds neither ':' nor
// '['. Measured on the previous head of this branch, with the probe below run
// against recordRemote:
//
//	in="//ghp_SECRET@github.com/acme/api.git"  form=local verdict=clean
//	  recorded="//ghp_SECRET@github.com/acme/api.git"
//
// Before the rewrite, url.Parse recognised this as RFC 3986's NETWORK-PATH
// REFERENCE — an authority with the scheme left off — and clearing User removed
// the PAT. Reading the grammar directly gained that authority no reader.
//
// WHY THE EXISTING SWEEP DID NOT CATCH IT, which is the more useful half. The
// grammar sweep in git_remote_grammar_sweep_test.go builds every hostile string
// as `prefix + user + ":" + secret + "@" + host + sep + path`. That constant
// ":" is a COLON IN FRONT OF EVERY PLANTED SECRET — and the colon is exactly
// the byte pathIsCredentialFree keys on, so the sweep's own construction
// guaranteed the rule under test would fire. It could not reach the commonest
// PAT spelling in the wild: a token that is the WHOLE username, with no
// password and therefore no colon anywhere.
//
// A sweep whose generator can only emit strings the rule already handles is a
// tautology, so this file varies the USERINFO as its own dimension and crosses
// it with every delimiter that introduces an authority.
//
// SCOPE, STATED, because the universal does not hold over all forms: this
// quantifies over the prefixes that introduce an AUTHORITY, not over every
// remote prefix. In scp syntax a bare token before the '@' is the ssh LOGIN —
// "ghs_TOKEN@github.com:acme/api.git" is spelled identically to
// "git@github.com:acme/api.git", which #9181 measured as must-survive — so no
// rule can strip one without destroying the other. Where an authority
// INTRODUCER is present there is no login exemption to protect, and userinfo is
// userinfo under every reading.

// authorityIntroducers enumerates every delimiter that puts the bytes after it
// in an AUTHORITY position for some reader.
//
// The last entry is the finding. "//" is the network-path reference of RFC 3986
// §4.2: every URL reader finds an authority in the bytes up to the next '/',
// while git's connect.c finds a local path. The two readings disagree about
// whether anything in those bytes is secret, which is the disagreement this
// attestor answers by refusing.
var authorityIntroducers = []string{
	"https://",
	"HTTPS://",
	"ssh://",
	"git://",
	"git+ssh://",
	"//",
}

// credentialUserinfos enumerates the COMPLETE userinfo span — everything up to
// and INCLUDING its '@' — with sweepSecret somewhere inside it.
//
// The first entries are password-bearing, the shape the older sweep already
// covered. The rest are the blind spot: a credential with NO COLON AT ALL.
func credentialUserinfos() []string {
	out := make([]string, 0, len(credentialUsers)+4)
	for _, user := range credentialUsers {
		out = append(out, user+":"+sweepSecret+"@")
	}
	return append(out,
		// THE FINDING'S SHAPE: the token is the entire username. GitHub,
		// GitLab and Azure all accept a PAT pasted here with no password, and
		// mirror scripts write it this way because it is shorter.
		sweepSecret+"@",
		// The same with an EMPTY password. The colon is present but carries
		// nothing, so a rule keyed on "a colon before the at-sign" fires while
		// a rule keyed on "a password" does not.
		sweepSecret+":@",
		// Two at-signs, no colon: the cut must take the LAST one or half the
		// credential stays behind.
		sweepSecret+"@tail@",
		// Userinfo that is ONLY the delimiter, with the secret in front of a
		// second segment — a near-miss that must not be read as "no userinfo".
		"@"+sweepSecret+"@",
	)
}

// TestNoUserinfoSpellingSurvivesAnAuthorityIntroducer is the sweep.
//
// FOR EVERY string in authorityIntroducers x credentialUserinfos x hosts x
// separators x paths, the attestor must either refuse the remote outright or
// record one that does not contain the planted secret. There is no third
// answer and no exemption list.
func TestNoUserinfoSpellingSurvivesAnAuthorityIntroducer(t *testing.T) {
	checked := 0

	for _, introducer := range authorityIntroducers {
		for _, userinfo := range credentialUserinfos() {
			for _, host := range remoteHosts {
				for _, sep := range remoteSeparators {
					for _, path := range remotePaths {
						raw := introducer + userinfo + host + sep + path
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

	// The count is asserted so that a generator that silently stops producing
	// strings — an empty slice, a loop bound edited to zero — fails here rather
	// than reporting a green sweep over nothing.
	require.Equal(t, len(authorityIntroducers)*len(credentialUserinfos())*len(remoteHosts)*len(remoteSeparators)*len(remotePaths), checked)
	require.Greater(t, checked, 1000, "the sweep must actually enumerate the grammar")
}

// TestASchemeRelativeRemoteWithNoCredentialKeepsItsIdentity is the CONTROL.
//
// Refusing every string that begins with "//" would satisfy the sweep above and
// would be the wrong fix: `git remote add origin //fileserver/share/repo.git`
// is a real remote — a UNC path on Windows, an ordinary path elsewhere — and
// judge links a DSSE to a product by exactly these strings. Nothing in it is
// ambiguous: with no '@' in the would-be authority, the git reading and the RFC
// reading agree that it holds no credential, so it is recorded VERBATIM.
func TestASchemeRelativeRemoteWithNoCredentialKeepsItsIdentity(t *testing.T) {
	for _, raw := range []string{
		"//fileserver/share/repo.git",
		"//10.0.0.1/git/repo.git",
		// An '@' AFTER the would-be authority is part of the repository NAME
		// under both readings, so it survives. This is the case a blanket
		// "'//' plus an at-sign is refused" rule would lose.
		"//fileserver/share/repo@release.git",
		"//fileserver/team/repo.git",
	} {
		t.Run(raw, func(t *testing.T) {
			out, ok := redactRemoteURL(raw)
			require.True(t, ok, "a credential-free scheme-relative remote must be recorded: %q", raw)
			require.Equal(t, raw, out, "it must be recorded byte for byte")
		})
	}
}

// TestASchemeRelativeAuthorityIsRefusedRatherThanRewritten pins the DIRECTION
// of the fix, which the sweep above cannot see: "refused" and "redacted to
// //github.com/acme/api.git" both satisfy "the secret is gone".
//
// Refusal is the only defensible answer here. git does NOT read "//host/path"
// as a network authority — connect.c sends it to the local-path branch — so
// under git's own reading the repository is a directory literally named
// "ghp_SECRET@github.com", and stripping that prefix would name a repository
// git never uses. This file has already paid for that mistake once: an earlier
// pass "redacted" an scp-like string to github.com/acme/api.git and invented a
// host inside signed evidence. Where two readings disagree about whether bytes
// are secret, neither reading is imposed and nothing is recorded.
func TestASchemeRelativeAuthorityIsRefusedRatherThanRewritten(t *testing.T) {
	for _, raw := range []string{
		"//ghp_SECRET@github.com/acme/api.git",
		"//ghp_SECRET@github.com",
		"//x-access-token:ghs_SECRET@github.com/acme/api.git",
		"//user@[::1]/path",
		// PERCENT-ENCODED DELIMITERS. There is no literal '@' in this string at
		// all, so the at-sign test never fires; "%40" is an at-sign the
		// userinfo cut cannot find and "%3A" is the colon in front of it. The
		// authority checks on the URL branch already refuse a percent for this
		// reason (authorityAlphabetIsSafe); a would-be authority introduced by
		// "//" gets the same treatment rather than a second, weaker rule.
		"//alice%3Aghs_SECRET%40github.com/acme/api.git",
		"//ghs_SECRET%40github.com/acme/api.git",
	} {
		t.Run(raw, func(t *testing.T) {
			verdict, recorded, reason := recordRemote(raw)
			require.Equal(t, remoteRefused, verdict,
				"an ambiguous scheme-relative authority must be refused, not rewritten: %q -> %q", raw, recorded)
			require.Empty(t, recorded, "a refused remote records nothing")
			require.Equal(t, refusalAmbiguousAuthority, reason,
				"the refusal must be attributable to the authority rule")
			require.NotContains(t, reason, "SECRET",
				"the refusal trace must never carry a byte of the refused string")
		})
	}
}

// TestTheSchemeRelativeRuleIsTheSharedPathRule pins that the fix landed in the
// ONE function all three record branches call, rather than in the local branch
// alone.
//
// This is the lesson round nine of #9177 already wrote down: the scp branch and
// the local branch each held their own spelling of the credential rule, and the
// leak lived in the gap between them. A fix applied to recordLocalRemote only
// would leave the identical string reachable through an scp path
// ("git@host://ghp_SECRET@evil/x"), so the property is asserted on
// pathIsCredentialFree itself.
func TestTheSchemeRelativeRuleIsTheSharedPathRule(t *testing.T) {
	require.False(t, pathIsCredentialFree("//ghp_SECRET@github.com/acme/api.git"),
		"a scheme-relative authority holding userinfo is not credential-free")
	require.False(t, pathIsCredentialFree("//ghp_SECRET%40github.com/x"),
		"a percent-encoded delimiter in a scheme-relative authority is not credential-free")
	require.True(t, pathIsCredentialFree("//fileserver/share/repo.git"),
		"a scheme-relative path with no userinfo is credential-free")
	require.True(t, pathIsCredentialFree("/srv/git/a@b.git"),
		"an at-sign in an ordinary path is part of the repository name")

	// Reached through the scp branch rather than the local one: the path half
	// of an scp remote takes the same test.
	verdict, recorded, _ := recordRemote("git@host://ghp_SECRET@evil.example/x.git")
	require.Equal(t, remoteRefused, verdict,
		"the scp path half takes the same rule: %q", recorded)
	require.NotContains(t, recorded, "ghp_SECRET")
}

// TestNoAuthorityIntroducerCarriesAUserinfoSpellingIntoSignedEvidence is the
// same universal asserted at the level the finding actually names.
//
// The sweep above reads recordRemote, which is one function call away from the
// attestation. This one runs the REAL attestor over a real repository and walks
// every string in the MARSHALLED envelope, because "reaches signed evidence" is
// a claim about what gets signed and not about what a helper returns. A future
// edit that routes remotes around recordRemote — a second recording site, a
// field that stashes the raw config — is invisible to a function-level sweep
// and fails here.
//
// The cross-product is smaller than the one above on purpose: each case builds
// a git repository on disk, so the set is the two dimensions that carry the
// finding (introducer x userinfo shape) with the host, separator and path held
// fixed. The function-level sweep covers the rest.
func TestNoAuthorityIntroducerCarriesAUserinfoSpellingIntoSignedEvidence(t *testing.T) {
	const secret = "ghs_s3cr3tTOKENvalue"

	userinfos := []string{
		secret + "@",                     // the token is the whole username
		"x-access-token:" + secret + "@", // what GitHub Actions writes
		":" + secret + "@",               // no username at all, Azure's spelling
		secret + ":@",                    // token as username, empty password
	}

	for _, introducer := range authorityIntroducers {
		for _, userinfo := range userinfos {
			raw := introducer + userinfo + "github.com/acme/api.git"
			t.Run(raw, func(t *testing.T) {
				attestor := runWithRemote(t, raw)

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
}

// TestAURLPathThatOpensADoubleSlashOntoAPercentIsRefused pins the KNOWN COST of
// putting the scheme-relative rule in the shared path function rather than in a
// second copy that runs only on a whole remote.
//
// "https://github.com//a%40b.git" is a URL path, not a network-path reference:
// the authority was already consumed by the scheme, so the "//" here introduces
// nothing. The shared rule refuses it anyway, because it cannot tell which span
// it was handed. That is the trade this file made on purpose — one rule three
// callers share beats two rules that drift apart — and a cost is only a trade
// if it is written down and asserted, so it is asserted here.
//
// The neighbouring spellings are asserted alongside it, because the cost has to
// be NARROW to be acceptable: a single slash is untouched, and an ordinary
// double-slashed path with no percent still records.
func TestAURLPathThatOpensADoubleSlashOntoAPercentIsRefused(t *testing.T) {
	_, ok := redactRemoteURL("https://github.com//a%40b.git")
	require.False(t, ok, "the stated over-refusal must actually be the behaviour")

	for _, raw := range []string{
		"https://github.com/a%40b.git",     // ONE slash: untouched
		"https://github.com//acme/api.git", // two slashes, no percent: untouched
		"https://github.com/acme//api.git", // the double slash deeper in: untouched
	} {
		out, ok := redactRemoteURL(raw)
		require.True(t, ok, "the over-refusal must not reach an ordinary URL path: %q", raw)
		require.Equal(t, raw, out, "and must not rewrite one either")
	}
}

// TestTheAuthorityIntroducerSetCoversEveryDelimiterTheClassifierKnows is the
// ANTI-DRIFT check on the sweep's own generator.
//
// A sweep is only as strong as the set it quantifies over, and this one names
// its introducers as literals. If a new scheme or delimiter is taught to
// classifyRemote and not added here, the sweep keeps passing while covering
// less — the failure mode that let "//" through in the first place. So every
// introducer listed must actually classify as a URL or as a path-with-authority
// today, which is the property that makes the list meaningful.
func TestTheAuthorityIntroducerSetCoversEveryDelimiterTheClassifierKnows(t *testing.T) {
	for _, introducer := range authorityIntroducers {
		t.Run(introducer, func(t *testing.T) {
			raw := introducer + "github.com/acme/api.git"
			form, _, _ := classifyRemote(raw)
			if strings.Contains(introducer, "://") {
				require.Equal(t, remoteFormURL, form,
					"a scheme'd introducer must reach the URL branch")
				return
			}
			require.Equal(t, remoteFormLocal, form,
				"a scheme-LESS authority introducer reaches the path branch, which is why the path rule must know about it")
		})
	}
}
