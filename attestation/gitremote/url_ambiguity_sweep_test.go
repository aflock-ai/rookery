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
)

// Round 5 found that the round-4 guard, authorityIsHostAndPort, is confidently
// WRONG on exactly the class it was aimed at, because it asks a question about
// the PORT and the leaking shapes have no port to ask about.
//
//	a bare PAT       "ghp_TOKEN"   has no colon, so "no port" reads as host-only
//	a numeric secret "alice:12345" has a port made of digits, so it reads as host:port
//
// Neither can be told from a real host by SHAPE — "ghp_TOKEN" is spelled
// exactly like a single-label host such as "myserver", and "alice:12345"
// exactly like "github.com:8443". So the sweep below crosses the CREDENTIAL
// SHAPE with the terminator, and the fix it pins is not a sharper shape test:
// it is redactURLRemote's disagreement rule, which refuses the string because
// its two readings disagree rather than because either looks wrong.
const numericCanary = "987654321"

// credentialShapesR5 spans the userinfo spellings a real credential wears. The
// last three are the round-5 additions: the two with no colon at all, which the
// port test cannot see, and the numeric password, which it actively approves.
var credentialShapesR5 = []struct {
	name     string
	userinfo string
	secret   string
}{
	{"user-and-password", "alice:" + terminatorCanary, terminatorCanary},
	{"empty-user", ":" + terminatorCanary, terminatorCanary},
	{"github-actions", "x-access-token:" + terminatorCanary, terminatorCanary},
	{"gitlab-oauth2", "oauth2:" + terminatorCanary, terminatorCanary},
	{"encoded-at-in-user", "alice%40corp:" + terminatorCanary, terminatorCanary},
	{"token-only", terminatorCanary, terminatorCanary},
	{"dotted-token", "git.corp." + terminatorCanary, "git.corp." + terminatorCanary},
	{"numeric-password", "alice:" + numericCanary, numericCanary},
}

// urlSchemesR5 are the scheme'd forms. The sweep is deliberately URL-ONLY.
//
// In the scp and local forms a bare token lands in the LOGIN position, and this
// file's standing doctrine is that a login is a routing value rather than a
// credential — kept on purpose, cost stated out loud, because ssh dials on it.
// On top of that, what those forms then record is decided by the query/fragment
// cut, which is the OPEN product question in reviewer finding 1 (whether
// "git@example.com:repo#release.git" may be recorded as a repository that does
// not exist). Sweeping them here would assert an answer to a question this
// branch has deliberately left to a human, so it does not.
var urlSchemesR5 = []string{"https://", "http://", "ssh://", "git://", "file://"}

// terminatorFillersR5 is what sits between the terminator and the '@'. There
// are two rather than the three placements used by the round-4 sweep: its third
// placement splits the secret, which needs a secret that can be cut in half,
// and a numeric password cut in half is no longer numeric — it would stop
// exercising the very shape this sweep exists for.
var terminatorFillersR5 = []string{"", "junk"}

// expectedR5SweepSize pins the product so a loop that silently stops
// enumerating cannot pass by testing nothing.
const expectedR5SweepSize = 5 * 8 * 3 * 2 // schemes x shapes x terminators x fillers

type r5Case struct{ remote, secret string }

func r5SweepCases() []r5Case {
	cases := make([]r5Case, 0, expectedR5SweepSize)
	for _, scheme := range urlSchemesR5 {
		for _, shape := range credentialShapesR5 {
			for _, terminator := range authorityTerminators {
				for _, filler := range terminatorFillersR5 {
					cases = append(cases, r5Case{
						remote: scheme + shape.userinfo + terminator + filler + "@github.com/acme/api.git",
						secret: shape.secret,
					})
				}
			}
		}
	}
	return cases
}

// TestNoURLWhoseAuthorityAndUserinfoReadingsDisagreeEverRecordsTheCredential is
// round 5's universal.
//
// NO scheme'd remote in which the authority carries no userinfo delimiter and
// an at-sign sits downstream may reach evidence with any part of the credential
// intact — for every credential shape, every RFC 3986 authority terminator, and
// every position the terminator can take.
//
// Measured on 9a5d6966 (the round-4 head), 7 of 7 probe shapes drawn from this
// product recorded the credential:
//
//	"https://ghp_CANARY?x@github.com/acme/api.git"      -> "https://ghp_CANARY"
//	"https://ghp_CANARY/x@github.com/acme/api.git"      -> recorded VERBATIM
//	"https://alice:987654321?x@github.com/acme/api.git" -> "https://alice:987654321"
//	"https://alice:987654321/x@github.com/acme/api.git" -> recorded VERBATIM
func TestNoURLWhoseAuthorityAndUserinfoReadingsDisagreeEverRecordsTheCredential(t *testing.T) {
	cases := r5SweepCases()
	if len(cases) != expectedR5SweepSize {
		t.Fatalf("sweep enumerated %d cases, want %d: the product is not being generated, so a pass here would prove nothing", len(cases), expectedR5SweepSize)
	}

	for _, tc := range cases {
		t.Run(tc.remote, func(t *testing.T) {
			recorded, ok := redactRemoteURL(tc.remote)
			if !ok {
				return // refused: nothing reaches evidence
			}
			if strings.Contains(recorded, tc.secret) {
				t.Fatalf("credential reached signed evidence\n  remote:   %q\n  recorded: %q\n  secret:   %q", tc.remote, recorded, tc.secret)
			}
		})
	}
}

// TestBracketsOutsideAnIPLiteralAreRefused pins round 5's second mechanism.
//
// A colon hidden inside brackets is invisible to colonOutsideBrackets by
// design — that is what makes "git@[2001:db8::1]:acme/api.git" work — so
// authorityIsHostAndPort reads "alice[realm:ghs_TOKEN]" as a host with no port
// and passes the token through. Every shape below was measured recorded
// VERBATIM on 9a5d6966.
func TestBracketsOutsideAnIPLiteralAreRefused(t *testing.T) {
	for _, remote := range []string{
		"https://alice[realm:ghs_CANARY]/repo.git",
		"https://alice[realm:ghs_CANARY]/part@github.com/repo.git",
		"https://alice[realm:ghs_CANARY]?x@github.com/repo.git",
		"https://alice[realm:ghs_CANARY]#x@github.com/repo.git",
		"[ghs_CANARY]@github.com:acme/api.git",
		"[ghs_CANARY]@github.com/acme/api.git",
		"https://[2001:db8::1]extra/repo.git",
	} {
		t.Run(remote, func(t *testing.T) {
			recorded, ok := redactRemoteURL(remote)
			if ok {
				t.Fatalf("a bracket outside an IP literal was recorded: %q -> %q", remote, recorded)
			}
		})
	}
}

// TestBracketsAreAnIPLiteralAsksWhereNotWhat pins the predicate directly: it is
// a question about POSITION, never about the bytes inside. "[not-an-address]"
// passes because the grammar allows a bracket there; deciding whether the
// contents parse as IPv6 would be the spelling question this file refuses.
func TestBracketsAreAnIPLiteralAsksWhereNotWhat(t *testing.T) {
	for _, tc := range []struct {
		component string
		want      bool
	}{
		{"github.com", true},
		{"", true},
		{"[2001:db8::1]", true},
		{"[::1]", true},
		{"[::1]:8080", true},       // a port is the only thing that may follow the literal
		{"[not-an-address]", true}, // position is legal; contents are not this test's question

		{"[2001:db8::1]extra", false}, // an IP literal ends the host; junk may not follow it

		{"alice[realm:tok]", false}, // does not open the component
		{"[2001:db8::1", false},     // never closes
		{"2001:db8::1]", false},     // closes without opening
		{"[a][b]", false},           // a second literal is not a host
		{"[a]junk]", false},         // a stray bracket after the literal
	} {
		t.Run(tc.component, func(t *testing.T) {
			if got := bracketsAreAnIPLiteral(tc.component); got != tc.want {
				t.Fatalf("bracketsAreAnIPLiteral(%q) = %v, want %v", tc.component, got, tc.want)
			}
		})
	}
}

// TestOrdinaryCredentialBearingRemotesStillSurviveRound5 is the over-refusal
// control, and it carries the COST of round 5 explicitly rather than leaving it
// implied. A rule that refuses ambiguity will happily refuse everything; these
// exact outputs are what stops it.
func TestOrdinaryCredentialBearingRemotesStillSurviveRound5(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote string
		want   string
		wantOK bool
	}{
		// The real CI forms. Every one has a genuine userinfo delimiter inside
		// its authority, so nothing about them is ambiguous and the credential
		// is stripped rather than the remote dropped.
		{"github actions", "https://x-access-token:ghs_TOK@github.com/acme/api.git", "https://github.com/acme/api.git", true},
		{"gitlab oauth2", "https://oauth2:glpat_TOK@gitlab.com/acme/api.git", "https://gitlab.com/acme/api.git", true},
		{"azure devops", "https://org@dev.azure.com/org/proj/_git/repo", "https://dev.azure.com/org/proj/_git/repo", true},
		{"empty password", "https://alice:@github.com/acme/api.git", "https://github.com/acme/api.git", true},
		{"empty user and password", "https://:@github.com/acme/api.git", "https://github.com/acme/api.git", true},
		{"bitbucket app password", "https://alice:ATBB_TOK@bitbucket.org/acme/api.git", "https://bitbucket.org/acme/api.git", true},

		// THE TWO GRAMMARS DIFFER ON PURPOSE, and these four rows are where
		// that is pinned. In a URL an at-sign in the path is refused with a
		// login as well as without: round 5 exempted the login-bearing
		// spelling, and round 6 removed the exemption because consuming one
		// userinfo says nothing about the span that was kept. In scp syntax the
		// authority ends at the first colon BEFORE any at-sign is read, so the
		// login exemption is sound there and #9181 measured the remote as
		// must-survive.
		{"url at-sign path WITH login", "https://git@github.com/repo@release.git", "", false},
		{"url at-sign path WITHOUT login", "https://github.com/repo@release.git", "", false},
		{"ssh url at-sign path WITH login", "ssh://git@github.com/acme/repo@release.git", "", false},
		{"scp at-sign path WITH login SURVIVES", "git@example.com:repo@release.git", "git@example.com:repo@release.git", true},

		// Ports and IP literals must not be read as credentials.
		{"explicit port", "https://github.com:8443/acme/api.git", "https://github.com:8443/acme/api.git", true},
		{"ipv6 with port", "https://[2001:db8::1]:443/acme/api.git", "https://[2001:db8::1]:443/acme/api.git", true},
		{"ipv6 scp", "git@[2001:db8::1]:acme/api.git", "git@[2001:db8::1]:acme/api.git", true},

		// The scp and local forms are untouched by round 5.
		{"scp ordinary", "git@github.com:acme/api.git", "git@github.com:acme/api.git", true},
		{"scp at-sign in repo name", "git@example.com:repo@release.git", "git@example.com:repo@release.git", true},
		{"local path", "/srv/git/repo.git", "/srv/git/repo.git", true},
		{"local bracket no at-sign", "/srv/git/repo[1:2.git", "/srv/git/repo[1:2.git", true},
		{"local at-sign no colon or bracket", "/srv/git/a@b.git", "/srv/git/a@b.git", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := redactRemoteURL(tc.remote)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("redactRemoteURL(%q) = (%q, %v), want (%q, %v)", tc.remote, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}
