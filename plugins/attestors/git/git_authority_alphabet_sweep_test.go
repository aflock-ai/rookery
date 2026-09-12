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
)

// Round 6 closed two holes that every earlier round's guard walked past.
//
// PERCENT-ENCODING hides the delimiters the guards locate. "%3A" is a colon the
// port test never sees and "%40" is an at-sign the userinfo cut never finds, so
// the authority boundary lands somewhere else and a credential is recorded as a
// hostname. MULTI-AT-SIGN defeated the round-5 gate a different way: it asked
// whether a userinfo had been consumed, which is a fact about the span that was
// REMOVED and says nothing about the span that was kept.
//
// Both are pre-existing rather than regressions. The pre-PR parser (raw
// url.Parse at merge-base 65c320c361ca) leaked every shape below: the
// single-encoded ones errored out of url.Parse and were recorded VERBATIM by
// the fail-open path that #8950 exists to close, the double-encoded ones parsed
// cleanly and had no userinfo to strip, and the multi-at-sign one had "alice@"
// consumed exactly as round 5 did.
const alphabetCanary = "ghs_CANARY"

// encodedColons and encodedAts are the SPELLINGS of the two delimiters that
// decide an authority. Case-varied and double-encoded rows are both present on
// purpose: they are what makes decoding the wrong answer. A decoder must choose
// how many layers to peel, and "%253A" survives one pass as "%3A"; the guard
// refuses the CHARACTER instead and is therefore indifferent to depth.
var encodedColons = []string{"%3A", "%3a", "%253A"}
var encodedAts = []string{"%40", "%2540"}

// authorityPositions are the THREE places this file treats a span as an
// authority. The scp LOGIN is one of them and is easy to forget: it is recorded
// verbatim, so a percent that moves the delimiter in a login is recorded whole.
// A mutation neutering the login guard survived an earlier draft of this sweep
// that only covered the other two — a NO-OP mutant is a coverage gap, not a
// pass, so the position was added until the mutant died.
var authorityPositions = []struct {
	name  string
	build func(authority string) string
}{
	{"url-authority", func(a string) string { return "https://" + a + "/acme/api.git" }},
	{"scp-host", func(a string) string { return "git@" + a + ":acme/api.git" }},
	{"scp-login", func(a string) string { return a + "@github.com:acme/api.git" }},
}

const expectedAlphabetSweepSize = 3 * 3 * 2 // positions x colon spellings x at spellings

func alphabetSweepCases() []string {
	cases := make([]string, 0, expectedAlphabetSweepSize)
	for _, pos := range authorityPositions {
		for _, colon := range encodedColons {
			for _, at := range encodedAts {
				cases = append(cases, pos.build("alice"+colon+alphabetCanary+at+"github.com"))
			}
		}
	}
	return cases
}

// TestNoPercentEncodedAuthorityDelimiterEverHidesACredential is round 6's first
// universal.
//
// NO remote may reach evidence with a credential intact because a delimiter
// inside its authority was percent-encoded — for every authority position,
// every spelling of the encoded colon, and every spelling of the encoded
// at-sign, at any encoding depth.
//
// Measured on 8e1e8100, 6 of 6 probe shapes recorded the credential:
//
//	"https://alice%3Aghs_CANARY%40github.com/acme/api.git"     -> VERBATIM
//	"https://alice%3aghs_CANARY%40github.com/acme/api.git"     -> VERBATIM
//	"https://alice%253Aghs_CANARY%2540github.com/acme/api.git" -> VERBATIM
//	"git@%5Bghs_CANARY%5D:acme/api.git"                        -> VERBATIM
func TestNoPercentEncodedAuthorityDelimiterEverHidesACredential(t *testing.T) {
	cases := alphabetSweepCases()
	if len(cases) != expectedAlphabetSweepSize {
		t.Fatalf("sweep enumerated %d cases, want %d: the product is not being generated, so a pass here would prove nothing", len(cases), expectedAlphabetSweepSize)
	}

	for _, remote := range cases {
		t.Run(remote, func(t *testing.T) {
			recorded, ok := redactRemoteURL(remote)
			if ok && strings.Contains(recorded, alphabetCanary) {
				t.Fatalf("a percent-hidden credential reached signed evidence\n  remote:   %q\n  recorded: %q", remote, recorded)
			}
		})
	}
}

// TestPercentEncodedBracketsCannotSmuggleAnAuthority covers the other delimiter
// pair. Round 5 refused a literal "[ghs_TOKEN]@host"; encoding the brackets
// walked straight past that check, which is the same lesson in a second place:
// a rule that reads characters must see the characters.
func TestPercentEncodedBracketsCannotSmuggleAnAuthority(t *testing.T) {
	for _, remote := range []string{
		"git@%5B" + alphabetCanary + "%5D:acme/api.git",
		"https://%5B" + alphabetCanary + "%5D/acme/api.git",
		"https://alice%5Brealm%3A" + alphabetCanary + "%5D/acme/api.git",
		"%5B" + alphabetCanary + "%5D@github.com:acme/api.git",
	} {
		t.Run(remote, func(t *testing.T) {
			recorded, ok := redactRemoteURL(remote)
			if ok && strings.Contains(recorded, alphabetCanary) {
				t.Fatalf("percent-encoded brackets smuggled a credential: %q -> %q", remote, recorded)
			}
		})
	}
}

// multiAtPrefixes consume one, two and three userinfo spans. The round-5 gate
// declared the remainder unambiguous after the FIRST, which is the defect.
var multiAtPrefixes = []string{"alice@", "a@b@", "x@y@z@"}

const expectedMultiAtSweepSize = 3 * 3 // prefixes x terminators

func multiAtSweepCases() []string {
	cases := make([]string, 0, expectedMultiAtSweepSize)
	for _, prefix := range multiAtPrefixes {
		for _, terminator := range authorityTerminators {
			cases = append(cases, "https://"+prefix+alphabetCanary+terminator+"part@github.com/acme/api.git")
		}
	}
	return cases
}

// TestNoNumberOfConsumedUserinfoSpansMakesTheRemainderSafe is round 6's second
// universal.
//
// NO remote may reach evidence with a credential intact because a userinfo span
// was already consumed — for any number of at-signs and any authority
// terminator. Measured on 8e1e8100:
//
//	"https://alice@ghs_CANARY/part@github.com/acme/api.git"
//	  -> ok=true "https://ghs_CANARY/part@github.com/acme/api.git"
//	"https://a@b@ghs_CANARY/part@github.com/acme/api.git"
//	  -> ok=true "https://ghs_CANARY/part@github.com/acme/api.git"
//
// The fix deletes the gate rather than adding a second pass, because a
// single-pass assumption on a multi-occurrence input is not repaired by one
// more pass.
func TestNoNumberOfConsumedUserinfoSpansMakesTheRemainderSafe(t *testing.T) {
	cases := multiAtSweepCases()
	if len(cases) != expectedMultiAtSweepSize {
		t.Fatalf("sweep enumerated %d cases, want %d: the product is not being generated, so a pass here would prove nothing", len(cases), expectedMultiAtSweepSize)
	}

	for _, remote := range cases {
		t.Run(remote, func(t *testing.T) {
			recorded, ok := redactRemoteURL(remote)
			if ok && strings.Contains(recorded, alphabetCanary) {
				t.Fatalf("a consumed userinfo span was mistaken for safety\n  remote:   %q\n  recorded: %q", remote, recorded)
			}
		})
	}
}

// TestAPercentOutsideAnAuthoritySurvives is the over-refusal control for round
// 6, and it is the half that makes the percent rule AUTHORITY-SCOPED rather
// than a blanket ban.
//
// A percent outside an authority is an ordinary byte of a name. A whole-string
// percent rule would delete every remote below, including two that the pre-PR
// parser also kept, so the scope is not a refinement — it is the difference
// between a guard and an outage.
func TestAPercentOutsideAnAuthoritySurvives(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote string
		want   string
		wantOK bool
	}{
		{"invalid escape in url path", "https://github.com/acme/api%zz.git", "https://github.com/acme/api%zz.git", true},
		{"space escape in url path", "https://github.com/acme/api%20one.git", "https://github.com/acme/api%20one.git", true},
		{"escape in scp path", "git@github.com:acme/api%20one.git", "git@github.com:acme/api%20one.git", true},
		{"escape in local path", "/srv/git/repo%20one.git", "/srv/git/repo%20one.git", true},
		{"escape in a query is cut with the query", "https://github.com/acme/api.git?a=%20b", "https://github.com/acme/api.git", true},

		// The userinfo may hold a percent freely: it is being DELETED, so what
		// it encodes never reaches evidence. This is a real GitHub spelling.
		{"encoded at-sign in userinfo", "https://alice%40corp:ghs_TOK@github.com/acme/api.git", "https://github.com/acme/api.git", true},

		// Ordinary CI forms, unaffected.
		{"github actions", "https://x-access-token:ghs_TOK@github.com/acme/api.git", "https://github.com/acme/api.git", true},
		{"gitlab oauth2", "https://oauth2:glpat_TOK@gitlab.com/acme/api.git", "https://gitlab.com/acme/api.git", true},
		{"azure devops", "https://org@dev.azure.com/org/proj/_git/repo", "https://dev.azure.com/org/proj/_git/repo", true},

		// IP literals and ports still work.
		{"ipv6 scp", "git@[2001:db8::1]:acme/api.git", "git@[2001:db8::1]:acme/api.git", true},
		{"ipv6 url with port", "https://[2001:db8::1]:443/acme/api.git", "https://[2001:db8::1]:443/acme/api.git", true},
		{"explicit port", "https://github.com:8443/acme/api.git", "https://github.com:8443/acme/api.git", true},

		// KNOWN COST, PINNED SO IT CANNOT CHANGE SILENTLY: an IPv6 zone
		// identifier is spelled with a percent, so a link-local remote is
		// refused. Raised with the sibling attestor's lane rather than decided
		// here; if it is ever allowed, the remedy is a carve-out inside
		// bracketsAreAnIPLiteral, never a loosening of the character rule.
		{"ipv6 zone id is refused (known cost)", "https://[fe80::1%25eth0]/repo.git", "", false},

		// KNOWN COST: an scp login that genuinely contains a percent.
		{"percent in scp login is refused (known cost)", "git%40corp@github.com:acme/api.git", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := redactRemoteURL(tc.remote)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("redactRemoteURL(%q) = (%q, %v), want (%q, %v)", tc.remote, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestAuthorityAlphabetIsSafeGuardsTheCharacter pins the predicate directly, so
// that a mutant swapping it for an escape TABLE is killed at the unit as well
// as end to end. A table enumerates the encodings someone thought of; the next
// spelling is the one that was not listed, which is why the character is the
// rule.
func TestAuthorityAlphabetIsSafeGuardsTheCharacter(t *testing.T) {
	for _, tc := range []struct {
		component string
		want      bool
	}{
		{"github.com", true},
		{"github.com:443", true},
		{"[2001:db8::1]", true},
		{"", true},
		{"alice-corp_1.example.com", true},

		{"alice%3Atoken", false},
		{"alice%3atoken", false},
		{"alice%253Atoken", false},
		{"alice%40github.com", false},
		{"%5Btoken%5D", false},
		{"[fe80::1%25eth0]", false}, // the known cost, stated as a property
		{"host%", false},            // a bare percent is not an escape at all
	} {
		t.Run(tc.component, func(t *testing.T) {
			if got := authorityAlphabetIsSafe(tc.component); got != tc.want {
				t.Fatalf("authorityAlphabetIsSafe(%q) = %v, want %v", tc.component, got, tc.want)
			}
		})
	}
}
