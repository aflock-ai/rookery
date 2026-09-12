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
	"fmt"
	"strings"
	"testing"
)

// Four rounds of review on this branch have found the same defect wearing four
// spellings: the authority was computed correctly and the thing NEXT to it was
// not. The path (round 1), the URL authority (round 2), the login (round 3),
// and now the byte that TERMINATES the authority. Four instance tests failed to
// kill it, so this file does not test instances.
//
// It quantifies over a closed set instead. RFC 3986 §3.2 says an authority runs
// until the next "/", "?" or "#", or the end of the URI — three bytes, and
// there is no fourth. cutRemoteAuthority splits on exactly those three, and
// cutRemoteQueryAndFragment cuts on two of them. So "a delimiter between the
// credential and its '@'" is not an open-ended class of inputs; it is a finite
// product, and the sweep below is that product enumerated.
//
// The canaries are the assertion. Each one is planted where a password goes and
// nowhere else, so "the recorded remote contains a canary" is exactly "a
// credential reached signed evidence" with no interpretation in between.
const (
	terminatorCanary      = "LEAKCANARY"
	terminatorCanaryLeft  = "LEFTCANARY"
	terminatorCanaryRight = "RIGHTCANARY"
)

// authorityTerminators is the COMPLETE set of bytes that end an authority under
// RFC 3986 §3.2. It is spelled out here, rather than derived, because its
// completeness is the whole claim the sweep rests on: if a fourth terminator
// existed, quantifying over these three would prove nothing.
var authorityTerminators = []string{"/", "?", "#"}

// credentialShapes are the userinfo prefixes that precede the secret. The
// GitHub Actions shape ("x-access-token:") is the one that carries a live token
// in real CI checkouts and is the reason this function exists (#8950).
var credentialShapes = []string{
	"alice:",
	":",
	"x-access-token:",
	"oauth2:",
	"alice%40corp:",
}

// remoteFormTemplates spell the three git remote forms. %s takes the userinfo,
// so every form is exercised with every credential and every terminator: the
// scp and local branches hand their input back unmodified, which is precisely
// why a credential that survives into them is recorded verbatim.
var remoteFormTemplates = []string{
	"https://%s@github.com/acme/api.git",
	"http://%s@github.com/acme/api.git",
	"ssh://%s@github.com/acme/api.git",
	"git://%s@github.com/acme/api.git",
	"file://%s@github.com/acme/api.git",
	"%s@github.com:acme/api.git",
	"/srv/%s@repo.git",
}

// terminatorPlacements put the terminator in each position it can occupy
// between the secret and the '@' that delimits it. The third splits the secret,
// which is what catches a redactor that truncates rather than refuses: cutting
// at the terminator leaves the FIRST half of the password in evidence, and a
// single whole-secret canary would score that as clean.
var terminatorPlacements = []struct {
	name  string
	build func(shape, terminator string) string
}{
	{
		name:  "terminator-immediately-after-secret",
		build: func(shape, t string) string { return shape + terminatorCanary + t },
	},
	{
		name:  "terminator-then-text-before-at-sign",
		build: func(shape, t string) string { return shape + terminatorCanary + t + "junk" },
	},
	{
		name:  "terminator-splits-the-secret",
		build: func(shape, t string) string { return shape + terminatorCanaryLeft + t + terminatorCanaryRight },
	},
}

// expectedTerminatorSweepSize pins the size of the product so that a loop which
// silently stops enumerating cannot pass by testing nothing. 7 forms x 5
// credential shapes x 3 terminators x 3 placements.
const expectedTerminatorSweepSize = 7 * 5 * 3 * 3

func terminatorSweepCases() []string {
	cases := make([]string, 0, expectedTerminatorSweepSize)
	for _, tmpl := range remoteFormTemplates {
		for _, shape := range credentialShapes {
			for _, terminator := range authorityTerminators {
				for _, placement := range terminatorPlacements {
					cases = append(cases, fmt.Sprintf(tmpl, placement.build(shape, terminator)))
				}
			}
		}
	}
	return cases
}

// TestNoRemoteWithAnAuthorityTerminatorBetweenACredentialAndItsAtSignIsEverRecorded
// is the universal this branch has been missing.
//
// NO remote in which an RFC 3986 authority terminator sits between a credential
// and the '@' that delimits it may reach evidence with any part of that
// credential intact — for every terminator, every credential shape, every
// remote form, and every position the terminator can take.
//
// Measured on the previous head of this branch (dde1aecd), redactRemoteURL
// leaked on 29 of 39 probe inputs drawn from this product. Two mechanisms did
// it. In the URL form the authority stops SHORT of the terminator, so
// LastIndexByte('@') found no at-sign to cut at and the password WAS the
// authority:
//
//	"https://alice:SECRETVALUE/q@github.com/acme/api.git" -> ok=true, recorded VERBATIM
//	"https://alice:SECRETVALUE?q@github.com/acme/api.git" -> ok=true "https://alice:SECRETVALUE"
//
// In the scp and local forms the query/fragment cut ran BEFORE classification
// and removed the '@' itself — the one byte that made the string recognisable
// as userinfo — leaving a credential that read as an ordinary "host:path":
//
//	"alice:SECRETVALUE?q@github.com:acme/api.git" -> ok=true "alice:SECRETVALUE"
//	"/srv/alice:SECRETVALUE#q@repo.git"           -> ok=true "/srv/alice:SECRETVALUE"
func TestNoRemoteWithAnAuthorityTerminatorBetweenACredentialAndItsAtSignIsEverRecorded(t *testing.T) {
	cases := terminatorSweepCases()
	if len(cases) != expectedTerminatorSweepSize {
		t.Fatalf("sweep enumerated %d cases, want %d: the product is not being generated, so a pass here would prove nothing", len(cases), expectedTerminatorSweepSize)
	}

	canaries := []string{terminatorCanary, terminatorCanaryLeft, terminatorCanaryRight}
	for _, remote := range cases {
		t.Run(remote, func(t *testing.T) {
			recorded, ok := redactRemoteURL(remote)
			if !ok {
				return // refused: nothing reaches evidence
			}
			for _, canary := range canaries {
				if strings.Contains(recorded, canary) {
					t.Fatalf("credential reached signed evidence\n  remote:   %q\n  recorded: %q\n  canary:   %q", remote, recorded, canary)
				}
			}
		})
	}
}

// TestEveryRealRemoteShapeSurvivesTheAuthorityTerminatorGuard is the
// over-refusal control, and it is not optional.
//
// A redactor that refuses everything passes the sweep above perfectly while
// deleting the attestation's whole discovery surface — judge links a DSSE to a
// product by these strings. So the sweep's universal is paired with an exact
// expected output for every remote shape that genuinely occurs, and both must
// hold at once.
func TestEveryRealRemoteShapeSurvivesTheAuthorityTerminatorGuard(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remote string
		want   string
		wantOK bool
	}{
		// IPv6 literals: the bracket case that authorityIsHostAndPort must not
		// mistake for a non-numeric port. The colon inside the brackets is not
		// the port delimiter, and "db8::1" is not a port.
		{"scp ipv6 literal", "git@[2001:db8::1]:acme/api.git", "git@[2001:db8::1]:acme/api.git", true},
		{"url ipv6 literal with port", "https://[2001:db8::1]:443/acme/api.git", "https://[2001:db8::1]:443/acme/api.git", true},
		{"url ipv6 literal no port", "https://[2001:db8::1]/acme/api.git", "https://[2001:db8::1]/acme/api.git", true},
		{"url ipv6 literal with login", "ssh://git@[2001:db8::1]:22/acme/api.git", "ssh://[2001:db8::1]:22/acme/api.git", true},

		// Ordinary numeric ports must not be read as a credential.
		{"url explicit port", "https://github.com:8443/acme/api.git", "https://github.com:8443/acme/api.git", true},
		{"url ssh port", "ssh://git@github.com:22/acme/api.git", "ssh://github.com:22/acme/api.git", true},

		// The everyday shapes.
		{"url no credential", "https://github.com/acme/api.git", "https://github.com/acme/api.git", true},
		{"url login only", "https://x-access-token@github.com/acme/api.git", "https://github.com/acme/api.git", true},
		{"url credential stripped", "https://alice:SECRET@github.com/acme/api.git", "https://github.com/acme/api.git", true},
		{"scp ordinary", "git@github.com:acme/api.git", "git@github.com:acme/api.git", true},
		{"scp single-label host", "git@myserver:repo.git", "git@myserver:repo.git", true},
		{"local absolute path", "/srv/git/repo.git", "/srv/git/repo.git", true},
		{"file scheme", "file:///srv/git/repo.git", "file:///srv/git/repo.git", true},

		// Round 1's case: an at-sign inside the repository NAME is not a
		// credential delimiter, because the scp path begins at the first colon.
		{"scp at-sign in repo name", "git@example.com:repo@release.git", "git@example.com:repo@release.git", true},

		// Round 3's case, and the reason colonOutsideBrackets stops at the
		// delimiter: '[' is an ordinary filename byte once the authority has
		// ended, so an unterminated one in the PATH must not make the remote
		// unclassifiable. Measured on dde1aecd: ok=false, the remote was
		// dropped from evidence.
		{"scp unterminated bracket in path", "git@myserver:repo[legacy.git", "git@myserver:repo[legacy.git", true},

		// The same byte in a local path, where the leading slash has already
		// settled the form before any bracket is read.
		{"local unterminated bracket and colon", "/srv/git/repo[1:2.git", "/srv/git/repo[1:2.git", true},
		{"local unterminated bracket no colon", "/srv/git/a[1.git", "/srv/git/a[1.git", true},
		{"local double colon is a filename", "/srv/git/a::b.git", "/srv/git/a::b.git", true},

		// A query on a URL is grammatical and is cut; the remote itself stays.
		{"url query cut", "https://github.com/acme/api.git?token=SECRET", "https://github.com/acme/api.git", true},

		// Still refused, and must stay refused: a helper invocation has no
		// authority to locate.
		{"remote helper refused", "ext::helper --token SECRET", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := redactRemoteURL(tc.remote)
			if ok != tc.wantOK || got != tc.want {
				t.Fatalf("redactRemoteURL(%q) = (%q, %v), want (%q, %v)", tc.remote, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

// TestAuthorityIsHostAndPortDecidesOnlyThePort pins the boundary directly, so
// that a mutation to the digit test or to the bracket-aware delimiter is killed
// at the unit as well as end to end.
func TestAuthorityIsHostAndPortDecidesOnlyThePort(t *testing.T) {
	for _, tc := range []struct {
		authority string
		want      bool
	}{
		{"github.com", true},
		{"github.com:443", true},
		{"myserver", true},
		{"[2001:db8::1]", true},
		{"[2001:db8::1]:443", true},
		{"[::1]:8080", true},

		{"alice:SECRETVALUE", false}, // a password sits where a port belongs
		{":SECRETVALUE", false},      // ...with no user in front of it
		{"github.com:", false},       // an empty port names no service
		{"github.com:44a", false},    // one non-digit is enough
		{"github.com:8443extra", false},
		{"[2001:db8::1", false}, // unterminated bracket swallowing a colon
	} {
		t.Run(tc.authority, func(t *testing.T) {
			if got := authorityIsHostAndPort(tc.authority); got != tc.want {
				t.Fatalf("authorityIsHostAndPort(%q) = %v, want %v", tc.authority, got, tc.want)
			}
		})
	}
}
