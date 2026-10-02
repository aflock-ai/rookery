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

// THE FORM SWEEP FOR THE QUERY/FRAGMENT CUT — testifysec/judge#9177.
//
// The class is A URL-GRAMMAR OPERATION APPLIED TO A REMOTE THAT IS NOT HANDED
// TO A URL PARSER, and three review rounds each found a different instance of
// it because each round NARROWED the cut instead of removing it:
//
//	round 7  cut ran before classification  -> renamed scp and local repositories
//	round 8  cut restricted to the URL form -> still renamed file:// and ssh://
//
// The second one is the interesting one, and it is why this file asserts over
// forms rather than over strings. CLASSIFYING A STRING AS A URL DOES NOT MEAN
// GIT HANDS IT TO A PARSER THAT HAS A QUERY: only the curl-family transports
// (http, https, ftp, ftps) ever interpret '?' and '#', while git's own ssh, git
// and file transports pass the path through verbatim. In every other form those
// bytes are filename bytes, so cutting there does not remove a credential — it
// renames the repository, and the rename is then signed:
//
//	"git@example.com:repo#release.git" -> "git@example.com:repo"
//	"/srv/git/repo#release.git"        -> "/srv/git/repo"
//	"file:///srv/git/repo#release.git" -> "file:///srv/git/repo"
//
// None of those targets exists. redactSCPRemote states the principle the cut
// broke — "rewriting it would invent a spelling git never used".
//
// The remedy is that redactRemoteURL now REFUSES any remote carrying either
// byte and cuts nothing, on any form. This test does not assert that remedy
// directly, because a test written to the remedy would have passed in round 8
// too. It asserts the two HARMS, which is what the review actually names and
// what both a truncating and a pass-through implementation violate:
//
//	HARM ONE  — the secret reaches evidence            (testifysec/judge#8950)
//	HARM TWO  — a shortened identity reaches evidence  (testifysec/judge#9177)
//
// Recording a remote VERBATIM commits harm one on the "?token=" rows. Cutting
// it commits harm two on the "#release.git" rows. Only refusing avoids both,
// which is how the policy was arrived at rather than assumed — and both
// mutations were measured red against this file before it was committed.

// queryFragmentByForm crosses every form classifyRemote can assign with
// spellings that carry a '?' or a '#'. The key is the form the row CLAIMS, and
// the sweep verifies that claim against the classifier before testing anything,
// so a row cannot silently drift into another form and take its coverage with
// it.
//
// The URL row deliberately mixes the curl-family schemes with file:// and
// ssh://, because "it classified as a URL" was exactly the reasoning that let
// round 8 through.
var queryFragmentByForm = map[remoteForm][]string{
	remoteFormLocal: {
		"/srv/git/repo#release.git",
		"/srv/git/repo?v=1.git",
		"../mirror#release",
		"/srv/git/repo.git?token=" + sweepSecret,
		"/srv/git/repo.git#" + sweepSecret,
	},
	remoteFormURL: {
		"https://github.com/acme/api.git?token=" + sweepSecret,
		"https://github.com/acme/api.git#" + sweepSecret,
		"http://github.com/acme/api.git?token=" + sweepSecret,
		"ssh://git@github.com/acme/api.git?token=" + sweepSecret,
		"ssh://git@github.com/acme/repo#release.git",
		"file:///srv/git/repo#release.git",
		"file:///srv/git/repo.git#" + sweepSecret,
		"git://github.com/acme/repo#release.git",
	},
	remoteFormSCP: {
		"git@example.com:repo#release.git",
		"git@example.com:repo?v=1.git",
		"github.com:acme/api.git?token=" + sweepSecret,
		"git@[2001:db8::1]:acme/api#release.git",
	},
	remoteFormHelper: {
		"ext::helper --token " + sweepSecret + "?x",
		"transport::addr#" + sweepSecret,
	},
	remoteFormUnclassifiable: {
		"[unterminated:host#" + sweepSecret,
		"[unterminated:host?token=" + sweepSecret,
	},
}

// TestNoRemoteFormHasItsQueryOrFragmentCut is the universal the review's
// critical asks for: quantified over the forms, not over the strings.
func TestNoRemoteFormHasItsQueryOrFragmentCut(t *testing.T) {
	// THE ENUMERATION IS TOTAL, AND SAYS SO OUT LOUD.
	//
	// remoteFormUnclassifiable is the catch-all and is declared last, so a form
	// added to the block lands before it and moves this constant. Pinning the
	// value is what makes "every form is covered" a claim about classifyRemote
	// rather than a claim about this map.
	require.Equal(t, remoteForm(4), remoteFormUnclassifiable,
		"the remoteForm block changed shape; every form classifyRemote can return needs a row in queryFragmentByForm")
	require.Len(t, queryFragmentByForm, int(remoteFormUnclassifiable)+1,
		"queryFragmentByForm must hold exactly one row per declared form")
	for form := remoteFormLocal; form <= remoteFormUnclassifiable; form++ {
		require.NotEmpty(t, queryFragmentByForm[form],
			"remote form %d has no query/fragment spelling in this sweep", form)
	}

	checked := 0
	for form, spellings := range queryFragmentByForm {
		for _, raw := range spellings {
			checked++

			require.True(t, strings.ContainsAny(raw, "?#"),
				"a row in this sweep must actually carry a query or fragment byte: %q", raw)
			gotForm, _, _ := classifyRemote(raw)
			require.Equal(t, form, gotForm,
				"this sweep files %q under form %d but classifyRemote assigns %d; the row's coverage is not what it claims", raw, form, gotForm)

			out, ok := redactRemoteURL(raw)

			// HARM ONE. A remote that is recorded at all must not carry the
			// canary, whichever form it wore.
			require.NotContains(t, out, sweepSecret,
				"a token in the query or fragment reached the attestation as form %d: %q -> %q", form, raw, out)

			// THE CUT IS LEGITIMATE EXACTLY WHERE GIT PARSES A QUERY, so the
			// expectation is keyed on the TRANSPORT rather than on the form.
			// Keying it on the form is what round 8 did, and file:// and ssh://
			// are the counterexamples that cost.
			_, scheme, _ := classifyRemote(raw)
			if form == remoteFormURL && schemeHasQueryGrammar(scheme) {
				require.True(t, ok,
					"dropping the query of a curl-family URL must not cost the whole remote: %q", raw)
				require.NotContains(t, out, "?",
					"the query must be gone from the recorded value: %q -> %q", raw, out)
				require.NotContains(t, out, "#",
					"the fragment must be gone from the recorded value: %q -> %q", raw, out)
				continue
			}

			// HARM TWO. Git hands this remote to no parser that has a query, so
			// a remote that IS recorded must be recorded WHOLE. Refusing is
			// permitted; shortening is not.
			if ok {
				require.Equal(t, raw, out,
					"form %d scheme %q gets no query/fragment parsing from git, so %q was recorded under a different repository identity: %q", form, scheme, raw, out)
			}
		}
	}

	t.Logf("swept %d spellings across %d forms", checked, len(queryFragmentByForm))
	require.Greater(t, checked, 20, "the sweep must enumerate its space")
}

// TestTheChosenPolicyForAQueryOrFragmentIsRefusal pins WHICH of the two
// permitted remedies this file took, so the choice is a decision in the tree
// rather than an accident of the implementation.
//
// The sweep above deliberately accepts either remedy. This one records that
// refusal was picked, and that it is uniform: no scheme and no form is exempt.
// A scheme allowlist was the alternative and is what round 8 effectively was —
// "the URL form may be cut" — which is the shape that had to be corrected. An
// exemption list that grows by one entry per review round is inverted; the
// invariant belongs at the top instead.
func TestTheChosenPolicyForAQueryOrFragmentIsRefusal(t *testing.T) {
	for _, raw := range []string{
		"git@example.com:repo#release.git",
		"github.com:acme/api.git?token=" + sweepSecret,
		"/srv/git/repo#release.git",
		"/srv/git/repo.git?token=" + sweepSecret,
		"../mirror#release",
		"file:///srv/git/repo#release.git",
		"ssh://git@github.com/acme/repo#release.git",
		"git://github.com/acme/repo#release.git",
	} {
		out, ok := redactRemoteURL(raw)
		require.False(t, ok,
			"a remote carrying a query or fragment byte is refused, not shortened: %q -> %q", raw, out)
		require.Empty(t, out)
	}
}

// TestSchemeHasQueryGrammarIsAClosedPositiveList pins the direction of the
// list, which is the property that keeps the next scheme from inheriting the
// bug. git's curl-family transports parse a query; its native ones do not; and
// anything unrecognised must answer NO so the caller refuses instead of cutting.
func TestSchemeHasQueryGrammarIsAClosedPositiveList(t *testing.T) {
	for _, scheme := range []string{"http://", "https://", "HTTPS://", "ftp://", "ftps://"} {
		require.True(t, schemeHasQueryGrammar(scheme), "curl-family scheme %q parses a query", scheme)
	}
	for _, scheme := range []string{
		"ssh://", "git://", "file://", "git+ssh://", "ssh+git://", "rsync://",
		"", "://", "gopher://", "whatever://",
	} {
		require.False(t, schemeHasQueryGrammar(scheme),
			"scheme %q is not handed to a query-parsing transport, so its delimiters are path bytes", scheme)
	}
}

// TestTheDelimiterRefusalSubsumesTheEarlierCutFindings is the reason this rule
// could replace three others rather than joining them.
//
// Every string here was reported on this branch as a separate critical, and
// every one had the same cause: the cut removed the '@' that made a span
// recognisable as userinfo, so the rule that would have caught it never saw the
// byte it keys on. They are refused now before any rule looks at them.
func TestTheDelimiterRefusalSubsumesTheEarlierCutFindings(t *testing.T) {
	for _, raw := range []string{
		"alice:" + sweepSecret + "?q@github.com:acme/api.git",
		"/srv/alice:" + sweepSecret + "#q@repo.git",
		"https://ghp_" + sweepSecret + "?x@github.com/acme/api.git",
		"https://user:p@" + sweepSecret + "?x@github.com/acme/api.git",
		"https://alice:" + sweepSecret + "#suffix@github.com/acme/api.git",
	} {
		out, ok := redactRemoteURL(raw)
		require.False(t, ok, "a delimiter inside a pasted credential is refused: %q -> %q", raw, out)
		require.NotContains(t, out, sweepSecret)
	}
}

// TestACurlFamilyQueryIsStillCutRatherThanCostingTheRemote is the property the
// narrowing must NOT break. Three other sweeps in this package assert it too —
// "the redacted remote must still identify the repository it came from" — and
// that design intent is why the cut was kept for http and https rather than
// deleted outright. Refusing everything would have been simpler and would have
// thrown the repository identity away on the one family where the bytes really
// are a query.
func TestACurlFamilyQueryIsStillCutRatherThanCostingTheRemote(t *testing.T) {
	for _, tt := range []struct{ raw, want string }{
		{"https://github.com/acme/api.git?token=" + sweepSecret, "https://github.com/acme/api.git"},
		{"http://github.com/acme/api.git#" + sweepSecret, "http://github.com/acme/api.git"},
		{"https://github.com/acme/api.git?a=1&b=2#" + sweepSecret, "https://github.com/acme/api.git"},
		{"https://x-access-token:ghs_TOK@github.com/acme/api.git?token=" + sweepSecret, "https://github.com/acme/api.git"},
	} {
		out, ok := redactRemoteURL(tt.raw)
		require.True(t, ok, "a curl-family remote must survive its query being cut: %q", tt.raw)
		require.Equal(t, tt.want, out, "%q", tt.raw)
		require.NotContains(t, out, sweepSecret)
	}
}

// TestEveryQueryFreeRemoteFormIsUntouchedByTheRefusal is the other side of the
// gate: the refusal must be keyed on the BYTE being present, not on the form.
// A mutation that refuses every scp or local remote outright would pass the
// tests above and take the attestor's whole discovery surface with it.
func TestEveryQueryFreeRemoteFormIsUntouchedByTheRefusal(t *testing.T) {
	for _, tt := range []struct{ raw, want string }{
		{"git@github.com:acme/api.git", "git@github.com:acme/api.git"},
		{"github.com:acme/api.git", "github.com:acme/api.git"},
		{"git@[2001:db8::1]:acme/api.git", "git@[2001:db8::1]:acme/api.git"},
		{"git@example.com:repo@release.git", "git@example.com:repo@release.git"},
		{"/srv/git/repo.git", "/srv/git/repo.git"},
		{"../mirror", "../mirror"},
		{"https://github.com/acme/api.git", "https://github.com/acme/api.git"},
		{"http://github.com/acme/api.git", "http://github.com/acme/api.git"},
		{"ssh://git@github.com/acme/api.git", "ssh://github.com/acme/api.git"},
		{"file:///srv/git/repo.git", "file:///srv/git/repo.git"},
		{"https://x-access-token:ghs_TOK@github.com/acme/api.git", "https://github.com/acme/api.git"},
	} {
		out, ok := redactRemoteURL(tt.raw)
		require.True(t, ok, "a credential-free remote with no query byte must survive: %q", tt.raw)
		require.Equal(t, tt.want, out, "%q", tt.raw)
	}
}
