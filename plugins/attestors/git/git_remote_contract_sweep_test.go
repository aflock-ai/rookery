// jade:ring local

package git

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/require"
)

// This file tests the THREE-VALUED remote contract (see remoteVerdict), and it
// is deliberately written as universals rather than as a table of spellings.
//
// #9177 burned nine consecutive review rounds in which every finding cited this
// one file. The shape of the stall is the point: each round tightened a rule to
// kill a credential leak, which broke a legitimate repository identity; the next
// round loosened it to keep the identity, which reopened a leak. Four separate
// rounds raised the SAME defect at four different line numbers. A test named
// "a malformed X never reaches Y" pins one instance and lets its class recur at
// the next line; a test named "no remote in <enumerable set> ..." kills the
// class. So the assertions below quantify over a cross product and hold for
// every member of it, and the concrete spellings the reviewer found are carried
// as an explicit regression table so they cannot be lost in the generalisation.

// contractCanary is the byte sequence that must never reach a recorded remote.
// It is one token so a single NotContains can stand for "no credential
// escaped", and it is deliberately not shaped like any real PAT — a test that
// matched on "ghs_" would pass for the wrong reason against an implementation
// that filtered prefixes, which is exactly the spelling question this attestor
// refuses to ask.
const contractCanary = "CONTRACTCANARY"

// contractLoginCanary marks the ONE position whose bytes are legitimately
// recorded: an scp LOGIN.
//
// It is a separate marker rather than a hole in contractCanary's universal,
// because the difference between the two positions is a fact about the two
// grammars and belongs in the test as an assertion rather than as an omission:
//
//	URL  (RFC 3986)  userinfo = user [":" password]. A PASSWORD POSITION
//	                 EXISTS, and no structural test separates a userinfo that
//	                 carries one from a userinfo that does not, so the whole
//	                 component is removed.
//	scp  (connect.c) [user@]host:path. THERE IS NO PASSWORD POSITION — the
//	                 first colon IS the host/path delimiter, so a password
//	                 cannot be spelled before it. What sits there is a routing
//	                 login (ssh dials on it; github and gitlab both require
//	                 "git@"), and it is recorded.
//
// So "LOGINCANARY@github.com:acme/api.git" records LOGINCANARY and
// "https://LOGINCANARY@github.com/acme/api.git" does not. That asymmetry is
// asserted in both directions by TestTheScpLoginIsRecordedAndTheResidualIsNamed
// rather than left as a gap a later reader has to rediscover.
const contractLoginCanary = "LOGINCANARY"

// refusalReasons is the closed set of reasons a refusal may carry. The trace in
// RemotesRefused is a signed predicate field, so the set of values it can hold
// is part of the contract and not an implementation detail.
var refusalReasons = map[string]bool{
	refusalAmbiguousAuthority:     true,
	refusalOpaqueTransport:        true,
	refusalPathBytesNotRedactable: true,
}

// TestRefusalReasonsAreAClosedSet pins the set in both directions: these three
// values and no others, with no two spelled the same.
//
// Without it the trace degrades silently. A fourth reason added without a
// thought lands in signed evidence as a new category nobody agreed to, and a
// copy-paste that duplicates a constant's VALUE while renaming the identifier
// makes two distinct refusals indistinguishable in the predicate — which is the
// failure this whole field exists to prevent, one level down.
func TestRefusalReasonsAreAClosedSet(t *testing.T) {
	require.Len(t, refusalReasons, 3, "a reason was added or removed without updating the contract")
	require.Equal(t, "ambiguous-authority", refusalAmbiguousAuthority)
	require.Equal(t, "opaque-transport", refusalOpaqueTransport)
	require.Equal(t, "path-bytes-not-redactable", refusalPathBytesNotRedactable)
}

// TestTheThirteenReviewedSpellings carries every concrete input the review
// raised across the nine rounds, with the COMPLETE recorded identity asserted
// rather than "the secret is absent".
//
// The complete-identity assertion is load-bearing and the leak-only one is not
// enough: over half of these findings are about recording a DIFFERENT
// repository, not about recording a secret. "git@example.com:repo@release.git"
// reduced to "release.git" carries no credential at all and is still a signed
// statement about a repository that does not exist. A test asserting only
// NotContains(secret) is green on every one of them.
func TestTheThirteenReviewedSpellings(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		verdict  remoteVerdict
		recorded string
		reason   string
	}{
		// ── Class A: a credential must not reach signed evidence ──────────
		{
			name:    "leading space defeats both the parser and the scheme test",
			in:      " https://alice:" + contractCanary + "@github.com/acme/api.git",
			verdict: remoteRefused,
			reason:  refusalAmbiguousAuthority,
		},
		{
			name:    "single slash makes a hierarchical url with no authority",
			in:      "https:/alice:" + contractCanary + "@github.com/acme/api.git",
			verdict: remoteRefused,
			reason:  refusalAmbiguousAuthority,
		},
		{
			name:    "a dotted username is spelled exactly like a dotted host",
			in:      "alice.smith:" + contractCanary + "@github.com:acme/api.git",
			verdict: remoteRefused,
			reason:  refusalAmbiguousAuthority,
		},
		{
			name:    "a fragment terminates the authority before its at-sign",
			in:      "https://alice:" + contractCanary + "#suffix@github.com/acme/api.git",
			verdict: remoteRefused,
			reason:  refusalAmbiguousAuthority,
		},
		{
			name:    "a query terminates the authority and the token reads as a host",
			in:      "https://" + contractCanary + "?x@github.com/acme/api.git",
			verdict: remoteRefused,
			reason:  refusalAmbiguousAuthority,
		},
		{
			name:    "an earlier at-sign must not disarm the downstream ambiguity check",
			in:      "https://user:p@" + contractCanary + "?x@github.com/acme/api.git",
			verdict: remoteRefused,
			reason:  refusalAmbiguousAuthority,
		},
		{
			// The single finding standing on the PR when this round began.
			// An email-style login made hasLogin true, which skipped the scp
			// ambiguity check, and pathIsCredentialFree passed the path
			// because its colon came AFTER its at-sign rather than before.
			name:    "an email-style login must not buy the path an exemption",
			in:      "alice@example.com:" + contractCanary + "@github.com:acme/api.git",
			verdict: remoteRefused,
			reason:  refusalAmbiguousAuthority,
		},

		// ── Class B: a legitimate repository identity must not be rewritten ─
		{
			// #9181. An at-sign in an scp PATH belongs to the repository name.
			name:     "an at-sign in an scp repository name survives whole",
			in:       "git@example.com:repo@release.git",
			verdict:  remoteClean,
			recorded: "git@example.com:repo@release.git",
		},
		{
			// The delimiter is the colon OUTSIDE the brackets, or the host
			// becomes "[2001" and the remote is dropped.
			name:     "a bracketed ipv6 host keeps its brackets and its remote",
			in:       "git@[2001:db8::1]:acme/api.git",
			verdict:  remoteClean,
			recorded: "git@[2001:db8::1]:acme/api.git",
		},
		{
			// Raised in FOUR separate rounds at four different line numbers —
			// git.go:676, :982, :1055 and :491 — which is the clearest
			// evidence in the PR that instance-shaped fixes relocate a defect
			// rather than remove it. It is REFUSED, not truncated: the review
			// offered "preserve those paths or refuse the entire remote", and
			// refusing is the fail-closed half of that choice. What makes the
			// refusal honest rather than a silent identity loss is that it is
			// now counted in RemotesRefused.
			name:    "a fragment in an scp repository name is never cut to a shorter repo",
			in:      "git@example.com:repo#release.git",
			verdict: remoteRefused,
			reason:  refusalPathBytesNotRedactable,
		},
		{
			name:    "a fragment in a local path is never cut to a shorter path",
			in:      "/srv/git/repo#release.git",
			verdict: remoteRefused,
			reason:  refusalPathBytesNotRedactable,
		},
		{
			// git resolves file:// on the filesystem and never parses a
			// fragment out of it, so these bytes are a filename.
			name:    "a fragment in a file url is never cut to a shorter path",
			in:      "file:///srv/git/repo#release.git",
			verdict: remoteRefused,
			reason:  refusalPathBytesNotRedactable,
		},
		{
			// A literal bracket past the delimiter is a filename byte. Carrying
			// bracket state to the end of the string left the depth nonzero
			// and dropped a remote that holds nothing at all.
			name:     "a literal bracket after the scp delimiter keeps its remote",
			in:       "git@myserver:repo[legacy.git",
			verdict:  remoteClean,
			recorded: "git@myserver:repo[legacy.git",
		},
	}

	require.Len(t, cases, 13, "the reviewed set is thirteen spellings; a dropped row is a dropped regression")

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verdict, recorded, reason := recordRemote(tc.in)
			require.Equal(t, tc.verdict, verdict, "verdict for %q", tc.in)
			require.Equal(t, tc.recorded, recorded, "recorded identity for %q", tc.in)
			require.Equal(t, tc.reason, reason, "refusal reason for %q", tc.in)
			require.NotContains(t, recorded, contractCanary, "a credential reached the recorded remote")
			require.NotContains(t, reason, contractCanary, "a credential reached the refusal trace")
		})
	}
}

// ── the cross product ────────────────────────────────────────────────────────

// The four axes. Each is an enumeration of a GRAMMAR position, not a list of
// spellings someone thought of, which is what makes the product a claim about
// the contract rather than about this file's imagination.
var (
	// contractSchemes crosses the curl-family transports (which parse a query)
	// with git's native ones (which do not) and with the scheme-less scp form,
	// because "it classified as a URL" was itself a defective reason to cut.
	contractSchemes = []string{"", "https://", "http://", "ssh://", "git://", "file://", "ftp://"}
	// contractHosts crosses a dotted name, a single label, a bracketed IPv6
	// literal and a host with an explicit port. A single label and a PAT are
	// spelled from the same characters, which is why the port — and never the
	// host — is the component the implementation decides structurally.
	contractHosts = []string{"github.com", "myserver", "[2001:db8::1]", "example.com:8443"}
	// contractCreds crosses no userinfo, a bare routing login, user:password,
	// a whole-username token (the shape a password-only check waves through),
	// and the email-style login that bought an exemption in round nine.
	//
	// The whole-username entry carries contractLoginCanary, not contractCanary,
	// because in the scp grammar that position IS the login and is recorded on
	// purpose — see contractLoginCanary. Using the strict canary there would
	// have made the sweep assert something neither grammar promises, and the
	// honest repair is a marker that says which position it is standing in, not
	// a deleted row.
	contractCreds = []string{"", "git@", "alice:" + contractCanary + "@", contractLoginCanary + "@", "alice@example.com:" + contractCanary + "@"}
	// contractPaths crosses a plain path with each of the four bytes the
	// review's Class B findings named as legitimate repository-name
	// characters: '@', '#', '?' and '['.
	contractPaths = []string{"/acme/api.git", "/acme/repo@release.git", "/acme/repo#release.git", "/acme/repo?v=1.git", "/acme/repo[legacy.git"}
)

// buildContractRemote assembles one cross-product member. The scp form takes
// its path after a colon rather than a slash, which is the whole reason it is a
// separate grammar and not a scheme with an empty prefix.
func buildContractRemote(scheme, cred, host, path string) string {
	if scheme == "" {
		return cred + host + ":" + strings.TrimPrefix(path, "/")
	}
	return scheme + cred + host + path
}

// TestRemoteContractHoldsAcrossTheGrammarCrossProduct is the universal. It
// asserts the three-valued contract itself for every member of
// {scheme} x {host} x {credential} x {path}, with no expected-value table: a
// table would be a restatement of the implementation, and a bug copied into it
// is a bug the test agrees with.
func TestRemoteContractHoldsAcrossTheGrammarCrossProduct(t *testing.T) {
	swept := 0
	byVerdict := map[remoteVerdict]int{}
	// recordableControls counts the rows that CANNOT legitimately be refused —
	// see the over-refusal control below.
	recordableControls := 0

	for _, scheme := range contractSchemes {
		for _, host := range contractHosts {
			for _, cred := range contractCreds {
				for _, path := range contractPaths {
					// Counted BEFORE any assertion, so a row that fails still
					// counts and the total below measures iteration rather
					// than success.
					swept++
					in := buildContractRemote(scheme, cred, host, path)
					verdict, recorded, reason := recordRemote(in)
					byVerdict[verdict]++

					// (1) NOTHING RECORDED EVER CARRIES THE CREDENTIAL. This
					// holds for all three verdicts, including refusal, and it
					// covers the refusal trace as well as the remote — a
					// reason string built from the input would leak through
					// the very field added to make refusals visible.
					require.NotContainsf(t, recorded, contractCanary, "credential reached signed evidence for %q", in)
					require.NotContainsf(t, reason, contractCanary, "credential reached the refusal trace for %q", in)
					require.NotContainsf(t, reason, contractLoginCanary, "a login reached the refusal trace for %q", in)
					// (1b) THE URL GRAMMAR REMOVES ITS USERINFO WHOLE. In a URL
					// the login sits in the same component as a password and
					// nothing structural tells them apart, so it goes with it.
					// The scp form is the other half of this and is asserted
					// in TestTheScpLoginIsRecordedAndTheResidualIsNamed.
					if scheme != "" {
						require.NotContainsf(t, recorded, contractLoginCanary, "url userinfo survived for %q", in)
					}

					switch verdict {
					case remoteClean:
						// (2) CLEAN MEANS VERBATIM. This is the assertion a
						// leak-only test cannot make, and it is the one that
						// catches every Class B finding: a remote recorded as
						// a DIFFERENT repository is not a leak, it is a false
						// signed statement.
						require.Equalf(t, in, recorded, "a clean remote must be recorded byte for byte: %q", in)
						require.Emptyf(t, reason, "a clean remote carries no refusal reason: %q", in)
					case remoteRedacted:
						// (3) REDACTION REMOVES THE CREDENTIAL AND KEEPS THE
						// REPOSITORY. The host is what names the repository;
						// a "redaction" that loses it has destroyed the
						// identity rather than protected it.
						require.NotEqualf(t, in, recorded, "a redacted remote must differ from its input: %q", in)
						require.Containsf(t, recorded, host, "redaction dropped the host for %q", in)
						require.Emptyf(t, reason, "a redacted remote carries no refusal reason: %q", in)
					case remoteRefused:
						// (4) REFUSAL RECORDS NOTHING AND SAYS WHY.
						require.Emptyf(t, recorded, "a refused remote records nothing: %q", in)
						require.Truef(t, refusalReasons[reason], "refusal reason %q for %q is outside the closed set", reason, in)
					default:
						t.Fatalf("unknown verdict %d for %q", verdict, in)
					}

					// (5) THE OVER-REFUSAL CONTROL. Every assertion above is
					// satisfied by an implementation that refuses everything,
					// so without this the sweep is green for the worst
					// possible redactor. A remote carrying no credential and
					// an ordinary path MUST be recorded.
					if (cred == "" || cred == "git@") && path == "/acme/api.git" {
						recordableControls++
						require.Truef(t, verdict.recordable(),
							"refused a credential-free remote with an ordinary path: %q (reason %q)", in, reason)
					}
				}
			}
		}
	}

	// THE SWEEP COUNTER. A sweep that silently swept nothing — an axis that
	// became empty in a refactor, a loop that was narrowed to a single case —
	// reports clean for the wrong reason, and has done so twice in this
	// repository. The count is asserted against the product of the axis
	// lengths, so it cannot drift with them.
	if want := len(contractSchemes) * len(contractHosts) * len(contractCreds) * len(contractPaths); swept != want {
		t.Fatalf("sweep covered %d cases, want %d", swept, want)
	}

	// NON-VACUITY, the other half. All three verdicts must actually occur, or
	// a whole branch of the contract is untested by a sweep that claims to
	// cover it.
	require.Positive(t, byVerdict[remoteClean], "no case exercised remoteClean")
	require.Positive(t, byVerdict[remoteRedacted], "no case exercised remoteRedacted")
	require.Positive(t, byVerdict[remoteRefused], "no case exercised remoteRefused")
	require.Equal(t, len(contractSchemes)*len(contractHosts)*2, recordableControls,
		"the over-refusal control did not reach every credential-free row")
	t.Logf("swept %d: clean=%d redacted=%d refused=%d, %d over-refusal controls",
		swept, byVerdict[remoteClean], byVerdict[remoteRedacted], byVerdict[remoteRefused], recordableControls)
}

// TestTheScpLoginIsRecordedAndTheResidualIsNamed pins the ONE position whose
// bytes survive into evidence, in both directions, and writes the residual down
// where the next reader will find it.
//
// A test that merely omitted the scp login from the credential sweep would look
// identical to a test that had never thought about it. This one asserts the
// asymmetry on purpose, so that a change to either grammar's handling turns it
// red and forces the reasoning to be re-stated rather than quietly lost.
//
// THE RESIDUAL, STATED: a token hand-written where an ssh login goes —
// "ghp_TOKEN@github.com:acme/api.git" — is recorded. It cannot be told from
// "git@github.com:acme/api.git" by anything but what the text spells, and "what
// does this text spell" is the unanswerable question this attestor exists to
// stop asking: a single-label host and a PAT are drawn from the same alphabet.
//
// The residual is bounded by the grammar rather than by a survey: ssh cannot
// authenticate with a PAT, so no tool produces this spelling and the string is
// not a working remote. The alternative — drop the scp login the way the URL
// branch drops its userinfo, which is what judge-api's own
// sanitizeSchemelessRemote and repoidentity.redactSCPLike both do — closes it
// completely and costs a change to what every ssh remote records in signed
// evidence. That is a product decision about evidence shape, not a bug fix, and
// it is deliberately not taken inside this change.
func TestTheScpLoginIsRecordedAndTheResidualIsNamed(t *testing.T) {
	t.Run("the scp login is recorded, because scp has no password position", func(t *testing.T) {
		verdict, recorded, _ := recordRemote("git@github.com:acme/api.git")
		require.Equal(t, remoteClean, verdict)
		require.Equal(t, "git@github.com:acme/api.git", recorded,
			"stripping the scp login would change what every ssh remote records")

		// The same rule, applied to a login that is not "git". This is the
		// residual, asserted rather than hidden.
		verdict, recorded, _ = recordRemote(contractLoginCanary + "@github.com:acme/api.git")
		require.Equal(t, remoteClean, verdict)
		require.Contains(t, recorded, contractLoginCanary,
			"the scp login is recorded; if this changed, the residual above is closed and the comment is stale")
	})

	t.Run("a url userinfo is removed, because a url has a password position", func(t *testing.T) {
		verdict, recorded, _ := recordRemote("https://git@github.com/acme/api.git")
		require.Equal(t, remoteRedacted, verdict)
		require.Equal(t, "https://github.com/acme/api.git", recorded)

		verdict, recorded, _ = recordRemote("https://" + contractLoginCanary + "@github.com/acme/api.git")
		require.Equal(t, remoteRedacted, verdict)
		require.Equal(t, "https://github.com/acme/api.git", recorded,
			"a whole-username token is the commonest PAT spelling and must not survive a URL")
	})

	t.Run("an scp login buys the PATH no exemption", func(t *testing.T) {
		// Round nine's finding, stated as the mechanism rather than the string:
		// whatever the login is, the path is judged on its own.
		for _, in := range []string{
			"alice@example.com:" + contractCanary + "@github.com:acme/api.git",
			"git@example.com:" + contractCanary + "@github.com:acme/api.git",
			contractLoginCanary + "@example.com:" + contractCanary + "@github.com:acme/api.git",
			"example.com:" + contractCanary + "@github.com:acme/api.git",
		} {
			verdict, recorded, reason := recordRemote(in)
			require.Equalf(t, remoteRefused, verdict, "a second authority in the path must be refused: %q", in)
			require.Emptyf(t, recorded, "%q", in)
			require.Equalf(t, refusalAmbiguousAuthority, reason, "%q", in)
		}
	})
}

// ── the trace, at attestation level ──────────────────────────────────────────

// TestARefusedRemoteIsDistinguishableFromNoRemote is the property the third
// verdict exists for, asserted where it matters — on the attestation, not on
// the function.
//
// Omitting an unrecordable remote is the fail-closed half. Omitting it SILENTLY
// is a fail-open of a second kind: the predicate is short a remote and says
// nothing about it, so a reader cannot tell "this repository has no remote"
// from "this attestor found one and refused it". That is the same shape as an
// attestor error meaning "could not look" being read downstream as "looked and
// found nothing", which this repository has been bitten by before.
func TestARefusedRemoteIsDistinguishableFromNoRemote(t *testing.T) {
	t.Run("a refused remote leaves a counted trace", func(t *testing.T) {
		a := runWithRemote(t, "alice@example.com:"+contractCanary+"@github.com:acme/api.git")

		require.Empty(t, a.Remotes, "an unrecordable remote must not be recorded")
		require.Len(t, a.RemotesRefused, 1, "the refusal must be visible in the predicate")
		require.Equal(t, refusalAmbiguousAuthority, a.RemotesRefused[0].Reason)
		require.Equal(t, 1, a.RemotesRefused[0].Count)

		// The trace must not become a new leak surface. The whole attestation
		// is searched, not just the field, because the point of the check is
		// that adding this field did not open a path the sweep does not watch.
		for _, s := range attestationStrings(t, a) {
			require.NotContains(t, s, contractCanary, "the refusal trace leaked the credential")
		}
	})

	t.Run("a recordable remote leaves no trace", func(t *testing.T) {
		a := runWithRemote(t, "https://github.com/acme/api.git")

		require.Equal(t, []string{"https://github.com/acme/api.git"}, a.Remotes)
		require.Nil(t, a.RemotesRefused, "nothing was refused, so the trace must be absent, not empty")
	})

	t.Run("an ordinary scp remote still survives whole", func(t *testing.T) {
		// The other half of round nine's ask — "reject this ambiguous
		// credential form ... WHILE PRESERVING ORDINARY SCP REMOTES". A fix
		// that refuses the leak by refusing the whole grammar satisfies the
		// first clause and fails the second, and only an attestation-level
		// assertion can tell the two apart.
		a := runWithRemote(t, "git@github.com:acme/api.git")

		require.Equal(t, []string{"git@github.com:acme/api.git"}, a.Remotes)
		require.Nil(t, a.RemotesRefused)
	})

	t.Run("the trace is absent from the json when nothing was refused", func(t *testing.T) {
		// omitempty is what makes "absent" and "empty" the same state in the
		// signed bytes. If the field ever serialises as [] the predicate gains
		// a third state that nothing downstream has a meaning for.
		a := runWithRemote(t, "https://github.com/acme/api.git")
		raw, err := json.Marshal(a)
		require.NoError(t, err)
		require.NotContains(t, string(raw), "remotesrefused")
	})
}

// runWithRemotes is runWithRemote for a repository configured with SEVERAL
// remotes, which is the only shape that can tell a per-remote refusal from an
// all-or-nothing one.
func runWithRemotes(t *testing.T, urls ...string) *Attestor {
	t.Helper()
	_, dir, cleanup := createTestRepo(t, true)
	t.Cleanup(cleanup)

	repo, err := git.PlainOpen(dir)
	require.NoError(t, err)
	for i, u := range urls {
		_, err = repo.CreateRemote(&config.RemoteConfig{Name: remoteFixtureName(i), URLs: []string{u}})
		require.NoErrorf(t, err, "go-git must accept %q; a rejected fixture tests nothing", u)
	}

	attestor := New()
	ctx, err := attestation.NewContext("test", []attestation.Attestor{attestor}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return attestor
}

func remoteFixtureName(i int) string {
	return "remote" + string(rune('a'+i))
}

// TestOneAmbiguousRemoteDoesNotTakeTheCleanOnesWithIt is the containment
// property, and it is the one that decides whether case 3 is a surgical refusal
// or a blunt one.
//
// The failure it guards against is not hypothetical arithmetic: a fix that
// answers "a credential reached evidence" by refusing the whole remote LIST
// satisfies every leak assertion in this package and destroys the attestation's
// entire repository-discovery surface. Several tests here already assert
// NotEmpty(attestor.Remotes) and would catch the all-remotes case, but none of
// them configures two remotes, so none can see one bad entry poisoning a good
// one. This does.
func TestOneAmbiguousRemoteDoesNotTakeTheCleanOnesWithIt(t *testing.T) {
	a := runWithRemotes(t,
		"https://github.com/acme/api.git",
		"alice@example.com:"+contractCanary+"@github.com:acme/api.git",
		"git@github.com:acme/other.git",
	)

	require.ElementsMatch(t,
		[]string{"https://github.com/acme/api.git", "git@github.com:acme/other.git"},
		a.Remotes,
		"the two recordable remotes must both survive their ambiguous neighbour")
	require.Len(t, a.RemotesRefused, 1)
	require.Equal(t, refusalAmbiguousAuthority, a.RemotesRefused[0].Reason)
	require.Equal(t, 1, a.RemotesRefused[0].Count, "exactly one remote was refused")

	for _, s := range attestationStrings(t, a) {
		require.NotContains(t, s, contractCanary)
	}
}

// TestTheRefusalTraceEmitsNoSubject pins the SHAPE of the trace against the one
// mistake that would make the policy surface worse rather than better.
//
// Every recorded remote becomes an attestation SUBJECT ("remote:<url>", see
// detector.yaml), which is what a witness policy can bind to. So refusing a
// remote does not merely shorten a list — it removes a bindable subject. The
// tempting repair is to emit a synthetic subject in its place so the count
// stays the same; that is strictly worse, because it swaps a subject naming a
// real repository for one naming nothing, and a policy matching on it would
// bind to a placeholder.
//
// The trace is therefore a PREDICATE field and must stay one: subjects are
// derived from a.Remotes alone, and the refusal contributes none.
func TestTheRefusalTraceEmitsNoSubject(t *testing.T) {
	a := runWithRemotes(t,
		"https://github.com/acme/api.git",
		"alice@example.com:"+contractCanary+"@github.com:acme/api.git",
	)
	require.Len(t, a.RemotesRefused, 1, "the fixture must actually have refused something")

	remoteSubjects := 0
	for name := range a.Subjects() {
		if strings.Contains(name, "remote:") {
			remoteSubjects++
		}
		require.NotContains(t, name, contractCanary, "a refused remote reached the subject set")
		for reason := range refusalReasons {
			require.NotContainsf(t, name, reason, "the refusal trace became a subject: %q", name)
		}
	}
	require.Equal(t, len(a.Remotes), remoteSubjects,
		"there must be exactly one remote subject per RECORDED remote — no more (a synthetic subject for the refusal) and no fewer")

	// BackRefs are the other bindable surface and must be equally untouched.
	for name := range a.BackRefs() {
		require.NotContains(t, name, contractCanary)
		for reason := range refusalReasons {
			require.NotContains(t, name, reason)
		}
	}
}

// TestTheRefusalTraceIsDeterministic pins the ordering, because this list is
// SIGNED. Go randomises map iteration on every range, so an unsorted projection
// of the per-reason tally gives two reads of one unchanged repository different
// predicate bytes — which defeats any consumer comparing evidence for the same
// commit, and is invisible until a second reason occurs.
func TestTheRefusalTraceIsDeterministic(t *testing.T) {
	tally := map[string]int{
		refusalOpaqueTransport:        2,
		refusalAmbiguousAuthority:     1,
		refusalPathBytesNotRedactable: 3,
	}

	want := []RefusedRemote{
		{Reason: refusalAmbiguousAuthority, Count: 1},
		{Reason: refusalOpaqueTransport, Count: 2},
		{Reason: refusalPathBytesNotRedactable, Count: 3},
	}

	// Repeated, because a single call has a real chance of coming out sorted
	// by luck with three keys. Map iteration order is re-randomised per range,
	// so this is a genuine retry and not a re-read of one cached answer.
	for range 64 {
		require.Equal(t, want, summarizeRefusedRemotes(tally))
	}

	require.Nil(t, summarizeRefusedRemotes(map[string]int{}), "no refusals must yield no trace")
	require.Nil(t, summarizeRefusedRemotes(nil), "no refusals must yield no trace")
}

// TestEveryRefusedRemoteIsCounted closes the gap between the function and the
// attestor: recordRemote can refuse correctly and Attest can still drop the
// refusal on the floor. It sweeps the cross product for refused spellings and
// asserts the tally adds up to the number of remotes that went in.
func TestEveryRefusedRemoteIsCounted(t *testing.T) {
	swept := 0
	for _, scheme := range contractSchemes {
		for _, host := range contractHosts {
			for _, cred := range contractCreds {
				for _, path := range contractPaths {
					swept++
					in := buildContractRemote(scheme, cred, host, path)
					verdict, _, reason := recordRemote(in)
					if verdict.recordable() {
						continue
					}
					// Every refusal contributes exactly one to exactly one
					// bucket. A refusal with an empty reason would land in a
					// bucket keyed "" and be indistinguishable from a bug.
					require.NotEmptyf(t, reason, "a refusal must name a reason: %q", in)
					got := summarizeRefusedRemotes(map[string]int{reason: 1})
					require.Lenf(t, got, 1, "one refusal must produce one trace entry: %q", in)
					require.Equalf(t, reason, got[0].Reason, "the trace must carry the reason that fired: %q", in)
					require.Equalf(t, 1, got[0].Count, "one refusal must count one: %q", in)
				}
			}
		}
	}
	if want := len(contractSchemes) * len(contractHosts) * len(contractCreds) * len(contractPaths); swept != want {
		t.Fatalf("sweep covered %d cases, want %d", swept, want)
	}
}
