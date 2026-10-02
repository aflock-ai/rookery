// jade:ring local

package git

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The function-level authority-introducer sweep moved to attestation/gitremote
// with the grammar (#9211). This is its end-to-end half, which needs a real
// repository and the attestor, so it stays with the attestor. The two helpers
// below are copies of the ones that sweep uses: test code cannot cross the
// package boundary, and a test must not ask production code whether
// production code worked.

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

// recordedRemoteCarriesUserinfo: a ":" before the first "@" with no "/" between.
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
