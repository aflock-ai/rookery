// jade:ring local

package canonicaljson

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Twin of judge-api/pkg/canonicaljson/canonicaljson_test.go. The platform
// recomputes an approval's subject digest with that package before it signs,
// so every approval it signed must digest to the same value here.
//
// Pinned against node running canonicalJSON from
// jade/factory/edge/git/approvalsign.js over approvalsign.test.mjs's SEALED
// fixture (insertion-ordered JSON.stringify output as the edge sends it).
const (
	edgeFixture   = `{"version":"pushgate.policy-assignment-approval.v4","connection_id":"github.com/acme/api","generation":2,"before":[],"after":[],"before_presets":["signed"],"after_presets":["signed","tested"],"before_modes":{"signed":"block"},"after_modes":{"tested":"block","signed":"block"},"reason":"Require tests"}`
	edgeCanonical = `{"after":[],"after_modes":{"signed":"block","tested":"block"},"after_presets":["signed","tested"],"before":[],"before_modes":{"signed":"block"},"before_presets":["signed"],"connection_id":"github.com/acme/api","generation":2,"reason":"Require tests","version":"pushgate.policy-assignment-approval.v4"}`
	edgeDigest    = "ad06e54bbbaaf7e7f69c5079d7de0f97fe58588a233bb76f91927716db4597df"
)

func TestCanonicalMatchesTheEdge(t *testing.T) {
	got, err := Canonical([]byte(edgeFixture))
	require.NoError(t, err)
	require.Equal(t, edgeCanonical, string(got))
	digest, err := Digest([]byte(edgeFixture))
	require.NoError(t, err)
	require.Equal(t, edgeDigest, digest)
}

// STRINGS ARE ESCAPED AS JSON.stringify ESCAPES THEM, NOT AS encoding/json
// DOES. The input carries `<>&` (HTML-escaped by encoding/json), the escapes
// \u003c and \u003e, `/`, a quote, a backslash, control bytes, U+007F, a
// surrogate-pair escape, non-ASCII, and keys that sort E < e < U+00E9. The
// expected bytes and digest come from node running the edge's canonicalJSON;
// the platform's Go package produces the same bytes.
const (
	stringifyInput        = `{"z":"\u003cscript\u003e<b>&amp;</b>","a":"café a/b\t\"q\" back\\slash \u0001\u001f\u007f \ud83d\ude00 \u00e9","m":{"\u00e9":1,"e":2,"E":3}}`
	stringifyCanonicalHex = "7b2261223a22636166c3a920612f625c745c22715c22206261636b5c5c736c617368205c75303030315c75303031667f20f09f988020c3a9222c226d223a7b2245223a332c2265223a322c22c3a9223a317d2c227a223a223c7363726970743e3c623e26616d703b3c2f623e227d"
	stringifyDigest       = "3da53eb322f946dc38e665c17d2b7507eb3390f025ff147c6a8421369df5483c"
)

func TestCanonicalEscapesExactlyLikeJSONStringify(t *testing.T) {
	want, err := hex.DecodeString(stringifyCanonicalHex)
	require.NoError(t, err)
	got, err := Canonical([]byte(stringifyInput))
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))
	digest, err := Digest([]byte(stringifyInput))
	require.NoError(t, err)
	require.Equal(t, stringifyDigest, digest)
}

// U+2028 AND U+2029 STAY RAW, AS THE PLATFORM SIGNER EMITS THEM. These are the
// literals of judge-api's TestCanonicalEscapesExactlyLikeJSONStringify. The
// edge's canonicalJSON escapes the two separators inside string values, so the
// edge and the platform disagree on this input and the platform refuses such
// an approval at signing (subject_digest_mismatch). cilock follows the signer:
// changing this side alone would fail envelopes the platform signs.
const (
	separatorInput        = `{"version":"pushgate.policy-assignment-approval.v4","connection_id":"github.com/acme-security/api","repository_id":"9001","connection_created_at":"2026-08-01T00:00:00Z","generation":7,"before":[],"after":[],"reason":"Require\u2028tests café a/b\t<&>\u0001","before_presets":["signed"],"after_presets":["signed","tested"],"before_modes":{"signed":"block"},"after_modes":{"tested":"warn","signed":"block"}}`
	separatorCanonicalHex = "7b226166746572223a5b5d2c2261667465725f6d6f646573223a7b227369676e6564223a22626c6f636b222c22746573746564223a227761726e227d2c2261667465725f70726573657473223a5b227369676e6564222c22746573746564225d2c226265666f7265223a5b5d2c226265666f72655f6d6f646573223a7b227369676e6564223a22626c6f636b227d2c226265666f72655f70726573657473223a5b227369676e6564225d2c22636f6e6e656374696f6e5f637265617465645f6174223a22323032362d30382d30315430303a30303a30305a222c22636f6e6e656374696f6e5f6964223a226769746875622e636f6d2f61636d652d73656375726974792f617069222c2267656e65726174696f6e223a372c22726561736f6e223a2252657175697265e280a8746573747320636166c3a920612f625c743c263e5c7530303031222c227265706f7369746f72795f6964223a2239303031222c2276657273696f6e223a2270757368676174652e706f6c6963792d61737369676e6d656e742d617070726f76616c2e7634227d"
	separatorDigest       = "756c0911e95846e3f1af14a80d60272cd058fb0ceb1eedca9ae1d68d93cb18f7"
)

func TestCanonicalKeepsLineSeparatorsRawLikeThePlatformSigner(t *testing.T) {
	want, err := hex.DecodeString(separatorCanonicalHex)
	require.NoError(t, err)
	got, err := Canonical([]byte(separatorInput))
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))
	digest, err := Digest([]byte(separatorInput))
	require.NoError(t, err)
	require.Equal(t, separatorDigest, digest)
}

func TestCanonicalIsByteStableAcrossKeyOrderAtEveryDepth(t *testing.T) {
	a, err := Canonical([]byte(`{ "b": [{"y":1,"x":2}], "a": {"d":null,"c":"<x>&"} }`))
	require.NoError(t, err)
	b, err := Canonical([]byte(`{"a":{"c":"<x>&","d":null},"b":[{"x":2,"y":1}]}`))
	require.NoError(t, err)
	require.Equal(t, string(a), string(b))
	require.Equal(t, `{"a":{"c":"<x>&","d":null},"b":[{"x":2,"y":1}]}`, string(a))
}

// Number literals pass through verbatim, as the platform's package keeps them.
// The edge only ever sends JSON.stringify's shortest form, which is unchanged
// by this; normalising here alone would split cilock from the signer.
func TestCanonicalKeepsNumberLiteralsVerbatim(t *testing.T) {
	got, err := Canonical([]byte(`{"b":1.0,"a":1e2,"c":-0,"d":12345678901234567890}`))
	require.NoError(t, err)
	require.Equal(t, `{"a":1e2,"b":1.0,"c":-0,"d":12345678901234567890}`, string(got))
}

func TestCanonicalRefusesAnythingButOneJSONValue(t *testing.T) {
	for _, raw := range []string{``, ` `, `{`, `[1,]`, `{} {}`, `{}}`, `{}]`, `{}x`, `1 2`} {
		_, err := Canonical([]byte(raw))
		require.Error(t, err, "must be refused: %q", raw)
		_, err = Digest([]byte(raw))
		require.Error(t, err, "no digest may be computed for %q", raw)
	}
}

// A DUPLICATE KEY MAKES A DOCUMENT MEAN TWO THINGS AT ONCE. Go's decoder keeps
// the LAST occurrence and says nothing; a first-wins parser reads the other.
// The key comparison is on DECODED names, so an escape cannot hide a repeat.
func TestCanonicalRefusesDuplicateKeys(t *testing.T) {
	for _, raw := range []string{
		`{"a":1,"a":2}`,
		`{"repository_id":"424242","version":"v4","repository_id":"9001"}`,
		`{"outer":{"b":1,"b":2}}`,
		`{"list":[{"c":1,"c":2}]}`,
		`{"a":1,"b":{"x":[{"d":1,"d":2}]}}`,
		`{"a":1,"\u0061":2}`,
		`{"approver":{"email":"a@x.test"},"approv\u0065r":{"email":"b@x.test"}}`,
	} {
		_, err := Canonical([]byte(raw))
		require.ErrorIs(t, err, ErrDuplicateKey, "duplicate key must be refused: %s", raw)
		_, err = Digest([]byte(raw))
		require.Error(t, err, "no digest may be computed for %s", raw)
		require.ErrorIs(t, RejectAmbiguous([]byte(raw)), ErrDuplicateKey, raw)
	}
}

// The same NAME at different DEPTHS is not a duplicate: "signed" is a key in
// both before_modes and after_modes on every real approval.
func TestCanonicalAcceptsTheSameKeyNameAtDifferentDepths(t *testing.T) {
	for _, raw := range []string{
		`{"before_modes":{"signed":"block"},"after_modes":{"signed":"block"}}`,
		`{"a":{"x":1},"b":{"x":2},"c":[{"x":3},{"x":4}]}`,
		edgeFixture,
	} {
		_, err := Canonical([]byte(raw))
		require.NoError(t, err, "same name at different depths is legitimate: %s", raw)
	}
}

// A STRING GO WOULD SILENTLY REWRITE HAS NO SINGLE MEANING. encoding/json
// turns invalid UTF-8 and every unpaired surrogate escape into U+FFFD, while
// JavaScript and Python keep a lone surrogate. Distinct signed bytes would
// then share one digest, and readers would disagree on the value. Neither
// form occurs in a platform-signed payload, which the platform re-serialises
// as valid UTF-8 before signing, so refusing them costs no real approval.
func TestCanonicalRefusesStringsGoWouldSilentlyRewrite(t *testing.T) {
	var high, low string
	require.NoError(t, json.Unmarshal([]byte(`"\ud800"`), &high))
	require.NoError(t, json.Unmarshal([]byte(`"\udfff"`), &low))
	require.Equal(t, high, low, "premise: encoding/json collapses distinct lone surrogates")

	for _, raw := range []string{
		"{\"reason\":\"a\xffb\"}",
		"{\"reason\":\"a\xfeb\"}",
		"{\"k\xc3\":1}",
		"{\"cesu\":\"\xed\xa0\x80\"}",
		"{\"overlong\":\"\xc0\xaf\"}",
		`{"reason":"\ud800"}`,
		`{"reason":"\udfff"}`,
		`{"reason":"x\ud83d"}`,
		`{"reason":"\ud83dx"}`,
		`{"reason":"\ud83d\u0041"}`,
		`{"reason":"\ude00\ud83d"}`,
		`{"reason":"\ud83d\ud83d"}`,
		`{"reason":"\\\ud800"}`,
		`{"\uDBFF":"key"}`,
		`[["\uDC00"]]`,
	} {
		_, err := Canonical([]byte(raw))
		require.ErrorIs(t, err, ErrAmbiguousString, "must be refused: %q", raw)
		_, err = Digest([]byte(raw))
		require.Error(t, err, "no digest may be computed for %q", raw)
		require.ErrorIs(t, RejectAmbiguous([]byte(raw)), ErrAmbiguousString, "%q", raw)
	}
}

func TestCanonicalAcceptsPairedSurrogatesAndEscapedBackslashes(t *testing.T) {
	const emoji = "\xf0\x9f\x98\x80"
	for raw, want := range map[string]string{
		`{"a":"\ud83d\ude00"}`:   `{"a":"` + emoji + `"}`,
		`{"a":"\uD83D\uDE00"}`:   `{"a":"` + emoji + `"}`,
		`{"a":"\\ud800"}`:        `{"a":"\\ud800"}`,
		`{"a":"\\\ud83d\ude00"}`: `{"a":"\\` + emoji + `"}`,
		`{"\ud83d\ude00":"k"}`:   `{"` + emoji + `":"k"}`,
		`{"a":"\ufffd"}`:         `{"a":"` + "\xef\xbf\xbd" + `"}`,
		`{"a":"\u2028"}`:         `{"a":"` + "\xe2\x80\xa8" + `"}`,
	} {
		got, err := Canonical([]byte(raw))
		require.NoError(t, err, raw)
		require.Equal(t, want, string(got), raw)
		require.NoError(t, RejectAmbiguous([]byte(raw)), raw)
	}
}

func TestCanonicalRefusesExcessiveNestingWithoutPanicking(t *testing.T) {
	const depth = 20000
	raw := strings.Repeat("[", depth) + strings.Repeat("]", depth)
	_, err := Canonical([]byte(raw))
	require.Error(t, err)
}
