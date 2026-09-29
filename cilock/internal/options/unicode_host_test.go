// jade:ring local

package options

import "testing"

// unicodeLookalikeHosts are hosts that a Unicode-aware comparison folds onto
// an ASCII host while Go's HTTP transport sends them, through IDNA, to a
// different punycode host: U+0130 (İ) lowers to i, and U+212A (Kelvin sign)
// and U+017F (long s) fold to k and s. The full value space is enumerated in
// platformauth.TestSameSchemeHostRefusesEveryUnicodeLookalike.
var unicodeLookalikeHosts = []struct{ spoof, real string }{
	{"cİ.example", "ci.example"},
	{"Key.example", "key.example"},
	{"ſign.example", "sign.example"},
}

// TestArchivistaDestinationRefusesUnicodeLookalikeHost: the CI upload token's
// audience check must not let a lookalike destination pass for the audience's
// host.
func TestArchivistaDestinationRefusesUnicodeLookalikeHost(t *testing.T) {
	for _, h := range unicodeLookalikeHosts {
		aud := "https://" + h.real + "/archivista"
		dst := "https://" + h.spoof + "/archivista"
		if err := archivistaAudienceNamesDestination(aud, dst); err == nil {
			t.Errorf("audience %q admitted destination %q", aud, dst)
		}
		if err := archivistaAudienceNamesDestination(dst, dst); err == nil {
			t.Errorf("a non-ASCII audience host %q was admitted; it must be given in punycode", dst)
		}
	}
}

// TestSameOriginRefusesUnicodeLookalikeHost: the session bearer's same-origin
// guard, a sibling of the destination check.
func TestSameOriginRefusesUnicodeLookalikeHost(t *testing.T) {
	for _, h := range unicodeLookalikeHosts {
		if sameOrigin("https://"+h.real, "https://"+h.spoof) {
			t.Errorf("sameOrigin admitted %q for %q", h.spoof, h.real)
		}
	}
}
