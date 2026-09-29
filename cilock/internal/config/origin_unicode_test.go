// jade:ring local

package config

import (
	"net/http"
	"net/url"
	"testing"
)

// TestOriginChecksRefuseUnicodeLookalikeHost: SameOrigin (the discovery
// document's bearer guard) and SameOriginRedirect (every bearer client's
// redirect guard) must not fold a Unicode lookalike onto an ASCII host that
// the transport would then leave for a different punycode host.
func TestOriginChecksRefuseUnicodeLookalikeHost(t *testing.T) {
	for _, h := range []struct{ spoof, real string }{
		{"cİ.example", "ci.example"},
		{"Key.example", "key.example"},
		{"ſign.example", "sign.example"},
	} {
		if SameOrigin("https://"+h.real, "https://"+h.spoof) {
			t.Errorf("SameOrigin admitted %q for %q", h.spoof, h.real)
		}
		orig := &http.Request{URL: &url.URL{Scheme: "https", Host: h.real}}
		next := &http.Request{URL: &url.URL{Scheme: "https", Host: h.spoof}}
		if err := SameOriginRedirect(next, []*http.Request{orig}); err == nil {
			t.Errorf("SameOriginRedirect followed %q from %q", h.spoof, h.real)
		}
	}
}
