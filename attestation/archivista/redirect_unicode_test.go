// jade:ring local

package archivista

import (
	"net/http"
	"net/url"
	"testing"
)

// TestRedirectRefusesUnicodeLookalikeHost: the Archivista client carries the
// upload bearer, so a redirect to a host that Unicode folding equates with
// the original (U+0130 İ lowers to i; the Kelvin sign and long s fold to k
// and s) must be refused: Go's transport maps it through IDNA to a different
// punycode host.
func TestRedirectRefusesUnicodeLookalikeHost(t *testing.T) {
	for _, h := range []struct{ spoof, real string }{
		{"cİ.example", "ci.example"},
		{"Key.example", "key.example"},
		{"ſign.example", "sign.example"},
	} {
		orig := &http.Request{URL: &url.URL{Scheme: "https", Host: h.real}}
		next := &http.Request{URL: &url.URL{Scheme: "https", Host: h.spoof}}
		if err := sameOriginRedirect(next, []*http.Request{orig}); err == nil {
			t.Errorf("followed a redirect to %q from %q", h.spoof, h.real)
		}
	}
	orig := &http.Request{URL: &url.URL{Scheme: "https", Host: "Archivista.Example"}}
	next := &http.Request{URL: &url.URL{Scheme: "HTTPS", Host: "archivista.example"}}
	if err := sameOriginRedirect(next, []*http.Request{orig}); err != nil {
		t.Errorf("an ASCII case-only difference is the same origin: %v", err)
	}
}
