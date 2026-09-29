// Copyright 2026 The Rookery Contributors
// SPDX-License-Identifier: Apache-2.0

// jade:ring local

package platformauth

import (
	"net/http"
	"net/url"
	"testing"
)

// TestResolveBindingRedirectRefusesUnicodeLookalikeHost: the resolve-binding
// client carries the CI token as a bearer, so a redirect to a lookalike host
// must be refused like any other cross-origin redirect.
func TestResolveBindingRedirectRefusesUnicodeLookalikeHost(t *testing.T) {
	for r, ascii := range asciiLookalikes() {
		prev := &http.Request{URL: &url.URL{Scheme: "https", Host: "c" + string(ascii) + ".example"}}
		next := &http.Request{URL: &url.URL{Scheme: "https", Host: "c" + string(r) + ".example"}}
		if err := refuseCrossOriginRedirect(next, []*http.Request{prev}); err == nil {
			t.Errorf("followed a redirect to %q (U+%04X) from %q", next.URL.Host, r, prev.URL.Host)
		}
	}
}
