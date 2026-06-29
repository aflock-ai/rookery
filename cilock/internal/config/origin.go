// Copyright 2026 TestifySec, Inc.
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

package config

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// SameOrigin reports whether two URLs share scheme+host (the security origin).
// The platform session token is a bearer credential scoped to the platform's
// own services; it must never travel to a host sourced from an untrusted
// discovery document. A parse failure or mismatch returns false so the token is
// withheld (fail closed). Mirrors options.sameOrigin.
func SameOrigin(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil || ua.Host == "" {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// SameOriginRedirect is a net/http CheckRedirect that refuses any redirect to a
// different origin (scheme+host) than the original request, and any redirect to
// a non-public IP literal (loopback, link-local, private). It exists because a
// bearer-bearing client follows 30x by default — a redirect to attacker.tld or
// 169.254.169.254 would resend the Authorization header and request body. Set
// this on every client that carries the session bearer.
func SameOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	orig := via[0].URL
	if !strings.EqualFold(req.URL.Scheme, orig.Scheme) || !strings.EqualFold(req.URL.Host, orig.Host) {
		return fmt.Errorf("refusing cross-origin redirect from %s://%s to %s://%s (bearer would leak)",
			orig.Scheme, orig.Host, req.URL.Scheme, req.URL.Host)
	}
	if host := req.URL.Hostname(); !isPublicRedirectHost(host) {
		return fmt.Errorf("refusing redirect to non-public host %q", host)
	}
	return nil
}

// isPublicRedirectHost reports whether host is acceptable as a redirect target.
// A hostname (non-IP) is allowed — DNS resolution is the transport's concern and
// the same-origin check already pins it. An IP literal must be a public address:
// loopback, link-local (incl. 169.254.169.254 cloud metadata), and private
// ranges are refused. Loopback is permitted only because local standalone/dev
// legitimately serves over 127.0.0.1, and the same-origin guard runs first.
func isPublicRedirectHost(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP literal — a hostname. Same-origin already constrains it.
		return true
	}
	if ip.IsLoopback() {
		return true
	}
	return !(ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast())
}
