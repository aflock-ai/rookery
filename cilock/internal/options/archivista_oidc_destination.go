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

package options

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/aflock-ai/rookery/platformauth"
)

// archivistaAudienceNamesDestination refuses to send a CI OIDC token to an
// Archivista its audience does not name. The audience is a credential scope:
// a token minted for P/archivista is one P accepts as the repository's trusted
// upload credential, so any other server it is sent to can replay it at P.
// Before this check, --archivista-server pointed anywhere else (a typo, a
// public or third-party Archivista, an injected flag or env) received such a
// token.
//
// The comparison is audience to destination, not "must be the platform": a
// bring-your-own Archivista with its own audience is fine. Origin is scheme,
// host and effective port, compared without case; the path must be the one the
// server serves, trailing slash aside. An audience that is not an absolute
// http(s) URL cannot name a destination and is refused, and so is one carrying
// user info, query or fragment.
func archivistaAudienceNamesDestination(audience, destination string) error {
	a, aerr := canonicalEndpoint(audience)
	d, derr := canonicalEndpoint(destination)
	switch {
	case aerr != nil:
		return fmt.Errorf("refusing to send a CI OIDC token for audience %q to Archivista %q: the audience is not an http(s) URL naming that server (%v); set --archivista-audience to the server's own URL",
			audience, destination, aerr)
	case derr != nil:
		return fmt.Errorf("refusing to send a CI OIDC token for audience %q to Archivista %q: the Archivista URL is not an http(s) URL (%v)",
			audience, destination, derr)
	case a != d:
		return fmt.Errorf("refusing to send a CI OIDC token for audience %q to Archivista %q: the token is a credential for %s, and any other server it reaches can replay it there; point --archivista-server at %s, or set --archivista-audience to the server's own URL for a different Archivista",
			audience, destination, a, a)
	}
	return nil
}

// canonicalEndpoint is scheme://host:port/path, lower-cased scheme and host,
// default port filled in, trailing slash removed.
func canonicalEndpoint(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || u.Hostname() == "" {
		return "", fmt.Errorf("not an absolute http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("carries user info, a query or a fragment")
	}
	// strings.ToLower below folds Unicode (U+0130 İ becomes i), while the HTTP
	// transport maps a non-ASCII host through IDNA to a different punycode
	// host, so two distinct servers could compare equal. Only an ASCII host
	// (an internationalized one in its xn-- form) can name a destination.
	if !platformauth.IsASCII(u.Hostname()) {
		return "", fmt.Errorf("host %q is not ASCII; give an internationalized host in its punycode (xn--) form", u.Hostname())
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"https": "443", "http": "80"}[scheme]
	}
	return scheme + "://" + strings.ToLower(u.Hostname()) + ":" + port + strings.TrimRight(u.EscapedPath(), "/"), nil
}
