// Copyright 2025 The Aflock Authors
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

package ociref

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Resolver resolves an OCI reference to its content digest via the registry's
// HEAD /v2/<repo>/manifests/<tag> endpoint, including the standard bearer
// token challenge handshake.
//
// The zero value resolves anonymously through http.DefaultClient against the
// reference's host as parsed. Override HTTPClient to plumb a test transport;
// HostOverride remaps parsed hosts to an httptest server address.
type Resolver struct {
	HTTPClient *http.Client

	// HostOverride maps the parsed Reference.Host to a substitute base
	// authority (e.g. "127.0.0.1:54321") used to construct the registry
	// URL. Hits an httptest.Server in tests; in production it stays empty.
	HostOverride map[string]string
}

// manifestAccept — the resolver advertises support for image and list
// manifest types so registries return the right Docker-Content-Digest for
// multi-arch refs (the index digest, not a per-arch image digest).
var manifestAccept = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}

// Resolve parses the reference and, if it's not already pinned to a digest,
// issues HEAD requests against the registry's manifest endpoint to find one.
func (r *Resolver) Resolve(reference string) (string, error) {
	ref, err := Parse(reference)
	if err != nil {
		return "", err
	}
	if ref.Digest != "" {
		return ref.Digest, nil
	}

	client := r.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	host := ref.Host
	if override, ok := r.HostOverride[host]; ok {
		host = override
	}

	// Try the call with no auth first. If we get 401, follow the
	// WWW-Authenticate challenge to a token endpoint and retry once.
	scheme := "https"
	if isPlainHTTPHost(host) {
		scheme = "http"
	}
	manifestURL := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, host, ref.Repo, ref.Identifier())

	resp, err := r.head(client, manifestURL, "")
	if err != nil {
		return "", err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		token, terr := r.fetchToken(client, resp.Header.Get("WWW-Authenticate"))
		_ = resp.Body.Close()
		if terr != nil {
			return "", fmt.Errorf("bearer challenge for %s: %w", reference, terr)
		}
		resp, err = r.head(client, manifestURL, "Bearer "+token)
		if err != nil {
			return "", err
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("registry returned %d for %s", resp.StatusCode, reference)
	}
	digest := resp.Header.Get("Docker-Content-Digest")
	if digest == "" {
		return "", fmt.Errorf("registry response for %s missing Docker-Content-Digest header", reference)
	}
	return digest, nil
}

func (r *Resolver) head(client *http.Client, url, auth string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodHead, url, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", strings.Join(manifestAccept, ","))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return client.Do(req)
}

// fetchToken parses a WWW-Authenticate challenge of the form
//   Bearer realm="https://auth.example/token",service="registry",scope="repository:foo:pull"
// and fetches a bearer token from the realm endpoint.
func (r *Resolver) fetchToken(client *http.Client, challenge string) (string, error) {
	scheme, params, err := parseChallenge(challenge)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(scheme, "Bearer") {
		return "", fmt.Errorf("unsupported auth scheme %q", scheme)
	}
	realm := params["realm"]
	if realm == "" {
		return "", errors.New("Bearer challenge missing realm")
	}

	tokenURL := realm
	q := url.Values{}
	for _, k := range []string{"service", "scope"} {
		if v := params[k]; v != "" {
			q.Add(k, v)
		}
	}
	if encoded := q.Encode(); encoded != "" {
		if strings.Contains(tokenURL, "?") {
			tokenURL += "&" + encoded
		} else {
			tokenURL += "?" + encoded
		}
	}

	req, err := http.NewRequest(http.MethodGet, tokenURL, http.NoBody)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if body.Token != "" {
		return body.Token, nil
	}
	if body.AccessToken != "" {
		return body.AccessToken, nil
	}
	return "", errors.New("token response had neither 'token' nor 'access_token'")
}

// parseChallenge cracks open a single WWW-Authenticate header value. It
// handles the realm/service/scope keys we care about; unknown keys are
// passed through.
func parseChallenge(h string) (string, map[string]string, error) {
	h = strings.TrimSpace(h)
	if h == "" {
		return "", nil, errors.New("empty challenge")
	}
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok {
		return "", nil, fmt.Errorf("challenge missing space-delimited params: %q", h)
	}
	params := map[string]string{}
	for _, kv := range splitCommaOutsideQuotes(rest) {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"`)
		params[strings.TrimSpace(k)] = v
	}
	return scheme, params, nil
}

// splitCommaOutsideQuotes splits "a=\"x,y\",b=z" into [a="x,y", b=z].
func splitCommaOutsideQuotes(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i, r := range s {
		switch r {
		case '"':
			depth ^= 1
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// isPlainHTTPHost returns true for hosts that should be reached over HTTP
// rather than HTTPS. Used so httptest servers (with their bound ports) and
// localhost dev registries work in tests.
func isPlainHTTPHost(host string) bool {
	if host == "" {
		return false
	}
	// Anything pointing at 127.0.0.1 or localhost with a port is dev/test.
	if strings.HasPrefix(host, "127.0.0.1") || strings.HasPrefix(host, "localhost") {
		return true
	}
	return false
}
