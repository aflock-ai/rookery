// Copyright 2021 The Witness Contributors
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

package jwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/redact"
	"github.com/invopop/jsonschema"
	"gopkg.in/go-jose/go-jose.v2"
	"gopkg.in/go-jose/go-jose.v2/jwt"
)

const (
	Name    = "jwt"
	Type    = "https://aflock.ai/attestations/jwt/v0.1"
	RunType = attestation.PreMaterialRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
}

type ErrInvalidToken string

func (e ErrInvalidToken) Error() string {
	return fmt.Sprintf("invalid token: \"%v\"", string(e))
}

type Option func(a *Attestor)

type VerificationInfo struct {
	JWKSUrl string          `json:"jwksUrl"`
	JWK     jose.JSONWebKey `json:"jwk"`
}

type Attestor struct {
	Claims     map[string]interface{} `json:"claims"`
	VerifiedBy VerificationInfo       `json:"verifiedBy,omitempty"`
	jwksUrl    string
	token      string
}

func WithToken(token string) Option {
	return func(a *Attestor) {
		a.token = token
	}
}

func WithJWKSUrl(url string) Option {
	return func(a *Attestor) {
		a.jwksUrl = url
	}
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		Claims: make(map[string]interface{}),
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Attestor) Schema() *jsonschema.Schema {
	// Reflect the single pointer (a is already *Attestor; the old &a passed a
	// **Attestor, a degenerate extra indirection — see R3-250).
	s := jsonschema.Reflect(a)
	// VerifiedBy.JWK is a jose.JSONWebKey, whose custom MarshalJSON emits JWK
	// JSON (kty/n/e/kid/alg/use/x5c/x5t) — NOT the reflected Go struct shape
	// (Key/KeyID/Algorithm/Certificates/...). The reflector can't see through
	// the custom marshaller, so it emits a schema requiring the Go field names
	// the real predicate never has, and a valid JWT predicate fails its own
	// Schema(). Patch the jwk subschema to the honest "opaque object" (its
	// internal JWK shape is RFC 7517's to define, not ours), mirroring sbom's
	// permissive-object Schema() and aws-iid's post-reflect patch.
	PermissiveJWK(s)
	return s
}

// permissiveJWKSchema is the honest schema for a jose.JSONWebKey field: an
// object whose contents (the RFC 7517 JWK members) are opaque to us because the
// type marshals through its own MarshalJSON. No Required, AdditionalProperties
// allowed — any well-formed JWK JSON validates.
func permissiveJWKSchema() *jsonschema.Schema {
	return &jsonschema.Schema{Type: "object", AdditionalProperties: jsonschema.TrueSchema}
}

// PermissiveJWK rewrites every "jwk" property (and any JSONWebKey-named $def) in
// a reflected schema to permissiveJWKSchema(). It walks both the referenced
// ($defs) and inlined (DoNotReference) forms so callers using either reflector
// mode get an honest schema. Exported so the github attestor — which embeds a
// *jwt.Attestor but reflects its OWN struct (with DoNotReference, inlining the
// jwk) — reuses the same fix instead of duplicating the jose-marshalling
// knowledge.
func PermissiveJWK(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	for name := range s.Definitions {
		if name == "JSONWebKey" || name == "JsonWebKey" {
			s.Definitions[name] = permissiveJWKSchema()
			continue
		}
		patchJWKProps(s.Definitions[name])
	}
	patchJWKProps(s)
}

// patchJWKProps recursively replaces any property keyed "jwk" with the
// permissive object schema, descending through nested properties, items, and
// the *Of combinators so a deeply-embedded jwk (github's
// jwt.verifiedBy.jwk) is reached.
func patchJWKProps(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	if s.Properties != nil {
		for pair := s.Properties.Oldest(); pair != nil; pair = pair.Next() {
			if pair.Key == "jwk" {
				s.Properties.Set(pair.Key, permissiveJWKSchema())
				continue
			}
			patchJWKProps(pair.Value)
		}
	}
	patchJWKProps(s.Items)
	patchJWKProps(s.AdditionalProperties)
	for _, sub := range s.AllOf {
		patchJWKProps(sub)
	}
	for _, sub := range s.AnyOf {
		patchJWKProps(sub)
	}
	for _, sub := range s.OneOf {
		patchJWKProps(sub)
	}
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	if a.token == "" {
		return ErrInvalidToken(a.token)
	}

	parsed, err := jwt.ParseSigned(a.token)
	if err != nil {
		return fmt.Errorf("error parsing token: %w", err)
	}

	jwksClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := jwksClient.Get(a.jwksUrl)
	if err != nil {
		return jwksFetchError(a.jwksUrl, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code from JWKS endpoint %s: %d", redact.URLCredentials(a.jwksUrl), resp.StatusCode)
	}

	// Limit JWKS response to 1MB to prevent OOM from a malicious endpoint.
	const maxJWKSSize = 1 << 20 // 1MB
	jwks := jose.JSONWebKeySet{}
	limitedBody := io.LimitReader(resp.Body, maxJWKSSize)
	decoder := json.NewDecoder(limitedBody)
	if err := decoder.Decode(&jwks); err != nil {
		return fmt.Errorf("error decoding jwks: %w", err)
	}

	// Verify the SIGNATURE against the JWKS and extract the claims. We
	// intentionally do NOT call .Validate() — no exp/nbf/aud time-validity check.
	// BY DESIGN: this attestor's job is to RECORD the token's claims as they were
	// when it was issued. Whether those claims were time-valid is a
	// VERIFICATION-TIME concern, enforced by policy against the attestation's own
	// witness/TSA timestamp (which establishes when the evidence was captured) —
	// not re-checked here at capture time. Re-checking exp here would make a
	// faithfully-recorded, later-verified attestation spuriously fail once the
	// short-lived OIDC token expired, which is exactly what the timestamped
	// signature chain exists to avoid.
	if err := parsed.Claims(jwks, &a.Claims); err != nil {
		return fmt.Errorf("error parsing claims: %w", err)
	}

	keyID := ""
	for _, header := range parsed.Headers {
		if header.KeyID != "" {
			keyID = header.KeyID
			break
		}
	}

	possibleJwk := jwks.Key(keyID)
	if len(possibleJwk) <= 0 {
		return nil
	}

	a.VerifiedBy = VerificationInfo{
		// The fetch above used the URL as configured; the recorded copy
		// loses a login in its userinfo (see redact.URLCredentials).
		JWKSUrl: redact.URLCredentials(a.jwksUrl),
		JWK:     possibleJwk[0],
	}

	return nil
}

// jwksFetchError is the error for a failed fetch of rawURL. It names the
// endpoint by redact.URLCredentials: net/http's *url.Error takes out only the
// password, so a token in the username slot would reach logs and the run's
// failure output.
//
// The error net/http wraps is text taken from the URL too. url.Parse quotes
// the bytes it refused ("invalid port \":SECRET\" after host" for
// "https://ci:SECRET/part@host/keys", "invalid URL escape \"%zz\"" for a
// password that holds one), and a dial names the host and port Go read, which,
// where the parsers do not agree where a userinfo ends, is part of it
// ("http://127.0.0.1:1/x@host" is user "127.0.0.1" and password "1/x" to
// Python's proxy parser). So that error is kept only when it can name nothing
// the redacted endpoint does not: when the URL holds no credential, or when Go
// parsed the URL and dials the host the redacted endpoint still names.
// Otherwise only its kind is said, and it is not wrapped, so no caller that
// walks the chain prints it either.
func jwksFetchError(rawURL string, err error) error {
	endpoint := redact.URLCredentials(rawURL)
	op := "Get"
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		op, err = urlErr.Op, urlErr.Err
	}
	if endpoint == rawURL || (op != "parse" && dialsNamedHost(rawURL, endpoint)) {
		return fmt.Errorf("error fetching jwks: %s %q: %w", op, endpoint, err)
	}
	kind := "the request failed"
	switch {
	case op == "parse":
		kind = "the URL does not parse"
	case urlErr != nil && urlErr.Timeout():
		kind = "the request timed out"
	}
	return fmt.Errorf("error fetching jwks: %s %q: %s (the detail is withheld because it can quote the URL's credential)", op, endpoint, kind)
}

// dialsNamedHost reports whether Go dials, for rawURL, the host that its
// redacted form endpoint names.
func dialsNamedHost(rawURL, endpoint string) bool {
	dialed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	named, err := url.Parse(endpoint)
	return err == nil && named.Host != "" && named.Host == dialed.Host
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}
