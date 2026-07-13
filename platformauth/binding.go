// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package platformauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// resolveBindingPath is the platform endpoint that resolves the authenticated
// identity's repository to its tenant + product binding. It authenticates with
// a login-audience OIDC token (ambient CI workflow identity) or a platform
// session bearer, and returns the server-derived tenant/product the evidence
// should be signed against.
const resolveBindingPath = "/api/auth/resolve-binding"

// bindingResponseLimit bounds the response body read so a hostile or
// misbehaving platform cannot stream an unbounded body into memory.
const bindingResponseLimit = 1 << 20 // 1 MiB

// bindingRequestTimeout bounds the whole exchange. The token this carries is
// short-lived, but a platform that TCP-accepts then stalls must not park the
// build until the CI job timeout.
const bindingRequestTimeout = 30 * time.Second

// Binding is the tenant + product a repository resolves to for the
// authenticated identity, as returned by the platform's resolve-binding
// endpoint. All ID fields are server-VALIDATED — the client treats them as
// authoritative and signs testifysec-product:<ProductID> /
// testifysec-tenant:<TenantID> into the DSSE.
type Binding struct {
	TenantID    string
	TenantName  string
	ProductID   string
	ProductName string
}

// ProductCandidate is one product a repository maps to. Returned in the
// ambiguous case so a caller (or the automated agent reading the failure) can
// choose exactly one.
type ProductCandidate struct {
	ProductID   string
	ProductName string
}

// Sentinel errors so callers can classify a binding failure with errors.Is
// without string-matching. The concrete *RepositoryNotMappedError /
// *AmbiguousProductError carry the identifiers a caller needs to build a
// machine-actionable message.
var (
	// ErrRepositoryNotMapped: the authenticated repository is connected to no
	// product in the tenant. The build must fail rather than add more unlinked
	// evidence.
	ErrRepositoryNotMapped = errors.New("repository_not_mapped")
	// ErrAmbiguousProduct: the repository maps to more than one product and no
	// (valid) selector was supplied. The caller must pass exactly one product.
	ErrAmbiguousProduct = errors.New("ambiguous_product")
)

// RepositoryNotMappedError carries the identifiers from a repository_not_mapped
// response so a caller can name the tenant + repo in a self-correcting message.
type RepositoryNotMappedError struct {
	TenantID     string
	TenantName   string
	Repository   string
	RepositoryID string
	Remediation  string
}

func (e *RepositoryNotMappedError) Error() string {
	repo := e.Repository
	if repo == "" {
		repo = "(unknown repository)"
	}
	msg := fmt.Sprintf("repository %s is authenticated to tenant %q (%s) but is not connected to any product",
		repo, e.TenantName, e.TenantID)
	if e.Remediation != "" {
		msg += ": " + e.Remediation
	}
	return msg
}

// Is lets errors.Is(err, ErrRepositoryNotMapped) match the concrete type.
func (e *RepositoryNotMappedError) Is(target error) bool { return target == ErrRepositoryNotMapped }

// AmbiguousProductError carries the candidate list from an ambiguous_product
// response so a caller can list every product UUID + name for the agent to
// choose from.
type AmbiguousProductError struct {
	TenantID     string
	TenantName   string
	Repository   string
	RepositoryID string
	Candidates   []ProductCandidate
	Remediation  string
}

func (e *AmbiguousProductError) Error() string {
	repo := e.Repository
	if repo == "" {
		repo = "(unknown repository)"
	}
	parts := make([]string, 0, len(e.Candidates))
	for _, c := range e.Candidates {
		parts = append(parts, fmt.Sprintf("%s %q", c.ProductID, c.ProductName))
	}
	msg := fmt.Sprintf("repository %s maps to %d products in tenant %q: [%s]",
		repo, len(e.Candidates), e.TenantName, strings.Join(parts, ", "))
	if e.Remediation != "" {
		msg += ". " + e.Remediation
	}
	return msg
}

// Is lets errors.Is(err, ErrAmbiguousProduct) match the concrete type.
func (e *AmbiguousProductError) Is(target error) bool { return target == ErrAmbiguousProduct }

// ErrBindingUnavailable classifies a binding failure as "endpoint unreachable or
// not deployed" — the ONLY class the fail-closed gate is allowed to soft-skip.
var ErrBindingUnavailable = errors.New("binding_unavailable")

// BindingUnavailableError signals the endpoint could not be reached or does not
// exist yet: a transport failure (DNS/connection/TLS/timeout), a 404 with no
// typed body (the route is absent on a server that predates this feature), a 5xx
// (transient), or a 200 whose body is not JSON (the SPA index.html served by the
// catch-all on an un-deployed server). The gate degrades to a loud soft-skip on
// THIS error only; every deterministic config/auth error (repo-not-mapped,
// ambiguous, invalid product, 401, 403) fails closed.
type BindingUnavailableError struct {
	Reason string
	Err    error
}

func (e *BindingUnavailableError) Error() string {
	if e.Err != nil {
		return e.Reason + ": " + e.Err.Error()
	}
	return e.Reason
}
func (e *BindingUnavailableError) Unwrap() error        { return e.Err }
func (e *BindingUnavailableError) Is(target error) bool { return target == ErrBindingUnavailable }

// bindingErrorBody is the typed 4xx envelope the endpoint returns for the
// classified failure cases. Extra fields (tenant_name, repository_id) are
// parsed when present so a richer message can be built, but are optional in the
// wire contract.
type bindingErrorBody struct {
	Error        string             `json:"error"`
	TenantID     string             `json:"tenant_id"`
	TenantName   string             `json:"tenant_name"`
	Repository   string             `json:"repository"`
	RepositoryID string             `json:"repository_id"`
	Candidates   []bindingCandidate `json:"candidates"`
	Remediation  string             `json:"remediation"`
}

type bindingCandidate struct {
	ProductID   string `json:"product_id"`
	ProductName string `json:"product_name"`
}

// bindingOKBody is the 200 response.
type bindingOKBody struct {
	TenantID    string `json:"tenant_id"`
	TenantName  string `json:"tenant_name"`
	ProductID   string `json:"product_id"`
	ProductName string `json:"product_name"`
}

// ResolveBinding exchanges an authenticated identity for its tenant + product
// binding. It POSTs {product_id?} to <platformURL>/api/auth/resolve-binding
// with bearerToken as the Authorization bearer, and returns the server-derived
// Binding.
//
// bearerToken is a login-audience OIDC token (ambient CI workflow identity) or
// a platform session bearer. It is NEVER logged or persisted, and only ever
// sent to the platform's own origin.
//
// selectorProductID, when non-empty, disambiguates a repository that maps to
// multiple products; it must be a valid UUID and the server accepts it only if
// it is one of that repository's candidates.
//
// Errors are typed: *RepositoryNotMappedError (repo connected to no product)
// and *AmbiguousProductError (repo maps to several, no valid selector) match
// errors.Is(ErrRepositoryNotMapped) / errors.Is(ErrAmbiguousProduct) and carry
// the identifiers a caller needs to build a self-correcting message.
func ResolveBinding(platformURL, bearerToken, selectorProductID string) (Binding, error) {
	client := &http.Client{
		Timeout:       bindingRequestTimeout,
		CheckRedirect: refuseCrossOriginRedirect,
	}
	return resolveBindingWithClient(client, platformURL, bearerToken, selectorProductID)
}

// resolveBindingWithClient is ResolveBinding with an injectable client, so a
// test can supply an httptest server's client (which trusts its self-signed
// cert). The security validation (bearer present, selector UUID, https/loopback
// only) runs here so the test path exercises it too.
func resolveBindingWithClient(client *http.Client, platformURL, bearerToken, selectorProductID string) (Binding, error) {
	if strings.TrimSpace(bearerToken) == "" {
		return Binding{}, fmt.Errorf("resolve-binding: no bearer token")
	}
	if selectorProductID != "" && !isValidUUID(selectorProductID) {
		return Binding{}, fmt.Errorf("resolve-binding: product selector %q is not a valid UUID", selectorProductID)
	}
	if err := requireSecurePlatformURL(platformURL); err != nil {
		return Binding{}, err
	}

	endpoint := strings.TrimRight(NormalizeURL(platformURL), "/") + resolveBindingPath

	reqBody, err := json.Marshal(struct {
		ProductID string `json:"product_id,omitempty"`
	}{ProductID: selectorProductID})
	if err != nil {
		return Binding{}, fmt.Errorf("resolve-binding: encode request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(reqBody))
	if err != nil {
		return Binding{}, fmt.Errorf("resolve-binding: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// Transport failure (DNS, connection refused, TLS, timeout): unreachable,
		// indistinguishable from "not deployed yet" → soft-skippable.
		return Binding{}, &BindingUnavailableError{Reason: fmt.Sprintf("resolve-binding: request to %s failed", endpoint), Err: err}
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort cleanup

	body, _ := io.ReadAll(io.LimitReader(resp.Body, bindingResponseLimit)) //nolint:errcheck // status drives handling

	if resp.StatusCode == http.StatusOK {
		return parseBindingOK(body)
	}
	// A classified 4xx carries a typed body; decode it into the right (hard) error
	// so the caller (an automated agent) can self-correct from the identifiers.
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		if typed := typedBindingError(body); typed != nil {
			return Binding{}, typed
		}
	}
	// A 404 with no typed body means the ROUTE is absent (a server predating this
	// endpoint); a 5xx is a transient server error. Both are soft-skippable — the
	// endpoint is effectively unavailable. Every OTHER reached status (400 invalid
	// request, 401 unauthenticated, 403 forbidden) is a deterministic config/auth
	// error and MUST fail closed.
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode >= 500 {
		return Binding{}, &BindingUnavailableError{
			Reason: fmt.Sprintf("resolve-binding: %s returned %d (endpoint unavailable / not deployed)", endpoint, resp.StatusCode),
		}
	}
	return Binding{}, fmt.Errorf("resolve-binding: %s returned %d: %s",
		endpoint, resp.StatusCode, strings.TrimSpace(string(body)))
}

// parseBindingOK decodes and validates a 200 body. It rejects a malformed
// tenant/product UUID so a compromised or buggy platform cannot inject a
// non-UUID subject into the signed DSSE.
func parseBindingOK(body []byte) (Binding, error) {
	var ok bindingOKBody
	if err := json.Unmarshal(body, &ok); err != nil {
		// A 200 whose body is not JSON is almost always the SPA index.html served
		// by the catch-all on a server that predates this endpoint → unavailable
		// (soft-skip), NOT a hard config error that would break the merge window.
		return Binding{}, &BindingUnavailableError{Reason: "resolve-binding: 200 response body was not JSON (endpoint likely not deployed)", Err: err}
	}
	if ok.TenantID == "" || !isValidUUID(ok.TenantID) {
		return Binding{}, fmt.Errorf("resolve-binding: response carried an invalid tenant_id %q", ok.TenantID)
	}
	// Empty/invalid product_id from a real (JSON) 200 is a deterministic failure:
	// the caller is authenticated but no product is bound (e.g. a tenant-only CLI
	// session with no selector). Fail closed rather than emit product-less evidence.
	if ok.ProductID == "" || !isValidUUID(ok.ProductID) {
		return Binding{}, fmt.Errorf("resolve-binding: no product is bound to this identity (product_id %q); pass an explicit product (`cilock login --product <uuid>` / action input `product:`), or --no-product-binding to attest without one", ok.ProductID)
	}
	return Binding(ok), nil
}

// typedBindingError maps a typed 4xx body onto a concrete error, or returns nil
// when the body is not a recognised typed error (caller falls back to a generic
// status error).
func typedBindingError(body []byte) error {
	var e bindingErrorBody
	if err := json.Unmarshal(body, &e); err != nil {
		return nil //nolint:nilerr // unrecognised/invalid 4xx body -> no typed error; caller uses the generic status error
	}
	switch e.Error {
	case "repository_not_mapped":
		return &RepositoryNotMappedError{
			TenantID:     e.TenantID,
			TenantName:   e.TenantName,
			Repository:   e.Repository,
			RepositoryID: e.RepositoryID,
			Remediation:  e.Remediation,
		}
	case "ambiguous_product":
		cands := make([]ProductCandidate, 0, len(e.Candidates))
		for _, c := range e.Candidates {
			cands = append(cands, ProductCandidate(c))
		}
		return &AmbiguousProductError{
			TenantID:     e.TenantID,
			TenantName:   e.TenantName,
			Repository:   e.Repository,
			RepositoryID: e.RepositoryID,
			Candidates:   cands,
			Remediation:  e.Remediation,
		}
	default:
		return nil
	}
}

// refuseCrossOriginRedirect rejects any redirect that changes scheme+host, so
// the bearer token can never be replayed to a different origin the platform
// redirected to. Same-origin redirects (e.g. a trailing-slash normalisation)
// are allowed.
func refuseCrossOriginRedirect(req *http.Request, via []*http.Request) error {
	if len(via) == 0 {
		return nil
	}
	prev := via[len(via)-1]
	if !strings.EqualFold(req.URL.Scheme, prev.URL.Scheme) || !strings.EqualFold(req.URL.Host, prev.URL.Host) {
		return fmt.Errorf("resolve-binding: refusing cross-origin redirect to %s://%s", req.URL.Scheme, req.URL.Host)
	}
	return nil
}

// requireSecurePlatformURL refuses a platform URL that would carry the bearer
// token over cleartext to a non-loopback host. https:// is always allowed;
// http:// only for loopback (local standalone/dev). Mirrors the cilock config
// guard, reimplemented here so platformauth stays free of a cilock dependency.
func requireSecurePlatformURL(rawURL string) error {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return fmt.Errorf("resolve-binding: parse platform url: %w", err)
	}
	if u.Scheme == "https" {
		return nil
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("resolve-binding: refusing to send a bearer token over %q to a non-loopback host (%q); use https", u.Scheme, rawURL)
}

// isLoopbackHost reports whether host is a loopback target for which plaintext
// http is acceptable (local standalone/dev): "localhost", the reserved
// .localhost TLD, or a loopback IP.
func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isValidUUID reports whether s is a canonical 8-4-4-4-12 hex UUID. A local
// check keeps platformauth dependency-free while still refusing a malformed ID
// before it reaches a signed subject.
func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}
