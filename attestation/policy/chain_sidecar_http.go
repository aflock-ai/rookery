// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/chain"
)

// HTTPChainSidecarSource fetches chain sidecars over HTTP(S) using a
// caller-supplied URL template. The template uses placeholders the
// source substitutes at lookup time:
//
//   - {envelopeDigest}   — the upstream step's signed-payload sha256 hex
//   - {downstreamStep}   — the downstream step's name (the consumer)
//   - {upstreamStep}     — the upstream step's name (the producer)
//
// Example: an Archivista deployment that serves chain sidecars at
// `https://archivista.example/sidecar/{envelopeDigest}.chain.json`
// would set `URLTemplate` to that string. A generic blob store keyed
// by (consumer, producer) might use
// `https://blob.example/{downstreamStep}/{upstreamStep}/sidecar.json`.
//
// HTTP status semantics:
//
//   - 200 with valid JSON → returned as a *ChainSidecar.
//   - 404 (or any "not found" mapped status) → (nil, nil). The
//     verifier interprets that as "no chain sidecar for this pair"
//     and falls through to legacy comparison.
//   - Any other non-2xx → error.
//
// Security:
//
//   - The verifier ALSO checks envelope-digest binding when running
//     the proofs, so the source's binding check here is defence in
//     depth, not the only line of defence.
//   - URLs are passed through net/url-style substitution to defang
//     placeholder injection; raw characters like '/' or '..' from a
//     hostile policy step name are not URL-escaped here because the
//     filesystem source's path-traversal guard catches that earlier
//     in the policy DAG. If you wire this source from operator
//     input directly, sanitise upstream.
type HTTPChainSidecarSource struct {
	// URLTemplate is the address pattern. Empty disables the source.
	URLTemplate string

	// Client is the HTTP client used for fetches. nil → http.DefaultClient
	// with DefaultHTTPChainSidecarTimeout applied per request (some
	// sidecars are large for high-cardinality material sets; tighter
	// timeouts cause false negatives on cold caches). Operators
	// override via the --chain-sidecar-http-timeout CLI flag.
	Client *http.Client

	// Headers are merged into every request — useful for bearer tokens
	// or Archivista-specific authentication. Nil means no extra headers.
	Headers map[string]string

	// MaxBodyBytes caps the response body the source will read from a
	// server. Zero falls back to DefaultHTTPChainSidecarMaxBytes
	// (64 MiB). Operators override via the
	// --chain-sidecar-http-max-bytes CLI flag.
	MaxBodyBytes int64
}

// DefaultHTTPChainSidecarTimeout is the per-request HTTP client
// timeout used when no override is supplied. Picked generously
// (30s) because cold-cache fetches of high-cardinality sidecars
// from Archivista take meaningful wall-clock time. Operators
// override via the --chain-sidecar-http-timeout flag.
const DefaultHTTPChainSidecarTimeout = 30 * time.Second

// DefaultHTTPChainSidecarMaxBytes caps the HTTP response body the
// source will read. A realistic sidecar (12k materials × 14 proof
// depth × 32 bytes + JSON overhead) is ≈ 6 MB; 64 MiB is well
// above that but well below memory exhaustion. Operators override
// via the --chain-sidecar-http-max-bytes flag.
const DefaultHTTPChainSidecarMaxBytes int64 = 64 << 20

// NewHTTPChainSidecarSource builds a source with sensible defaults.
// An empty URLTemplate is allowed and short-circuits to "no source"
// the same way an empty Dir does in FilesystemChainSidecarSource.
func NewHTTPChainSidecarSource(urlTemplate string) *HTTPChainSidecarSource {
	return &HTTPChainSidecarSource{
		URLTemplate:  urlTemplate,
		Client:       &http.Client{Timeout: DefaultHTTPChainSidecarTimeout},
		MaxBodyBytes: DefaultHTTPChainSidecarMaxBytes,
	}
}

// NewHTTPChainSidecarSourceWithOptions builds a source with operator
// overrides for the timeout and response-body cap. Zero values mean
// "use the compiled-in default" (DefaultHTTPChainSidecarTimeout,
// DefaultHTTPChainSidecarMaxBytes). Use this constructor when the
// CLI layer is plumbing through --chain-sidecar-http-timeout and
// --chain-sidecar-http-max-bytes.
func NewHTTPChainSidecarSourceWithOptions(urlTemplate string, timeout time.Duration, maxBodyBytes int64) *HTTPChainSidecarSource {
	if timeout <= 0 {
		timeout = DefaultHTTPChainSidecarTimeout
	}
	if maxBodyBytes <= 0 {
		maxBodyBytes = DefaultHTTPChainSidecarMaxBytes
	}
	return &HTTPChainSidecarSource{
		URLTemplate:  urlTemplate,
		Client:       &http.Client{Timeout: timeout},
		MaxBodyBytes: maxBodyBytes,
	}
}

// LookupChainSidecar fetches the chain sidecar for the given chain
// edge. See HTTPChainSidecarSource doc-comment for URL template
// semantics and status-code mapping.
func (s *HTTPChainSidecarSource) LookupChainSidecar(ctx context.Context, downstreamStep, upstreamStep, upstreamEnvelopeDigest string) (*chain.ChainSidecar, error) { //nolint:gocyclo // validate → fetch → status-switch → parse → bind-check; one linear path
	if s == nil || s.URLTemplate == "" {
		return nil, nil //nolint:nilnil // disabled
	}
	if downstreamStep == "" || upstreamStep == "" || upstreamEnvelopeDigest == "" {
		return nil, errors.New("http chain sidecar source: downstreamStep, upstreamStep, and upstreamEnvelopeDigest are all required")
	}
	// Validate step names before URL substitution: reject any
	// character that could escape a URL path segment. The policy DAG
	// is signed but step names are author-controlled — a hostile
	// policy could use names like '../admin' or 'a?b=c' to redirect
	// fetches. Mirrors the filesystem source's path-traversal guard
	// so HTTP-only deployments (no multi-source fallback) get the
	// same defense.
	if err := validateStepNameForURL(downstreamStep); err != nil {
		return nil, fmt.Errorf("http chain sidecar source: downstreamStep: %w", err)
	}
	if err := validateStepNameForURL(upstreamStep); err != nil {
		return nil, fmt.Errorf("http chain sidecar source: upstreamStep: %w", err)
	}
	if err := validateEnvelopeDigestForURL(upstreamEnvelopeDigest); err != nil {
		return nil, fmt.Errorf("http chain sidecar source: upstreamEnvelopeDigest: %w", err)
	}
	// PathEscape after validation: validation rejects path-bearing
	// characters (/, ..), PathEscape encodes any remaining URL-special
	// bytes (?, #, %, etc.). Belt-and-braces.
	urlStr := s.URLTemplate
	urlStr = strings.ReplaceAll(urlStr, "{envelopeDigest}", url.PathEscape(upstreamEnvelopeDigest))
	urlStr = strings.ReplaceAll(urlStr, "{downstreamStep}", url.PathEscape(downstreamStep))
	urlStr = strings.ReplaceAll(urlStr, "{upstreamStep}", url.PathEscape(upstreamStep))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("http chain sidecar source: build request: %w", err)
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")

	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultHTTPChainSidecarTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http chain sidecar source: fetch %s: %w", urlStr, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusOK:
		// fall through
	case http.StatusNotFound, http.StatusGone:
		return nil, nil //nolint:nilnil // no sidecar published for this pair
	default:
		// Read up to 1 KiB of body for diagnostics; servers vary.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("http chain sidecar source: unexpected status %d from %s: %s", resp.StatusCode, urlStr, strings.TrimSpace(string(body)))
	}

	// Cap the body size — a hostile server could otherwise OOM the
	// verifier with a multi-GB response. The default
	// (DefaultHTTPChainSidecarMaxBytes, 64 MiB) is well above any
	// realistic sidecar (12k materials × 14 proof depth × 32 bytes
	// + JSON overhead ≈ 6 MB) but well below memory exhaustion.
	// Operators override via --chain-sidecar-http-max-bytes.
	maxBody := s.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = DefaultHTTPChainSidecarMaxBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("http chain sidecar source: read body: %w", err)
	}

	var sidecar chain.ChainSidecar
	if err := json.Unmarshal(body, &sidecar); err != nil {
		return nil, fmt.Errorf("http chain sidecar source: decode body: %w", err)
	}

	// Same source-side binding checks as the filesystem source.
	// Belt-and-braces with the verifier's own envelope check.
	if sidecar.SourceStep.StepName != "" && sidecar.SourceStep.StepName != upstreamStep {
		return nil, fmt.Errorf("http chain sidecar from %s declares sourceStep=%q but policy edge expects %q",
			urlStr, sidecar.SourceStep.StepName, upstreamStep)
	}
	if sidecar.SourceStep.EnvelopeDigest != "" && sidecar.SourceStep.EnvelopeDigest != upstreamEnvelopeDigest {
		return nil, fmt.Errorf("http chain sidecar from %s binds to envelope %s but policy edge upstream envelope is %s",
			urlStr, sidecar.SourceStep.EnvelopeDigest, upstreamEnvelopeDigest)
	}

	return &sidecar, nil
}

// validateStepNameForURL rejects step names that could escape the
// URL path segment they get substituted into. Mirrors the
// filesystem source's path-traversal guard: no '/', no '..' path
// components, no URL control characters. Step names are
// policy-signed but author-controlled — a hostile policy author
// could otherwise redirect chain-sidecar fetches to arbitrary URLs.
func validateStepNameForURL(s string) error {
	if s == "" {
		return errors.New("step name must not be empty")
	}
	return rejectURLInjectionChars("step name", s)
}

// validateEnvelopeDigestForURL rejects URL-injection characters
// in the digest before substitution. We deliberately validate the
// security property (no URL-syntactic chars), not the content
// shape (hex / sha256 / length):
//
//   - The canonical length + hex check happens at the verify-side
//     envelope-digest comparison.
//   - Forcing length == 64 here rejects future digest algorithms
//     (sha384, sha512) without buying any security.
//   - Restricting to hex blocks test fixtures that exercise the
//     HTTP flow without supplying realistic digests.
//
// The single thing we must enforce here is: a hostile policy
// can't sneak a '/' or '?' into the URL via this argument.
func validateEnvelopeDigestForURL(s string) error {
	if s == "" {
		return errors.New("envelope digest must not be empty")
	}
	return rejectURLInjectionChars("envelope digest", s)
}

// rejectURLInjectionChars is the shared core of step-name and
// digest validation. Any character that could escape a URL path
// segment or carry URL-syntactic meaning is fatal.
func rejectURLInjectionChars(label, s string) error {
	if strings.Contains(s, "/") || strings.Contains(s, "\\") {
		return fmt.Errorf("%s %q must not contain path separators", label, s)
	}
	if strings.Contains(s, "..") {
		return fmt.Errorf("%s %q must not contain '..'", label, s)
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s %q contains control character %#x", label, s, r)
		}
		switch r {
		case '?', '#', '@', '&', '=', '+', '\n', '\r', '\t', ' ', '%':
			return fmt.Errorf("%s %q contains URL-syntactic character %q", label, s, r)
		}
	}
	return nil
}

// MultiChainSidecarSource composes multiple sources, returning the
// first non-nil sidecar found. Sources are tried in order; an error
// from one source aborts the chain — it's not safe to silently fall
// through past a configured source that errored.
//
// Use this when the verifier should prefer filesystem (offline) then
// fall back to HTTP (Archivista), or any other "try local first" /
// "try authoritative first" preference order.
type MultiChainSidecarSource struct {
	Sources []ChainSidecarSource
}

// NewMultiChainSidecarSource builds a multi-source from the given
// component sources, in priority order.
func NewMultiChainSidecarSource(sources ...ChainSidecarSource) *MultiChainSidecarSource {
	return &MultiChainSidecarSource{Sources: sources}
}

// LookupChainSidecar tries each source in order. Returns the first
// non-nil sidecar; surfaces the first error.
func (m *MultiChainSidecarSource) LookupChainSidecar(ctx context.Context, downstreamStep, upstreamStep, upstreamEnvelopeDigest string) (*chain.ChainSidecar, error) {
	if m == nil {
		return nil, nil //nolint:nilnil
	}
	for _, s := range m.Sources {
		if s == nil {
			continue
		}
		sidecar, err := s.LookupChainSidecar(ctx, downstreamStep, upstreamStep, upstreamEnvelopeDigest)
		if err != nil {
			return nil, err
		}
		if sidecar != nil {
			return sidecar, nil
		}
	}
	return nil, nil //nolint:nilnil
}
