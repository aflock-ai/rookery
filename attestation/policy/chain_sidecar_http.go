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
	// with a 30s timeout applied per request (some sidecars are large
	// for high-cardinality material sets; tighter timeouts cause false
	// negatives on cold caches).
	Client *http.Client

	// Headers are merged into every request — useful for bearer tokens
	// or Archivista-specific authentication. Nil means no extra headers.
	Headers map[string]string
}

// NewHTTPChainSidecarSource builds a source with sensible defaults.
// An empty URLTemplate is allowed and short-circuits to "no source"
// the same way an empty Dir does in FilesystemChainSidecarSource.
func NewHTTPChainSidecarSource(urlTemplate string) *HTTPChainSidecarSource {
	return &HTTPChainSidecarSource{
		URLTemplate: urlTemplate,
		Client:      &http.Client{Timeout: 30 * time.Second},
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
	url := s.URLTemplate
	url = strings.ReplaceAll(url, "{envelopeDigest}", upstreamEnvelopeDigest)
	url = strings.ReplaceAll(url, "{downstreamStep}", downstreamStep)
	url = strings.ReplaceAll(url, "{upstreamStep}", upstreamStep)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("http chain sidecar source: build request: %w", err)
	}
	for k, v := range s.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")

	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http chain sidecar source: fetch %s: %w", url, err)
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
		return nil, fmt.Errorf("http chain sidecar source: unexpected status %d from %s: %s", resp.StatusCode, url, strings.TrimSpace(string(body)))
	}

	// Cap the body size — a hostile server could otherwise OOM the
	// verifier with a multi-GB response. 64 MiB is well above any
	// realistic sidecar (12k materials × 14 proof depth × 32 bytes
	// + JSON overhead ≈ 6 MB) but well below memory exhaustion.
	const maxBody = 64 << 20
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
			url, sidecar.SourceStep.StepName, upstreamStep)
	}
	if sidecar.SourceStep.EnvelopeDigest != "" && sidecar.SourceStep.EnvelopeDigest != upstreamEnvelopeDigest {
		return nil, fmt.Errorf("http chain sidecar from %s binds to envelope %s but policy edge upstream envelope is %s",
			url, sidecar.SourceStep.EnvelopeDigest, upstreamEnvelopeDigest)
	}

	return &sidecar, nil
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
