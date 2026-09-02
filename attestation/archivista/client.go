// Copyright 2022 The Witness Contributors
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

// Package archivista provides a lightweight client for the Archivista
// attestation storage server. It replaces the upstream dependency on
// github.com/in-toto/archivista/pkg/api with a minimal HTTP client
// that implements only the three endpoints needed: upload, download,
// and GraphQL query.
package archivista

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/gitoid"
)

// maxErrorBodySize limits how much of an error response body we read to prevent OOM.
const maxErrorBodySize = 1 << 20 // 1MB

// MaxDownloadBytes caps the bytes the client will decode from an Archivista
// response. It mirrors bundle.MaxBundleBytes (512 MiB): an attestation envelope
// (DSSE carrying an in-toto statement, possibly with an embedded SBOM) is
// comfortably under this, while a compromised/on-path server can no longer
// stream a multi-GiB body to OOM-kill the caller. Without this bound the
// json.Decoder would buffer the whole response.
const MaxDownloadBytes = 512 << 20 // 512 MiB

// defaultHTTPTimeout bounds every Archivista request. http.DefaultClient has no
// Timeout, so a server (or LB) that TCP-accepts then stalls the response would
// otherwise hang the caller forever — in CI that meant a 20-min job-timeout hang
// with no error. Generous enough for an attestation upload, short enough that a
// stall fails fast with a diagnostic instead of parking the whole run.
const defaultHTTPTimeout = 120 * time.Second

// readLimitedErrorBody reads up to maxErrorBodySize bytes from the response body
// and returns a truncated string suitable for error messages.
func readLimitedErrorBody(body io.Reader) string {
	data, _ := io.ReadAll(io.LimitReader(body, maxErrorBodySize))
	s := string(data)
	if len(s) > 500 {
		s = s[:500] + "..."
	}
	return s
}

// Client communicates with an Archivista server over HTTP.
type Client struct {
	url         string
	headers     http.Header
	client      *http.Client
	tokenSource func() (string, error)
	// retry, when non-nil, bounds automatic retry of Store on retryable
	// failures. nil means a single attempt — see WithRetry for why retry is
	// opt-in rather than the default.
	retry *RetryPolicy
}

// Option configures a Client.
type Option func(*Client)

// WithHeaders adds custom HTTP headers to every request.
func WithHeaders(h http.Header) Option {
	return func(c *Client) {
		if h != nil {
			c.headers = h.Clone()
		}
	}
}

// WithAuthTokenSource sets a PER-REQUEST bearer-token source: fn is invoked on
// every request and its result sent as "Authorization: Bearer <token>".
//
// This exists because a token frozen at client-construction time outlives its
// validity on long operations: the v4.1.2 release verify minted a GitHub
// Actions OIDC token (≈5-minute expiry) once, then a single policyverify ran
// >5 minutes and every later graphql call 401'd. A source lets the caller
// re-mint/refresh so the credential is live for each request.
//
// Precedence: an explicit Authorization header from WithHeaders WINS — the
// source is only consulted when no static Authorization is set (mirrors the
// "explicit headers override OIDC" contract in cilock's ArchivistaOptions).
// A source error fails the request closed: sending no credential where one
// was configured would demote authenticated reads to anonymous ones.
func WithAuthTokenSource(fn func() (string, error)) Option {
	return func(c *Client) {
		c.tokenSource = fn
	}
}

// WithHTTPClient sets a custom http.Client for requests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.client = hc
		}
	}
}

// New creates an Archivista client for the given server URL.
//
// The default http.Client installs sameOriginRedirect as its CheckRedirect:
// requests carry the platform session token as a Bearer header, and a redirect
// to a different origin (or a private/link-local IP) would resend that bearer
// and the uploaded DSSE bundle to an attacker. Callers that supply their own
// client via WithHTTPClient own their redirect policy.
func New(url string, opts ...Option) *Client {
	c := &Client{
		url:    strings.TrimRight(url, "/"),
		client: &http.Client{Timeout: defaultHTTPTimeout, CheckRedirect: sameOriginRedirect},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// Store uploads a DSSE envelope and returns its gitoid.
//
// When the client was built WithRetry, a retryable failure (any 5xx, a
// timeout, a reset connection, a 429 honouring Retry-After) is retried with
// bounded exponential backoff before the error is returned. Terminal failures
// — 400/401/403/422 and friends — still fail on the first attempt. Without
// WithRetry this is a single attempt, exactly as it always was.
//
// The envelope is marshalled ONCE, outside the retry loop, and every attempt
// posts that same byte slice from a fresh reader. Marshalling per attempt
// would be wasted work, and reusing a spent io.Reader would silently upload an
// empty body on the second try.
func (c *Client) Store(ctx context.Context, env dsse.Envelope) (string, error) {
	body, err := json.Marshal(env)
	if err != nil {
		// Deterministic and local to this process: no server involvement, so
		// nothing to retry. Returned before the retry loop is entered.
		return "", fmt.Errorf("marshal envelope: %w", err)
	}

	return c.storeWithRetry(ctx, body, func(ctx context.Context) (string, error) {
		return c.storeOnce(ctx, body)
	})
}

// storeOnce performs a single upload attempt with the already-marshalled body.
func (c *Client) storeOnce(ctx context.Context, body []byte) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/upload", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.applyHeaders(req); err != nil {
		return "", err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("archivista store: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", &StatusError{
			Op:         "store",
			StatusCode: resp.StatusCode,
			Body:       readLimitedErrorBody(resp.Body),
			RetryAfter: resp.Header.Get("Retry-After"),
		}
	}

	var result storeResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxDownloadBytes+1)).Decode(&result); err != nil {
		return "", fmt.Errorf("decode store response: %w", err)
	}
	return result.Gitoid, nil
}

// Download retrieves a DSSE envelope by its gitoid.
func (c *Client) Download(ctx context.Context, gitoidArg string) (dsse.Envelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/download/"+url.PathEscape(gitoidArg), nil)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("create request: %w", err)
	}
	if err := c.applyHeaders(req); err != nil {
		return dsse.Envelope{}, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("archivista download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return dsse.Envelope{}, &StatusError{
			Op:         "download",
			StatusCode: resp.StatusCode,
			Body:       readLimitedErrorBody(resp.Body),
			RetryAfter: resp.Header.Get("Retry-After"),
		}
	}

	// Read the raw body under a hard cap. Archivista content-addresses each
	// envelope by the git-blob-sha256 of the exact bytes it stored, so we must
	// re-hash the raw bytes (not a re-marshaled struct, whose key order and
	// dropped unknown fields would not reproduce the stored bytes) and decode
	// from those same bytes. Reading MaxDownloadBytes+1 lets us detect overflow.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxDownloadBytes+1))
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("read envelope: %w", err)
	}
	if int64(len(raw)) > MaxDownloadBytes {
		return dsse.Envelope{}, fmt.Errorf("archivista download exceeds %d byte limit", MaxDownloadBytes)
	}

	// Verify the content address: the returned bytes must hash to the requested
	// gitoid. This rejects a compromised/on-path server returning a
	// different-but-signed envelope than the gitoid names.
	gid, err := gitoid.New(bytes.NewReader(raw), gitoid.WithSha256(), gitoid.WithContentLength(int64(len(raw))))
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("compute gitoid: %w", err)
	}
	if !strings.EqualFold(gid.String(), gitoidArg) {
		return dsse.Envelope{}, fmt.Errorf("archivista download gitoid mismatch: requested %s, got %s", gitoidArg, gid.String())
	}

	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return dsse.Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	return env, nil
}

// SearchGitoidVariables are the parameters for a gitoid search query.
type SearchGitoidVariables struct {
	SubjectDigests []string `json:"subjectDigests"`
	CollectionName string   `json:"collectionName"`
	Attestations   []string `json:"attestations"`
	ExcludeGitoids []string `json:"excludeGitoids"`
}

// SearchGitoids queries Archivista's GraphQL API for envelope gitoids
// matching the given search criteria.
func (c *Client) SearchGitoids(ctx context.Context, vars SearchGitoidVariables) ([]string, error) {
	const query = `query ($subjectDigests: [String!], $attestations: [String!], $collectionName: String!, $excludeGitoids: [String!]) {
  dsses(
    where: {
      gitoidSha256NotIn: $excludeGitoids,
      hasStatementWith: {
        hasAttestationCollectionsWith: {
          name: $collectionName,
          hasAttestationsWith: {
            typeIn: $attestations
          }
        },
        hasSubjectsWith: {
          hasSubjectDigestsWith: {
            valueIn: $subjectDigests
          }
        }
      }
    }
  ) {
    edges {
      node {
        gitoidSha256
      }
    }
  }
}`

	var response searchGitoidResponse
	if err := c.graphqlQuery(ctx, query, vars, &response); err != nil {
		return nil, err
	}

	gitoids := make([]string, 0, len(response.Dsses.Edges))
	for _, edge := range response.Dsses.Edges {
		gitoids = append(gitoids, edge.Node.Gitoid)
	}
	return gitoids, nil
}

// SearchGitoidsBySubjects queries Archivista's GraphQL API for envelope
// gitoids whose statement subjects intersect subjectDigests, regardless of
// predicate type or collection name. Used by bundle subject-graph walking
// where the caller wants everything reachable from a starting subject.
func (c *Client) SearchGitoidsBySubjects(ctx context.Context, subjectDigests, excludeGitoids []string) ([]string, error) {
	const query = `query ($subjectDigests: [String!], $excludeGitoids: [String!]) {
  dsses(
    where: {
      gitoidSha256NotIn: $excludeGitoids,
      hasStatementWith: {
        hasSubjectsWith: {
          hasSubjectDigestsWith: {
            valueIn: $subjectDigests
          }
        }
      }
    }
  ) {
    edges {
      node {
        gitoidSha256
      }
    }
  }
}`

	vars := struct {
		SubjectDigests []string `json:"subjectDigests"`
		ExcludeGitoids []string `json:"excludeGitoids"`
	}{
		SubjectDigests: subjectDigests,
		ExcludeGitoids: excludeGitoids,
	}

	var response searchGitoidResponse
	if err := c.graphqlQuery(ctx, query, vars, &response); err != nil {
		return nil, err
	}

	gitoids := make([]string, 0, len(response.Dsses.Edges))
	for _, edge := range response.Dsses.Edges {
		gitoids = append(gitoids, edge.Node.Gitoid)
	}
	return gitoids, nil
}

// SearchGitoidByPredicateVariables are the parameters for a gitoid search
// that filters by predicate type rather than by collection name/attestations.
// Used for the external-attestation flow where bare DSSE envelopes (SLSA
// provenance, VSAs, cosign attestations) are matched by predicateType +
// subject digest intersection.
type SearchGitoidByPredicateVariables struct {
	PredicateTypes []string `json:"predicateTypes"`
	SubjectDigests []string `json:"subjectDigests"`
	ExcludeGitoids []string `json:"excludeGitoids"`
}

// SearchGitoidsByPredicate queries Archivista's GraphQL API for envelope
// gitoids whose statement predicateType is in the given list AND whose
// subjects intersect subjectDigests. See issue #39.
func (c *Client) SearchGitoidsByPredicate(ctx context.Context, vars SearchGitoidByPredicateVariables) ([]string, error) {
	const query = `query ($predicateTypes: [String!]!, $subjectDigests: [String!], $excludeGitoids: [String!]) {
  dsses(
    where: {
      gitoidSha256NotIn: $excludeGitoids,
      hasStatementWith: {
        predicateIn: $predicateTypes,
        hasSubjectsWith: {
          hasSubjectDigestsWith: {
            valueIn: $subjectDigests
          }
        }
      }
    }
  ) {
    edges {
      node {
        gitoidSha256
      }
    }
  }
}`

	var response searchGitoidResponse
	if err := c.graphqlQuery(ctx, query, vars, &response); err != nil {
		return nil, err
	}

	gitoids := make([]string, 0, len(response.Dsses.Edges))
	for _, edge := range response.Dsses.Edges {
		gitoids = append(gitoids, edge.Node.Gitoid)
	}
	return gitoids, nil
}

func (c *Client) applyHeaders(req *http.Request) error {
	for key, values := range c.headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
	// Static Authorization (WithHeaders) wins; the token source is only
	// consulted when none is set — see WithAuthTokenSource.
	if c.tokenSource != nil && req.Header.Get("Authorization") == "" {
		token, err := c.tokenSource()
		if err != nil {
			return fmt.Errorf("archivista auth token source: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

func (c *Client) graphqlQuery(ctx context.Context, query string, variables any, result any) error {
	reqBody := graphqlRequest{
		Query:     query,
		Variables: variables,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshal graphql request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/query", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.applyHeaders(req); err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("archivista graphql: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return &StatusError{
			Op:         "graphql",
			StatusCode: resp.StatusCode,
			Body:       readLimitedErrorBody(resp.Body),
			RetryAfter: resp.Header.Get("Retry-After"),
		}
	}

	var gqlResp graphqlResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, MaxDownloadBytes+1)).Decode(&gqlResp); err != nil {
		return fmt.Errorf("decode graphql response: %w", err)
	}

	if len(gqlResp.Errors) > 0 {
		msgs := make([]string, len(gqlResp.Errors))
		for i, e := range gqlResp.Errors {
			msgs[i] = e.Message
		}
		return fmt.Errorf("graphql errors: %s", strings.Join(msgs, "; "))
	}

	return json.Unmarshal(gqlResp.Data, result)
}

// Internal types for JSON serialization.

type storeResponse struct {
	Gitoid string `json:"gitoid"`
}

type searchGitoidResponse struct {
	Dsses struct {
		Edges []struct {
			Node struct {
				Gitoid string `json:"gitoidSha256"`
			} `json:"node"`
		} `json:"edges"`
	} `json:"dsses"`
}

type graphqlRequest struct {
	Query     string `json:"query"`
	Variables any    `json:"variables"`
}

type graphqlResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}
