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
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/gitoid"
	"github.com/aflock-ai/rookery/attestation/log"
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
	// authRefresh renews the credential tokenSource reads; see WithAuthRefresh.
	authRefresh func() error
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

// WithAuthRefresh registers a renewal for the credential the token source
// reads. Store calls it AT MOST ONCE per upload, and only after the server
// answered 401: it then re-runs the upload with whatever the source returns
// next. A refresh that fails, or a second 401, returns the ORIGINAL refusal
// joined with the refresh error: failing to renew is never reported as success
// and never hides what the server said. Without a token source it has no effect,
// since there is no credential the refresh could change (#9358).
func WithAuthRefresh(fn func() error) Option {
	return func(c *Client) { c.authRefresh = fn }
}

// WithHTTPClient sets a custom http.Client for requests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.client = hc
		}
	}
}

// WithTimeout overrides the PER-ATTEMPT request deadline.
//
// Per-attempt is the whole point, and it is why no retry knob could substitute
// for this. defaultHTTPTimeout is a ceiling on one request; a retry policy
// bounds how many requests and how long between them. An envelope that cannot
// transfer in the ceiling fails every attempt at exactly the ceiling — measured
// on an idle host: seven attempts, 120.001s to 120.003s each, 2ms of total
// variance, 14m24s of wall clock, every one "Client.Timeout exceeded while
// awaiting headers" with no response headers ever arriving. Raising the retry
// count cannot defeat a per-attempt ceiling, and until now nothing exposed it.
//
// A non-positive duration is ignored rather than installing a client with no
// deadline at all: an unbounded upload is the hang defaultHTTPTimeout exists to
// prevent, and an operator reaching for this option wants a LONGER bound, not
// none. Callers that genuinely want no timeout can say so explicitly through
// WithHTTPClient.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.client.Timeout = d
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

	attempt := func(ctx context.Context) (string, error) { return c.storeOnce(ctx, body) }
	stored, err := c.storeWithRetry(ctx, body, attempt)
	var statusErr *StatusError
	if err == nil || c.authRefresh == nil || c.tokenSource == nil ||
		!errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusUnauthorized {
		return stored, err
	}
	// A 401 is not retryable as-is, but it is retryable after the credential is
	// renewed: re-exchange once, then upload again. One renewal, never a loop.
	log.Warnf("archivista upload refused with 401; renewing the credential and retrying once")
	if rerr := c.authRefresh(); rerr != nil {
		return "", errors.Join(err, fmt.Errorf("renewing the upload credential after a 401: %w", rerr))
	}
	return c.storeWithRetry(ctx, body, attempt)
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

	bearer := bearerOf(req)
	log.Infof("archivista upload attempt: %d bytes, token fp=%s", len(body), tokenFingerprint(bearer))

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("archivista store: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		log.Warnf("archivista upload refused 401: %d bytes, token sent [%s], response headers [%s]",
			len(body), TokenSummary(bearer), responseDiagnostics(resp.Header))
	}
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
	return c.download(ctx, gitoidArg, MaxDownloadBytes)
}

// DownloadBounded retrieves an envelope under a caller's tighter wire-byte cap.
// The URL, credentials, redirect rules and exact gitoid verification are the
// same as Download. Successful replies with a declared overflow are refused
// before reading; streams are capped before hashing or JSON/base64 decoding.
func (c *Client) DownloadBounded(ctx context.Context, gitoidArg string, maxBytes int64) (dsse.Envelope, error) {
	if maxBytes <= 0 || maxBytes > MaxDownloadBytes {
		return dsse.Envelope{}, fmt.Errorf("invalid download byte limit %d", maxBytes)
	}
	return c.download(ctx, gitoidArg, maxBytes)
}

// DownloadRaw retrieves the EXACT stored bytes of a DSSE envelope by gitoid,
// verified against that gitoid.
//
// It exists because Download hands back a decoded dsse.Envelope, and a decoded
// envelope cannot be turned back into the bytes Archivista stored: json.Marshal
// fixes the key order to the struct's, drops any member the struct has no field
// for, and re-encodes whitespace. Re-hashing a re-marshalled envelope therefore
// does NOT reproduce the gitoid, which makes it useless as the thing a caller
// saves to disk and later re-verifies. Anything that must round-trip the
// content address — `cilock fetch`, an evidence archive, a bundle writer that
// preserves provenance — needs these bytes, not the struct.
//
// It verifies the CONTENT ADDRESS only: the bytes are the bytes the gitoid
// names. It says nothing about the signature or the signer.
func (c *Client) DownloadRaw(ctx context.Context, gitoidArg string) ([]byte, error) {
	return c.downloadRaw(ctx, gitoidArg, MaxDownloadBytes)
}

// DownloadRawBounded is DownloadRaw under a caller's tighter wire-byte cap,
// with the same bounds contract as DownloadBounded.
func (c *Client) DownloadRawBounded(ctx context.Context, gitoidArg string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 || maxBytes > MaxDownloadBytes {
		return nil, fmt.Errorf("invalid download byte limit %d", maxBytes)
	}
	return c.downloadRaw(ctx, gitoidArg, maxBytes)
}

// download is the envelope-shaped view of downloadRaw. The fetch, the bounds
// and the content-address check live in ONE place (downloadRaw) so a fix to the
// verification cannot land in one copy and miss the other; all this adds is the
// decode.
func (c *Client) download(ctx context.Context, gitoidArg string, maxBytes int64) (dsse.Envelope, error) {
	raw, err := c.downloadRaw(ctx, gitoidArg, maxBytes)
	if err != nil {
		return dsse.Envelope{}, err
	}

	var env dsse.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return dsse.Envelope{}, fmt.Errorf("decode envelope: %w", err)
	}
	return env, nil
}

// downloadRaw is the single fetch-and-verify path shared by every download
// entry point. It returns bytes only after they content-address to gitoidArg.
func (c *Client) downloadRaw(ctx context.Context, gitoidArg string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/download/"+url.PathEscape(gitoidArg), nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if err := c.applyHeaders(req); err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("archivista download: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{
			Op:         "download",
			StatusCode: resp.StatusCode,
			Body:       readLimitedErrorBody(io.LimitReader(resp.Body, maxBytes)),
			RetryAfter: resp.Header.Get("Retry-After"),
		}
	}

	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("archivista download exceeds %d byte limit", maxBytes)
	}

	// Read the raw body under a hard cap. Archivista content-addresses each
	// envelope by the git-blob-sha256 of the exact bytes it stored, so we must
	// re-hash the raw bytes (not a re-marshaled struct, whose key order and
	// dropped unknown fields would not reproduce the stored bytes) and decode
	// from those same bytes. Reading maxBytes+1 lets us detect overflow.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read envelope: %w", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, fmt.Errorf("archivista download exceeds %d byte limit", maxBytes)
	}

	// Verify the content address: the returned bytes must hash to the requested
	// gitoid. This rejects a compromised/on-path server returning a
	// different-but-signed envelope than the gitoid names.
	gid, err := gitoid.New(bytes.NewReader(raw), gitoid.WithSha256(), gitoid.WithContentLength(int64(len(raw))))
	if err != nil {
		return nil, fmt.Errorf("compute gitoid: %w", err)
	}
	if !strings.EqualFold(gid.String(), gitoidArg) {
		return nil, fmt.Errorf("archivista download gitoid mismatch: requested %s, got %s", gitoidArg, gid.String())
	}

	return raw, nil
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

// ErrCredentialUnavailable marks a token-source failure as PERMANENT: the grant
// this run needs is missing or has been withdrawn, so re-asking the same source
// cannot change the answer.
//
// It exists because the WRAPPER TYPE CANNOT CARRY THAT JUDGEMENT.
// AuthTokenError wraps every token-source failure, and the reasons a source
// fails are not one kind of thing. An enrolled agent whose upload grant the
// platform withdrew has answered permanently; a GitHub Actions OIDC mint that
// timed out, or that got a 503 from the runner's token endpoint, has answered
// "not right now" — which is the same saturation symptom the upload retry
// exists to absorb. Treating the wrapper as uniformly terminal gives the second
// case ZERO retries and throws away a whole gate run's signed evidence on a
// blip; treating it as uniformly retryable spends the budget re-asking for a
// grant that is gone. Only the SOURCE knows which of the two it is, so the
// source says so by wrapping this sentinel and the classifier reads the answer
// instead of inferring it from the wrapper.
//
// A source declares permanence with %w:
//
//	if p.uploadToken == "" {
//		return "", fmt.Errorf("the platform issued no upload token: %w", archivista.ErrCredentialUnavailable)
//	}
var ErrCredentialUnavailable = errors.New("archivista credential unavailable")

// AuthTokenError reports that the per-request token source (WithAuthTokenSource)
// could not produce a credential. The request was never sent.
//
// It is a distinct type so the classifier can tell "the request never left the
// process" apart from a transport failure — NOT because every instance is
// terminal. Whether re-asking can succeed is a property of the CAUSE, and it is
// read with Permanent().
type AuthTokenError struct{ Err error }

// Error guards the nil receiver and nil cause the same way StatusError.Retryable
// does: this type is exported, so a caller can construct one by hand, and an
// error type that panics while being printed turns a clean refusal into a crash.
func (e *AuthTokenError) Error() string {
	if e == nil || e.Err == nil {
		return "archivista auth token source: no credential"
	}
	return "archivista auth token source: " + e.Err.Error()
}

func (e *AuthTokenError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// Permanent reports whether the cause says the credential is GONE, as opposed
// to momentarily unobtainable.
//
// The default is RETRYABLE, on the same asymmetry the rest of the classifier is
// built on (see IsRetryable): a wrongly-retried failure costs at most the retry
// budget and then surfaces the identical error, while a wrongly-terminal one
// discards an entire gate run's evidence, silently, in production, while every
// unit test still passes. So a cause that says nothing about permanence —
// including a hand-constructed AuthTokenError carrying no cause at all — is not
// permanent.
//
// Sniffing for transient SHAPES instead (net.Error, *url.Error,
// context.DeadlineExceeded) is the losing alternative, and it loses the same way
// enumerating 502/503/504 loses in StatusError.Retryable: a source that reports
// "OIDC token request returned 503" as a plain fmt.Errorf carries none of those
// shapes, so the enumeration would re-create the fail-closed bug at a new line
// number. Permanence is declared, never guessed.
func (e *AuthTokenError) Permanent() bool {
	if e == nil {
		return false
	}
	return errors.Is(e.Err, ErrCredentialUnavailable)
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
			return &AuthTokenError{Err: err}
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
