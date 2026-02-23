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

	"github.com/aflock-ai/rookery/attestation/dsse"
)

// maxErrorBodySize limits how much of an error response body we read to prevent OOM.
const maxErrorBodySize = 1 << 20 // 1MB

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
	url     string
	headers http.Header
	client  *http.Client
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

// WithHTTPClient sets a custom http.Client for requests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.client = hc
		}
	}
}

// New creates an Archivista client for the given server URL.
func New(url string, opts ...Option) *Client {
	c := &Client{
		url:    strings.TrimRight(url, "/"),
		client: http.DefaultClient,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// Store uploads a DSSE envelope and returns its gitoid.
func (c *Client) Store(ctx context.Context, env dsse.Envelope) (string, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/upload", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("archivista store: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("archivista store returned %d: %s", resp.StatusCode, readLimitedErrorBody(resp.Body))
	}

	var result storeResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode store response: %w", err)
	}
	return result.Gitoid, nil
}

// Download retrieves a DSSE envelope by its gitoid.
func (c *Client) Download(ctx context.Context, gitoid string) (dsse.Envelope, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/download/"+url.PathEscape(gitoid), nil)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("create request: %w", err)
	}
	c.applyHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return dsse.Envelope{}, fmt.Errorf("archivista download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return dsse.Envelope{}, fmt.Errorf("archivista download returned %d: %s", resp.StatusCode, readLimitedErrorBody(resp.Body))
	}

	var env dsse.Envelope
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
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

func (c *Client) applyHeaders(req *http.Request) {
	for key, values := range c.headers {
		for _, v := range values {
			req.Header.Add(key, v)
		}
	}
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
	c.applyHeaders(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("archivista graphql: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("archivista graphql returned %d: %s", resp.StatusCode, readLimitedErrorBody(resp.Body))
	}

	var gqlResp graphqlResponse
	if err := json.NewDecoder(resp.Body).Decode(&gqlResp); err != nil {
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
