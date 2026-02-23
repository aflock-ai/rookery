// Copyright 2023 The Witness Contributors
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

package fulcio

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

var githubHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

func fetchToken(tokenURL string, bearer string, audience string) (string, error) {
	if tokenURL == "" || bearer == "" || audience == "" {
		return "", fmt.Errorf("tokenURL, bearer, and audience cannot be empty")
	}

	client := githubHTTPClient

	//add audient "&audience=witness" to the end of the tokenURL, parse it, and then add it to the query
	u, err := url.Parse(tokenURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse token URL: %w", err)
	}

	//check to see if the tokenURL already has a query with an audience
	//if it does throw an error
	q := u.Query()
	if q.Get("audience") != audience && q.Get("audience") != "" {
		return "", fmt.Errorf("api error: tokenURL already has an audience, %s, and it does not match the audience, %s", q.Get("audience"), audience)
	}

	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	reqURL := u.String()

	// Retry logic with exponential backoff
	const maxRetries = 3
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 1s, 2s, 4s
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			time.Sleep(backoff)
		}

		req, err := http.NewRequest("GET", reqURL, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Add("Authorization", "bearer "+bearer)

		resp, err := client.Do(req)
		if err != nil {
			// Check for HTTP/2 connection issues and fallback to HTTP/1.1
			if strings.Contains(err.Error(), "HTTP_1_1_REQUIRED") {
				http1transport := githubHTTPClient.Transport.(*http.Transport).Clone()
				http1transport.ForceAttemptHTTP2 = false
				client = &http.Client{
					Transport: http1transport,
					Timeout:   30 * time.Second,
				}
				// Retry immediately with HTTP/1.1
				resp, err = client.Do(req)
			}

			if err != nil {
				lastErr = fmt.Errorf("failed to fetch token from GitHub Actions (attempt %d/%d): %w", attempt+1, maxRetries, err)
				continue
			}
		}

		// Read the body and close immediately rather than using defer inside
		// the retry loop (deferred closes stack up, leaking connections).
		// Limit read to 1MB to prevent OOM from a compromised token endpoint.
		const maxTokenResponseSize = 1 << 20 // 1MB
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseSize))
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body (attempt %d/%d): %w", attempt+1, maxRetries, err)
			continue
		}

		// Check HTTP status code
		if resp.StatusCode != http.StatusOK {
			bodyStr := string(bodyBytes)
			if len(bodyStr) > 500 {
				end := 500
				for end > 0 && !utf8.RuneStart(bodyStr[end]) {
					end--
				}
				bodyStr = bodyStr[:end] + "..."
			}
			lastErr = fmt.Errorf("unexpected status code %d from GitHub Actions API (attempt %d/%d), body: %s",
				resp.StatusCode, attempt+1, maxRetries, bodyStr)
			continue
		}

		var tokenResponse struct {
			Count int    `json:"count"`
			Value string `json:"value"`
		}

		// Attempt to unmarshal the response
		if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
			// Log the actual response for debugging
			bodyStr := string(bodyBytes)

			// Truncate very long responses for logging
			if len(bodyStr) > 500 {
				end := 500
				for end > 0 && !utf8.RuneStart(bodyStr[end]) {
					end--
				}
				bodyStr = bodyStr[:end] + "..."
			}

			// Check if the response looks like HTML (common error response)
			if strings.HasPrefix(strings.TrimSpace(bodyStr), "<") {
				lastErr = fmt.Errorf("received HTML response instead of JSON from GitHub Actions API (attempt %d/%d), possible authentication or network issue. Response: %s",
					attempt+1, maxRetries, bodyStr)
				continue
			}

			// Check if response is empty
			if len(bytes.TrimSpace(bodyBytes)) == 0 {
				lastErr = fmt.Errorf("received empty response from GitHub Actions API (attempt %d/%d)", attempt+1, maxRetries)
				continue
			}

			lastErr = fmt.Errorf("failed to parse JSON response from GitHub Actions API (attempt %d/%d): %w. Response body: %s",
				attempt+1, maxRetries, err, bodyStr)
			continue
		}

		// Validate the token value
		if tokenResponse.Value == "" {
			lastErr = fmt.Errorf("received empty token value from GitHub Actions API (attempt %d/%d)", attempt+1, maxRetries)
			continue
		}

		return tokenResponse.Value, nil
	}

	return "", fmt.Errorf("failed to fetch GitHub Actions token after %d attempts: %w", maxRetries, lastErr)
}
