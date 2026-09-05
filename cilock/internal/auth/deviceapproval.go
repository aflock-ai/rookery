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

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/config"
)

// A DEVICE APPROVAL is how an agent asks a human to authorize one exact act.
//
// It is RFC 8628's device flow with one addition the platform makes
// load-bearing: the request carries an APPROVAL — the values of the act being
// authorized. The platform stores those values, renders them on the approve
// page, gates the approval at AAL2 when the tenant requires it, and digests
// the bytes IT SHOWED onto the credential it mints. A client-claimed digest is
// never read, so the credential can only ever be spent on the change the human
// actually saw.
//
// The credential that comes back is therefore not a general session. It is
// scoped, short-lived, bound to one digest, and single-use at the endpoint
// that spends it.
//
// This is deliberately NOT the browser-loopback machinery BrowserEnroll uses.
// There is no callback listener and no secret in a URL: the credential is
// returned on the CLI's own poll, so it never crosses the human's browser.
const (
	deviceCodePath  = "/oauth/device/code"
	deviceTokenPath = "/oauth/device/token" //nolint:gosec // G101 false positive: a URL path, not a credential.
	deviceGrantType = "urn:ietf:params:oauth:grant-type:device_code"

	// deviceApprovalDefaultTimeout bounds how long a command waits for the
	// human. It is the CLIENT's patience; the platform's own device-code TTL
	// is authoritative and may be shorter.
	deviceApprovalDefaultTimeout = 15 * time.Minute
)

// ApprovalRequest is one act put to a human.
type ApprovalRequest struct {
	// ClientID names the tool asking, and is echoed on the approve page.
	ClientID string
	// Scopes the minted credential must carry. Ask for exactly what the act
	// needs: the credential is what signs, so a wider scope here is a wider
	// blast radius for a single approval.
	Scopes []string
	// Approval is the object the human is shown and that binds their
	// approval. Sent verbatim; the platform digests these exact bytes.
	Approval json.RawMessage
	// Timeout bounds the wait. Zero means deviceApprovalDefaultTimeout.
	Timeout time.Duration
	// Prompt is called once with the user code and the URL to open, so the
	// caller decides how to present them. Required: a ceremony nobody is told
	// about is a command that hangs.
	Prompt func(userCode, url string)
}

// ApprovalResult is the credential the human's approval minted, plus what the
// platform said it is for.
type ApprovalResult struct {
	Token      string
	TenantID   string
	TenantName string
	Scopes     []string
	ExpiresIn  int
}

type deviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type deviceTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
	TenantID    string `json:"tenant_id,omitempty"`
	TenantName  string `json:"tenant_name,omitempty"`
}

type deviceOAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *deviceOAuthError) Error() string {
	if e.Description != "" {
		return e.Code + ": " + e.Description
	}
	return e.Code
}

// ErrApprovalDenied is the human saying no. It is a decision, not a failure,
// and callers should report it as such rather than suggesting a retry.
var ErrApprovalDenied = errors.New("the approval was denied")

// DeviceApproval runs the ceremony and returns the credential the human's
// approval minted.
func DeviceApproval(ctx context.Context, platformURL string, req ApprovalRequest) (*ApprovalResult, error) {
	if req.Prompt == nil {
		return nil, errors.New("device approval needs a prompt: a ceremony nobody is told about is a hang")
	}
	if len(req.Scopes) == 0 {
		return nil, errors.New("device approval needs at least one scope")
	}
	if len(req.Approval) == 0 {
		return nil, errors.New("device approval needs the approval values the human will be shown")
	}
	// The approval and the session bearer both travel here; a downgraded
	// platform URL would put them on the wire in the clear.
	if err := config.RequireSecurePlatformURL(platformURL); err != nil {
		return nil, err
	}
	base := strings.TrimRight(NormalizeURL(platformURL), "/")

	dc, err := requestDeviceApproval(ctx, base, req)
	if err != nil {
		return nil, err
	}
	url := dc.VerificationURIComplete
	if url == "" {
		url = dc.VerificationURI
	}
	req.Prompt(dc.UserCode, url)

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = deviceApprovalDefaultTimeout
	}
	// The platform's own TTL wins when it is shorter: waiting past it would
	// poll a code that can no longer be approved.
	if dc.ExpiresIn > 0 && time.Duration(dc.ExpiresIn)*time.Second < timeout {
		timeout = time.Duration(dc.ExpiresIn) * time.Second
	}
	return pollDeviceApproval(ctx, base, req.ClientID, dc, timeout)
}

func requestDeviceApproval(ctx context.Context, base string, req ApprovalRequest) (*deviceCodeResponse, error) {
	body, err := json.Marshal(map[string]any{
		"client_id": req.ClientID,
		"scope":     strings.Join(req.Scopes, " "),
		"approval":  req.Approval,
	})
	if err != nil {
		return nil, err
	}
	raw, status, err := postDeviceJSON(ctx, base+deviceCodePath, body)
	if err != nil {
		return nil, fmt.Errorf("request an approval from %s: %w", base, err)
	}
	if status != http.StatusOK {
		return nil, deviceStatusError(base, status, raw)
	}
	var dc deviceCodeResponse
	if err := json.Unmarshal(raw, &dc); err != nil {
		return nil, fmt.Errorf("decode the approval request response: %w", err)
	}
	if dc.DeviceCode == "" || dc.UserCode == "" {
		return nil, errors.New("the platform returned an approval with no code")
	}
	if dc.Interval <= 0 {
		dc.Interval = 5
	}
	return &dc, nil
}

// pollDeviceApproval waits for the human. authorization_pending is the normal
// answer and is not an error; slow_down widens the interval per RFC 8628 §3.5;
// every other OAuth error is terminal, because re-polling a denied or expired
// code cannot start succeeding.
func pollDeviceApproval(ctx context.Context, base, clientID string, dc *deviceCodeResponse, timeout time.Duration) (*ApprovalResult, error) {
	body, err := json.Marshal(map[string]string{
		"grant_type":  deviceGrantType,
		"device_code": dc.DeviceCode,
		"client_id":   clientID,
	})
	if err != nil {
		return nil, err
	}
	interval := time.Duration(dc.Interval) * time.Second
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("no approval within %s — the ceremony expired; run the command again when your human is ready", timeout)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
		result, wait, err := pollDeviceApprovalOnce(ctx, base+deviceTokenPath, body)
		if err != nil {
			return nil, err
		}
		if result != nil {
			return result, nil
		}
		interval += wait
	}
}

// pollDeviceApprovalOnce is one poll. It returns the credential once the human
// has approved, or how much longer to wait before asking again.
//
// The three outcomes are deliberately distinct. A CREDENTIAL ends the wait. An
// ERROR ends it too, and only for reasons re-polling cannot fix: a denial, an
// expiry, an unreadable answer. Everything else — a pending approval, a
// transient network failure — is (nil, wait, nil), because a human is in the
// middle of a ceremony and the deadline in the caller is what ends it, not one
// failed request.
func pollDeviceApprovalOnce(ctx context.Context, url string, body []byte) (*ApprovalResult, time.Duration, error) {
	raw, status, err := postDeviceJSON(ctx, url, body)
	if err != nil {
		return nil, 0, nil //nolint:nilerr // a transient request failure is not an outcome: the human is mid-ceremony and the caller's deadline ends the wait
	}
	if status == http.StatusOK {
		var tr deviceTokenResponse
		if err := json.Unmarshal(raw, &tr); err != nil {
			return nil, 0, fmt.Errorf("decode the approved credential: %w", err)
		}
		if tr.AccessToken == "" {
			return nil, 0, errors.New("the platform approved the request but returned no credential")
		}
		return &ApprovalResult{
			Token: tr.AccessToken, TenantID: tr.TenantID, TenantName: tr.TenantName,
			Scopes: strings.Fields(tr.Scope), ExpiresIn: tr.ExpiresIn,
		}, 0, nil
	}
	var oe deviceOAuthError
	if json.Unmarshal(raw, &oe) != nil || oe.Code == "" {
		return nil, 0, deviceStatusError(url, status, raw)
	}
	switch oe.Code {
	case "authorization_pending":
		return nil, 0, nil
	case "slow_down":
		// RFC 8628 §3.5: five more seconds between requests, permanently.
		return nil, 5 * time.Second, nil
	case "access_denied":
		return nil, 0, ErrApprovalDenied
	default:
		return nil, 0, &oe
	}
}

func postDeviceJSON(ctx context.Context, url string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// Same rule as every other client that carries platform material: an
	// identical scheme and host, so a redirect cannot move the approval or the
	// minted credential to another origin.
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: config.SameOriginRedirect}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return raw, resp.StatusCode, nil
}

func deviceStatusError(base string, status int, body []byte) error {
	var oe deviceOAuthError
	if json.Unmarshal(body, &oe) == nil && oe.Code != "" {
		return &oe
	}
	trimmed := strings.TrimSpace(string(body))
	if len(trimmed) > 512 {
		trimmed = trimmed[:512] + "…"
	}
	return fmt.Errorf("%s answered %d: %s", base, status, trimmed)
}
