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

package cli

import (
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/embeddedtrust"
)

// jsonFlag is the machine-output switch, spelled as `cilock agent status`
// spells it. Each --json object carries the same facts as the text form,
// and every field is always emitted: an absent key is never an answer.
const jsonFlag = "json"

const jsonFlagUsage = "Emit one JSON object instead of text"

func writeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

type versionJSON struct {
	Version       string            `json:"version"`
	Commit        string            `json:"commit"`
	Built         string            `json:"built"`
	EmbeddedTrust embeddedTrustJSON `json:"embedded_trust"`
}

type embeddedTrustJSON struct {
	// Status is none (flagless verify disabled), present, or error.
	Status string   `json:"status"`
	Lines  []string `json:"lines"`
	Error  string   `json:"error"`
}

func writeVersionJSON(out io.Writer) error {
	et := embeddedTrustJSON{Lines: []string{}}
	switch lines, err := embeddedtrust.Summary(); {
	case err != nil:
		et.Status, et.Error = "error", err.Error()
	case len(lines) == 0:
		et.Status = "none"
	default:
		et.Status, et.Lines = "present", lines
	}
	return writeJSON(out, versionJSON{Version: Version, Commit: GitCommit, Built: BuildTime, EmbeddedTrust: et})
}

type whoamiJSON struct {
	PlatformURL string    `json:"platform_url"`
	LoggedIn    bool      `json:"logged_in"`
	Session     string    `json:"session"`
	AuthMode    string    `json:"auth_mode"`
	TenantID    string    `json:"tenant_id"`
	TenantName  string    `json:"tenant_name"`
	ProductID   string    `json:"product_id"`
	ProductName string    `json:"product_name"`
	Email       string    `json:"email"`
	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	// AgentID names the enrolled agent that signs on this machine when no
	// human session exists (see `cilock agent status`).
	AgentID string `json:"agent_id"`
}

// writeWhoamiJSON reports resolved (nil when there is no session) as JSON.
// The caller still returns the no-session error, so the exit status matches
// the text form.
func writeWhoamiJSON(out io.Writer, url string, resolved *auth.Resolved) error {
	w := whoamiJSON{PlatformURL: auth.NormalizeURL(url)}
	if resolved == nil {
		if agent, _ := storedAgent(url); agent != nil {
			w.AgentID = agent.AgentID
		}
		return writeJSON(out, w)
	}
	c := resolved.Credential
	w.LoggedIn, w.PlatformURL, w.Session, w.AuthMode = true, c.PlatformURL, resolved.Posture(), c.AuthMode
	w.TenantID, w.TenantName, w.ProductID, w.ProductName = c.TenantID, c.TenantName, c.ProductID, c.ProductName
	w.Email, w.ExpiresAt = c.Email, c.ExpiresAt
	return writeJSON(out, w)
}

type bindPushgateJSON struct {
	Repository string `json:"repository"`
	Release    string `json:"release"`
	Mode       string `json:"mode"`
	Reason     string `json:"reason"`
	ReviewURL  string `json:"review_url"`
	Opened     bool   `json:"opened"`
	// Applied is always false: only the human's approval in the review
	// changes anything, and this command cannot see it.
	Applied bool `json:"applied"`
}

func writeBindPushgateJSON(out io.Writer, o bindPushgateOpts, review string, opened bool) error {
	return writeJSON(out, bindPushgateJSON{Repository: o.repo, Release: o.release, Mode: o.mode,
		Reason: strings.TrimSpace(o.reason), ReviewURL: review, Opened: opened})
}
