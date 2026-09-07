// jade:ring local

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAgentStatusJSONPublicProjection(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)
	active := auth.AgentCredential{PlatformURL: "https://p.example.invalid", TenantID: "tenant-active", AgentID: "agent-active", TrustDomain: "p.example.invalid", RefreshCredential: "synthetic-active-secret", ExpiresAt: now.Add(time.Hour)}
	pending := auth.AgentCredential{PlatformURL: active.PlatformURL, TenantID: "tenant-pending", AgentID: "agent-pending", RefreshCredential: "synthetic-pending-secret"}
	unredeemed, expired, unrecorded := active, active, active
	unredeemed.TrustDomain = ""
	expired.ExpiresAt = now
	unrecorded.ExpiresAt = time.Time{}
	for _, tc := range []struct {
		name                  string
		cred, pending         *auth.AgentCredential
		status, agentID       string
		active, eligible, err bool
	}{
		{name: "absent", status: "not_enrolled"},
		{name: "pending only", pending: &pending, status: "pending", agentID: pending.AgentID},
		{name: "unredeemed", cred: &unredeemed, status: "unredeemed", agentID: active.AgentID, eligible: true},
		{name: "redeemed", cred: &active, status: "eligible", agentID: active.AgentID, active: true, eligible: true},
		{name: "expired", cred: &expired, status: "expired", agentID: active.AgentID, active: true, err: true},
		{name: "pending beside active", cred: &active, pending: &pending, status: "eligible", agentID: active.AgentID, active: true, eligible: true},
		{name: "unknown ceiling", cred: &unrecorded, status: "eligible", agentID: active.AgentID, active: true, eligible: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := writeAgentStatusJSON(&out, active.PlatformURL, tc.cred, tc.pending, now)
			assert.Equal(t, tc.err, err != nil)
			var got map[string]any
			decoder := json.NewDecoder(&out)
			raw := out.String()
			require.NoError(t, decoder.Decode(&got))
			assert.ErrorIs(t, decoder.Decode(&struct{}{}), io.EOF, "stdout contains exactly one JSON value")
			allowed := map[string]bool{"platform_url": true, "principal_kind": true, "tenant_id": true, "agent_id": true, "spiffe_id": true, "active": true, "pending": true, "eligible": true, "status": true, "expires_at": true, "source": true, "platform_checked": true}
			for key := range got {
				assert.True(t, allowed[key], "unexpected status output field %s", key)
			}
			assert.NotContains(t, raw, active.RefreshCredential)
			assert.NotContains(t, raw, pending.RefreshCredential)
			assert.Equal(t, active.PlatformURL, got["platform_url"])
			assert.Equal(t, tc.agentID, got["agent_id"])
			assert.Equal(t, tc.status, got["status"])
			assert.Equal(t, tc.active, got["active"])
			assert.Equal(t, tc.eligible, got["eligible"])
			assert.Equal(t, tc.pending != nil, got["pending"])
			assert.Equal(t, "local_store", got["source"])
			assert.Equal(t, false, got["platform_checked"])
			if tc.active {
				assert.Equal(t, "spiffe://p.example.invalid/tenant/tenant-active/agent/agent-active", got["spiffe_id"])
			} else {
				assert.Equal(t, "", got["spiffe_id"], "unredeemed identities do not invent a trust domain")
			}
			if tc.agentID == "" {
				assert.Equal(t, "", got["principal_kind"])
			} else {
				assert.Equal(t, "agent", got["principal_kind"])
			}
		})
	}
}

func TestAgentStatusJSONCommandPreservesExitSemanticsAndStaysLocal(t *testing.T) {
	isolateAgentConfig(t)
	t.Setenv("APPDATA", t.TempDir())
	var hits atomic.Int64
	platform := countingPlatform(t, &hits)
	for _, expires := range []time.Time{{}, time.Now().Add(time.Hour), time.Now().Add(-time.Hour)} {
		if !expires.IsZero() {
			require.NoError(t, auth.SaveAgent(auth.AgentCredential{PlatformURL: platform.URL, TenantID: "t-1", AgentID: "a-1", TrustDomain: "p.example.invalid", RefreshCredential: agentTestSecret, ExpiresAt: expires}))
		}
		var text, machine bytes.Buffer
		textCommand := AgentStatusCmd()
		textCommand.SetOut(&text)
		textCommand.SetArgs([]string{"--platform-url", platform.URL})
		textErr := textCommand.Execute()
		jsonCommand := AgentStatusCmd()
		jsonCommand.SetOut(&machine)
		jsonCommand.SetArgs([]string{"--platform-url", platform.URL, "--json"})
		jsonErr := jsonCommand.Execute()
		assert.Equal(t, textErr != nil, jsonErr != nil)
		if textErr != nil {
			require.EqualError(t, jsonErr, textErr.Error())
		}
		var status agentStatusJSON
		require.NoError(t, json.Unmarshal(machine.Bytes(), &status))
		assert.Equal(t, !expires.IsZero() && expires.After(time.Now()), status.Eligible)
		assert.NotContains(t, machine.String(), agentTestSecret)
	}
	assert.Zero(t, hits.Load(), "status never exchanges a credential or claims remote revocation knowledge")
}

type failedStatusWriter struct{ err error }

func (w failedStatusWriter) Write([]byte) (int, error) { return 0, w.err }

func TestAgentStatusJSONReportsOutputFailure(t *testing.T) {
	want := errors.New("output unavailable")
	err := writeAgentStatusJSON(failedStatusWriter{want}, "https://p.example.invalid", nil, nil, time.Now())
	assert.ErrorIs(t, err, want)
}
