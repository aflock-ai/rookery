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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/stretchr/testify/require"
)

// TestRunEvidenceGateRunsBeforeTheCommand drives the real `cilock run`, not
// the option method, through the one cell of the evidence gate a current
// credential path can reach: an enrolled agent with an explicit
// --enable-archivista=false. The gate's own warning on stderr is the proof it
// executed in RunE (nothing else emits it); the marker file is the proof the
// explicit opt-out let the wrapped command run; and the error, when the run
// later fails at the fixture's Fulcio, is not the gate's refusal.
//
// The refusing cell (principal, upload off, no explicit flag) is unreachable
// from any credential path since #8732 — both paths turn the upload on — and is
// pinned on the option method and its value-space sweep instead.
func TestRunEvidenceGateRunsBeforeTheCommand(t *testing.T) {
	isolateAgentConfig(t)
	platform := agentExchangePlatform(t)
	require.NoError(t, auth.SaveAgent(auth.AgentCredential{
		PlatformURL:       platform.URL,
		TenantID:          "t-1",
		AgentID:           "a-1",
		RefreshCredential: agentTestSecret,
	}))
	logs := &captureLogger{}
	log.SetLogger(logs)
	t.Cleanup(func() { log.SetLogger(log.SilentLogger{}) })

	marker := filepath.Join(t.TempDir(), "wrapped-command-ran")
	cmd := RunCmd()
	// -a environment: an explicit attestor set that needs nothing the test
	// binary does not register, so the invocation reaches the wrapped command.
	cmd.SetArgs([]string{
		"--platform-url", platform.URL, "--step", "push-tests", "-a", "environment",
		"--enable-archivista=false", "--", "touch", marker,
	})
	err := cmd.Execute()

	var notStored *options.EvidenceNotStoredError
	require.False(t, errors.As(err, &notStored), "explicit --enable-archivista=false must not be refused: %v", err)
	_, statErr := os.Stat(marker)
	require.NoError(t, statErr, "the explicit opt-out must let the wrapped command run")

	warned := strings.Join(logs.warns, "\n")
	require.Contains(t, warned, "NO evidence stored", "the gate must run in RunE and say no evidence is stored; warnings:\n%s", warned)
	require.Contains(t, warned, agentTestSPIFFEID, "the warning must name the principal that signs unstored")
	require.NotContains(t, warned, agentTestSecret)
}
