// jade:ring local
// Copyright 2026 TestifySec, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestAttestValidateOnlySignsNothing (#9495): `cilock attest --validate-only`
// accepted the flag, then signed evidence and ran its synthesized command
// anyway. With a working signer, validate-only must still sign nothing, write
// nothing and print no envelope.
func TestAttestValidateOnlySignsNothing(t *testing.T) {
	isolateAgentConfig(t)
	dir := t.TempDir()
	key := generateTestKey(t, dir)
	out := filepath.Join(dir, "attest.json")

	cmd := AttestCmd()
	cmd.SetArgs([]string{"--offline", "--step", "validate-only", "-a", "environment", "-k", key, "-o", out, "--validate-only"})
	stdout, stderr, err := inventoryCapture(t, func() error { return cmd.ExecuteContext(t.Context()) })
	require.NoError(t, err)
	require.Empty(t, stdout, "validate-only printed evidence")
	require.Contains(t, stderr, "--validate-only")
	_, statErr := os.Stat(out)
	require.True(t, os.IsNotExist(statErr), "validate-only wrote %s", out)
}
