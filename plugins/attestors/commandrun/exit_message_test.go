// jade:ring local
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

package commandrun

import (
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// The last line `cilock run` prints for a failed wrapped command was
// "attestor command-run failed: detected: command exited with status 3": it
// said a command failed without saying which one. It now names the command.
func TestExitOutcomeNamesTheCommandAndItsExitCode(t *testing.T) {
	r := &CommandRun{Cmd: []string{"sh", "-c", "exit 3"}}
	err := r.exitOutcome(3, nil)
	require.True(t, attestation.IsDetectionError(err), "still a detection verdict")
	require.Contains(t, err.Error(), "command `sh -c 'exit 3'` exited with status 3")
	require.Equal(t, 3, r.ExitCode)
}

// The message is logged, so a secret the shell expanded into argv is masked
// exactly as it is in the signed predicate.
func TestExitOutcomeMasksSecretsInTheCommand(t *testing.T) {
	t.Setenv("MY_API_TOKEN", "s3cr3t-value-123456")
	r := &CommandRun{Cmd: []string{"deploy", "--token=s3cr3t-value-123456"}}
	msg := r.exitOutcome(1, nil).Error()
	require.NotContains(t, msg, "s3cr3t-value-123456")
	require.Contains(t, msg, "exited with status 1")
	require.Equal(t, "s3cr3t-value-123456", strings.TrimPrefix(r.Cmd[1], "--token="), "the argv itself is left for the marshal to redact")
}

// A long command (an inline script) is shortened, not dumped whole.
func TestExitOutcomeShortensALongCommand(t *testing.T) {
	r := &CommandRun{Cmd: []string{"sh", "-c", strings.Repeat("echo hi; ", 100)}}
	msg := r.exitOutcome(2, nil).Error()
	require.Less(t, len(msg), 300, msg)
	require.Contains(t, msg, "exited with status 2")
}

func TestExitOutcomeWithoutACommandKeepsTheOldWording(t *testing.T) {
	r := &CommandRun{}
	require.Contains(t, r.exitOutcome(4, nil).Error(), "command exited with status 4")
}
