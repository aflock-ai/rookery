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

// jade:ring local

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// `cilock version --json` is one object with the same facts as the text. The
// text form, whose first line release-fanout pins, is unchanged.
func TestVersionJSON(t *testing.T) {
	stdout, _, err := executeCmdOutput("version", "--json")
	require.NoError(t, err)
	var v versionJSON
	require.NoError(t, json.Unmarshal([]byte(stdout), &v), stdout)
	require.Equal(t, Version, v.Version)
	require.Equal(t, GitCommit, v.Commit)
	require.Contains(t, []string{"none", "present", "error"}, v.EmbeddedTrust.Status)
}

// `cilock whoami --json` with no session says so in the object and still
// exits non-zero, like the text form.
func TestWhoamiJSONNoSession(t *testing.T) {
	isolateAgentConfig(t)
	stdout, _, err := executeCmdOutput("whoami", "--json", "--platform-url", "https://platform.example.com")
	require.Error(t, err, "no session is not success")
	var w whoamiJSON
	require.NoError(t, json.Unmarshal([]byte(stdout), &w), stdout)
	require.False(t, w.LoggedIn)
	require.Equal(t, "https://platform.example.com", w.PlatformURL)
}

// `cilock policy bind pushgate --json` reports the review it prepared and
// says, as data, that nothing was applied.
func TestBindPushgateJSON(t *testing.T) {
	t.Setenv("BROWSER", "none")
	var out bytes.Buffer
	err := writeBindPushgateJSON(&out, bindPushgateOpts{
		release: "11111111-1111-4111-8111-111111111111", repo: "github.com/testifysec/judge", mode: "warn", reason: " side by side ",
	}, "https://pushgate.example.com/gates?assign=x", false)
	require.NoError(t, err)
	var b bindPushgateJSON
	require.NoError(t, json.Unmarshal(out.Bytes(), &b), out.String())
	require.Equal(t, "github.com/testifysec/judge", b.Repository)
	require.Equal(t, "warn", b.Mode)
	require.Equal(t, "side by side", b.Reason)
	require.Equal(t, "https://pushgate.example.com/gates?assign=x", b.ReviewURL)
	require.False(t, b.Applied, "this command never applies the assignment")
	require.True(t, strings.Contains(out.String(), `"applied": false`), "applied is always emitted: %s", out.String())
}
