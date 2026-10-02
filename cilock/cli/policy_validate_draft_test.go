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

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	internalpolicy "github.com/aflock-ai/rookery/cilock/internal/policy"
	"github.com/stretchr/testify/require"
)

// Onboarding simulator, top friction item: `cilock policy validate` exited 1
// with `Root 'fulcio-root': missing certificate data` on every correct
// template draft (13 hits in 7 runs; 15 failed validates, 10 retries). The
// placeholder is the template's own output, so validate now passes the
// unsigned draft, says what the placeholders are, and says the draft is not
// releasable; --strict keeps the old refusal for the release form.

func templatedDraft(t *testing.T) string {
	t.Helper()
	sandboxCredentials(t, true)
	out := filepath.Join(t.TempDir(), "policy.json")
	_, err := templateCmd(t, "--goal", "tests", "-o", out,
		"--fill", `tests.command-pin=["go","test","./..."]`)
	require.NoError(t, err)
	return out
}

func TestValidatePassesATemplateDraftAndSaysItIsNotReleasable(t *testing.T) {
	draft := templatedDraft(t)
	stdout, _, err := executeCmdOutput("policy", "validate", "-p", draft)
	require.NoError(t, err, "a template draft whose only gap is the platform placeholders exits 0; output:\n%s", stdout)
	require.Contains(t, stdout, "Policy validation: PASSED (unsigned draft)")
	require.Contains(t, stdout, "roots.fulcio-root, timestampauthorities.platform-tsa")
	require.Contains(t, stdout, "the platform fills them when your human signs")
	require.Contains(t, stdout, "not signed and not releasable")
	require.NotContains(t, stdout, "missing certificate data")
}

func TestValidateStrictRefusesTheDraftPlaceholders(t *testing.T) {
	draft := templatedDraft(t)
	stdout, _, err := executeCmdOutput("policy", "validate", "-p", draft, "--strict")
	require.Error(t, err, "--strict is the release form and must refuse an unfilled placeholder")
	require.Contains(t, stdout, "Root 'fulcio-root': missing certificate data")
	require.Contains(t, stdout, "Timestamp authority 'platform-tsa': missing certificate data")
}

func TestValidateJSONListsThePlaceholders(t *testing.T) {
	draft := templatedDraft(t)
	stdout, _, err := executeCmdOutput("policy", "validate", "-p", draft, "--format", "json")
	require.NoError(t, err)
	var got internalpolicy.ValidationResult
	require.NoError(t, json.Unmarshal([]byte(stdout), &got))
	require.True(t, got.Valid)
	require.Equal(t, []string{"roots.fulcio-root", "timestampauthorities.platform-tsa"}, got.Placeholders)
	require.Equal(t, internalpolicy.SignatureUnsigned, got.Signature)
}

// A real root problem on the same draft still fails, and the placeholder line
// still tells the author the fulcio-root entry is not the problem.
func TestValidateDraftWithARealErrorStillFails(t *testing.T) {
	draft := templatedDraft(t)
	raw, err := os.ReadFile(draft)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	doc["roots"].(map[string]any)["my-root"] = map[string]any{"certificate": ""}
	raw, err = json.Marshal(doc)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(draft, raw, 0o600))

	stdout, _, err := executeCmdOutput("policy", "validate", "-p", draft)
	require.Error(t, err)
	require.Contains(t, stdout, "Root 'my-root': missing certificate data")
	require.NotContains(t, stdout, "Root 'fulcio-root'")
	require.True(t, strings.Contains(stdout, "roots.fulcio-root"), "the placeholder note still prints beside a real error:\n%s", stdout)
}

// The template writer and the validator's tolerance share one name, so they
// cannot drift apart.
func TestTemplatePlaceholderNamesAreTheValidatorsNames(t *testing.T) {
	require.Equal(t, internalpolicy.PlatformRootPlaceholder, platformFulcioRoot)
	require.Equal(t, internalpolicy.PlatformTSAPlaceholder, platformTSA)
}
