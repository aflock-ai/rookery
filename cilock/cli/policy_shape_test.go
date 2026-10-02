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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Onboarding simulator (fullblind45 and one other run): a rego module written
// as a bare string got "cannot unmarshal string into Go struct field
// attestation.steps.attestations.regopolicies of type policy.regoPolicy" from
// validate, and template and prove, which read the draft as untyped JSON,
// silently treated the string as no rule at all. Every authoring command now
// names the element and the shape the schema wants.

const regoStringDraft = `{
  "expires": "2030-01-01T00:00:00Z",
  "roots": {"fulcio-root": {"certificate": ""}},
  "steps": {"build": {"name": "build",
    "functionaries": [{"type": "root", "certConstraint": {"roots": ["fulcio-root"], "commonname": "*"}}],
    "attestations": [{"type": "https://aflock.ai/attestations/command-run/v0.1", "regopolicies": ["cGFja2FnZSB4"]}]}}
}`

const regoShapeMessage = `steps.build.attestations[0].regopolicies[0] must be an object {"name": "<rule name>", "module": "<base64 rego>"}; got a string`

func writeRegoStringDraft(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "policy.json")
	require.NoError(t, os.WriteFile(p, []byte(regoStringDraft), 0o600))
	return p
}

func TestValidateNamesTheRegoPolicyShape(t *testing.T) {
	stdout, _, err := executeCmdOutput("policy", "validate", "-p", writeRegoStringDraft(t))
	require.Error(t, err)
	require.Contains(t, stdout, `must be an object {\"name\": \"<rule name>\", \"module\": \"<base64 rego>\"}; got a string`,
		"validate prints errors %%q-quoted")
	require.NotContains(t, stdout, "policy.regoPolicy")
}

func TestLoadDraftNamesTheRegoPolicyShape(t *testing.T) {
	_, err := loadDraft(writeRegoStringDraft(t))
	require.Error(t, err, "template and prove must not read a string rule as no rule")
	require.Contains(t, err.Error(), regoShapeMessage)
}

func TestTemplateAddStepNamesTheRegoPolicyShape(t *testing.T) {
	sandboxCredentials(t, true)
	_, err := templateCmd(t, "-p", writeRegoStringDraft(t), "--add-step", "lint", "--attestor", "command-run")
	require.Error(t, err)
	require.Contains(t, err.Error(), regoShapeMessage)
	require.NotContains(t, err.Error(), "create a draft first", "the draft exists; the fix is the shape, not a new draft")
}

func TestTemplateAddStepOnAMissingDraftSaysCreateItFirst(t *testing.T) {
	sandboxCredentials(t, true)
	_, err := templateCmd(t, "-p", filepath.Join(t.TempDir(), "absent.json"), "--add-step", "lint", "--attestor", "command-run")
	require.Error(t, err)
	require.Contains(t, err.Error(), "create a draft first")
}
