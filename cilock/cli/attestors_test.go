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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttestorsList_JSONFormatIsValidAndStructured pins fix #6094: `cilock
// attestors list --format json` must exist and emit a structured array (an
// agent enumerating attestors should not have to scrape the ASCII table).
func TestAttestorsList_JSONFormatIsValidAndStructured(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, runList(&buf, "json"))

	var entries []attestorListEntry
	require.NoError(t, json.Unmarshal(buf.Bytes(), &entries),
		"--format json must emit a decodable JSON array; got:\n%s", buf.String())

	// The cli package registers product + material (imported by run.go), so the
	// list is non-empty and every always-run/default flag is derivable.
	require.NotEmpty(t, entries, "expected at least the always-run attestors registered in the cli binary")
	for _, e := range entries {
		assert.NotEmpty(t, e.Name, "every entry must carry a name")
	}
}

// TestAttestorsList_UnknownFormatErrors mirrors `tools list`: an unknown
// --format is a clear error, not a silent fallback.
func TestAttestorsList_UnknownFormatErrors(t *testing.T) {
	var buf bytes.Buffer
	err := runList(&buf, "yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown --format")
}

// TestAttestorsList_TableFormatStillRenders guards the default path.
func TestAttestorsList_TableFormatStillRenders(t *testing.T) {
	for _, format := range []string{"", "table"} {
		var buf bytes.Buffer
		require.NoError(t, runList(&buf, format))
		assert.Contains(t, buf.String(), "NAME",
			"table output must render a header (tablewriter upper-cases it)")
	}
}

// TestIsAlwaysRunAttestor covers the always-run classification, including the
// command-run case that previously appended " (always run)" once per
// alwaysRunAttestors entry (a doubled marker).
func TestIsAlwaysRunAttestor(t *testing.T) {
	for _, name := range []string{"product", "material", attestorCommandRun} {
		assert.True(t, isAlwaysRunAttestor(name), "%q must be classified always-run", name)
	}
	for _, name := range []string{"environment", "git", "platform", "sbom", ""} {
		assert.False(t, isAlwaysRunAttestor(name), "%q must NOT be classified always-run", name)
	}
}

// TestAttestorsTable_CommandRunMarkerNotDoubled locks the marker-doubling
// regression: command-run must get exactly one " (always run)" suffix.
func TestAttestorsTable_CommandRunMarkerNotDoubled(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeAttestorsTable(&buf, []attestorListEntry{
		{Name: attestorCommandRun, PredicateType: "t", RunType: "execute", AlwaysRun: true},
	}))
	out := buf.String()
	assert.Equal(t, 1, strings.Count(out, "(always run)"),
		"command-run must carry exactly one (always run) marker; got:\n%s", out)
}

// TestIsDefaultAttestor ties the default classification to the single source of
// truth (options.DefaultAttestors) rather than a hard-coded list.
func TestIsDefaultAttestor(t *testing.T) {
	for _, name := range options.DefaultAttestors {
		assert.True(t, isDefaultAttestor(name), "%q is in DefaultAttestors and must classify as default", name)
	}
	assert.False(t, isDefaultAttestor("sbom"))
	assert.False(t, isDefaultAttestor(""))
}
