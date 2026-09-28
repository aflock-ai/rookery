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
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/standards"
)

func TestToolsStandardsListsCatalog(t *testing.T) {
	var out bytes.Buffer
	cmd := ToolsCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"standards", "--format", "json"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	var got standardsCatalogListing
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if got.GuidanceSchema != standards.GuidanceSchema || len(got.Standards) != 2 ||
		got.Standards[0].Standard != standards.StandardSLSABuild || got.Standards[1].Standard != standards.StandardALPS {
		t.Fatalf("unexpected listing: schema %q, %d standards", got.GuidanceSchema, len(got.Standards))
	}

	out.Reset()
	cmd = ToolsCmd()
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"standards"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"It is not a verified level",
		"slsa-provenance-workflow -> L3 [planned",
		"snippet (not yet published; not shown in run or verify output):",
		"ALPS-3 [future]",
		"requires cilockd (not yet available)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("text listing lacks %q:\n%s", want, out.String())
		}
	}
}
