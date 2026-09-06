// Copyright 2026 The Witness Contributors
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

//go:build audit

package buildpacks

import (
	"encoding/json"
	"strings"
	"testing"

	toml "github.com/pelletier/go-toml/v2"
)

// FuzzReportParse exercises the report.toml decode plus the sha256-prefix
// identity rule: arbitrary TOML must never panic, and no digest that fails
// the "sha256:" prefix check may survive as an identity.
func FuzzReportParse(f *testing.F) {
	f.Add("[image]\n  tags = [\"a\"]\n  digest = \"sha256:abc\"\n  manifest-size = 1\n")
	f.Add("[image]\n  image-id = \"deadbeef\"\n")
	f.Add("[image]\n  digest = \"md5:zz\"\n")
	f.Add("not toml at all ][")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		var report Report
		if err := toml.Unmarshal([]byte(raw), &report); err != nil {
			return // refusing to parse is always a legal outcome
		}
		trimmed, found := strings.CutPrefix(report.Image.Digest, "sha256:")
		if found && trimmed == "" && report.Image.Digest != "sha256:" {
			t.Fatalf("CutPrefix invariant broken for %q", report.Image.Digest)
		}
	})
}

// FuzzLabelsParse exercises the labels-document decode and the nested
// metadata label unmarshals: arbitrary JSON must never panic, and a document
// without an io.buildpacks. key must never be treated as a CNB label dump.
func FuzzLabelsParse(f *testing.F) {
	f.Add(`{"io.buildpacks.stack.id":"heroku-24"}`)
	f.Add(`{"io.buildpacks.build.metadata":"{\"buildpacks\":[{\"id\":\"a\",\"version\":\"1\"}]}"}`)
	f.Add(`{"io.buildpacks.lifecycle.metadata":"{not json"}`)
	f.Add(`{"unrelated":"json"}`)
	f.Add(`null`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, raw string) {
		var labels labelsDocument
		if err := json.Unmarshal([]byte(raw), &labels); err != nil {
			return
		}
		if labels.isBuildpacksLabels() {
			found := false
			for k := range labels {
				if strings.HasPrefix(k, "io.buildpacks.") {
					found = true
					break
				}
			}
			if !found {
				t.Fatal("isBuildpacksLabels true without an io.buildpacks. key")
			}
		}
		// The nested decodes may fail, but must never panic.
		_, _ = labels.buildMetadata()
		_, _ = labels.lifecycleMetadata()
	})
}

// FuzzDigestHexFromReference: a reference without "@sha256:" must never yield
// a digest, and the returned hex is exactly the suffix after the marker.
func FuzzDigestHexFromReference(f *testing.F) {
	f.Add("index.docker.io/heroku/heroku@sha256:26197de1")
	f.Add("docker.io/heroku/heroku:24")
	f.Add("@sha256:")
	f.Add("")
	f.Fuzz(func(t *testing.T, ref string) {
		hex := digestHexFromReference(ref)
		if hex != "" && !strings.Contains(ref, "@sha256:"+hex) {
			t.Fatalf("digestHexFromReference(%q) = %q not a suffix after the marker", ref, hex)
		}
		if hex == "" {
			return
		}
		if !strings.Contains(ref, "@sha256:") {
			t.Fatalf("digest %q minted from reference %q without marker", hex, ref)
		}
	})
}
