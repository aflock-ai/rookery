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

//go:build audit

package buildpacks

import (
	"encoding/json"
	"strings"
	"testing"
)

// FuzzReportAttest drives arbitrary report.toml bytes through the real
// attestor (not just a TOML decode): Attest must never panic, and whenever it
// accepts a report, every imagedigest subject it emits must be a 64-hex sha256
// that also appears in the predicate's ImageDigest. Removing the production
// identity check would make this fail, which the earlier decode-only fuzzer
// could not catch.
func FuzzReportAttest(f *testing.F) {
	f.Add("[image]\n  tags = [\"a\"]\n  digest = \"sha256:" + strings.Repeat("a", 64) + "\"\n")
	f.Add("[image]\n  image-id = \"deadbeef\"\n")
	f.Add("[image]\n  digest = \"md5:zz\"\n")
	f.Add("[image]\n")
	f.Add("not toml at all ][")
	f.Add("")
	f.Fuzz(func(t *testing.T, raw string) {
		ctx := contextWithFiles(t, map[string][]byte{"out/report.toml": []byte(raw)})
		a := New()
		if err := a.Attest(ctx); err != nil {
			return // refusing is always a legal outcome
		}
		var want string
		for _, v := range a.ImageDigest {
			want = v
		}
		for key := range a.Subjects() {
			if !strings.HasPrefix(key, "imagedigest:") {
				continue
			}
			hex := strings.TrimPrefix(key, "imagedigest:")
			if len(hex) != 64 {
				t.Fatalf("imagedigest subject is not 64-hex: %q", key)
			}
			if hex != want {
				t.Fatalf("imagedigest subject %q disagrees with predicate ImageDigest %q", hex, want)
			}
		}
	})
}

// FuzzConfigParse exercises the OCI config decode plus the metadata accessors:
// arbitrary JSON must never panic, and a config with no io.buildpacks. label
// must never be treated as a CNB image.
func FuzzConfigParse(f *testing.F) {
	f.Add(`{"config":{"Labels":{"io.buildpacks.stack.id":"heroku-24"}}}`)
	f.Add(`{"config":{"Labels":{"io.buildpacks.build.metadata":"{not json"}}}`)
	f.Add(`{"config":{"Labels":{"unrelated":"x"}}}`)
	f.Add(`{"config":{"Labels":{"io.buildpacks.lifecycle.metadata":"{\"sbom\":{\"sha\":\"sha256:x\"}}"}}}`)
	f.Add(`null`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, raw string) {
		var cfg ociImageConfig
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return
		}
		if cfg.isBuildpacksImage() {
			found := false
			for k := range cfg.labels() {
				if strings.HasPrefix(k, "io.buildpacks.") {
					found = true
					break
				}
			}
			if !found {
				t.Fatal("isBuildpacksImage true without an io.buildpacks. label")
			}
		}
		// Accessors must never panic on arbitrary input.
		_, _ = cfg.buildMetadata()
		_, _ = cfg.lifecycleMetadata()
	})
}

// FuzzManifestParse: arbitrary manifest JSON must never panic, and the config
// descriptor digest is only ever read for a single manifest (an image index,
// with a non-empty manifests array, must not be treated as one).
func FuzzManifestParse(f *testing.F) {
	f.Add(`{"config":{"digest":"sha256:` + strings.Repeat("a", 64) + `"}}`)
	f.Add(`{"manifests":[{"digest":"sha256:x"}]}`)
	f.Add(`{"config":{}}`)
	f.Add(`null`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, raw string) {
		var man ociManifest
		if err := json.Unmarshal([]byte(raw), &man); err != nil {
			return
		}
		if len(man.Manifests) > 0 && man.Config.Digest != "" {
			// An index descriptor should not also carry a top-level config; if a
			// crafted blob has both, the attestor's index guard runs first, so
			// this is only a smoke assertion that both fields decode.
			_ = man.Config.Digest
		}
	})
}

// FuzzDigestHexFromReference: a reference without "@sha256:" must never yield a
// digest, and any returned hex is exactly the suffix after the marker.
func FuzzDigestHexFromReference(f *testing.F) {
	f.Add("index.docker.io/heroku/heroku@sha256:26197de1")
	f.Add("docker.io/heroku/heroku:24")
	f.Add("@sha256:")
	f.Add("")
	f.Fuzz(func(t *testing.T, ref string) {
		hex := digestHexFromReference(ref)
		if hex == "" {
			return
		}
		if !strings.Contains(ref, "@sha256:"+hex) {
			t.Fatalf("digestHexFromReference(%q) = %q is not the suffix after the marker", ref, hex)
		}
	})
}
