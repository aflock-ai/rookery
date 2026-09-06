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

package buildpacks

import (
	"encoding/json"
	"strings"
)

// Report models the lifecycle exporter's report.toml (CNB Platform API), the
// file `pack build --report-output-dir` places on the host. Per the spec,
// digest and manifest-size are present only for registry exports (--publish);
// a daemon export carries image-id instead.
type Report struct {
	Image ReportImage `toml:"image" json:"image"`
}

type ReportImage struct {
	Tags         []string `toml:"tags" json:"tags"`
	Digest       string   `toml:"digest" json:"digest,omitempty"`
	ImageID      string   `toml:"image-id" json:"imageid,omitempty"`
	ManifestSize int64    `toml:"manifest-size" json:"manifestsize,omitempty"`
}

// The io.buildpacks.* labels the lifecycle writes onto the exported image.
// They are captured on the host as a labels JSON product (one post-build
// `docker image inspect --format '{{json .Config.Labels}}'` line, or a
// registry config fetch) — the attestor itself never talks to a daemon.

const (
	labelBuildMetadata     = "io.buildpacks.build.metadata"
	labelLifecycleMetadata = "io.buildpacks.lifecycle.metadata"
	labelStackID           = "io.buildpacks.stack.id"
	labelDistroName        = "io.buildpacks.base.distro.name"
	labelDistroVersion     = "io.buildpacks.base.distro.version"
)

// buildMetadataLabel is the subset of io.buildpacks.build.metadata this
// predicate records: which buildpacks ran, and the lifecycle's own provenance.
type buildMetadataLabel struct {
	Buildpacks []BuildpackRef `json:"buildpacks"`
	Launcher   struct {
		Version string `json:"version"`
		Source  struct {
			Git struct {
				Repository string `json:"repository"`
				Commit     string `json:"commit"`
			} `json:"git"`
		} `json:"source"`
	} `json:"launcher"`
}

// BuildpackRef identifies one buildpack that participated in the build.
type BuildpackRef struct {
	ID       string `json:"id"`
	Version  string `json:"version"`
	Homepage string `json:"homepage,omitempty"`
}

// lifecycleMetadataLabel is the subset of io.buildpacks.lifecycle.metadata
// this predicate records: the run image the app sits on.
type lifecycleMetadataLabel struct {
	RunImage struct {
		Image     string `json:"image"`
		Reference string `json:"reference"`
		TopLayer  string `json:"topLayer"`
	} `json:"runImage"`
}

// RunImage is the predicate's record of the base image under the app. The
// lifecycle resolves Reference to a digest reference at export time — the
// policy-pinnable identity a tag can never be.
type RunImage struct {
	Image     string `json:"image,omitempty"`
	Reference string `json:"reference,omitempty"`
	TopLayer  string `json:"toplayer,omitempty"`
}

// Launcher records the lifecycle's own provenance as reported by the build
// metadata label: its version and the source commit it was built from.
type Launcher struct {
	Version    string `json:"version,omitempty"`
	Repository string `json:"repository,omitempty"`
	Commit     string `json:"commit,omitempty"`
}

// BaseDistro is the run image's OS distribution as labeled at export.
type BaseDistro struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// labelsDocument parses a labels JSON product: a flat map of label name to
// string value, where the io.buildpacks metadata labels hold nested JSON as
// strings and so need a second decode. isBuildpacksLabels reports whether the
// document is recognizably a CNB label dump at all — the content sniff that
// lets Attest skip foreign JSON products without error.
type labelsDocument map[string]string

func (l labelsDocument) isBuildpacksLabels() bool {
	for k := range l {
		if strings.HasPrefix(k, "io.buildpacks.") {
			return true
		}
	}
	return false
}

func (l labelsDocument) buildMetadata() (*buildMetadataLabel, error) {
	raw, ok := l[labelBuildMetadata]
	if !ok || raw == "" {
		return nil, nil
	}
	var bm buildMetadataLabel
	if err := json.Unmarshal([]byte(raw), &bm); err != nil {
		return nil, err
	}
	return &bm, nil
}

func (l labelsDocument) lifecycleMetadata() (*lifecycleMetadataLabel, error) {
	raw, ok := l[labelLifecycleMetadata]
	if !ok || raw == "" {
		return nil, nil
	}
	var lm lifecycleMetadataLabel
	if err := json.Unmarshal([]byte(raw), &lm); err != nil {
		return nil, err
	}
	return &lm, nil
}

// digestHexFromReference extracts the sha256 hex from a digest reference like
// "index.docker.io/heroku/heroku@sha256:26197de1…". Empty when the reference
// carries no digest — a tag-only reference is a name, not an identity, and
// yields no subject.
func digestHexFromReference(ref string) string {
	_, after, found := strings.Cut(ref, "@sha256:")
	if !found {
		return ""
	}
	return after
}
