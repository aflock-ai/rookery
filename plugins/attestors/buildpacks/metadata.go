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

// The io.buildpacks.* labels the lifecycle writes onto the exported image live
// in the image's OCI config blob. The attestor reads them ONLY from that blob,
// reached by digest from the report: report [image].digest is the manifest
// digest (CNB Platform API), the manifest names the config blob's digest, and
// the config blob carries the labels. Each hop is matched by content address,
// so the labels are bound to the reported image. A self-declared
// `docker image inspect` dump is NOT used — it can name any image and is not
// evidence. See ociManifest / ociImageConfig below.

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
// this predicate records: the run image the app sits on, and the diffID of the
// SBOM layer the lifecycle wrote into the image. Both are part of the image
// config the report's digest commits to, so reading them from a label dump
// verified to be that image's binds them to the reported build.
type lifecycleMetadataLabel struct {
	RunImage struct {
		Image     string `json:"image"`
		Reference string `json:"reference"`
		TopLayer  string `json:"topLayer"`
	} `json:"runImage"`
	SBOM struct {
		SHA string `json:"sha"`
	} `json:"sbom"`
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

// ociManifest is the subset of an OCI/Docker image manifest the attestor needs
// to reach the config blob. The manifest's OWN sha256 is the image digest
// report.toml records ([image].digest is the manifest digest for a registry
// export), so a manifest product is identified by content address, never by a
// self-declared field. Manifests is non-empty only for an image index
// (multi-arch), which carries no single config to read.
type ociManifest struct {
	Config    ociDescriptor     `json:"config"`
	Manifests []json.RawMessage `json:"manifests"`
}

type ociDescriptor struct {
	Digest string `json:"digest"`
}

// ociImageConfig is the subset of the image CONFIG blob the predicate reads: the
// io.buildpacks.* labels the lifecycle wrote (OCI stores image labels under
// .config.Labels). The blob's sha256 is the manifest's config.digest, so a
// config product is identified by content address. Reading labels from THIS
// blob — reached by digest from the report — is what binds the run-image and
// buildpack claims to the reported image.
type ociImageConfig struct {
	Config struct {
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
}

func (l *ociImageConfig) labels() map[string]string {
	if l.Config.Labels == nil {
		return map[string]string{}
	}
	return l.Config.Labels
}

// isBuildpacksImage reports whether this image config carries CNB labels at all
// — the content sniff that lets Attest skip a config blob that is not a
// buildpacks image (or a foreign JSON product that happened to chain).
func (l *ociImageConfig) isBuildpacksImage() bool {
	for k := range l.labels() {
		if strings.HasPrefix(k, "io.buildpacks.") {
			return true
		}
	}
	return false
}

func (l *ociImageConfig) buildMetadata() (*buildMetadataLabel, error) {
	raw := l.labels()[labelBuildMetadata]
	if raw == "" {
		return nil, nil
	}
	var bm buildMetadataLabel
	if err := json.Unmarshal([]byte(raw), &bm); err != nil {
		return nil, err
	}
	return &bm, nil
}

func (l *ociImageConfig) lifecycleMetadata() (*lifecycleMetadataLabel, error) {
	raw := l.labels()[labelLifecycleMetadata]
	if raw == "" {
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
// carries no digest OR the value after @sha256: is not a well-formed 64-hex
// digest — a tag-only or malformed reference is a name, not an identity, and
// yields no subject.
func digestHexFromReference(ref string) string {
	_, after, found := strings.Cut(ref, "@sha256:")
	if !found || !isSHA256Hex(after) {
		return ""
	}
	return after
}

// isSHA256Hex reports whether s is exactly 64 lowercase hex characters — the
// shape of a real sha256 digest. A shorter, longer, or non-hex value is not an
// identity and must never become an imagedigest / runimagedigest subject.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
