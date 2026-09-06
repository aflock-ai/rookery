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

// Package buildpacks attests Cloud Native Buildpacks builds. It reads the
// lifecycle's own outputs — report.toml (`pack build --report-output-dir`),
// the exported SBOM files (`--sbom-output-dir`), and a labels JSON dump of
// the io.buildpacks.* image labels — and binds them into one predicate whose
// subject is the built image's digest.
//
// kpack signs SLSA provenance for builds inside its Kubernetes controller;
// every other `pack` invocation produces no verifiable evidence. This
// attestor closes that gap wherever `cilock run -- pack build …` runs, and
// records the buildpacks-specific facts generic SLSA has no fields for: the
// run image under the app, the buildpack group that ran, and the SBOMs by
// digest.
package buildpacks

import (
	"crypto"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
	toml "github.com/pelletier/go-toml/v2"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "buildpacks"
	Type    = "https://aflock.ai/attestations/buildpacks/v0.1"
	RunType = attestation.PostProductRunType

	reportFileName = "report.toml"
)

var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

// SBOMRef binds one exported SBOM file by digest. The files themselves can be
// megabytes; the claim stays verifiable and the envelope stays small.
type SBOMRef struct {
	Path   string               `json:"path"`
	Format string               `json:"format,omitempty"`
	Digest cryptoutil.DigestSet `json:"digest"`
}

type Attestor struct {
	// ImageDigest is the identity anchor: the registry digest from
	// report.toml. Present only for --publish builds; see the daemon-export
	// note in Attest.
	ImageDigest  cryptoutil.DigestSet `json:"imagedigest,omitempty"`
	ImageTags    []string             `json:"imagetags,omitempty"`
	ImageID      string               `json:"imageid,omitempty"`
	ManifestSize int64                `json:"manifestsize,omitempty"`

	RunImage   *RunImage      `json:"runimage,omitempty"`
	Buildpacks []BuildpackRef `json:"buildpacks,omitempty"`
	Launcher   *Launcher      `json:"launcher,omitempty"`
	BaseDistro *BaseDistro    `json:"basedistro,omitempty"`
	StackID    string         `json:"stackid,omitempty"`

	SBOMs []SBOMRef `json:"sboms,omitempty"`
}

func New() *Attestor {
	return &Attestor{}
}

func (a *Attestor) Name() string {
	return Name
}

func (a *Attestor) Type() string {
	return Type
}

func (a *Attestor) RunType() attestation.RunType {
	return RunType
}

func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(a)
}

// Attest scans the step's products for the lifecycle's outputs. Files that do
// not parse as what their name suggests are logged and skipped — other
// attestors own them — but a build whose report carries no digest gets no
// imagedigest subject: a tag is repointable and an image-id is daemon-local,
// so neither can deterministically say what the image is (the same refusal
// the docker attestor applies).
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	foundReport := false
	for path, product := range products {
		base := filepath.Base(path)
		switch {
		case base == reportFileName:
			if a.parseReport(ctx, path) {
				foundReport = true
			}
		case strings.HasSuffix(base, ".json"):
			a.tryParseLabels(ctx, path)
		}
		if isSBOMProduct(path, base) {
			a.SBOMs = append(a.SBOMs, SBOMRef{
				Path:   path,
				Format: sbomFormat(base),
				Digest: product.Digest,
			})
		}
	}

	if !foundReport {
		return fmt.Errorf("no buildpacks report.toml among the products; run pack build with --report-output-dir")
	}
	return nil
}

func (a *Attestor) parseReport(ctx *attestation.AttestationContext, path string) bool {
	f, err := os.ReadFile(filepath.Join(ctx.WorkingDir(), path)) //nolint:gosec // G304: path from attestation context
	if err != nil {
		log.Debugf("(attestation/buildpacks) failed to read %s: %v", path, err)
		return false
	}
	var report Report
	if err := toml.Unmarshal(f, &report); err != nil {
		log.Debugf("(attestation/buildpacks) %s did not parse as a lifecycle report: %v", path, err)
		return false
	}
	if len(report.Image.Tags) == 0 && report.Image.Digest == "" && report.Image.ImageID == "" {
		log.Debugf("(attestation/buildpacks) %s parsed but carries no image section; skipping", path)
		return false
	}

	a.ImageTags = report.Image.Tags
	a.ManifestSize = report.Image.ManifestSize
	a.ImageID = report.Image.ImageID

	if trimmed, found := strings.CutPrefix(report.Image.Digest, "sha256:"); found && trimmed != "" {
		a.ImageDigest = cryptoutil.DigestSet{
			{Hash: crypto.SHA256}: trimmed,
		}
	} else if report.Image.Digest != "" {
		log.Warnf("(attestation/buildpacks) report image digest is not sha256 (%q); recording no image identity", report.Image.Digest)
	} else {
		// Daemon export: image-id only. Recorded above for context, but an
		// image-id is not durable identity, so no digest and no subject.
		log.Warnf("(attestation/buildpacks) report carries no registry digest (daemon export?); build with --publish for a durable image identity")
	}
	return true
}

func (a *Attestor) tryParseLabels(ctx *attestation.AttestationContext, path string) {
	f, err := os.ReadFile(filepath.Join(ctx.WorkingDir(), path)) //nolint:gosec // G304: path from attestation context
	if err != nil {
		log.Debugf("(attestation/buildpacks) failed to read %s: %v", path, err)
		return
	}
	var labels labelsDocument
	if err := json.Unmarshal(f, &labels); err != nil || !labels.isBuildpacksLabels() {
		// Not a CNB label dump — some other JSON product. Not ours to judge.
		return
	}

	if bm, err := labels.buildMetadata(); err != nil {
		log.Warnf("(attestation/buildpacks) %s: %s did not parse: %v", path, labelBuildMetadata, err)
	} else if bm != nil {
		a.Buildpacks = bm.Buildpacks
		if bm.Launcher.Version != "" {
			a.Launcher = &Launcher{
				Version:    bm.Launcher.Version,
				Repository: bm.Launcher.Source.Git.Repository,
				Commit:     bm.Launcher.Source.Git.Commit,
			}
		}
	}

	if lm, err := labels.lifecycleMetadata(); err != nil {
		log.Warnf("(attestation/buildpacks) %s: %s did not parse: %v", path, labelLifecycleMetadata, err)
	} else if lm != nil && (lm.RunImage.Reference != "" || lm.RunImage.Image != "") {
		a.RunImage = &RunImage{
			Image:     lm.RunImage.Image,
			Reference: lm.RunImage.Reference,
			TopLayer:  lm.RunImage.TopLayer,
		}
	}

	a.StackID = labels[labelStackID]
	if labels[labelDistroName] != "" || labels[labelDistroVersion] != "" {
		a.BaseDistro = &BaseDistro{
			Name:    labels[labelDistroName],
			Version: labels[labelDistroVersion],
		}
	}
}

// isSBOMProduct recognizes files exported by `pack build --sbom-output-dir`:
// <dir>/sbom/{build,launch}/<buildpack-id>/…/sbom.<format>.json plus the
// legacy aggregate. Matched on the lifecycle's own layout, not file contents —
// the contents are bound by digest, not interpreted.
func isSBOMProduct(path, base string) bool {
	if !strings.HasPrefix(base, "sbom.") || !strings.HasSuffix(base, ".json") {
		return false
	}
	dir := filepath.ToSlash(filepath.Dir(path))
	return strings.Contains(dir, "sbom/build") || strings.Contains(dir, "sbom/launch") || strings.HasSuffix(dir, "/sbom")
}

func sbomFormat(base string) string {
	switch base {
	case "sbom.cdx.json":
		return "cyclonedx"
	case "sbom.spdx.json":
		return "spdx"
	case "sbom.syft.json":
		return "syft"
	case "sbom.legacy.json":
		return "legacy"
	default:
		return ""
	}
}

// Subjects exports the identities this build can later be found by:
//
//	imagedigest:<hex>     the built image (real content digest)
//	imagereference:<tag>  each tag (sha256 of the reference string)
//	runimagedigest:<hex>  the base image under the app (real digest) — the
//	                      subject a run-image-pinning policy verifies against
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	subj := make(map[string]cryptoutil.DigestSet)

	if hex, ok := a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}]; ok && hex != "" {
		subj[fmt.Sprintf("imagedigest:%s", hex)] = a.ImageDigest
	}

	for _, tag := range a.ImageTags {
		if hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(tag), hashes); err == nil {
			subj[fmt.Sprintf("imagereference:%s", tag)] = hash
		} else {
			log.Debugf("(attestation/buildpacks) failed to record imagereference subject: %v", err)
		}
	}

	if a.RunImage != nil {
		if hex := digestHexFromReference(a.RunImage.Reference); hex != "" {
			subj[fmt.Sprintf("runimagedigest:%s", hex)] = cryptoutil.DigestSet{
				{Hash: crypto.SHA256}: hex,
			}
		}
	}

	return subj
}
