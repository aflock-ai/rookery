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
// lifecycle's report.toml (`pack build --report-output-dir`) for the built
// image's digest, and the image's OCI manifest + config blob for the
// io.buildpacks.* labels, binding them into one predicate whose subject is the
// built image's digest.
//
// kpack signs SLSA provenance for builds inside its Kubernetes controller;
// every other `pack` invocation produces no verifiable evidence. This
// attestor closes that gap wherever `cilock run -- pack build …` runs, and
// records the buildpacks-specific facts generic SLSA has no fields for: the
// run image under the app, the buildpack group that ran, and the image's own
// SBOM-layer digest.
//
// Claims about the image (run image, buildpack group, SBOM layer) are read ONLY
// from the image's own config blob, reached by content address from the report:
// report [image].digest is the manifest digest, the manifest names the config
// blob's digest, and the config carries the labels. Every hop is matched by
// sha256, so the claims are bound to the reported image. The attestor never
// trusts a self-declared `docker image inspect` dump (which can name any image)
// and never reads loose `--sbom-output-dir` files (which carry no image
// identity) — a name is not evidence.
package buildpacks

import (
	"crypto"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

	// SBOMLayer is the diffID of the image's SBOM layer, taken from the
	// io.buildpacks.lifecycle.metadata label. Unlike loose --sbom-output-dir
	// files — which carry no image identity and are deliberately NOT attested —
	// this digest is committed to by the image config the report identifies and
	// is read only from a label dump already verified to be that image's, so it
	// binds the image's SBOM contents to the reported build.
	SBOMLayer cryptoutil.DigestSet `json:"sbomlayer,omitempty"`
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

	// Deterministic, ambiguity-free processing. Map iteration order must not
	// decide which image the predicate describes — identical inputs must sign
	// identical bytes. Sort the product paths and classify them.
	paths := make([]string, 0, len(products))
	for p := range products {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	var reportPaths, jsonPaths []string
	for _, path := range paths {
		base := filepath.Base(path)
		switch {
		case base == reportFileName:
			reportPaths = append(reportPaths, path)
		case strings.HasSuffix(base, ".json"):
			// Candidate OCI manifest / config blob. Selection is by content
			// address below (a product's sha256 must equal the report digest or
			// the manifest's config digest), so a foreign JSON — a loose SBOM
			// file included — is simply one that matches no hop and is ignored.
			jsonPaths = append(jsonPaths, path)
		}
	}

	switch len(reportPaths) {
	case 0:
		return fmt.Errorf("no buildpacks report.toml among the products; run pack build with --report-output-dir")
	case 1:
		// exactly one report: the image this predicate is about.
	default:
		return fmt.Errorf("ambiguous: %d report.toml products found; one pack build produces one report", len(reportPaths))
	}

	if err := a.parseReport(ctx, reportPaths[0], products[reportPaths[0]]); err != nil {
		return err
	}

	// Run-image / buildpack / SBOM-layer claims are read only from the image's
	// own config blob, reached by content address from the report digest. A
	// missing or unchainable blob leaves those fields unset — report-only
	// identity still stands — but it is NEVER filled from a self-declared dump.
	a.bindLabelsFromImage(ctx, jsonPaths, products)
	return nil
}

// bindLabelsFromImage walks the OCI content chain from the report's image digest
// to the config blob and applies its labels: report digest == image manifest
// sha256, manifest.config.digest == config blob sha256, labels from that config.
// Each product is selected by matching its captured sha256 to the digest the
// previous hop names, so nothing self-declared decides ownership. Any break in
// the chain (no manifest for the report digest, an image index, no config blob)
// leaves the label fields unset with a warning; there is no fallback.
func (a *Attestor) bindLabelsFromImage(ctx *attestation.AttestationContext, jsonPaths []string, products map[string]attestation.Product) {
	aHex := a.ImageDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
	if aHex == "" {
		return // daemon export or no registry digest: nothing to chain to.
	}
	manBytes := verifiedProductWithDigest(ctx, jsonPaths, products, aHex)
	if manBytes == nil {
		log.Warnf("(attestation/buildpacks) no image manifest product hashes to the report digest %s; run-image and buildpack labels not attested (export it, e.g. crane manifest <ref>@sha256:%s)", aHex, aHex)
		return
	}
	var man ociManifest
	if err := json.Unmarshal(manBytes, &man); err != nil {
		log.Warnf("(attestation/buildpacks) manifest for %s did not parse: %v; labels not attested", aHex, err)
		return
	}
	if len(man.Manifests) > 0 {
		log.Warnf("(attestation/buildpacks) report digest %s is an image index (multi-arch); per-image labels not attested", aHex)
		return
	}
	cfgHex, ok := strings.CutPrefix(man.Config.Digest, "sha256:")
	if !ok || !isSHA256Hex(cfgHex) {
		log.Warnf("(attestation/buildpacks) image manifest for %s carries no well-formed config digest (%q); labels not attested", aHex, man.Config.Digest)
		return
	}
	cfgBytes := verifiedProductWithDigest(ctx, jsonPaths, products, cfgHex)
	if cfgBytes == nil {
		log.Warnf("(attestation/buildpacks) image config blob sha256:%s (named by the manifest) not among products; labels not attested (export it, e.g. crane config <ref>@sha256:%s)", cfgHex, aHex)
		return
	}
	var cfg ociImageConfig
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		log.Warnf("(attestation/buildpacks) image config blob sha256:%s did not parse: %v; labels not attested", cfgHex, err)
		return
	}
	if !cfg.isBuildpacksImage() {
		log.Warnf("(attestation/buildpacks) image config sha256:%s carries no io.buildpacks.* labels; not attributing", cfgHex)
		return
	}
	a.applyInspectFields(&cfg)
}

// verifiedProductWithDigest returns the bytes of the sorted-first product whose
// captured sha256 equals wantHex, after re-reading the file and confirming it
// still hashes to that digest. Selecting a product by its content digest — not a
// name or a self-declared field — is what ties it to the image by content
// address. Returns nil when no product matches or the match fails verification.
func verifiedProductWithDigest(ctx *attestation.AttestationContext, paths []string, products map[string]attestation.Product, wantHex string) []byte {
	if wantHex == "" {
		return nil
	}
	for _, p := range paths {
		if products[p].Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}] != wantHex {
			continue
		}
		data, err := verifiedProductBytes(ctx, p, products[p])
		if err != nil {
			log.Warnf("(attestation/buildpacks) product %s matched digest %s but failed verification: %v", p, wantHex, err)
			continue
		}
		return data
	}
	return nil
}

// verifiedProductBytes reads path and rejects it unless the bytes hash to the
// sha256 digest cilock recorded for the product. Parsing the SAME buffer it
// verified closes the gap where a file is swapped after product hashing but
// before the attestor reads it (RACE / EVIDENCE_UNBOUND).
func verifiedProductBytes(ctx *attestation.AttestationContext, path string, product attestation.Product) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(ctx.WorkingDir(), path)) //nolint:gosec // G304: path from attestation context
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	want, ok := product.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
	if !ok || want == "" {
		return nil, fmt.Errorf("product has no recorded sha256 digest to verify the parsed bytes against")
	}
	got, err := cryptoutil.CalculateDigestSetFromBytes(data, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err != nil {
		return nil, fmt.Errorf("digest: %w", err)
	}
	if got[cryptoutil.DigestValue{Hash: crypto.SHA256}] != want {
		return nil, fmt.Errorf("bytes do not match the recorded product digest (modified after capture?)")
	}
	return data, nil
}

func (a *Attestor) parseReport(ctx *attestation.AttestationContext, path string, product attestation.Product) error {
	data, err := verifiedProductBytes(ctx, path, product)
	if err != nil {
		return fmt.Errorf("report %s: %w", path, err)
	}
	var report Report
	if err := toml.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("report %s did not parse as a lifecycle report: %w", path, err)
	}
	if len(report.Image.Tags) == 0 && report.Image.Digest == "" && report.Image.ImageID == "" {
		return fmt.Errorf("report %s carries no image section", path)
	}

	a.ImageTags = report.Image.Tags
	a.ManifestSize = report.Image.ManifestSize
	a.ImageID = report.Image.ImageID

	if trimmed, found := strings.CutPrefix(report.Image.Digest, "sha256:"); found && isSHA256Hex(trimmed) {
		a.ImageDigest = cryptoutil.DigestSet{
			{Hash: crypto.SHA256}: trimmed,
		}
	} else if report.Image.Digest != "" {
		log.Warnf("(attestation/buildpacks) report image digest is not a well-formed sha256 (%q); recording no image identity", report.Image.Digest)
	} else {
		// Daemon export: image-id only. Recorded above for context, but an
		// image-id is not durable identity, so no digest and no subject.
		log.Warnf("(attestation/buildpacks) report carries no registry digest (daemon export?); build with --publish for a durable image identity")
	}
	return nil
}

// applyInspectFields copies the verified config's run-image, buildpack-group,
// SBOM-layer and distro claims into the predicate.
func (a *Attestor) applyInspectFields(matched *ociImageConfig) {
	if bm, err := matched.buildMetadata(); err != nil {
		log.Warnf("(attestation/buildpacks) %s did not parse: %v", labelBuildMetadata, err)
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

	if lm, err := matched.lifecycleMetadata(); err != nil {
		log.Warnf("(attestation/buildpacks) %s did not parse: %v", labelLifecycleMetadata, err)
	} else if lm != nil {
		if lm.RunImage.Reference != "" || lm.RunImage.Image != "" {
			a.RunImage = &RunImage{
				Image:     lm.RunImage.Image,
				Reference: lm.RunImage.Reference,
				TopLayer:  lm.RunImage.TopLayer,
			}
		}
		// The image's own SBOM-layer diffID, committed to by the image config
		// this label was verified to belong to. A malformed value binds nothing.
		if hex, ok := strings.CutPrefix(lm.SBOM.SHA, "sha256:"); ok && isSHA256Hex(hex) {
			a.SBOMLayer = cryptoutil.DigestSet{{Hash: crypto.SHA256}: hex}
		}
	}

	a.StackID = matched.labels()[labelStackID]
	if matched.labels()[labelDistroName] != "" || matched.labels()[labelDistroVersion] != "" {
		a.BaseDistro = &BaseDistro{
			Name:    matched.labels()[labelDistroName],
			Version: matched.labels()[labelDistroVersion],
		}
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
