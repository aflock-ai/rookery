// Copyright 2022 The Witness Contributors
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

package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "oci"
	Type    = "https://aflock.ai/attestations/oci/v0.1"
	RunType = attestation.PostProductRunType

	mimeTypes = "application/x-tar"

	maxTarEntrySize = 256 * 1024 * 1024 // 256 MB
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
	_ OCIAttestor           = &Attestor{}
)

type OCIAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error

	// Subjector
	Subjects() map[string]cryptoutil.DigestSet
}

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

type Attestor struct {
	TarDigest      cryptoutil.DigestSet   `json:"tardigest"`
	Manifest       []Manifest             `json:"manifest"`
	ImageTags      []string               `json:"imagetags"`
	LayerDiffIDs   []cryptoutil.DigestSet `json:"diffids"`
	ImageID        cryptoutil.DigestSet   `json:"imageid"`
	ManifestRaw    []byte                 `json:"manifestraw"`
	ManifestDigest cryptoutil.DigestSet   `json:"manifestdigest"`

	// RegistryDigests are the registry-assigned manifest digests observed in
	// the output of the push/copy commands this run executed. Unlike every
	// other field here they are not derived from the tarball — see
	// registry.go for why that distinction matters.
	RegistryDigests []RegistryDigest `json:"registrydigests,omitempty"`

	tarFilePath string `json:"-"`
}

type Manifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

func (m *Manifest) getImageID(ctx *attestation.AttestationContext, tarFilePath string) (cryptoutil.DigestSet, error) {
	tarFile, err := os.Open(tarFilePath) //nolint:gosec // G304: tar file path from attestation context
	if err != nil {
		return nil, err
	}
	defer func() { _ = tarFile.Close() }()

	tarReader := tar.NewReader(tarFile)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.FileInfo().IsDir() {
			continue
		}

		if h.Name == m.Config {
			if h.Size < 0 || h.Size > maxTarEntrySize {
				return nil, fmt.Errorf("config entry has invalid size: %d", h.Size)
			}
			b := make([]byte, h.Size)
			if _, err := io.ReadFull(tarReader, b); err != nil {
				return nil, fmt.Errorf("failed to read config: %w", err)
			}

			imageID, err := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
			if err != nil {
				log.Debugf("(attestation/oci) error calculating image id: %v", err)
				return nil, err
			}

			return imageID, nil
		}
	}
	return nil, fmt.Errorf("could not find config in tar file")
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
	return jsonschema.Reflect(&a)
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	// Registry digests come from observed push output, never from the
	// tarball, so they are collected before the tar path runs. A run that
	// only pushes (docker push, crane push) produces no tar product at all,
	// and the tar path below would abort before reaching this.
	a.RegistryDigests = collectRegistryDigests(ctx)

	if err := a.getCandidate(ctx); err != nil {
		// A push-only run legitimately has nothing to unpack. The observed
		// registry digests are the entire attestation in that case, so this
		// is a complete result rather than a failure. ONLY the explicit
		// no-candidate outcome qualifies: a tarball that exists but is
		// unreadable or fails its integrity check is a real failure, and
		// letting parsed digests mask it would turn a corrupted product
		// into a successful partial attestation.
		if errors.Is(err, errNoCandidate) && len(a.RegistryDigests) > 0 {
			log.Debugf("(attestation/oci) no image tarball found; attesting %d observed registry digest(s) only", len(a.RegistryDigests))
			return nil
		}
		log.Debugf("(attestation/oci) error getting candidate: %v", err)
		return err
	}

	if err := a.parseMaifest(ctx); err != nil {
		log.Debugf("(attestation/oci) error parsing manifest: %v", err)
		return err
	}

	if len(a.Manifest) == 0 {
		return fmt.Errorf("manifest.json contains no entries")
	}

	imageID, err := a.Manifest[0].getImageID(ctx, a.tarFilePath)
	if err != nil {
		log.Debugf("(attestation/oci) error getting image id: %v", err)
		return err
	}

	layerDiffIDs, err := a.Manifest[0].getLayerDIFFIDs(ctx, a.tarFilePath)
	if err != nil {
		return err
	}

	a.ImageID = imageID
	a.LayerDiffIDs = layerDiffIDs
	a.ImageTags = a.Manifest[0].RepoTags

	return nil
}

// errNoCandidate is the explicit "nothing to unpack" outcome from
// getCandidate: no products at all, or no product with the tarball MIME
// type. It is the ONLY getCandidate failure Attest may treat as benign on a
// push-only run — every other failure means a tarball candidate existed and
// something is wrong with it.
var errNoCandidate = errors.New("no image tarball candidate found")

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	products := ctx.Products()

	if len(products) == 0 {
		return fmt.Errorf("%w: no products to attest", errNoCandidate)
	}

	// A candidate that exists but cannot be validated is remembered and
	// reported if no other candidate succeeds. It must not collapse into
	// errNoCandidate: an unreadable or tampered tarball is a failure, not
	// an absence.
	var candidateErr error
	for path, product := range products {
		if product.MimeType != mimeTypes {
			continue
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromFile(path, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/oci) error calculating digest set from file %s: %v", path, err)
			if candidateErr == nil {
				if err == nil {
					err = errors.New("calculated digest set is nil")
				}
				candidateErr = fmt.Errorf("error calculating digest set from candidate %s: %w", path, err)
			}
			continue
		}

		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/oci) integrity error for %s: product digest does not match candidate", path)
			if candidateErr == nil {
				candidateErr = fmt.Errorf("integrity error for candidate %s: product digest does not match", path)
			}
			continue
		}

		a.TarDigest = product.Digest

		a.tarFilePath = path
		return nil
	}
	if candidateErr != nil {
		return candidateErr
	}
	return fmt.Errorf("%w: no tar file found", errNoCandidate)
}

func (a *Attestor) parseMaifest(ctx *attestation.AttestationContext) error {
	f, err := os.Open(a.tarFilePath)
	if err != nil {
		err = fmt.Errorf("error opening tar file: %w", err)
		return err
	}
	defer func() { _ = f.Close() }()

	tarReader := tar.NewReader(f)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		if h.FileInfo().IsDir() {
			continue
		}
		if h.Name == "manifest.json" {
			if h.Size < 0 || h.Size > maxTarEntrySize {
				return fmt.Errorf("manifest entry has invalid size: %d", h.Size)
			}
			a.ManifestRaw = make([]byte, h.Size)
			if _, err = io.ReadFull(tarReader, a.ManifestRaw); err != nil {
				return fmt.Errorf("failed to read manifest: %w", err)
			}
			break
		}
	}

	manifestDigest, err := cryptoutil.CalculateDigestSetFromBytes(a.ManifestRaw, ctx.Hashes())
	if err != nil {
		return err
	}

	a.ManifestDigest = manifestDigest

	err = json.Unmarshal(a.ManifestRaw, &a.Manifest)
	if err != nil {
		return err
	}

	return nil
}

func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	sha256Key := cryptoutil.DigestValue{Hash: crypto.SHA256}
	subj := make(map[string]cryptoutil.DigestSet)

	// These three are tar-derived. On a push-only run there is no tarball, so
	// they are empty and must be skipped — a bare "manifestdigest:" key
	// carrying no digest is not evidence of anything.
	if d := a.ManifestDigest[sha256Key]; d != "" {
		subj[fmt.Sprintf("manifestdigest:%s", d)] = a.ManifestDigest
	}
	if d := a.TarDigest[sha256Key]; d != "" {
		subj[fmt.Sprintf("tardigest:%s", d)] = a.TarDigest
	}
	if d := a.ImageID[sha256Key]; d != "" {
		subj[fmt.Sprintf("imageid:%s", d)] = a.ImageID
	}

	// Registry manifest digests, keyed by the pinned reference they belong
	// to. The key tail is a directly pullable "repo:tag@sha256:..." string
	// and the digest set carries the registry's value for policy matching.
	for _, rd := range a.RegistryDigests {
		d := rd.Digest[sha256Key]
		if d == "" || rd.Reference == "" {
			continue
		}
		subj[fmt.Sprintf("registrydigest:%s@sha256:%s", rd.Reference, d)] = rd.Digest
	}

	// image tags
	for _, tag := range a.ImageTags {
		hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(tag), hashes)
		if err != nil {
			log.Debugf("(attestation/oci) error calculating image tag: %v", err)
			continue
		}
		subj[fmt.Sprintf("imagetag:%s", tag)] = hash
	}

	// diff ids
	for layer := range a.LayerDiffIDs {
		subj[fmt.Sprintf("layerdiffid%02d:%s", layer, a.LayerDiffIDs[layer][cryptoutil.DigestValue{Hash: crypto.SHA256}])] = a.LayerDiffIDs[layer]
	}
	return subj
}

// BackRefs declares the identity of the image this attestor examined —
// manifest digest, image ID, and tags — anchoring downstream verdicts to
// the image's build attestations. Layer diff IDs deliberately stay subjects
// only: layers are shared across every image built on a common base, so
// backreffing them would create hub edges linking unrelated products. The
// local tarball digest likewise identifies this archive, not the image's
// cross-collection identity.
func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	refs := make(map[string]cryptoutil.DigestSet)

	if digest := a.ManifestDigest[cryptoutil.DigestValue{Hash: crypto.SHA256}]; digest != "" {
		refs[fmt.Sprintf("manifestdigest:%s", digest)] = a.ManifestDigest
	}
	if digest := a.ImageID[cryptoutil.DigestValue{Hash: crypto.SHA256}]; digest != "" {
		refs[fmt.Sprintf("imageid:%s", digest)] = a.ImageID
	}
	for _, tag := range a.ImageTags {
		if tag == "" {
			continue
		}
		if hash, err := cryptoutil.CalculateDigestSetFromBytes([]byte(tag), hashes); err == nil {
			refs[fmt.Sprintf("imagetag:%s", tag)] = hash
		} else {
			log.Debugf("(attestation/oci) error calculating image tag backref: %v", err)
		}
	}
	// The registry digest is the image's strongest cross-collection identity:
	// it is what a deployed workload reports and what a pinned reference
	// names, so it is the key other collections are most likely to arrive
	// with. Backreffing it is the whole point of capturing it.
	for _, rd := range a.RegistryDigests {
		digest := rd.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
		if digest == "" || rd.Reference == "" {
			continue
		}
		refs[fmt.Sprintf("registrydigest:%s@sha256:%s", rd.Reference, digest)] = rd.Digest
	}

	return refs
}

func (m *Manifest) getLayerDIFFIDs(ctx *attestation.AttestationContext, tarFilePath string) ([]cryptoutil.DigestSet, error) { //nolint:gocognit,gocyclo // OCI layer diffID calculation is inherently complex
	var layerDiffIDs []cryptoutil.DigestSet

	tarFile, err := os.Open(tarFilePath) //nolint:gosec // G304: tar file path from attestation context
	if err != nil {
		return nil, err
	}
	defer func() { _ = tarFile.Close() }()

	tarReader := tar.NewReader(tarFile)
	for {
		h, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.FileInfo().IsDir() {
			continue
		}
		for _, layerFile := range m.Layers {
			if h.Name == layerFile { //nolint:nestif // layer processing requires nested decompression logic
				if h.Size < 0 || h.Size > maxTarEntrySize {
					return nil, fmt.Errorf("layer entry has invalid size: %d", h.Size)
				}
				b := make([]byte, h.Size)
				if _, err := io.ReadFull(tarReader, b); err != nil {
					return nil, fmt.Errorf("failed to read layer: %w", err)
				}

				contentType := http.DetectContentType(b)
				if contentType == "application/x-gzip" {
					breader, err := gzip.NewReader(bytes.NewReader(b))
					if err != nil {
						return nil, err
					}
					// Limit decompressed size to prevent gzip bombs. The decompressed
					// layer could be orders of magnitude larger than the compressed size.
					const maxDecompressedSize = maxTarEntrySize
					c, err := io.ReadAll(io.LimitReader(breader, maxDecompressedSize+1))
					_ = breader.Close()
					if err != nil {
						return nil, err
					}
					if int64(len(c)) > maxDecompressedSize {
						return nil, fmt.Errorf("decompressed layer exceeds maximum size of %d bytes", maxDecompressedSize)
					}
					layerDiffID, err := cryptoutil.CalculateDigestSetFromBytes(c, ctx.Hashes())
					if err != nil {
						return nil, err
					}
					layerDiffIDs = append(layerDiffIDs, layerDiffID)

				} else {
					layerDiffID, err := cryptoutil.CalculateDigestSetFromBytes(b, ctx.Hashes())
					if err != nil {
						return nil, err
					}
					layerDiffIDs = append(layerDiffIDs, layerDiffID)
				}

			}
		}
	}
	return layerDiffIDs, nil
}
