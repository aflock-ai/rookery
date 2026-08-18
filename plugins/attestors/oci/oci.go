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
	"bufio"
	"compress/gzip"
	"crypto"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

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

	// sniffLen is how many bytes http.DetectContentType actually looks at.
	sniffLen = 512
)

// maxDecompressedLayerSize bounds how many bytes a single image layer may
// contribute before the attestor gives up.
//
// It is deliberately NOT maxTarEntrySize. maxTarEntrySize guards the small
// JSON entries (manifest.json, the config blob) that are read into memory
// whole, where 256 MB is already absurdly generous. Layers are different:
// they are measured by streaming (see getLayerDIFFIDs), so their memory cost
// is constant no matter how big they get, and real base images routinely
// carry layers well past 256 MB — judge-golang, judge-grafana and
// judge-api-runtime all do. Applying the small-entry ceiling to layers cost
// those images their signed envelope every night.
//
// What remains is a runaway circuit-breaker: a decompression bomb cannot
// exhaust memory here, but it can still burn the box's CPU forever, so the
// stream is cut at a size no legitimate layer approaches. It is a var only so
// tests can lower it.
//
// The number is MEASURED, not judged — see largestMeasuredLayerSize and
// TestCeilings_AdmitLargestRealImagesAndBoundTheAttacker for the survey it comes
// from and the ratchet that keeps it honest. 8 GiB is 1.4x the largest layer
// found in any real image and 12x the largest the judge factory itself scans.
//
// On its own this is NOT bomb protection — see maxDecompressedImageSize.
var maxDecompressedLayerSize int64 = 8 << 30 // 8 GiB

// maxDecompressedImageSize bounds how many decompressed bytes ALL of an
// image's layers may contribute together.
//
// A per-layer ceiling is correct in isolation and unbounded in aggregate: a
// manifest naming N distinct layers buys N times the allowance, so a tarball of
// a few megabytes carrying a hundred separately-compressed bombs forces
// terabytes of decompression and hashing without any single layer ever crossing
// its own limit. What exhausts the worker is the total work, and the total work
// is the sum, so the ceiling has to be on the sum.
//
// This budget is drawn down by every layer of one image and is never reset
// mid-image. It sits above the per-layer ceiling — an image is allowed more than
// any one legitimate layer's worth of headroom — but far below what an
// amplification attack needs: the attack dies on its second oversized layer
// instead of its ten-thousandth. It is a var only so tests can lower it.
//
// 24 GiB is 1.9x the largest real image measured anywhere and 18x the largest
// the judge factory scans (see largestMeasuredImageSize). It is the number that
// converts into a wall-clock bound on the attacker, because it is the total
// work one image can force: gzip-decompress feeding SHA-256 measured at
// 1874 MiB/s on an M-series core over maximally compressible input (258:1), so
// 24 GiB is ~13s there and well under a minute on a slower x86 runner — roughly
// twice what legitimately scanning the largest real image already costs, and
// below the time its tarball took to pull. The previous 64 GiB bought an
// attacker ~35s of that same core for a ~10 MB push.
var maxDecompressedImageSize int64 = 24 << 30 // 24 GiB

// maxLayerCount bounds how many layer positions a single manifest may name.
//
// Same per-item-versus-aggregate shape as the byte ceilings, but for
// allocations rather than CPU: every entry in Manifest.Layers costs an entry in
// the wanted and byName maps and a slot in the emitted diffID slice, and all
// three are sized directly from a count that manifest.json supplies — a file
// this attestor will read up to maxTarEntrySize of. Docker's own historical
// ceiling is 127 layers and no real image comes near four times that, so this
// rejects the pathological manifest without touching a legitimate one.
//
// It keeps a much looser multiple over the measured maximum (18 layers) than the
// byte ceilings do over theirs, and deliberately: the resource is different.
// Three small map/slice slots per layer means 512 costs kilobytes however the
// manifest is shaped, so there is nothing here for an attacker to convert into
// work. The byte ceilings bound CPU, which is why they are held to the measured
// evidence instead.
const maxLayerCount = 512

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

// getLayerDIFFIDs measures every layer the manifest names, in manifest order.
//
// Layers are streamed, never buffered. A base image layer is routinely
// hundreds of megabytes and occasionally gigabytes, so reading one into a
// []byte to hash it is both a memory hazard and the reason the old ceiling
// existed. Streaming makes the cost constant and lets the ceiling move to
// where it belongs — a runaway guard, not a size limit on legitimate images.
//
// Each tar entry is read at most once and keyed by name, because a manifest
// may reference one physical blob from several layer positions (identical
// layers are stored once). Walking the layer list per tar entry, as this
// used to, re-read an already-consumed entry and failed with io.EOF.
//
// Everything the manifest can inflate is bounded here, before any of it is
// acted on: the layer COUNT (which sizes three allocations), the decompressed
// bytes of the whole IMAGE (a per-layer ceiling multiplies by the layer count
// and so bounds nothing), and the hash set (an empty one measures nothing at
// all). Each of those is a fail-closed error, never a narrowing or a skip — an
// image this attestor cannot fully measure must not yield a signed envelope
// claiming it did.
func (m *Manifest) getLayerDIFFIDs(ctx *attestation.AttestationContext, tarFilePath string) ([]cryptoutil.DigestSet, error) {
	if len(m.Layers) == 0 {
		return nil, nil
	}
	// Checked before anything is sized from it: the maps and the diffID slice
	// below all take their capacity from this count.
	if len(m.Layers) > maxLayerCount {
		return nil, fmt.Errorf("manifest names %d layers, above the maximum of %d", len(m.Layers), maxLayerCount)
	}

	// Resolved once, up front, and fatal when empty. A layer the attestor
	// cannot measure must stop the attestation here rather than be recorded as
	// a subject carrying no digest — see layerHashes.
	hashes, err := layerHashes(ctx)
	if err != nil {
		return nil, err
	}

	// Keyed by the EXTRACTED path, mapped back to the manifest's own string.
	//
	// Matching on the raw tar name would let `./a.tar` and `a.tar` — one file to
	// every extractor there is — arrive as two unrelated keys, which is a
	// same-file collision that walks straight past the duplicate-entry refusal
	// in digestTarEntries. Cleaning both sides is identity for every real image
	// (docker save and crane pull both emit already-clean names) and is exactly
	// what the extractor does with a crafted one.
	wanted := make(map[string]string, len(m.Layers))
	for _, layerFile := range m.Layers {
		clean := tarEntryKey(layerFile)
		// Two DIFFERENT manifest strings naming one extracted path is the same
		// ambiguity as two physical entries, one level up: the positional
		// evidence would claim two layers where the image has one.
		if prev, ok := wanted[clean]; ok && prev != layerFile {
			return nil, fmt.Errorf("%w: manifest layers %q and %q both resolve to %q", errDuplicateTarEntry, prev, layerFile, clean)
		}
		wanted[clean] = layerFile
	}

	scan := &layerScan{
		hashes: hashes,
		budget: &decompressionBudget{limit: maxDecompressedImageSize},
	}

	byName, err := digestTarEntries(tarFilePath, wanted, scan)
	if err != nil {
		return nil, err
	}

	// Emit in manifest order: layerdiffidNN is positional evidence, and tar
	// entry order is an artefact of how the archive happened to be written.
	layerDiffIDs := make([]cryptoutil.DigestSet, 0, len(m.Layers))
	for _, layerFile := range m.Layers {
		digest, ok := byName[layerFile]
		if !ok {
			return nil, fmt.Errorf("layer %q is named in the manifest but absent from the image tar", layerFile)
		}
		layerDiffIDs = append(layerDiffIDs, digest)
	}
	return layerDiffIDs, nil
}

// errDuplicateTarEntry is the fail-closed outcome when the image tar carries
// more than one PHYSICAL entry for a layer name the manifest asked for. It is a
// sentinel so callers and tests can assert that THIS is why the attestation
// refused, rather than matching on message text.
var errDuplicateTarEntry = errors.New("image tar contains more than one entry for a wanted layer name")

// errUnmeasurableTarEntry is the fail-closed outcome when a layer name resolves
// to a tar entry that carries no bytes to measure. Sentinel, same reasons.
var errUnmeasurableTarEntry = errors.New("layer is not a regular file")

// tarEntryKey is the path a tar entry EXTRACTS to, which is the only identity
// that matters when deciding whether two entries are the same file.
//
// `a.tar`, `./a.tar`, `x/../a.tar` and `/a.tar` are four header names and one
// extracted file — tar stores whatever the writer put there and extractors
// normalise on the way out (GNU tar strips the leading slash, cleans the rest).
// Comparing raw header names would file those as unrelated entries and walk
// straight past the duplicate refusal below. On every real tarball this is the
// identity function: `crane pull` writes flat, already-clean names (verified
// against docker.io/library/busybox:1.31.1 and
// quay.io/brancz/kube-rbac-proxy:v0.13.1 — every entry a regular file with a
// bare name), so the normalisation costs a legitimate image nothing.
func tarEntryKey(name string) string {
	return strings.TrimLeft(path.Clean(name), "/")
}

// digestTarEntries walks the image tar once and digests every entry named in
// wanted, returning them keyed by tar entry name.
//
// Single pass: the tar reader is a forward-only stream, so an entry consumed
// for one layer position cannot be re-read for another. A manifest may name one
// physical blob from several positions (identical layers are stored once),
// which is why the caller maps this result back over the layer list rather than
// expecting it to be 1:1 — repeated REFERENCES are legitimate and stay
// supported.
//
// A repeated PHYSICAL entry is a different thing entirely and is refused. tar
// permits the same name to appear more than once and assigns no meaning to the
// repetition; the near-universal extractor convention is LAST-ENTRY-WINS (GNU
// tar, bsdtar and docker/podman image loads all overwrite as they extract), so
// silently keeping the first entry would let an archive be attested with the
// benign bytes a consumer never sees while the bytes it actually gets go
// unmeasured. That is precisely the attestation-versus-reality split this
// attestor exists to make impossible. Taking the last entry instead would only
// move the ambiguity — the archive has two answers and no authority to choose
// between them — so the honest outcome is to refuse the image as ambiguous
// evidence rather than sign either reading of it.
func digestTarEntries(
	tarFilePath string,
	wanted map[string]string,
	scan *layerScan,
) (map[string]cryptoutil.DigestSet, error) {
	tarFile, err := os.Open(tarFilePath) //nolint:gosec // G304: tar file path from attestation context
	if err != nil {
		return nil, err
	}
	defer func() { _ = tarFile.Close() }()

	byName := make(map[string]cryptoutil.DigestSet, len(wanted))
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
		key, ok := wanted[tarEntryKey(h.Name)]
		if !ok {
			continue
		}
		// A layer must be a REGULAR FILE. A symlink, hardlink or device node
		// wearing a wanted name has no payload in the archive — tar stores its
		// target, not its bytes — so streaming it digests zero bytes and the
		// envelope ends up asserting a diffID that measures nothing, the same
		// unmeasured-but-signed outcome layerHashes refuses. Go's tar reader has
		// already folded the legacy TypeRegA into TypeReg by this point
		// (archive/tar/reader.go), so TypeReg is the whole legitimate set.
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: layer %q has tar type %q", errUnmeasurableTarEntry, h.Name, string(h.Typeflag))
		}
		if _, done := byName[key]; done {
			return nil, fmt.Errorf("%w: %q", errDuplicateTarEntry, h.Name)
		}
		if h.Size < 0 {
			return nil, fmt.Errorf("layer entry has invalid size: %d", h.Size)
		}
		digest, err := layerDiffID(tarReader, scan)
		if err != nil {
			return nil, fmt.Errorf("layer %q: %w", h.Name, err)
		}
		byName[key] = digest
	}
	return byName, nil
}

// layerScan is the state one tar walk shares across every layer of the same
// image: the streaming hash set each layer is measured with, and the cumulative
// decompression budget they all draw from. Both are per-image, which is the
// whole point of the budget — a per-layer allowance is not a bomb defence.
type layerScan struct {
	hashes []cryptoutil.DigestValue
	budget *decompressionBudget
}

// decompressionBudget is the image-wide allowance every layer draws down. It
// puts the ceiling on the total work the attestor will perform for one image
// rather than on each layer independently.
type decompressionBudget struct {
	limit int64
	used  int64
}

func (b *decompressionBudget) exceeded() bool { return b.used > b.limit }

// layerDiffID digests one layer straight off the tar reader, transparently
// decompressing a gzipped layer so the diffID is over the uncompressed bytes
// exactly as before.
func layerDiffID(r io.Reader, scan *layerScan) (cryptoutil.DigestSet, error) {
	// http.DetectContentType only ever inspects the first 512 bytes, so peek
	// that much rather than reading the layer in to sniff it.
	buffered := bufio.NewReaderSize(r, sniffLen)
	head, err := buffered.Peek(sniffLen)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("failed to read layer: %w", err)
	}

	var src io.Reader = buffered
	if http.DetectContentType(head) == "application/x-gzip" {
		gzReader, err := gzip.NewReader(buffered)
		if err != nil {
			return nil, err
		}
		defer func() { _ = gzReader.Close() }()
		src = gzReader
	}

	capped := &cappedReader{r: src, limit: maxDecompressedLayerSize, budget: scan.budget}
	digest, err := cryptoutil.CalculateDigestSet(capped, scan.hashes)
	if err != nil {
		return nil, err
	}
	// Both ceilings are checked after the copy, not only from inside Read: a
	// stream that ends exactly on a ceiling reports its final bytes and io.EOF
	// in one call, so the reader is never entered again to raise the error
	// itself. Per-layer first, so a single bomb names itself rather than being
	// reported as the image's cumulative overrun.
	if capped.exceeded() {
		return nil, fmt.Errorf("decompressed layer exceeds maximum size of %d bytes", capped.limit)
	}
	if scan.budget.exceeded() {
		return nil, fmt.Errorf("decompressed image exceeds the cumulative maximum of %d bytes across all layers", scan.budget.limit)
	}
	return digest, nil
}

// errNoStreamableLayerHash is the fail-closed outcome when a context asks for
// layer measurement with nothing but buffering (gitoid) hashes. It is a
// sentinel so callers and tests can assert that THIS is why the attestation
// refused, rather than matching on message text.
var errNoStreamableLayerHash = errors.New("no streamable hash available to measure layers")

// layerHashes returns the subset of the context's hash set a layer can actually
// be streamed through, and fails closed when that subset is empty.
//
// The gitoid hasher must know the content length before it can hash, so it
// accumulates the entire payload in memory (attestation/cryptoutil/gitoid.go).
// Feeding a multi-gigabyte layer through it would reintroduce, verbatim, the
// memory blowup streaming exists to remove. A gitoid over a layer blob is not
// evidence anyone consumes either: the OCI spec defines a diffID as the
// SHA-256 of the uncompressed layer, and Subjects() reads exactly that.
// `cilock run` is unaffected — it builds every DigestValue with GitOID:false
// (cilock/cli/run.go), so for cilock the streamable set is always the whole
// requested set.
//
// Dropping SOME hashes is a narrowing; dropping ALL of them is a missing
// measurement, and it must not be silent. A context configured with nothing but
// gitoid values — reachable through attestation.WithHashes, which this attestor
// is a library consumer of — leaves nothing to narrow to, and
// cryptoutil.CalculateDigestSet does not treat an empty hash set as an error:
// it drains the reader and returns an EMPTY DigestSet. That set would be
// recorded as the layer's diffID and emitted by Subjects() as a bare
// "layerdiffidNN:" key carrying no digest, i.e. a successful, signed
// attestation asserting a measurement that was never taken. Refusing here is
// the only outcome that keeps the envelope honest.
func layerHashes(ctx *attestation.AttestationContext) ([]cryptoutil.DigestValue, error) {
	hashes := ctx.Hashes()
	streamable := make([]cryptoutil.DigestValue, 0, len(hashes))
	for _, h := range hashes {
		if h.GitOID {
			continue
		}
		streamable = append(streamable, h)
	}
	if len(streamable) == 0 {
		return nil, fmt.Errorf(
			"%w: all %d requested hash(es) buffer the whole payload (gitoid), so no layer could be measured without loading it into memory",
			errNoStreamableLayerHash, len(hashes),
		)
	}
	return streamable, nil
}

// cappedReader stops a layer that streams past a ceiling rather than
// truncating it — a short read would yield a confidently wrong digest, which
// is worse than no digest at all. It reads one byte beyond the ceiling so the
// overrun is detectable, and refuses to go further so a bomb cannot spin.
//
// Two ceilings apply and the tighter one governs every read: this layer's own
// limit, and the image-wide budget shared with every other layer of the same
// image. A layer that is individually legitimate therefore still stops the
// moment the image as a whole has spent its allowance, which is what makes a
// many-small-bombs manifest bounded rather than merely bounded per layer.
//
// budget is REQUIRED, not optional. An optional aggregate ceiling is how the
// bypass this closes came about in the first place, so there is deliberately no
// nil case to fall through: a cappedReader without a budget is a construction
// error, not a per-layer-only mode.
type cappedReader struct {
	r      io.Reader
	limit  int64
	read   int64
	budget *decompressionBudget
}

func (c *cappedReader) Read(p []byte) (int, error) {
	room := c.limit + 1 - c.read
	if room <= 0 {
		return 0, fmt.Errorf("decompressed layer exceeds maximum size of %d bytes", c.limit)
	}
	budgetRoom := c.budget.limit + 1 - c.budget.used
	if budgetRoom <= 0 {
		return 0, fmt.Errorf("decompressed image exceeds the cumulative maximum of %d bytes across all layers", c.budget.limit)
	}
	if budgetRoom < room {
		room = budgetRoom
	}
	if int64(len(p)) > room {
		p = p[:room]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	c.budget.used += int64(n)
	return n, err
}

func (c *cappedReader) exceeded() bool { return c.read > c.limit }
