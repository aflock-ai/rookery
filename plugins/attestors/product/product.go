// Copyright 2021 The Witness Contributors
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

package product

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/file"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	"github.com/gabriel-vasile/mimetype"
	"github.com/gobwas/glob"
	"github.com/invopop/jsonschema"
)

// portableNormalize rewrites a relative path into the canonical form used
// by the v0.2 merkle root. Backslashes are unconditionally replaced with
// forward slashes — we do NOT use filepath.ToSlash because that helper is
// OS-aware (it leaves backslashes alone on non-Windows hosts), which would
// make a Windows-recorded attestation produce a different merkle root when
// re-hashed on Linux for verification. The merkle root must be a function
// of the predicate alone, regardless of host OS.
func portableNormalize(p string) string {
	return strings.ReplaceAll(p, "\\", "/")
}

// safeGlobMatch wraps glob.Match with panic recovery. The gobwas/glob library
// can panic on certain patterns that compile successfully but trigger out-of-bounds
// access during matching. We treat panics as non-matches.
func safeGlobMatch(g glob.Glob, s string) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched = false
			err = fmt.Errorf("glob match panicked: %v", r)
		}
	}()
	return g.Match(s), nil
}

const (
	ProductName = "product"
	// ProductType is bumped to v0.2 to signal a breaking change in subject
	// semantics: instead of one `file:<path>` subject per file, the attestor
	// now emits a single `tree:products` subject whose digest is a
	// deterministic merkle root over the included product set. The full
	// per-file map is still available in the predicate. Consumers that
	// match subjects by file path must be updated.
	ProductType    = "https://aflock.ai/attestations/product/v0.2"
	ProductRunType = attestation.ProductRunType

	// LegacyProductType is the prior per-file-subject schema. Verifiers may
	// continue to recognize it for backward compatibility when parsing old
	// attestations, but new attestations always use ProductType.
	LegacyProductType = "https://aflock.ai/attestations/product/v0.1"

	defaultIncludeGlob = "*"
	defaultExcludeGlob = ""
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor  = &Attestor{}
	_ attestation.Subjecter = &Attestor{}
	_ attestation.Producer  = &Attestor{}
)

type ProductAttestor interface {
	// Attestor
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error

	// Subjector
	Subjects() map[string]cryptoutil.DigestSet

	// Producter
	Products() map[string]attestation.Product
}

// configOptions are the registry options shared by both the modern and the
// legacy product attestor registrations. Defining them once keeps the two
// registrations from drifting apart.
func configOptions() []registry.Configurer {
	return []registry.Configurer{
		registry.StringConfigOption(
			"include-glob",
			"Pattern to use when recording products. Files that match this pattern will be included as subjects on the attestation.",
			defaultIncludeGlob,
			func(a attestation.Attestor, includeGlob string) (attestation.Attestor, error) {
				prodAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product attestor", a)
				}
				WithIncludeGlob(includeGlob)(prodAttestor)
				return prodAttestor, nil
			},
		),
		registry.StringConfigOption(
			"exclude-glob",
			"Pattern to use when recording products. Files that match this pattern will be excluded as subjects on the attestation.",
			defaultExcludeGlob,
			func(a attestation.Attestor, excludeGlob string) (attestation.Attestor, error) {
				prodAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product attestor", a)
				}
				WithExcludeGlob(excludeGlob)(prodAttestor)
				return prodAttestor, nil
			},
		),
	}
}

func init() {
	// Register the LEGACY v0.1 predicate type FIRST so that the second
	// registration (the modern v0.2) wins when looking up the attestor by
	// name in attestorRegistry / attestationsByRun. The v0.1 entry survives
	// only in attestationsByType, so verifiers loading historical
	// attestations from Archivista still get a working attestor.
	//
	// The legacy factory hands back an Attestor with legacyMode=true. Its
	// Subjects() method emits one `file:<path>` (or `dir:<path>`) entry per
	// included product, exactly matching what cilock used to write into
	// pre-v0.2 DSSE statements. That preserves subject-equality and
	// therefore policy / verification semantics for old artifacts.
	attestation.RegisterAttestation(
		ProductName,
		LegacyProductType,
		ProductRunType,
		func() attestation.Attestor { return New(WithLegacyMode()) },
		configOptions()...,
	)

	// Register the MODERN v0.2 predicate type. New attestations always use
	// this type and the merkle-root tree subject.
	attestation.RegisterAttestation(
		ProductName,
		ProductType,
		ProductRunType,
		func() attestation.Attestor { return New() },
		configOptions()...,
	)
}

type Option func(*Attestor)

func WithIncludeGlob(glob string) Option {
	return func(a *Attestor) {
		a.includeGlob = glob
	}
}

func WithExcludeGlob(glob string) Option {
	return func(a *Attestor) {
		a.excludeGlob = glob
	}
}

// WithLegacyMode flips the attestor into v0.1 compatibility mode: Subjects()
// emits one `file:<path>` (or `dir:<path>`) entry per included product
// instead of the v0.2 merkle-root tree subject. This is used by the
// registry-side legacy factory so that verifiers loading historical
// attestations get the same subject set the original cilock run wrote into
// the DSSE statement. Do not use this for *new* attestations.
func WithLegacyMode() Option {
	return func(a *Attestor) {
		a.legacyMode = true
	}
}

type Attestor struct {
	products            map[string]attestation.Product
	baseArtifacts       map[string]cryptoutil.DigestSet
	includeGlob         string
	compiledIncludeGlob glob.Glob
	excludeGlob         string
	compiledExcludeGlob glob.Glob
	// legacyMode, when true, makes Subjects() emit per-file `file:<path>` /
	// `dir:<path>` subjects exactly the way the v0.1 product attestor did.
	// It is set only by the v0.1 registry factory used at verification time.
	legacyMode bool
}

func fromDigestMap(workingDir string, digestMap map[string]cryptoutil.DigestSet) map[string]attestation.Product {
	products := make(map[string]attestation.Product)
	for fileName, digestSet := range digestMap {
		filePath := filepath.Join(workingDir, fileName)

		mimeType, err := getFileContentType(filePath)
		if err != nil {
			mimeType = "unknown"
		}

		if mimeType == "application/octet-stream" {
			fileInfo, err := os.Stat(filePath)
			if err == nil && fileInfo.IsDir() {
				mimeType = "text/directory"
			}
		}

		products[fileName] = attestation.Product{
			MimeType: mimeType,
			Digest:   digestSet,
		}
	}

	return products
}

func (a *Attestor) Name() string {
	return ProductName
}

func (a *Attestor) Type() string {
	return ProductType
}

func (a *Attestor) RunType() attestation.RunType {
	return ProductRunType
}

func New(opts ...Option) *Attestor {
	a := &Attestor{
		includeGlob: defaultIncludeGlob,
		excludeGlob: defaultExcludeGlob,
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

func (a *Attestor) Schema() *jsonschema.Schema {
	// MarshalJSON outputs the products map directly (not wrapped in a struct),
	// so the schema must reflect a flat map to match the actual JSON shape.
	return jsonschema.Reflect(map[string]attestation.Product{})
}

func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	compiledIncludeGlob, err := glob.Compile(a.includeGlob)
	if err != nil {
		return err
	}
	a.compiledIncludeGlob = compiledIncludeGlob

	compiledExcludeGlob, err := glob.Compile(a.excludeGlob)
	if err != nil {
		return err
	}
	a.compiledExcludeGlob = compiledExcludeGlob

	a.baseArtifacts = ctx.Materials()

	processWasTraced := false
	openedFileSet := map[string]bool{}

	for _, completedAttestor := range ctx.CompletedAttestors() {
		attestor := completedAttestor.Attestor
		if commandRunAttestor, ok := attestor.(*commandrun.CommandRun); ok && commandRunAttestor.TracingEnabled() {
			processWasTraced = true

			for _, process := range commandRunAttestor.Processes {
				for fname := range process.OpenedFiles {
					openedFileSet[fname] = true
				}
			}
		}
	}

	products, err := file.RecordArtifacts(ctx.WorkingDir(), a.baseArtifacts, ctx.Hashes(), map[string]struct{}{}, processWasTraced, openedFileSet, ctx.DirHashGlob(), a.compiledIncludeGlob, a.compiledExcludeGlob)
	if err != nil {
		return err
	}

	a.products = fromDigestMap(ctx.WorkingDir(), products)
	return nil
}

func (a *Attestor) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.products)
}

func (a *Attestor) UnmarshalJSON(data []byte) error {
	prods := make(map[string]attestation.Product)
	if err := json.Unmarshal(data, &prods); err != nil {
		return err
	}

	a.products = prods
	return nil
}

func (a *Attestor) Products() map[string]attestation.Product {
	return a.products
}

// TreeSubjectName is the single subject name emitted by the product attestor.
// Instead of one subject per file (which exploded to 30k+ subjects on
// node_modules trees and broke Archivista's MySQL placeholder limit), the
// product attestor now emits ONE deterministic merkle root over the entire
// product set. The full per-file list is still preserved in the predicate
// JSON via MarshalJSON, where it is gzip-compressed in transit and not
// multiplied across SQL placeholders.
const TreeSubjectName = "tree:products"

// Subjects returns the in-toto subject set for this attestor.
//
// In v0.2 (the default) it returns a single "tree:products" subject whose
// digest set is the merkle root over all products that pass the
// include/exclude globs. The merkle root for each hash algorithm is computed
// as:
//
//	h := New(algo)
//	for _, name := sortedProductNames {
//	    h.Write([]byte(name))
//	    h.Write([]byte{0})
//	    h.Write([]byte(productDigests[name][algo]))
//	    h.Write([]byte{0})
//	}
//	root := h.Sum(nil)
//
// This is deterministic, reproducible, and verifiable from the predicate
// alone (anyone can recompute the root from the predicate's product map and
// compare against the subject digest).
//
// If there are no included products the function returns an empty map (no
// subjects), matching the prior behavior of "empty workdir → empty subjects".
//
// When the attestor is in legacy mode (constructed via WithLegacyMode, which
// only happens when the registry instantiates it for the v0.1 predicate
// type), it instead emits one "file:<path>" / "dir:<path>" subject per
// included product — exactly the v0.1 shape — so historical DSSE statements
// continue to verify.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	if a.legacyMode {
		return a.legacySubjects()
	}

	// Filter products by globs and collect (normalized-name, original-key)
	// pairs. The original key is whatever was stored in the products map at
	// Attest time, which on Windows uses backslash; the normalized name is
	// what gets fed into the hash so the merkle root is portable across
	// operating systems. We need both: the original key to look up the
	// product, the normalized name for the hash.
	included := a.includedProductPairs()
	if len(included) == 0 {
		return map[string]cryptoutil.DigestSet{}
	}

	// Collect every (Hash, GitOID, DirHash) tuple that appears across the
	// included products. We compute one root per distinct algorithm so the
	// emitted DigestSet matches whatever set the products themselves use.
	algos := map[cryptoutil.DigestValue]struct{}{}
	for _, p := range included {
		for dv := range a.products[p.originalKey].Digest {
			algos[dv] = struct{}{}
		}
	}

	root := make(cryptoutil.DigestSet, len(algos))
	for dv := range algos {
		h := dv.New()
		for _, p := range included {
			digest, ok := a.products[p.originalKey].Digest[dv]
			if !ok {
				// Product missing this algorithm — fold the absence into
				// the root deterministically (using the normalized name as
				// part of the hash input) so the root still depends on the
				// file list, never silently skipping a file.
				digest = ""
			}
			writeMerkleEntry(h, p.normalized, digest)
		}
		root[dv] = encodeRoot(h, dv)
	}

	return map[string]cryptoutil.DigestSet{
		TreeSubjectName: root,
	}
}

// legacySubjects returns the v0.1 per-file subject map. It is byte-for-byte
// identical to what the v0.1 product attestor produced, so subject equality
// — and therefore go-witness policy verification of historical attestations
// — still holds. New attestations never call this; only the v0.1 registry
// factory wires it in via WithLegacyMode.
func (a *Attestor) legacySubjects() map[string]cryptoutil.DigestSet {
	subjects := make(map[string]cryptoutil.DigestSet, len(a.products))
	for productName, product := range a.products {
		// Normalize path to forward slashes for glob matching so Windows
		// paths like "subdir\test.txt" become "subdir/test.txt".
		normalizedPath := filepath.ToSlash(productName)

		if a.compiledExcludeGlob != nil {
			if matched, err := safeGlobMatch(a.compiledExcludeGlob, normalizedPath); err != nil {
				log.Debugf("exclude glob match error for path %q: %v", normalizedPath, err)
			} else if matched {
				continue
			}
		}
		if a.compiledIncludeGlob != nil {
			if matched, err := safeGlobMatch(a.compiledIncludeGlob, normalizedPath); err != nil {
				log.Debugf("include glob match error for path %q: %v", normalizedPath, err)
			} else if !matched {
				continue
			}
		}

		subjectType := "file"
		if product.MimeType == "text/directory" {
			subjectType = "dir"
		}
		// IMPORTANT: use the raw productName (NOT the normalized one) so the
		// emitted key matches exactly what v0.1 wrote into the original
		// statement. v0.1 used the OS-native path here.
		subjects[fmt.Sprintf("%v:%v", subjectType, productName)] = product.Digest
	}
	return subjects
}

// productPair carries both the normalized (forward-slash) form of a product
// path and its original key in the attestor's product map. The normalized
// form is what we hash into the merkle root (so the root is portable across
// operating systems); the original key is what we use to look up the
// product's digest set.
type productPair struct {
	normalized  string // forward-slash, used for hashing and sorting
	originalKey string // OS-native, used for map lookup
}

// includedProductPairs returns the product entries that survive
// include/exclude glob filtering, sorted by their normalized name for
// deterministic merkle ordering.
func (a *Attestor) includedProductPairs() []productPair {
	pairs := make([]productPair, 0, len(a.products))
	for productName := range a.products {
		// portableNormalize unconditionally rewrites backslashes to
		// forward slashes so the merkle root is the same regardless of
		// which OS originally produced the attestation.
		normalizedPath := portableNormalize(productName)

		if a.compiledExcludeGlob != nil {
			if matched, err := safeGlobMatch(a.compiledExcludeGlob, normalizedPath); err != nil {
				log.Debugf("exclude glob match error for path %q: %v", normalizedPath, err)
			} else if matched {
				continue
			}
		}

		if a.compiledIncludeGlob != nil {
			if matched, err := safeGlobMatch(a.compiledIncludeGlob, normalizedPath); err != nil {
				log.Debugf("include glob match error for path %q: %v", normalizedPath, err)
			} else if !matched {
				continue
			}
		}

		pairs = append(pairs, productPair{normalized: normalizedPath, originalKey: productName})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].normalized < pairs[j].normalized
	})
	return pairs
}

// writeMerkleEntry writes one (name, digest) pair into the rolling hash with
// NUL framing so distinct entries cannot collide via concatenation.
func writeMerkleEntry(h hash.Hash, name, digest string) {
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(digest))
	_, _ = h.Write([]byte{0})
}

// encodeRoot returns the hex (or gitoid-string) encoding of the merkle root
// using the same convention as cryptoutil.CalculateDigestSet.
func encodeRoot(h hash.Hash, dv cryptoutil.DigestValue) string {
	if dv.GitOID {
		// gitoidHasher.Sum returns a gitoid URI string, not raw bytes.
		return string(h.Sum(nil))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func IsSPDXJson(buf []byte) bool {
	maxLen := len(buf)
	if maxLen > 500 {
		maxLen = 500
	}
	header := buf[:maxLen]

	return bytes.Contains(header, []byte(`"spdxVersion":"SPDX-`)) || bytes.Contains(header, []byte(`"spdxVersion": "SPDX-`))
}

func IsCycloneDXJson(buf []byte) bool {
	maxLen := len(buf)
	if maxLen > 500 {
		maxLen = 500
	}
	header := buf[:maxLen]

	return bytes.Contains(header, []byte(`"bomFormat":"CycloneDX"`)) || bytes.Contains(header, []byte(`"bomFormat": "CycloneDX"`))
}

func init() {
	// Register custom MIME type detectors once at startup, not on every call.
	mimetype.Lookup("application/json").Extend(func(buf []byte, limit uint32) bool {
		return IsSPDXJson(buf)
	}, "application/spdx+json", ".spdx.json")

	mimetype.Lookup("application/json").Extend(func(buf []byte, limit uint32) bool {
		return IsCycloneDXJson(buf)
	}, "application/vnd.cyclonedx+json", ".cdx.json")

	mimetype.Lookup("text/xml").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`<?xml version="1.0" encoding="UTF-8"?><bom xmlns="http://cyclonedx.org/schema/bom/`))
	}, "application/vnd.cyclonedx+xml", ".cdx.xml")

	mimetype.Lookup("application/json").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`{"@context":"https://openvex.dev/ns`))
	}, "application/vex+json", ".vex.json")

	mimetype.Lookup("text/plain").Extend(func(buf []byte, limit uint32) bool {
		return bytes.HasPrefix(buf, []byte(`sha256:`))
	}, "text/sha256+text", ".sha256")
}

func getFileContentType(fileName string) (string, error) {
	contentType, err := mimetype.DetectFile(fileName)
	if err != nil {
		return "", err
	}

	return contentType.String(), nil
}
