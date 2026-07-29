// Copyright 2024 The Witness Contributors
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

package vex

import (
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
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/plugins/attestors/vex/openvex"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "vex"
	Type    = "https://openvex.dev/ns"
	RunType = attestation.PostProductRunType
)

// This is a hacky way to create a compile time error in case the attestor
// doesn't implement the expected interfaces.
var (
	_ attestation.Attestor = &Attestor{}
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType,
		func() attestation.Attestor { return New() },
		registry.StringConfigOption(
			"file",
			"Path to an existing OpenVEX document to attest directly. Bypasses product-set scanning — "+
				"use it when the document was authored before the wrapped command ran (i.e. it's a material, "+
				"not a product). Relative paths are resolved against the working directory.",
			"",
			func(a attestation.Attestor, val string) (attestation.Attestor, error) {
				vexAttestor, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a VEX attestor", a)
				}
				WithVEXFile(val)(vexAttestor)
				return vexAttestor, nil
			},
		),
	)
	detection.Register(Name, detectorYAML)
}

type Option func(*Attestor)

// WithVEXFile pins the attestor to a specific OpenVEX document on disk.
// When set, getCandidate reads that file directly instead of scanning the
// product attestor's output set — the same escape hatch the sbom attestor
// exposes via WithSBOMFile. Operators name pre-existing documents this
// way; `cilock attest vex` does NOT (it hands over the bytes it rendered,
// see WithVEXBytes).
func WithVEXFile(path string) Option {
	return func(a *Attestor) {
		a.vexFile = path
	}
}

// WithVEXBytes pins the attestor to an in-memory OpenVEX document. The
// bytes are what gets validated, digested, and signed; path is used ONLY
// to derive the stable name recorded in the predicate and is never
// reopened.
//
// This is the channel `cilock attest vex` uses, and the reason it exists
// is a TOCTOU: the command writes the authored document to disk for the
// operator, but if the attestor then re-read that path, anything with
// write access to the workspace could swap the file between the write and
// the read — and cilock would sign products, vulnerabilities, or a status
// the operator never passed. Signing the bytes the command itself
// rendered removes the window entirely; the on-disk file is a courtesy
// copy, not the signing input.
//
// When both bytes and a file are configured, the bytes win: they are the
// stronger binding, and `cilock attest vex` sets them deliberately. That
// precedence is tracked by CONFIGURATION, not by content — an empty
// buffer is a caller bug and is rejected in loadFromBytes, never treated
// as "no bytes were set" with a silent fall back to re-reading the path,
// which would reopen exactly the TOCTOU window this channel closes.
func WithVEXBytes(raw []byte, path string) Option {
	return func(a *Attestor) {
		a.vexBytes = raw
		a.vexBytesSet = true
		a.vexFile = path
	}
}

type Attestor struct {
	VEXDocument     openvex.VEX          `json:"vexDocument"`
	ReportFile      string               `json:"reportFileName,omitempty"`
	ReportDigestSet cryptoutil.DigestSet `json:"reportDigestSet,omitempty"`

	// vexFile, when non-empty, is the explicit document path set by
	// WithVEXFile / --attestor-vex-file. When vexBytes is also set, it is
	// only the name source, never reopened.
	vexFile string

	// vexBytes is the exact document to attest, set by WithVEXBytes.
	// When vexBytesSet is true it takes precedence over every
	// file-reading path.
	vexBytes []byte

	// vexBytesSet records that WithVEXBytes was called at all, so the
	// dispatch in getCandidate keys on the caller's intent rather than
	// on len(vexBytes) — an empty configured buffer must be an error,
	// not a silent fallback to the file path.
	vexBytesSet bool
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
	if err := a.getCandidate(ctx); err != nil {
		log.Debugf("(attestation/vex) error getting candidate: %v", err)
		return err
	}

	return nil
}

func (a *Attestor) getCandidate(ctx *attestation.AttestationContext) error {
	if a.vexBytesSet {
		return a.loadFromBytes(ctx)
	}
	if a.vexFile != "" {
		return a.loadFromExplicitFile(ctx)
	}

	products := ctx.Products()

	if len(products) == 0 {
		return fmt.Errorf("no products to attest")
	}

	// lastInvalid remembers why the most recent parseable candidate was
	// rejected, so "no VEX file found" can say what was actually wrong
	// with the document the operator probably meant.
	var lastInvalid error

	// Iterate the product set in a fixed order. Go randomizes map
	// iteration, so scanning ctx.Products() directly would pick an
	// arbitrary document whenever a build produces more than one valid
	// VEX file — two runs over identical inputs could sign different
	// evidence, and neither the operator nor a verifier would see why.
	// Sorting makes the choice a property of the tree rather than of the
	// runtime, which is the whole point of reproducible attestation.
	paths := make([]string, 0, len(products))
	for path := range products {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	for _, path := range paths {
		product := products[path]

		// Product-set keys are working-dir RELATIVE — the product
		// attestor stores them that way (see fromDigestMap, which keys
		// on the relative name while stat'ing workingDir+name). Opening
		// the bare key resolves it against the PROCESS cwd instead, so
		// `cilock run --workingdir build -a vex` looked for the document
		// beside the binary rather than beside the build. Same rule the
		// sbom attestor already follows.
		resolved := path
		if !filepath.IsAbs(resolved) {
			resolved = filepath.Join(ctx.WorkingDir(), resolved)
		}

		// Read ONCE, then derive everything from this one buffer.
		// Hashing the file and reopening it to parse leaves a window in
		// which the bytes can change between the two reads: the recorded
		// digest would then describe the file as it was during hashing
		// while the signed predicate came from whatever replaced it.
		// That is a signature attesting to bytes nobody verified.
		reportBytes, err := os.ReadFile(resolved) //nolint:gosec // G304: path from attestation context products
		if err != nil {
			log.Debugf("(attestation/vex) error reading file %s: %v", resolved, err)
			continue
		}

		newDigestSet, err := cryptoutil.CalculateDigestSetFromBytes(reportBytes, ctx.Hashes())
		if newDigestSet == nil || err != nil {
			log.Debugf("(attestation/vex) error calculating digest set from %s: %v", resolved, err)
			continue
		}

		if !newDigestSet.Equal(product.Digest) {
			log.Debugf("(attestation/vex) integrity error for %s: product digest does not match", resolved)
			continue
		}

		// Decode into a fresh document. Unmarshaling straight into
		// a.VEXDocument would merge a rejected candidate's fields into
		// the next one, so a document assembled from two different files
		// could end up signed.
		var doc openvex.VEX
		if err := json.Unmarshal(reportBytes, &doc); err != nil {
			log.Debugf("(attestation/vex) error unmarshaling VEX document: %v", err)
			continue
		}

		// Decoding proves nothing: every VEX field is optional to
		// encoding/json and unknown keys are ignored, so any JSON object
		// in the product set decodes into an empty document. Only a
		// document the spec would accept may become the predicate.
		if err := openvex.Validate(&doc); err != nil {
			log.Debugf("(attestation/vex) %s is not a usable OpenVEX document: %v", resolved, err)
			lastInvalid = fmt.Errorf("%s: %w", resolved, err)
			continue
		}

		a.VEXDocument = doc
		// `resolved` is where THIS machine found the bytes; the name
		// recorded has to be what the file is called relative to the
		// build. ReportFile is part of the signed predicate, so storing
		// the machine-specific form would make the same product under two
		// different working directories produce two different
		// attestations, and would publish the host's directory layout in
		// signed evidence. Resolve for I/O, record what is stable — and
		// both ingestion paths name the document through the SAME helper,
		// so neither can start recording a host path while the other does
		// not.
		a.ReportFile = stableReportName(ctx.WorkingDir(), resolved)
		// The digest of the exact bytes that were parsed into the
		// predicate above — not the product attestor's separately
		// observed digest, which is what made the two divergeable.
		a.ReportDigestSet = newDigestSet

		return nil
	}
	if lastInvalid != nil {
		return fmt.Errorf("no valid VEX file found: %w", lastInvalid)
	}
	return fmt.Errorf("no VEX file found")
}

// loadFromBytes validates and records the in-memory document set by
// WithVEXBytes. Nothing here touches the filesystem: the digest, the
// parsed predicate, and the recorded name all come from the same buffer
// the caller rendered, so there is no window in which a workspace write
// can substitute different content between validation and signing.
//
// Fail closed exactly like the explicit-file path: the caller named this
// document deliberately, so a rejection is an error, never a skip.
func (a *Attestor) loadFromBytes(ctx *attestation.AttestationContext) error {
	if len(a.vexBytes) == 0 {
		return fmt.Errorf("vex: WithVEXBytes was configured with an empty document — refusing to sign it or to fall back to reading %q from disk", a.vexFile)
	}
	var doc openvex.VEX
	if err := json.Unmarshal(a.vexBytes, &doc); err != nil {
		return fmt.Errorf("vex: authored document is not valid OpenVEX JSON: %w", err)
	}
	if err := openvex.Validate(&doc); err != nil {
		return fmt.Errorf("vex: authored document is not a usable OpenVEX document: %w", err)
	}

	digestSet, err := cryptoutil.CalculateDigestSetFromBytes(a.vexBytes, ctx.Hashes())
	if err != nil {
		return fmt.Errorf("vex: digest authored document: %w", err)
	}

	a.VEXDocument = doc
	// The path was never read; it only names the courtesy copy on disk.
	// Same naming rule, same helper, as both file-reading paths.
	resolved := a.vexFile
	if resolved != "" && !filepath.IsAbs(resolved) {
		resolved = filepath.Join(ctx.WorkingDir(), resolved)
	}
	a.ReportFile = stableReportName(ctx.WorkingDir(), resolved)
	a.ReportDigestSet = digestSet
	return nil
}

// loadFromExplicitFile reads the document at a.vexFile and populates the
// predicate exactly as the product-scan path would.
//
// There is no product digest to cross-check against here, so the recorded
// digest is computed from the same bytes that were unmarshaled — the
// attestation still binds to the exact content attested. Unlike the
// product scan, a failure is returned rather than skipped: the operator
// named this file explicitly, so silently attesting nothing would be the
// wrong answer.
//
// The document is validated before anything is recorded. Parsing alone
// would let `{}` — or any unrelated JSON object, since encoding/json
// ignores unknown keys — through as an empty-but-signed VEX predicate.
func (a *Attestor) loadFromExplicitFile(ctx *attestation.AttestationContext) error {
	resolved := a.vexFile
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(ctx.WorkingDir(), resolved)
	}

	reportBytes, err := os.ReadFile(resolved) //nolint:gosec // G304: operator-specified flag
	if err != nil {
		return fmt.Errorf("vex: read --attestor-vex-file %s: %w", resolved, err)
	}

	var doc openvex.VEX
	if err := json.Unmarshal(reportBytes, &doc); err != nil {
		return fmt.Errorf("vex: --attestor-vex-file %s is not a valid OpenVEX document: %w", resolved, err)
	}
	if err := openvex.Validate(&doc); err != nil {
		return fmt.Errorf("vex: --attestor-vex-file %s is not a usable OpenVEX document: %w", resolved, err)
	}

	digestSet, err := cryptoutil.CalculateDigestSetFromBytes(reportBytes, ctx.Hashes())
	if err != nil {
		return fmt.Errorf("vex: digest --attestor-vex-file %s: %w", resolved, err)
	}

	a.VEXDocument = doc
	// Same rule as the product scan: resolve for I/O, record something
	// stable. `cilock attest vex` hands this attestor an ABSOLUTE path
	// (it has to, so the path is not re-resolved against --workingdir a
	// second time), so recording `resolved` would stamp a machine- and
	// run-specific directory into signed evidence.
	a.ReportFile = stableReportName(ctx.WorkingDir(), resolved)
	a.ReportDigestSet = digestSet
	return nil
}

// stableReportName picks the name recorded in the signed predicate for an
// explicitly named document.
//
// ReportFile is signed, so it must not vary with where the build happened.
// A path INSIDE the working directory has exactly one machine-independent
// spelling — its working-dir-relative form, which is how the product scan
// names its candidates — so that is what gets recorded.
//
// A path OUTSIDE the working directory has no such spelling at all. The
// previous round recorded the ".."-climbing relative form here, but that
// string is a function of the checkout's depth and of every directory
// name between the file and the tree: `--vex-out /tmp/shared/vex.json`
// under /home/runner/work/x relativizes to
// "../../../tmp/shared/vex.json" and under /srv/ci/a/b/c to
// "../../../../../tmp/shared/vex.json" — different signed evidence for
// identical documents, still leaking the host layout it was supposed to
// hide. The only name an out-of-tree file has that is a property of the
// file rather than of this machine is its own basename, so that is what
// gets recorded — the same answer the unrelatable-path branch below
// always gave.
func stableReportName(workingDir, resolved string) string {
	base := workingDir
	if abs, err := filepath.Abs(base); err == nil {
		base = abs
	}
	absResolved := resolved
	if abs, err := filepath.Abs(resolved); err == nil {
		absResolved = abs
	}

	if rel, err := filepath.Rel(base, absResolved); err == nil &&
		rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		// Slash-canonical, always: filepath.Rel spells the separator the
		// OS's way, and a name recorded in signed evidence must not read
		// "out/vex.json" on one runner and `out\vex.json` on another for
		// the same tree.
		return filepath.ToSlash(rel)
	}

	// Out of tree, or (on Windows) on a different volume entirely: the
	// file's own name is the only machine-independent thing left to say.
	return filepath.Base(resolved)
}
