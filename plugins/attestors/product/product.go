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

// Package product implements the v0.3 product attestor.
//
// # Predicate shape
//
// A v0.3 product attestor publishes a single in-toto subject named
// `tree:products` whose digest is the SHA-256 Merkle root of the product set.
// The predicate JSON carries the root, the tree size, and the algorithm /
// construction identifiers so verifiers can refuse anything that claims
// another shape. Per-file data is NOT in the predicate — it lives in a
// sidecar file for the inclusion-proof attestor to consume later.
//
// # Leaf encoding (coordinate with the inclusion-proof attestor)
//
// Two-step hashing keeps the attestation/merkle wrapper API contract clean
// (every leaf is exactly HashSize bytes) while still cryptographically
// binding the file path to the file content:
//
//  1. Per file, compute the path-prefixed pre-hash
//     leafPreHash = sha256(path-bytes || 0x00 || file-digest-bytes-raw32)
//     The path is the UTF-8 file path (forward slashes, see
//     inclusionproof.NormalizePath); 0x00 is a single NUL delimiter; the
//     file digest is the raw 32-byte SHA-256 of the file content.
//
//  2. Pass leafPreHash (32 bytes) into merkle.NewTree([][]byte). The wrapper
//     applies its own 0x00 leaf domain prefix per RFC 6962 §2.1, so the
//     hash the Merkle tree actually commits to is
//     H(0x00 || sha256(path || 0x00 || file-digest)).
//
// This guarantees:
//   - Two files with identical content but different paths produce distinct
//     leaf hashes and distinct roots.
//   - The path is cryptographically bound at the leaf level.
//   - The merkle wrapper sees only HashSize leaves, preserving its
//     fixed-length-leaf invariant.
//
// # Determinism
//
// Leaves are sorted by their forward-slash-normalized path before tree
// construction. Two attestations recorded against the same logical product
// set always produce the same root regardless of host OS or filesystem walk
// order.
package product

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/file"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/aflock-ai/rookery/attestation/merkle"
	"github.com/aflock-ai/rookery/attestation/registry"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/gabriel-vasile/mimetype"
	"github.com/gobwas/glob"
	"github.com/invopop/jsonschema"
)

const (
	// Name is the canonical attestor name registered with the attestation
	// registry. The CLI flag `--attestations product` references this.
	Name = "product"

	// Type is the v0.3 predicate type URI. v0.3 is a HARD CUT for
	// production: the predicate shape is different (root + size + algo,
	// no per-file map) and v0.3 is the only producer registered under
	// the canonical "product" name. Historical v0.1 / v0.2 attestations
	// remain verify-only via the LegacyDecoder in legacy.go, registered
	// under the distinct names "product-v0.1" and "product-v0.2".
	Type = "https://aflock.ai/attestations/product/v0.3"

	// RunType places the attestor in the post-product phase, identical to
	// v0.1 / v0.2.
	RunType = attestation.ProductRunType

	// HashAlgorithm is the algorithm identifier published in the predicate
	// so verifiers can refuse anything that claims another algorithm. The
	// underlying merkle wrapper hardcodes SHA-256 as a defence against
	// hash-algorithm-confusion attacks.
	HashAlgorithm = "sha256"

	// Construction identifies the Merkle construction. Verifiers must
	// refuse anything that claims another construction.
	Construction = "RFC6962"

	// ProductName is kept as a re-export of Name for in-repo consumers
	// (link, slsa) that switch on the attestor's canonical name. New code
	// should use Name.
	ProductName = Name

	// TreeSubjectName is the single subject the attestor emits. It exists
	// as an exported constant so verifiers can build subject filters
	// without copying the literal string.
	TreeSubjectName = "tree:products"

	defaultIncludeGlob = "*"
	defaultExcludeGlob = ""
)

// ProductAttestor is the interface in-repo consumers (the link and slsa
// attestors) use to obtain the in-memory product map without depending on
// the concrete *Attestor type. Subjects() and Products() match the
// attestation library's Subjecter / Producer interfaces.
type ProductAttestor interface {
	Name() string
	Type() string
	RunType() attestation.RunType
	Attest(ctx *attestation.AttestationContext) error
	Subjects() map[string]cryptoutil.DigestSet
	Products() map[string]attestation.Product
}

// Compile-time interface checks.
var (
	_ attestation.Attestor   = (*Attestor)(nil)
	_ attestation.Subjecter  = (*Attestor)(nil)
	_ attestation.Producer   = (*Attestor)(nil)
	_ attestation.BackReffer = (*Attestor)(nil)
	_ ProductAttestor        = (*Attestor)(nil)
)

// Attestor implements the v0.3 product attestor.
//
// The exported predicate fields (MerkleRoot, TreeSize, HashAlgorithmField,
// ConstructionField) are what get marshalled into the in-toto Statement's
// predicate. The lowercase fields are run-time state used to build the
// tree, including the per-file leaf data that the sidecar writer consumes.
// leaves is intentionally not in the predicate — clients call BuildSidecar
// (which returns the canonical inclusionproof.Sidecar) to capture the
// full tree contents.
type Attestor struct {
	// Predicate fields. These are the bytes any verifier needs to refuse
	// or accept the attestation; nothing else from this struct ends up in
	// the signed DSSE statement.
	MerkleRoot         string `json:"merkleRoot"`
	TreeSize           uint64 `json:"treeSize"`
	HashAlgorithmField string `json:"hashAlgorithm"`
	ConstructionField  string `json:"construction"`

	// Internal state — NOT part of the predicate. The `json:"-"` tags
	// keep them out of MarshalJSON so the signed Statement never carries
	// per-file data. BuildSidecar reads `leaves` to construct the
	// canonical inclusion-proof sidecar alongside the signed envelope.
	products            map[string]attestation.Product `json:"-"`
	baseArtifacts       map[string]cryptoutil.DigestSet
	leaves              []ProductLeaf `json:"-"`
	rootBytes           []byte        `json:"-"`
	includeGlob         string
	compiledIncludeGlob glob.Glob
	excludeGlob         string
	compiledExcludeGlob glob.Glob

	// includeGlobUserSet tracks whether the include-glob came from
	// explicit user intent (cobra Changed()) or from the default. Only
	// user-intent include-globs participate in the precedence table
	// in Attest — i.e., can rescue a path that default cache patterns
	// would otherwise classify as cache. Without this signal the
	// default include="*" would always match and would "rescue"
	// everything from cache, defeating the cache classifier entirely.
	includeGlobUserSet bool

	// droppedByClassification counts paths the trace probe returned
	// but the precedence table classified as CACHE or DROP. Populated
	// in Attest's trace path so the CLI can emit a helpful "products
	// set is empty but trace observed N writes" warning before
	// signing.
	droppedByClassification int

	// requireExistsAtExit (default true) is the "product = surviving
	// deliverable" gate. When true, files the tracee wrote but that
	// no longer exist when the attestor runs are NOT recorded as
	// products. When false, they're emitted as witness-only entries
	// (path with nil digest) for forensic completeness — useful when
	// investigating builds that produce-then-clean scratch artifacts
	// you want named in the signed record. Set via
	// WithRequireExistsAtExit(false) or `--product-allow-removed`.
	requireExistsAtExit bool
}

// ProductLeaf describes one entry of the input tree. The Merkle leaf
// digest the tree commits to is H(0x00 || LeafHash) — the merkle wrapper
// applies the 0x00 RFC 6962 leaf prefix to the value passed into NewTree.
// LeafHash itself is the pre-hash H(path || 0x00 || file-digest).
type ProductLeaf struct {
	Path       string `json:"path"`
	FileDigest string `json:"fileDigest"`
	LeafHash   string `json:"leafHash"`
	// Kind hints what KIND of file this product is, by filename suffix.
	// Empty when the file's kind isn't one of the well-known
	// attestation/SBOM formats. omitempty so v0.3 attestations from
	// before this field landed continue to round-trip byte-identically.
	//
	// Used by sandbox-boundary linking (V2 plan Phase 10): when a
	// build emits its own inner attestation (Bazel SLSA provenance,
	// BuildKit provenance, etc.), the OUTER trace catches the file
	// in its products set. Tagging the kind here lets verifiers
	// pick up the inner attestation by `kind` without re-parsing
	// every product file.
	//
	// Recognized kinds (extend as needed; keep the set small to avoid
	// scope creep — only formats that actually chain into the
	// attestation graph belong here):
	//   - "intoto"          — in-toto Statement envelope (.intoto.json/.jsonl)
	//   - "intoto-dsse"     — DSSE-wrapped in-toto (.dsse, .intoto.dsse)
	//   - "slsa-provenance" — SLSA provenance (.slsa-provenance.json)
	//   - "spdx"            — SPDX SBOM (.spdx.json, .spdx.yaml)
	//   - "cyclonedx"       — CycloneDX SBOM (.cdx.json, .cdx.xml, bom.json)
	//   - "sarif"           — Static Analysis Results Interchange Format
	//                          (.sarif, .sarif.json)
	//   - "vex"             — OpenVEX / CSAF VEX (.vex.json, .csaf.json)
	Kind string `json:"kind,omitempty"`
}

// detectProductKind inspects a filename for well-known attestation /
// SBOM / scan-result format suffixes. Returns "" when the suffix
// doesn't match a recognized kind. Pure function; no I/O.
//
// Conservative on purpose: filename-suffix only. We don't open files
// to magic-byte sniff because (a) the product attestor runs at the
// end of a build, files may be huge, (b) any reader-side validation
// of the kind hint can re-verify by parsing. The hint is advisory.
func detectProductKind(path string) string {
	// Lower-case match. Most attestation tooling emits lowercase
	// suffixes anyway, but normalize defensively.
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".slsa-provenance.json"):
		return "slsa-provenance"
	case strings.HasSuffix(lower, ".intoto.jsonl"),
		strings.HasSuffix(lower, ".intoto.json"):
		return "intoto"
	case strings.HasSuffix(lower, ".intoto.dsse"),
		strings.HasSuffix(lower, ".dsse"):
		return "intoto-dsse"
	case strings.HasSuffix(lower, ".spdx.json"),
		strings.HasSuffix(lower, ".spdx.yaml"),
		strings.HasSuffix(lower, ".spdx.yml"):
		return "spdx"
	case strings.HasSuffix(lower, ".cdx.json"),
		strings.HasSuffix(lower, ".cdx.xml"),
		strings.HasSuffix(lower, "/bom.json"),
		lower == "bom.json":
		return "cyclonedx"
	case strings.HasSuffix(lower, ".sarif.json"),
		strings.HasSuffix(lower, ".sarif"):
		return "sarif"
	case strings.HasSuffix(lower, ".vex.json"),
		strings.HasSuffix(lower, ".csaf.json"):
		return "vex"
	}
	return ""
}

// Option configures a new Attestor.
type Option func(*Attestor)

// WithIncludeGlob restricts the recorded product set to paths matching the
// glob (default "*" — all files).
func WithIncludeGlob(g string) Option {
	return func(a *Attestor) { a.includeGlob = g }
}

// WithIncludeGlobUserIntent marks the include-glob as having come from
// explicit operator intent (e.g., a non-default cobra flag value). The
// CLI calls this when cmd.Flags().Changed("attestor-product-include-glob")
// is true. The precedence table in Attest treats a user-intent include
// glob as the highest-priority signal — a path matching it is recorded
// as a product even if a default cache pattern would otherwise drop it.
func WithIncludeGlobUserIntent(userSet bool) Option {
	return func(a *Attestor) { a.includeGlobUserSet = userSet }
}

// WithExcludeGlob removes paths matching the glob from the recorded
// product set (default empty — exclude nothing).
func WithExcludeGlob(g string) Option {
	return func(a *Attestor) { a.excludeGlob = g }
}

// WithRequireExistsAtExit toggles the "product must still exist when
// the attestor runs" gate. Default is true (the strict, intent-matching
// behavior). Set to false to keep witness-only entries (path with nil
// digest) for files the tracee wrote then cleaned up — useful for
// forensic builds where you want every transient artifact named.
func WithRequireExistsAtExit(require bool) Option {
	return func(a *Attestor) { a.requireExistsAtExit = require }
}

// New constructs an Attestor with default globs (include="*", exclude="").
func New(opts ...Option) *Attestor {
	a := &Attestor{
		includeGlob:         defaultIncludeGlob,
		excludeGlob:         defaultExcludeGlob,
		requireExistsAtExit: true, // strict by default; explicit opt-out
		HashAlgorithmField:  HashAlgorithm,
		ConstructionField:   Construction,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func configOptions() []registry.Configurer {
	return []registry.Configurer{
		registry.StringConfigOption(
			"include-glob",
			"Pattern to use when recording products. Files that match this pattern will be included as subjects on the attestation.",
			defaultIncludeGlob,
			func(a attestation.Attestor, includeGlob string) (attestation.Attestor, error) {
				prod, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product attestor", a)
				}
				WithIncludeGlob(includeGlob)(prod)
				return prod, nil
			},
		),
		registry.StringConfigOption(
			"exclude-glob",
			"Pattern to use when recording products. Files that match this pattern will be excluded as subjects on the attestation.",
			defaultExcludeGlob,
			func(a attestation.Attestor, excludeGlob string) (attestation.Attestor, error) {
				prod, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product attestor", a)
				}
				WithExcludeGlob(excludeGlob)(prod)
				return prod, nil
			},
		),
		registry.BoolConfigOption(
			"require-exists-at-exit",
			"When true (default), a file the build wrote must still exist at attestation time to be recorded as a product. Files the build wrote then removed are treated as scratch and dropped. Set false to keep witness-only entries (path with nil digest) for forensic completeness.",
			true,
			func(a attestation.Attestor, v bool) (attestation.Attestor, error) {
				prod, ok := a.(*Attestor)
				if !ok {
					return a, fmt.Errorf("unexpected attestor type: %T is not a product attestor", a)
				}
				WithRequireExistsAtExit(v)(prod)
				return prod, nil
			},
		),
	}
}

func init() {
	// v0.3 is the only producer. v0.1 and v0.2 historical attestations
	// remain *verifiable* via the LegacyDecoder registered in legacy.go
	// — that file uses distinct registry names (product-v0.1, product-v0.2)
	// so `cilock run --attestations product` always picks the v0.3
	// producer below, never a legacy decoder.
	attestation.RegisterAttestation(
		Name,
		Type,
		RunType,
		func() attestation.Attestor { return New() },
		configOptions()...,
	)
}

// Name returns the attestor's registered name.
func (a *Attestor) Name() string { return Name }

// Type returns the v0.3 predicate type URI.
func (a *Attestor) Type() string { return Type }

// RunType places the attestor in the post-product phase.
func (a *Attestor) RunType() attestation.RunType { return RunType }

// Schema is the JSON schema for the predicate as it ships in the DSSE
// Statement. It reflects the struct fields with json tags, which excludes
// the run-time leaves slice. MarshalJSON honours the same exclusion.
func (a *Attestor) Schema() *jsonschema.Schema {
	return jsonschema.Reflect(&Attestor{})
}

// collectTracedFileSet inspects completed attestors for any traced
// CommandRun and returns (a) whether tracing was active, and (b) the
// set of paths whose contents should survive the --trace filter in
// shouldRecord. open()'d files are obvious; rename destinations and
// direct-write targets are required because atomic-rename builds (e.g.
// `go build`) never open() the final artifact directly. (closes #152)
func collectTracedFileSet(ctx *attestation.AttestationContext) (bool, map[string]bool) {
	traced := false
	set := map[string]bool{}
	for _, completed := range ctx.CompletedAttestors() {
		cmd, ok := completed.Attestor.(*commandrun.CommandRun)
		if !ok || !cmd.TracingEnabled() {
			continue
		}
		// Tracing was REQUESTED (config flag set) — but check that it
		// actually produced data. On macOS / Windows / any platform
		// where tracing_unsupported.go is built, trace() returns an
		// error and cmd.Processes stays empty. Returning traced=true
		// here with an empty openedFiles set would tell walk-mode
		// "trust the trace" — which combined with the empty set
		// causes shouldRecord() in file.RecordArtifacts to reject
		// EVERY product (file.go:237 — "not in openedFiles AND
		// processWasTraced → drop"). Result: silent product loss,
		// no sbom / no go-build / no envelope despite the build
		// having succeeded.
		//
		// If tracing failed to produce processes, fall back to an
		// unfiltered walk so downstream attestors see the actual
		// build outputs.
		if len(cmd.Processes) == 0 {
			continue
		}
		traced = true
		for _, process := range cmd.Processes {
			for fname := range process.OpenedFiles {
				set[fname] = true
			}
			if process.FileOps == nil {
				continue
			}
			for _, r := range process.FileOps.Renames {
				set[r.NewPath] = true
			}
			for _, w := range process.FileOps.Writes {
				set[w.Path] = true
			}
		}
	}
	return traced, set
}

// Attest walks the product set, computes the per-file pre-hashes, sorts
// them deterministically, and builds the Merkle tree. The signed
// predicate's MerkleRoot is the resulting tree root in hex.
//
//nolint:gocyclo,gocognit,funlen // glob compile → mode resolve → trace integrate → walk fallback; refactoring obscures the mode-dispatch logic
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

	// Resolve capture mode at attestor-run time. CaptureAuto picks the
	// fastest available source (trace if a CaptureProbe was registered;
	// otherwise walk). Non-auto modes fail loudly when their source
	// isn't available — see ResolveCaptureMode for the contract.
	resolved, probe, err := attestation.ResolveCaptureMode(
		ctx.CaptureMode(), ctx.CompletedAttestors(), ctx.RegisteredAttestors())
	if err != nil {
		return fmt.Errorf("product attestor: %w", err)
	}

	if resolved == attestation.CaptureTrace && probe != nil { //nolint:nestif // trace-integration block has inherent nesting over probe outputs
		// Build cache-pattern matchers used by the precedence table
		// below. Two matchers, two roles:
		//
		//   cacheMatcher: defaults + env-derived + user-added.
		//     A path matching here is CACHE unless a higher-priority
		//     rule (user include-glob, --cache-allow-pattern) rescues
		//     it. Drives classifyCache.
		//
		//   cacheAllowMatcher: a separate per-PATH glob set from
		//     CachePatternOptions.Allow. This is intentionally per-path
		//     (not the existing pattern-string-removal in
		//     ResolveCachePatterns) so operators can write
		//     --cache-allow-pattern='/tmp/build/**' and have that
		//     path-glob exempt their build output from the default
		//     /tmp/** cache pattern, without having to know the exact
		//     default pattern string.
		//
		// Cache classification runs HERE, in the product attestor,
		// rather than inside commandrun.TraceOutputs(). That move is
		// the substance of Bug 1 from the blind Linux UX test
		// (rookery#TBD): the user's --attestor-product-include-glob
		// flag must be able to rescue a path the cache pattern would
		// otherwise drop. Doing classification in commandrun (where
		// product globs are out of reach) deprived the user of any
		// way to override.
		cachePatternOpts := ctx.CachePatterns()
		patterns := attestation.ResolveCachePatterns(cachePatternOpts)
		cacheMatcher, perrs := attestation.NewCachePathMatcher(patterns)
		for _, perr := range perrs {
			// Soft failure: a bad pattern doesn't block attestation,
			// just gets logged. Operator sees it and fixes.
			log.Debugf("cache pattern compile error: %v", perr)
		}
		cacheAllowMatcher, aerrs := attestation.NewCachePathMatcher(cachePatternOpts.Allow)
		for _, aerr := range aerrs {
			log.Debugf("cache-allow pattern compile error: %v", aerr)
		}
		// Keep the cache matcher installed on the probe so
		// TraceCacheArtifacts() / TraceIntermediates() see the same
		// cache definition the product attestor uses. Their bucket
		// (cache-only inventory) still uses the pattern matcher
		// directly.
		if installer, ok := probe.(interface {
			SetCacheMatcher(*attestation.CachePathMatcher)
		}); ok {
			installer.SetCacheMatcher(cacheMatcher)
		}

		// Trace mode: consume the digests the read-tap / path-hash
		// already computed during the trace. Skip the workdir walk
		// entirely — the trace knows exactly what files the tracee
		// wrote, and path-hashing happened post-tracee-exit when the
		// files are stable. No re-read on the hot path.
		raw := probe.TraceOutputs()
		filtered := make(map[string]attestation.CaptureEntry, len(raw))
		dropped := 0
		// Resolve relative trace paths against workingDir. ctx.WorkingDir()
		// may be empty when the caller didn't pass one explicitly (common
		// from cilock-action with no `workingdir:` input); fall back to
		// the process cwd, which is what the tracee inherited.
		workdir := ctx.WorkingDir()
		if workdir == "" {
			if cwd, err := os.Getwd(); err == nil {
				workdir = cwd
			}
		}
		for path, entry := range raw {
			// Trace records mix absolute and relative paths. atomic-
			// rename builds (Go, Cargo, GCC -o) write to a temp
			// absolute path then RENAME(2) to the final target —
			// the rename target is recorded relative to the tracee's
			// cwd. Resolve relative trace paths against workdir so
			// the include-glob (always absolute when set from
			// cilock-action) matches the right surface.
			resolved := path
			if workdir != "" && !filepath.IsAbs(resolved) {
				resolved = filepath.Join(workdir, resolved)
			}

			decision := classifyTracePath(
				resolved,
				a.compiledIncludeGlob, a.includeGlobUserSet,
				a.compiledExcludeGlob,
				cacheAllowMatcher,
				cacheMatcher,
			)
			switch decision {
			case classifyProduct:
				// Use resolved as the map key so downstream (mime
				// detect, digest hash, exists-at-exit stat) sees the
				// real path.
				filtered[resolved] = entry
			case classifyCache, classifyDrop:
				dropped++
			}
		}
		a.products = fromCaptureEntries(filtered, a.requireExistsAtExit)
		a.droppedByClassification = dropped
		return a.buildTree()
	}

	// Walk mode (legacy default). Walk the workdir, optionally
	// filtered to files the tracee touched (collectTracedFileSet),
	// hash each. This is the v0.1 behavior preserved bit-for-bit.
	processWasTraced, openedFileSet := collectTracedFileSet(ctx)

	digestMap, err := file.RecordArtifacts(
		ctx.WorkingDir(),
		a.baseArtifacts,
		ctx.Hashes(),
		map[string]struct{}{},
		processWasTraced,
		openedFileSet,
		ctx.DirHashGlob(),
		a.compiledIncludeGlob,
		a.compiledExcludeGlob,
	)
	if err != nil {
		return err
	}

	a.products = fromDigestMap(ctx.WorkingDir(), digestMap)
	return a.buildTree()
}

// fromCaptureEntries converts the trace probe's per-path digest map
// into the attestation.Product type. A "product" must satisfy:
//   - written by the tracee (the probe wouldn't include it otherwise)
//   - matches the include-glob (caller already filtered)
//   - **exists at the moment we attest** (this function's check)
//   - has a content hash
//
// The exists-at-exit rule turns "product = anything the build wrote"
// (which on a Go build was 9000+ scratch files) into "product = the
// surviving deliverables". Files the build wrote then cleaned up are
// no longer products — they're routed to ScratchWrites in the trace
// summary so a verifier can still see "the build created N temp
// files and removed them" as forensic evidence.
//
// Mime-type detection is best-effort.
func fromCaptureEntries(entries map[string]attestation.CaptureEntry, requireExistsAtExit bool) map[string]attestation.Product {
	out := make(map[string]attestation.Product, len(entries))
	for path, entry := range entries {
		// Exists-at-exit gate. Default-on; callers can opt out via
		// WithRequireExistsAtExit(false) when they want forensic
		// completeness over deliverable-only semantics.
		fi, statErr := os.Stat(path)
		if statErr != nil {
			if requireExistsAtExit {
				continue
			}
			// Path is gone — emit witness-only entry (nil digest,
			// unknown mime).
			out[path] = attestation.Product{MimeType: "unknown", Digest: nil}
			continue
		}

		mimeType := "unknown"
		if mt, mtErr := getFileContentType(path); mtErr == nil {
			mimeType = mt
		}
		if mimeType == "application/octet-stream" && fi.IsDir() {
			mimeType = "text/directory"
		}

		// Path exists but we couldn't hash it (trace race, transient
		// permission). Keep as witness-only product entry — the
		// existence-at-exit invariant tells us this IS a real
		// deliverable, just one whose content we couldn't capture.
		if entry.Digest == nil {
			out[path] = attestation.Product{
				MimeType: mimeType,
				Digest:   nil,
			}
			continue
		}

		ds, err := cryptoutil.NewDigestSet(entry.Digest)
		if err != nil {
			// Same fallback path — bad digest data on the trace
			// side; record the path without a digest rather than
			// dropping it silently.
			out[path] = attestation.Product{
				MimeType: mimeType,
				Digest:   nil,
			}
			continue
		}
		out[path] = attestation.Product{
			MimeType: mimeType,
			Digest:   ds,
		}
	}
	return out
}

// buildTree filters the product set through the include / exclude globs,
// sorts the survivors by normalized path, computes per-file leaf
// pre-hashes, and constructs the Merkle tree.
func (a *Attestor) buildTree() error {
	pairs := a.includedProductPairs()

	leaves := make([]ProductLeaf, 0, len(pairs))
	preHashes := make([][]byte, 0, len(pairs))

	for _, p := range pairs {
		prod, ok := a.products[p.originalKey]
		if !ok {
			continue
		}
		// Trace mode now emits witness-only entries with nil Digest
		// when a write was observed but the file couldn't be hashed
		// (gone before attest, fast-exit race, etc.). Those entries
		// stay in the product map for inventory but DON'T enter the
		// Merkle tree — a tree leaf needs a content digest. Skip
		// silently here; downstream consumers (link, slsa) still see
		// the path via Products().
		if prod.Digest == nil {
			continue
		}
		digestHex, ok := prod.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}]
		if !ok {
			// A product without a SHA-256 digest is a contract
			// violation by file.RecordArtifacts. Refuse to build a
			// tree that silently omits files.
			return fmt.Errorf("product %q has no sha256 digest; v0.3 requires sha256", p.normalized)
		}
		// LeafHash is the single canonical leaf encoder for v0.3 product
		// and material attestors. Defined once in plugins/attestors/inclusion-proof
		// so the producer (product/material) and the verifier (inclusion-proof)
		// can never drift apart byte-for-byte.
		leafPreHash, err := inclusionproof.LeafHash(p.normalized, digestHex)
		if err != nil {
			return fmt.Errorf("product %q: %w", p.normalized, err)
		}
		leaves = append(leaves, ProductLeaf{
			Path:       p.normalized,
			FileDigest: digestHex,
			LeafHash:   hex.EncodeToString(leafPreHash),
			Kind:       detectProductKind(p.normalized),
		})
		preHashes = append(preHashes, leafPreHash)
	}

	tree, err := merkle.NewTree(preHashes)
	if err != nil {
		return fmt.Errorf("building merkle tree: %w", err)
	}

	root := tree.Root()
	a.leaves = leaves
	a.rootBytes = root
	a.MerkleRoot = hex.EncodeToString(root)
	a.TreeSize = tree.Size()
	a.HashAlgorithmField = HashAlgorithm
	a.ConstructionField = Construction
	return nil
}

// Products returns the per-file product map for in-process consumers
// (link, slsa). It is NOT part of the predicate.
func (a *Attestor) Products() map[string]attestation.Product { return a.products }

// DroppedByClassification returns the number of paths the trace probe
// surfaced that the precedence table classified as CACHE or filtered
// out by user globs. The CLI uses this signal to emit a helpful
// "products set is empty but the trace observed N writes" warning so
// operators don't ship a signed-but-empty envelope without realising
// their build output went to a default cache location.
func (a *Attestor) DroppedByClassification() int { return a.droppedByClassification }

// Subjects returns the single tree:products subject. If the product set
// is empty the subject is still emitted, with the digest set to the
// RFC 6962 empty-tree root (sha256("")), so verifiers can refuse a
// missing root rather than treating empty as absent. Per the v0.3 spec
// the predicate ALWAYS carries a root.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{
		TreeSubjectName: a.rootDigestSet(),
	}
}

// BackRefs mirrors Subjects per the v0.3 spec: the tree:products subject
// is the only chainable subject the attestor produces. (Issue #126
// intentionally narrowed BackRefs to the tree subject only.)
func (a *Attestor) BackRefs() map[string]cryptoutil.DigestSet {
	return map[string]cryptoutil.DigestSet{
		TreeSubjectName: a.rootDigestSet(),
	}
}

func (a *Attestor) rootDigestSet() cryptoutil.DigestSet {
	return cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: crypto.SHA256}: a.MerkleRoot,
	}
}

// MarshalJSON publishes only the predicate fields. The leaves slice is
// kept out of the signed Statement; sidecar consumers use BuildSidecar.
func (a *Attestor) MarshalJSON() ([]byte, error) {
	type predicate struct {
		MerkleRoot    string `json:"merkleRoot"`
		TreeSize      uint64 `json:"treeSize"`
		HashAlgorithm string `json:"hashAlgorithm"`
		Construction  string `json:"construction"`
	}
	return json.Marshal(predicate{
		MerkleRoot:    a.MerkleRoot,
		TreeSize:      a.TreeSize,
		HashAlgorithm: a.HashAlgorithmField,
		Construction:  a.ConstructionField,
	})
}

// UnmarshalJSON restores the predicate fields from JSON. The leaves and
// products maps are NOT in the predicate; verifiers must obtain those
// from the sidecar (if it was retained) or recompute them from the build
// outputs.
func (a *Attestor) UnmarshalJSON(data []byte) error {
	type predicate struct {
		MerkleRoot    string `json:"merkleRoot"`
		TreeSize      uint64 `json:"treeSize"`
		HashAlgorithm string `json:"hashAlgorithm"`
		Construction  string `json:"construction"`
	}
	var p predicate
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	a.MerkleRoot = p.MerkleRoot
	a.TreeSize = p.TreeSize
	a.HashAlgorithmField = p.HashAlgorithm
	a.ConstructionField = p.Construction
	return nil
}

// BuildSidecar returns the canonical inclusion-proof sidecar for this
// attestor's leaf set. The sidecar is the SAME shape `cilock run` writes
// adjacent to the signed attestation (rookery.inclusion-proof.sidecar/v0.1)
// and the SAME shape `cilock prove` consumes — no parallel format exists.
// Library consumers holding an *Attestor directly use this when they need
// the sidecar bytes without going through the CLI.
//
// The sidecar is NOT signed and NOT part of the attestation envelope —
// integrity comes from the fact that the reconstructed Merkle root must
// match the root in the signed predicate.
func (a *Attestor) BuildSidecar() (inclusionproof.Sidecar, error) {
	digests := make(map[string]string, len(a.leaves))
	for _, l := range a.leaves {
		digests[l.Path] = l.FileDigest
	}
	return inclusionproof.BuildSidecar("product", digests)
}

// Leaves returns the raw (unprefixed) per-file leaf records used to build
// the tree. Used by tests and by the inclusion-proof attestor when it
// constructs proofs in-process.
func (a *Attestor) Leaves() []ProductLeaf {
	out := make([]ProductLeaf, len(a.leaves))
	copy(out, a.leaves)
	return out
}

// RootBytes returns the raw 32-byte Merkle root. Used by the
// inclusion-proof attestor to verify proofs against the same in-memory
// tree.
func (a *Attestor) RootBytes() []byte {
	out := make([]byte, len(a.rootBytes))
	copy(out, a.rootBytes)
	return out
}

// =====================================================================
// Trace-mode classification
// =====================================================================

// classification is the per-path outcome of the precedence table in
// classifyTracePath. Exported via a small helper rather than booleans
// so callers can clearly distinguish "this is a product" from "this is
// a cache artifact" from "the user explicitly excluded it" without
// magic-string-matching log lines.
type classification int

const (
	classifyProduct classification = iota
	classifyCache
	classifyDrop
)

// classifyTracePath applies the v0.3 product precedence rules from
// the design doc (most-specific wins, top to bottom):
//
//  1. User --attestor-product-include-glob (when non-default) matches
//     → PRODUCT (regardless of cache patterns). This is the rescue
//     path: the operator typed an include glob, that intent dominates
//     default classification.
//  2. User --attestor-product-exclude-glob matches → DROP (never a
//     product, even if include-glob also matched).
//  3. User --cache-allow-pattern matches path → PRODUCT. cache-allow
//     is a per-path exemption from the cache classifier; useful for
//     reclaiming specific cache locations as products without
//     knowing the exact default pattern string.
//  4. cache pattern (defaults + env-derived + user-added) matches
//     → CACHE. This is where /tmp/**, GOCACHE, ~/.cache, etc. live.
//  5. Otherwise → PRODUCT.
//
// includeGlobUserSet captures whether the include-glob came from the
// operator or the default. When false (default "*"), the include-glob
// is NOT treated as user intent: it still acts as a filter at step 5
// (when nothing else fired), but it does NOT override cache
// classification. This preserves the existing behavior for operators
// who never touched the flag.
//
// Returns classifyProduct / classifyCache / classifyDrop. The caller
// (Attest's trace path) decides which bucket to put the path in.
//
//nolint:gocognit,nestif // five-step precedence with a small nested check for exclude-inside-include; flattening hides the precedence intent
func classifyTracePath(
	path string,
	includeGlob glob.Glob, includeGlobUserSet bool,
	excludeGlob glob.Glob,
	cacheAllow *attestation.CachePathMatcher,
	cache *attestation.CachePathMatcher,
) classification {
	// 1. User include-glob (non-default) takes precedence over
	//    cache classification. Without this rule the default cache
	//    pattern (/tmp/**) silently drops Argo CD's
	//    `go build -o /tmp/out/argocd ./cmd` output even though the
	//    operator passed --attestor-product-include-glob '/tmp/**'.
	if includeGlobUserSet && includeGlob != nil {
		if matched, _ := safeGlobMatch(includeGlob, path); matched {
			// Step 2 still applies — even with user-set include,
			// an explicit exclude wins.
			if excludeGlob != nil {
				if exMatched, _ := safeGlobMatch(excludeGlob, path); exMatched {
					return classifyDrop
				}
			}
			return classifyProduct
		}
		// User set an include glob and this path did not match.
		// Fall through to the rest of the table — the path may still
		// be a default-classifiable cache item that should land in
		// the cache bucket rather than being silently dropped here.
		// (Step 5's default include-glob check below catches the
		// "exclude things outside the user's intent" case.)
	}

	// 2. User exclude-glob always wins for paths it matches.
	if excludeGlob != nil {
		if matched, _ := safeGlobMatch(excludeGlob, path); matched {
			return classifyDrop
		}
	}

	// 3. Cache-allow rescues from cache classification.
	if cacheAllow != nil && cacheAllow.Matches(path) {
		return classifyProduct
	}

	// 4. Default + user-added cache patterns.
	if cache != nil && cache.Matches(path) {
		return classifyCache
	}

	// 5. Otherwise: PRODUCT — but still honour the include glob as a
	// FILTER (not a rescue). When the include glob is the default
	// "*" everything matches, so this is a no-op for unset flags.
	// When the operator passed a narrower include glob, paths that
	// don't match it AND aren't cache get DROPPED here.
	if includeGlob != nil {
		if matched, _ := safeGlobMatch(includeGlob, path); !matched {
			return classifyDrop
		}
	}
	return classifyProduct
}

// =====================================================================
// Internal helpers
// =====================================================================

// safeGlobMatch wraps glob.Match with panic recovery. The gobwas/glob
// library can panic on certain patterns that compile successfully but
// trigger out-of-bounds access during matching. We treat panics as
// non-matches.
func safeGlobMatch(g glob.Glob, s string) (matched bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			matched = false
			err = fmt.Errorf("glob match panicked: %v", r)
		}
	}()
	return g.Match(s), nil
}

type productPair struct {
	normalized  string
	originalKey string
}

func (a *Attestor) includedProductPairs() []productPair {
	pairs := make([]productPair, 0, len(a.products))
	for name := range a.products {
		normalized := inclusionproof.NormalizePath(name)
		if a.compiledExcludeGlob != nil {
			if matched, err := safeGlobMatch(a.compiledExcludeGlob, normalized); err != nil {
				log.Debugf("exclude glob match error for path %q: %v", normalized, err)
			} else if matched {
				continue
			}
		}
		if a.compiledIncludeGlob != nil {
			if matched, err := safeGlobMatch(a.compiledIncludeGlob, normalized); err != nil {
				log.Debugf("include glob match error for path %q: %v", normalized, err)
			} else if !matched {
				continue
			}
		}
		pairs = append(pairs, productPair{normalized: normalized, originalKey: name})
	}

	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].normalized < pairs[j].normalized
	})
	return pairs
}

func fromDigestMap(workingDir string, digestMap map[string]cryptoutil.DigestSet) map[string]attestation.Product {
	products := make(map[string]attestation.Product, len(digestMap))
	for name, digestSet := range digestMap {
		full := filepath.Join(workingDir, name)
		mimeType, err := getFileContentType(full)
		if err != nil {
			mimeType = "unknown"
		}
		if mimeType == "application/octet-stream" {
			if info, err := os.Stat(full); err == nil && info.IsDir() {
				mimeType = "text/directory"
			}
		}
		products[name] = attestation.Product{
			MimeType: mimeType,
			Digest:   digestSet,
		}
	}
	return products
}

func getFileContentType(fileName string) (string, error) {
	contentType, err := mimetype.DetectFile(fileName)
	if err != nil {
		return "", err
	}
	return contentType.String(), nil
}

// IsSPDXJson returns true if the leading bytes of a JSON document look
// like SPDX. Re-exported because the sbom attestor uses it for MIME
// detection.
func IsSPDXJson(buf []byte) bool {
	maxLen := len(buf)
	if maxLen > 500 {
		maxLen = 500
	}
	header := buf[:maxLen]
	return bytes.Contains(header, []byte(`"spdxVersion":"SPDX-`)) ||
		bytes.Contains(header, []byte(`"spdxVersion": "SPDX-`))
}

// IsCycloneDXJson returns true if the leading bytes of a JSON document
// look like CycloneDX. Re-exported because the sbom attestor uses it for
// MIME detection.
func IsCycloneDXJson(buf []byte) bool {
	maxLen := len(buf)
	if maxLen > 500 {
		maxLen = 500
	}
	header := buf[:maxLen]
	return bytes.Contains(header, []byte(`"bomFormat":"CycloneDX"`)) ||
		bytes.Contains(header, []byte(`"bomFormat": "CycloneDX"`))
}

func init() {
	// Custom MIME-type detectors registered once at process start.
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
