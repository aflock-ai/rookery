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

// Package gobuild implements an attestor for Go-compiled binaries.
//
// Goal: capture the build provenance Go embeds in every binary
// (runtime/debug.BuildInfo) at attestation time, while the build
// environment is still close at hand — and persist it to a sidecar
// JSON file on disk so the evidence survives `strip(1)` or any other
// post-build operation that nukes the .go.buildinfo section of the
// binary.
//
// Why a sidecar?
//
// The standard story for Go provenance is "just call
// runtime/debug.ReadBuildInfo() from inside the binary." That works
// until release engineering strips the binary to shave a few hundred
// kilobytes — once `strip` walks an ELF/Mach-O/PE, the buildinfo
// section is gone forever and there is no way to recover the module
// graph, vcs.revision, build settings, or any of the other rich
// data the toolchain originally put there.
//
// The cilock workflow has a unique window: it observes products
// immediately after the build completes (PostProductRunType), before
// any release-stage packaging step gets a chance to mutate them. At
// that point the binary is guaranteed to still carry its BuildInfo.
// We extract it via debug/buildinfo.ReadFile (which works on any
// path, unlike runtime/debug.ReadBuildInfo which is process-local)
// and serialize it next to the binary. The sidecar JSON then gets
// hashed by the product attestor on a subsequent run, or carried
// through whatever release pipeline ships the artifacts.
//
// Subjects:
//   - One subject per Go binary keyed `binary:<path>` with the digest
//     of the binary file content. This is the natural "verify the
//     released artifact" subject: users will point `cilock verify
//     --artifactfile` at the binary and this is what matches.
//   - One subject per Go binary keyed `go-build-sidecar:<path>` with
//     the digest of the JSON sidecar. This lets a verifier re-read
//     the JSON from disk and confirm it matches what was signed.
package gobuild

import (
	"debug/buildinfo"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/log"
	"github.com/invopop/jsonschema"
)

//go:embed detector.yaml
var detectorYAML []byte

const (
	Name    = "go-build"
	Type    = "https://aflock.ai/attestations/go-build/v0.1"
	RunType = attestation.PostProductRunType

	// SidecarExt is the suffix appended to a binary path to derive
	// its provenance sidecar path. We deliberately use a multi-dot
	// extension so the sidecar is distinguishable at a glance and
	// has effectively zero collision probability with anything a
	// build pipeline might produce on its own.
	SidecarExt = ".gobuild.json"
)

var (
	_ attestation.Attestor  = (*Attestor)(nil)
	_ attestation.Subjecter = (*Attestor)(nil)
)

func init() {
	attestation.RegisterAttestation(Name, Type, RunType, func() attestation.Attestor {
		return New()
	})
	detection.Register(Name, detectorYAML)
}

// Attestor captures BuildInfo for every Go binary in the product set
// and writes one JSON sidecar per binary.
type Attestor struct {
	// Binaries is the per-binary provenance record. Order is stable
	// (sorted by Path) so the predicate is byte-stable across runs
	// for the same product set.
	Binaries []BinaryInfo `json:"binaries"`

	// SkippedNonGo lists product paths that were considered but
	// rejected because debug/buildinfo couldn't read them. Useful
	// for debugging "why didn't my binary get a sidecar?" without
	// having to crank the log level.
	SkippedNonGo []string `json:"skipped_non_go,omitempty"`

	subjects map[string]cryptoutil.DigestSet
}

// BinaryInfo is the per-binary record stamped into the predicate and
// also serialized to the sidecar JSON. Fields mirror
// runtime/debug.BuildInfo with one addition: SidecarPath, which is
// the path the sidecar was actually written to (relative to the
// attestation context's working directory).
type BinaryInfo struct {
	// Path is the binary's path relative to the attestation context's
	// working directory. Same key the product attestor uses.
	Path string `json:"path"`

	// SidecarPath is the JSON sidecar's path, also relative to the
	// working directory. Empty if writing the sidecar failed (we
	// still record the binary's BuildInfo in the predicate either way
	// — failing to write the sidecar shouldn't lose all the data).
	SidecarPath string `json:"sidecar_path,omitempty"`

	// GoVersion is the toolchain that produced the binary, e.g.
	// "go1.26.3".
	GoVersion string `json:"go_version"`

	// MainPath is the package path of the binary's main package.
	MainPath string `json:"main_path"`

	// Main is the main module's identity (path + version + sum +
	// optional replace). Nil for binaries built outside a module
	// (rare in modern Go but possible with GO111MODULE=off).
	Main *Module `json:"main_module,omitempty"`

	// Deps is the full dependency graph as Go's toolchain recorded
	// it. Each entry mirrors debug.Module 1:1.
	Deps []Module `json:"deps,omitempty"`

	// Settings is BuildInfo.Settings flattened into a map. Common
	// keys include: -buildmode, -compiler, -trimpath, -ldflags,
	// CGO_ENABLED, GOOS, GOARCH, GOAMD64, vcs, vcs.revision,
	// vcs.time, vcs.modified. Anything Go's BuildInfo carries today
	// — and anything it adds in future versions — surfaces here
	// without code changes.
	Settings map[string]string `json:"settings,omitempty"`
}

// Module mirrors debug.Module.
type Module struct {
	Path    string  `json:"path"`
	Version string  `json:"version,omitempty"`
	Sum     string  `json:"sum,omitempty"`
	Replace *Module `json:"replace,omitempty"`
}

// New returns a fresh attestor with initialized subject map.
func New() *Attestor {
	return &Attestor{
		subjects: make(map[string]cryptoutil.DigestSet),
	}
}

func (a *Attestor) Name() string                 { return Name }
func (a *Attestor) Type() string                 { return Type }
func (a *Attestor) RunType() attestation.RunType { return RunType }
func (a *Attestor) Schema() *jsonschema.Schema   { return jsonschema.Reflect(a) }

// Subjects returns two entries per binary the attestor successfully
// processed:
//   - `binary:<binary-path>` digested over the binary file content,
//     so `cilock verify --artifactfile <binary>` resolves naturally.
//   - `go-build-sidecar:<binary-path>` digested over the sidecar JSON,
//     so a verifier can re-read the on-disk JSON and confirm it
//     matches what was signed.
func (a *Attestor) Subjects() map[string]cryptoutil.DigestSet {
	return a.subjects
}

// Attest walks the product set, ignores everything that isn't a Go
// binary, and for each Go binary writes a `.gobuild.json` sidecar
// next to it carrying the full BuildInfo. The attestation predicate
// also carries every BinaryInfo so the data is recoverable even if
// the on-disk sidecars are themselves discarded later.
func (a *Attestor) Attest(ctx *attestation.AttestationContext) error {
	products := ctx.Products()
	if len(products) == 0 {
		// No products means there was nothing to scan. This is not
		// an error — a step might run go-build as part of an
		// always-on attestor set even when the user ran something
		// unrelated.
		return nil
	}

	workingDir := ctx.WorkingDir()
	for path := range products {
		abs := absPathIn(workingDir, path)

		info, err := readGoBinary(abs)
		if err != nil {
			if errors.Is(err, errNotGo) {
				a.SkippedNonGo = append(a.SkippedNonGo, path)
				continue
			}
			// Genuine read error (file disappeared, perms). Log and
			// keep going — one bad binary shouldn't kill the rest.
			log.Debugf("(attestation/go-build) reading %s: %v", path, err)
			a.SkippedNonGo = append(a.SkippedNonGo, path)
			continue
		}
		info.Path = path

		// Record the binary's own digest under `binary:<path>`. This
		// is the subject `cilock verify --artifactfile <binary>`
		// resolves against — without it, the natural verify flow
		// fails with a cryptic "no collections found." See #219.
		if d, derr := digestFile(abs, ctx.Hashes()); derr == nil {
			a.subjects["binary:"+path] = d
		} else {
			log.Debugf("(attestation/go-build) digesting binary %s: %v", path, derr)
		}

		sidecarPath := path + SidecarExt
		sidecarAbs := absPathIn(workingDir, sidecarPath)
		if err := writeSidecar(sidecarAbs, info); err != nil {
			// Sidecar persistence is the headline feature; failing
			// here is worth surfacing. Still keep the in-predicate
			// record so the data survives at all.
			log.Warnf("(attestation/go-build) sidecar write failed for %s: %v", path, err)
		} else {
			info.SidecarPath = sidecarPath
			if d, derr := digestFile(sidecarAbs, ctx.Hashes()); derr == nil {
				a.subjects["go-build-sidecar:"+path] = d
			} else {
				log.Debugf("(attestation/go-build) digesting %s: %v", sidecarPath, derr)
			}
		}

		a.Binaries = append(a.Binaries, info)
	}

	sortBinaries(a.Binaries)
	return nil
}

// errNotGo signals that buildinfo.ReadFile correctly identified the
// file as something other than a Go binary (or a Go binary with the
// buildinfo section already stripped). Distinct from a generic
// read-error so the caller can decide whether to log loudly or quietly.
var errNotGo = errors.New("not a Go binary or buildinfo missing")

// readGoBinary attempts to read BuildInfo from the file at abs.
// Returns errNotGo when the file isn't a Go binary or its buildinfo
// section is missing (stripped already, non-Go ELF, text file, etc.).
func readGoBinary(abs string) (BinaryInfo, error) {
	bi, err := buildinfo.ReadFile(abs)
	if err != nil {
		// debug/buildinfo distinguishes "I don't know this file
		// format" from "I know it but the buildinfo section is
		// missing/corrupt" by error message text, not error type.
		// Either way, treat as not-a-Go-binary — there's nothing
		// we can do.
		return BinaryInfo{}, fmt.Errorf("%w: %v", errNotGo, err)
	}
	return convertBuildInfo(bi), nil
}

// convertBuildInfo turns debug/buildinfo.BuildInfo into our wire
// shape. Module conversion is recursive because Replace can be
// chained (rare in practice, but allowed by the toolchain).
func convertBuildInfo(bi *buildinfo.BuildInfo) BinaryInfo {
	info := BinaryInfo{
		GoVersion: bi.GoVersion,
		MainPath:  bi.Path,
	}
	if bi.Main.Path != "" || bi.Main.Version != "" {
		m := convertModule(bi.Main)
		info.Main = &m
	}
	if len(bi.Deps) > 0 {
		info.Deps = make([]Module, 0, len(bi.Deps))
		for _, d := range bi.Deps {
			if d == nil {
				continue
			}
			info.Deps = append(info.Deps, convertModule(*d))
		}
	}
	if len(bi.Settings) > 0 {
		info.Settings = make(map[string]string, len(bi.Settings))
		for _, s := range bi.Settings {
			info.Settings[s.Key] = s.Value
		}
	}
	return info
}

func convertModule(m debug.Module) Module {
	out := Module{
		Path:    m.Path,
		Version: m.Version,
		Sum:     m.Sum,
	}
	if m.Replace != nil {
		r := convertModule(*m.Replace)
		out.Replace = &r
	}
	return out
}

// writeSidecar serializes info to JSON and writes it atomically to
// abs. "Atomic" here means tmp-file + rename, so a concurrent reader
// can never see a half-written sidecar. The marshal indents 2 spaces
// because these files are routinely read by humans (and by jq) and
// the size penalty is negligible.
func writeSidecar(abs string, info BinaryInfo) error {
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return fmt.Errorf("mkdir sidecar parent: %w", err)
	}
	body, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sidecar: %w", err)
	}
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return fmt.Errorf("write sidecar tmp: %w", err)
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename sidecar: %w", err)
	}
	return nil
}

// digestFile hashes the file at abs with the same hash algorithms
// the attestation context is configured for. Used for both the
// binary file and its sidecar JSON — keeps the subject digests
// consistent with every other digest in the bundle without
// hardcoding sha256 here.
func digestFile(abs string, hashes []cryptoutil.DigestValue) (cryptoutil.DigestSet, error) {
	f, err := os.Open(abs) //nolint:gosec // G304: path comes from products (trusted) or products+SidecarExt
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return cryptoutil.CalculateDigestSet(f, hashes)
}

// absPathIn resolves a (possibly-relative) path against a working
// directory, leaving absolute paths untouched. Matches the
// product-attestor convention so subjects line up cleanly.
func absPathIn(workingDir, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(workingDir, path)
}

// sortBinaries stable-sorts the slice in place by Path. Stable
// because a path can legitimately appear twice if the same binary
// shows up under both its absolute and relative form — keeping
// input order in that pathological case avoids surprising the user.
func sortBinaries(bins []BinaryInfo) {
	// Manual insertion sort — n is tiny (usually 1-5 binaries, never
	// more than a few hundred even in monorepo build steps) and we
	// avoid pulling in sort just for this.
	for i := 1; i < len(bins); i++ {
		for j := i; j > 0 && bins[j-1].Path > bins[j].Path; j-- {
			bins[j-1], bins[j] = bins[j], bins[j-1]
		}
	}
}
