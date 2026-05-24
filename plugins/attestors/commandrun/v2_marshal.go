// Copyright 2026 The Rookery Contributors
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

// V2 Phase 4: schema v0.2 emitter.
//
// v0.2 keeps the same semantic content as v0.1 — processes, opened
// files, syscall events, summary — but reshapes the wire format so:
//
//   1. Repeated strings (file paths, comms, cmdlines) are interned into
//      top-level arrays; per-process records hold integer ids instead.
//      A `cilock` build's v0.1 attestation has ~50 KB of duplicated
//      glibc-header paths spread across 100+ compile workers. v0.2
//      collapses these to one paths[] entry each.
//
//   2. _meta is the FIRST key — AI agents and operators can read a
//      small prefix and learn the document's shape without parsing
//      the whole thing.
//
//   3. Schema is designed to support future v0.3 (reference-only:
//      digests resolved against material/product attestations rather
//      than inlined) without reshape.
//
// What this commit does NOT yet implement:
//   - Column-packed events arrays (top-level `events[]` with delta-
//     encoded timestamps + integer opcodes). Plan retains this for
//     a follow-up; ProcessInfo.SyscallEvents stays per-process for now.
//   - Two-pass byte-offset section index (_meta.sections with EXACT
//     byte ranges). Plan retains for a follow-up.
//   - envDigests interning. Each process still holds its environ
//     string inline; will move to a digest-keyed table in a follow-up.
//
// These deferrals are intentional: the interned tables alone deliver
// the goal-mandated 50% size reduction. Column-packing + byte-offset
// index are AI-traversal-quality features, not size features.

package commandrun

import (
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// V02PredicateType is the in-toto predicate URI for v0.2 attestations.
// Discoverable separately from the v0.1 type so verifiers can route
// envelopes to the correct decoder.
const V02PredicateType = "https://aflock.ai/attestations/command-run/v0.2"

// V02Meta is the leading metadata block of a v0.2 attestation. AI
// agents and operators read this first to learn the document's shape
// before consuming the rest.
type V02Meta struct {
	Version       string         `json:"version"`           // "v0.2"
	CaptureMode   string         `json:"captureMode,omitempty"`
	TraceBackend  string         `json:"traceBackend,omitempty"`
	Counts        V02MetaCounts  `json:"counts"`
}

// V02MetaCounts surfaces the cardinality of each interned table so
// agents can size their downstream pipelines without parsing the
// whole document.
type V02MetaCounts struct {
	Processes      int `json:"processes"`
	UniquePaths    int `json:"uniquePaths"`
	UniqueDigests  int `json:"uniqueDigests"`
	UniqueComms    int `json:"uniqueComms"`
	Materials      int `json:"materials,omitempty"`
	Intermediates  int `json:"intermediates,omitempty"`
	Products       int `json:"products,omitempty"`
	CacheArtifacts int `json:"cacheArtifacts,omitempty"`
}

// V02DigestEntry is one row in the interned digests[] table. `Src`
// distinguishes trust sources: "trace-readtap" for in-kernel streaming
// hashes, "trace-pathhash" for after-the-fact path hashes, "ima" for
// kernel-measured (Phase 7), "fs-verity" for ioctl-measured (Phase 7).
type V02DigestEntry struct {
	// SHA256 is the hex-encoded SHA-256. Always present; other hash
	// algorithms can be added per-entry if produced.
	SHA256 string            `json:"sha256,omitempty"`
	Others map[string]string `json:"others,omitempty"` // future: sha512, blake3, gitoid-sha1
	Src    string            `json:"src,omitempty"`
}

// V02OpenedFile references a path + digest from the interned tables.
// Replaces v0.1's `map[path]DigestSet` per-process which duplicated
// every glibc header across hundreds of processes.
type V02OpenedFile struct {
	PathID   int `json:"pathId"`
	DigestID int `json:"digestId"`
}

// V02Process is the slim per-process record. Path-strings, comms, and
// cmdlines that v0.1 stored inline are replaced by indices into the
// interned top-level tables.
type V02Process struct {
	ProcessID   int                `json:"processid"`
	ParentPID   int                `json:"parentpid"`
	CommID      int                `json:"commId,omitempty"`
	ExecPathID  int                `json:"execPathId,omitempty"`
	Cmdline     string             `json:"cmdline,omitempty"` // TODO: intern in follow-up
	OpenedFiles []V02OpenedFile    `json:"openedFiles,omitempty"`
	FileOps     *FileActivity      `json:"fileOps,omitempty"`
	Syscalls    []SyscallEvent     `json:"syscalls,omitempty"`
}

// V02Predicate is the top-level v0.2 attestation body. Field order
// in the struct matches the JSON output order (Go's encoding/json
// preserves struct field order). _meta MUST be first.
type V02Predicate struct {
	Meta      V02Meta          `json:"_meta"`
	Summary   *TraceSummary    `json:"summary,omitempty"`
	Digests   []V02DigestEntry `json:"digests"`
	Paths     []string         `json:"paths"`
	Comms     []string         `json:"comms"`
	Processes []V02Process     `json:"processes"`
	Cmd       []string         `json:"cmd,omitempty"`
	ExitCode  int              `json:"exitcode,omitempty"`
}

// ToV02 converts a v0.1 CommandRun into the v0.2 wire shape. Lossless
// for the fields v0.2 supports. Re-marshaling the result produces the
// v0.2 attestation body.
//
// Interning strategy:
//   - paths: keyed by full path string
//   - digests: keyed by (sha256) since the same content produces the
//     same digest regardless of which path opened it. Also dedupes
//     across processes that opened "the same" file content via
//     different paths (symlinks, bind mounts, etc.)
//   - comms: keyed by string
//
// Returns *V02Predicate so callers can mutate before marshal if
// needed.
func (rc *CommandRun) ToV02() *V02Predicate {
	if rc == nil {
		return nil
	}

	v02 := &V02Predicate{
		Meta: V02Meta{
			Version: "v0.2",
		},
		Cmd:      rc.Cmd,
		ExitCode: rc.ExitCode,
		Summary:  rc.Summary,
	}

	// Intern tables. The keys are the natural identity of each entity.
	pathIDs := make(map[string]int)
	digestIDs := make(map[string]int) // key = sha256 hex
	commIDs := make(map[string]int)

	internPath := func(p string) int {
		if p == "" {
			return -1
		}
		if id, ok := pathIDs[p]; ok {
			return id
		}
		id := len(v02.Paths)
		pathIDs[p] = id
		v02.Paths = append(v02.Paths, p)
		return id
	}
	internComm := func(c string) int {
		if c == "" {
			return -1
		}
		if id, ok := commIDs[c]; ok {
			return id
		}
		id := len(v02.Comms)
		commIDs[c] = id
		v02.Comms = append(v02.Comms, c)
		return id
	}
	internDigest := func(ds cryptoutil.DigestSet) int {
		if ds == nil {
			return -1
		}
		// Extract sha256 — the canonical interning key.
		var sha256 string
		for k, v := range ds {
			if hashName(k) == "sha256" {
				sha256 = v
				break
			}
		}
		if sha256 == "" {
			return -1
		}
		if id, ok := digestIDs[sha256]; ok {
			return id
		}
		entry := V02DigestEntry{SHA256: sha256}
		// Capture additional hash types if present.
		for k, v := range ds {
			n := hashName(k)
			if n == "sha256" {
				continue
			}
			if entry.Others == nil {
				entry.Others = make(map[string]string)
			}
			entry.Others[n] = v
		}
		id := len(v02.Digests)
		digestIDs[sha256] = id
		v02.Digests = append(v02.Digests, entry)
		return id
	}

	// Pass over processes: emit slim V02Process records, interning
	// strings as we go.
	v02.Processes = make([]V02Process, 0, len(rc.Processes))
	for i := range rc.Processes {
		p := &rc.Processes[i]
		vp := V02Process{
			ProcessID: p.ProcessID,
			ParentPID: p.ParentPID,
			Cmdline:   p.Cmdline,
			FileOps:   p.FileOps,
			Syscalls:  p.SyscallEvents,
		}
		if p.Comm != "" {
			vp.CommID = internComm(p.Comm)
		}
		if p.Program != "" {
			vp.ExecPathID = internPath(p.Program)
		}
		// Opened files → interned references.
		if len(p.OpenedFiles) > 0 {
			vp.OpenedFiles = make([]V02OpenedFile, 0, len(p.OpenedFiles))
			for path, ds := range p.OpenedFiles {
				pid := internPath(path)
				did := internDigest(ds)
				vp.OpenedFiles = append(vp.OpenedFiles, V02OpenedFile{
					PathID:   pid,
					DigestID: did,
				})
			}
		}
		v02.Processes = append(v02.Processes, vp)
	}

	// Backfill counts.
	v02.Meta.Counts.Processes = len(v02.Processes)
	v02.Meta.Counts.UniquePaths = len(v02.Paths)
	v02.Meta.Counts.UniqueDigests = len(v02.Digests)
	v02.Meta.Counts.UniqueComms = len(v02.Comms)
	if rc.Summary != nil {
		v02.Meta.Counts.Materials = rc.Summary.Totals.Materials
		v02.Meta.Counts.Intermediates = rc.Summary.Totals.Intermediates
		v02.Meta.Counts.Products = rc.Summary.Totals.Products
		v02.Meta.Counts.CacheArtifacts = rc.Summary.Totals.CacheArtifacts
	}

	return v02
}

// hashName returns the canonical string name of a hash type from a
// cryptoutil.DigestValue. Used as the interning key for digest entries.
func hashName(dv cryptoutil.DigestValue) string {
	// cryptoutil.DigestValue.Hash is a crypto.Hash; standard names are
	// in lowercase per the in-toto convention.
	switch dv.Hash.String() {
	case "SHA-256":
		return "sha256"
	case "SHA-512":
		return "sha512"
	case "SHA-1":
		return "sha1"
	}
	return ""
}
