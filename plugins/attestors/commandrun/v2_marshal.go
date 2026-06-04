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

// command-run v0.2 wire schema: the interned, _meta-first reshape of the
// v0.1 predicate.
//
// v0.2 carries the SAME semantic content as v0.1 — every process, opened
// file, written digest, fs-verity root, network event, syscall, and the
// summary — but reshapes the wire format so:
//
//  1. Repeated strings (file paths, comms, cmdlines) and digests are
//     interned into top-level arrays; per-process records hold integer
//     ids instead. A `cilock` build's v0.1 attestation has tens of KB of
//     duplicated glibc-header paths spread across 100+ compile workers;
//     v0.2 collapses each to a single table entry.
//
//  2. `_meta` is the FIRST key — agents and operators read a small prefix
//     and learn the document's shape (and the signer's anti-tamper state)
//     without parsing the whole thing.
//
// LOSSLESS FOR EVIDENCE, with a deliberate prune of v0.1 cruft. ToV02 +
// FromV02 round-trip every SECURITY-RELEVANT field — the ones the earlier WIP
// wrongly dropped: the wrapped command's exit code, Stdout/Stderr build logs,
// WrittenDigests (products), FsVerityDigests (kernel Merkle roots), Network
// (egress — the SLSA-L3 hermeticity signal), ProgramDigest, ExeDigest,
// UnhashedOpens, and syscalls. The round-trip is gated by a test; dropping one
// of THOSE is a correctness bug, not an optimization. (Stdout/Stderr can carry
// secrets a build echoes — that is the build's responsibility to avoid; the
// logs are audit-critical and are kept by design.)
//
// v0.2 INTENTIONALLY DROPS two v0.1 fields that are pure liability or noise:
//   - ProcessInfo.Environ (per-process): the raw environment of every traced
//     process, captured from /proc/<pid>/environ and SIGNED + uploaded to
//     Archivista. It has ZERO readers (no policy, link, slsa, or UI consumes
//     it) and routes secrets (CI tokens, cloud keys) straight into the
//     attestation, bypassing the obfuscation the `environment` attestor
//     applies. Dropping it is a security win with no functional loss.
//   - ProcessInfo.SpecBypassIsVuln (per-process): a Spectre-v4 mitigation
//     status scraped from /proc/<pid>/status. Niche kernel telemetry with no
//     consumer — it does not belong in build provenance.

package commandrun

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// V02PredicateType is the in-toto predicate URI for v0.2 attestations.
// Discoverable separately from the v0.1 type so verifiers can route
// envelopes to the correct decoder.
const V02PredicateType = "https://aflock.ai/attestations/command-run/v0.2"

// V02KeyGuard records the in-process anti-tamper hardening that was in
// effect in the SIGNER (cilock) while the build ran and the signing key was
// live. It is NON-FORGEABILITY evidence carried INSIDE the signed predicate:
// dumpable==false means a same-UID attacker on the build host could not lift
// the signing key out of cilock's memory mid-build (ptrace / process_vm_readv
// / /proc/<pid>/mem / core dump all denied), so the keyless workflow identity
// the build signed with is actually non-forgeable. A verifier/policy can gate
// an SLSA L3 verdict on `_meta.keyGuard.dumpable == false`.
//
// The values are read back from the kernel at attestation time (never
// asserted) and frozen into the signed bytes — a verifier reads them from the
// envelope, it does NOT re-probe (which would read the verifier's process,
// not the signer's).
type V02KeyGuard struct {
	// Applied is true when at least the dumpable protection took effect.
	Applied bool `json:"applied"`
	// Dumpable is the PR_GET_DUMPABLE read-back: FALSE means protected. This is
	// the load-bearing extraction control and the only field the L3 gate asserts.
	Dumpable bool `json:"dumpable"`
	// YamaPtraceScope echoes /proc/sys/kernel/yama/ptrace_scope (-1 if absent).
	YamaPtraceScope int `json:"yamaPtraceScope"`
	// Note carries a short human explanation (e.g. why a layer didn't apply).
	Note string `json:"note,omitempty"`
}

// V02Meta is the leading metadata block of a v0.2 attestation. Agents and
// operators read this first to learn the document's shape — and the signer's
// anti-tamper state — before consuming the rest.
//
// Sections is the byte-offset section index — only populated when the
// document is emitted via MarshalV02WithSections (the two-pass encoder).
// Maps section name → [startByte, endByte] inclusive, relative to the
// predicate body's first byte. Empty when the document is emitted via plain
// json.Marshal.
type V02Meta struct {
	Version      string              `json:"version"` // "v0.2"
	CaptureMode  string              `json:"captureMode,omitempty"`
	TraceBackend string              `json:"traceBackend,omitempty"`
	KeyGuard     *V02KeyGuard        `json:"keyGuard,omitempty"`
	Counts       V02MetaCounts       `json:"counts"`
	Sections     map[string][2]int64 `json:"sections,omitempty"`
}

// V02MetaCounts surfaces the cardinality of each interned table so agents
// can size their downstream pipelines without parsing the whole document.
type V02MetaCounts struct {
	Processes      int `json:"processes"`
	UniquePaths    int `json:"uniquePaths"`
	UniqueDigests  int `json:"uniqueDigests"`
	UniqueComms    int `json:"uniqueComms"`
	UniqueCmdlines int `json:"uniqueCmdlines,omitempty"`
	Materials      int `json:"materials,omitempty"`
	Intermediates  int `json:"intermediates,omitempty"`
	Products       int `json:"products,omitempty"`
	CacheArtifacts int `json:"cacheArtifacts,omitempty"`
}

// V02DigestEntry is one row in the interned digests[] table. Digests holds
// the full name→hex map (e.g. {"sha256":"…","gitoid:sha256":"…"}) so the
// entry round-trips through cryptoutil.NewDigestSet losslessly for EVERY
// hash type, not just sha256.
type V02DigestEntry struct {
	Digests map[string]string `json:"digests"`
	Src     string            `json:"src,omitempty"`
}

// V02FileRef references a path + digest from the interned tables. Replaces
// v0.1's `map[path]DigestSet` per-process which duplicated every glibc
// header across hundreds of processes. Used for both OpenedFiles (reads)
// and WrittenFiles (write-tap outputs).
type V02FileRef struct {
	PathID   int `json:"pathId"`
	DigestID int `json:"digestId"`
}

// V02FsVerity references an interned path plus the kernel fs-verity Merkle
// root value ("alg:hex"), preserving v0.1's per-path FsVerityDigests.
type V02FsVerity struct {
	PathID int    `json:"pathId"`
	Value  string `json:"value"`
}

// V02UnhashedOpen references an interned path plus the reason the open could
// not be hashed, preserving v0.1's UnhashedOpens (a security-relevant gap a
// verifier must judge).
type V02UnhashedOpen struct {
	PathID int    `json:"pathId"`
	Reason string `json:"reason"`
}

// V02Process is the slim per-process record. Path-strings, comms, cmdlines,
// and digests that v0.1 stored inline are replaced by indices into the
// interned top-level tables. Single-value ids use -1 to mean "absent"
// (0 is a valid intern id, so omitempty cannot be used for them). Everything
// not worth interning (network, file-ops, syscalls, environ, flags, exit
// code) is carried inline, lossless.
type V02Process struct {
	ProcessID       int               `json:"processid"`
	ParentPID       int               `json:"parentpid"`
	CommID          int               `json:"commId"`
	ExecPathID      int               `json:"execPathId"`
	CmdlineID       int               `json:"cmdlineId"`
	ProgramDigestID int               `json:"programDigestId"`
	ExeDigestID     int               `json:"exeDigestId"`
	OpenedFiles     []V02FileRef      `json:"openedFiles,omitempty"`
	WrittenFiles    []V02FileRef      `json:"writtenFiles,omitempty"`
	FsVerity        []V02FsVerity     `json:"fsVerity,omitempty"`
	UnhashedOpens   []V02UnhashedOpen `json:"unhashedOpens,omitempty"`
	Network         *NetworkActivity  `json:"network,omitempty"`
	FileOps         *FileActivity     `json:"fileOps,omitempty"`
	Syscalls        []SyscallEvent    `json:"syscalls,omitempty"`
	ExitCode        int               `json:"exitcode,omitempty"`
}

// V02Predicate is the top-level v0.2 attestation body. Field order in the
// struct matches the JSON output order (Go's encoding/json preserves struct
// field order). _meta MUST be first.
type V02Predicate struct {
	Meta      V02Meta          `json:"_meta"`
	Summary   *TraceSummary    `json:"summary,omitempty"`
	Digests   []V02DigestEntry `json:"digests"`
	Paths     []string         `json:"paths"`
	Comms     []string         `json:"comms"`
	Cmdlines  []string         `json:"cmdlines,omitempty"`
	Processes []V02Process     `json:"processes"`
	Cmd       []string         `json:"cmd,omitempty"`
	ExitCode  int              `json:"exitcode,omitempty"`
	// Stdout/Stderr are the wrapped command's captured build logs — kept in
	// v0.2 for audit/debugging. Serialized AFTER the heavy interned tables so
	// an agent reading the _meta prefix isn't forced through them.
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
}

// v02Interner holds the dedup tables shared by ToV02. Each intern* returns an
// index into the corresponding top-level array, or -1 for an empty/absent
// value.
type v02Interner struct {
	p          *V02Predicate
	pathIDs    map[string]int
	commIDs    map[string]int
	cmdlineIDs map[string]int
	digestIDs  map[string]int
}

func newV02Interner(p *V02Predicate) *v02Interner {
	return &v02Interner{
		p:          p,
		pathIDs:    make(map[string]int),
		commIDs:    make(map[string]int),
		cmdlineIDs: make(map[string]int),
		digestIDs:  make(map[string]int),
	}
}

func (in *v02Interner) path(s string) int {
	if s == "" {
		return -1
	}
	if id, ok := in.pathIDs[s]; ok {
		return id
	}
	id := len(in.p.Paths)
	in.pathIDs[s] = id
	in.p.Paths = append(in.p.Paths, s)
	return id
}

func (in *v02Interner) comm(s string) int {
	if s == "" {
		return -1
	}
	if id, ok := in.commIDs[s]; ok {
		return id
	}
	id := len(in.p.Comms)
	in.commIDs[s] = id
	in.p.Comms = append(in.p.Comms, s)
	return id
}

func (in *v02Interner) cmdline(s string) int {
	if s == "" {
		return -1
	}
	if id, ok := in.cmdlineIDs[s]; ok {
		return id
	}
	id := len(in.p.Cmdlines)
	in.cmdlineIDs[s] = id
	in.p.Cmdlines = append(in.p.Cmdlines, s)
	return id
}

// digest interns a DigestSet by its canonical name-map. Returns -1 for nil,
// empty, or unsupported-hash sets (which cryptoutil cannot round-trip).
func (in *v02Interner) digest(ds cryptoutil.DigestSet) int {
	if len(ds) == 0 {
		return -1
	}
	nm, err := ds.ToNameMap()
	if err != nil || len(nm) == 0 {
		return -1
	}
	key := canonicalDigestKey(nm)
	if id, ok := in.digestIDs[key]; ok {
		return id
	}
	id := len(in.p.Digests)
	in.digestIDs[key] = id
	in.p.Digests = append(in.p.Digests, V02DigestEntry{Digests: nm})
	return id
}

// canonicalDigestKey is the dedup key for a digest name-map: the names sorted
// and joined with their hex values so two identical sets collapse to one
// table entry regardless of Go map iteration order.
func canonicalDigestKey(nm map[string]string) string {
	names := make([]string, 0, len(nm))
	for n := range nm {
		names = append(names, n)
	}
	sort.Strings(names)
	var b bytes.Buffer
	for _, n := range names {
		b.WriteString(n)
		b.WriteByte('=')
		b.WriteString(nm[n])
		b.WriteByte(';')
	}
	return b.String()
}

// fileRefs interns a path→digest map into a path-sorted []V02FileRef so the
// output is deterministic across runs (maps iterate randomly).
func (in *v02Interner) fileRefs(m map[string]cryptoutil.DigestSet) []V02FileRef {
	if len(m) == 0 {
		return nil
	}
	paths := make([]string, 0, len(m))
	for p := range m {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := make([]V02FileRef, 0, len(m))
	for _, p := range paths {
		out = append(out, V02FileRef{PathID: in.path(p), DigestID: in.digest(m[p])})
	}
	return out
}

// ToV02 converts a v0.1 CommandRun into the v0.2 wire shape, losslessly.
// Re-marshaling the result produces the v0.2 attestation body; FromV02
// reverses it.
func (rc *CommandRun) ToV02() *V02Predicate {
	if rc == nil {
		return nil
	}

	v02 := &V02Predicate{
		Meta:     V02Meta{Version: "v0.2", KeyGuard: rc.keyGuard},
		Cmd:      rc.Cmd,
		ExitCode: rc.ExitCode,
		Stdout:   rc.Stdout,
		Stderr:   rc.Stderr,
		Summary:  rc.Summary,
	}
	if rc.Summary != nil {
		v02.Meta.CaptureMode = rc.Summary.CaptureMode
		v02.Meta.TraceBackend = rc.Summary.TraceModeDetail
	}

	in := newV02Interner(v02)

	v02.Processes = make([]V02Process, 0, len(rc.Processes))
	for i := range rc.Processes {
		p := &rc.Processes[i]
		vp := V02Process{
			ProcessID:       p.ProcessID,
			ParentPID:       p.ParentPID,
			CommID:          in.comm(p.Comm),
			ExecPathID:      in.path(p.Program),
			CmdlineID:       in.cmdline(p.Cmdline),
			ProgramDigestID: in.digest(p.ProgramDigest),
			ExeDigestID:     in.digest(p.ExeDigest),
			OpenedFiles:     in.fileRefs(p.OpenedFiles),
			WrittenFiles:    in.fileRefs(p.WrittenDigests),
			FsVerity:        in.fsVerity(p.FsVerityDigests),
			UnhashedOpens:   in.unhashedOpens(p.UnhashedOpens),
			Network:         p.Network,
			FileOps:         p.FileOps,
			Syscalls:        p.SyscallEvents,
			ExitCode:        p.ExitCode,
		}
		v02.Processes = append(v02.Processes, vp)
	}

	// Backfill counts.
	v02.Meta.Counts.Processes = len(v02.Processes)
	v02.Meta.Counts.UniquePaths = len(v02.Paths)
	v02.Meta.Counts.UniqueDigests = len(v02.Digests)
	v02.Meta.Counts.UniqueComms = len(v02.Comms)
	v02.Meta.Counts.UniqueCmdlines = len(v02.Cmdlines)
	if rc.Summary != nil {
		v02.Meta.Counts.Materials = rc.Summary.Totals.Materials
		v02.Meta.Counts.Intermediates = rc.Summary.Totals.Intermediates
		v02.Meta.Counts.Products = rc.Summary.Totals.Products
		v02.Meta.Counts.CacheArtifacts = rc.Summary.Totals.CacheArtifacts
	}

	return v02
}

// fsVerity interns a path→"alg:hex" map into a path-sorted slice.
func (in *v02Interner) fsVerity(m map[string]string) []V02FsVerity {
	if len(m) == 0 {
		return nil
	}
	paths := make([]string, 0, len(m))
	for p := range m {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	out := make([]V02FsVerity, 0, len(m))
	for _, p := range paths {
		out = append(out, V02FsVerity{PathID: in.path(p), Value: m[p]})
	}
	return out
}

// unhashedOpens interns the path of each UnhashedOpen, preserving order.
func (in *v02Interner) unhashedOpens(u []UnhashedOpen) []V02UnhashedOpen {
	if len(u) == 0 {
		return nil
	}
	out := make([]V02UnhashedOpen, 0, len(u))
	for _, e := range u {
		out = append(out, V02UnhashedOpen{PathID: in.path(e.Path), Reason: e.Reason})
	}
	return out
}

// v02Deinterner resolves interned ids back to their values during FromV02.
type v02Deinterner struct{ p *V02Predicate }

func (d v02Deinterner) path(id int) string {
	if id < 0 || id >= len(d.p.Paths) {
		return ""
	}
	return d.p.Paths[id]
}

func (d v02Deinterner) comm(id int) string {
	if id < 0 || id >= len(d.p.Comms) {
		return ""
	}
	return d.p.Comms[id]
}

func (d v02Deinterner) cmdline(id int) string {
	if id < 0 || id >= len(d.p.Cmdlines) {
		return ""
	}
	return d.p.Cmdlines[id]
}

func (d v02Deinterner) digest(id int) cryptoutil.DigestSet {
	if id < 0 || id >= len(d.p.Digests) {
		return nil
	}
	ds, err := cryptoutil.NewDigestSet(d.p.Digests[id].Digests)
	if err != nil || len(ds) == 0 {
		return nil
	}
	return ds
}

func (d v02Deinterner) fileMap(refs []V02FileRef) map[string]cryptoutil.DigestSet {
	if len(refs) == 0 {
		return nil
	}
	out := make(map[string]cryptoutil.DigestSet, len(refs))
	for _, r := range refs {
		path := d.path(r.PathID)
		if path == "" {
			continue
		}
		out[path] = d.digest(r.DigestID)
	}
	// Normalize empty → nil so a corrupt/all-invalid ref list reconstructs the
	// same nil a clean empty input produced (consistent with ToV02 dropping
	// empty maps to a nil slice — see the normalization note on FromV02).
	if len(out) == 0 {
		return nil
	}
	return out
}

// FromV02 reconstructs a CommandRun from the v0.2 wire shape. It is the inverse
// of ToV02 for all CONTENT — digests, paths, network, syscalls, logs — so
// verify-time consumers reading Data() (link, slsa, rego) see the same trace
// the producer recorded.
//
// Normalization: empty and nil maps/slices are treated as equivalent and
// reconstruct as nil. This is not a lossy gap — the v0.2 wire's omitempty
// tags cannot distinguish an empty collection from an absent one in the first
// place, and the Go nil/empty-map distinction has no observable meaning for a
// verifier (len/range/lookup behave identically). Both directions normalize to
// nil so the round-trip is consistent.
func FromV02(p *V02Predicate) *CommandRun {
	if p == nil {
		return nil
	}
	rc := New()
	rc.Cmd = p.Cmd
	rc.ExitCode = p.ExitCode
	rc.Stdout = p.Stdout
	rc.Stderr = p.Stderr
	rc.Summary = p.Summary
	rc.keyGuard = p.Meta.KeyGuard

	de := v02Deinterner{p: p}
	rc.Processes = make([]ProcessInfo, 0, len(p.Processes))
	for i := range p.Processes {
		vp := &p.Processes[i]
		pi := ProcessInfo{
			Program:         de.path(vp.ExecPathID),
			ProcessID:       vp.ProcessID,
			ParentPID:       vp.ParentPID,
			ProgramDigest:   de.digest(vp.ProgramDigestID),
			Comm:            de.comm(vp.CommID),
			Cmdline:         de.cmdline(vp.CmdlineID),
			ExeDigest:       de.digest(vp.ExeDigestID),
			OpenedFiles:     de.fileMap(vp.OpenedFiles),
			WrittenDigests:  de.fileMap(vp.WrittenFiles),
			FsVerityDigests: de.fsVerityMap(vp.FsVerity),
			UnhashedOpens:   de.unhashedOpens(vp.UnhashedOpens),
			Network:         vp.Network,
			FileOps:         vp.FileOps,
			SyscallEvents:   vp.Syscalls,
			ExitCode:        vp.ExitCode,
		}
		rc.Processes = append(rc.Processes, pi)
	}
	return rc
}

func (d v02Deinterner) fsVerityMap(refs []V02FsVerity) map[string]string {
	if len(refs) == 0 {
		return nil
	}
	out := make(map[string]string, len(refs))
	for _, r := range refs {
		path := d.path(r.PathID)
		if path == "" {
			continue
		}
		out[path] = r.Value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (d v02Deinterner) unhashedOpens(refs []V02UnhashedOpen) []UnhashedOpen {
	if len(refs) == 0 {
		return nil
	}
	out := make([]UnhashedOpen, 0, len(refs))
	for _, r := range refs {
		out = append(out, UnhashedOpen{Path: d.path(r.PathID), Reason: r.Reason})
	}
	return out
}

// MarshalV02WithSections emits the v0.2 predicate body with `_meta.sections`
// populated to exact byte offsets [start, end] for each top-level section.
// The offsets are relative to the predicate body's first byte (the opening
// `{`).
//
// Why two-pass: the offsets in _meta change the byte length of _meta itself
// (more digits = longer meta = shifts every later offset). Iterating to a
// fixpoint is the only way to converge without distortion-via-padding tricks.
// Typical convergence: 2 passes.
func MarshalV02WithSections(p *V02Predicate) ([]byte, *V02Predicate, error) {
	if p == nil {
		return nil, nil, fmt.Errorf("nil predicate")
	}

	type section struct {
		name string
		body []byte
	}
	mkSection := func(name string, v interface{}) (section, error) {
		b, err := json.Marshal(v)
		if err != nil {
			return section{}, fmt.Errorf("marshal %s: %w", name, err)
		}
		return section{name: name, body: b}, nil
	}
	type sectionSpec struct {
		name     string
		val      interface{}
		included bool
	}
	// NOTE: the section encoder emits ONLY the sections listed here — any
	// top-level V02Predicate field missing from this list is silently dropped
	// from the signed body. exitcode/stdout/stderr MUST be present (their
	// inclusion gate mirrors the struct's omitempty: emit only when non-zero).
	specs := []sectionSpec{
		{"summary", p.Summary, p.Summary != nil},
		{"digests", p.Digests, true},
		{"paths", p.Paths, true},
		{"comms", p.Comms, true},
		{"cmdlines", p.Cmdlines, len(p.Cmdlines) > 0},
		{"processes", p.Processes, true},
		{"cmd", p.Cmd, len(p.Cmd) > 0},
		{"exitcode", p.ExitCode, p.ExitCode != 0},
		{"stdout", p.Stdout, p.Stdout != ""},
		{"stderr", p.Stderr, p.Stderr != ""},
	}
	sections := make([]section, 0, len(specs))
	for _, s := range specs {
		if !s.included {
			continue
		}
		sec, err := mkSection(s.name, s.val)
		if err != nil {
			return nil, nil, err
		}
		sections = append(sections, sec)
	}

	const maxIter = 8
	prevMetaLen := -1
	var metaBytes []byte
	var offsets map[string][2]int64

	for iter := 0; iter < maxIter; iter++ {
		guess := prevMetaLen
		if guess < 0 {
			p.Meta.Sections = nil
			tmp, err := json.Marshal(p.Meta)
			if err != nil {
				return nil, nil, fmt.Errorf("seed marshal _meta: %w", err)
			}
			guess = len(tmp)
		}

		// Layout: {"_meta":<meta>,"<sec1>":<sec1Body>,...}
		offsets = make(map[string][2]int64, len(sections))
		cursor := int64(len(`{"_meta":`)) + int64(guess) // end of meta
		for _, s := range sections {
			cursor += int64(len(s.name)) + 4 // ,"":
			start := cursor
			cursor += int64(len(s.body))
			end := cursor - 1
			offsets[s.name] = [2]int64{start, end}
		}

		p.Meta.Sections = offsets
		mb, err := json.Marshal(p.Meta)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal _meta with offsets: %w", err)
		}
		if len(mb) == guess {
			metaBytes = mb
			break
		}
		prevMetaLen = len(mb)
	}
	if metaBytes == nil {
		return nil, nil, fmt.Errorf("two-pass encoder failed to converge after %d iterations", maxIter)
	}

	total := len(metaBytes) + 32
	for _, s := range sections {
		total += len(s.name) + len(s.body) + 5
	}
	var out bytes.Buffer
	out.Grow(total)
	out.WriteString(`{"_meta":`)
	out.Write(metaBytes)
	for _, s := range sections {
		out.WriteString(`,"`)
		out.WriteString(s.name)
		out.WriteString(`":`)
		out.Write(s.body)
	}
	out.WriteByte('}')

	final := out.Bytes()
	for _, s := range sections {
		off := offsets[s.name]
		got := final[off[0] : off[1]+1]
		if !bytes.Equal(got, s.body) {
			return nil, nil, fmt.Errorf("internal: section %s offsets %v don't point at the section body "+
				"(got %d bytes, want %d)", s.name, off, len(got), len(s.body))
		}
	}

	return final, p, nil
}
