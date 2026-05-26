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

// V2 Phase 4: schema v0.2 tests. Each test pins a single schema
// invariant; together they form the gate the v0.2 emitter must clear.

package commandrun

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// synthCommandRun builds a synthetic CommandRun with realistic process
// + opened-file shape so the schema tests can exercise the interning
// paths without spinning up a real tracee. ~100 processes, ~50 unique
// paths each opened by multiple processes — exactly the redundancy
// pattern v0.2 must collapse.
func synthCommandRun() *CommandRun {
	rc := New()
	rc.Cmd = []string{"go", "build", "./..."}
	rc.ExitCode = 0

	// 50 unique library/header paths shared across many processes.
	sharedPaths := make([]string, 50)
	for i := range sharedPaths {
		sharedPaths[i] = fmt.Sprintf("/usr/include/%s.h", strings.Repeat("x", i%10+1))
	}
	// One stable digest per path (same content read by every process).
	sharedDigest := func(p string) cryptoutil.DigestSet {
		return cryptoutil.DigestSet{
			{Hash: 5}: fmt.Sprintf("%064x", []byte(p)[0]),
		}
	}

	// 100 processes, each opens 30 of the shared paths.
	rc.Processes = make([]ProcessInfo, 0, 100)
	for pid := 1000; pid < 1100; pid++ {
		pi := ProcessInfo{
			ProcessID: pid,
			ParentPID: 999,
			Comm:      "compile",
			Cmdline:   "go tool compile -p main -lang go1.21 -complete -buildid xyz123 -goversion go1.21.5 -o /tmp/foo.a -trimpath /home/user/code main.go",
			Environ:   "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nHOME=/root\nGOCACHE=/root/.cache/go-build\nGOROOT=/usr/local/go\n",
			OpenedFiles: make(map[string]cryptoutil.DigestSet),
		}
		for i := 0; i < 30; i++ {
			p := sharedPaths[(pid+i)%len(sharedPaths)]
			pi.OpenedFiles[p] = sharedDigest(p)
		}
		rc.Processes = append(rc.Processes, pi)
	}
	return rc
}

// TestV02_SmallerThan_V01 pins the goal-mandated size reduction:
// v0.2 attestation MUST be ≤ 50% of v0.1 byte-size on the same data.
// This is the load-bearing test for Phase 4's value proposition.
func TestV02_SmallerThan_V01(t *testing.T) {
	rc := synthCommandRun()

	v01Bytes, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("v0.1 marshal: %v", err)
	}

	v02Bytes, err := json.Marshal(rc.ToV02())
	if err != nil {
		t.Fatalf("v0.2 marshal: %v", err)
	}

	v01Size := len(v01Bytes)
	v02Size := len(v02Bytes)
	target := v01Size / 2
	t.Logf("v0.1=%d bytes  v0.2=%d bytes  reduction=%.1f%%  target=%d",
		v01Size, v02Size, 100.0*float64(v01Size-v02Size)/float64(v01Size), target)

	if v02Size > target {
		t.Errorf("v0.2 size %d > 50%% target %d (v0.1=%d). "+
			"Interning of paths[]/comms[]/cmdlines[] not aggressive enough.",
			v02Size, target, v01Size)
	}
}

// TestV02_SchemaShape pins the required top-level keys and their
// order in the JSON output. Without _meta + interned tables in fixed
// positions, AI-agent traversal can't seek to summary without parsing
// the whole document.
func TestV02_SchemaShape(t *testing.T) {
	rc := synthCommandRun()

	out, err := json.Marshal(rc.ToV02())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Required top-level keys per the V2 plan's schema design.
	// summary is omitempty so it only appears when set; the synth
	// fixture doesn't populate it.
	requiredKeys := []string{
		`"_meta":`,
		`"digests":`,
		`"paths":`,
		`"comms":`,
		`"processes":`,
	}
	for _, k := range requiredKeys {
		if !strings.Contains(string(out), k) {
			t.Errorf("v0.2 output missing required top-level key %s\nfirst 500 bytes: %s",
				k, truncate(string(out), 500))
		}
	}

	// _meta MUST be the first key — operators reading a small prefix
	// of the file rely on it.
	if !strings.HasPrefix(string(out), `{"_meta":`) {
		t.Errorf("v0.2 output must lead with _meta; got: %s", truncate(string(out), 100))
	}
}

// TestV02_DigestsDedup pins that the interned digests[] table has one
// entry per UNIQUE (path, digest) pair, not one per process×path.
// The synthetic CommandRun has 100 procs × 30 opens but only 50 unique
// paths → expect ≤50 digest entries.
func TestV02_DigestsDedup(t *testing.T) {
	rc := synthCommandRun()
	v02 := rc.ToV02()

	if got := len(v02.Digests); got > 50 {
		t.Errorf("v0.2 digests[] dedup failed: %d entries; expected ≤50 (50 unique paths)", got)
	}
	if got := len(v02.Paths); got > 50 {
		t.Errorf("v0.2 paths[] dedup failed: %d entries; expected ≤50", got)
	}
}

// TestV02_LegacyDecode_V01Envelope pins backwards-compat: an
// attestation produced by today's v0.1 attestor must still decode
// under the legacy verify-only decoder. Without this, every
// pre-v0.2 attestation in production breaks.
func TestV02_LegacyDecode_V01Envelope(t *testing.T) {
	rc := synthCommandRun()
	v01Bytes, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("v0.1 marshal: %v", err)
	}

	dec := newLegacyDecoder(LegacyV01Type)
	if err := dec.UnmarshalJSON(v01Bytes); err != nil {
		t.Fatalf("legacy decoder rejected a freshly-produced v0.1 envelope: %v", err)
	}

	// Subjects should match what the v0.1 attestor produced.
	subs := dec.Subjects()
	if len(subs) == 0 {
		t.Errorf("legacy decoder produced 0 subjects from a v0.1 attestation; "+
			"expected per-process file subjects. Got %d processes in input.",
			len(rc.Processes))
	}
}

// TestV02_LegacyDecoder_RefusesProduce pins the verify-only contract:
// the legacy decoder must refuse Attest() so an accidental producer
// invocation fails loudly (same guarantee product's legacy decoder
// provides).
func TestV02_LegacyDecoder_RefusesProduce(t *testing.T) {
	dec := newLegacyDecoder(LegacyV01Type)
	err := dec.Attest(nil)
	if err == nil {
		t.Fatal("legacy decoder Attest() returned nil; expected errLegacyDecodeOnly")
	}
	if !strings.Contains(err.Error(), "legacy") {
		t.Errorf("legacy decoder Attest() returned wrong error: %v", err)
	}
}

// TestV02_SectionOffsets_RoundTripExact pins the goal-mandated
// byte-offset section index invariant: reading the document at the
// offsets recorded in `_meta.sections` MUST return the exact bytes
// that section was marshaled to. Off-by-one or off-by-cursor here
// makes the AI-traversal feature useless.
func TestV02_SectionOffsets_RoundTripExact(t *testing.T) {
	rc := synthCommandRun()
	v02 := rc.ToV02()
	// Add a Summary so the summary section is present in the output.
	v02.Summary = &TraceSummary{}

	out, _, err := MarshalV02WithSections(v02)
	if err != nil {
		t.Fatalf("MarshalV02WithSections: %v", err)
	}

	// Parse the first chunk to extract _meta.sections.
	var firstChunk struct {
		Meta V02Meta `json:"_meta"`
	}
	chunkSize := 8192
	if chunkSize > len(out) {
		chunkSize = len(out)
	}
	// Find the end of the _meta object by counting braces.
	depth := 0
	metaEnd := 0
	for i := 0; i < len(out); i++ {
		c := out[i]
		if c == '{' {
			depth++
		} else if c == '}' {
			depth--
			if depth == 1 { // back to top-level object brace level
				// Close of _meta object (which is at depth 2 → back to 1)
				metaEnd = i + 1
				break
			}
		}
	}
	if metaEnd == 0 {
		t.Fatalf("could not find end of _meta in first %d bytes", chunkSize)
	}
	// _meta object spans [9, metaEnd-1]; we wrap it in a stub doc to
	// parse just the _meta block.
	stub := []byte(`{"_meta":`)
	stub = append(stub, out[len(`{"_meta":`):metaEnd]...)
	stub = append(stub, '}')
	if err := json.Unmarshal(stub, &firstChunk); err != nil {
		t.Fatalf("parse _meta from prefix: %v\nprefix: %s", err, string(stub))
	}
	if len(firstChunk.Meta.Sections) == 0 {
		t.Fatalf("_meta.sections is empty; encoder didn't populate")
	}

	// For each section in _meta.sections, verify seeking to those
	// offsets yields the SAME bytes a fresh json.Marshal would produce.
	for name, off := range firstChunk.Meta.Sections {
		start, end := off[0], off[1]
		if start < 0 || end < start || int(end) >= len(out) {
			t.Errorf("section %s offsets %v out of bounds (doc len %d)", name, off, len(out))
			continue
		}
		got := out[start : end+1]

		// Independently re-marshal the section to compare.
		var want []byte
		var werr error
		switch name {
		case "summary":
			want, werr = json.Marshal(v02.Summary)
		case "digests":
			want, werr = json.Marshal(v02.Digests)
		case "paths":
			want, werr = json.Marshal(v02.Paths)
		case "comms":
			want, werr = json.Marshal(v02.Comms)
		case "cmdlines":
			want, werr = json.Marshal(v02.Cmdlines)
		case "processes":
			want, werr = json.Marshal(v02.Processes)
		case "cmd":
			want, werr = json.Marshal(v02.Cmd)
		default:
			t.Errorf("unknown section %s in offsets", name)
			continue
		}
		if werr != nil {
			t.Errorf("re-marshal %s: %v", name, werr)
			continue
		}
		if !bytesEqual(got, want) {
			t.Errorf("section %s round-trip mismatch:\n  got  (%d bytes): %s\n  want (%d bytes): %s",
				name, len(got), truncate(string(got), 80), len(want), truncate(string(want), 80))
		}
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
