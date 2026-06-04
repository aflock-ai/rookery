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

// Fuzz + adversarial edge-case coverage for the v0.2 wire codec.
//
// THREAT MODEL: `cilock verify` decodes attestations pulled from a multi-tenant
// Archivista — i.e. UNTRUSTED, attacker-influenced bytes flow through
// CommandRun.UnmarshalJSON -> FromV02. A panic there is a verifier DoS. These
// tests assert the decoder is total (never panics) on arbitrary input, and that
// the decode->encode->decode round-trip is a stable fixpoint.

package commandrun

import (
	"crypto"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// FuzzCommandRun_UnmarshalNoPanic feeds arbitrary bytes to the v0.2 decoder.
// The ONLY invariant is total-ness: malformed/malicious input may error, but it
// must never panic (index-out-of-range on interned ids, nil deref on _meta,
// etc.). This guards the verify path against a hostile attestation.
func FuzzCommandRun_UnmarshalNoPanic(f *testing.F) {
	// Seeds: realistic bodies + nasty shapes the decoder must survive.
	seedBodies(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		var rc CommandRun
		_ = json.Unmarshal(data, &rc) // must not panic; error is fine
		// If it decoded, re-marshalling must also not panic.
		_, _ = json.Marshal(&rc)
	})
}

// FuzzV02_DecodeReencodeStable fuzzes the wire form, decodes it, then runs the
// real produce->verify path (MarshalJSON=v0.2 -> UnmarshalJSON) and asserts the
// second decode equals the first. Once FromV02 has normalized arbitrary input,
// the round-trip must be a fixpoint — this catches interning/de-interning drift
// the static tests miss.
func FuzzV02_DecodeReencodeStable(f *testing.F) {
	seedBodies(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		var p V02Predicate
		if json.Unmarshal(data, &p) != nil {
			return // not a v0.2 body; nothing to assert
		}
		rc := FromV02(&p)
		if rc == nil {
			return
		}
		out, err := json.Marshal(rc) // v0.2 via MarshalJSON
		if err != nil {
			t.Fatalf("re-marshal of decoded predicate failed: %v", err)
		}
		var rc2 CommandRun
		if err := json.Unmarshal(out, &rc2); err != nil {
			t.Fatalf("re-unmarshal failed on our own output: %v\n%s", err, truncate(string(out), 200))
		}
		if !reflect.DeepEqual(rc.Processes, rc2.Processes) {
			t.Errorf("decode->encode->decode not stable for processes")
		}
		if rc.ExitCode != rc2.ExitCode || rc.Stdout != rc2.Stdout || rc.Stderr != rc2.Stderr {
			t.Errorf("scalar drift: exit %d/%d stdout %q/%q", rc.ExitCode, rc2.ExitCode, rc.Stdout, rc2.Stdout)
		}
		if !reflect.DeepEqual(rc.keyGuard, rc2.keyGuard) {
			t.Errorf("keyGuard drift: %+v vs %+v", rc.keyGuard, rc2.keyGuard)
		}
	})
}

// seedBodies registers a varied corpus so the fuzzer starts from realistic
// structure and known-nasty shapes rather than random noise.
func seedBodies(f *testing.F) {
	f.Helper()
	add := func(v any) {
		b, err := json.Marshal(v)
		if err == nil {
			f.Add(b)
		}
	}
	add(richCommandRun().ToV02())
	add(synthCommandRun().ToV02())
	add(New().ToV02()) // empty
	// Hand-built nasties: out-of-range ids, nil tables, duplicate digests.
	f.Add([]byte(`{"_meta":{"version":"v0.2"}}`))
	f.Add([]byte(`{"_meta":{"version":"v0.2","keyGuard":null},"processes":[{"processid":1,"commId":99,"execPathId":-7,"openedFiles":[{"pathId":42,"digestId":-3}]}]}`))
	f.Add([]byte(`{"processes":[{"openedFiles":[{"pathId":0,"digestId":0}]}],"paths":[],"digests":[]}`))
	f.Add([]byte(`{"_meta":{"version":"v0.2"},"paths":["/a"],"digests":[{"digests":{"sha256":"` + strings.Repeat("a", 64) + `"}}],"processes":[{"openedFiles":[{"pathId":0,"digestId":0}]}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
}

// TestV02_Edge_OutOfRangeIDs pins that a predicate with interned ids pointing
// outside every table decodes WITHOUT panic and simply drops the dangling
// references (a malicious uploader can't crash verify, nor smuggle a phantom
// entry).
func TestV02_Edge_OutOfRangeIDs(t *testing.T) {
	p := &V02Predicate{
		Paths:   []string{"/real/path"},
		Digests: []V02DigestEntry{{Digests: map[string]string{"sha256": strings.Repeat("a", 64)}}},
		Processes: []V02Process{{
			ProcessID:       7,
			ParentPID:       1,
			CommID:          99,      // out of range (no comms table)
			ExecPathID:      -42,     // negative beyond the -1 sentinel
			CmdlineID:       1 << 30, // absurd
			ProgramDigestID: 5,       // out of range
			ExeDigestID:     -1,      // absent
			OpenedFiles: []V02FileRef{
				{PathID: 99, DigestID: 99}, // both dangling -> skipped
				{PathID: 0, DigestID: 0},   // both valid -> kept
			},
			FsVerity:      []V02FsVerity{{PathID: 500, Value: "sha256:x"}}, // dangling -> skipped
			UnhashedOpens: []V02UnhashedOpen{{PathID: -9, Reason: "race"}}, // dangling path -> ""
		}},
	}

	rc := FromV02(p) // must not panic
	got := rc.Processes[0]

	if got.Comm != "" || got.Program != "" || got.Cmdline != "" || got.ProgramDigest != nil {
		t.Errorf("dangling single-value ids should resolve to empty, got comm=%q prog=%q cmdline=%q pdigest=%v",
			got.Comm, got.Program, got.Cmdline, got.ProgramDigest)
	}
	// Only the in-range opened-file survives, mapped to the real path+digest.
	if len(got.OpenedFiles) != 1 || got.OpenedFiles["/real/path"] == nil {
		t.Errorf("expected exactly the in-range opened file to survive; got %v", got.OpenedFiles)
	}
	if got.FsVerityDigests != nil {
		t.Errorf("dangling fsverity ref should be dropped; got %v", got.FsVerityDigests)
	}
}

// TestV02_Edge_GitoidDigest pins that non-sha256 supported hashes (gitoid)
// round-trip — the digest interning must use the full name-map, not a sha256
// fast-path that would silently drop gitoids.
func TestV02_Edge_GitoidDigest(t *testing.T) {
	ds := cryptoutil.DigestSet{
		cryptoutil.DigestValue{Hash: crypto.SHA256}:               strings.Repeat("a", 64),
		cryptoutil.DigestValue{Hash: crypto.SHA1, GitOID: true}:   "gitoid:blob:sha1:" + strings.Repeat("b", 40),
		cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: true}: "gitoid:blob:sha256:" + strings.Repeat("c", 64),
	}
	rc := New()
	rc.Cmd = []string{"x"}
	rc.Processes = []ProcessInfo{{ProcessID: 1, OpenedFiles: map[string]cryptoutil.DigestSet{"/f": ds}}}

	back := FromV02(rc.ToV02())
	if !reflect.DeepEqual(rc.Processes[0].OpenedFiles, back.Processes[0].OpenedFiles) {
		t.Errorf("gitoid multi-hash digest lost in round-trip:\n want %v\n got  %v",
			rc.Processes[0].OpenedFiles, back.Processes[0].OpenedFiles)
	}
}

// TestV02_Edge_DedupAtScale pins interning correctness at scale: N processes
// sharing the same K paths/digests must collapse to K table entries, and the
// de-interned view must match every original mapping.
func TestV02_Edge_DedupAtScale(t *testing.T) {
	const procs, paths = 200, 30
	mk := func(i int) (string, cryptoutil.DigestSet) {
		p := "/usr/include/h" + strings.Repeat("x", i%paths)
		return p, cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: strings.Repeat("0", 63) + string(rune('a'+i%paths%16))}
	}
	rc := New()
	rc.Cmd = []string{"build"}
	for pid := 0; pid < procs; pid++ {
		pi := ProcessInfo{ProcessID: pid, OpenedFiles: map[string]cryptoutil.DigestSet{}}
		for i := 0; i < paths; i++ {
			p, d := mk(pid*paths + i)
			pi.OpenedFiles[p] = d
		}
		rc.Processes = append(rc.Processes, pi)
	}

	v02 := rc.ToV02()
	if len(v02.Paths) > paths {
		t.Errorf("paths[] not deduped: %d > %d", len(v02.Paths), paths)
	}
	back := FromV02(v02)
	for i := range rc.Processes {
		if !reflect.DeepEqual(rc.Processes[i].OpenedFiles, back.Processes[i].OpenedFiles) {
			t.Fatalf("proc %d opened-files lost in dedup round-trip", i)
		}
	}
}

// TestV02_Edge_UnicodeAndControlChars pins that exotic path/cmdline bytes
// (unicode, quotes, newlines, NUL-ish) survive interning + JSON round-trip.
func TestV02_Edge_UnicodeAndControlChars(t *testing.T) {
	weird := []string{
		"/päth/ünïcode/文件.go",
		"/path/with \"quotes\" and \n newline",
		"/emoji/🔐/key",
		"/tab\tand\\backslash",
	}
	rc := New()
	rc.Cmd = []string{"x"}
	pi := ProcessInfo{ProcessID: 1, Cmdline: strings.Join(weird, " "), OpenedFiles: map[string]cryptoutil.DigestSet{}}
	for i, w := range weird {
		pi.OpenedFiles[w] = cryptoutil.DigestSet{cryptoutil.DigestValue{Hash: crypto.SHA256}: strings.Repeat("0", 63) + string(rune('a'+i))}
	}
	rc.Processes = []ProcessInfo{pi}

	out, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got CommandRun
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(rc.Processes[0].OpenedFiles, got.Processes[0].OpenedFiles) {
		t.Errorf("unicode/control paths lost in JSON round-trip")
	}
	if got.Processes[0].Cmdline != pi.Cmdline {
		t.Errorf("cmdline corrupted: want %q got %q", pi.Cmdline, got.Processes[0].Cmdline)
	}
}

// TestV02_Edge_CanonicalDigestKey_NoCollision pins that distinct digest sets
// never share an intern slot (a collision would let one file's digest stand in
// for another's). Includes the tricky case where one set's value contains the
// separator chars used by the key encoder.
func TestV02_Edge_CanonicalDigestKey_NoCollision(t *testing.T) {
	cases := []map[string]string{
		{"sha256": "aa", "sha1": "bb"},
		{"sha256": "aa;sha1=bb"}, // value embeds the key's separators
		{"sha256": "aa", "sha1": "cc"},
		{"sha1": "aa", "sha256": "bb"}, // same pairs, different roles
	}
	seen := map[string]int{}
	for i, c := range cases {
		k := canonicalDigestKey(c)
		if j, ok := seen[k]; ok {
			t.Errorf("digest key collision: case %d and %d both -> %q", j, i, k)
		}
		seen[k] = i
	}
}

// TestV02_Edge_EmptyAndNilCommandRun pins that the degenerate shapes (no
// processes, nil everything) marshal and round-trip cleanly.
func TestV02_Edge_EmptyAndNilCommandRun(t *testing.T) {
	for name, rc := range map[string]*CommandRun{
		"empty":     New(),
		"cmd-only":  func() *CommandRun { r := New(); r.Cmd = []string{"true"}; return r }(),
		"nil-procs": func() *CommandRun { r := New(); r.Processes = nil; return r }(),
	} {
		out, err := json.Marshal(rc)
		if err != nil {
			t.Errorf("%s: marshal: %v", name, err)
			continue
		}
		if !strings.HasPrefix(string(out), `{"_meta":`) {
			t.Errorf("%s: must lead with _meta; got %s", name, truncate(string(out), 48))
		}
		var got CommandRun
		if err := json.Unmarshal(out, &got); err != nil {
			t.Errorf("%s: unmarshal: %v", name, err)
		}
	}
}
