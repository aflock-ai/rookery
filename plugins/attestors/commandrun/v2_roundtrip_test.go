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

// v0.2 round-trip invariants: the producer flip is only correct if ToV02 +
// FromV02 (and the JSON MarshalJSON/UnmarshalJSON that wrap them) preserve
// every security-relevant field, while deliberately dropping the pruned ones.

package commandrun

import (
	"crypto"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// richCommandRun builds a CommandRun exercising every field v0.2 carries —
// the read/write/fsverity/unhashed digest maps, network egress, file-ops,
// syscalls, per-process exit codes, program/exe digests — PLUS the two fields
// v0.2 deliberately drops (Environ, SpecBypassIsVuln) so the prune is
// asserted, not assumed.
func richCommandRun() *CommandRun {
	sha := func(hex string) cryptoutil.DigestSet {
		return cryptoutil.DigestSet{{Hash: crypto.SHA256}: strings.Repeat("0", 64-len(hex)) + hex}
	}
	// sha256 + sha1 — both registered in cryptoutil (sha512 is NOT, so the
	// real tracer never emits it); exercises the multi-hash intern path.
	multi := func(s256, s1 string) cryptoutil.DigestSet {
		return cryptoutil.DigestSet{
			{Hash: crypto.SHA256}: strings.Repeat("0", 64-len(s256)) + s256,
			{Hash: crypto.SHA1}:   strings.Repeat("0", 40-len(s1)) + s1,
		}
	}
	rc := New()
	rc.Cmd = []string{"go", "build", "-o", "app", "."}
	rc.ExitCode = 2 // non-zero so the exitcode section is exercised (it was being dropped)
	rc.Stdout = "compiling main.go\nlinking app\n"
	rc.Stderr = "warning: deprecated API used\n"
	rc.Summary = &TraceSummary{CaptureMode: "ebpf-readtap", TraceModeDetail: "eBPF kprobes + read-tap"}
	rc.Processes = []ProcessInfo{
		{
			Program:       "/usr/local/go/bin/go",
			ProcessID:     1000,
			ParentPID:     999,
			ProgramDigest: sha("aa"),
			Comm:          "go",
			Cmdline:       "go build -o app .",
			ExeDigest:     multi("bb", "cc"),
			OpenedFiles: map[string]cryptoutil.DigestSet{
				"/usr/include/stdio.h": sha("11"),
				"/home/u/main.go":      sha("22"),
			},
			WrittenDigests:  map[string]cryptoutil.DigestSet{"/home/u/app": sha("33")},
			FsVerityDigests: map[string]string{"/home/u/app": "sha256:deadbeef"},
			UnhashedOpens:   []UnhashedOpen{{Path: "/tmp/cc1.s", Reason: "file removed before hash"}},
			Network:         &NetworkActivity{DNSLookups: []DNSLookup{{ServerAddress: "1.1.1.1", ServerPort: 443}}},
			FileOps:         &FileActivity{Writes: []FileWrite{{Path: "/home/u/app", Bytes: 42}}},
			SyscallEvents:   []SyscallEvent{{Syscall: "memfd_create", Detail: "anon", Path: "/memfd:x"}},
			ExitCode:        0,
			// Pruned fields — set so the prune is observable.
			Environ:          "AWS_SECRET_ACCESS_KEY=should-not-survive\nPATH=/usr/bin\n",
			SpecBypassIsVuln: true,
		},
		{
			Program:   "/usr/local/go/pkg/tool/linux_arm64/compile",
			ProcessID: 1001,
			ParentPID: 1000,
			Comm:      "compile",
			OpenedFiles: map[string]cryptoutil.DigestSet{
				"/usr/include/stdio.h": sha("11"), // shared content → dedups in digests[]
			},
		},
	}
	return rc
}

// pruned returns a copy of want with the deliberately-dropped fields zeroed,
// so reflect.DeepEqual reflects the intended v0.2 shape.
func prunedProcesses(src []ProcessInfo) []ProcessInfo {
	out := make([]ProcessInfo, len(src))
	copy(out, src)
	for i := range out {
		out[i].Environ = ""
		out[i].SpecBypassIsVuln = false
	}
	return out
}

// TestV02_RoundTrip_PreservesEvidence is the load-bearing correctness gate:
// FromV02(ToV02(x)) reconstructs every security-relevant field of x exactly.
func TestV02_RoundTrip_PreservesEvidence(t *testing.T) {
	rc := richCommandRun()
	back := FromV02(rc.ToV02())

	if !reflect.DeepEqual(rc.Cmd, back.Cmd) {
		t.Errorf("cmd drift:\n want %v\n got  %v", rc.Cmd, back.Cmd)
	}
	if rc.ExitCode != back.ExitCode {
		t.Errorf("exitcode drift: want %d got %d", rc.ExitCode, back.ExitCode)
	}
	if rc.Stdout != back.Stdout || rc.Stderr != back.Stderr {
		t.Errorf("stdout/stderr drift:\n want %q / %q\n got  %q / %q", rc.Stdout, rc.Stderr, back.Stdout, back.Stderr)
	}
	if !reflect.DeepEqual(rc.Summary, back.Summary) {
		t.Errorf("summary drift:\n want %+v\n got  %+v", rc.Summary, back.Summary)
	}

	want := prunedProcesses(rc.Processes)
	if !reflect.DeepEqual(want, back.Processes) {
		t.Errorf("process round-trip is lossy.\n want %#v\n got  %#v", want, back.Processes)
	}
}

// TestV02_RoundTrip_DropsPrunedFields pins that Environ and SpecBypassIsVuln
// are gone from the v0.2 wire AND from the de-interned result — never round-
// trip the secret-leak / noise fields back in.
func TestV02_RoundTrip_DropsPrunedFields(t *testing.T) {
	rc := richCommandRun()
	out, err := json.Marshal(rc) // v0.2
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "AWS_SECRET_ACCESS_KEY") || strings.Contains(string(out), "environ") {
		t.Errorf("v0.2 wire leaked per-process Environ — secret-leak prune failed")
	}
	if strings.Contains(string(out), "specbypassisvuln") {
		t.Errorf("v0.2 wire carried specbypassisvuln — prune failed")
	}

	back := FromV02(rc.ToV02())
	if back.Processes[0].Environ != "" {
		t.Errorf("Environ survived the round-trip: %q", back.Processes[0].Environ)
	}
	if back.Processes[0].SpecBypassIsVuln {
		t.Errorf("SpecBypassIsVuln survived the round-trip")
	}
}

// TestV02_RoundTrip_EmptyMapsNormalizeToNil pins the documented normalization:
// an empty (non-nil) digest/fsverity map reconstructs as nil, CONSISTENTLY, in
// both the direct ToV02/FromV02 path and the JSON path. The v0.2 wire's
// omitempty tags can't carry the empty-vs-absent distinction, so normalizing to
// nil is the honest, consistent behavior — not a lossy gap. (Surfaced by the
// adversarial review of the producer flip.)
func TestV02_RoundTrip_EmptyMapsNormalizeToNil(t *testing.T) {
	rc := New()
	rc.Cmd = []string{"true"}
	rc.Processes = []ProcessInfo{{
		ProcessID:       1,
		OpenedFiles:     map[string]cryptoutil.DigestSet{}, // empty, non-nil
		WrittenDigests:  map[string]cryptoutil.DigestSet{}, // empty, non-nil
		FsVerityDigests: map[string]string{},               // empty, non-nil
	}}

	p := FromV02(rc.ToV02()).Processes[0]
	if p.OpenedFiles != nil || p.WrittenDigests != nil || p.FsVerityDigests != nil {
		t.Errorf("empty maps must normalize to nil; got opened=%v written=%v fsverity=%v",
			p.OpenedFiles, p.WrittenDigests, p.FsVerityDigests)
	}

	// JSON path (the real produce→verify path) agrees.
	out, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got CommandRun
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Processes[0].OpenedFiles != nil {
		t.Errorf("JSON round-trip must normalize empty OpenedFiles to nil; got %v", got.Processes[0].OpenedFiles)
	}
}

// TestV02_JSONRoundTrip_ViaAttestorMethods pins the real produce→verify path:
// CommandRun.MarshalJSON (v0.2 wire) → CommandRun.UnmarshalJSON reconstructs
// the trace a verifier reads via Data(). Leads with _meta.
func TestV02_JSONRoundTrip_ViaAttestorMethods(t *testing.T) {
	rc := richCommandRun()
	rc.keyGuard = &V02KeyGuard{Applied: true, Dumpable: false, YamaPtraceScope: 1}

	out, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.HasPrefix(string(out), `{"_meta":`) {
		t.Errorf("v0.2 body must lead with _meta; got %s", truncate(string(out), 64))
	}

	var got CommandRun
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := prunedProcesses(rc.Processes)
	if !reflect.DeepEqual(want, got.Processes) {
		t.Errorf("JSON round-trip lossy.\n want %#v\n got  %#v", want, got.Processes)
	}
	// exitcode/stdout/stderr travel through the section encoder — the path that
	// was silently dropping them before they were added to the specs list.
	if got.ExitCode != rc.ExitCode {
		t.Errorf("exitcode dropped by section encoder: want %d got %d", rc.ExitCode, got.ExitCode)
	}
	if got.Stdout != rc.Stdout || got.Stderr != rc.Stderr {
		t.Errorf("stdout/stderr dropped by section encoder:\n want %q / %q\n got  %q / %q",
			rc.Stdout, rc.Stderr, got.Stdout, got.Stderr)
	}
}

// TestV02_Registration_Routing pins the backward-compat the user requires:
// a v0.1 policy + v0.1 attestation must still verify. At the registry level
// that means the v0.1 predicate type routes to the verify-only LegacyDecoder
// (NOT the v0.2 producer, which would try to decode the inline body as
// interned and fail), while the v0.2 type routes to the CommandRun producer.
func TestV02_Registration_Routing(t *testing.T) {
	// v0.2 type → the CommandRun producer.
	pf, ok := attestation.FactoryByType(V02PredicateType)
	if !ok {
		t.Fatal("v0.2 producer not registered for " + V02PredicateType)
	}
	if _, isCR := pf().(*CommandRun); !isCR {
		t.Errorf("v0.2 type must resolve to the *CommandRun producer")
	}

	// v0.1 type → the verify-only legacy decoder, never the producer.
	lf, ok := attestation.FactoryByType(LegacyV01Type)
	if !ok {
		t.Fatal("v0.1 legacy decoder not registered — a v0.1 envelope would have no factory and backward compat would break")
	}
	dec := lf()
	if _, isCR := dec.(*CommandRun); isCR {
		t.Fatal("v0.1 type resolves to the v0.2 producer — a v0.1 attestation would be decoded as interned-v0.2 and fail to verify")
	}
	if err := dec.Attest(nil); err == nil {
		t.Error("v0.1 factory must be verify-only (Attest must refuse)")
	}
}

// TestV02_KeyGuard_TravelsInSignedBody pins the non-forgeability evidence:
// the signer's anti-tamper state must be in the _meta block (signed) and
// survive a JSON round-trip so a verifier/policy can gate an L3 verdict on it.
func TestV02_KeyGuard_TravelsInSignedBody(t *testing.T) {
	rc := richCommandRun()
	rc.keyGuard = &V02KeyGuard{Applied: true, Dumpable: false, YamaPtraceScope: 1}

	out, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"keyGuard"`) || !strings.Contains(string(out), `"dumpable":false`) {
		t.Errorf("_meta.keyGuard missing or not dumpable=false in signed body:\n%s", truncate(string(out), 400))
	}

	var got CommandRun
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.keyGuard == nil || got.keyGuard.Dumpable || !got.keyGuard.Applied {
		t.Errorf("keyGuard did not round-trip: %+v", got.keyGuard)
	}
}

// NOTE: the v0.2 contract intentionally normalizes empty and nil maps to nil
// (the omitempty wire can't distinguish them). That invariant is asserted by
// TestV02_RoundTrip_EmptyMapsNormalizeToNil above — do not add a test expecting
// empty non-nil maps to survive the round-trip; it contradicts the contract.
