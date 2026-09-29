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

// jade:ring local

package commandrun

// These tests read the program record from the SIGNED wire form, the bytes
// MarshalJSON produces, never from the Go struct. A field that is computed but
// dropped on the way to the wire is evidence the attestor collected and threw
// away, and only a test on the bytes can see that. They are written against
// the JSON on purpose, so they compile against a CommandRun that has no program
// record at all and fail there for the right reason.
//
// Design: docs/design/command-program-pinning.md, sections 3.1, 3.3 and 3.4
// (lane P1a). Binding decisions: every run records the program, with no flag
// and no dependence on --trace; the record carries the path the lookup
// resolved AND the real path after symlinks; the only permitted absence of a
// digest is a program cilock cannot read, and the record then says why.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
)

const programTestScript = "#!/bin/sh\nexit 0\n"

// runForProgram runs argv through the real Attest path and returns the
// program record as the wire carries it, or nil when the wire has none.
func runForProgram(t *testing.T, argv []string, workdir string, opts ...Option) (*CommandRun, map[string]any) {
	t.Helper()
	rc, err := attestForProgram(t, argv, workdir, opts...)
	if err != nil {
		t.Fatalf("Attest %v: %v", argv, err)
	}
	return rc, wireProgram(t, rc)
}

func attestForProgram(t *testing.T, argv []string, workdir string, opts ...Option) (*CommandRun, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	actx, err := attestation.NewContext("program-record-test", []attestation.Attestor{},
		attestation.WithContext(ctx), attestation.WithWorkingDir(workdir))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	all := append([]Option{WithCommand(argv), WithSilent(true), WithScriptCapture(ScriptCaptureOff)}, opts...)
	rc := New(all...)
	return rc, rc.Attest(actx)
}

func wireProgram(t *testing.T, rc *CommandRun) map[string]any {
	t.Helper()
	raw, err := json.Marshal(rc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal wire: %v", err)
	}
	p, _ := body["program"].(map[string]any)
	return p
}

func writeProgramScript(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil { //nolint:gosec // an executable fixture must be executable
		t.Fatal(err)
	}
}

func programSHA256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func sha256OfFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // test fixture
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func realPathOf(t *testing.T, path string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func wireStr(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func wireSHA256(m map[string]any) string {
	d, _ := m["digest"].(map[string]any)
	s, _ := d["sha256"].(string)
	return s
}

// requireHashedProgram asserts the record every readable program must carry.
func requireHashedProgram(t *testing.T, p map[string]any, wantLookup, wantPath, wantRealPath string, content []byte) {
	t.Helper()
	if p == nil {
		t.Fatal("the signed predicate has no program record")
	}
	if got := wireStr(p, "lookup"); got != wantLookup {
		t.Errorf("lookup = %q, want %q", got, wantLookup)
	}
	if got := wireStr(p, "path"); got != wantPath {
		t.Errorf("path = %q, want the exec's own lookup result %q", got, wantPath)
	}
	if got := wireStr(p, "realPath"); got != wantRealPath {
		t.Errorf("realPath = %q, want %q", got, wantRealPath)
	}
	if got := wireSHA256(p); got != programSHA256Hex(content) {
		t.Errorf("digest.sha256 = %q, want the sha256 of the program's bytes %q", got, programSHA256Hex(content))
	}
	if got, _ := p["sizeBytes"].(float64); int(got) != len(content) {
		t.Errorf("sizeBytes = %v, want %d", p["sizeBytes"], len(content))
	}
	if u := wireStr(p, "unresolved"); u != "" {
		t.Errorf("a readable program recorded unresolved %q", u)
	}
	requireUnverifiedBinding(t, p)
}

// requireUnverifiedBinding: this build never binds the program to the exec
// (lane P3c does), so every record must say "unverified", with a reason, and
// must say it explicitly rather than by omission.
func requireUnverifiedBinding(t *testing.T, p map[string]any) {
	t.Helper()
	b, present := p["executionBinding"]
	if !present {
		t.Fatal("executionBinding is absent: the binding status must always be emitted")
	}
	if b != "unverified" {
		t.Errorf("executionBinding = %v, want \"unverified\": this build does not bind the program to the exec", b)
	}
	if wireStr(p, "bindingReason") == "" {
		t.Error("an unverified program record carries no bindingReason")
	}
}

// TestEveryRunRecordsTheProgram is the 05:03Z decision in one test: a run with
// no --trace and with script capture off still records the program argv[0]
// started, hashed, with its binding status.
func TestEveryRunRecordsTheProgram(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script as the program")
	}
	bin := t.TempDir()
	tool := filepath.Join(bin, "p1a-tool")
	writeProgramScript(t, tool, programTestScript)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	workdir := t.TempDir()

	rc, p := runForProgram(t, []string{"p1a-tool"}, workdir)
	if rc.TracingEnabled() {
		t.Fatal("precondition: this run must be untraced")
	}
	requireHashedProgram(t, p, "path-search", tool, realPathOf(t, tool), []byte(programTestScript))

	if got := wireStr(p, "host"); got != runtime.GOOS+"/"+runtime.GOARCH {
		t.Errorf("host = %q, want %q", got, runtime.GOOS+"/"+runtime.GOARCH)
	}
	if got := wireStr(p, "workdir"); got != realPathOf(t, workdir) {
		t.Errorf("workdir = %q, want the directory the child started in, %q", got, realPathOf(t, workdir))
	}
	if got := wireStr(p, "format"); got != "script" {
		t.Errorf("format = %q, want \"script\" for a #! file", got)
	}
	checkout, _ := p["checkout"].(map[string]any)
	if checkout == nil {
		t.Fatal("the record has no checkout block")
	}
	// Containment is lane P1c. Until then the relation is always unknown, with
	// the reason, and NEVER outside: a build that did not compute it must not
	// be able to satisfy a rule that requires it.
	if got := wireStr(checkout, "relation"); got != "unknown" {
		t.Errorf("checkout.relation = %q, want \"unknown\" until containment is computed", got)
	}
	if wireStr(checkout, "reason") == "" {
		t.Error("an unknown checkout relation carries no reason")
	}
}

// TestProgramPathIsTheExecsLookup: the recorded path is the one the exec's own
// lookup produced, for each of the three forms argv[0] can take.
func TestProgramPathIsTheExecsLookup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell scripts as programs; the Windows lookup is lane P1b")
	}

	t.Run("bare name: the first of two PATH directories", func(t *testing.T) {
		first, second := t.TempDir(), t.TempDir()
		want := filepath.Join(first, "p1a-dup")
		writeProgramScript(t, want, programTestScript)
		writeProgramScript(t, filepath.Join(second, "p1a-dup"), "#!/bin/sh\n# the shadowed copy\nexit 0\n")
		t.Setenv("PATH", first+string(os.PathListSeparator)+second+string(os.PathListSeparator)+os.Getenv("PATH"))

		_, p := runForProgram(t, []string{"p1a-dup"}, t.TempDir())
		requireHashedProgram(t, p, "path-search", want, realPathOf(t, want), []byte(programTestScript))
	})

	t.Run("relative ./t is resolved against the working directory, uncleaned", func(t *testing.T) {
		workdir := t.TempDir()
		writeProgramScript(t, filepath.Join(workdir, "t"), programTestScript)
		// The exec runs c.Dir + "/" + "./t" (exec.go: a relative Path is
		// evaluated relative to Dir), and c.Dir is the resolved working
		// directory. The record keeps "./" as the kernel will walk it.
		wantPath := realPathOf(t, workdir) + string(os.PathSeparator) + "./t"
		_, p := runForProgram(t, []string{"./t"}, workdir)
		requireHashedProgram(t, p, "workdir-relative", wantPath, realPathOf(t, filepath.Join(workdir, "t")), []byte(programTestScript))
	})

	t.Run("relative bin/tool", func(t *testing.T) {
		workdir := t.TempDir()
		writeProgramScript(t, filepath.Join(workdir, "bin", "tool"), programTestScript)
		wantPath := realPathOf(t, workdir) + string(os.PathSeparator) + "bin/tool"
		_, p := runForProgram(t, []string{"bin/tool"}, workdir)
		requireHashedProgram(t, p, "workdir-relative", wantPath, realPathOf(t, filepath.Join(workdir, "bin", "tool")), []byte(programTestScript))
	})

	t.Run("absolute path is recorded as given", func(t *testing.T) {
		abs := filepath.Join(t.TempDir(), "abs-tool")
		writeProgramScript(t, abs, programTestScript)
		_, p := runForProgram(t, []string{abs}, t.TempDir())
		requireHashedProgram(t, p, "absolute", abs, realPathOf(t, abs), []byte(programTestScript))
	})

	t.Run("a dot in PATH is refused before anything runs", func(t *testing.T) {
		dir := t.TempDir()
		writeProgramScript(t, filepath.Join(dir, "p1a-dotted"), programTestScript)
		t.Chdir(dir)
		t.Setenv("PATH", "."+string(os.PathListSeparator)+os.Getenv("PATH"))
		_, err := attestForProgram(t, []string{"p1a-dotted"}, t.TempDir())
		if !errors.Is(err, exec.ErrDot) {
			t.Fatalf("Attest error = %v, want exec.ErrDot: a current-directory PATH hit must not run, so no record can describe it", err)
		}
	})
}

// TestSymlinkedProgramRecordsBothPaths: argv[0] found on PATH as a symlink
// records the path the lookup found AND the real path, and the digest is of
// the real file's bytes, never of the link.
func TestSymlinkedProgramRecordsBothPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX symlinks and scripts")
	}
	bin, store := t.TempDir(), t.TempDir()
	target := filepath.Join(store, "versions", "tool-1.2.3")
	writeProgramScript(t, target, programTestScript)
	link := filepath.Join(bin, "p1a-linked")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, p := runForProgram(t, []string{"p1a-linked"}, t.TempDir())
	requireHashedProgram(t, p, "path-search", link, realPathOf(t, target), []byte(programTestScript))
	if wireStr(p, "path") == wireStr(p, "realPath") {
		t.Error("path and realPath are equal for a symlinked program: one of the two was not recorded")
	}
}

// TestLargeProgramHashedWhole: the 64 MiB script ceiling does not apply to the
// program. Every readable byte is hashed (Q1).
func TestLargeProgramHashedWhole(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script as the program")
	}
	if testing.Short() {
		t.Skip("hashes 65 MiB")
	}
	path := filepath.Join(t.TempDir(), "big-tool")
	writeProgramScript(t, path, programTestScript)
	// The shell exits at line 2 and never reads the sparse tail.
	if err := os.Truncate(path, 65<<20); err != nil {
		t.Fatal(err)
	}
	_, p := runForProgram(t, []string{path}, t.TempDir())
	if p == nil {
		t.Fatal("no program record")
	}
	if got := wireSHA256(p); got != sha256OfFile(t, path) {
		t.Fatalf("digest.sha256 = %q, want the sha256 of all 65 MiB (%s)", got, sha256OfFile(t, path))
	}
	if got, _ := p["sizeBytes"].(float64); int64(got) != 65<<20 {
		t.Fatalf("sizeBytes = %v, want %d", p["sizeBytes"], 65<<20)
	}
}

// TestUnreadableProgramIsRecordedWithReason: an execute-only program still
// runs, and its record has no digest and says why. This is the only permitted
// absence of a digest.
func TestUnreadableProgramIsRecordedWithReason(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	if os.Geteuid() == 0 {
		t.Skip("precondition: not root; root can read a mode 0111 file, so nothing is unreadable")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(self) //nolint:gosec // the running test binary
	if err != nil {
		t.Fatal(err)
	}
	// A native binary, because the kernel can exec an execute-only native
	// image, while an interpreter cannot read an execute-only script.
	prog := filepath.Join(t.TempDir(), "execute-only")
	if err := os.WriteFile(prog, body, 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.Chmod(prog, 0o111); err != nil { //nolint:gosec // the point of the test is an execute-only file
		t.Fatal(err)
	}
	if _, err := os.Open(prog); err == nil { //nolint:gosec // probing the precondition
		t.Fatal("precondition: the fixture is still readable")
	}

	rc, p := runForProgram(t, []string{prog, "-test.run=^$"}, t.TempDir())
	if rc.ExitCode != 0 {
		t.Fatalf("the execute-only program did not run cleanly: exit %d", rc.ExitCode)
	}
	if p == nil {
		t.Fatal("an unreadable program left no record: the absence must be recorded, not silent")
	}
	if d := p["digest"]; d != nil {
		t.Fatalf("an unreadable program carries a digest: %v", d)
	}
	if got := wireStr(p, "unresolved"); got != "permission denied: the program is executable but not readable" {
		t.Fatalf("unresolved = %q, want the permission-denied reason", got)
	}
	if got := wireStr(p, "path"); got != prog {
		t.Errorf("path = %q, want %q", got, prog)
	}
	if got := wireStr(p, "realPath"); got != realPathOf(t, prog) {
		t.Errorf("realPath = %q, want %q", got, realPathOf(t, prog))
	}
	requireUnverifiedBinding(t, p)
}

// TestProgramRecordedWithTraceOnAndOff: the record does not depend on --trace.
func TestProgramRecordedWithTraceOnAndOff(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("no tracing backend on this platform")
	}
	path := filepath.Join(t.TempDir(), "traced-tool")
	writeProgramScript(t, path, programTestScript)

	_, off := runForProgram(t, []string{path}, t.TempDir())
	requireHashedProgram(t, off, "absolute", path, realPathOf(t, path), []byte(programTestScript))

	if runtime.GOOS == "linux" {
		t.Setenv(EnvVarTraceMode, traceModeNamePtraceForTest)
	}
	rc, err := attestForProgram(t, []string{path}, t.TempDir(), WithTracing(true))
	if err != nil {
		t.Skipf("precondition: tracing is unavailable on this host (%v); the untraced half above ran", err)
	}
	on := wireProgram(t, rc)
	requireHashedProgram(t, on, "absolute", path, realPathOf(t, path), []byte(programTestScript))
	if runtime.GOOS == "darwin" {
		w, _ := on["wrapper"].(map[string]any)
		if wireStr(w, "kind") != "sandbox-exec" || wireStr(w, "path") == "" || wireSHA256(w) == "" {
			t.Errorf("a traced macOS run starts the program through sandbox-exec; wrapper = %v", on["wrapper"])
		}
	}
}

const traceModeNamePtraceForTest = "ptrace"

// v02BodyWithProgram is a minimal signed-shape command-run/v0.2 body carrying
// the given program JSON.
func v02BodyWithProgram(program string) []byte {
	return []byte(`{"_meta":{"version":"v0.2","counts":{"processes":0,"uniquePaths":0,"uniqueDigests":0,"uniqueComms":0}},` +
		`"digests":[],"paths":[],"comms":[],"processes":[],"cmd":["terraform","plan"],"exitcode":0,` +
		`"program":` + program + `}`)
}

// TestAbsentRelationDecodesAsNotOutside: signed bytes whose checkout block
// lacks the relation key, or lack the checkout block entirely, go through the
// production decode (json.Unmarshal into CommandRun) and back out, as Rego
// input is built. The relation must come out as something other than
// "outside", and the key must still be there, so a rule reading it sees an
// explicit non-outside value rather than a Go zero value read as a verdict.
func TestAbsentRelationDecodesAsNotOutside(t *testing.T) {
	cases := map[string]string{
		"relation key absent":   `{"path":"/usr/bin/terraform","executionBinding":"unverified","checkout":{"root":"/src/app"}}`,
		"checkout block absent": `{"path":"/usr/bin/terraform","executionBinding":"unverified"}`,
	}
	for name, program := range cases {
		t.Run(name, func(t *testing.T) {
			var rc CommandRun
			if err := json.Unmarshal(v02BodyWithProgram(program), &rc); err != nil {
				t.Fatalf("production decode: %v", err)
			}
			p := wireProgram(t, &rc)
			if p == nil {
				t.Fatal("the decoder dropped the program record: a verifier would show Rego no program at all")
			}
			checkout, _ := p["checkout"].(map[string]any)
			if checkout == nil {
				t.Fatal("re-marshalled record has no checkout block")
			}
			rel, present := checkout["relation"]
			if !present {
				t.Fatal("re-marshalled checkout has no relation key: the relation must always be emitted")
			}
			if rel == "outside" {
				t.Fatal("an absent relation decoded as \"outside\"")
			}
			if _, present := p["executionBinding"]; !present {
				t.Fatal("re-marshalled record has no executionBinding key")
			}
		})
	}
}

// TestProgramBindingAndRelationAlwaysEmitted: a record whose binding and
// relation are the zero value still carries both keys on the wire. omitempty
// on either makes an honest "unknown" indistinguishable from an old producer.
func TestProgramBindingAndRelationAlwaysEmitted(t *testing.T) {
	var rc CommandRun
	if err := json.Unmarshal(v02BodyWithProgram(`{"path":"/bin/x"}`), &rc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	p := wireProgram(t, &rc)
	if p == nil {
		t.Fatal("no program record after a round trip")
	}
	for _, key := range []string{"executionBinding", "checkout"} {
		if _, ok := p[key]; !ok {
			t.Errorf("key %q is not emitted for a zero value", key)
		}
	}
	checkout, _ := p["checkout"].(map[string]any)
	if _, ok := checkout["relation"]; !ok {
		t.Error("checkout.relation is not emitted for a zero value")
	}
	if wireStr(p, "executionBinding") == "verified" {
		t.Error("a zero binding came out as verified")
	}
}
