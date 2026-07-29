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

package cli

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/plugins/attestors/vex"
	"github.com/aflock-ai/rookery/plugins/attestors/vex/openvex"
	"github.com/spf13/pflag"
)

func fixedVEXClock() func() time.Time {
	return func() time.Time { return time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC) }
}

func validVEXOptions(dir string) *vexAuthorOptions {
	return &vexAuthorOptions{
		Products:        []string{"ghcr.io/acme/api@sha256:d0d0caca00000000000000000000000000000000000000000000000000000000"},
		Vulns:           []string{"CVE-2024-12345"},
		Status:          "not_affected",
		Justification:   "vulnerable_code_not_in_execute_path",
		ImpactStatement: "the vulnerable parser is unreachable from the request path",
		Author:          "cilock",
		OutFile:         filepath.Join(dir, "vex.openvex.json"),
		now:             fixedVEXClock(),
	}
}

// TestAttestKeepsFlagDrivenInvocation is the regression guard for adding
// a subcommand to `attest`: the existing no-subcommand form must keep
// resolving to attest itself, and attest must still refuse positional
// args (use `cilock run` for a wrapped command).
func TestAttestKeepsFlagDrivenInvocation(t *testing.T) {
	attest := AttestCmd()

	if attest.RunE == nil {
		t.Fatal("attest lost its RunE — the flag-driven invocation would stop working")
	}

	// `cilock attest -a github-review …` must land on attest, not a
	// subcommand, and survive arg validation once its flags are parsed.
	target, rest, err := attest.Find([]string{"-a", "github-review", "-s", "review"})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if target.Name() != "attest" {
		t.Errorf("resolved to %q, want attest", target.Name())
	}
	if err := target.ParseFlags(rest); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if err := target.ValidateArgs(target.Flags().Args()); err != nil {
		t.Errorf("attest rejected its own flag-driven invocation: %v", err)
	}
	if got, _ := target.Flags().GetStringSlice("attestations"); len(got) != 1 || got[0] != "github-review" {
		t.Errorf("-a did not reach attest: %v", got)
	}

	// A positional arg is still an error — attest is not `run`.
	if err := attest.ValidateArgs([]string{"go", "build"}); err == nil {
		t.Error("attest accepted positional args; it should direct users to `cilock run`")
	}
}

// TestAttestRoutesToVexSubcommand pins the shipped surface:
// `cilock attest vex`, a subcommand of the existing attest verb.
func TestAttestRoutesToVexSubcommand(t *testing.T) {
	attest := AttestCmd()

	target, _, err := attest.Find([]string{"vex", "--status", "fixed"})
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if target.Name() != "vex" {
		t.Fatalf("resolved to %q, want vex", target.Name())
	}
	if target.Parent() == nil || target.Parent().Name() != "attest" {
		t.Errorf("vex is not nested under attest")
	}
}

// TestAttestVexFlagSurface asserts both halves of the command: the
// authoring flags, and the signing/output/upload flags reused verbatim
// from the attest/run option set.
//
// The reuse half is asserted as flag-set parity with `attest` rather than
// as a hand-listed set, so it stays true no matter which signer and
// attestor plugins the binary links in.
func TestAttestVexFlagSurface(t *testing.T) {
	cmd := AttestVexCmd()

	authoring := []string{"product", "vuln", "status", "justification", "impact-statement", "action-statement", "vex-out", "author"}
	// The wire that lets the authored document reach the attestor.
	plumbing := []string{"attestor-vex-file"}

	for _, group := range [][]string{authoring, plumbing} {
		for _, name := range group {
			if cmd.Flags().Lookup(name) == nil {
				t.Errorf("missing flag --%s", name)
			}
		}
	}

	// Sanity anchors that must hold in any build.
	for _, name := range []string{"signer-file-key-path", "outfile", "archivista-server", "enable-archivista", "timestamp-servers", "step"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing reused flag --%s", name)
		}
	}

	// Every flag `attest` offers must also be offered here.
	AttestCmd().Flags().VisitAll(func(f *pflag.Flag) {
		if cmd.Flags().Lookup(f.Name) == nil {
			t.Errorf("attest offers --%s but attest vex does not", f.Name)
		}
	})
}

func TestAttestVexWritesDeterministicDocument(t *testing.T) {
	dir := t.TempDir()
	vo := validVEXOptions(dir)

	doc, err := vo.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	path, raw, err := vo.write(doc, dir)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(first) != string(raw) {
		t.Errorf("write returned bytes that differ from the file it wrote — the attestor signs the returned bytes, so they must be the same document")
	}

	// A second authoring pass with the same clock must be byte-identical.
	doc2, err := vo.build()
	if err != nil {
		t.Fatalf("build again: %v", err)
	}
	second, err := openvex.Marshal(doc2)
	if err != nil {
		t.Fatalf("marshal again: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("output is not deterministic under a fixed clock:\n%s\n---\n%s", first, second)
	}

	// And it must be a document the vex attestor can decode.
	var decoded openvex.VEX
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("emitted document does not unmarshal as OpenVEX: %v", err)
	}
	if decoded.Statements[0].Status != openvex.StatusNotAffected {
		t.Errorf("status = %q", decoded.Statements[0].Status)
	}
	if !strings.Contains(string(first), `"timestamp": "2026-07-27T12:00:00Z"`) {
		t.Errorf("clock was not honored:\n%s", first)
	}
	if !strings.HasPrefix(decoded.Tooling, "cilock/") {
		t.Errorf("tooling = %q, want a cilock/<version> stamp", decoded.Tooling)
	}
}

// TestAttestVexFailsClosedBeforeWriting: a rejected document must not
// leave a file behind for something else to pick up.
func TestAttestVexFailsClosedBeforeWriting(t *testing.T) {
	tests := map[string]func(*vexAuthorOptions){
		"not_affected without justification": func(vo *vexAuthorOptions) { vo.Justification = "" },
		"affected without action statement": func(vo *vexAuthorOptions) {
			vo.Status = "affected"
			vo.Justification = ""
		},
		"unknown status":        func(vo *vexAuthorOptions) { vo.Status = "probably_fine" },
		"unknown justification": func(vo *vexAuthorOptions) { vo.Justification = "we_looked_at_it" },
		"malformed vuln id":     func(vo *vexAuthorOptions) { vo.Vulns = []string{"CVE-24-1"} },
		"no product":            func(vo *vexAuthorOptions) { vo.Products = nil },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			vo := validVEXOptions(dir)
			mutate(vo)

			if _, err := vo.build(); err == nil {
				t.Fatal("build succeeded on a document that should be rejected")
			}
			if _, err := os.Stat(vo.OutFile); !os.IsNotExist(err) {
				t.Errorf("a rejected document left a file at %s", vo.OutFile)
			}
		})
	}
}

// TestAttestVexRelativeOutFileResolvesAgainstWorkingDir keeps --vex-out
// consistent with the run pipeline's --workingdir.
func TestAttestVexRelativeOutFileResolvesAgainstWorkingDir(t *testing.T) {
	dir := t.TempDir()
	vo := validVEXOptions(dir)
	vo.OutFile = "triage.openvex.json"

	doc, err := vo.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	path, _, err := vo.write(doc, dir)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if want := filepath.Join(dir, "triage.openvex.json"); path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("document not written: %v", err)
	}
}

// TestVexBytesSetterBindsTheAuthoredBytes is the TOCTOU regression test
// for the authoring handoff. `attest vex` used to pass the attestor a
// PATH (--attestor-vex-file) and let it re-read the file at attest time;
// anything with write access to the workspace could swap the document
// between the write and that read, and the signature would bind to the
// substituted content. The contract now: the attestor signs the bytes the
// command rendered, no matter what the file at docPath has become.
func TestVexBytesSetterBindsTheAuthoredBytes(t *testing.T) {
	dir := t.TempDir()
	vo := validVEXOptions(dir)

	doc, err := vo.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	docPath, raw, err := vo.write(doc, dir)
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// The attack: replace the on-disk document with a DIFFERENT valid VEX
	// document after authoring, before the attestor runs. Valid on
	// purpose — a swap that fails validation would be caught for the
	// wrong reason.
	swapped := *vo
	swapped.Vulns = []string{"CVE-2024-99999"}
	swappedDoc, err := swapped.build()
	if err != nil {
		t.Fatalf("build swapped: %v", err)
	}
	swappedRaw, err := openvex.Marshal(swappedDoc)
	if err != nil {
		t.Fatalf("marshal swapped: %v", err)
	}
	if err := os.WriteFile(docPath, swappedRaw, 0o600); err != nil {
		t.Fatalf("swap file: %v", err)
	}

	// Apply the setter exactly as runRun does.
	vexAttestor := vex.New()
	updated, err := vexBytesSetter(raw, docPath)(vexAttestor)
	if err != nil {
		t.Fatalf("setter: %v", err)
	}
	vexAttestor = updated.(*vex.Attestor)

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{vexAttestor},
		attestation.WithHashes(hashes),
		attestation.WithWorkingDir(dir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := vexAttestor.Attest(ctx); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	// The predicate must be the AUTHORED document, not the substitution.
	if got := vexAttestor.VEXDocument.Statements[0].Vulnerability.Name; got != "CVE-2024-12345" {
		t.Fatalf("signed vulnerability = %q — the substituted file won the race", got)
	}
	authoredDigest, err := cryptoutil.CalculateDigestSetFromBytes(raw, hashes)
	if err != nil {
		t.Fatalf("digest authored bytes: %v", err)
	}
	if !vexAttestor.ReportDigestSet.Equal(authoredDigest) {
		t.Error("ReportDigestSet does not match the authored bytes")
	}
	swappedDigest, err := cryptoutil.CalculateDigestSetFromBytes(swappedRaw, hashes)
	if err != nil {
		t.Fatalf("digest swapped bytes: %v", err)
	}
	if vexAttestor.ReportDigestSet.Equal(swappedDigest) {
		t.Error("ReportDigestSet matches the substituted file — the attestor read from disk")
	}
	// And the recorded name stays the stable in-tree form.
	if vexAttestor.ReportFile != "vex.openvex.json" {
		t.Errorf("ReportFile = %q, want %q", vexAttestor.ReportFile, "vex.openvex.json")
	}
}

// TestVexBytesSetterRejectsWrongAttestorType keeps the setter honest when
// the registry hands it something that is not the vex attestor.
func TestVexBytesSetterRejectsWrongAttestorType(t *testing.T) {
	if _, err := vexBytesSetter([]byte("{}"), "x.json")(&notAVexAttestor{}); err == nil {
		t.Fatal("setter accepted a non-vex attestor")
	}
}

type notAVexAttestor struct{ attestation.Attestor }

func TestAppendAttestorIsIdempotent(t *testing.T) {
	got := appendAttestor([]string{"environment", "vex"}, "vex")
	if len(got) != 2 {
		t.Errorf("appendAttestor duplicated an existing entry: %v", got)
	}
	got = appendAttestor([]string{"environment"}, "vex")
	if len(got) != 2 || got[1] != "vex" {
		t.Errorf("appendAttestor = %v, want environment+vex", got)
	}
}

// TestAttestVexWriteHandlesRelativeWorkingDir is the regression bar for
// the path handoff between the two halves of this command.
//
// write returns the path that is then handed to --attestor-vex-file, and
// the vex attestor resolves a RELATIVE value of that flag against the
// same --workingdir. So a working-dir-relative return value made the
// directory count twice: `--workingdir build` wrote to build/vex.openvex.json
// and then tried to read build/build/vex.openvex.json, failing the run on
// a document that had been written correctly. The test drives the real
// attestor rather than asserting on a string, because the double-join
// only shows up when both halves resolve the same value.
func TestAttestVexWriteHandlesRelativeWorkingDir(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)

	const relativeWorkingDir = "build"
	if err := os.MkdirAll(filepath.Join(root, relativeWorkingDir), 0o750); err != nil {
		t.Fatalf("mkdir working dir: %v", err)
	}

	vo := validVEXOptions(root)
	vo.OutFile = "vex.openvex.json" // relative, as the flag defaults to

	doc, err := vo.build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	path, _, err := vo.write(doc, relativeWorkingDir)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("write returned %q — a relative path is re-resolved against --workingdir by the attestor", path)
	}
	// EvalSymlinks: macOS temp dirs are reached through /private, so the
	// literal strings differ while naming the same file.
	wantPath, err := filepath.EvalSymlinks(filepath.Join(root, relativeWorkingDir, "vex.openvex.json"))
	if err != nil {
		t.Fatalf("the document did not land under the working dir: %v", err)
	}
	gotPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("resolve written path: %v", err)
	}
	if gotPath != wantPath {
		t.Fatalf("document landed at %q, want %q", gotPath, wantPath)
	}

	// The half that actually consumes it: same --workingdir, same value.
	vexAttestor := vex.New()
	vex.WithVEXFile(path)(vexAttestor)

	ctx, err := attestation.NewContext("test",
		[]attestation.Attestor{vexAttestor},
		attestation.WithHashes([]cryptoutil.DigestValue{{Hash: crypto.SHA256}}),
		attestation.WithWorkingDir(relativeWorkingDir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	if err := vexAttestor.Attest(ctx); err != nil {
		t.Fatalf("the vex attestor could not read the document this command just wrote: %v", err)
	}
	if len(vexAttestor.VEXDocument.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(vexAttestor.VEXDocument.Statements))
	}
}
