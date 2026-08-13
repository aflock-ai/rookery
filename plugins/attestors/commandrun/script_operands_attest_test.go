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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestAttestPopulatesScripts runs a REAL command through Attest and checks the
// scripts block afterwards.
//
// Every other test in this file set exercises the resolver helpers directly.
// That leaves the wiring untested — whether Attest actually calls capture, and
// whether the working directory it hands over is the one the command ran in.
// Those are exactly where a mistake would survive a green helper suite, so
// this drives the real path: a real script, really executed.
func TestAttestPopulatesScripts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script")
	}

	workdir := t.TempDir()
	body := "#!/bin/sh\necho attested\n"
	if err := os.WriteFile(filepath.Join(workdir, "build.sh"), []byte(body), 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	actx, err := attestation.NewContext(
		"commandrun-scripts-test",
		[]attestation.Attestor{},
		attestation.WithContext(ctx),
		attestation.WithWorkingDir(workdir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}

	rc := New(
		WithCommand([]string{"sh", "build.sh"}),
		WithSilent(true),
	)
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	if rc.ExitCode != 0 {
		t.Fatalf("script exited %d — the command did not actually run", rc.ExitCode)
	}
	if len(rc.Scripts) != 1 {
		t.Fatalf("Attest did not populate Scripts: %+v", rc.Scripts)
	}

	got := rc.Scripts[0]
	if got.Unresolved != "" {
		t.Fatalf("script unresolved after a successful run: %s", got.Unresolved)
	}
	// The recorded path must be absolute and inside the working directory the
	// command actually ran in — not the test process's own CWD.
	want := filepath.Join(workdir, "build.sh")
	if got.Path != want {
		t.Errorf("path = %q, want %q (wrong working directory was handed to capture)",
			got.Path, want)
	}
	if got.Role != RoleInterpreterOperand {
		t.Errorf("role = %q, want %q", got.Role, RoleInterpreterOperand)
	}
	if got.SizeBytes != int64(len(body)) {
		t.Errorf("size = %d, want %d", got.SizeBytes, len(body))
	}

	wantDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte(body), defaultScriptDigests())
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range wantDigest {
		if got.Digest[k] != v {
			t.Errorf("digest %v = %q, want %q — not the script that ran", k, got.Digest[k], v)
		}
	}
	if got.Content != "" {
		t.Error("identity is the default; content must not be embedded unasked")
	}
}

// TestAttestCapturesScriptDeletedAfterRun pins the reason capture happens
// BEFORE the command runs.
//
// cilock writes its step wrapper to a temp path and removes it once the step
// finishes. A post-run capture would find nothing and report every wrapper
// unresolved — which is the exact case this feature exists to fix, so it gets
// a test rather than a comment.
func TestAttestCapturesScriptDeletedAfterRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script")
	}

	workdir := t.TempDir()
	script := filepath.Join(workdir, "self-deleting.sh")
	// The script removes itself, standing in for cilock's wrapper cleanup.
	body := "#!/bin/sh\nrm -f \"$0\"\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	actx, err := attestation.NewContext(
		"commandrun-scripts-deleted-test",
		[]attestation.Attestor{},
		attestation.WithContext(ctx),
		attestation.WithWorkingDir(workdir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}

	rc := New(WithCommand([]string{"sh", script}), WithSilent(true))
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	// Confirm the premise: the script really is gone by now. Without this the
	// test could pass while never exercising the case it claims to cover.
	if _, err := os.Stat(script); !os.IsNotExist(err) {
		t.Fatalf("premise failed: script still present, so pre-run capture was never exercised (stat err=%v)", err)
	}

	if len(rc.Scripts) != 1 {
		t.Fatalf("expected the deleted wrapper to still be recorded: %+v", rc.Scripts)
	}
	if rc.Scripts[0].Unresolved != "" {
		t.Fatalf("wrapper recorded as unresolved (%s) — capture ran too late",
			rc.Scripts[0].Unresolved)
	}
	if len(rc.Scripts[0].Digest) == 0 {
		t.Error("deleted wrapper has no digest — capture ran after the command")
	}
}

// TestAttestResolvesSymlinkedWorkingDirectoryThroughTheOS pins that the
// directory capture measures against is the directory the KERNEL puts the
// command in.
//
// runCmd hands ctx.WorkingDir() to exec.Cmd.Dir verbatim and the kernel applies
// `..` to whatever the preceding component actually resolved to. scriptWorkdir
// used filepath.Abs, which calls Clean, which removes `..` LEXICALLY — deleting
// the preceding component from the string without knowing it was a symlink.
// With `work/link/..` those are two different directories, so capture hashed a
// real file with a real digest that the command demonstrably never opened.
//
// This is the SAME defect an earlier round closed for OPERANDS, reappearing in
// the WORKDIR: the earlier fix was applied to an instance rather than to the
// class. The fixture makes lexical and kernel resolution disagree on purpose,
// and the command itself prints which directory it really ran in — so the test
// cannot agree with a wrong implementation by construction.
func TestAttestResolvesSymlinkedWorkingDirectoryThroughTheOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script")
	}

	root := t.TempDir()
	work := filepath.Join(root, "work")
	other := filepath.Join(root, "other")
	sub := filepath.Join(other, "sub")
	for _, d := range []string{work, other, sub} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// work/link -> other/sub, so `work/link/..` is `other` to the kernel and
	// `work` to filepath.Clean. Everything below hangs on that disagreement.
	if err := os.Symlink(sub, filepath.Join(work, "link")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	lexicalBody := "#!/bin/sh\necho LEXICAL\n"
	kernelBody := "#!/bin/sh\necho KERNEL\n"
	if err := os.WriteFile(filepath.Join(work, "build.sh"), []byte(lexicalBody), 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "build.sh"), []byte(kernelBody), 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	// Built by concatenation, NOT filepath.Join: Join cleans, which would
	// collapse the `..` here in the test and quietly remove the very thing
	// under test.
	sep := string(os.PathSeparator)
	rawWorkdir := work + sep + "link" + sep + ".."

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	actx, err := attestation.NewContext(
		"commandrun-symlinked-workdir",
		[]attestation.Attestor{},
		attestation.WithContext(ctx),
		attestation.WithWorkingDir(rawWorkdir),
	)
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}

	rc := New(
		WithCommand([]string{"sh", "build.sh"}),
		WithSilent(true),
	)
	if err := rc.Attest(actx); err != nil {
		t.Fatalf("Attest: %v", err)
	}

	// GROUND TRUTH first. The kernel, not this package, decides which script
	// ran. If this assertion fails the fixture is broken and every assertion
	// below would be measuring nothing.
	if got := strings.TrimSpace(rc.Stdout); got != "KERNEL" {
		t.Fatalf("the command printed %q — the fixture does not create the "+
			"lexical/kernel disagreement it is supposed to", got)
	}

	if len(rc.Scripts) != 1 {
		t.Fatalf("expected 1 script, got %+v", rc.Scripts)
	}
	got := rc.Scripts[0]
	if got.Unresolved != "" {
		t.Fatalf("script unresolved: %s", got.Unresolved)
	}

	wantDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte(kernelBody), defaultScriptDigests())
	if err != nil {
		t.Fatal(err)
	}
	wrongDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte(lexicalBody), defaultScriptDigests())
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range wantDigest {
		if got.Digest[k] == wrongDigest[k] {
			t.Errorf("digest is the LEXICALLY resolved %s/build.sh — capture measured "+
				"a directory the command never ran in", work)
		}
		if got.Digest[k] != v {
			t.Errorf("digest %v = %q, want %q (the script the kernel actually ran)",
				k, got.Digest[k], v)
		}
	}

	// The recorded path must name the file the kernel opened. EvalSymlinks on
	// the expected location because the OS may canonicalise the temp root too
	// (/var -> /private/var on darwin).
	wantPath, err := filepath.EvalSymlinks(filepath.Join(other, "build.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != wantPath {
		t.Errorf("path = %q, want %q", got.Path, wantPath)
	}
}
