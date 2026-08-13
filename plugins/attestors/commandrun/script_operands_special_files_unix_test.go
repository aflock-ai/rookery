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

//go:build !windows

package commandrun

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// symlinkFixture builds a tree where lexical and kernel resolution of `..`
// DISAGREE, and returns the operand plus the bytes the kernel actually reads.
//
//	<root>/work/build.sh   <- what a lexical `filepath.Join` collapses to
//	<root>/other/build.sh  <- what the kernel opens
//	<root>/work/link       -> <root>/other/sub   (so link/.. is <root>/other)
//
// The returned bytes come from the OS, not from any resolution this package
// performs: the test asks the kernel to open the exact path string the command
// would use, so it cannot agree with a wrong implementation by construction.
func symlinkFixture(t *testing.T, name, wrongBody, rightBody string) (workdir, operand string, kernelBytes []byte) {
	t.Helper()

	root := t.TempDir()
	work := filepath.Join(root, "work")
	other := filepath.Join(root, "other")
	sub := filepath.Join(other, "sub")
	for _, d := range []string{work, other, sub} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(work, name), []byte(wrongBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, name), []byte(rightBody), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, filepath.Join(work, "link")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	// Deliberately NOT filepath.Join: Join cleans the ".." away, and that
	// collapse is the defect under test. The command's argv carries the
	// uncollapsed string, so the fixture must too.
	operand = "link/.." + string(os.PathSeparator) + name
	rawPath := work + string(os.PathSeparator) + operand

	kernelBytes, err := os.ReadFile(rawPath) //nolint:gosec // G304: fixture path built by this test
	if err != nil {
		t.Fatalf("fixture unreadable at %q: %v", rawPath, err)
	}
	if string(kernelBytes) != rightBody {
		t.Fatalf("fixture does not exercise the defect: the kernel read %q from %q, "+
			"so lexical and kernel resolution agree here", kernelBytes, rawPath)
	}
	return work, operand, kernelBytes
}

// TestParentTraversalResolvesLikeTheKernel pins that `..` after a symlinked
// directory is resolved the way the OS resolves it.
//
// filepath.Join removes `..` LEXICALLY. The kernel removes it after following
// the symlink. With `link -> /other/sub`, `bash link/../build.sh` executes
// /other/build.sh while capture hashed /work/build.sh — a real file, a real
// digest, and the wrong one. No attacker, no race, no concurrent writer: a
// symlinked directory and an ordinary `..` are enough, on a completely stable
// filesystem.
func TestParentTraversalResolvesLikeTheKernel(t *testing.T) {
	assertMatchesKernel := func(t *testing.T, refs []ScriptRef, kernelBytes []byte) {
		t.Helper()
		if len(refs) != 1 {
			t.Fatalf("expected exactly 1 ref, got %+v", refs)
		}
		r := refs[0]
		if r.Unresolved != "" {
			t.Fatalf("operand did not resolve: %s", r.Unresolved)
		}
		if r.Content != string(kernelBytes) {
			t.Fatalf("captured the file LEXICAL `..` names, not the one the kernel opens.\n"+
				" captured: %q\n kernel:   %q\n recorded path: %q",
				r.Content, kernelBytes, r.Path)
		}
		want, err := cryptoutil.CalculateDigestSetFromBytes(kernelBytes, defaultScriptDigests())
		if err != nil {
			t.Fatal(err)
		}
		for k, v := range want {
			if r.Digest[k] != v {
				t.Errorf("digest %v = %q, want %q — signed the wrong file", k, r.Digest[k], v)
			}
		}
	}

	t.Run("interpreter operand", func(t *testing.T) {
		work, operand, kernelBytes := symlinkFixture(t, "build.sh",
			"#!/bin/sh\necho LEXICAL-WRONG\n", "#!/bin/sh\necho KERNEL-RIGHT\n")
		refs := captureScriptRefs(context.Background(),
			[]string{"bash", operand}, work, ScriptCaptureContent)
		assertMatchesKernel(t, refs, kernelBytes)
	})

	// joinUnderBase feeds make's -C and -f resolution, so it carries the same
	// defect by the same mechanism.
	t.Run("make -C through a symlinked parent", func(t *testing.T) {
		work, _, kernelBytes := symlinkFixture(t, "x.mk",
			"all:\n\t@echo LEXICAL-WRONG\n", "all:\n\t@echo KERNEL-RIGHT\n")
		// Spelled out rather than via filepath.Dir: Dir calls Clean, which
		// collapses "link/../x.mk" to "." and quietly removes the very
		// construct under test from the fixture.
		dir := "link/.."
		refs := captureScriptRefs(context.Background(),
			[]string{"make", "-C", dir, "-f", "x.mk"}, work, ScriptCaptureContent)
		assertMatchesKernel(t, refs, kernelBytes)
	})
}

// hydrateDeadline bounds how long capture may take for these fixtures. They are
// a few bytes or a nameless pipe; anything approaching this is a block, not
// slowness.
const hydrateDeadline = 10 * time.Second

// TestSpecialFileOperandsDoNotBlock pins that capture never hangs on a
// non-regular operand.
//
// This failure is worse than false evidence. A FIFO opened for reading blocks
// until a writer appears, and capture runs BEFORE the command starts — outside
// any command timeout, outside context cancellation. An argv naming a FIFO
// therefore wedges the attestor, and the build, indefinitely, with no signal
// about why.
//
// The test must prove NON-BLOCKING, not merely "recorded nothing". A test that
// only asserted absence would sit at a green-looking prompt forever in CI while
// the capture hung, so the call runs on its own goroutine against a deadline
// and the fixture has NO writer — the exact condition under which a blocking
// open never returns.
func TestSpecialFileOperandsDoNotBlock(t *testing.T) {
	t.Run("fifo operand abstains without blocking", func(t *testing.T) {
		dir := t.TempDir()
		// Named as a shell script so the resolver genuinely produces a ref and
		// hydration is genuinely attempted — the whole point is the open.
		if err := syscall.Mkfifo(filepath.Join(dir, "build.sh"), 0o600); err != nil {
			t.Skipf("mkfifo unavailable here: %v", err)
		}

		done := make(chan []ScriptRef, 1)
		go func() {
			// NOTHING ever opens the write end. A blocking open never returns.
			done <- captureScriptRefs(context.Background(), []string{"bash", "build.sh"}, dir, ScriptCaptureIdentity)
		}()

		select {
		case refs := <-done:
			if len(refs) != 1 {
				t.Fatalf("a named operand must still be REPORTED, got %+v", refs)
			}
			r := refs[0]
			if r.Unresolved == "" {
				t.Error("a FIFO is not a script: it must carry a reason, not a bare path")
			}
			if len(r.Digest) != 0 {
				t.Error("Unresolved and Digest are mutually exclusive")
			}
			if r.SizeBytes != 0 || r.Content != "" {
				t.Errorf("nothing may be measured from a non-regular file: %+v", r)
			}
		case <-time.After(hydrateDeadline):
			t.Fatalf("capture blocked for %s on a FIFO with no writer — this hangs the "+
				"attestor before the command starts, where no command timeout applies",
				hydrateDeadline)
		}
	})

	// MANDATORY counterweight, in this file so the property and its cost are
	// read together: an implementation that refused to open anything would
	// satisfy the test above and silently gut capture.
	t.Run("regular file still hydrates", func(t *testing.T) {
		dir := t.TempDir()
		body := "#!/bin/sh\ncosign verify\n"
		if err := os.WriteFile(filepath.Join(dir, "build.sh"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		done := make(chan []ScriptRef, 1)
		go func() {
			done <- captureScriptRefs(context.Background(), []string{"bash", "build.sh"}, dir, ScriptCaptureContent)
		}()

		select {
		case refs := <-done:
			if len(refs) != 1 {
				t.Fatalf("expected 1 ref, got %+v", refs)
			}
			r := refs[0]
			if r.Unresolved != "" {
				t.Fatalf("an ordinary script must hydrate, got Unresolved=%q", r.Unresolved)
			}
			if len(r.Digest) == 0 {
				t.Error("a regular file must still be digested")
			}
			if r.SizeBytes != int64(len(body)) {
				t.Errorf("size = %d, want %d", r.SizeBytes, len(body))
			}
			if r.Content != body {
				t.Errorf("content = %q, want %q", r.Content, body)
			}
		case <-time.After(hydrateDeadline):
			t.Fatalf("capture of an ordinary regular file took over %s", hydrateDeadline)
		}
	})

	// A directory is the other non-regular shape that reaches the open. It
	// never blocked, but it must keep reporting a reason rather than a digest.
	t.Run("directory operand abstains", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "build.sh"), 0o750); err != nil {
			t.Fatal(err)
		}
		refs := captureScriptRefs(context.Background(), []string{"bash", "build.sh"}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 || refs[0].Unresolved == "" {
			t.Fatalf("a directory operand must be reported unresolved, got %+v", refs)
		}
		if len(refs[0].Digest) != 0 {
			t.Error("Unresolved and Digest are mutually exclusive")
		}
	})
}
