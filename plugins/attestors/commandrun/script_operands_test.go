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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestResolveScriptOperands covers the argv shapes that actually appear in
// recorded production command-run attestations, plus the shapes that must NOT
// resolve to a file.
func TestResolveScriptOperands(t *testing.T) {
	tests := []struct {
		name     string
		argv     []string
		wantPath string // "" means: must resolve to nothing
		wantRole ScriptRole
	}{
		{
			// Verbatim shape from a recorded production attestation. Without
			// env-prefix stripping this resolves to the program `env` and
			// yields nothing, which is how every wrapper script in the corpus
			// came back opaque.
			name: "env prefix with assignments then bash script",
			argv: []string{
				"env", "GOOS=linux", "GOARCH=arm64", "TOOL=cilock",
				"BIN=/tmp/tmp.Zt2PWVy655/cilock",
				"bash", "/opt/runner/_work/judge/build.sh",
			},
			wantPath: "/opt/runner/_work/judge/build.sh",
			wantRole: RoleInterpreterOperand,
		},
		{
			name:     "plain bash script",
			argv:     []string{"bash", "scripts/release.sh"},
			wantPath: "scripts/release.sh",
			wantRole: RoleInterpreterOperand,
		},
		{
			name:     "absolute interpreter path",
			argv:     []string{"/usr/bin/python3", "tools/scan.py", "--verbose"},
			wantPath: "tools/scan.py",
			wantRole: RoleInterpreterOperand,
		},
		{
			// bash's -e is errexit and takes no operand, so the script IS
			// found. A shared flag table across interpreters got this wrong.
			name:     "bash boolean flags precede the script",
			argv:     []string{"bash", "-x", "-e", "deploy.sh"},
			wantPath: "deploy.sh",
			wantRole: RoleInterpreterOperand,
		},
		{
			// The same flag, opposite meaning: perl's -e IS inline code, so
			// there is no script file. This pair is why the grammar must be
			// per-interpreter.
			name:     "perl -e is inline code, not a flag",
			argv:     []string{"perl", "-e", "print 1"},
			wantPath: "",
		},
		{
			name:     "python -m names a module, not a path",
			argv:     []string{"python3", "-m", "pytest"},
			wantPath: "",
		},
		{
			name:     "flag values are not mistaken for the script",
			argv:     []string{"python3", "-W", "ignore", "tools/scan.py"},
			wantPath: "tools/scan.py",
			wantRole: RoleInterpreterOperand,
		},
		{
			// node executes the inline code; decoy.js never runs. Generic
			// "--flag=value" handling used to fall through and record it.
			name:     "node --eval=code does not record a decoy path",
			argv:     []string{"node", "--eval=console.log(1)", "decoy.js"},
			wantPath: "",
		},
		{
			name:     "python --flag=value form does not swallow the script",
			argv:     []string{"python3", "-W=ignore", "tools/scan.py"},
			wantPath: "tools/scan.py",
			wantRole: RoleInterpreterOperand,
		},
		{
			// THE false-evidence case. -euo is -e -u -o; -o takes a value, so
			// "pipefail" is that value, not the script. Treating the cluster
			// as one opaque boolean flag recorded pipefail as the executed
			// script — a signed digest naming the wrong file entirely.
			name:     "clustered -euo consumes pipefail, not the script",
			argv:     []string{"bash", "-euo", "pipefail", "build.sh"},
			wantPath: "build.sh",
			wantRole: RoleInterpreterOperand,
		},
		{
			// Attached value form: -o's value rides in the cluster tail, so
			// the following token is NOT consumed.
			name:     "clustered -eopipefail does not consume the script",
			argv:     []string{"bash", "-eopipefail", "build.sh"},
			wantPath: "build.sh",
			wantRole: RoleInterpreterOperand,
		},
		{
			name:     "plain cluster of boolean switches",
			argv:     []string{"bash", "-ex", "deploy.sh"},
			wantPath: "deploy.sh",
			wantRole: RoleInterpreterOperand,
		},
		{
			// -c inside a cluster is still inline code: no script file ran.
			name:     "clustered -ec is inline code",
			argv:     []string{"sh", "-ec", "go build ./..."},
			wantPath: "",
		},
		{
			name:     "cluster with an unknown member abstains",
			argv:     []string{"bash", "-eQ", "deploy.sh"},
			wantPath: "",
		},
		{
			name:     "make attached -f form",
			argv:     []string{"make", "-fCustom.mk"},
			wantPath: "Custom.mk",
			wantRole: RoleMakefile,
		},
		{
			name:     "unrecognised flag makes the resolver abstain",
			argv:     []string{"bash", "--totally-unknown-flag", "deploy.sh"},
			wantPath: "",
		},
		{
			name:     "make -C resolves the makefile in the target directory",
			argv:     []string{"make", "-C", "sub", "-f", "ci.mk", "all"},
			wantPath: "sub/ci.mk",
			wantRole: RoleMakefile,
		},
		{
			// The case that makes an over-eager resolver hash a file named
			// "set -euo pipefail; go build ./...".
			name:     "bash -c inline code is NOT a path",
			argv:     []string{"bash", "-c", "set -euo pipefail; go build ./..."},
			wantPath: "",
		},
		{
			name:     "sh -c inline code is NOT a path",
			argv:     []string{"sh", "-c", "trivy image alpine:latest"},
			wantPath: "",
		},
		{
			name:     "explicit make -f",
			argv:     []string{"make", "-f", "build/ci.mk", "all"},
			wantPath: "build/ci.mk",
			wantRole: RoleMakefile,
		},
		{
			name:     "make --file= form",
			argv:     []string{"make", "--file=custom.mk"},
			wantPath: "custom.mk",
			wantRole: RoleMakefile,
		},
		{
			name:     "non-interpreter program resolves to nothing",
			argv:     []string{"go", "build", "./..."},
			wantPath: "",
		},
		{
			name:     "trivy is not an interpreter",
			argv:     []string{"trivy", "image", "--severity", "CRITICAL", "alpine"},
			wantPath: "",
		},
		{
			name:     "empty argv",
			argv:     nil,
			wantPath: "",
		},
		{
			name:     "env with nothing after it",
			argv:     []string{"env"},
			wantPath: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveScriptOperands(tc.argv, "")
			if tc.wantPath == "" {
				if len(got) != 0 {
					t.Fatalf("expected no operand, got %+v", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("expected exactly 1 operand, got %d: %+v", len(got), got)
			}
			if got[0].Path != tc.wantPath {
				t.Errorf("path = %q, want %q", got[0].Path, tc.wantPath)
			}
			if got[0].Role != tc.wantRole {
				t.Errorf("role = %q, want %q", got[0].Role, tc.wantRole)
			}
		})
	}
}

// TestMakeImplicitMakefile checks GNU make's search order, and that a makefile
// is reported ONLY when it exists — naming "Makefile" when none is present
// would fabricate a path the build never read.
func TestMakeImplicitMakefile(t *testing.T) {
	t.Run("reports nothing when no makefile exists", func(t *testing.T) {
		dir := t.TempDir()
		if got := resolveScriptOperands([]string{"make", "all"}, dir); len(got) != 0 {
			t.Fatalf("expected no operand in empty dir, got %+v", got)
		}
	})

	t.Run("honours GNU make search order", func(t *testing.T) {
		dir := t.TempDir()
		// Write them in reverse-preference order; GNUmakefile must still win.
		for _, name := range []string{"Makefile", "makefile", "GNUmakefile"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("all:\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		got := resolveScriptOperands([]string{"make"}, dir)
		if len(got) != 1 {
			t.Fatalf("expected 1 operand, got %+v", got)
		}
		if filepath.Base(got[0].Path) != "GNUmakefile" {
			t.Errorf("chose %q, want GNUmakefile (make's first search hit)",
				filepath.Base(got[0].Path))
		}
	})
}

// TestCaptureScriptRefsIdentity is the default-mode contract: a digest and size
// but no bytes.
func TestCaptureScriptRefsIdentity(t *testing.T) {
	dir := t.TempDir()
	body := "#!/bin/bash\ngovulncheck ./...\n"
	script := filepath.Join(dir, "scan.sh")
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}

	refs := captureScriptRefs(context.Background(), []string{"bash", "scan.sh"}, dir, ScriptCaptureIdentity)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %+v", refs)
	}
	r := refs[0]
	if r.Unresolved != "" {
		t.Fatalf("unexpected Unresolved: %s", r.Unresolved)
	}
	if len(r.Digest) == 0 {
		t.Error("identity mode must record a digest")
	}
	if r.SizeBytes != int64(len(body)) {
		t.Errorf("size = %d, want %d", r.SizeBytes, len(body))
	}
	if r.Content != "" {
		t.Error("identity mode must NOT embed content — that is the opt-in mode")
	}
	if !filepath.IsAbs(r.Path) {
		t.Errorf("path %q should be resolved absolute against the workdir", r.Path)
	}
}

// TestCaptureScriptRefsOff verifies the off switch actually switches off.
func TestCaptureScriptRefsOff(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "s.sh"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if refs := captureScriptRefs(context.Background(), []string{"bash", "s.sh"}, dir, ScriptCaptureOff); refs != nil {
		t.Fatalf("off mode must capture nothing, got %+v", refs)
	}
}

// TestCaptureScriptRefsContent covers the opt-in body capture, including the
// truncation flag. The digest must always cover the WHOLE file even when the
// embedded body is clipped.
func TestCaptureScriptRefsContent(t *testing.T) {
	t.Run("small script embeds verbatim", func(t *testing.T) {
		dir := t.TempDir()
		body := "#!/bin/sh\nsyft packages dir:. -o cyclonedx-json\n"
		if err := os.WriteFile(filepath.Join(dir, "sbom.sh"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		refs := captureScriptRefs(context.Background(), []string{"sh", "sbom.sh"}, dir, ScriptCaptureContent)
		if len(refs) != 1 || refs[0].Content != body {
			t.Fatalf("content not captured verbatim: %+v", refs)
		}
		if refs[0].ContentTruncated {
			t.Error("small script must not be flagged truncated")
		}
	})

	t.Run("oversized script truncates EXPLICITLY", func(t *testing.T) {
		dir := t.TempDir()
		big := strings.Repeat("a", maxScriptContentBytes+4096)
		if err := os.WriteFile(filepath.Join(dir, "big.sh"), []byte(big), 0o600); err != nil {
			t.Fatal(err)
		}
		refs := captureScriptRefs(context.Background(), []string{"bash", "big.sh"}, dir, ScriptCaptureContent)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		r := refs[0]
		if !r.ContentTruncated {
			t.Error("oversized content must set ContentTruncated, not silently shorten")
		}
		if len(r.Content) != maxScriptContentBytes {
			t.Errorf("content len = %d, want cap %d", len(r.Content), maxScriptContentBytes)
		}
		if r.SizeBytes != int64(len(big)) {
			t.Errorf("SizeBytes = %d, must report the FULL file size %d",
				r.SizeBytes, len(big))
		}
		if len(r.Digest) == 0 {
			t.Error("digest must still cover the whole file when content is clipped")
		}
	})

	t.Run("binary body is withheld but digest kept", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "b.sh"), []byte{0xff, 0xfe, 0x00, 0x01}, 0o600); err != nil {
			t.Fatal(err)
		}
		refs := captureScriptRefs(context.Background(), []string{"bash", "b.sh"}, dir, ScriptCaptureContent)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		if !refs[0].ContentOmittedBinary {
			t.Error("non-UTF8 body must be flagged, not embedded")
		}
		if refs[0].Content != "" {
			t.Error("binary content must not be embedded")
		}
		if len(refs[0].Digest) == 0 {
			t.Error("digest must survive a withheld body")
		}
	})
}

// TestUnresolvedIsExplicit is the core anti-pattern guard: a missing script
// must carry a REASON, never come back as a bare path with no digest that a
// reader could mistake for a file that hashed to nothing.
func TestUnresolvedIsExplicit(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file", func(t *testing.T) {
		refs := captureScriptRefs(context.Background(), []string{"bash", "gone.sh"}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 {
			t.Fatalf("a missing script must still be REPORTED, got %+v", refs)
		}
		if refs[0].Unresolved == "" {
			t.Fatal("missing file must record why it is unresolved")
		}
		if len(refs[0].Digest) != 0 {
			t.Error("Unresolved and Digest are mutually exclusive")
		}
	})

	t.Run("directory is not a script", func(t *testing.T) {
		sub := filepath.Join(dir, "adir")
		if err := os.Mkdir(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		refs := captureScriptRefs(context.Background(), []string{"bash", "adir"}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 || refs[0].Unresolved == "" {
			t.Fatalf("a directory operand must be reported unresolved, got %+v", refs)
		}
	})
}

// TestUnresolvedRefsCarryTheAbsoluteAttemptedPath pins WHICH file a failure
// record is about.
//
// An Unresolved ScriptRef exists for exactly one purpose: to say that a
// specific file could not be measured. A Path still holding the bare argv token
// cannot do that job. "build.sh" is indistinguishable from a successfully
// resolved relative path, so a verifier reading signed evidence months later
// cannot tell which directory the attestor looked in — and the ScriptRef
// contract says Path is the operand AS RESOLVED against the working directory,
// which a bare token is not.
//
// The defect was ordering: ref.Path was assigned only after a successful open
// and descriptor validation, so every path that failed BEFORE that point —
// missing, non-regular, unreadable, cancelled, unresolvable traversal, budget
// exhausted — emitted the unresolved operand. The absolute attempted path must
// be recorded before anything that can fail.
func TestUnresolvedRefsCarryTheAbsoluteAttemptedPath(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	for _, tc := range []struct {
		name    string
		operand string
		ctx     context.Context
		setup   func(t *testing.T, dir string)
		// wantPath is the absolute form the record must carry. It is not always
		// filepath.Join: a `..` operand must keep its raw shape, because
		// collapsing it lexically names a different file than the kernel opens.
		wantPath func(dir string) string
	}{
		{
			name:     "missing file",
			operand:  "gone.sh",
			ctx:      context.Background(),
			wantPath: func(dir string) string { return filepath.Join(dir, "gone.sh") },
		},
		{
			name:    "not a regular file",
			operand: "adir",
			ctx:     context.Background(),
			setup: func(t *testing.T, dir string) {
				if err := os.Mkdir(filepath.Join(dir, "adir"), 0o750); err != nil {
					t.Fatal(err)
				}
			},
			wantPath: func(dir string) string { return filepath.Join(dir, "adir") },
		},
		{
			name:    "unreadable file",
			operand: "noperm.sh",
			ctx:     context.Background(),
			setup: func(t *testing.T, dir string) {
				p := filepath.Join(dir, "noperm.sh")
				if err := os.WriteFile(p, []byte("echo hi\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(p, 0o000); err != nil {
					t.Skipf("chmod unavailable here: %v", err)
				}
				// Verify the precondition rather than assuming it. Running as
				// root, or on a filesystem that ignores mode bits, a 0000 file
				// still opens — and this case would then silently assert
				// nothing while looking like it passed.
				if f, err := os.Open(p); err == nil {
					_ = f.Close()
					t.Skip("this environment can read a 0000 file (root?); " +
						"the unreadable case cannot be exercised here")
				}
			},
			wantPath: func(dir string) string { return filepath.Join(dir, "noperm.sh") },
		},
		{
			name:    "context cancelled before the read",
			operand: "any.sh",
			ctx:     cancelled,
			setup: func(t *testing.T, dir string) {
				if err := os.WriteFile(filepath.Join(dir, "any.sh"),
					[]byte("echo hi\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantPath: func(dir string) string { return filepath.Join(dir, "any.sh") },
		},
		{
			name:    "parent traversal the OS cannot resolve",
			operand: "nodir/../x.sh",
			ctx:     context.Background(),
			// The record must keep the RAW join. Cleaning it to <dir>/x.sh
			// would name a file the attestor never asked the kernel about.
			wantPath: func(dir string) string { return rawJoin(dir, "nodir/../x.sh") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.setup != nil {
				tc.setup(t, dir)
			}

			refs := captureScriptRefs(tc.ctx,
				[]string{"bash", tc.operand}, dir, ScriptCaptureIdentity)
			if len(refs) != 1 {
				t.Fatalf("expected 1 ref, got %+v", refs)
			}
			r := refs[0]

			if r.Unresolved == "" {
				t.Fatalf("this case must be unresolved; the test is not exercising "+
					"a failure path at all: %+v", r)
			}
			if r.Path == tc.operand {
				t.Errorf("Path = %q — the bare argv operand. A verifier cannot tell this "+
					"from a resolved relative path, so the record does not identify "+
					"which file failed", r.Path)
			}
			if !filepath.IsAbs(r.Path) {
				t.Errorf("Path = %q is not absolute; the attempted path must be recorded "+
					"before anything that can fail", r.Path)
			}
			if want := tc.wantPath(dir); r.Path != want {
				t.Errorf("Path = %q, want %q", r.Path, want)
			}
			if len(r.Digest) != 0 || r.SizeBytes != 0 {
				t.Errorf("nothing may be measured on a failure: %+v", r)
			}
		})
	}

	// The budget gate is its own exit, added in a previous round, and it returns
	// before any stat or open. It must record the attempted path too.
	t.Run("aggregate budget exhausted", func(t *testing.T) {
		dir := t.TempDir()
		restoreTotal, restorePer := maxCaptureTotalBytes, maxScriptDigestBytes
		maxCaptureTotalBytes = 1
		maxScriptDigestBytes = 1 << 20
		t.Cleanup(func() {
			maxCaptureTotalBytes, maxScriptDigestBytes = restoreTotal, restorePer
		})

		for _, n := range []string{"a.mk", "b.mk"} {
			if err := os.WriteFile(filepath.Join(dir, n), []byte("all:\n\techo\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		// `./` prefixes so the recorded path differs from the resolved one
		// unless the resolved form is what gets written back.
		refs := captureScriptRefs(context.Background(),
			[]string{"make", "-f", "./a.mk", "-f", "./b.mk"}, dir, ScriptCaptureIdentity)
		if len(refs) != 2 {
			t.Fatalf("expected 2 refs, got %+v", refs)
		}
		for i, want := range []string{filepath.Join(dir, "a.mk"), filepath.Join(dir, "b.mk")} {
			if refs[i].Unresolved == "" {
				t.Fatalf("ref %d must be unresolved under a 1-byte budget: %+v", i, refs[i])
			}
			if refs[i].Path != want {
				t.Errorf("ref %d Path = %q, want %q — an operand rejected before the open "+
					"still has to say which file it was", i, refs[i].Path, want)
			}
		}
	})

	// COUNTERWEIGHT. Every assertion above is satisfied by an implementation
	// that resolves a path and then refuses to measure anything. The success
	// path must still record the same absolute path AND still hydrate.
	t.Run("success still records the resolved path and hydrates", func(t *testing.T) {
		dir := t.TempDir()
		body := "echo built\n"
		if err := os.WriteFile(filepath.Join(dir, "ok.sh"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "ok.sh"}, dir, ScriptCaptureContent)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		r := refs[0]

		if r.Unresolved != "" {
			t.Fatalf("an ordinary script must hydrate, got %q", r.Unresolved)
		}
		if want := filepath.Join(dir, "ok.sh"); r.Path != want {
			t.Errorf("Path = %q, want %q", r.Path, want)
		}
		if r.SizeBytes != int64(len(body)) || r.Content != body {
			t.Errorf("the success path lost its measurement: %+v", r)
		}
		wantDigest, err := cryptoutil.CalculateDigestSetFromBytes([]byte(body), defaultScriptDigests())
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Digest) != len(wantDigest) {
			t.Fatalf("digest set size %d != %d", len(r.Digest), len(wantDigest))
		}
		for k, v := range wantDigest {
			if r.Digest[k] != v {
				t.Errorf("digest %v = %q, want %q", k, r.Digest[k], v)
			}
		}
	})
}

// TestOperandThatCannotBeMadeAbsoluteSaysSo covers the one case where there is
// no absolute path to record: no working directory was supplied AND the process
// cannot report its own.
//
// The tempting fallback is to leave the relative operand in Path and say
// nothing. That is precisely the defect this round is about, one level deeper:
// the record would claim a resolution that never happened. The struct could not
// express "attempted, not resolvable" — a bare token and a resolved relative
// path were the same string — so PathUnresolvable was added to separate them.
func TestOperandThatCannotBeMadeAbsoluteSaysSo(t *testing.T) {
	t.Run("marked when the working directory is unavailable", func(t *testing.T) {
		restore := getwd
		getwd = func() (string, error) { return "", errors.New("getwd: no such file or directory") }
		t.Cleanup(func() { getwd = restore })

		// Empty workdir, so the operand can only be resolved via the process
		// working directory — which the injection above has taken away.
		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "build.sh"}, "", ScriptCaptureIdentity)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		r := refs[0]

		if !r.PathUnresolvable {
			t.Errorf("Path %q could not be made absolute and the record does not say so: "+
				"a reader cannot tell this from a resolved relative path", r.Path)
		}
		if r.Unresolved == "" {
			t.Error("an operand that could not be located must carry a reason")
		}
		if r.Path != "build.sh" {
			t.Errorf("Path = %q, want the argv operand %q preserved as the best known form",
				r.Path, "build.sh")
		}
		if len(r.Digest) != 0 || r.SizeBytes != 0 {
			t.Errorf("nothing may be measured: %+v", r)
		}
	})

	// COUNTERWEIGHT: an empty workdir is NOT by itself unresolvable. With a
	// working process CWD the operand resolves against it, exactly where the
	// command itself would run, and the flag must stay off. Marking this case
	// would turn every workdir-less caller's evidence into a degraded record.
	t.Run("empty workdir alone resolves against the process cwd", func(t *testing.T) {
		cwd, err := getwd()
		if err != nil {
			t.Skipf("no process working directory here: %v", err)
		}

		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "definitely-not-here.sh"}, "", ScriptCaptureIdentity)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		r := refs[0]

		if r.PathUnresolvable {
			t.Errorf("Path %q resolved fine against the process cwd but was marked "+
				"unresolvable", r.Path)
		}
		if want := filepath.Join(cwd, "definitely-not-here.sh"); r.Path != want {
			t.Errorf("Path = %q, want %q", r.Path, want)
		}
	})
}

// TestWindowsExecutableSuffixResolves covers interpreters named the way Windows
// names them.
//
// cilock ships a windows/amd64 binary and commandrun carries no build tag, so
// this resolver runs there. Every interpreter is `python.exe`, `bash.exe`,
// `make.exe`, and NTFS is case-insensitive so `Make.EXE` is the same program as
// `make`. Matching the raw basename finds none of them, and the attestor
// silently records no script evidence for every interpreted step on the
// platform.
//
// That is MISSING evidence rather than WRONG evidence, which is the safe
// direction — but it is missing for a reason that has nothing to do with the
// command, and a verifier cannot distinguish "this step ran no script" from
// "this attestor cannot read this platform's program names".
func TestWindowsExecutableSuffixResolves(t *testing.T) {
	t.Run("windows", func(t *testing.T) {
		restore := windowsExecutableNames
		windowsExecutableNames = true
		t.Cleanup(func() { windowsExecutableNames = restore })

		for _, tc := range []struct {
			name string
			argv []string
			want string
			role ScriptRole
		}{
			{"python.exe", []string{"python.exe", "build.py"}, "build.py", RoleInterpreterOperand},
			{"bash.exe", []string{"bash.exe", "build.sh"}, "build.sh", RoleInterpreterOperand},
			{"make.exe", []string{"make.exe", "-f", "Custom.mk"}, "Custom.mk", RoleMakefile},
			// NTFS is case-insensitive: this is the same program.
			{"upper BASH.EXE", []string{"BASH.EXE", "build.sh"}, "build.sh", RoleInterpreterOperand},
			{"mixed Make.Exe", []string{"Make.Exe", "-f", "Custom.mk"}, "Custom.mk", RoleMakefile},
			// A full path, as a shell would hand it over.
			{"absolute path", []string{`C:\Python311\python.exe`, "build.py"}, "build.py", RoleInterpreterOperand},
			// The suffix must not defeat the option grammar either.
			{"clustered options", []string{"bash.exe", "-euo", "pipefail", "build.sh"}, "build.sh", RoleInterpreterOperand},
		} {
			t.Run(tc.name, func(t *testing.T) {
				refs := resolveScriptOperands(tc.argv, "")
				if len(refs) != 1 || refs[0].Path != tc.want {
					t.Fatalf("resolved %+v, want one ref with path %q", refs, tc.want)
				}
				if refs[0].Role != tc.role {
					t.Errorf("role = %q, want %q", refs[0].Role, tc.role)
				}
			})
		}
	})

	// COUNTERWEIGHT. On a POSIX system a file named "python.exe" is a file
	// named "python.exe" — not python. Stripping the suffix there would claim
	// python's argument grammar for a program this resolver has never seen, and
	// a wrong grammar is how the wrong file gets signed as the executed script.
	// Abstaining is correct here.
	t.Run("posix does not strip the suffix", func(t *testing.T) {
		restore := windowsExecutableNames
		windowsExecutableNames = false
		t.Cleanup(func() { windowsExecutableNames = restore })

		for _, argv := range [][]string{
			{"python.exe", "build.py"},
			{"bash.exe", "build.sh"},
			{"make.exe", "-f", "Custom.mk"},
			{"BASH", "build.sh"}, // case is significant on POSIX
		} {
			if refs := resolveScriptOperands(argv, ""); len(refs) != 0 {
				t.Errorf("argv %v resolved to %+v on POSIX — a program this resolver "+
					"has never seen must abstain, not borrow another's grammar", argv, refs)
			}
		}
	})

	// COUNTERWEIGHT. The ordinary POSIX names must keep working under BOTH
	// settings; the Windows rule must add names, never replace them.
	t.Run("plain names still resolve either way", func(t *testing.T) {
		for _, windows := range []bool{false, true} {
			restore := windowsExecutableNames
			windowsExecutableNames = windows
			refs := resolveScriptOperands([]string{"bash", "build.sh"}, "")
			if len(refs) != 1 || refs[0].Path != "build.sh" {
				t.Errorf("windowsExecutableNames=%v broke the ordinary case: %+v", windows, refs)
			}
			refs = resolveScriptOperands([]string{"make", "-f", "Custom.mk"}, "")
			if len(refs) != 1 || refs[0].Path != "Custom.mk" {
				t.Errorf("windowsExecutableNames=%v broke make: %+v", windows, refs)
			}
			windowsExecutableNames = restore
		}
	})
}

// TestContentOmittedBinaryCoversTheWholeFile pins the field to the claim its
// name makes.
//
// ContentOmittedBinary says "the file is not valid UTF-8". It was computed from
// the retained 256 KiB prefix, so a file that is text for its first 256 KiB and
// binary afterwards came back with the flag FALSE — a positive assertion that
// the whole file is text — plus an embedded text prefix marked merely
// truncated. A verifier reading that is told it holds a truncated text script
// when it holds the readable head of a binary artifact.
//
// Validating the whole stream is the fix rather than renaming the field to
// match the smaller thing it measured: the bytes already flow past for the
// digest, so whole-file validation costs CPU and no I/O, and it makes
// ContentOmittedBinary=false a claim a verifier can actually rely on. Renaming
// would leave nobody able to tell a truncated script from a binary blob with a
// text header, which is precisely the case an operator wants flagged.
func TestContentOmittedBinaryCoversTheWholeFile(t *testing.T) {
	t.Run("invalid bytes after the retained prefix are still detected", func(t *testing.T) {
		dir := t.TempDir()
		// Valid UTF-8 through the whole retained prefix and well beyond it,
		// then bytes that are not.
		body := append([]byte(strings.Repeat("a", maxScriptContentBytes+4096)), 0xff, 0xfe, 0xfd)
		if err := os.WriteFile(filepath.Join(dir, "sneaky.sh"), body, 0o600); err != nil {
			t.Fatal(err)
		}

		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "sneaky.sh"}, dir, ScriptCaptureContent)
		if len(refs) != 1 || refs[0].Unresolved != "" {
			t.Fatalf("expected one hydrated ref, got %+v", refs)
		}
		r := refs[0]

		if !r.ContentOmittedBinary {
			t.Errorf("ContentOmittedBinary=false claims the whole file is valid UTF-8, "+
				"but the invalid bytes are past the %d-byte retained prefix where the "+
				"check could not see them", maxScriptContentBytes)
		}
		if r.Content != "" {
			t.Errorf("a binary artifact's text head must not be embedded as a script "+
				"body (%d bytes were)", len(r.Content))
		}
		// The digest and size still describe the whole file: withholding the
		// body is not the same as not measuring it.
		if len(r.Digest) == 0 || r.SizeBytes != int64(len(body)) {
			t.Errorf("size/digest must still cover the whole file: %+v", r)
		}
	})

	// COUNTERWEIGHT. A whole-file validator that gets this wrong stops
	// embedding every large script in the fleet, silently.
	t.Run("a large VALID file is still embedded and marked truncated", func(t *testing.T) {
		dir := t.TempDir()
		body := strings.Repeat("a", maxScriptContentBytes+4096)
		if err := os.WriteFile(filepath.Join(dir, "big.sh"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "big.sh"}, dir, ScriptCaptureContent)
		if len(refs) != 1 || refs[0].Unresolved != "" {
			t.Fatalf("expected one hydrated ref, got %+v", refs)
		}
		r := refs[0]

		if r.ContentOmittedBinary {
			t.Fatal("a large file of plain ASCII was reported binary")
		}
		if !r.ContentTruncated {
			t.Error("a file past the content cap must be marked truncated")
		}
		if len(r.Content) != maxScriptContentBytes {
			t.Errorf("embedded %d bytes, want the full %d-byte prefix",
				len(r.Content), maxScriptContentBytes)
		}
		if r.SizeBytes != int64(len(body)) {
			t.Errorf("size = %d, want %d", r.SizeBytes, len(body))
		}
	})

	// COUNTERWEIGHT. Streaming validation sees the file in ~32 KiB chunks, so a
	// multibyte rune straddling a chunk boundary is the obvious way to get a
	// false "binary". The euro sign starts at byte 32767, one byte before the
	// first boundary.
	t.Run("a multibyte rune split across a read boundary is still valid", func(t *testing.T) {
		dir := t.TempDir()
		body := strings.Repeat("a", 32767) + "\u20ac" + strings.Repeat("b", maxScriptContentBytes)
		if err := os.WriteFile(filepath.Join(dir, "utf8.sh"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "utf8.sh"}, dir, ScriptCaptureContent)
		if len(refs) != 1 || refs[0].Unresolved != "" {
			t.Fatalf("expected one hydrated ref, got %+v", refs)
		}
		if refs[0].ContentOmittedBinary {
			t.Error("a rune split across a read boundary was reported as binary — " +
				"validation must carry incomplete runes between chunks")
		}
		if !utf8.ValidString(refs[0].Content) {
			t.Error("the embedded prefix is not valid UTF-8")
		}
	})

	// COUNTERWEIGHT. Small ordinary scripts are the common case and must be
	// embedded whole, untruncated, unflagged.
	t.Run("an ordinary small script is embedded whole", func(t *testing.T) {
		dir := t.TempDir()
		body := "#!/bin/sh\necho ünïcödé is fine\n"
		if err := os.WriteFile(filepath.Join(dir, "small.sh"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "small.sh"}, dir, ScriptCaptureContent)
		if len(refs) != 1 || refs[0].Unresolved != "" {
			t.Fatalf("expected one hydrated ref, got %+v", refs)
		}
		r := refs[0]
		if r.ContentOmittedBinary || r.ContentTruncated {
			t.Errorf("an ordinary script was flagged: %+v", r)
		}
		if r.Content != body {
			t.Errorf("content = %q, want %q", r.Content, body)
		}
	})
}

// TestOptionsTheShellDoesNotSupportAbstain covers options the grammar tables
// claimed for EVERY shell that only some shells have.
//
// One optionGrammar was shared by sh, bash, zsh, dash, ksh and ash, so bash's
// own options were asserted for all six. `dash --norc decoy.sh` exits on the
// unsupported option without ever opening decoy.sh, and the resolver recorded
// and hashed it anyway: signed evidence that a script executed when it provably
// did not. Wrong evidence, not missing evidence — the bad direction.
//
// Every case below was determined by RUNNING the real binary, not by reading
// documentation; see TestGrammarSwitchClaimsHoldAgainstRealInterpreters, which
// re-derives these from the table on every run.
func TestOptionsTheShellDoesNotSupportAbstain(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		// Named by the review.
		{"dash --norc", []string{"dash", "--norc", "decoy.sh"}},
		{"dash --noprofile", []string{"dash", "--noprofile", "decoy.sh"}},
		{"zsh --norc", []string{"zsh", "--norc", "decoy.sh"}},
		{"ksh --noprofile", []string{"ksh", "--noprofile", "decoy.sh"}},

		// Found by the harness, not by the review: dash rejects these too.
		{"dash --posix", []string{"dash", "--posix", "decoy.sh"}},
		{"dash -h", []string{"dash", "-h", "decoy.sh"}},
		{"dash -k", []string{"dash", "-k", "decoy.sh"}},
		{"dash -p", []string{"dash", "-p", "decoy.sh"}},
		{"dash -t", []string{"dash", "-t", "decoy.sh"}},
		{"zsh --posix", []string{"zsh", "--posix", "decoy.sh"}},
		{"zsh --noprofile", []string{"zsh", "--noprofile", "decoy.sh"}},
		{"ksh --posix", []string{"ksh", "--posix", "decoy.sh"}},

		// `sh` is not a program, it is a name: it is bash on macOS and dash on
		// Debian. Anything not verified on BOTH must abstain under that name.
		{"sh --norc", []string{"sh", "--norc", "decoy.sh"}},
		{"sh --noprofile", []string{"sh", "--noprofile", "decoy.sh"}},
		{"sh -h", []string{"sh", "-h", "decoy.sh"}},

		// ash could not be verified anywhere the harness runs, so it claims no
		// options at all.
		{"ash -e", []string{"ash", "-e", "decoy.sh"}},
		{"ash -o errexit", []string{"ash", "-o", "errexit", "decoy.sh"}},

		// Clusters must not smuggle one in either.
		{"dash -ex cluster with -h", []string{"dash", "-exh", "decoy.sh"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if refs := resolveScriptOperands(tc.argv, ""); len(refs) != 0 {
				t.Errorf("recorded %+v — this interpreter exits on that option "+
					"without opening the operand, so the record claims a script "+
					"executed that provably did not", refs)
			}
		})
	}
}

// TestMakeEmptyDirectoryValueAbstains covers `make --directory=`.
//
// An empty -C value was treated as a no-op, so the resolver carried on and
// recorded the -f makefile. Real make refuses: "the `-C' option requires a
// non-empty string argument", exit 2, no makefile read. Recording one signs a
// file the build never opened.
func TestMakeEmptyDirectoryValueAbstains(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"--directory=", []string{"make", "--directory=", "-f", "decoy.mk"}},
		{"-C empty arg", []string{"make", "-C", "", "-f", "decoy.mk"}},
		{"--directory empty arg", []string{"make", "--directory", "", "-f", "decoy.mk"}},
		// An empty -C must also suppress the IMPLICIT lookup, not just -f:
		// falling through would hash whatever Makefile happens to be present.
		{"--directory= with implicit makefile", []string{"make", "--directory="}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if refs := resolveScriptOperands(tc.argv, ""); len(refs) != 0 {
				t.Errorf("recorded %+v — make fails on an empty -C before reading "+
					"any makefile", refs)
			}
		})
	}
}

// TestValueOptionsWithUnverifiedValuesAbstain closes the gap the previous round
// DOCUMENTED instead of fixing.
//
// The harness header said "option values aren't modelled — `dash -o pipefail`
// fails on the value, not the option". That was true and it was not enough: the
// code went on consuming the value and signing the operand as executed. A
// stated limitation that still emits a positive claim is a bug with a comment.
//
// Two kinds of value option exist and the probe tells them apart. Some are
// OPAQUE — `perl -I /nonexistent` still runs the script, so no value can make
// the claim wrong. Others are load-bearing: the interpreter validates the value
// and exits without running anything. Those may only carry values verified
// against the real binary, and anything else abstains.
func TestValueOptionsWithUnverifiedValuesAbstain(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		// Named by the review: dash has no pipefail, so it exits before
		// build.sh runs.
		{"dash -o pipefail", []string{"dash", "-o", "pipefail", "build.sh"}},
		{"dash -o pipefail clustered", []string{"dash", "-euo", "pipefail", "build.sh"}},
		// sh may BE dash, so the same value is unsafe under that name.
		{"sh -o pipefail", []string{"sh", "-o", "pipefail", "build.sh"}},
		{"zsh -o pipefail", []string{"zsh", "-o", "pipefail", "build.sh"}},

		// Nonsense values: no shell accepts these, on any implementation.
		{"bash -o garbage", []string{"bash", "-o", "zzznope", "build.sh"}},
		{"dash -o garbage", []string{"dash", "-o", "zzznope", "build.sh"}},
		{"bash -o attached garbage", []string{"bash", "-ozzznope", "build.sh"}},

		// -o noexec runs NOTHING on any shell, which is why the enumeration is
		// derived from the probe and not from the POSIX list that contains it.
		{"bash -o noexec", []string{"bash", "-o", "noexec", "build.sh"}},
		{"dash -o noexec", []string{"dash", "-o", "noexec", "build.sh"}},

		// Unbounded value-sensitive options: the interpreter resolves the value
		// and exits when it cannot, and the set of valid values is every module
		// or encoding name in existence, so nothing can be verified.
		{"ruby -r lib", []string{"ruby", "-r", "somelib", "build.rb"}},
		{"ruby -E enc", []string{"ruby", "-E", "UTF-8", "build.rb"}},
		{"node -r mod", []string{"node", "-r", "somemod", "build.js"}},
		{"node --require mod", []string{"node", "--require", "somemod", "build.js"}},

		// make --eval does not exist before GNU make 3.82 and could not be
		// verified here.
		{"make -E", []string{"make", "-E", "x=1", "-f", "real.mk"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if refs := resolveScriptOperands(tc.argv, ""); len(refs) != 0 {
				t.Errorf("recorded %+v — the interpreter validates this value and exits "+
					"without running the operand, so the record claims an execution "+
					"that did not happen", refs)
			}
		})
	}
}

// TestBashLongOptionsAfterShortOptionsAbstain covers argument ORDER, which the
// probe harness had verified nothing about.
//
// scanArgs classified tokens order-independently. Bash does not: its long
// options are only recognised before any short option. `bash -e --norc
// build.sh` makes bash report "--: invalid option" and never run build.sh,
// while the resolver walked past both and signed build.sh.
//
// Verified against the real binary, both directions: `bash --norc -e decoy`
// runs, `bash -e --norc decoy` does not.
func TestBashLongOptionsAfterShortOptionsAbstain(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"bash -e --norc", []string{"bash", "-e", "--norc", "build.sh"}},
		{"bash -e --posix", []string{"bash", "-e", "--posix", "build.sh"}},
		{"bash -e --noprofile", []string{"bash", "-e", "--noprofile", "build.sh"}},
		{"bash cluster then long", []string{"bash", "-eu", "--norc", "build.sh"}},
		{"bash value option then long", []string{"bash", "-o", "errexit", "--norc", "build.sh"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if refs := resolveScriptOperands(tc.argv, ""); len(refs) != 0 {
				t.Errorf("recorded %+v — bash rejects a long option in this position "+
					"and never runs the operand", refs)
			}
		})
	}
}

// TestMakeMissingChdirDirectoryRecordsNoDigest pins what `-C` naming a
// directory that is not there actually produces.
//
// make chdirs BEFORE it opens any makefile: `-C missing` makes it exit 2 having
// read nothing at all. So no path this argv named was read, and measuring any
// of them attaches a real digest to a file the command demonstrably never
// opened.
//
// The RELATIVE -f case used to degrade correctly by accident — the composed
// path does not resolve either, so nothing got hashed — and that accident is
// what hid the real one. With an ABSOLUTE -f the composed path exists, and the
// resolver hashed it and signed it as a makefile of a successful build. This
// test previously documented that as an accepted residual; it is not one, and
// the absolute case below is the regression guard.
//
// The check lives in the capture layer, not in makefileOperands: composing the
// path is a pure function of argv that the tests below go on asking about trees
// that do not exist, while whether make could reach it is a fact about the disk
// and belongs where the bytes are actually read.
func TestMakeMissingChdirDirectoryRecordsNoDigest(t *testing.T) {
	dir := t.TempDir()

	t.Run("relative -f under a missing -C measures nothing", func(t *testing.T) {
		refs := captureScriptRefs(context.Background(),
			[]string{"make", "-C", "nope-zzz", "-f", "x.mk"}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		if refs[0].Unresolved == "" || len(refs[0].Digest) != 0 || refs[0].SizeBytes != 0 {
			t.Errorf("a makefile under a missing -C must carry a reason and no "+
				"measurement: %+v", refs[0])
		}
	})

	// THE REGRESSION GUARD. An absolute -f composes to a file that really is on
	// disk, so nothing about the path stops the measurement — only knowing that
	// make never got there does.
	t.Run("absolute -f under a missing -C measures nothing", func(t *testing.T) {
		real := filepath.Join(dir, "real.mk")
		if err := os.WriteFile(real, []byte("all:\n\t@echo hi\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		refs := captureScriptRefs(context.Background(),
			[]string{"make", "-C", "nope-zzz", "-f", real}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		if len(refs[0].Digest) != 0 || refs[0].SizeBytes != 0 {
			t.Errorf("make exits in the chdir and never opens %s, so hashing it "+
				"signs a makefile the build never read: %+v", real, refs[0])
		}
		if refs[0].Unresolved == "" {
			t.Errorf("a refusal must say why, or it is indistinguishable from an "+
				"empty file: %+v", refs[0])
		}
	})

	// -C at a path that exists but is not a directory fails the chdir just the
	// same, and an existence-only check would walk straight past it.
	t.Run("-C naming a regular file measures nothing", func(t *testing.T) {
		notDir := filepath.Join(dir, "a-file")
		if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		real := filepath.Join(dir, "real.mk")
		if err := os.WriteFile(real, []byte("all:\n"), 0o600); err != nil {
			t.Fatal(err)
		}

		refs := captureScriptRefs(context.Background(),
			[]string{"make", "-C", notDir, "-f", real}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		if len(refs[0].Digest) != 0 || refs[0].Unresolved == "" {
			t.Errorf("chdir into a regular file fails, so nothing was read: %+v", refs[0])
		}
	})

	// COUNTERWEIGHT: an existing -C directory is the ordinary case and must
	// still resolve and still hash.
	t.Run("existing -C still resolves and hydrates", func(t *testing.T) {
		sub := filepath.Join(dir, "sub")
		if err := os.Mkdir(sub, 0o750); err != nil {
			t.Fatal(err)
		}
		body := "all:\n\t@echo hi\n"
		if err := os.WriteFile(filepath.Join(sub, "x.mk"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		refs := captureScriptRefs(context.Background(),
			[]string{"make", "-C", "sub", "-f", "x.mk"}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 || refs[0].Unresolved != "" {
			t.Fatalf("an ordinary `make -C sub -f x.mk` must hydrate, got %+v", refs)
		}
		if refs[0].Path != filepath.Join(sub, "x.mk") || len(refs[0].Digest) == 0 {
			t.Errorf("lost the measurement: %+v", refs[0])
		}
	})
}

// TestPythonVersionSafeGrammars pins that python3's option table is claimed for
// python3 ALONE.
//
// One table served "python", "python2" and "python3". Every entry in it was
// probed against a real python3 and nothing else, and several do not exist in
// python 2.x: -I (3.4+), -q, -b, -X (3.2+) and --check-hash-based-pycs (3.7+).
// Python 2 exits with an option error without ever opening the operand, so the
// scan walked past the option, recorded the operand, and hashed a file that
// never ran.
//
// The probe harness cannot catch this by itself: it SKIPS an interpreter the
// machine does not carry, and no machine this suite runs on carries python2. So
// the sharing is what has to go, not the probe coverage.
//
// Bare `python` gets the same treatment for the reason `sh` does — it is a NAME,
// python 2.7 on RHEL 7/8, CentOS, Amazon Linux 1 and older Debian, and python 3
// elsewhere — and a claim made under it is only safe if it holds for both.
func TestPythonVersionSafeGrammars(t *testing.T) {
	dir := t.TempDir()
	body := "print('hi')\n"
	if err := os.WriteFile(filepath.Join(dir, "build.py"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	// MUST ABSTAIN: a python3-only option under a spelling that may be python 2.
	// Each of these currently hashes build.py when the tables are shared.
	for _, tc := range []struct {
		name string
		argv []string
	}{
		// Codex's example, verbatim: python 2 rejects the option and never
		// opens build.py.
		{"python2 --check-hash-based-pycs", []string{"python2", "--check-hash-based-pycs=default", "build.py"}},
		{"python2 -I isolated", []string{"python2", "-I", "build.py"}},
		{"python2 -q quiet", []string{"python2", "-q", "build.py"}},
		{"python2 -X opaque", []string{"python2", "-X", "faulthandler", "build.py"}},
		{"ambiguous python -I", []string{"python", "-I", "build.py"}},
		{"ambiguous python --check-hash-based-pycs", []string{"python", "--check-hash-based-pycs=default", "build.py"}},
	} {
		t.Run("abstains: "+tc.name, func(t *testing.T) {
			refs := captureScriptRefs(context.Background(), tc.argv, dir, ScriptCaptureIdentity)
			if len(refs) != 0 {
				t.Errorf("recorded %+v — this interpreter may reject the option and "+
					"never open the operand, so any digest here is a file that never ran", refs)
			}
		})
	}

	// COUNTERWEIGHT. Narrowing a grammar ships as "no evidence at all" if it
	// goes too far. The bare form is what CI overwhelmingly writes and it must
	// keep resolving under every spelling, and python3 must keep its own
	// probe-verified options.
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"bare python", []string{"python", "build.py"}},
		{"bare python2", []string{"python2", "build.py"}},
		{"bare python3", []string{"python3", "build.py"}},
		{"python3 keeps -I", []string{"python3", "-I", "build.py"}},
		{"python3 keeps --check-hash-based-pycs", []string{"python3", "--check-hash-based-pycs=default", "build.py"}},
		{"python3 keeps -X", []string{"python3", "-X", "faulthandler", "build.py"}},
	} {
		t.Run("still resolves: "+tc.name, func(t *testing.T) {
			refs := captureScriptRefs(context.Background(), tc.argv, dir, ScriptCaptureIdentity)
			if len(refs) != 1 || refs[0].Unresolved != "" || len(refs[0].Digest) == 0 {
				t.Fatalf("lost ordinary script evidence: %+v", refs)
			}
			if refs[0].Path != filepath.Join(dir, "build.py") {
				t.Errorf("path = %q, want %q", refs[0].Path, filepath.Join(dir, "build.py"))
			}
		})
	}

	// Inline code must still refuse under every spelling: the unresolvable set
	// is shared, and dropping it while narrowing would turn `python -c "..."`
	// into a recorded path.
	for _, argv := range [][]string{
		{"python", "-c", "print(1)"},
		{"python2", "-c", "print(1)"},
		{"python3", "-c", "print(1)"},
		{"python2", "-m", "pytest"},
	} {
		t.Run("inline/module still refuses: "+argv[0]+" "+argv[1], func(t *testing.T) {
			if refs := captureScriptRefs(context.Background(), argv, dir, ScriptCaptureIdentity); len(refs) != 0 {
				t.Errorf("inline code or a module name is not a script path: %+v", refs)
			}
		})
	}
}

// TestGrammarNarrowingKeepsOrdinaryInvocations is the counterweight to the two
// tests above and to the table narrowing behind them.
//
// Splitting one shared grammar into per-interpreter tables is exactly the
// change that ships as "no script evidence at all" if it goes too far. These
// are the invocations that appear in real CI and they must keep resolving.
func TestGrammarNarrowingKeepsOrdinaryInvocations(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want string
		role ScriptRole
	}{
		{"bare sh", []string{"sh", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"bare bash", []string{"bash", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"bare dash", []string{"dash", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"bare zsh", []string{"zsh", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"bare ksh", []string{"ksh", "build.sh"}, "build.sh", RoleInterpreterOperand},
		// ash claims no OPTIONS, but the program is still recognised.
		{"bare ash", []string{"ash", "build.sh"}, "build.sh", RoleInterpreterOperand},

		// The canonical CI idiom, on every shell that verified -e/-u/-o.
		{"bash -euo pipefail", []string{"bash", "-euo", "pipefail", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"sh -eu", []string{"sh", "-eu", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"dash -e", []string{"dash", "-e", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"dash -x", []string{"dash", "-x", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"zsh -e", []string{"zsh", "-e", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"ksh -eux", []string{"ksh", "-eux", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"dash -o errexit", []string{"dash", "-o", "errexit", "build.sh"}, "build.sh", RoleInterpreterOperand},

		// bash keeps its own options, which DID verify against bash.
		{"bash --norc", []string{"bash", "--norc", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"bash --noprofile", []string{"bash", "--noprofile", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"bash --posix", []string{"bash", "--posix", "build.sh"}, "build.sh", RoleInterpreterOperand},
		{"bash -h", []string{"bash", "-h", "build.sh"}, "build.sh", RoleInterpreterOperand},

		// make must be untouched by the -C change unless the value is empty.
		{"make -f", []string{"make", "-f", "real.mk"}, "real.mk", RoleMakefile},
		{"make -C sub -f", []string{"make", "-C", "sub", "-f", "real.mk"}, "sub/real.mk", RoleMakefile},
		{"make --directory=sub -f", []string{"make", "--directory=sub", "-f", "real.mk"}, "sub/real.mk", RoleMakefile},
		{"make -n -f", []string{"make", "-n", "-f", "real.mk"}, "real.mk", RoleMakefile},

		// The other interpreters are unchanged; every one of their switch
		// claims verified against the real binary.
		{"python3 -B", []string{"python3", "-B", "build.py"}, "build.py", RoleInterpreterOperand},
		{"perl -w", []string{"perl", "-w", "build.pl"}, "build.pl", RoleInterpreterOperand},
		{"ruby -w", []string{"ruby", "-w", "build.rb"}, "build.rb", RoleInterpreterOperand},
		{"node --no-warnings", []string{"node", "--no-warnings", "build.js"}, "build.js", RoleInterpreterOperand},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refs := resolveScriptOperands(tc.argv, "")
			if len(refs) != 1 {
				t.Fatalf("resolved %+v, want exactly one ref with path %q — "+
					"narrowing the grammars must not cost ordinary evidence",
					refs, tc.want)
			}
			if refs[0].Path != tc.want {
				t.Errorf("path = %q, want %q", refs[0].Path, tc.want)
			}
			if refs[0].Role != tc.role {
				t.Errorf("role = %q, want %q", refs[0].Role, tc.role)
			}
		})
	}
}

// TestScriptCaptureModeDefault pins the default. An attestor constructed
// without the option must capture identity, not nothing — the zero value of the
// field is the empty string, and treating that as "off" would silently disable
// capture for every existing caller.
func TestScriptCaptureModeDefault(t *testing.T) {
	var rc CommandRun
	if got := rc.scriptCaptureMode(); got != ScriptCaptureIdentity {
		t.Errorf("default mode = %q, want %q", got, ScriptCaptureIdentity)
	}

	for _, mode := range []ScriptCaptureMode{ScriptCaptureOff, ScriptCaptureContent, ScriptCaptureIdentity} {
		rc := CommandRun{}
		WithScriptCapture(mode)(&rc)
		if got := rc.scriptCaptureMode(); got != mode {
			t.Errorf("WithScriptCapture(%q) => %q", mode, got)
		}
	}

	// An unrecognised value must fall back to the default rather than disable
	// capture, so a typo in configuration degrades to more evidence, not less.
	rc2 := CommandRun{}
	WithScriptCapture(ScriptCaptureMode("nonsense"))(&rc2)
	if got := rc2.scriptCaptureMode(); got != ScriptCaptureIdentity {
		t.Errorf("unknown mode => %q, want fallback %q", got, ScriptCaptureIdentity)
	}
}

// TestScriptsSurviveV02RoundTrip guards the wire shape. A digest the attestor
// collects and the marshaller drops is worse than not collecting it: the
// operator believes the evidence exists.
func TestScriptsSurviveV02RoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.sh"), []byte("#!/bin/sh\ncosign sign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := CommandRun{
		Cmd:     []string{"bash", "r.sh"},
		Scripts: captureScriptRefs(context.Background(), []string{"bash", "r.sh"}, dir, ScriptCaptureIdentity),
	}
	if len(orig.Scripts) != 1 || len(orig.Scripts[0].Digest) == 0 {
		t.Fatalf("fixture did not produce a digested script: %+v", orig.Scripts)
	}

	raw, err := json.Marshal(&orig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"scripts"`) {
		t.Fatalf("marshalled predicate has no scripts field: %s", raw)
	}

	var back CommandRun
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Scripts) != 1 {
		t.Fatalf("scripts did not survive the round trip: %+v", back.Scripts)
	}
	if back.Scripts[0].Path != orig.Scripts[0].Path {
		t.Errorf("path drifted: %q -> %q", orig.Scripts[0].Path, back.Scripts[0].Path)
	}
	if len(back.Scripts[0].Digest) == 0 {
		t.Error("digest did not survive the round trip")
	}
}

// TestMakeChangeDirectory covers `make -C`, which GNU make honours before
// looking for a makefile. Ignoring it hashes the caller's Makefile while the
// build actually read another one — signed evidence pointing at a file that
// was never used.
func TestMakeChangeDirectory(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "child")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	// A Makefile in BOTH directories, so choosing the wrong one is detectable.
	for _, d := range []string{root, sub} {
		if err := os.WriteFile(filepath.Join(d, "Makefile"), []byte("all:\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got := resolveScriptOperands([]string{"make", "-C", "child"}, root)
	if len(got) != 1 {
		t.Fatalf("expected 1 makefile, got %+v", got)
	}
	// Assert the DIRECTORY, not the filename. On a case-insensitive
	// filesystem (macOS by default) "Makefile" and "makefile" are the same
	// file, so the spelling the search order returns is not meaningful — but
	// which directory it came from is exactly what -C governs.
	if gotDir := filepath.Dir(got[0].Path); gotDir != sub {
		t.Errorf("makefile resolved in %q, want %q — make -C was ignored", gotDir, sub)
	}
}

// TestScriptRefFieldsComeFromOneFile pins the single-descriptor contract: the
// size and digest recorded must describe the same bytes, even if the path is
// rewritten while capture is in flight.
func TestScriptRefFieldsComeFromOneFile(t *testing.T) {
	dir := t.TempDir()
	body := "#!/bin/sh\necho consistent\n"
	if err := os.WriteFile(filepath.Join(dir, "s.sh"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	refs := captureScriptRefs(context.Background(), []string{"sh", "s.sh"}, dir, ScriptCaptureContent)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %+v", refs)
	}
	r := refs[0]
	if r.SizeBytes != int64(len(body)) {
		t.Errorf("size %d != file size %d", r.SizeBytes, len(body))
	}
	if r.Content != body {
		t.Errorf("content mismatch: %q", r.Content)
	}
	// The digest must be over the same bytes the content reports.
	want, err := cryptoutil.CalculateDigestSetFromBytes([]byte(body), defaultScriptDigests())
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Digest) != len(want) {
		t.Fatalf("digest set size %d != %d", len(r.Digest), len(want))
	}
	for k, v := range want {
		if r.Digest[k] != v {
			t.Errorf("digest %v = %q, want %q (fields came from different reads)", k, r.Digest[k], v)
		}
	}
}

// TestMakeMultipleFileFlags covers GNU make reading EVERY -f it is given.
// Overwriting on each flag signed only the last makefile and silently omitted
// the others — a partial record that looks complete.
func TestMakeMultipleFileFlags(t *testing.T) {
	got := resolveScriptOperands(
		[]string{"make", "-f", "base.mk", "-f", "build.mk", "all"}, "")
	if len(got) != 2 {
		t.Fatalf("expected both makefiles, got %d: %+v", len(got), got)
	}
	// Order matters: make applies them in the order given.
	if got[0].Path != "base.mk" || got[1].Path != "build.mk" {
		t.Errorf("got %q,%q — want base.mk,build.mk in order",
			got[0].Path, got[1].Path)
	}
	for _, r := range got {
		if r.Role != RoleMakefile {
			t.Errorf("role = %q, want %q", r.Role, RoleMakefile)
		}
	}
}

// TestMakeMultipleFileFlagsWithChdir checks -f list and -C compose.
func TestMakeMultipleFileFlagsWithChdir(t *testing.T) {
	got := resolveScriptOperands(
		[]string{"make", "-C", "sub", "-f", "a.mk", "--file=b.mk"}, "/base")
	if len(got) != 2 {
		t.Fatalf("expected 2 makefiles, got %+v", got)
	}
	for i, want := range []string{"/base/sub/a.mk", "/base/sub/b.mk"} {
		if got[i].Path != want {
			t.Errorf("makefile[%d] = %q, want %q", i, got[i].Path, want)
		}
	}
}

// TestParseScriptCaptureMode pins the asymmetry between an ABSENT value and a
// WRONG one. An unset field means "caller predates the option" and defaults to
// identity; a string an operator typed must fail loudly, because silently
// treating "contnet" as identity leaves them believing content capture is on.
func TestParseScriptCaptureMode(t *testing.T) {
	for in, want := range map[string]ScriptCaptureMode{
		"":         ScriptCaptureIdentity,
		"off":      ScriptCaptureOff,
		"identity": ScriptCaptureIdentity,
		"content":  ScriptCaptureContent,
	} {
		got, err := ParseScriptCaptureMode(in)
		if err != nil {
			t.Errorf("ParseScriptCaptureMode(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseScriptCaptureMode(%q) = %q, want %q", in, got, want)
		}
	}

	for _, bad := range []string{"contnet", "Content", "on", "true", "full"} {
		if _, err := ParseScriptCaptureMode(bad); err == nil {
			t.Errorf("ParseScriptCaptureMode(%q) accepted an invalid mode — a typo "+
				"must fail loudly, not silently degrade to the default", bad)
		}
	}
}

// TestMakeAttachedChdirForm covers `make -Csub`, GNU make's attached -C form.
// Missing it is worse than missing the file: resolution falls through to
// implicit lookup and can hash a default Makefile make never reads.
func TestMakeAttachedChdirForm(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "child")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{root, sub} {
		if err := os.WriteFile(filepath.Join(d, "Makefile"), []byte("all:\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := resolveScriptOperands([]string{"make", "-Cchild"}, root)
	if len(got) != 1 {
		t.Fatalf("expected 1 makefile, got %+v", got)
	}
	if gotDir := filepath.Dir(got[0].Path); gotDir != sub {
		t.Errorf("resolved in %q, want %q — attached -C form was ignored", gotDir, sub)
	}
}

// TestHydrateSinglePassConsistency pins that size, digest and content all come
// from ONE read of the same bytes. A stat-derived size, or a re-read for
// content, can describe bytes the digest never saw.
func TestHydrateSinglePassConsistency(t *testing.T) {
	dir := t.TempDir()
	// Larger than the content cap so the truncation path is exercised too.
	body := strings.Repeat("x", maxScriptContentBytes+1024)
	if err := os.WriteFile(filepath.Join(dir, "big.sh"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	refs := captureScriptRefs(context.Background(), []string{"bash", "big.sh"}, dir, ScriptCaptureContent)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %+v", refs)
	}
	r := refs[0]

	// Size must be the FULL byte count seen by the hash, not the capped body.
	if r.SizeBytes != int64(len(body)) {
		t.Errorf("SizeBytes = %d, want %d (size must come from the hashed stream)",
			r.SizeBytes, len(body))
	}
	if !r.ContentTruncated {
		t.Error("oversized content must be flagged truncated")
	}
	if len(r.Content) != maxScriptContentBytes {
		t.Errorf("content len = %d, want cap %d", len(r.Content), maxScriptContentBytes)
	}
	// The digest must cover the whole file, not the retained prefix.
	want, err := cryptoutil.CalculateDigestSetFromBytes([]byte(body), defaultScriptDigests())
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range want {
		if r.Digest[k] != v {
			t.Errorf("digest %v = %q, want whole-file %q", k, r.Digest[k], v)
		}
	}
}

// TestTruncationDoesNotSplitARune guards the boundary between the byte cap and
// UTF-8 validation.
//
// The capped buffer stops at exactly maxScriptContentBytes, which can land
// inside a multibyte character. Validating that byte string reports invalid
// UTF-8, and a perfectly ordinary text build script gets signed as
// ContentOmittedBinary purely because of where the cap fell.
func TestTruncationDoesNotSplitARune(t *testing.T) {
	dir := t.TempDir()
	// "é" is two bytes. Pad so the cap lands between them, then keep writing
	// so the file is genuinely over the limit.
	body := strings.Repeat("a", maxScriptContentBytes-1) + "é" + strings.Repeat("b", 100)
	if err := os.WriteFile(filepath.Join(dir, "utf8.sh"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	refs := captureScriptRefs(context.Background(), []string{"bash", "utf8.sh"}, dir, ScriptCaptureContent)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %+v", refs)
	}
	r := refs[0]
	if r.ContentOmittedBinary {
		t.Error("a text script must not be flagged binary because the cap split a rune")
	}
	if !r.ContentTruncated {
		t.Error("oversized content must still be flagged truncated")
	}
	if !utf8.ValidString(r.Content) {
		t.Error("captured content must be valid UTF-8 after trimming the partial rune")
	}
}

// TestStdinProgramModesAbstain covers the interpreter modes where the program
// arrives on STDIN. These are the sharpest false-evidence shapes in the whole
// resolver: the argv contains a token that looks exactly like a script path,
// the file may genuinely exist on disk, and it is NOT what executed.
//
// `bash -s deploy.sh` reads commands from stdin and passes deploy.sh to them as
// the positional parameter $1. Recording deploy.sh would sign a real file, with
// a real digest, that the command never ran — indistinguishable, downstream,
// from evidence that it did.
func TestStdinProgramModesAbstain(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"bash -s with a script-shaped parameter", []string{"bash", "-s", "deploy.sh"}},
		{"bash -s clustered with switches", []string{"bash", "-es", "deploy.sh"}},
		{"sh reading stdin via bare dash", []string{"sh", "-", "deploy.sh"}},
		{"python reading stdin via bare dash", []string{"python3", "-", "arg.py"}},
		{"node reading stdin via bare dash", []string{"node", "-", "arg.js"}},
		{"bare dash after the -- terminator", []string{"bash", "--", "-"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if refs := resolveScriptOperands(tc.argv, ""); len(refs) != 0 {
				t.Errorf("stdin mode must record nothing, got %+v", refs)
			}
		})
	}
}

// TestChdirFlagsAbstain pins that a script path is never resolved against a
// directory the interpreter has already left.
//
// `ruby -C sub build.rb` executes sub/build.rb. Resolving build.rb against the
// original workdir is not a near-miss: on a repo that has both, it hashes a
// real, wrong file and signs it as the thing that ran.
func TestChdirFlagsAbstain(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"ruby -C separate form", []string{"ruby", "-C", "sub", "build.rb"}},
		{"ruby -C clustered with a switch", []string{"ruby", "-wC", "sub", "build.rb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if refs := resolveScriptOperands(tc.argv, ""); len(refs) != 0 {
				t.Errorf("a moved resolution base must abstain, got %+v", refs)
			}
		})
	}
}

// TestMakeFileFromStdinAbstains pins that `make -f -` records nothing AND does
// not fall through to implicit lookup.
//
// The fall-through is the dangerous half: an explicit -f means make will not
// read GNUmakefile/makefile/Makefile at all, so hashing one found on disk would
// sign a file the build definitively never read.
func TestMakeFileFromStdinAbstains(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte("all:\n\t@true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if refs := resolveScriptOperands([]string{"make", "-f", "-"}, dir); len(refs) != 0 {
		t.Errorf("make -f - must record nothing and must NOT fall back to the implicit Makefile, got %+v", refs)
	}
}

// TestKnownGoodShapesStillResolve is the counterweight to the three tests
// above: abstention is only a virtue when it is selective. If tightening the
// grammar silently turned the common cases into no-ops, the attestor would
// record nothing at all and every one of those tests would still pass.
func TestKnownGoodShapesStillResolve(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want string
	}{
		{"plain shell script", []string{"bash", "build.sh"}, "build.sh"},
		{"shell with switch clusters", []string{"bash", "-euo", "pipefail", "build.sh"}, "build.sh"},
		{"ruby without -C", []string{"ruby", "-w", "build.rb"}, "build.rb"},
		{"python script", []string{"python3", "setup.py"}, "setup.py"},
		{"after the -- terminator", []string{"bash", "--", "build.sh"}, "build.sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refs := resolveScriptOperands(tc.argv, "")
			if len(refs) != 1 || refs[0].Path != tc.want {
				t.Errorf("want a single ref for %q, got %+v", tc.want, refs)
			}
		})
	}
}

// TestMakeEndOfOptionsMarker pins that `--` stops option parsing.
//
// GNU make treats everything after `--` as goal targets, so
// `make -- -f Custom.mk` reads the IMPLICIT makefile and never opens
// Custom.mk. Continuing to scan past the marker signs a file make did not
// read — the same false-evidence shape as the stdin modes, reached through
// option grammar instead.
func TestMakeEndOfOptionsMarker(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Makefile"), []byte("all:\n\t@true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Custom.mk"), []byte("all:\n\t@true\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	refs := resolveScriptOperands([]string{"make", "--", "-f", "Custom.mk"}, dir)
	if len(refs) != 1 {
		t.Fatalf("want exactly the implicit makefile, got %+v", refs)
	}
	// Compare case-insensitively: the implicit search order is
	// GNUmakefile/makefile/Makefile, and on a case-insensitive filesystem the
	// lowercase probe matches the file written as "Makefile". Which spelling
	// wins is not the property under test — NOT signing Custom.mk is.
	if got := filepath.Base(refs[0].Path); !strings.EqualFold(got, "Makefile") {
		t.Errorf("after `--`, -f is a TARGET not a flag: make reads its implicit makefile, "+
			"but the resolver signed %q", got)
	}

	// Counterweight: without the marker, -f still means what it means.
	refs = resolveScriptOperands([]string{"make", "-f", "Custom.mk"}, dir)
	if len(refs) != 1 || filepath.Base(refs[0].Path) != "Custom.mk" {
		t.Errorf("a real -f must still resolve, got %+v", refs)
	}
}

// captureDeadline bounds the capture calls in these tests. The fixtures are a
// few MiB at most, so anything near this is a wedge, not slowness.
const captureDeadline = 20 * time.Second

// TestAssignmentsStrippedOnlyForARealEnvInvocation pins that VAR=value tokens
// are skipped only while parsing an actual `env` command.
//
// There is no shell in a captured argv. `["FOO=bar","bash","decoy.sh"]` is a
// request to exec a program literally NAMED "FOO=bar" — which does not exist,
// so nothing runs at all. Stripping the assignment invents an `env` that was
// never in the argv and then signs decoy.sh as the executed script of a command
// that could not even start.
func TestAssignmentsStrippedOnlyForARealEnvInvocation(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want string // "" means the resolver must abstain
	}{
		{
			// THE case: no `env` anywhere, so argv[0] is the program name.
			name: "bare assignment prefix is a program name, not a prefix",
			argv: []string{"FOO=bar", "bash", "decoy.sh"},
			want: "",
		},
		{
			name: "several bare assignments",
			argv: []string{"A=1", "B=2", "bash", "decoy.sh"},
			want: "",
		},
		{
			// An assignment AFTER a real program is that program's argument.
			name: "assignment following a non-env program",
			argv: []string{"go", "FOO=bar", "bash", "decoy.sh"},
			want: "",
		},

		// COUNTERWEIGHTS. These are why the strip exists at all: without it
		// every wrapper script in the recorded corpus came back opaque.
		{
			// Verbatim shape from a recorded production attestation.
			name: "recorded production env shape still resolves",
			argv: []string{
				"env", "GOOS=linux", "GOARCH=arm64", "TOOL=cilock",
				"BIN=/tmp/tmp.Zt2PWVy655/cilock",
				"bash", "/opt/runner/_work/judge/build.sh",
			},
			want: "/opt/runner/_work/judge/build.sh",
		},
		{
			name: "env with an absolute path still resolves",
			argv: []string{"/usr/bin/env", "FOO=bar", "bash", "build.sh"},
			want: "build.sh",
		},
		{
			name: "env -i still resolves",
			argv: []string{"env", "-i", "FOO=bar", "bash", "build.sh"},
			want: "build.sh",
		},
		{
			name: "nested env invocations still resolve",
			argv: []string{"env", "A=1", "env", "B=2", "bash", "build.sh"},
			want: "build.sh",
		},
		{
			name: "env with no assignments still resolves",
			argv: []string{"env", "bash", "build.sh"},
			want: "build.sh",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refs := resolveScriptOperands(tc.argv, "")
			if tc.want == "" {
				if len(refs) != 0 {
					t.Fatalf("argv[0] %q is the program the kernel was asked to exec, "+
						"not an assignment prefix — nothing should be recorded, got %+v",
						tc.argv[0], refs)
				}
				return
			}
			if len(refs) != 1 || refs[0].Path != tc.want {
				t.Fatalf("want a single ref for %q, got %+v", tc.want, refs)
			}
		})
	}
}

// TestCaptureAbortsOnCancellation pins that hashing is interruptible.
//
// This is the sibling of the FIFO hang: that one blocked on OPEN, this one
// blocks on READ, and both happen BEFORE the command starts — outside the
// command's timeout and outside anything the caller can cancel. A huge or
// steadily growing regular file would hold a worker indefinitely with the
// context already cancelled and nobody able to stop it.
//
// The abort must record NOTHING measured. A digest over however many bytes we
// managed to read before giving up would describe a prefix while claiming to
// describe the file.
func TestCaptureAbortsOnCancellation(t *testing.T) {
	dir := t.TempDir()
	// Large enough that hashing takes several reads, so an implementation that
	// only checked the context once at the top would still be caught.
	if err := os.WriteFile(filepath.Join(dir, "big.sh"),
		[]byte(strings.Repeat("a", 8<<20)), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("cancelled context abstains", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		done := make(chan []ScriptRef, 1)
		go func() {
			done <- captureScriptRefs(ctx, []string{"bash", "big.sh"}, dir, ScriptCaptureContent)
		}()

		select {
		case refs := <-done:
			if len(refs) != 1 {
				t.Fatalf("a named operand must still be REPORTED, got %+v", refs)
			}
			r := refs[0]
			if r.Unresolved == "" {
				t.Fatal("an aborted capture must carry a REASON, not look like a clean read")
			}
			if len(r.Digest) != 0 {
				t.Error("no digest may survive an aborted read — it would describe a prefix")
			}
			if r.SizeBytes != 0 || r.Content != "" {
				t.Errorf("nothing may be measured from an aborted read: %+v", r)
			}
		case <-time.After(captureDeadline):
			t.Fatalf("capture ignored cancellation for %s", captureDeadline)
		}
	})

	// MANDATORY counterweight: an implementation that abstained on every
	// context would pass the subtest above and silently disable capture.
	t.Run("live context still hydrates the same file", func(t *testing.T) {
		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "big.sh"}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		if refs[0].Unresolved != "" {
			t.Fatalf("an ordinary read must succeed, got %q", refs[0].Unresolved)
		}
		if len(refs[0].Digest) == 0 || refs[0].SizeBytes != int64(8<<20) {
			t.Errorf("live capture must produce a whole-file digest and size: %+v", refs[0])
		}
	})
}

// TestOversizedOperandAbstainsRatherThanHashingAPrefix pins the ceiling.
//
// Cancellation only helps if somebody cancels. A file that grows as fast as it
// is read never ends and the attestation context may carry no deadline at all,
// so a hard ceiling is the only thing that bounds the work unconditionally.
//
// Exceeding it must ABSTAIN. Truncating instead would emit a digest computed
// over the first N bytes while the record claims to identify the file — the
// same false-evidence shape as naming the wrong path, reached through the read
// path instead of the argv.
func TestOversizedOperandAbstainsRatherThanHashingAPrefix(t *testing.T) {
	dir := t.TempDir()

	// maxScriptDigestBytes is a var so this test can exercise the boundary
	// without writing the real ceiling to disk.
	restore := maxScriptDigestBytes
	maxScriptDigestBytes = 1 << 20
	t.Cleanup(func() { maxScriptDigestBytes = restore })

	t.Run("over the ceiling records nothing measured", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(dir, "huge.sh"),
			[]byte(strings.Repeat("a", (1<<20)+4096)), 0o600); err != nil {
			t.Fatal(err)
		}
		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "huge.sh"}, dir, ScriptCaptureContent)
		if len(refs) != 1 {
			t.Fatalf("expected 1 ref, got %+v", refs)
		}
		r := refs[0]
		if r.Unresolved == "" {
			t.Fatal("an operand past the ceiling must carry a reason")
		}
		if len(r.Digest) != 0 {
			t.Error("a digest over a PREFIX is worse than no digest — it claims to identify the file")
		}
		if r.SizeBytes != 0 || r.Content != "" || r.ContentTruncated {
			t.Errorf("nothing may be measured past the ceiling: %+v", r)
		}
	})

	// Counterweight: the ceiling must not gut ordinary capture.
	t.Run("under the ceiling hydrates completely", func(t *testing.T) {
		body := strings.Repeat("b", (1<<20)-4096)
		if err := os.WriteFile(filepath.Join(dir, "ok.sh"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		refs := captureScriptRefs(context.Background(),
			[]string{"bash", "ok.sh"}, dir, ScriptCaptureIdentity)
		if len(refs) != 1 || refs[0].Unresolved != "" {
			t.Fatalf("a file under the ceiling must hydrate, got %+v", refs)
		}
		if len(refs[0].Digest) == 0 || refs[0].SizeBytes != int64(len(body)) {
			t.Errorf("want a whole-file digest and size %d, got %+v", len(body), refs[0])
		}
	})
}

// TestRepeatedOperandIsReadOnce pins that one capture pass reads a given file
// once, however many times the argv names it.
//
// The recorded output cannot distinguish a correct pass from a pathological
// one: a thousand refs with identical digests look the same whether the file
// was read once or a thousand times. So this asserts the READ VOLUME, which is
// the only place the difference is visible — and the difference is the whole
// defect, because those reads all happen before runCmd where no command
// timeout applies.
func TestRepeatedOperandIsReadOnce(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat("m", 512<<10) // 512 KiB
	if err := os.WriteFile(filepath.Join(dir, "large.mk"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	const repeats = 200
	argv := make([]string, 0, 1+2*repeats)
	argv = append(argv, "make")
	for range repeats {
		argv = append(argv, "-f", "large.mk")
	}

	refs, budget := captureScriptRefsWithBudget(
		context.Background(), argv, dir, ScriptCaptureIdentity)

	if len(refs) != repeats {
		t.Fatalf("make reads every -f it is given: want %d refs, got %d", repeats, len(refs))
	}
	if budget.hydrations != 1 {
		t.Errorf("hydrated the same file %d times, want 1 — a small argv bought %d× the I/O",
			budget.hydrations, budget.hydrations)
	}
	if budget.bytesRead != int64(len(body)) {
		t.Errorf("read %d bytes for one %d-byte file named %d times, want %d",
			budget.bytesRead, len(body), repeats, len(body))
	}

	// Counterweight: dedupe must not cost evidence. EVERY occurrence still
	// carries the real measurement, not just the first.
	for i, r := range refs {
		if r.Unresolved != "" {
			t.Fatalf("ref %d unresolved: %s", i, r.Unresolved)
		}
		if len(r.Digest) == 0 || r.SizeBytes != int64(len(body)) {
			t.Fatalf("ref %d lost its measurement to dedupe: %+v", i, r)
		}
		if r.Role != RoleMakefile {
			t.Errorf("ref %d role = %q, want %q", i, r.Role, RoleMakefile)
		}
	}
}

// TestAggregateBudgetExhaustionAbstains pins the pass-wide ceiling.
//
// Dedupe removes the repeated-operand amplifier; this bounds what is left,
// many DISTINCT large operands. Exceeding it must record a REASON and nothing
// measured, and the reason must name the AGGREGATE cap — "this argv asked for
// too much in total" and "this one file is too big" call for different operator
// responses, and a shared message would make them indistinguishable.
func TestAggregateBudgetExhaustionAbstains(t *testing.T) {
	dir := t.TempDir()

	restoreTotal, restorePer := maxCaptureTotalBytes, maxScriptDigestBytes
	maxCaptureTotalBytes = 1 << 20 // 1 MiB for the whole pass
	maxScriptDigestBytes = 1 << 20 // per-operand ceiling deliberately NOT the binding one
	t.Cleanup(func() {
		maxCaptureTotalBytes, maxScriptDigestBytes = restoreTotal, restorePer
	})

	// Three DISTINCT half-MiB files: the first two exactly consume the budget,
	// so dedupe cannot rescue the third.
	const half = 512 << 10
	for _, name := range []string{"a.mk", "b.mk", "c.mk"} {
		if err := os.WriteFile(filepath.Join(dir, name),
			[]byte(strings.Repeat(name[:1], half)), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	refs := captureScriptRefs(context.Background(),
		[]string{"make", "-f", "a.mk", "-f", "b.mk", "-f", "c.mk"}, dir, ScriptCaptureIdentity)
	if len(refs) != 3 {
		t.Fatalf("expected 3 refs, got %+v", refs)
	}

	// Counterweight: everything that FITS is still fully measured. A budget
	// that abstained on everything would satisfy the assertion below.
	for i := range 2 {
		if refs[i].Unresolved != "" {
			t.Fatalf("ref %d fits inside the budget and must be measured, got %q",
				i, refs[i].Unresolved)
		}
		if len(refs[i].Digest) == 0 || refs[i].SizeBytes != int64(half) {
			t.Fatalf("ref %d lost its measurement: %+v", i, refs[i])
		}
	}

	over := refs[2]
	if over.Unresolved == "" {
		t.Fatal("the operand past the budget must carry a reason")
	}
	if len(over.Digest) != 0 || over.SizeBytes != 0 || over.Content != "" {
		t.Errorf("nothing may be measured past the budget: %+v", over)
	}
	if !strings.Contains(over.Unresolved, "budget") {
		t.Errorf("the reason must name the AGGREGATE cap so an operator can tell "+
			"'too many' from 'too big', got %q", over.Unresolved)
	}
	if strings.Contains(over.Unresolved, "per-operand") {
		t.Errorf("blamed the per-operand ceiling for an aggregate exhaustion: %q", over.Unresolved)
	}
}

// TestAggregateBudgetBoundsTotalBytesRead is the regression for a ceiling that
// measured the cost only AFTER paying it.
//
// boundedReader filled the whole supplied buffer and compared its running total
// to the limit afterwards, so the bound did not bound: with the allowance
// already spent, every further DISTINCT operand still opened its file, pulled
// one full 32 KiB io.Copy buffer, drove `remaining` further negative, and
// repeated. `make -f a.mk -f b.mk ...` with enough operands therefore read far
// past maxCaptureTotalBytes — the amplification the aggregate ceiling exists to
// close, reached one buffer at a time instead of one file at a time.
//
// The assertion is on the AGGREGATE, deliberately. Every per-operand assertion
// in this file passes against the broken code: each ref past the budget is
// unresolved with the right reason, and the refs are the whole recorded output.
// bytesRead is the only place the defect is visible at all.
func TestAggregateBudgetBoundsTotalBytesRead(t *testing.T) {
	dir := t.TempDir()

	restoreTotal, restorePer := maxCaptureTotalBytes, maxScriptDigestBytes
	maxCaptureTotalBytes = 256 << 10 // 256 KiB for the whole pass
	maxScriptDigestBytes = 1 << 20   // per-operand ceiling deliberately NOT binding
	t.Cleanup(func() {
		maxCaptureTotalBytes, maxScriptDigestBytes = restoreTotal, restorePer
	})

	// Sized so the first four operands consume the allowance EXACTLY and the
	// remaining sixty have nothing left to spend. Under the broken code those
	// sixty read one buffer each — roughly 1.9 MiB past a 256 KiB ceiling.
	const (
		operands = 64
		each     = 64 << 10
		fits     = 4 // maxCaptureTotalBytes / each
	)
	body := []byte(strings.Repeat("x", each))
	argv := make([]string, 0, 1+2*operands)
	argv = append(argv, "make")
	for i := range operands {
		name := fmt.Sprintf("op%02d.mk", i)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		argv = append(argv, "-f", name)
	}

	refs, budget := captureScriptRefsWithBudget(
		context.Background(), argv, dir, ScriptCaptureIdentity)
	if len(refs) != operands {
		t.Fatalf("expected %d refs, got %d", operands, len(refs))
	}

	if budget.bytesRead > maxCaptureTotalBytes {
		t.Errorf("read %d bytes under a %d-byte aggregate ceiling: %d operands past "+
			"the budget each still bought a buffer of I/O before the check fired",
			budget.bytesRead, maxCaptureTotalBytes, operands-fits)
	}
	if budget.hydrations != fits {
		t.Errorf("hydrated %d operands, want %d: hydration must STOP once the "+
			"allowance is gone, not be attempted and then rejected", budget.hydrations, fits)
	}

	// Counterweight: everything that fits is still fully measured. A pass that
	// read nothing at all would satisfy the ceiling assertion above.
	for i := range fits {
		if refs[i].Unresolved != "" {
			t.Fatalf("ref %d fits inside the budget and must be measured, got %q",
				i, refs[i].Unresolved)
		}
		if len(refs[i].Digest) == 0 || refs[i].SizeBytes != int64(each) {
			t.Fatalf("ref %d lost its measurement: %+v", i, refs[i])
		}
	}
	for i := fits; i < operands; i++ {
		if refs[i].Unresolved == "" {
			t.Fatalf("ref %d is past the budget and must carry a reason: %+v", i, refs[i])
		}
		if !strings.Contains(refs[i].Unresolved, "budget") {
			t.Errorf("ref %d must name the AGGREGATE cap, got %q", i, refs[i].Unresolved)
		}
	}
}

// TestSingleOperandStopsAtTheAggregateAllowance pins the per-READ half of the
// same defect.
//
// Stopping hydration once the budget is gone bounds operand N+1 onward; it does
// nothing for the operand that STRADDLES the boundary, which is still read
// buffer-by-buffer with the limit compared only afterwards. Each underlying
// read must itself be clamped to what the allowance can still pay for.
func TestSingleOperandStopsAtTheAggregateAllowance(t *testing.T) {
	dir := t.TempDir()

	restoreTotal, restorePer := maxCaptureTotalBytes, maxScriptDigestBytes
	maxCaptureTotalBytes = 64 << 10 // smaller than one io.Copy buffer's worth of overshoot
	maxScriptDigestBytes = 1 << 20  // per-operand ceiling deliberately NOT binding
	t.Cleanup(func() {
		maxCaptureTotalBytes, maxScriptDigestBytes = restoreTotal, restorePer
	})

	if err := os.WriteFile(filepath.Join(dir, "big.mk"),
		[]byte(strings.Repeat("z", 1<<20)), 0o600); err != nil {
		t.Fatal(err)
	}

	refs, budget := captureScriptRefsWithBudget(
		context.Background(), []string{"make", "-f", "big.mk"}, dir, ScriptCaptureIdentity)
	if len(refs) != 1 {
		t.Fatalf("expected 1 ref, got %+v", refs)
	}

	// The allowance plus ONE byte: that byte is the probe distinguishing "the
	// file ends exactly at the ceiling" (measure it) from "the file runs past
	// it" (abstain), and nothing short of reading it can tell those apart. It is
	// paid at most once per pass, because the operand that pays it takes the
	// allowance to zero and every later operand then abstains before opening
	// anything.
	if budget.bytesRead > maxCaptureTotalBytes+1 {
		t.Errorf("read %d bytes for one operand under a %d-byte allowance: the final "+
			"read was not clamped to what the budget could still pay for",
			budget.bytesRead, maxCaptureTotalBytes)
	}
	if refs[0].Unresolved == "" || len(refs[0].Digest) != 0 || refs[0].SizeBytes != 0 {
		t.Errorf("an operand past the allowance must abstain outright: %+v", refs[0])
	}
}

// TestCaptureBudgetRemainingNeverGoesNegative pins the allowance as a quantity
// that cannot be overdrawn.
//
// `remaining -= read` with no floor let the spent allowance go arbitrarily
// negative, and that value feeds straight back into the per-operand limit — a
// negative ceiling that every subsequent read is compared against AFTER the
// fact. Not going negative "in the paths we tested" is not the property; the
// subtraction itself must be incapable of it.
func TestCaptureBudgetRemainingNeverGoesNegative(t *testing.T) {
	dir := t.TempDir()

	restoreTotal, restorePer := maxCaptureTotalBytes, maxScriptDigestBytes
	maxCaptureTotalBytes = 64 << 10
	maxScriptDigestBytes = 1 << 20
	t.Cleanup(func() {
		maxCaptureTotalBytes, maxScriptDigestBytes = restoreTotal, restorePer
	})

	const operands = 8
	body := []byte(strings.Repeat("q", 64<<10))
	argv := make([]string, 0, 1+2*operands)
	argv = append(argv, "make")
	for i := range operands {
		name := fmt.Sprintf("neg%d.mk", i)
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
		argv = append(argv, "-f", name)
	}

	_, budget := captureScriptRefsWithBudget(
		context.Background(), argv, dir, ScriptCaptureIdentity)

	if budget.remaining < 0 {
		t.Errorf("remaining = %d: the allowance was overdrawn by %d bytes, and a "+
			"negative allowance is what the next operand's ceiling is computed from",
			budget.remaining, -budget.remaining)
	}
	if budget.remaining > maxCaptureTotalBytes {
		t.Errorf("remaining = %d exceeds the allowance %d it started from",
			budget.remaining, maxCaptureTotalBytes)
	}
}

// TestOrdinaryOperandsUnderBudgetAreFullyHydrated is the counterweight to the
// three tests above, and it runs against the REAL ceilings.
//
// Every assertion about a bound is satisfied by an implementation that reads
// nothing: abstain on everything and no budget is ever exceeded, no allowance
// ever goes negative, and the whole feature is silently gone. This is the test
// that fails when the fix over-corrects.
func TestOrdinaryOperandsUnderBudgetAreFullyHydrated(t *testing.T) {
	dir := t.TempDir()

	bodies := map[string]string{
		"one.mk":   "all:\n\techo one\n",
		"two.mk":   "all:\n\techo two\n",
		"three.mk": "all:\n\techo three\n",
	}
	names := []string{"one.mk", "two.mk", "three.mk"}
	argv := make([]string, 0, 1+2*len(names))
	argv = append(argv, "make")
	total := 0
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(bodies[name]), 0o600); err != nil {
			t.Fatal(err)
		}
		argv = append(argv, "-f", name)
		total += len(bodies[name])
	}

	refs, budget := captureScriptRefsWithBudget(
		context.Background(), argv, dir, ScriptCaptureContent)
	if len(refs) != len(bodies) {
		t.Fatalf("expected %d refs, got %+v", len(bodies), refs)
	}

	for i, r := range refs {
		want := bodies[filepath.Base(r.Path)]
		if r.Unresolved != "" {
			t.Fatalf("ref %d is far under every ceiling and must hydrate, got %q",
				i, r.Unresolved)
		}
		if r.Content != want {
			t.Errorf("ref %d content = %q, want %q", i, r.Content, want)
		}
		if r.SizeBytes != int64(len(want)) {
			t.Errorf("ref %d size = %d, want %d", i, r.SizeBytes, len(want))
		}
		if r.ContentTruncated || r.ContentOmittedBinary {
			t.Errorf("ref %d was clipped by a ceiling it is nowhere near: %+v", i, r)
		}
		wantDigest, err := cryptoutil.CalculateDigestSetFromBytes(
			[]byte(want), defaultScriptDigests())
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Digest) != len(wantDigest) {
			t.Fatalf("ref %d digest set size %d != %d", i, len(r.Digest), len(wantDigest))
		}
		for k, v := range wantDigest {
			if r.Digest[k] != v {
				t.Errorf("ref %d digest %v = %q, want %q", i, k, r.Digest[k], v)
			}
		}
	}

	if budget.hydrations != len(bodies) {
		t.Errorf("hydrated %d operands, want %d — a bound that stops ordinary "+
			"capture has replaced one defect with a worse one",
			budget.hydrations, len(bodies))
	}
	if budget.bytesRead != int64(total) {
		t.Errorf("read %d bytes, want %d (every operand, exactly once)",
			budget.bytesRead, total)
	}
	if budget.remaining != maxCaptureTotalBytes-int64(total) {
		t.Errorf("remaining = %d, want %d: the allowance must be charged for what "+
			"was read and nothing else", budget.remaining, maxCaptureTotalBytes-int64(total))
	}
}

// TestOptionsThatNeverRunTheOperandAbstain covers the options under which the
// operand is NOT executed.
//
// This is the abstain rule one notch further out than an unknown token. Here
// the token IS positively classified — `-h` and `--version` are perfectly good
// switches — but classifying them as ordinary switches asserts something the
// argv does not support: that the operand still ran. `python3 -h decoy.py`
// prints usage and exits with status 0 having never opened decoy.py, and
// `make --version -f decoy.mk` never reads decoy.mk. Both would otherwise be
// signed as executed inputs of a successful command, which is the same false
// evidence as naming the wrong file — the operand here is a real file with a
// real digest that this command demonstrably did not run.
//
// Two sub-classes, both covered: options that EXIT before reading anything
// (help, version), and options that read the operand but never execute it
// (shell noexec, perl/ruby syntax-check).
func TestOptionsThatNeverRunTheOperandAbstain(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
	}{
		// Named by the review.
		{"python -h", []string{"python3", "-h", "decoy.py"}},
		{"make --version", []string{"make", "--version", "-f", "decoy.mk"}},

		// The rest of the sweep: every grammar this resolver models.
		{"python --help", []string{"python3", "--help", "decoy.py"}},
		{"python -V", []string{"python3", "-V", "decoy.py"}},
		{"python --version", []string{"python3", "--version", "decoy.py"}},
		{"make -v", []string{"make", "-v", "-f", "decoy.mk"}},
		{"make -h", []string{"make", "-h", "-f", "decoy.mk"}},
		{"make --help", []string{"make", "--help", "-f", "decoy.mk"}},
		{"shell --help", []string{"bash", "--help", "decoy.sh"}},
		{"shell --version", []string{"bash", "--version", "decoy.sh"}},
		{"node -v", []string{"node", "-v", "decoy.js"}},
		{"node --help", []string{"node", "--help", "decoy.js"}},
		{"node --version", []string{"node", "--version", "decoy.js"}},
		{"perl -v", []string{"perl", "-v", "decoy.pl"}},
		{"perl -V", []string{"perl", "-V", "decoy.pl"}},
		{"ruby --version", []string{"ruby", "--version", "decoy.rb"}},
		{"ruby -v", []string{"ruby", "-v", "decoy.rb"}},

		// Read but never executed. The field's documented claim is the script
		// the command EXECUTES, so a syntax check is not it.
		{"shell noexec", []string{"bash", "-n", "decoy.sh"}},
		{"shell noexec clustered", []string{"bash", "-en", "decoy.sh"}},
		{"perl syntax check", []string{"perl", "-c", "decoy.pl"}},
		{"ruby syntax check", []string{"ruby", "-c", "decoy.rb"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if refs := resolveScriptOperands(tc.argv, ""); len(refs) != 0 {
				t.Fatalf("the operand is never executed under this option, but it was "+
					"recorded as an executed input: %+v", refs)
			}
		})
	}
}

// TestOptionsThatStillRunTheOperand is the counterweight to the sweep above.
//
// Sweeping "looks like it might not run the file" too widely would abstain on
// ordinary verbose and interactive builds. These options all still execute the
// operand, and make's dry-run still READS its makefile — which is why make and
// the interpreters are treated differently on -n, and that asymmetry needs a
// test rather than a comment.
func TestOptionsThatStillRunTheOperand(t *testing.T) {
	t.Run("interpreters", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			argv []string
			want string
		}{
			{"shell verbose", []string{"bash", "-v", "build.sh"}, "build.sh"},
			{"python verbose", []string{"python3", "-v", "scan.py"}, "scan.py"},
			{"python inspect after running", []string{"python3", "-i", "scan.py"}, "scan.py"},
			{"shell interactive", []string{"bash", "-i", "build.sh"}, "build.sh"},
			{"ruby warnings", []string{"ruby", "-w", "build.rb"}, "build.rb"},
			{"perl warnings", []string{"perl", "-w", "build.pl"}, "build.pl"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				refs := resolveScriptOperands(tc.argv, "")
				if len(refs) != 1 || refs[0].Path != tc.want {
					t.Fatalf("want a single ref for %q, got %+v", tc.want, refs)
				}
			})
		}
	})

	t.Run("make dry-run still reads its makefile", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "Custom.mk"), []byte("all:\n\t@true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// -n does not run the recipes, but make still opens and parses the
		// makefile. RoleMakefile claims the file make READS, so this resolves.
		for _, argv := range [][]string{
			{"make", "-n", "-f", "Custom.mk"},
			{"make", "--dry-run", "-f", "Custom.mk"},
			{"make", "-q", "-f", "Custom.mk"},
		} {
			refs := resolveScriptOperands(argv, dir)
			if len(refs) != 1 || filepath.Base(refs[0].Path) != "Custom.mk" {
				t.Errorf("%v: want Custom.mk, got %+v", argv, refs)
			}
		}
	})
}

// TestPlusIntroducedOptionsAreNotOperands pins that `+` introduces an OPTION
// for a shell, not a path.
//
// A resolver that decides "operand" by testing for a leading `-` alone hands
// back `+o` as the executed script — and `+o` is not even an unknown token, it
// is a value-taking option the grammar already lists. The script really being
// run (build.sh) sits two tokens further along, so the recorded path is not a
// near miss: it is a token that names no file at all, or worse, a real file
// somewhere named `+o`.
func TestPlusIntroducedOptionsAreNotOperands(t *testing.T) {
	for _, tc := range []struct {
		name string
		argv []string
		want string // "" means the resolver must abstain
	}{
		{
			// THE case. `+o` takes "errexit" as its value; build.sh is the
			// script. Recording "+o" is signed evidence naming a non-file.
			name: "bash +o consumes its value and the script still resolves",
			argv: []string{"bash", "+o", "errexit", "build.sh"},
			want: "build.sh",
		},
		{
			// `+x` is the disable form of `-x`; it takes no value.
			name: "bash +x is a switch, not the script",
			argv: []string{"bash", "+x", "build.sh"},
			want: "build.sh",
		},
		{
			// Clustered plus form: +e +u are both switches.
			name: "clustered plus switches",
			argv: []string{"bash", "+eu", "build.sh"},
			want: "build.sh",
		},
		{
			// `+` is not an option introducer for python, so a +-prefixed
			// token is a shape the grammar does not model: abstain.
			name: "python plus token abstains",
			argv: []string{"python3", "+q", "scan.py"},
			want: "",
		},
		{
			name: "shell plus token that names no known option abstains",
			argv: []string{"bash", "+Z", "build.sh"},
			want: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refs := resolveScriptOperands(tc.argv, "")
			for _, r := range refs {
				if strings.HasPrefix(r.Path, "+") {
					t.Fatalf("recorded a +-introduced OPTION as the executed script: %q", r.Path)
				}
			}
			if tc.want == "" {
				if len(refs) != 0 {
					t.Fatalf("expected abstention, got %+v", refs)
				}
				return
			}
			if len(refs) != 1 || refs[0].Path != tc.want {
				t.Fatalf("want a single ref for %q, got %+v", tc.want, refs)
			}
		})
	}
}

// TestMakeClusteredShortOptions pins that make's option scan decomposes
// clusters, and that failing to account for a token abstains instead of
// falling through to the implicit makefile.
//
// `make -sfCustom.mk` is `-s` plus `-f Custom.mk`: make reads Custom.mk and
// never opens Makefile. A scan that only recognises the unclustered `-fX` form
// sees no -f at all, drops through to implicit lookup, finds Makefile on disk
// and signs it — a real file, a real digest, and the wrong one.
func TestMakeClusteredShortOptions(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Makefile", "Custom.mk"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("all:\n\t@true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"silent clustered with file", []string{"make", "-sfCustom.mk"}},
		{"several switches then file", []string{"make", "-rsfCustom.mk"}},
		{"clustered -f taking the FOLLOWING token", []string{"make", "-sf", "Custom.mk"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			refs := resolveScriptOperands(tc.argv, dir)
			if len(refs) != 1 {
				t.Fatalf("expected exactly the -f makefile, got %+v", refs)
			}
			if got := filepath.Base(refs[0].Path); got != "Custom.mk" {
				t.Fatalf("signed %q — make reads Custom.mk, so this is a makefile "+
					"the build never opened", got)
			}
		})
	}
}

// TestUnaccountedTokenAbstains is the whole-class guard. Any token the grammar
// cannot positively classify makes the resolver report NOTHING.
//
// The failure mode being closed is specific: an unclassified token may consume
// the token after it, so nothing further along is anchored. For make the
// consequence is sharper than a missing record — an unrecognised option may
// have been an -f, and falling through to implicit lookup then signs a default
// makefile that make, given that -f, does not read.
func TestUnaccountedTokenAbstains(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"Makefile", "Custom.mk"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("all:\n\t@true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"unknown make long option", []string{"make", "--totally-unknown", "-f", "Custom.mk"}},
		{"unknown make short option", []string{"make", "-Z", "all"}},
		{"unknown member inside a make cluster", []string{"make", "-sZfCustom.mk"}},
		{
			// -j takes an OPTIONAL argument: GNU make reads it from the
			// attached tail, or from the next token when that token looks
			// numeric. This resolver does not model that peek, so it declines
			// the whole invocation rather than guess which token was eaten.
			name: "make optional-argument option",
			argv: []string{"make", "-j4", "-f", "Custom.mk"},
		},
		{"attached value on a make switch that takes none", []string{"make", "-s=1", "-f", "Custom.mk"}},
		{"unknown attached-value form on an interpreter", []string{"bash", "--unknown=x", "build.sh"}},
		{"option promising a value the argv does not carry", []string{"make", "-f"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if refs := resolveScriptOperands(tc.argv, dir); len(refs) != 0 {
				t.Fatalf("an unaccounted token must abstain, got %+v", refs)
			}
		})
	}
}

// TestOrdinaryShapesSurviveTheStrictScan is the counterweight to every
// abstention test in this file.
//
// Abstaining is only a virtue when it is selective. A resolver that returned
// nothing for every argv would satisfy all three tests above and silently
// remove the feature, and no test asserting absence could tell the difference.
// These are the shapes that MUST still produce a signed path.
func TestOrdinaryShapesSurviveTheStrictScan(t *testing.T) {
	t.Run("interpreter shapes", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			argv []string
			want string
		}{
			{"plain script", []string{"bash", "build.sh"}, "build.sh"},
			{"clustered switches with a value option", []string{"bash", "-euo", "pipefail", "build.sh"}, "build.sh"},
			{"separate switches", []string{"bash", "-e", "-x", "build.sh"}, "build.sh"},
			{"script with its own arguments", []string{"python3", "scan.py", "--verbose", "-x"}, "scan.py"},
			// A doubled switch is just a two-member cluster, which is why the
			// grammar no longer spells out python's -OO and -bb separately.
			{"doubled short switch", []string{"python3", "-OO", "scan.py"}, "scan.py"},
			{"attached value on a value option", []string{"python3", "-Wignore", "scan.py"}, "scan.py"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				refs := resolveScriptOperands(tc.argv, "")
				if len(refs) != 1 || refs[0].Path != tc.want {
					t.Fatalf("want a single ref for %q, got %+v", tc.want, refs)
				}
				if refs[0].Role != RoleInterpreterOperand {
					t.Errorf("role = %q, want %q", refs[0].Role, RoleInterpreterOperand)
				}
			})
		}
	})

	t.Run("make shapes", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"Makefile", "Custom.mk"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("all:\n\t@true\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		for _, tc := range []struct {
			name string
			argv []string
			want string
		}{
			{"explicit -f", []string{"make", "-f", "Custom.mk"}, "Custom.mk"},
			{"explicit -f with switches and a goal", []string{"make", "-s", "-f", "Custom.mk", "all"}, "Custom.mk"},
			{"implicit makefile", []string{"make"}, "Makefile"},
			{"implicit makefile with a goal", []string{"make", "all"}, "Makefile"},
			{"implicit makefile with a variable assignment", []string{"make", "CGO_ENABLED=0", "build"}, "Makefile"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				refs := resolveScriptOperands(tc.argv, dir)
				if len(refs) != 1 {
					t.Fatalf("want a single makefile, got %+v", refs)
				}
				// Case-insensitive: the implicit search probes GNUmakefile,
				// makefile, Makefile, and on a case-insensitive filesystem the
				// lowercase probe matches the file written as "Makefile".
				if got := filepath.Base(refs[0].Path); !strings.EqualFold(got, tc.want) {
					t.Fatalf("resolved %q, want %q", got, tc.want)
				}
				if refs[0].Role != RoleMakefile {
					t.Errorf("role = %q, want %q", refs[0].Role, RoleMakefile)
				}
			})
		}
	})
}
