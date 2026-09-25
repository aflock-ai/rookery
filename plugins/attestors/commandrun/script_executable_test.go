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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

func writeExecFixture(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o700); err != nil { //nolint:gosec // test fixture
		t.Fatal(err)
	}
	return p
}

func attestExecIn(t *testing.T, workdir string, opts ...Option) (*CommandRun, error) {
	t.Helper()
	actx, err := attestation.NewContext("commandrun-executable-test", []attestation.Attestor{},
		attestation.WithContext(context.Background()), attestation.WithWorkingDir(workdir))
	if err != nil {
		t.Fatalf("NewContext: %v", err)
	}
	rc := New(append([]Option{WithSilent(true)}, opts...)...)
	return rc, rc.Attest(actx)
}

func execSHA256Hex(b string) string {
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:])
}

// `./build.sh` runs build.sh through its shebang with no interpreter in argv,
// so no interpreter-operand rule can see it. It is recorded as an executable,
// with the digest and (under content capture) the body.
func TestAttestRecordsShebangArgv0AsExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shebang execution is POSIX")
	}
	workdir := t.TempDir()
	body := "#!/bin/sh\necho executable-ran\n"
	path := writeExecFixture(t, workdir, "build.sh", body)

	for _, mode := range []ScriptCaptureMode{ScriptCaptureIdentity, ScriptCaptureContent} {
		t.Run(string(mode), func(t *testing.T) {
			rc, err := attestExecIn(t, workdir, WithCommand([]string{"./build.sh"}), WithScriptCapture(mode))
			if err != nil {
				t.Fatalf("Attest: %v", err)
			}
			if rc.ExitCode != 0 {
				t.Fatalf("exit %d: the script did not run", rc.ExitCode)
			}
			if len(rc.Scripts) != 1 {
				t.Fatalf("want one script ref, got %+v", rc.Scripts)
			}
			got := rc.Scripts[0]
			if got.Role != RoleExecutable {
				t.Errorf("role = %q, want %q", got.Role, RoleExecutable)
			}
			if got.Path != path {
				t.Errorf("path = %q, want %q", got.Path, path)
			}
			if got.Digest[cryptoutil.DigestValue{Hash: crypto.SHA256}] != execSHA256Hex(body) {
				t.Errorf("digest %v does not cover the script bytes", got.Digest)
			}
			if got.ExecutionBinding != ScriptBindingUnverified {
				t.Errorf("binding = %q, want unverified without a trace", got.ExecutionBinding)
			}
			wantContent := ""
			if mode == ScriptCaptureContent {
				wantContent = body
			}
			if got.Content != wantContent {
				t.Errorf("content = %q, want %q", got.Content, wantContent)
			}
		})
	}
}

// Only a shebang script is a script. A compiled binary named by path, a bare
// PATH lookup, and a missing file must not produce an executable record: the
// role claims "these bytes are program text an interpreter ran".
func TestExecutableRoleRequiresShebangFileByPath(t *testing.T) {
	workdir := t.TempDir()
	writeExecFixture(t, workdir, "tool", "\x7fELF\x02\x01\x01binary-not-a-script")
	writeExecFixture(t, workdir, "short", "#")
	writeExecFixture(t, workdir, "run.sh", "#!/bin/sh\ntrue\n")
	if err := os.Mkdir(filepath.Join(workdir, "adir"), 0o755); err != nil {
		t.Fatal(err)
	}

	for _, argv := range [][]string{
		{"./tool"},
		{"./short"},
		{"./adir"},
		{"run.sh"}, // no separator: exec resolves it through PATH, not the workdir
		{"true"},
	} {
		refs := captureScriptRefs(context.Background(), argv, workdir, ScriptCaptureContent)
		if len(refs) != 0 {
			t.Errorf("%v: want no script refs, got %+v", argv, refs)
		}
	}

	refs := captureScriptRefs(context.Background(), []string{"env", "A=1", "./run.sh", "arg"}, workdir, ScriptCaptureIdentity)
	if len(refs) != 1 || refs[0].Role != RoleExecutable {
		t.Fatalf("env-prefixed shebang script: got %+v", refs)
	}
}

// The guard sees every captured ref before the command starts, and a refusal
// stops the command from running at all.
func TestScriptGuardRunsBeforeTheCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell script")
	}
	workdir := t.TempDir()
	marker := filepath.Join(workdir, "ran")
	writeExecFixture(t, workdir, "build.sh", "#!/bin/sh\ntouch "+marker+"\n")

	var seen []ScriptRef
	refuse := errors.New("refused by guard")
	_, err := attestExecIn(t, workdir,
		WithCommand([]string{"sh", "build.sh"}),
		WithScriptCapture(ScriptCaptureContent),
		WithScriptGuard(func(refs []ScriptRef) error {
			seen = append(seen, refs...)
			return refuse
		}))
	if !errors.Is(err, refuse) {
		t.Fatalf("Attest error = %v, want the guard's refusal", err)
	}
	if len(seen) != 1 || !strings.Contains(seen[0].Content, "touch") {
		t.Fatalf("guard did not receive the captured body: %+v", seen)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("the command ran despite the guard refusing (stat err %v)", statErr)
	}

	// A guard that accepts lets the command run.
	_, err = attestExecIn(t, workdir,
		WithCommand([]string{"sh", "build.sh"}),
		WithScriptCapture(ScriptCaptureContent),
		WithScriptGuard(func([]ScriptRef) error { return nil }))
	if err != nil {
		t.Fatalf("Attest with an accepting guard: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("the command did not run under an accepting guard: %v", statErr)
	}
}
