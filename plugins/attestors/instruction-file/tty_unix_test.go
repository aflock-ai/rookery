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

//go:build unix

package instructionfile

import (
	"os"
	"path/filepath"
	"testing"
)

// TestFileIsTerminalRejectsNonTerminalCharDevices pins the distinction between
// "is a character device" and "is a terminal".
//
// The two are not the same set, and conflating them is how this attestor came
// to claim `interactive-human-session` for an unattended CI job. /dev/null is a
// character device and is the single most common stdin for a non-interactive
// build: every `cmd < /dev/null`, every daemon-launched runner, every container
// started without a TTY. A mode-bit test (`Mode()&os.ModeCharDevice != 0`)
// answers true for it, so the probe reported a human at the keyboard for the
// exact environments that most certainly had none.
//
// The direction of that error is conservative — `interactive-human-session` is
// a deny-side kind — but a control that denies every unattended build is as
// unusable as one that permits every human, and either way the predicate says
// something false about the process that produced it. The honest probe is an
// ioctl that asks the kernel whether the descriptor has a terminal line
// discipline; /dev/null has none.
func TestFileIsTerminalRejectsNonTerminalCharDevices(t *testing.T) {
	t.Parallel()

	regular := filepath.Join(t.TempDir(), "regular.txt")
	if err := os.WriteFile(regular, []byte("not a terminal"), 0o600); err != nil {
		t.Fatalf("write regular file: %v", err)
	}

	cases := []struct {
		name string
		path string
		// charDevice records whether the mode-bit heuristic this replaced
		// would have answered true, so the test states plainly which entries
		// are the regression and which are merely controls.
		charDevice bool
	}{
		{name: "dev-null is a character device but not a terminal", path: os.DevNull, charDevice: true},
		{name: "dev-zero is a character device but not a terminal", path: "/dev/zero", charDevice: true},
		{name: "regular file is not a terminal", path: regular, charDevice: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f, err := os.Open(tc.path)
			if err != nil {
				t.Skipf("cannot open %s on this platform: %v", tc.path, err)
			}
			defer func() { _ = f.Close() }()

			info, statErr := f.Stat()
			if statErr != nil {
				t.Fatalf("stat %s: %v", tc.path, statErr)
			}
			if got := info.Mode()&os.ModeCharDevice != 0; got != tc.charDevice {
				t.Fatalf("%s: precondition failed, ModeCharDevice = %v, want %v", tc.path, got, tc.charDevice)
			}

			if fileIsTerminal(f) {
				t.Errorf("fileIsTerminal(%s) = true, want false: a character device is not a terminal", tc.path)
			}
		})
	}
}

// TestFileIsTerminalHandlesNilFile pins the nil case rather than panicking.
// detectSigner falls through to `unknown` when the probe cannot answer, which
// is the correct outcome when there is no descriptor to ask about.
func TestFileIsTerminalHandlesNilFile(t *testing.T) {
	t.Parallel()

	if fileIsTerminal(nil) {
		t.Error("fileIsTerminal(nil) = true, want false")
	}
}

// TestDetectSignerDoesNotClaimHumanForRedirectedStdin is the end-to-end shape
// of the same defect: an unattended run with stdin on /dev/null and no
// token-request variables must land on `unknown`, not on a human session.
func TestDetectSignerDoesNotClaimHumanForRedirectedStdin(t *testing.T) {
	t.Parallel()

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("cannot open %s: %v", os.DevNull, err)
	}
	defer func() { _ = devNull.Close() }()

	env := func(string) string { return "" }

	got := detectSigner(env, fileIsTerminal(devNull))
	if got.Kind != SignerKindUnknown {
		t.Errorf("detectSigner with stdin on %s = %q, want %q", os.DevNull, got.Kind, SignerKindUnknown)
	}
}
