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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/options"
)

// The mode rule is the compatibility contract: no existing invocation may
// change meaning. Every row here is a real invocation shape from the command's
// own examples, and the platform default applies ONLY to the flagless-policy
// session form — the one shape whose meaning Cole's ruling redefined.
func TestPlatformVerifyMode(t *testing.T) {
	cases := []struct {
		name     string
		vo       options.VerifyOptions
		platform bool
	}{
		{
			name:     "flagless with a platform URL -> PLATFORM (the redefined shape)",
			vo:       options.VerifyOptions{PlatformURL: "https://platform.example"},
			platform: true,
		},
		{
			name:     "-p names a local policy the platform cannot evaluate -> LOCAL",
			vo:       options.VerifyOptions{PlatformURL: "https://platform.example", PolicyFilePath: "policy.json.signed"},
			platform: false,
		},
		{
			name:     "--client -> LOCAL under the bound policy",
			vo:       options.VerifyOptions{PlatformURL: "https://platform.example", ClientSide: true},
			platform: false,
		},
		{
			name:     "--platform-url '' (fully offline) -> LOCAL, structurally",
			vo:       options.VerifyOptions{PlatformURL: ""},
			platform: false,
		},
		{
			name: "anchors do not decide the mode — an artifact plus -p is still LOCAL",
			vo: options.VerifyOptions{
				PlatformURL: "https://platform.example", PolicyFilePath: "p.json",
				ArtifactFilePath: "./app", CommitHash: "abc",
			},
			platform: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := platformVerifyMode(&tc.vo); got != tc.platform {
				t.Fatalf("platformVerifyMode = %v, want %v", got, tc.platform)
			}
		})
	}
}

func TestPlatformVerifyAnchors(t *testing.T) {
	t.Run("no anchor refuses with the rule, not a shrug", func(t *testing.T) {
		vo := options.VerifyOptions{}
		_, _, err := platformVerifyAnchors(&vo)
		if err == nil {
			t.Fatal("an anchorless platform verify must be refused")
		}
		if !strings.Contains(err.Error(), "--commit") {
			t.Fatalf("the refusal must name the remedies: %v", err)
		}
	})

	t.Run("--commit alone is a sufficient anchor", func(t *testing.T) {
		vo := options.VerifyOptions{CommitHash: " abc123 "}
		commit, subjects, err := platformVerifyAnchors(&vo)
		if err != nil {
			t.Fatal(err)
		}
		if commit != "abc123" || len(subjects) != 0 {
			t.Fatalf("commit %q subjects %v", commit, subjects)
		}
	})

	t.Run("a positional artifact becomes its own sha256 anchor", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "artifact.bin")
		content := []byte("the artifact under verification")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		want := sha256.Sum256(content)

		vo := options.VerifyOptions{ArtifactFilePath: path, AdditionalSubjects: []string{"sha256:aaaa"}}
		commit, subjects, err := platformVerifyAnchors(&vo)
		if err != nil {
			t.Fatal(err)
		}
		if commit != "" {
			t.Fatalf("no commit was given, got %q", commit)
		}
		if len(subjects) != 2 {
			t.Fatalf("want the -s subject plus the computed digest, got %v", subjects)
		}
		if subjects[0] != "sha256:aaaa" {
			t.Errorf("-s subjects ride through verbatim: %v", subjects)
		}
		if subjects[1] != hex.EncodeToString(want[:]) {
			t.Errorf("the artifact digest must be the file's real sha256: got %q want %q",
				subjects[1], hex.EncodeToString(want[:]))
		}
	})

	t.Run("an unreadable artifact is an error, not a silently narrower request", func(t *testing.T) {
		vo := options.VerifyOptions{ArtifactFilePath: filepath.Join(t.TempDir(), "missing"), CommitHash: "abc"}
		if _, _, err := platformVerifyAnchors(&vo); err == nil {
			t.Fatal("a named artifact that cannot be hashed must fail the request — dropping it would verify less than the caller asked")
		}
	})
}

// The exit contract, as value claims per verdict shape (Codex, #8666 round 1:
// a PASSED with no VSA exited 0). The mode's contract is "the answer is a
// VSA", so an unverifiable pass is a degraded answer and the gate fails
// closed — while FAILED/PENDING keep their VSA-independent refusals.
func TestRenderPlatformEvaluation_ExitContract(t *testing.T) {
	vo := options.VerifyOptions{OutputFormat: "json"} // stdout stays parseable either way
	cases := []struct {
		name    string
		eval    options.PlatformEvaluation
		wantErr bool
		errHas  string
	}{
		{name: "PASSED with a VSA is the only success",
			eval: options.PlatformEvaluation{Status: "PASSED", VsaGitoidSha256: "deadbeef"}},
		{name: "PASSED without a VSA fails closed - the verdict is not independently verifiable",
			eval: options.PlatformEvaluation{Status: "PASSED"}, wantErr: true, errHas: "not independently verifiable"},
		{name: "FAILED refuses regardless of its VSA",
			eval: options.PlatformEvaluation{Status: "FAILED", VsaGitoidSha256: "cafef00d"}, wantErr: true},
		{name: "PENDING refuses - evidence not arrived is not a pass",
			eval: options.PlatformEvaluation{Status: "PENDING"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Capture the emitted JSON: `passed` is documented "for branching",
			// so it must agree with the exit decision in EVERY case (Codex,
			// #8666 round 3 — a JSON consumer accepted a verdict the exit code
			// refused). Both derive from gateAccepts; this asserts the wire
			// bytes, not the shared implementation.
			r, w, perr := os.Pipe()
			if perr != nil {
				t.Fatal(perr)
			}
			origStdout := os.Stdout
			os.Stdout = w
			err := renderPlatformEvaluation(vo, &tc.eval)
			os.Stdout = origStdout
			_ = w.Close()
			raw, _ := io.ReadAll(r)

			if tc.wantErr && err == nil {
				t.Fatal("must refuse")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("must pass: %v", err)
			}
			if tc.errHas != "" && (err == nil || !strings.Contains(err.Error(), tc.errHas)) {
				t.Fatalf("refusal must say why: %v", err)
			}

			var out struct {
				Passed bool `json:"passed"`
			}
			if jerr := json.Unmarshal(raw, &out); jerr != nil {
				t.Fatalf("stdout must stay parseable JSON: %v (%q)", jerr, raw)
			}
			if out.Passed != (err == nil) {
				t.Fatalf("the JSON passed field (%v) and the exit decision (err=%v) branched differently — one predicate, both surfaces", out.Passed, err)
			}
		})
	}
}
