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

//go:build live

// Package catalogtest's LIVE gate (build tag `live`) is the un-forgeable anchor
// of the verification loop: for every fixture that carries a recording, it
// RE-RUNS THE REAL TOOL in a fresh copy of the fixture's recording-input, then
// runs the attestor over that freshly-produced output and asserts the contract
// still holds. The hermetic gate (default build) proves the attestor CODE
// against a committed recording; this proves the committed recording reflects
// what a REAL TOOL produces TODAY — something an AI-authored fixture cannot
// fake, because the tool is run independently here. It also catches tool drift
// (a tool that changes its output so the contract no longer holds turns this
// red).
//
// Tagged out of the fast hermetic suite because it needs the tools installed
// (and, for some, network). Run it via `make catalog-verify-live`, or in CI
// with the tools provisioned and -catalog.live.strict so a missing tool FAILS
// instead of skipping (a skip must not stand in for verification in CI).
package catalogtest

import (
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/testkit"
	_ "github.com/aflock-ai/rookery/presets/all"
)

// liveStrict makes a missing tool a FAILURE rather than a skip. CI sets this so
// "the tool wasn't installed" can never silently pass as verified; locally it
// defaults off so the gate is ergonomic when a given tool isn't present.
var liveStrict = flag.Bool("catalog.live.strict", false, "fail (not skip) when a fixture's recording tool is not installed")

func TestCatalogLiveReverify(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "plugins", "attestors"))
	if err != nil {
		t.Fatalf("resolve plugins dir: %v", err)
	}
	fixtureDirs, err := filepath.Glob(filepath.Join(root, "*", "testdata", "fixtures"))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}

	ran := 0
	for _, fdir := range fixtureDirs {
		fxs, err := testkit.LoadFixtures(fdir)
		if err != nil {
			t.Errorf("load fixtures from %s: %v", fdir, err)
			continue
		}
		for _, fx := range fxs {
			// Only fixtures with a recording + a re-runnable input directory
			// can be live-verified; a contract fixture without one has no real
			// tool to re-run.
			if fx.Recording == nil || fx.Recording.Tool == "" || len(fx.Recording.Argv) == 0 {
				continue
			}
			recInput := filepath.Join(fx.Dir, "recording-input")
			if st, err := os.Stat(recInput); err != nil || !st.IsDir() {
				continue
			}
			t.Run(fx.Attestor+"/"+fx.Name, func(t *testing.T) {
				liveReverify(t, fx, recInput)
				ran++
			})
		}
	}
	if ran == 0 && *liveStrict {
		t.Fatal("live gate ran zero re-verifications under -catalog.live.strict — expected the recordable fixtures (no tools installed?)")
	}
	t.Logf("live re-verified %d fixture(s) against freshly-run real tools", ran)
}

func liveReverify(t *testing.T, fx *testkit.Fixture, recInput string) {
	t.Helper()

	// The tool must be present. In CI (strict) absence is a failure; locally it
	// is a skip so the gate is usable without every tool installed.
	if _, err := exec.LookPath(fx.Recording.Tool); err != nil {
		if *liveStrict {
			t.Fatalf("recording tool %q not installed (strict mode) — provision it for the live gate", fx.Recording.Tool)
		}
		t.Skipf("recording tool %q not installed — skipping live re-verify (run with the tool present)", fx.Recording.Tool)
	}

	// Re-run the REAL tool in a throwaway copy of the recording input, exactly
	// as it was recorded (recording.argv). The fresh output lands at the same
	// basename as the fixture's replay input.
	work := t.TempDir()
	if err := os.CopyFS(work, os.DirFS(recInput)); err != nil {
		t.Fatalf("copy recording-input: %v", err)
	}
	argv := fx.Recording.Argv
	cmd := exec.Command(argv[0], argv[1:]...) //nolint:gosec // argv is the committed, reviewed recording command
	cmd.Dir = work
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("re-running %v failed: %v\n%s", argv, err, out)
	}

	freshOut := filepath.Join(work, filepath.Base(fx.InputPath))
	if _, err := os.Stat(freshOut); err != nil {
		t.Fatalf("re-run produced no %s (the recorded command did not write the expected output): %v", filepath.Base(fx.InputPath), err)
	}

	// Build a fresh fixture pointing at the just-produced output, with the
	// recording detached (we are proving the LIVE tool output satisfies the
	// contract, not re-checking the committed recording) and goldens off
	// (fresh output legitimately differs in volatile fields).
	fresh := *fx
	fresh.InputPath = freshOut
	fresh.Recording = nil
	fresh.GoldenPath = ""

	res := testkit.RunAttestorWithFixture(t, &fresh)
	// Asserts predicate type + the contract's subject families + schema against
	// the FRESHLY produced real-tool output. If today's tool no longer produces
	// a conformant attestation, this is the contract breaking against reality.
	res.AssertContract(t, &fresh)
}
