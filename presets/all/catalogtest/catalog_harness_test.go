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

// Package catalogtest is the all-attestors catalog verification harness. It
// blank-imports presets/all (registering every attestor) and walks every
// plugin's testdata/fixtures/, driving each fixture through the testkit SDK and
// asserting its contract. One `go test` here is the CI gate: it proves the
// catalog's claims against recorded (real-run) evidence for every contracted
// attestor at once. Per-plugin fixtures_test.go files cover the same fixtures
// for fast local iteration; this is the aggregate gate.
//
// Hermetic: no real tools, no network — fixtures are committed recordings.
// Fixtures are discovered on disk via presets/all's replace paths to the
// plugin source trees (go:embed can't cross module boundaries, so the harness
// reads the files directly).
package catalogtest

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/testkit"
	"github.com/aflock-ai/rookery/plugins/attestors/commandrun"
	_ "github.com/aflock-ai/rookery/presets/all" // register every attestor + signer
)

func TestCatalogContracts(t *testing.T) {
	// rookery/plugins/attestors relative to this package (presets/all/catalogtest).
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "plugins", "attestors"))
	if err != nil {
		t.Fatalf("resolve plugins dir: %v", err)
	}
	fixtureDirs, err := filepath.Glob(filepath.Join(root, "*", "testdata", "fixtures"))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}

	total := 0
	for _, fdir := range fixtureDirs {
		fxs, err := testkit.LoadFixtures(fdir)
		if err != nil {
			t.Errorf("load fixtures from %s: %v", fdir, err)
			continue
		}
		for _, fx := range fxs {
			total++
			t.Run(fx.Attestor+"/"+fx.Name, func(t *testing.T) {
				res := testkit.RunAttestorWithFixture(t, fx, withReplayedCommandRun)
				res.AssertContract(t, fx)
				// Signed evidence must be reproducible: re-run and assert the
				// predicate is identical (catches nondeterministic output).
				testkit.AssertDeterministic(t, fx, res, withReplayedCommandRun)
			})
		}
	}
	// A broken cross-module glob (the ../../../ path or the module layout
	// changing) would otherwise make this whole suite pass by finding nothing.
	// At least the committed proven fixtures (trivy/sbom/sarif) must load, so
	// zero is a hard failure, never a silent skip.
	if total == 0 {
		t.Fatalf("no catalog fixtures found under %s — the fixture glob is broken (expected the committed proven fixtures); a skip here would be a false green", root)
	}
	t.Logf("verified %d catalog fixture(s) across %d attestor(s) with fixtures", total, len(fixtureDirs))
}

// withReplayedCommandRun lets a fixture that declares setup.command_run replay
// with the command-run its recorded collection holds (the live gate passes its
// re-run's instead). An attestor that reads the wrapped command's exit status
// (govulncheck: an unknown status is never attested as a completed scan) sees
// the argv and exit code the real run recorded, as it did inside that
// `cilock run`. Fixtures that do not declare it replay with no command-run, as
// before.
var withReplayedCommandRun = testkit.WithCommandRun(func(cr testkit.CommandRun) attestation.Attestor {
	run := commandrun.New(commandrun.WithCommand(cr.Argv))
	run.ExitCode = cr.ExitCode
	return replayedCommandRun{run}
})

// replayedCommandRun is a command-run that already completed in the recorded
// run. Attest does nothing: re-executing the recorded argv (a real govulncheck
// against the network) would break the hermetic replay, and its outcome is
// already in the recording.
type replayedCommandRun struct{ *commandrun.CommandRun }

func (replayedCommandRun) Attest(*attestation.AttestationContext) error { return nil }

// TestReplayedCommandRunCarriesTheExitStatus pins that the replay hands the
// attestor the recorded exit status rather than a stand-in 0: the same
// recorded govulncheck stream, replayed with a command-run that exited 1, is
// refused. Without this, a builder that hard-coded a clean exit would keep the
// canonical row green whatever the recording said.
func TestReplayedCommandRunCarriesTheExitStatus(t *testing.T) {
	// Resolved from pluginsRoot like every other catalogtest read of a plugin
	// tree: presets/all imports the govulncheck plugin, so the ring's module
	// graph selects this package for a change to that plugin's testdata.
	fx, err := testkit.LoadFixture(filepath.Join(pluginsRoot(t), "govulncheck", "testdata", "fixtures", "vuln-found"))
	if err != nil {
		t.Fatalf("load vuln-found: %v", err)
	}
	if fx.CommandRun == nil || fx.CommandRun.ExitCode != 0 {
		t.Fatalf("vuln-found must replay its recorded command-run with exit 0, got %+v", fx.CommandRun)
	}
	failed := *fx
	failed.CommandRun = &testkit.CommandRun{Argv: fx.CommandRun.Argv, ExitCode: 1}
	res := testkit.RunAttestorWithFixture(t, &failed, withReplayedCommandRun)
	if res.RunErr == nil || !strings.Contains(res.RunErr.Error(), "exited with status 1") {
		t.Fatalf("a recorded exit status of 1 must refuse the scan, got error %v", res.RunErr)
	}
}
