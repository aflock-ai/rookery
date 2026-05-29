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

package catalogtest

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/aflock-ai/rookery/attestation/detection"
	"github.com/aflock-ai/rookery/attestation/testkit"
	_ "github.com/aflock-ai/rookery/presets/all" // register every attestor + detector
)

// provenExempt lists attestors that declare an output contract but are NOT yet
// backed by a recorded real-run fixture. It is the warn->promote allowlist that
// keeps the gate HONEST during migration: without it, "declared a contract" and
// "proven by a real run" are conflated, and 28 of 31 contracts ride green while
// verifying nothing.
//
// The gate fails if a contracted attestor is neither proven nor listed here,
// AND it fails if an entry here has become proven — so the list can only
// SHRINK, never rot. Promotion is mechanical: record a fixture (trivy / sbom /
// sarif are the templates), add `fixtures:` to the contract, and DELETE the
// entry below. Each entry states why it isn't proven yet.
var provenExempt = map[string]string{
	// PostProduct — what remains is a genuine env/license/runtime gap, NOT
	// unrecorded laziness: every attestor whose real tool we can run has been
	// proven from a real run and DELETED from this list (and bugs that blocked
	// real output — docker-bench schema, steampipe sidecar — were FIXED, not
	// exempted).
	"nessus":         "declared; Nessus is commercial (license required) — no real scanner available to produce a .nessus report",
	"pip-install":    "declared; ambient introspector — bare-pip bug FIXED (now resolves pip3), but Attest() shells out to the live interpreter + makes live PyPI HTTP calls (PEP 740) and ignores any injected Product; not hermetically product-provable",
	"sinkhole-flows": "declared; consumes a hardcoded absolute /flows/out.jsonl produced ONLY by the proprietary testifysec/pip-witness mitmproxy sidecar (private, unreachable) — no available tool emits the schema and no testkit mode can write that absolute path",

	// PreMaterial — need env/workdir-mode fixtures. Those driver paths exist in
	// testkit but are not yet exercised by any fixture (see task #22). git is
	// now PROVEN (workdir-mode fixture single-commit) and removed from here.
	"aws-codebuild": "declared; needs env-mode fixture",
	"github":        "declared; needs env-mode fixture",
	"github-review": "declared; needs env-mode fixture",
	"gitlab":        "declared; needs env-mode fixture",
	"jenkins":       "declared; needs env-mode fixture",

	// PreMaterial cloud-identity — the http-mock metadata driver is now
	// implemented. aws (aws-iid) is PROVEN (http-mock fixture
	// ec2-instance-identity, replaying a real EC2 IMDS capture) and removed from
	// here. gcp-iit still needs its own recorded GCP metadata capture.
	"gcp-iit": "declared; http-mock driver exists, but needs a real GCP metadata-server capture (GCE_METADATA_HOST + recorded identity token) — not yet recorded",
}

// liveExempt lists PROVEN attestors whose contract is NOT backed by a
// re-runnable external tool, so the live gate (TestCatalogLiveReverify, build
// tag `live`) cannot re-run a real tool to re-derive their evidence. These are
// the two honest cases: (1) no-external-tool attestors that parse a committed
// artifact in pure Go (lockfiles) — the input IS the real artifact, there is
// nothing to re-run; (2) attestors whose tool needs credentials/infrastructure
// we won't run in CI (added here only once they have a recorded fixture). Like
// provenExempt, the list can only SHRINK: the gate fails if a proven attestor
// is neither live-re-runnable nor listed here, and fails if a listed attestor
// turns out to be live-re-runnable after all.
// NOTE: hermetic-by-construction attestors (fixtures in http-mock/workdir mode,
// which replay committed bytes through pure-Go code with no external tool that
// could drift — e.g. lockfiles, git, aws) are NOT listed here. The live gate
// recognizes them structurally (see TestCatalogLiveReRunnableOrExempt) because
// there is nothing for a live re-run to re-derive; an allowlist entry for them
// would wrongly imply "untested".
var liveExempt = map[string]string{
	"oci":           "crane pulls a remote public image (cgr.dev/.../hello-world) — the recorded image.tar IS the real pulled artifact; there is no local recording-input to re-derive it hermetically in CI without network",
	"prowler":       "prowler scans a live AWS account (testifysec-demo 898769392027, needs read-only creds + network) — the recorded prowler-output.json IS the real scan; cannot re-derive hermetically in CI",
	"asff":          "ASFF produced by a live prowler AWS scan (needs creds + network) — the recorded findings.asff.json IS the real artifact; cannot re-derive hermetically in CI",
	"steampipe":     "steampipe queries a live AWS account via the aws plugin (needs creds) — the recorded steampipe-output.json IS the real query result; cannot re-derive hermetically in CI",
	"aws-config":    "aws-config reads a live AWS Config service (needs creds) — the recorded get-compliance-details JSON IS the real artifact; cannot re-derive hermetically in CI",
	"docker-bench":  "docker-bench audits a live Docker daemon via /var/run/docker.sock (host-specific) — the recorded JSON IS the real audit; not hermetically re-runnable in CI",
	"oscap":         "oscap runs openscap-scanner against SCAP content in a Linux container — the recorded results XML IS the real scan; not hermetically re-runnable in CI",
	"inspec":        "inspec/cinc-auditor runs a remote dev-sec profile in a container (needs network + image) — the recorded json reporter IS the real run output",
	"kube-bench":    "kube-bench runs against a live Kubernetes node/cluster — the recorded JSON IS the real benchmark output; not hermetically re-runnable in CI",
	"linkerd-check": "linkerd check runs against a live cluster with linkerd installed — the recorded JSON IS the real check output; not hermetically re-runnable in CI",
	"falco":         "live Falco eBPF event stream — per-event timestamps + short-lived container ids vary every run, so a second real run never reproduces byte-for-byte (same class as prowler); the recorded falco-events.jsonl IS the real capture",
}

// TestCatalogLiveReRunnableOrExempt enforces the live gate's exception list
// statically (no tools needed, so it runs on every PR). Every proven attestor
// must either own a fixture the live gate can re-run (a recording with argv +
// a recording-input dir) or be in liveExempt with a reason.
func TestCatalogLiveReRunnableOrExempt(t *testing.T) {
	reg := detection.Default()
	all, _ := reg.LookupAll()
	root := pluginsRoot(t)
	dirs := pluginDirs(t, root)

	for name, d := range all {
		if d.Contract == nil || !d.Contract.Proven() {
			continue
		}
		dir, ok := dirs[name]
		if !ok {
			dir = filepath.Join(root, name) // fall back to name==dir
		}
		reRunnable := false
		hermetic := false
		fxs, err := testkit.LoadFixtures(filepath.Join(dir, "testdata", "fixtures"))
		if err == nil {
			for _, fx := range fxs {
				// Hermetic-by-construction modes replay COMMITTED bytes (the
				// recorded metadata response / repo tree) through pure-Go attestor
				// code — there is no external tool whose output could drift, so the
				// hermetic gate IS the full proof and there is nothing for a live
				// re-run to re-derive. (Same honest basis as the lockfiles/oci
				// liveExempt entries, but recognized structurally instead of by an
				// allowlist, so these can't masquerade as "untested".)
				if fx.Mode == testkit.ModeHTTPMock || fx.Mode == testkit.ModeWorkdir {
					hermetic = true
				}
				if fx.Recording == nil || len(fx.Recording.Argv) == 0 {
					continue
				}
				if st, err := os.Stat(filepath.Join(fx.Dir, "recording-input")); err == nil && st.IsDir() {
					reRunnable = true
				}
			}
		}
		_, lx := liveExempt[name]
		switch {
		case reRunnable && lx:
			t.Errorf("attestor %q is live-re-runnable (has a recording + recording-input) but is in liveExempt — delete the allowlist entry", name)
		case hermetic && lx:
			t.Errorf("attestor %q is hermetic-by-construction (http-mock/workdir fixture replays committed bytes) but is in liveExempt — delete the allowlist entry; it needs no live re-run", name)
		case !reRunnable && !hermetic && !lx:
			t.Errorf("attestor %q is proven but is neither live-re-runnable (recording + recording-input) nor hermetic-by-construction (http-mock/workdir) and is not in liveExempt — add a re-runnable recording, a hermetic fixture, or a liveExempt entry with a reason", name)
		}
	}

	for name := range liveExempt {
		d, ok := all[name]
		if !ok || d.Contract == nil || !d.Contract.Proven() {
			t.Errorf("liveExempt lists %q but it is not a proven attestor — remove the stale entry", name)
		}
	}
}

// TestCatalogCoverageEnforced is the anti-false-green gate. It makes "declared
// a contract" imply "proven by a real-run fixture OR explicitly exempt", and it
// ratchets the exempt list downward. It is the check that stops a green
// `catalog-verify` from silently meaning "3 of 31 verified".
func TestCatalogCoverageEnforced(t *testing.T) {
	reg := detection.Default()
	all, failures := reg.LookupAll()
	for name, err := range failures {
		t.Errorf("detector %q failed to parse: %v", name, err)
	}

	root := pluginsRoot(t)
	dirs := pluginDirs(t, root)
	contracted, proven := 0, 0
	for name, d := range all {
		if d.Contract == nil {
			continue
		}
		contracted++
		isProven := d.Contract.Proven()
		_, exempt := provenExempt[name]
		if isProven {
			proven++
		}

		switch {
		case isProven && exempt:
			t.Errorf("attestor %q is fixture-proven but still in provenExempt — delete the allowlist entry (the list must only shrink)", name)
		case !isProven && !exempt:
			t.Errorf("attestor %q declares a contract but has no canonical fixture and is not in provenExempt — record a real-run fixture (see trivy/sbom/sarif) or add an allowlist entry with a reason", name)
		}

		// A proven contract's declared canonical fixtures must exist on disk,
		// or the harness (which globs dirs, not contract refs) would silently
		// never run them.
		if isProven {
			dir, ok := dirs[name]
			if !ok {
				dir = filepath.Join(root, name) // fall back to name==dir
			}
			for _, fx := range d.Contract.Fixtures {
				if fx.Role != "" && fx.Role != detection.FixtureCanonical {
					continue
				}
				man := filepath.Join(dir, "testdata", "fixtures", fx.Name, "fixture.yaml")
				if _, err := os.Stat(man); err != nil {
					t.Errorf("attestor %q contract declares canonical fixture %q but %s is missing", name, fx.Name, man)
				}
			}
		}
	}

	// No stale exempt entries that don't map to a real declared contract.
	for name := range provenExempt {
		d, ok := all[name]
		if !ok || d.Contract == nil {
			t.Errorf("provenExempt lists %q but it has no registered contract — remove the stale entry", name)
		}
	}

	exemptNames := make([]string, 0, len(provenExempt))
	for n := range provenExempt {
		exemptNames = append(exemptNames, n)
	}
	sort.Strings(exemptNames)
	t.Logf("coverage: %d contracts, %d fixture-proven, %d exempt (allowlist must shrink): %v", contracted, proven, len(provenExempt), exemptNames)
}

// pluginDirs maps each registered attestor name to its plugin directory under
// plugins/attestors/. Almost always name == dir, but the registered name can
// diverge from the package dir (aws-iid registers as "aws"), so resolve by
// reading each detector.yaml's `name:` rather than assuming they match. Built
// once and reused by the coverage/live gates so their fixture-path lookups
// don't silently miss a renamed plugin's fixtures.
func pluginDirs(t *testing.T, root string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read plugins dir %s: %v", root, err)
	}
	out := make(map[string]string, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dy := filepath.Join(root, e.Name(), "detector.yaml")
		raw, err := os.ReadFile(dy) //nolint:gosec // test-only read of in-repo detector files
		if err != nil {
			continue
		}
		var d struct {
			Name string `yaml:"name"`
		}
		if err := yaml.Unmarshal(raw, &d); err != nil || d.Name == "" {
			continue
		}
		out[d.Name] = filepath.Join(root, e.Name())
	}
	return out
}

func pluginsRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", "..", "plugins", "attestors"))
	if err != nil {
		t.Fatalf("resolve plugins dir: %v", err)
	}
	return root
}
