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

package testkit

import (
	"crypto"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/invopop/jsonschema"
)

// Result is the post-run observable surface of an attestor — exactly what the
// validate tests assert against by hand today, collapsed into one struct.
type Result struct {
	Attestor  attestation.Attestor
	PredType  string                          // attestor.Type()
	Subjects  map[string]cryptoutil.DigestSet // attestor's own Subjecter contribution
	Materials map[string]cryptoutil.DigestSet // attestor's own Materialer contribution
	Products  map[string]attestation.Product  // attestor's own Producer contribution
	Predicate json.RawMessage                 // json.Marshal(attestor) — what policyverify sees
	Schema    *jsonschema.Schema
	RunErr    error // the Attest() error (nil on success) — for exit-behavior checks
}

// RunOption configures a fixture run.
type RunOption func(*runConfig)

type runConfig struct {
	attestor attestation.Attestor // pre-configured instance (overrides GetAttestor by name)
	mime     string               // override product mime
}

// WithAttestor supplies a pre-configured attestor instead of resolving by
// name. Needed for attestors requiring constructor options the fixture can't
// express generically (e.g. steampipe WithFrontmatter/WithSQL).
func WithAttestor(a attestation.Attestor) RunOption {
	return func(c *runConfig) { c.attestor = a }
}

// WithProductMime overrides the injected product mime type (product mode).
func WithProductMime(m string) RunOption {
	return func(c *runConfig) { c.mime = m }
}

// RunAttestorWithFixture drives the attestor named by the fixture against the
// fixture's recorded input, hermetically (no real tool, no network), and
// returns the observable Result. The driver is polymorphic over the fixture's
// setup mode so it covers all run-types.
//
// product mode is the generalized fakeProducer pattern: the input is
// materialized into a temp file (so the post-product attestor's digest re-check
// passes), digested, and injected as a Product before the attestor runs.
func RunAttestorWithFixture(t *testing.T, fx *Fixture, opts ...RunOption) *Result {
	t.Helper()
	cfg := &runConfig{mime: fx.MimeType}
	for _, o := range opts {
		o(cfg)
	}

	// http-mock: stand up the stub server and set its plain + endpoint env BEFORE
	// constructing the attestor. Endpoint-reading attestors (github reads
	// ACTIONS_ID_TOKEN_REQUEST_URL / WITNESS_GITHUB_JWKS_URL in New()) capture the
	// URL at construction time, so the env must already point at the stub. (Safe
	// for IMDS attestors too — the AWS SDK reads the endpoint lazily at request
	// time regardless.) `option:` endpoints (github-review's api-url) can't bind
	// at construction time since the stub URL isn't known until the server is up;
	// startHTTPMock returns them as option name -> stub base URL to apply below.
	var optionEndpointBindings map[string]any
	if fx.Mode == ModeHTTPMock {
		optionEndpointBindings = startHTTPMock(t, fx)
	}

	target := cfg.attestor
	if target == nil {
		a, err := attestation.GetAttestor(fx.Attestor)
		if err != nil {
			t.Fatalf("testkit: get attestor %q: %v", fx.Attestor, err)
		}
		// Apply fixture-declared attestor-specific options (e.g. steampipe
		// plugin/sql/id, or github-review repo/pr) through the SAME registered
		// setters the CLI flags use. The hermetic replay rebuilds the attestor by
		// name, so without this it would lose the config and emit zero/divergent
		// subjects — diverging from the recorded real run. ADDITIVE: fixtures with
		// no options are untouched.
		opts := attestorOptionValues(fx, optionEndpointBindings)
		if len(opts) > 0 {
			a, err = attestation.ApplyAttestorOptions(fx.Attestor, a, opts)
			if err != nil {
				t.Fatalf("testkit: apply options for %q: %v", fx.Attestor, err)
			}
		}
		target = a
	}

	hashes := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	var runErr error

	switch fx.Mode {
	case ModeProduct:
		producer, dir := materializeProduct(t, fx, cfg.mime, hashes)
		// WorkingDir=dir + a RELATIVE product path + t.Chdir(dir) (in
		// materializeProduct) make the product resolve for BOTH path
		// conventions: attestors that filepath.Join(WorkingDir, path) it
		// (trivy, sarif, govulncheck) and those that open it as-is relative to
		// the process CWD (prowler, steampipe). This mirrors a real cilock run,
		// where WorkingDir == process CWD == the run dir and products are
		// relative paths.
		ctx, err := attestation.NewContext(fx.Attestor, []attestation.Attestor{producer, target},
			attestation.WithHashes(hashes), attestation.WithWorkingDir(dir))
		if err != nil {
			t.Fatalf("testkit: new context: %v", err)
		}
		runErr = runAndCollect(ctx, target)

	case ModeEnv:
		for k, v := range fx.Env {
			t.Setenv(k, v)
		}
		wd := materializeWorkdir(t, fx)
		opts := []attestation.AttestationContextOption{attestation.WithHashes(hashes)}
		if wd != "" {
			// Many prematerial attestors search "." (the process CWD), not
			// ctx.WorkingDir(); chdir so the materialized tree is what they see,
			// mirroring a real cilock run where CWD == working dir.
			t.Chdir(wd)
			opts = append(opts, attestation.WithWorkingDir(wd))
		}
		ctx, err := attestation.NewContext(fx.Attestor, []attestation.Attestor{target}, opts...)
		if err != nil {
			t.Fatalf("testkit: new context: %v", err)
		}
		runErr = runAndCollect(ctx, target)

	case ModeWorkdir:
		wd := materializeWorkdir(t, fx)
		if wd != "" {
			// Same as ModeEnv: chdir so "."-searching attestors (lockfiles, git)
			// see the materialized tree, mirroring a real cilock run.
			t.Chdir(wd)
		}
		ctx, err := attestation.NewContext(fx.Attestor, []attestation.Attestor{target},
			attestation.WithHashes(hashes), attestation.WithWorkingDir(wd))
		if err != nil {
			t.Fatalf("testkit: new context: %v", err)
		}
		runErr = runAndCollect(ctx, target)

	case ModeHTTPMock:
		// Attestors that read a service endpoint over HTTP: cloud-identity
		// (aws-iid IMDS / gcp-iit metadata) and ci-context (github's OIDC token +
		// JWKS, gitlab's JWKS, github-review's GitHub API). startHTTPMock stands up
		// an httptest server replaying the COMMITTED RECORDED responses captured
		// from a real run, sets the plain setup.env, and points the attestor at
		// the stub via the right endpoint env var(s) — the AWS-IMDS special case
		// or the generalized setup.options.endpoints model. It then runs through
		// the same NewContext/RunAttestors path. The recorded bytes are the real
		// signed evidence (instance-identity doc+sig / OIDC JWT verified against
		// the recorded JWKS), so the attestor's real verification runs against
		// real evidence — hermetically, no live cloud/CI. The stub + env were set
		// up before the attestor was constructed (see top of this function).
		ctx, err := attestation.NewContext(fx.Attestor, []attestation.Attestor{target}, attestation.WithHashes(hashes))
		if err != nil {
			t.Fatalf("testkit: new context: %v", err)
		}
		runErr = runAndCollect(ctx, target)

	case ModeCommand, ModeAttestations:
		// Stretch run-types (Execute / Verify). These need a recorded trace or an
		// input-attestation+policy driver, neither of which testkit v0.1
		// implements. A fixture that declares one of these modes MUST fail
		// loudly: a t.Skip is indistinguishable from a pass in a green run and
		// would let an unverifiable contract ride. Attestors that can only use
		// these modes carry NO fixture and sit on the catalog proven-exempt
		// allowlist instead — implement the driver before adding a fixture.
		t.Fatalf("testkit: setup mode %q is not implemented yet (attestor %q) — implement the driver before adding a fixture; a skip must never stand in for verification", fx.Mode, fx.Attestor)

	default:
		t.Fatalf("testkit: unknown setup mode %q", fx.Mode)
	}

	return buildResult(t, target, runErr)
}

// driverOnlyOptionKeys are setup.options keys consumed by the testkit DRIVER
// (the http-mock metadata/endpoint plumbing), never forwarded to the attestor's
// registered config setters. Everything else in setup.options is an attestor
// option (steampipe sql/plugin, github-review repo/pr) applied via
// ApplyAttestorOptions.
var driverOnlyOptionKeys = map[string]struct{}{
	optEndpoints:     {},
	optIMDSDocument:  {},
	optIMDSSignature: {},
	optIMDSToken:     {},
}

// attestorOptionValues computes the option map to apply to the constructed
// attestor: the fixture's plain setup.options (minus driver-only keys) merged
// with the option-endpoint bindings produced by the http-mock server (e.g.
// github-review's api-url -> stub base URL). Endpoint bindings win on a key
// clash — a fixture can't both hardcode and bind the same option.
func attestorOptionValues(fx *Fixture, endpointBindings map[string]any) map[string]any {
	out := make(map[string]any, len(fx.Options)+len(endpointBindings))
	for k, v := range fx.Options {
		if _, drv := driverOnlyOptionKeys[k]; drv {
			continue
		}
		out[k] = v
	}
	for k, v := range endpointBindings {
		out[k] = v
	}
	return out
}

// runAndCollect runs the context's attestors and returns the TARGET attestor's
// own Attest error, if any.
//
// This closes a real gap: attestation.RunAttestors() records each attestor's
// Attest error in the completed-attestor list but DOES NOT return it (a single
// attestor's failure is non-fatal to the collection by design). The testkit's
// contract assertions key off Result.RunErr, so without lifting the per-attestor
// error out, an Attest failure — e.g. aws-iid's RSA signature verification
// rejecting a tampered instance-identity document — would be silently swallowed
// and the contract test would only catch it indirectly (changed subjects),
// losing the strongest anchor. Surfacing it makes a failed Attest fail the test
// for what it is.
func runAndCollect(ctx *attestation.AttestationContext, target attestation.Attestor) error {
	if err := ctx.RunAttestors(); err != nil {
		return err
	}
	for _, c := range ctx.CompletedAttestors() {
		if c.Attestor == target && c.Error != nil {
			return c.Error
		}
	}
	return nil
}

// materializeProduct writes the fixture input into a fresh temp dir, chdirs
// into it, digests it, and returns a fakeProducer injecting it as a Product by
// its RELATIVE (basename) path — plus the temp dir for the caller to set as
// WorkingDir. t.Chdir auto-restores the CWD at test end and fails if the test
// is parallel (so product-mode fixtures must not call t.Parallel). The product
// must exist on disk because post-product attestors re-digest its path.
func materializeProduct(t *testing.T, fx *Fixture, mime string, hashes []cryptoutil.DigestValue) (*fakeProducer, string) {
	t.Helper()
	if fx.InputPath == "" {
		t.Fatalf("testkit: product mode requires setup.input (fixture %q)", fx.Name)
	}
	raw, err := os.ReadFile(fx.InputPath) //nolint:gosec // path from the fixture manifest
	if err != nil {
		t.Fatalf("testkit: read input %s: %v", fx.InputPath, err)
	}
	dir := t.TempDir()
	base := filepath.Base(fx.InputPath)
	if err := os.WriteFile(filepath.Join(dir, base), raw, 0o600); err != nil {
		t.Fatalf("testkit: materialize input: %v", err)
	}
	t.Chdir(dir)
	ds, err := cryptoutil.CalculateDigestSetFromFile(base, hashes)
	if err != nil {
		t.Fatalf("testkit: digest input: %v", err)
	}
	return &fakeProducer{path: base, mime: mime, digest: ds}, dir
}

// materializeWorkdir copies the fixture's workdir files (or its single input)
// into a fresh temp working directory and returns its path ("" if none).
//
// Each workdir file is recreated at its SUBPATH relative to the fixture dir, not
// flattened to its basename — so a committed tree like `.git/HEAD`,
// `.git/refs/heads/main` materializes with its structure intact (the structure
// PlainOpen/DetectDotGit and other tree-walking attestors require). Flattening
// to basenames would collapse distinct nested files onto each other.
//
// dot-git rename trick: git refuses to track a nested `.git/` directory, so a
// recorded repo's metadata is committed under `dot-git/...` and materialized
// here as `.git/...`. The rename is applied to the leading path segment.
func materializeWorkdir(t *testing.T, fx *Fixture) string {
	t.Helper()
	files := fx.Workdir
	if len(files) == 0 && fx.InputPath != "" {
		files = []string{fx.InputPath}
	}
	if len(files) == 0 {
		return ""
	}
	wd := t.TempDir()
	for _, src := range files {
		raw, err := os.ReadFile(src) //nolint:gosec // path from the fixture manifest
		if err != nil {
			t.Fatalf("testkit: read workdir file %s: %v", src, err)
		}
		dest := filepath.Join(wd, workdirRel(fx, src))
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			t.Fatalf("testkit: materialize workdir tree %s: %v", filepath.Dir(dest), err)
		}
		if err := os.WriteFile(dest, raw, 0o600); err != nil {
			t.Fatalf("testkit: materialize workdir file: %v", err)
		}
	}
	return wd
}

// workdirRel computes a workdir file's destination path relative to the
// materialized root. It preserves the file's subpath under the fixture dir and
// rewrites a leading `dot-git` segment to `.git` (the nested-repo storage
// trick). If the source isn't under the fixture dir (or fx.Dir is unset), it
// falls back to the basename so the existing single-file fixtures are unchanged.
func workdirRel(fx *Fixture, src string) string {
	if fx.Dir == "" {
		return filepath.Base(src)
	}
	rel, err := filepath.Rel(fx.Dir, src)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return filepath.Base(src)
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if parts[0] == "dot-git" {
		parts[0] = ".git"
	}
	return filepath.Join(parts...)
}

// buildResult reads the attestor's own interface contributions (NOT the context
// aggregate, which would include the injected fakeProducer's product) and
// marshals its predicate.
func buildResult(t *testing.T, target attestation.Attestor, runErr error) *Result {
	t.Helper()
	r := &Result{Attestor: target, PredType: target.Type(), RunErr: runErr, Schema: target.Schema()}
	if s, ok := target.(attestation.Subjecter); ok {
		r.Subjects = s.Subjects()
	}
	if m, ok := target.(attestation.Materialer); ok {
		r.Materials = m.Materials()
	}
	if p, ok := target.(attestation.Producer); ok {
		r.Products = p.Products()
	}
	if runErr == nil {
		b, err := json.Marshal(target)
		if err != nil {
			t.Fatalf("testkit: marshal predicate (must be DSSE-serializable): %v", err)
		}
		r.Predicate = b
	}
	return r
}

// fakeProducer is a minimal ProductRunType attestor that injects a single
// pre-recorded file as a Product. Lifted from steampipe_validate_test.go and
// generalized with a configurable mime type.
type fakeProducer struct {
	path   string
	mime   string
	digest cryptoutil.DigestSet
}

func (f *fakeProducer) Name() string                                   { return "testkit-fake-producer" }
func (f *fakeProducer) Type() string                                   { return "https://aflock.ai/testkit/fake-producer/v0.1" }
func (f *fakeProducer) RunType() attestation.RunType                   { return attestation.ProductRunType }
func (f *fakeProducer) Schema() *jsonschema.Schema                     { return jsonschema.Reflect(f) }
func (f *fakeProducer) Attest(_ *attestation.AttestationContext) error { return nil }
func (f *fakeProducer) Products() map[string]attestation.Product {
	return map[string]attestation.Product{
		f.path: {MimeType: f.mime, Digest: f.digest},
	}
}
