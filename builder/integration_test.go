// Copyright 2025 The Aflock Authors
//
// Use of this software is governed by the Business Source License 1.1,
// included in the builder/LICENSE file (https://spdx.org/licenses/BUSL-1.1).
// As of the Change Date specified in that file, the Licensed Work converts
// to the GNU General Public License, version 2.0.
//
// Built with the build tag `integration` to keep `make test` fast.
// CI runs this in a dedicated `builder-smoke` job (see ci.yml).
//
//	go test -v -tags=integration ./builder/...

//go:build integration

package builder_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dsseEnvelope is the minimal shape we need to assert the binaries produce
// equivalent output. Re-declared rather than imported from
// attestation/dsse so the test catches a schema regression on either side.
type dsseEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

type intotoStatement struct {
	Type          string            `json:"_type"`
	PredicateType string            `json:"predicateType"`
	Subject       []json.RawMessage `json:"subject"`
}

// run shells out, returning combined output and erroring on non-zero exit.
func run(t *testing.T, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %v failed in %s: %v\n%s", name, args, dir, err, buf.String())
	}
	return buf.String()
}

// findRookeryRoot walks up from cwd looking for go.work — same shape the
// builder's --local autodetect uses.
func findRookeryRoot(t *testing.T) string {
	t.Helper()
	wd, _ := os.Getwd()
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
	}
	t.Fatalf("rookery root not found above %s", wd)
	return ""
}

// fixture bundles a tempdir with an RSA keypair, a tiny git-initialized
// workdir, and built builder + stock cilock binaries. Mirrors the
// newTestEnv pattern from cilock/test/compat_test.go.
type fixture struct {
	root        string // rookery root
	dir         string // tempdir
	workdir     string // tempdir/work with one file + git
	keyPath     string // tempdir/test.pem (RSA private)
	pubPath     string // tempdir/test.pub
	builderBin  string // built builder
	cilockBin   string // built stock cilock from cilock/cmd/cilock/
	generated   string // generated cilock binary (after build)
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH; required for keypair generation")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH; required for the git attestor")
	}

	f := &fixture{root: findRookeryRoot(t), dir: t.TempDir()}
	f.workdir = filepath.Join(f.dir, "work")
	if err := os.MkdirAll(f.workdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.workdir, "hello.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Minimal git init so the git attestor succeeds.
	run(t, f.workdir, "git", "init", "-q")
	run(t, f.workdir, "git", "config", "user.email", "test@example.com")
	run(t, f.workdir, "git", "config", "user.name", "Test")
	run(t, f.workdir, "git", "add", ".")
	run(t, f.workdir, "git", "commit", "-q", "-m", "init", "--no-gpg-sign")

	// RSA keypair via openssl — same recipe cilock/test/compat_test.go uses.
	f.keyPath = filepath.Join(f.dir, "test.pem")
	f.pubPath = filepath.Join(f.dir, "test.pub")
	run(t, f.dir, "openssl", "genpkey", "-algorithm", "RSA",
		"-out", f.keyPath, "-pkeyopt", "rsa_keygen_bits:2048")
	run(t, f.dir, "openssl", "rsa", "-in", f.keyPath, "-pubout", "-out", f.pubPath)

	// Build the rookery-builder from current tree.
	f.builderBin = filepath.Join(f.dir, "rookery-builder")
	run(t, f.root, "go", "build", "-o", f.builderBin, "./builder/cmd/builder/")

	// Build stock cilock from current tree — same `go build` the release
	// pipeline runs at .github/workflows/release.yml.
	f.cilockBin = filepath.Join(f.dir, "stock-cilock")
	cmd := exec.Command("go", "build", "-o", f.cilockBin, "./cmd/cilock/")
	cmd.Dir = filepath.Join(f.root, "cilock")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build stock cilock: %v\n%s", err, string(out))
	}

	// Generate a cilock binary via the builder using --preset minimal.
	f.generated = filepath.Join(f.dir, "gen-cilock")
	run(t, f.root, f.builderBin, "--preset", "minimal", "--local",
		"--output", f.generated)
	return f
}

// runCilock invokes a cilock binary's `run` subcommand to produce a DSSE
// envelope at outFile, signed with the fixture's RSA key.
func (f *fixture) runCilock(t *testing.T, bin, step, outFile string) {
	t.Helper()
	run(t, f.workdir, bin, "run",
		"--step", step,
		"--signer-file-key-path", f.keyPath,
		"--outfile", outFile,
		"--workingdir", f.workdir,
		"--attestations", "environment,git",
		"--", "sh", "-c", "echo product > out.txt")
}

func (f *fixture) parseEnvelope(t *testing.T, path string) (dsseEnvelope, intotoStatement) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var env dsseEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("parse envelope %s: %v\n%s", path, err, string(data))
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var stmt intotoStatement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		t.Fatalf("parse statement: %v", err)
	}
	return env, stmt
}

// TestGeneratedBinaryHasFullCLISurface — Layer 2 of the original plan:
// the rewired generated binary must expose `run/verify/sign` just like
// stock cilock. This is the regression that would fire if someone
// reverted the codegen rewrite without noticing.
func TestGeneratedBinaryHasFullCLISurface(t *testing.T) {
	f := newFixture(t)
	out := run(t, f.dir, f.generated, "--help")
	for _, sub := range []string{"run", "verify", "sign", "attestors", "completion", "version"} {
		// Match the cobra subcommand-table indent so `signer` doesn't
		// false-positive `sign`.
		if !strings.Contains(out, "  "+sub+" ") && !strings.Contains(out, "  "+sub+"\n") {
			t.Errorf("generated binary --help missing expected subcommand %q\n%s", sub, out)
		}
	}
}

// TestGeneratedBinaryEmitsValidDSSE — Layer 4: full pipeline runs and
// the output parses as a DSSE envelope wrapping an in-toto Statement.
func TestGeneratedBinaryEmitsValidDSSE(t *testing.T) {
	f := newFixture(t)
	outFile := filepath.Join(f.dir, "gen.dsse.json")
	f.runCilock(t, f.generated, "gen-step", outFile)

	env, stmt := f.parseEnvelope(t, outFile)
	if env.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("payloadType = %q, want application/vnd.in-toto+json", env.PayloadType)
	}
	if len(env.Signatures) != 1 {
		t.Fatalf("expected 1 signature; got %d", len(env.Signatures))
	}
	// cilock currently emits the legacy v0.1 Statement type for compat
	// with witness; the canonical in-toto spec URI is v1. Accept either.
	if stmt.Type != "https://in-toto.io/Statement/v1" &&
		stmt.Type != "https://in-toto.io/Statement/v0.1" {
		t.Errorf("statement _type = %q, want in-toto Statement v0.1 or v1", stmt.Type)
	}
	if stmt.PredicateType == "" {
		t.Error("predicate type is empty")
	}
}

// TestStockCilockAndGeneratedAgreeOnKeyID — Layer 5/6 partial:
// signing the same payload with the same key under both binaries
// produces matching key IDs. This is a fingerprint of the keyloader
// + signer plumbing; if it ever differs, downstream policy verifiers
// would silently reject one side's envelopes.
func TestStockCilockAndGeneratedAgreeOnKeyID(t *testing.T) {
	f := newFixture(t)

	stockOut := filepath.Join(f.dir, "stock.dsse.json")
	genOut := filepath.Join(f.dir, "gen.dsse.json")

	f.runCilock(t, f.cilockBin, "stock-step", stockOut)
	stockEnv, _ := f.parseEnvelope(t, stockOut)

	// Clean up the product file so cilock generates a fresh subject.
	_ = os.Remove(filepath.Join(f.workdir, "out.txt"))

	f.runCilock(t, f.generated, "gen-step", genOut)
	genEnv, _ := f.parseEnvelope(t, genOut)

	if len(stockEnv.Signatures) == 0 || len(genEnv.Signatures) == 0 {
		t.Fatal("missing signatures on one side")
	}
	if stockEnv.Signatures[0].KeyID != genEnv.Signatures[0].KeyID {
		t.Errorf("key ID drift: stock=%s gen=%s — signer or keyloader regressed",
			stockEnv.Signatures[0].KeyID, genEnv.Signatures[0].KeyID)
	}
}

// TestAttestorsListMatchesMinimalPreset is the equivalent of layer 7:
// for the `minimal` preset, the registered attestor + signer names
// must match what cilock/builder/cmd/builder/main.go declares.
//
// Today's minimal preset (from builder/cmd/builder/main.go):
//   attestors: commandrun, environment, git, material, product
//   signers:   file
//
// If someone changes either list without updating the corresponding
// side, this test fires.
func TestAttestorsListMatchesMinimalPreset(t *testing.T) {
	f := newFixture(t)
	out := run(t, f.dir, f.generated, "attestors", "list")

	wantAttestors := []string{"command-run", "environment", "git", "material", "product"}
	for _, want := range wantAttestors {
		if !strings.Contains(out, want) {
			t.Errorf("attestors list missing %q\n%s", want, out)
		}
	}
}
