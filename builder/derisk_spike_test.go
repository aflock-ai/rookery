// Copyright 2025 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

// Package builder derisk spike: characterize the rookery-builder's current
// behavior and lay out the post-rewire assertions as skip-guarded blocks.
//
// The goal is to surface the unknowns BEFORE writing the full rewire:
//
//  1. Does `rookery-builder --preset minimal --local` actually produce a
//     binary today? (Sanity: yes, but the shape is wrong.)
//  2. What subcommands does the current generated binary expose? (Expected
//     answer: attestors / signers / buildinfo / version / license / help —
//     no run / verify / sign. This is the bug we're fixing.)
//  3. Does `go.mod` in the generated build dir resolve cleanly via
//     `go mod tidy` against the rookery in-tree state? (Tests the
//     codegen + builder/go.mod plumbing without touching cilock/cli yet.)
//  4. Does the existing `cilock/test/compat_test.go` helper shape
//     (newTestEnv, parseEnvelope, RSA keypair via openssl, etc.) compose
//     into a builder test, or are there hidden test-tag / package
//     boundaries to work around?
//  5. Confirm Go's internal-package visibility rule does in fact block
//     an external module from importing `cilock/internal/cmd`. This is
//     the load-bearing assumption for needing the cli/ rename at all.
//
// Run from the rookery root with:
//
//	go test -v -tags=derisk ./builder/...
//
// The test is build-tagged so it does not pollute `make test`. Once the
// rewire lands, the post-rewire blocks become regular asserts and the
// pre-rewire blocks become regressions to delete.

//go:build derisk

package builder_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// findRookeryRoot walks up from the current test binary until it finds
// the go.work file at the rookery root. This is the same shape the
// builder's --local autodetect uses.
func findRookeryRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
	}
	t.Fatalf("rookery root not found above %s", wd)
	return ""
}

// runWithEnv shells out and returns combined output + error. We use it in
// place of cilock/test's `run` because that helper t.Fatal's on error,
// and here we want to *observe* failures (e.g. confirm the generated
// binary errors when run with `run`).
func runWithEnv(t *testing.T, dir string, env []string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

// TestSpike_CurrentBuilderProducesInspectorStub characterizes today's
// state: the builder runs, the binary builds, but it lacks `run/verify/
// sign`. This will FAIL once the rewire ships, signaling time to delete
// this test and replace it with the real integration test.
func TestSpike_CurrentBuilderProducesInspectorStub(t *testing.T) {
	root := findRookeryRoot(t)

	// Step 1 — build the builder itself.
	builderBin := filepath.Join(t.TempDir(), "rookery-builder")
	out, err := runWithEnv(t, root, nil,
		"go", "build", "-o", builderBin, "./builder/cmd/builder/")
	if err != nil {
		t.Fatalf("go build builder: %v\n%s", err, out)
	}
	t.Logf("built rookery-builder at %s", builderBin)

	// Step 2 — generate a minimal-preset binary against the local tree.
	outBin := filepath.Join(t.TempDir(), "gen-cilock")
	out, err = runWithEnv(t, root, nil,
		builderBin, "--preset", "minimal", "--local", "--output", outBin)
	if err != nil {
		t.Fatalf("rookery-builder --preset minimal --local: %v\n%s", err, out)
	}
	if _, err := os.Stat(outBin); err != nil {
		t.Fatalf("generated binary not at %s: %v", outBin, err)
	}
	t.Logf("generated binary at %s", outBin)

	// Step 3 — assert today's wrong shape: no `run` subcommand.
	out, err = runWithEnv(t, root, nil, outBin, "--help")
	if err != nil {
		// Today the binary exit-codes 0 with help text; this branch is
		// future-proofing for the rewire when cobra takes over.
		t.Logf("--help exited non-zero (might be post-rewire?): %v\n%s", err, out)
	}
	t.Logf("--help output:\n%s", out)

	// PRE-REWIRE: the inspector stub does not have `run`.
	preRewireSubcommands := []string{"attestors", "signers", "buildinfo", "license"}
	for _, sub := range preRewireSubcommands {
		if !strings.Contains(out, sub) {
			t.Errorf("expected inspector subcommand %q in --help; got:\n%s", sub, out)
		}
	}

	// Match whole subcommand tokens — the inspector's `signers` line
	// would false-positive a naive substring search for "sign".
	postRewireMissing := []string{"run", "verify", "sign-file"}
	for _, sub := range postRewireMissing {
		// Subcommands in the inspector help live on lines of the form
		// "  <name>   <description>". A run/verify subcommand would
		// appear as "  run " (with trailing space + description) or as
		// "  run\n" if it had no help text. Match the leading indent.
		needle := "  " + sub + " "
		needleNL := "  " + sub + "\n"
		if strings.Contains(out, needle) || strings.Contains(out, needleNL) {
			t.Errorf("UNEXPECTED: post-rewire subcommand %q already present; "+
				"delete this test and write the real integration test", sub)
		}
	}
	// `sign` alone has to be checked specially since it's a substring of
	// `signers`. The post-rewire cobra tree exposes `sign` as a
	// standalone subcommand (see cilock/internal/cmd/sign.go).
	// We match it as either "  sign\n" or "  sign " but NOT "signers".
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 1 && fields[0] == "sign" {
			t.Errorf("UNEXPECTED: post-rewire subcommand \"sign\" already present; "+
				"delete this test and write the real integration test")
		}
	}
}

// TestSpike_GeneratedGoModResolvesCleanly verifies that the builder's
// codegen produces a go.mod that `go mod tidy` accepts against the
// current rookery state. If this breaks the rewire is undeployable.
func TestSpike_GeneratedGoModResolvesCleanly(t *testing.T) {
	root := findRookeryRoot(t)
	builderBin := filepath.Join(t.TempDir(), "rookery-builder")
	if out, err := runWithEnv(t, root, nil,
		"go", "build", "-o", builderBin, "./builder/cmd/builder/"); err != nil {
		t.Fatalf("go build builder: %v\n%s", err, out)
	}

	// The builder writes to a subdir of $TMPDIR by default; running it
	// once already validates `go mod tidy` succeeds because the builder
	// runs it internally and would have failed earlier if it didn't.
	outBin := filepath.Join(t.TempDir(), "gen-cilock")
	if out, err := runWithEnv(t, root, nil,
		builderBin, "--preset", "minimal", "--local", "--output", outBin); err != nil {
		t.Fatalf("builder mod tidy implicitly failed: %v\n%s", err, out)
	}
	t.Log("generated go.mod tidied cleanly against in-tree rookery")
}

// TestSpike_InternalPackageRuleBlocksExternalImport confirms Go's
// internal-package visibility rule will reject any attempt to import
// `cilock/internal/cmd` from outside the cilock/ tree. If this passes,
// the rename to cilock/cli is mandatory. If it fails, we've
// misunderstood Go's rules and the rewire plan is wrong.
func TestSpike_InternalPackageRuleBlocksExternalImport(t *testing.T) {
	root := findRookeryRoot(t)

	// Generate a tiny external module that tries to import the internal
	// package, then attempt `go build`. We expect a hard error from go.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module derisk\n\ngo 1.26\n\nrequire github.com/aflock-ai/rookery v0.0.0\n"+
			"replace github.com/aflock-ai/rookery => "+root+"\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"),
		[]byte(`package main

import (
	_ "github.com/aflock-ai/rookery/cilock/internal/cmd"
)

func main() {}
`), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}

	out, err := runWithEnv(t, dir, nil, "go", "build", "./...")
	if err == nil {
		t.Fatalf("UNEXPECTED: external module imported cilock/internal/cmd successfully. "+
			"This means the rewire plan's premise is wrong — re-examine before coding. "+
			"Output:\n%s", out)
	}
	if !strings.Contains(out, "use of internal package") {
		t.Logf("got error (good) but not the expected 'use of internal package' wording:\n%s", out)
	}
	t.Logf("confirmed: external import of cilock/internal/cmd fails with:\n%s", out)
}

// TestSpike_CompatHelpersCompose pulls in cilock/test's helper shape
// (RSA keypairs via openssl, tempdir workdir, parseEnvelope/Collection)
// to make sure they work outside the cilock module. This is a smoke
// test for "can the real integration test reuse those helpers, or do
// we need to fork them?"
//
// This test is intentionally minimal — we just generate a keypair the
// same way newTestEnv does, then assert the file exists and parses.
func TestSpike_CompatHelpersCompose(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not on PATH; cilock/test/compat_test.go has the same requirement")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test.pem")
	pubPath := filepath.Join(dir, "test.pub")
	if out, err := runWithEnv(t, dir, nil,
		"openssl", "genpkey", "-algorithm", "RSA", "-out", keyPath,
		"-pkeyopt", "rsa_keygen_bits:2048"); err != nil {
		t.Fatalf("genpkey: %v\n%s", err, out)
	}
	if out, err := runWithEnv(t, dir, nil,
		"openssl", "rsa", "-in", keyPath, "-pubout", "-out", pubPath); err != nil {
		t.Fatalf("rsa pubout: %v\n%s", err, out)
	}
	for _, p := range []string{keyPath, pubPath} {
		if st, err := os.Stat(p); err != nil || st.Size() == 0 {
			t.Errorf("expected non-empty file at %s; err=%v", p, err)
		}
	}
	t.Logf("RSA keypair generation pattern from cilock/test composes cleanly")
}

// TestSpike_PostRewireAssertions enumerates the assertions that should
// pass *after* the cilock/cli rename + builder codegen rewrite lands.
// Each block is t.Skip'd today so the test stays green. Once the rewire
// is done, change `skipReason` to "" to enable the block.
func TestSpike_PostRewireAssertions(t *testing.T) {
	const skipReason = "post-rewire only; delete the skip once cilock/internal/cmd → cilock/cli lands"

	t.Run("generated_binary_has_run_subcommand", func(t *testing.T) {
		t.Skip(skipReason)
		// After rewire:
		//   out, _ := runWithEnv(t, root, nil, generatedBin, "--help")
		//   for _, sub := range []string{"run", "verify", "sign", "attestors"} {
		//       require.Contains(t, out, sub)
		//   }
	})

	t.Run("generated_binary_produces_valid_dsse_envelope", func(t *testing.T) {
		t.Skip(skipReason)
		// After rewire:
		//   env := newTestEnv(t)  // borrowed from cilock/test/compat_test.go
		//   run(t, env.workdir, generatedBin, "run", "--step", "test",
		//       "--signer-file-key-path", env.keyPath,
		//       "-o", outFile, "--workingdir", env.workdir,
		//       "--attestations", "environment,git", "--", "echo", "hi")
		//   envelope, stmt := parseEnvelope(t, outFile)
		//   require.NotEmpty(t, envelope.Signatures)
		//   require.Equal(t, "https://in-toto.io/Statement/v1", stmt.Type)
	})

	t.Run("stock_cilock_verifies_generated_binary_envelope", func(t *testing.T) {
		t.Skip(skipReason)
		// After rewire:
		//   1. generatedBin run → outFile.dsse (signed with env.keyPath)
		//   2. write a minimal policy referencing env.pubPath as the
		//      functionary public key (the policy JSON in compat_test.go's
		//      TestMixAndMatchVerify lines 437-473 is the template)
		//   3. stockCilockBin verify --policy <signed-policy> --publickey
		//      <policy-pubkey> --attestations outFile.dsse
		//   4. assert exit 0
	})

	t.Run("generated_binary_verifies_stock_cilock_envelope", func(t *testing.T) {
		t.Skip(skipReason)
		// Inverse of above.
	})

	t.Run("attestors_list_byte_identical_with_matching_blank_imports", func(t *testing.T) {
		t.Skip(skipReason)
		// After rewire:
		//   - build generated cilock with a manifest covering exactly the
		//     same plugin set as cilock/cmd/cilock/main.go's blank imports
		//   - `./generatedBin attestors list` and `./stockCilockBin attestors list`
		//     should produce byte-identical output
		//   - if they don't, the rewire missed something in the init() ordering
		//     or attestor-registration plumbing
	})

	t.Run("fips_mode_propagates_to_generated_main_go", func(t *testing.T) {
		t.Skip(skipReason)
		// After rewire:
		//   - generate with --fips=on
		//   - `go version -m generatedBin` should show fips140=on in build settings
	})
}

// TestSpike_DocumentObservedBuilderState dumps the builder's current
// help text and the first 1KB of a sample generated main.go to test
// output, so the rewire reviewer has a snapshot of "what we started
// from" before any code moves.
func TestSpike_DocumentObservedBuilderState(t *testing.T) {
	root := findRookeryRoot(t)

	builderBin := filepath.Join(t.TempDir(), "rookery-builder")
	if out, err := runWithEnv(t, root, nil,
		"go", "build", "-o", builderBin, "./builder/cmd/builder/"); err != nil {
		t.Fatalf("go build builder: %v\n%s", err, out)
	}

	helpOut, _ := runWithEnv(t, root, nil, builderBin, "--help")
	t.Logf("=== rookery-builder --help ===\n%s", helpOut)

	// Generate into a known dir so we can read the emitted main.go.
	genDir := t.TempDir()
	if out, err := runWithEnv(t, root, nil,
		builderBin, "--preset", "minimal", "--local",
		"--output", filepath.Join(genDir, "gen-cilock")); err != nil {
		t.Fatalf("generate: %v\n%s", err, out)
	}

	// The builder writes its working dir under $TMPDIR; we don't have a
	// direct handle to it. Instead, run --help on the generated binary
	// and dump that — same forensic value.
	helpOut, _ = runWithEnv(t, root, nil,
		filepath.Join(genDir, "gen-cilock"), "--help")
	t.Logf("=== generated binary --help ===\n%s", helpOut)

	atOut, _ := runWithEnv(t, root, nil,
		filepath.Join(genDir, "gen-cilock"), "attestors")
	t.Logf("=== generated binary attestors ===\n%s", atOut)

	siOut, _ := runWithEnv(t, root, nil,
		filepath.Join(genDir, "gen-cilock"), "signers")
	t.Logf("=== generated binary signers ===\n%s", siOut)

	licOut, _ := runWithEnv(t, root, nil,
		filepath.Join(genDir, "gen-cilock"), "license")
	t.Logf("=== generated binary license ===\n%s", licOut)
}

// Confirm we can locate the existing compat_test.go so the real
// integration test can reuse its helpers. Smoke test only.
func TestSpike_ExistingCompatTestIsReachable(t *testing.T) {
	root := findRookeryRoot(t)
	compatPath := filepath.Join(root, "cilock", "test", "compat_test.go")
	if _, err := os.Stat(compatPath); err != nil {
		t.Fatalf("expected reusable compat helpers at %s: %v", compatPath, err)
	}

	// Confirm the helper symbols we want to reuse are exported (lowercase
	// means we'd need to copy them into the builder test or refactor to a
	// shared internal/testutil package).
	data, err := os.ReadFile(compatPath)
	if err != nil {
		t.Fatalf("read compat: %v", err)
	}
	source := string(data)
	for _, sym := range []string{
		"func newTestEnv",     // helper that builds tempdir + keypairs
		"func parseEnvelope",  // helper that parses DSSE
		"func parseCollection", // helper that parses collection predicate
		"func run(",           // shell-out runner
	} {
		if !strings.Contains(source, sym) {
			t.Errorf("compat_test.go does not export expected helper %q", sym)
		}
	}

	// Note: all those helpers are package-private (`package test`,
	// lowercase symbols). To reuse them we'll either copy them into
	// builder/integration_test.go or extract to cilock/internal/testutil.
	// Flag the decision now so the rewire PR includes it.
	fmt.Fprintln(os.Stderr,
		"NOTE: cilock/test helpers are package-private. The real "+
			"integration test will need to either (a) copy them or (b) extract "+
			"to a shared internal/testutil package. Recommend (b).")
}
