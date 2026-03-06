// Package test contains integration compatibility tests between witness and cilock.
// All tests execute the binaries — no library calls are made.
package test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// dsse is the minimal DSSE envelope structure for parsing binary output.
type dsse struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"`
	Signatures  []signature `json:"signatures"`
}

type signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type intotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Subject       []subject       `json:"subject"`
	Predicate     json.RawMessage `json:"predicate"`
}

type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

type collectionPredicate struct {
	Name         string     `json:"name"`
	Attestations []attEntry `json:"attestations"`
}

type attEntry struct {
	Type        string          `json:"type"`
	Attestation json.RawMessage `json:"attestation"`
}

var (
	witnessBin string
	cilockBin  string
)

func TestMain(m *testing.M) {
	var err error
	witnessBin, err = exec.LookPath("witness")
	if err != nil {
		fmt.Println("SKIP: witness binary not found in PATH")
		os.Exit(0)
	}

	cilockBin = filepath.Join("..", "cilock")
	if _, err := os.Stat(cilockBin); os.IsNotExist(err) {
		fmt.Println("SKIP: cilock binary not found (run 'go build -o cilock ./cmd/cilock/' first)")
		os.Exit(0)
	}

	// Make cilockBin absolute
	cilockBin, _ = filepath.Abs(cilockBin)
	witnessBin, _ = filepath.Abs(witnessBin)

	os.Exit(m.Run())
}

// testEnv sets up keys and a git-initialized working directory.
type testEnv struct {
	dir        string
	workdir    string
	keyPath    string
	pubPath    string
	polKeyPath string
	polPubPath string
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	workdir := filepath.Join(dir, "workdir")
	mustMkdir(t, workdir)

	mustWrite(t, filepath.Join(workdir, "file1.txt"), "content1")
	mustWrite(t, filepath.Join(workdir, "file2.txt"), "content2")

	run(t, workdir, "git", "init", "-q")
	run(t, workdir, "git", "add", ".")
	run(t, workdir, "git", "commit", "-q", "-m", "init", "--no-gpg-sign")

	keyPath := filepath.Join(dir, "test.pem")
	pubPath := filepath.Join(dir, "test.pub")
	run(t, dir, "openssl", "genpkey", "-algorithm", "RSA", "-out", keyPath, "-pkeyopt", "rsa_keygen_bits:2048")
	run(t, dir, "openssl", "rsa", "-in", keyPath, "-pubout", "-out", pubPath)

	polKeyPath := filepath.Join(dir, "policy.pem")
	polPubPath := filepath.Join(dir, "policy.pub")
	run(t, dir, "openssl", "genpkey", "-algorithm", "RSA", "-out", polKeyPath, "-pkeyopt", "rsa_keygen_bits:2048")
	run(t, dir, "openssl", "rsa", "-in", polKeyPath, "-pubout", "-out", polPubPath)

	return &testEnv{dir: dir, workdir: workdir, keyPath: keyPath, pubPath: pubPath, polKeyPath: polKeyPath, polPubPath: polPubPath}
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command %s %v failed: %v\n%s", name, args, err, string(out))
	}
	return string(out)
}

func tryRun(t *testing.T, dir, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func parseEnvelope(t *testing.T, path string) (dsse, intotoStatement) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var env dsse
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("parse DSSE %s: %v", path, err)
	}
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("decode payload %s: %v", path, err)
	}
	var stmt intotoStatement
	if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
		t.Fatalf("parse statement %s: %v", path, err)
	}
	return env, stmt
}

func parseCollection(t *testing.T, stmt intotoStatement) collectionPredicate {
	t.Helper()
	var pred collectionPredicate
	if err := json.Unmarshal(stmt.Predicate, &pred); err != nil {
		t.Fatalf("parse collection: %v", err)
	}
	return pred
}

// ===================================================================
// Test: Flag Parity
// ===================================================================

func TestFlagParity(t *testing.T) {
	for _, cmd := range []string{"run", "verify", "sign"} {
		t.Run(cmd, func(t *testing.T) {
			wHelp := run(t, ".", witnessBin, cmd, "--help")
			cHelp := run(t, ".", cilockBin, cmd, "--help")
			wFlags := extractFlags(wHelp)
			cFlags := extractFlagSet(cHelp)

			var missing []string
			for _, f := range wFlags {
				if !cFlags[f] {
					missing = append(missing, f)
				}
			}
			if len(missing) > 0 {
				t.Errorf("cilock %s missing witness flags: %v", cmd, missing)
			}
		})
	}
}

func extractFlags(helpOutput string) []string {
	var flags []string
	for _, line := range strings.Split(helpOutput, "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, "--")
		if idx < 0 {
			continue
		}
		rest := line[idx+2:]
		end := strings.IndexAny(rest, " =")
		if end < 0 {
			end = len(rest)
		}
		flag := "--" + rest[:end]
		if flag != "--" && flag != "--help" {
			flags = append(flags, flag)
		}
	}
	return flags
}

func extractFlagSet(helpOutput string) map[string]bool {
	set := make(map[string]bool)
	for _, f := range extractFlags(helpOutput) {
		set[f] = true
	}
	return set
}

// ===================================================================
// Test: Attestor List Parity
// ===================================================================

func TestAttestorListParity(t *testing.T) {
	wOut := run(t, ".", witnessBin, "attestors", "list")
	cOut := run(t, ".", cilockBin, "attestors", "list")
	wNames := extractAttestorNames(wOut)
	cNameSet := make(map[string]bool)
	for _, n := range extractAttestorNames(cOut) {
		cNameSet[n] = true
	}
	for _, n := range wNames {
		if !cNameSet[n] {
			t.Errorf("witness attestor %q missing from cilock", n)
		}
	}
}

func extractAttestorNames(output string) []string {
	var names []string
	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, "│") {
			continue
		}
		parts := strings.Split(line, "│")
		if len(parts) < 3 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		if name == "" || name == "NAME" || strings.HasPrefix(name, "─") {
			continue
		}
		if idx := strings.Index(name, "("); idx > 0 {
			name = strings.TrimSpace(name[:idx])
		}
		names = append(names, name)
	}
	return names
}

// ===================================================================
// Test: Run Output Structure
// ===================================================================

func TestRunOutputStructure(t *testing.T) {
	env := newTestEnv(t)

	wOut := filepath.Join(env.dir, "w.json")
	cOut := filepath.Join(env.dir, "c.json")

	// Use a command that produces a file so the product attestor has something to record
	run(t, env.workdir, witnessBin, "run",
		"--step", "test-step",
		"--signer-file-key-path", env.keyPath,
		"-o", wOut, "--workingdir", env.workdir,
		"--attestations", "environment,git",
		"--", "sh", "-c", "echo build-output > output.txt")

	// Remove the output so cilock's product attestor also detects it as new
	os.Remove(filepath.Join(env.workdir, "output.txt"))

	run(t, env.workdir, cilockBin, "run",
		"--step", "test-step",
		"--signer-file-key-path", env.keyPath,
		"-o", cOut, "--workingdir", env.workdir,
		"--attestations", "environment,git",
		"--", "sh", "-c", "echo build-output > output.txt")

	wEnv, wStmt := parseEnvelope(t, wOut)
	cEnv, cStmt := parseEnvelope(t, cOut)

	// payloadType must be identical
	if wEnv.PayloadType != cEnv.PayloadType {
		t.Errorf("payloadType: witness=%q cilock=%q", wEnv.PayloadType, cEnv.PayloadType)
	}

	// in-toto _type must be identical
	if wStmt.Type != cStmt.Type {
		t.Errorf("_type: witness=%q cilock=%q", wStmt.Type, cStmt.Type)
	}

	// predicateType intentionally differs (witness.testifysec.com vs aflock.ai)
	t.Logf("predicateType: witness=%q cilock=%q (intentional difference)", wStmt.PredicateType, cStmt.PredicateType)

	// Build digest maps keyed by digest value for comparison.
	// Subject names intentionally differ (witness.dev vs aflock.ai prefixes),
	// but the digest VALUES for the same logical subject should be identical.
	wDigests := make(map[string]string) // digest_value → algo
	for _, sub := range wStmt.Subject {
		for algo, digest := range sub.Digest {
			wDigests[digest] = algo
		}
	}
	cDigests := make(map[string]string)
	for _, sub := range cStmt.Subject {
		for algo, digest := range sub.Digest {
			cDigests[digest] = algo
		}
	}

	// Every witness digest should appear in cilock's digests
	for digest, algo := range wDigests {
		if _, ok := cDigests[digest]; !ok {
			t.Errorf("witness subject digest %s:%s missing from cilock subjects", algo, digest[:16])
		}
	}

	// Same number of attestations
	wPred := parseCollection(t, wStmt)
	cPred := parseCollection(t, cStmt)
	if len(wPred.Attestations) != len(cPred.Attestations) {
		t.Errorf("attestation count: witness=%d cilock=%d", len(wPred.Attestations), len(cPred.Attestations))
	}

	// Step name must match
	if wPred.Name != cPred.Name {
		t.Errorf("step name: witness=%q cilock=%q", wPred.Name, cPred.Name)
	}
}

// ===================================================================
// Test: Sign Byte-for-Byte Payload
// ===================================================================

func TestSignPayloadIdentical(t *testing.T) {
	env := newTestEnv(t)
	input := filepath.Join(env.dir, "input.json")
	mustWrite(t, input, `{"test":"data"}`)

	wOut := filepath.Join(env.dir, "w_signed.json")
	cOut := filepath.Join(env.dir, "c_signed.json")

	run(t, env.dir, witnessBin, "sign",
		"--signer-file-key-path", env.keyPath,
		"--infile", input, "--outfile", wOut)

	run(t, env.dir, cilockBin, "sign",
		"--signer-file-key-path", env.keyPath,
		"--infile", input, "--outfile", cOut)

	wEnv, _ := parseEnvelope(t, wOut)
	cEnv, _ := parseEnvelope(t, cOut)

	// Payload MUST be byte-for-byte identical
	if wEnv.Payload != cEnv.Payload {
		t.Errorf("sign payload differs:\n  witness: %s\n  cilock:  %s", wEnv.Payload[:40], cEnv.Payload[:40])
	}

	// PayloadType MUST be identical
	if wEnv.PayloadType != cEnv.PayloadType {
		t.Errorf("sign payloadType: witness=%q cilock=%q", wEnv.PayloadType, cEnv.PayloadType)
	}
}

// ===================================================================
// Test: Mix-and-Match Verification
// ===================================================================

func TestMixAndMatchVerify(t *testing.T) {
	env := newTestEnv(t)

	// The command MUST produce a file so the product attestor creates subjects
	// that the verify command can match via --artifactfile.
	productCmd := []string{"sh", "-c", "echo build-output > output.txt"}
	artifact := filepath.Join(env.workdir, "output.txt")

	// Probe to get the key ID
	probeOut := filepath.Join(env.dir, "probe.json")
	run(t, env.workdir, witnessBin, "run",
		"--step", "probe",
		"--signer-file-key-path", env.keyPath,
		"-o", probeOut, "--workingdir", env.workdir,
		"--attestations", "environment,git",
		"--", productCmd[0], productCmd[1], productCmd[2])

	probeEnv, _ := parseEnvelope(t, probeOut)
	if len(probeEnv.Signatures) == 0 {
		t.Fatal("no signatures in probe")
	}
	keyID := probeEnv.Signatures[0].KeyID

	// Verify cilock produces the same key ID
	os.Remove(artifact) // remove so cilock also sees it as new product
	cilockProbe := filepath.Join(env.dir, "cilock_probe.json")
	run(t, env.workdir, cilockBin, "run",
		"--step", "probe",
		"--signer-file-key-path", env.keyPath,
		"-o", cilockProbe, "--workingdir", env.workdir,
		"--attestations", "environment,git",
		"--", productCmd[0], productCmd[1], productCmd[2])

	cilockProbeEnv, _ := parseEnvelope(t, cilockProbe)
	if len(cilockProbeEnv.Signatures) == 0 {
		t.Fatal("no signatures in cilock probe")
	}
	if cilockProbeEnv.Signatures[0].KeyID != keyID {
		t.Fatalf("key ID mismatch: witness=%s cilock=%s", keyID, cilockProbeEnv.Signatures[0].KeyID)
	}
	t.Logf("Shared key ID: %s", keyID)

	// Read public key and base64 encode it for the policy
	pubKeyBytes, err := os.ReadFile(env.pubPath)
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// Create policy with witness.dev type URIs
	witnessPolicyJSON := fmt.Sprintf(`{
		"expires": "2030-12-01T00:00:00Z",
		"steps": {
			"test-step": {
				"name": "test-step",
				"functionaries": [{"type": "publickey", "publickeyid": "%s"}],
				"attestations": [
					{"type": "https://witness.dev/attestations/environment/v0.1"},
					{"type": "https://witness.dev/attestations/git/v0.1"},
					{"type": "https://witness.dev/attestations/material/v0.1"},
					{"type": "https://witness.dev/attestations/product/v0.1"},
					{"type": "https://witness.dev/attestations/command-run/v0.1"}
				]
			}
		},
		"publickeys": {"%s": {"keyid": "%s", "key": "%s"}}
	}`, keyID, keyID, keyID, pubKeyB64)

	// Create policy with aflock.ai type URIs
	cilockPolicyJSON := fmt.Sprintf(`{
		"expires": "2030-12-01T00:00:00Z",
		"steps": {
			"test-step": {
				"name": "test-step",
				"functionaries": [{"type": "publickey", "publickeyid": "%s"}],
				"attestations": [
					{"type": "https://aflock.ai/attestations/environment/v0.1"},
					{"type": "https://aflock.ai/attestations/git/v0.1"},
					{"type": "https://aflock.ai/attestations/material/v0.1"},
					{"type": "https://aflock.ai/attestations/product/v0.1"},
					{"type": "https://aflock.ai/attestations/command-run/v0.1"}
				]
			}
		},
		"publickeys": {"%s": {"keyid": "%s", "key": "%s"}}
	}`, keyID, keyID, keyID, pubKeyB64)

	// Write and sign policies
	wPolFile := filepath.Join(env.dir, "w_policy.json")
	cPolFile := filepath.Join(env.dir, "c_policy.json")
	mustWrite(t, wPolFile, witnessPolicyJSON)
	mustWrite(t, cPolFile, cilockPolicyJSON)

	wPolSigned := filepath.Join(env.dir, "w_policy_signed.json")
	cPolSigned := filepath.Join(env.dir, "c_policy_signed.json")
	run(t, env.dir, witnessBin, "sign", "--signer-file-key-path", env.polKeyPath, "--infile", wPolFile, "--outfile", wPolSigned)
	run(t, env.dir, witnessBin, "sign", "--signer-file-key-path", env.polKeyPath, "--infile", cPolFile, "--outfile", cPolSigned)

	// Create attestations with both tools.
	// Each run must produce output.txt as a new file for the product attestor.
	wAtt := filepath.Join(env.dir, "w_att.json")
	cAtt := filepath.Join(env.dir, "c_att.json")

	os.Remove(artifact)
	run(t, env.workdir, witnessBin, "run",
		"--step", "test-step",
		"--signer-file-key-path", env.keyPath,
		"-o", wAtt, "--workingdir", env.workdir,
		"--attestations", "environment,git",
		"--", productCmd[0], productCmd[1], productCmd[2])

	os.Remove(artifact)
	run(t, env.workdir, cilockBin, "run",
		"--step", "test-step",
		"--signer-file-key-path", env.keyPath,
		"-o", cAtt, "--workingdir", env.workdir,
		"--attestations", "environment,git",
		"--", productCmd[0], productCmd[1], productCmd[2])

	// Mix-and-match verification matrix
	tests := []struct {
		name     string
		verifier string
		policy   string
		att      string
		wantPass bool
		note     string
	}{
		{
			name:     "witness-self-verify",
			verifier: witnessBin, policy: wPolSigned, att: wAtt,
			wantPass: true,
			note:     "witness verifying its own attestation with witness-type policy",
		},
		{
			name:     "cilock-self-verify",
			verifier: cilockBin, policy: cPolSigned, att: cAtt,
			wantPass: true,
			note:     "cilock verifying its own attestation with cilock-type policy",
		},
		{
			name:     "cilock-verifies-witness-att-with-witness-policy",
			verifier: cilockBin, policy: wPolSigned, att: wAtt,
			wantPass: true,
			note:     "cilock consuming witness attestation + witness-type policy (legacy alias resolution)",
		},
		{
			name:     "cilock-verifies-cilock-att-with-witness-policy",
			verifier: cilockBin, policy: wPolSigned, att: cAtt,
			wantPass: true,
			note:     "cilock attestation verified against witness-type policy (cross-type resolution)",
		},
		{
			name:     "witness-verifies-witness-att-with-cilock-policy",
			verifier: witnessBin, policy: cPolSigned, att: wAtt,
			wantPass: false,
			note:     "witness does NOT know about aflock.ai URIs (expected failure)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tryRun(t, env.dir, tt.verifier, "verify",
				"--policy", tt.policy,
				"--publickey", env.polPubPath,
				"--attestations", tt.att,
				"--artifactfile", artifact)

			passed := err == nil
			t.Logf("[%s] %s\n  passed=%v wantPass=%v\n  output: %s", tt.name, tt.note, passed, tt.wantPass, truncate(out, 500))

			if tt.wantPass && !passed {
				t.Errorf("expected pass but got failure: %v\n%s", err, out)
			}
			if !tt.wantPass && passed {
				t.Errorf("expected failure but got pass")
			}
		})
	}
}

// ===================================================================
// Test: Debug Signer (cilock extra feature)
// ===================================================================

func TestDebugSigner(t *testing.T) {
	env := newTestEnv(t)

	cOut := filepath.Join(env.dir, "debug.json")
	run(t, env.workdir, cilockBin, "run",
		"--step", "debug-test",
		"--signer-debug-enabled",
		"-o", cOut,
		"--workingdir", env.workdir,
		"--", "echo", "debug signer test")

	_, stmt := parseEnvelope(t, cOut)
	if stmt.Type != "https://in-toto.io/Statement/v0.1" {
		t.Errorf("unexpected _type: %q", stmt.Type)
	}
}

// ===================================================================
// Test: Error Behavior Parity
// ===================================================================

func TestErrorBehaviorParity(t *testing.T) {
	env := newTestEnv(t)

	tests := []struct {
		name string
		args []string
	}{
		{"run-no-step", []string{"run", "--signer-file-key-path", env.keyPath, "--", "echo", "test"}},
		{"run-no-signer", []string{"run", "--step", "test", "--", "echo", "test"}},
		{"run-bad-key", []string{"run", "--step", "test", "--signer-file-key-path", "/nonexistent", "--", "echo", "test"}},
		{"verify-no-policy", []string{"verify", "--publickey", env.pubPath, "--attestations", "/nonexistent"}},
		{"sign-no-input", []string{"sign", "--signer-file-key-path", env.keyPath, "--infile", "/nonexistent"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, wErr := tryRun(t, env.dir, witnessBin, tt.args...)
			_, cErr := tryRun(t, env.dir, cilockBin, tt.args...)

			wFailed := wErr != nil
			cFailed := cErr != nil

			if wFailed != cFailed {
				t.Errorf("error behavior differs: witness failed=%v cilock failed=%v", wFailed, cFailed)
			} else {
				t.Logf("both %s (witness=%v cilock=%v)", map[bool]string{true: "failed", false: "succeeded"}[wFailed], wErr, cErr)
			}
		})
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
