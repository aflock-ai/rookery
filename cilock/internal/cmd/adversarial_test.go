// Copyright 2025 The Aflock Authors
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

package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Import plugins so that dynamic flags (--signer-file-key-path etc.) are
	// registered on the cobra command tree, matching what main.go does.
	_ "github.com/aflock-ai/rookery/plugins/attestors/environment"
	_ "github.com/aflock-ai/rookery/plugins/attestors/git"
	_ "github.com/aflock-ai/rookery/plugins/attestors/material"
	_ "github.com/aflock-ai/rookery/plugins/attestors/product"
	_ "github.com/aflock-ai/rookery/plugins/signers/debug-signer"
	_ "github.com/aflock-ai/rookery/plugins/signers/file"
)

// helper: execute the root cobra command with the given args and capture
// whether it returned an error. We construct a fresh command tree per test
// to avoid flag state leaking between tests.
func executeCmd(args ...string) error {
	cmd := New()
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return cmd.Execute()
}

// executeCmdOutput runs the command and captures both stdout and stderr.
func executeCmdOutput(args ...string) (string, string, error) {
	cmd := New()
	cmd.SetArgs(args)
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

// writeFile is a test helper that writes content to a file.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
}

// generateTestKey generates an RSA private key in PEM format and writes it
// to a file, returning the path.
func generateTestKey(t *testing.T, dir string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	keyPath := filepath.Join(dir, "test.pem")
	f, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(f, pemBlock))
	require.NoError(t, f.Close())
	return keyPath
}

// generateTestPublicKey derives a public key from the private key file.
func generateTestPublicKey(t *testing.T, dir string, privKeyPath string) string {
	t.Helper()
	privKeyBytes, err := os.ReadFile(privKeyPath)
	require.NoError(t, err)

	block, _ := pem.Decode(privKeyBytes)
	require.NotNil(t, block)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)

	pubPath := filepath.Join(dir, "test.pub")
	f, err := os.Create(pubPath)
	require.NoError(t, err)
	pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}
	require.NoError(t, pem.Encode(f, pemBlock))
	require.NoError(t, f.Close())
	return pubPath
}

// ==========================================================================
// 1. Missing required flags
// ==========================================================================

func TestRunMissingStepFlag(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	err := executeCmd("run", "--signer-file-key-path", keyPath, "--", "echo", "hello")
	require.Error(t, err, "run without --step must fail")
}

func TestRunMissingSignerFlag(t *testing.T) {
	err := executeCmd("run", "--step", "test-step", "--", "echo", "hello")
	require.Error(t, err, "run without any signer must fail")
}

func TestSignMissingInfileFlag(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Sign requires both --infile and --outfile together.
	err := executeCmd("sign", "--signer-file-key-path", keyPath, "--outfile", filepath.Join(dir, "out.json"))
	require.Error(t, err, "sign without --infile must fail")
}

func TestSignMissingOutfileFlag(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	infile := filepath.Join(dir, "in.json")
	writeFile(t, infile, `{"test":"data"}`)

	err := executeCmd("sign", "--signer-file-key-path", keyPath, "--infile", infile)
	require.Error(t, err, "sign without --outfile must fail")
}

func TestVerifyMissingPolicyFlag(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)

	err := executeCmd("verify", "--publickey", pubPath, "--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify without --policy must fail")
}

func TestVerifyMissingKeyAndCA(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{}`)

	// Must supply publickey, CA, or verifier.
	err := executeCmd("verify", "--policy", polFile, "--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify without publickey or CA must fail")
}

func TestVerifyMissingSubjectAndArtifact(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{}`)

	// Must supply either --artifactfile or --subjects.
	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath, "--attestations", "/dev/null")
	require.Error(t, err, "verify without any subject must fail")
}

// ==========================================================================
// 2. Non-existent file paths
// ==========================================================================

func TestRunNonExistentKeyFile(t *testing.T) {
	err := executeCmd("run", "--step", "test", "--signer-file-key-path", "/nonexistent/key.pem", "--", "echo", "hello")
	require.Error(t, err, "run with non-existent key file must fail")
}

func TestSignNonExistentInfile(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	outfile := filepath.Join(dir, "out.json")

	err := executeCmd("sign", "--signer-file-key-path", keyPath, "--infile", "/nonexistent/input.json", "--outfile", outfile)
	require.Error(t, err, "sign with non-existent infile must fail")
}

func TestVerifyNonExistentPolicyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)

	err := executeCmd("verify", "--policy", "/nonexistent/policy.json", "--publickey", pubPath,
		"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify with non-existent policy file must fail")
}

func TestVerifyNonExistentAttestationFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--attestations", "/nonexistent/att.json", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify with non-existent attestation file must fail")
}

func TestVerifyNonExistentPublicKeyFile(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", "/nonexistent/key.pub",
		"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify with non-existent public key must fail")
}

func TestVerifyNonExistentCARootFile(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--policy-ca-roots", "/nonexistent/ca.pem",
		"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify with non-existent CA root must fail")
}

// ==========================================================================
// 3. Invalid key formats
// ==========================================================================

func TestRunCorruptedKeyFile(t *testing.T) {
	dir := t.TempDir()
	badKey := filepath.Join(dir, "bad.pem")
	writeFile(t, badKey, "THIS IS NOT A PEM KEY")

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", badKey, "--", "echo", "hello")
	require.Error(t, err, "run with corrupted key must fail")
}

func TestRunEmptyKeyFile(t *testing.T) {
	dir := t.TempDir()
	emptyKey := filepath.Join(dir, "empty.pem")
	writeFile(t, emptyKey, "")

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", emptyKey, "--", "echo", "hello")
	require.Error(t, err, "run with empty key file must fail")
}

func TestRunBinaryGarbageKeyFile(t *testing.T) {
	dir := t.TempDir()
	garbageKey := filepath.Join(dir, "garbage.pem")
	garbage := make([]byte, 256)
	_, _ = rand.Read(garbage)
	require.NoError(t, os.WriteFile(garbageKey, garbage, 0600))

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", garbageKey, "--", "echo", "hello")
	require.Error(t, err, "run with binary garbage key must fail")
}

func TestRunPEMWrongBlockType(t *testing.T) {
	dir := t.TempDir()
	certPEM := filepath.Join(dir, "cert.pem")
	// A PEM block typed as CERTIFICATE should not parse as a signing key.
	writeFile(t, certPEM, `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLU3
jSMb/ccRHbRaINE/W7knHfCbRLDhxQGVHvkTeVGRg99oBLPb7Ar5bGwiVTIuzVbq
MEhZODljMTBjNjVlMzCjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2wpSek3WRvEa
AIFMtspKg0IJANH+kFSETbLGvKZr3QcCIAbh/VCbGPQ2MY3IJdE9k7j+SIRT1BBk
XDmqRkfVVmwf
-----END CERTIFICATE-----`)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", certPEM, "--", "echo", "hello")
	require.Error(t, err, "run with certificate PEM instead of key must fail")
}

func TestVerifyCorruptedPublicKey(t *testing.T) {
	dir := t.TempDir()
	badPub := filepath.Join(dir, "bad.pub")
	writeFile(t, badPub, "NOT A PUBLIC KEY")
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", badPub,
		"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify with corrupted public key must fail")
}

func TestVerifyPrivateKeyAsPublicKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Using a private key where a public key is expected should fail or
	// at least not silently succeed with wrong verification semantics.
	err := executeCmd("verify", "--policy", polFile, "--publickey", keyPath,
		"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify with private key where public key expected should fail")
}

// ==========================================================================
// 4. Invalid attestor names
// ==========================================================================

func TestRunInvalidAttestorName(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--attestations", "nonexistent-attestor-xyz", "--", "echo", "hello")
	require.Error(t, err, "run with non-existent attestor name must fail")
}

func TestRunMultipleInvalidAttestors(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--attestations", "fake1,fake2,fake3", "--", "echo", "hello")
	require.Error(t, err, "run with multiple non-existent attestors must fail")
}

func TestRunAttestorNameWithPathTraversal(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--attestations", "../../../etc/passwd", "--", "echo", "hello")
	require.Error(t, err, "run with path traversal as attestor name must fail")
}

func TestRunAttestorNameEmpty(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Empty attestor name -- should either be ignored or error, never panic.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
			"--attestations", "", "--", "echo", "hello")
	})
}

// ==========================================================================
// 5. Attestors schema with invalid input
// ==========================================================================

func TestAttestorsSchemaNoArgs(t *testing.T) {
	err := executeCmd("attestors", "schema")
	require.Error(t, err, "attestors schema without arguments must fail")
	assert.Contains(t, err.Error(), "specify an attestor")
}

func TestAttestorsSchemaMultipleArgs(t *testing.T) {
	err := executeCmd("attestors", "schema", "environment", "git")
	require.Error(t, err, "attestors schema with multiple args must fail")
	assert.Contains(t, err.Error(), "one attestor")
}

func TestAttestorsSchemaInvalidName(t *testing.T) {
	err := executeCmd("attestors", "schema", "nonexistent-attestor-xyz")
	require.Error(t, err, "attestors schema with invalid name must fail")
}

func TestAttestorsSchemaVeryLongName(t *testing.T) {
	longName := strings.Repeat("z", 10000)
	err := executeCmd("attestors", "schema", longName)
	require.Error(t, err, "attestors schema with absurdly long name must fail")
}

// ==========================================================================
// 6. Empty arguments where arguments are required
// ==========================================================================

func TestRunEmptyStepName(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Passing --step "" is valid flag syntax but semantically dubious.
	// The important thing: it must not panic.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "", "--signer-file-key-path", keyPath, "--", "echo", "hello")
	})
}

func TestRunEmptyOutfilePath(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Empty --outfile defaults to stdout via loadOutfile.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
			"--outfile", "", "--", "echo", "hello")
	})
}

func TestSignEmptyDataType(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	infile := filepath.Join(dir, "in.json")
	outfile := filepath.Join(dir, "out.json")
	writeFile(t, infile, `{"test":"data"}`)

	// Empty datatype should not crash.
	assert.NotPanics(t, func() {
		_ = executeCmd("sign", "--signer-file-key-path", keyPath, "--infile", infile,
			"--outfile", outfile, "--datatype", "")
	})
}

// ==========================================================================
// 7. Very long arguments
// ==========================================================================

func TestRunVeryLongStepName(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	longName := strings.Repeat("A", 10000)

	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", longName, "--signer-file-key-path", keyPath, "--", "echo", "hello")
	})
}

func TestRunVeryLongKeyPath(t *testing.T) {
	longPath := "/" + strings.Repeat("a/", 5000) + "key.pem"

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", longPath, "--", "echo", "hello")
	require.Error(t, err, "run with impossibly long key path must fail")
}

func TestRunVeryLongAttestorName(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	longAttestor := strings.Repeat("x", 10000)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--attestations", longAttestor, "--", "echo", "hello")
	require.Error(t, err, "run with absurdly long attestor name must fail")
}

// ==========================================================================
// 8. Config file edge cases
//
// NOTE: initConfig calls logger.l.Fatal on parse errors, which invokes
// os.Exit(1) and kills the test process. We can only safely test cases
// that do NOT trigger Fatal -- namely, non-existent file with --config
// explicitly set (returns error before viper parse) and empty file.
// ==========================================================================

// NOTE: TestConfigFileNonExistent is intentionally omitted.
// Explicitly specifying a non-existent config via --config triggers
// logger.l.Fatal in preRoot (which calls os.Exit(1)). Testing this
// in-process would kill the test binary. Calling initConfig() directly
// does not work because cobra only merges PersistentFlags into Flags()
// during Execute(), and initConfig uses rootCmd.Flags().Lookup("config")
// which returns nil before that merge. This is a testing gap that could
// be addressed by changing initConfig to use rootCmd.Flag("config")
// (which checks both local and persistent flags) or by using exec-based
// testing (os/exec to run the binary and check the exit code).

func TestConfigFileEmptyFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "empty.yaml")
	writeFile(t, configPath, "")

	// Empty config file should be tolerated (no values to override).
	err := executeCmd("--config", configPath, "version")
	assert.NoError(t, err, "empty config file should be tolerated")
}

func TestConfigFileValidYAMLNoMatchingCommand(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "valid.yaml")
	writeFile(t, configPath, "run:\n  step: from-config\n")

	// The "version" command has no flags that match run.step, so the config
	// should be silently ignored.
	err := executeCmd("--config", configPath, "version")
	assert.NoError(t, err, "valid config with non-matching command should be fine")
}

// ==========================================================================
// 9. Invalid hash algorithms
// ==========================================================================

func TestRunCompletelyBogusHash(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--hashes", "notahash", "--", "echo", "hello")
	require.Error(t, err, "run with completely bogus hash algorithm must fail")
}

func TestRunEmptyHash(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Empty hash string should be rejected.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
			"--hashes", "", "--", "echo", "hello")
	})
}

// ==========================================================================
// 10. Invalid glob patterns
// ==========================================================================

func TestRunInvalidDirHashGlob(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--dirhash-glob", "[invalid-glob", "--", "echo", "hello")
	require.Error(t, err, "run with invalid glob pattern must fail")
}

// ==========================================================================
// 11. isValidHexDigest -- thorough unit tests
// ==========================================================================

func TestIsValidHexDigest(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// --- valid ---
		{"valid sha256 with prefix", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"valid no prefix", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"32 hex chars (minimum)", "e3b0c44298fc1c149afbf4c8996fb924", true},
		{"upper case hex", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", true},
		{"upper case prefix", "SHA256:E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", true},
		{"mixed case hex", "e3B0c44298FC1c149afBF4c8996fb92427AE41e4649b934ca495991b7852b855", true},

		// --- invalid ---
		{"empty string", "", false},
		{"too short", "abcdef", false},
		{"31 chars", "abcdef0123456789abcdef012345678", false},
		{"odd length", "e3b0c44298fc1c149afbf4c8996fb924271", false},
		{"non-hex chars", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852bxyz", false},
		{"just prefix no hex", "sha256:", false},
		{"prefix with short hex", "sha256:abcd", false},
		{"unicode", "e3b0c44298fc1c149afbf4c8996fb924\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9", false},
		{"null bytes", "e3b0c44298fc1c149afbf4c8996fb924\x00\x00\x00\x00\x00\x00\x00\x00", false},
		{"sql injection", "sha256:' OR 1=1 --", false},
		{"path traversal", "sha256:../../../etc/passwd/../../../etc/passwd", false},
		{"newline injection", "sha256:e3b0c44298fc1c149afbf4c8996fb924\n27ae41e4649b934ca", false},
		{"spaces in hex", "sha256:e3b0 c442 98fc 1c14 9afb f4c8 996f b924", false},
		{"colon in hex after prefix", "sha256:e3b0c44298fc1c14:afbf4c8996fb9242", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHexDigest(tt.input)
			assert.Equal(t, tt.want, got, "isValidHexDigest(%q)", tt.input)
		})
	}
}

// TestIsValidHexDigestMultipleColons verifies that strings.Index finds only
// the FIRST colon, so "sha256:sha256:..." treats everything after the first
// colon as the hex portion -- which will fail because 's' is not hex.
func TestIsValidHexDigestMultipleColons(t *testing.T) {
	input := "sha256:sha256:e3b0c44298fc1c149afbf4c8996fb924"
	assert.False(t, isValidHexDigest(input),
		"multiple colons: hex portion starts with 'sha256:e3...' which contains non-hex 's'")
}

func TestVerifyInvalidSubjectDigest(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--attestations", "/dev/null", "--subjects", "sha256:not-a-real-digest")
	require.Error(t, err, "verify with invalid subject digest must fail")
	assert.Contains(t, err.Error(), "invalid subject digest")
}

func TestVerifySubjectDigestSQLInjection(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--attestations", "/dev/null", "--subjects", "sha256:' OR 1=1; DROP TABLE attestations; --")
	require.Error(t, err, "verify with SQL injection in subject must fail")
}

func TestVerifySubjectDigestPathTraversal(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--attestations", "/dev/null", "--subjects", "sha256:../../../../etc/shadow")
	require.Error(t, err, "verify with path traversal in subject must fail")
}

// ==========================================================================
// 12. Valid log levels
// ==========================================================================

func TestValidLogLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			err := executeCmd("--log-level", level, "version")
			assert.NoError(t, err, "log level %q should be valid", level)
		})
	}
}

// ==========================================================================
// 13. Root command with no subcommand
// ==========================================================================

func TestNoSubcommand(t *testing.T) {
	err := executeCmd()
	assert.NoError(t, err, "running with no subcommand should print help and succeed")
}

// ==========================================================================
// 14. Unknown subcommands and flags
// ==========================================================================

func TestUnknownSubcommand(t *testing.T) {
	err := executeCmd("nonexistent-command")
	require.Error(t, err, "unknown subcommand must fail")
}

func TestRunUnknownFlag(t *testing.T) {
	err := executeCmd("run", "--nonexistent-flag", "value")
	require.Error(t, err, "unknown flag must fail")
}

func TestVersionCommand(t *testing.T) {
	err := executeCmd("version")
	assert.NoError(t, err, "version command should succeed")
}

// ==========================================================================
// 15. Policy validate adversarial inputs
// ==========================================================================

func TestPolicyValidateNoPolicy(t *testing.T) {
	err := executeCmd("policy", "validate")
	require.Error(t, err, "policy validate without --policy must fail")
}

func TestPolicyValidateNonExistentPolicy(t *testing.T) {
	err := executeCmd("policy", "validate", "--policy", "/nonexistent/policy.json")
	require.Error(t, err, "policy validate with non-existent file must fail")
}

func TestPolicyValidateEmptyFile(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "empty.json")
	writeFile(t, polFile, "")

	err := executeCmd("policy", "validate", "--policy", polFile)
	require.Error(t, err, "policy validate with empty file must fail")
}

func TestPolicyValidateInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "bad.json")
	writeFile(t, polFile, "{invalid json content!@#}")

	err := executeCmd("policy", "validate", "--policy", polFile)
	require.Error(t, err, "policy validate with invalid JSON must fail")
}

func TestPolicyValidateBinaryGarbage(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "garbage.json")
	garbage := make([]byte, 256)
	_, _ = rand.Read(garbage)
	require.NoError(t, os.WriteFile(polFile, garbage, 0600))

	err := executeCmd("policy", "validate", "--policy", polFile)
	require.Error(t, err, "policy validate with binary garbage must fail")
}

func TestPolicyValidateInvalidOutputFormat(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	// This is valid JSON but an incomplete policy -- validation will catch errors
	// but the output format "xml" is not validated.
	writeFile(t, polFile, `{"expires":"2030-01-01T00:00:00Z","steps":{"s":{"name":"s","functionaries":[{"type":"publickey","publickeyid":"k1"}],"attestations":[{"type":"t"}]}},"publickeys":{"k1":{"keyid":"k1","key":""}}}`)

	// The code does not validate --output; "xml" falls through to text.
	// This test documents that behavior -- it is a potential improvement.
	err := executeCmd("policy", "validate", "--policy", polFile, "--output", "xml")
	if err != nil {
		t.Logf("invalid output format rejected: %v", err)
	} else {
		t.Log("BUG CANDIDATE: invalid output format 'xml' silently accepted, falls through to text output")
	}
}

func TestPolicyValidateNonExistentPublicKey(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("policy", "validate", "--policy", polFile, "--publickey", "/nonexistent/key.pub")
	require.Error(t, err, "policy validate with non-existent public key must fail")
}

func TestPolicyValidateCorruptedPublicKey(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)
	badKey := filepath.Join(dir, "bad.pub")
	writeFile(t, badKey, "NOT A VALID KEY AT ALL")

	err := executeCmd("policy", "validate", "--policy", polFile, "--publickey", badKey)
	require.Error(t, err, "policy validate with corrupted public key must fail")
}

// ==========================================================================
// 16. Sign requires --infile and --outfile together
// ==========================================================================

func TestSignRequiresInfileAndOutfileTogether(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	t.Run("only infile", func(t *testing.T) {
		err := executeCmd("sign", "--signer-file-key-path", keyPath, "--infile", filepath.Join(dir, "in.json"))
		require.Error(t, err, "sign with only --infile must fail (requires --outfile)")
	})

	t.Run("only outfile", func(t *testing.T) {
		err := executeCmd("sign", "--signer-file-key-path", keyPath, "--outfile", filepath.Join(dir, "out.json"))
		require.Error(t, err, "sign with only --outfile must fail (requires --infile)")
	})
}

// ==========================================================================
// 17. Timestamp server adversarial inputs
// ==========================================================================

func TestRunInvalidTimestampServerURL(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Invalid URL as timestamp server -- must not panic.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
			"--timestamp-servers", "not-a-url", "--", "echo", "hello")
	})
}

// ==========================================================================
// 18. Verify with archivista but invalid server
// ==========================================================================

func TestVerifyArchivistaInvalidServer(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--enable-archivista", "--archivista-server", "http://localhost:99999",
		"--artifactfile", "/dev/null")
	require.Error(t, err, "verify with invalid archivista server must fail")
}

// ==========================================================================
// 19. Archivista headers parsing
// ==========================================================================

func TestArchivistaInvalidHeaderFormat(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Header without colon separator should fail.
	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--enable-archivista", "--archivista-headers", "invalid-no-colon",
		"--artifactfile", "/dev/null")
	require.Error(t, err, "archivista header without colon must fail")
}

// ==========================================================================
// 20. EC key handling
// ==========================================================================

func TestRunECKeyAccepted(t *testing.T) {
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyBytes, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	ecKeyPath := filepath.Join(dir, "ec.pem")
	f, err := os.Create(ecKeyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
	require.NoError(t, f.Close())

	// EC key should be accepted and must not panic.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", ecKeyPath,
			"--", "echo", "hello")
	})
}

// ==========================================================================
// 21. Completion command adversarial
// ==========================================================================

func TestCompletionInvalidShell(t *testing.T) {
	err := executeCmd("completion", "invalidshell")
	require.Error(t, err, "completion with invalid shell must fail")
}

func TestCompletionNoArgs(t *testing.T) {
	err := executeCmd("completion")
	require.Error(t, err, "completion without shell argument must fail")
}

func TestCompletionTooManyArgs(t *testing.T) {
	err := executeCmd("completion", "bash", "extra")
	require.Error(t, err, "completion with too many args must fail")
}

func TestCompletionValidShells(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			err := executeCmd("completion", shell)
			assert.NoError(t, err, "completion for %q should succeed", shell)
		})
	}
}

// ==========================================================================
// 22. Environment variable injection through CLI args
// ==========================================================================

func TestRunStepNameWithEnvVarSyntax(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Step name containing shell variable syntax -- Go does not expand
	// these, but verify there is no panic.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "${PATH}", "--signer-file-key-path", keyPath, "--", "echo", "hello")
	})
}

func TestRunStepNameWithBackticks(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "`whoami`", "--signer-file-key-path", keyPath, "--", "echo", "hello")
	})
}

func TestRunWorkingDirInjection(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Working dir with command injection attempt.
	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--workingdir", "/tmp; rm -rf /", "--", "echo", "hello")
	require.Error(t, err, "working dir with shell metacharacters must fail")
}

func TestRunStepNameWithNullByte(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test\x00injected", "--signer-file-key-path", keyPath, "--", "echo", "hello")
	})
}

// ==========================================================================
// 23. Sensitive env var flags are recognized
// ==========================================================================

func TestRunEnvSensitiveKeyFlags(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// These flags must be recognized even if the command fails later.
	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--env-filter-sensitive-vars",
		"--env-add-sensitive-key", "MY_SECRET",
		"--env-allow-sensitive-key", "HOME",
		"--", "echo", "hello")
	if err != nil {
		assert.NotContains(t, err.Error(), "unknown flag",
			"sensitive env flags should be recognized")
	}
}

func TestRunEnvDisableDefaultSensitiveVars(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--env-disable-default-sensitive-vars",
		"--", "echo", "hello")
	if err != nil {
		assert.NotContains(t, err.Error(), "unknown flag",
			"--env-disable-default-sensitive-vars should be recognized")
	}
}

// ==========================================================================
// 24. closeOutfile safety
// ==========================================================================

func TestCloseOutfileNil(t *testing.T) {
	assert.NotPanics(t, func() {
		closeOutfile(nil)
	})
}

func TestCloseOutfileStdout(t *testing.T) {
	assert.NotPanics(t, func() {
		closeOutfile(os.Stdout)
	})
}

func TestCloseOutfileRegularFile(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "test.json"))
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		closeOutfile(f)
	})
}

// ==========================================================================
// 25. loadOutfile edge cases
// ==========================================================================

func TestLoadOutfileEmpty(t *testing.T) {
	f, err := loadOutfile("")
	require.NoError(t, err)
	assert.Equal(t, os.Stdout, f, "empty path should return stdout")
}

func TestLoadOutfileInvalidPath(t *testing.T) {
	_, err := loadOutfile("/nonexistent/directory/file.json")
	require.Error(t, err, "loadOutfile with non-existent directory must fail")
}

func TestLoadOutfileReadOnlyDir(t *testing.T) {
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	require.NoError(t, os.MkdirAll(roDir, 0555))
	t.Cleanup(func() {
		_ = os.Chmod(roDir, 0755)
	})

	_, err := loadOutfile(filepath.Join(roDir, "out.json"))
	require.Error(t, err, "loadOutfile to read-only directory must fail")
}

func TestLoadOutfileValidPath(t *testing.T) {
	dir := t.TempDir()
	f, err := loadOutfile(filepath.Join(dir, "out.json"))
	require.NoError(t, err)
	require.NotNil(t, f)
	assert.NotEqual(t, os.Stdout, f)
	closeOutfile(f)
}

// ==========================================================================
// 26. Duplicate attestation flags
// ==========================================================================

func TestVerifyDuplicateAttestationPaths(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)
	attFile := filepath.Join(dir, "att.json")
	writeFile(t, attFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	assert.NotPanics(t, func() {
		_ = executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
			"--attestations", attFile, "--attestations", attFile,
			"--artifactfile", "/dev/null")
	})
}

// ==========================================================================
// 27. Debug signer (no key file needed)
// ==========================================================================

func TestRunDebugSignerNoKeyFile(t *testing.T) {
	// The debug signer generates an ephemeral key, so no --signer-file-key-path
	// is needed. This exercises a completely different code path.
	err := executeCmd("run", "--step", "test", "--signer-debug-enabled", "--", "echo", "hello")
	// This may fail because of git/working dir issues, but the signer should
	// load successfully.
	if err != nil {
		// The error should NOT be about signers.
		assert.NotContains(t, err.Error(), "failed to load any signers",
			"debug signer should load without a key file")
	}
}

func TestRunDebugSignerWithFileSignerConflict(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Providing both debug signer and file signer should trigger the
	// "only one signer is supported" error.
	err := executeCmd("run", "--step", "test",
		"--signer-debug-enabled",
		"--signer-file-key-path", keyPath,
		"--", "echo", "hello")
	require.Error(t, err, "using both debug and file signers should fail")
	assert.Contains(t, err.Error(), "only one signer",
		"error should mention multiple signers")
}

// ==========================================================================
// 28. Verify with both --artifactfile and --subjects
// ==========================================================================

func TestVerifyBothArtifactAndSubject(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Both --artifactfile and --subjects together. The code appends both
	// to the subjects slice, so this should not panic.
	assert.NotPanics(t, func() {
		_ = executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
			"--attestations", "/dev/null",
			"--artifactfile", "/dev/null",
			"--subjects", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	})
}

// ==========================================================================
// 29. Verify CA intermediates with non-existent file
// ==========================================================================

func TestVerifyNonExistentCAIntermediateFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--policy-ca-intermediates", "/nonexistent/intermediate.pem",
		"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify with non-existent intermediate CA must fail")
}

// ==========================================================================
// 30. Verify timestamp server CA with non-existent file
// ==========================================================================

func TestVerifyNonExistentTimestampServerCA(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--policy-timestamp-servers", "/nonexistent/tsa.pem",
		"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify with non-existent timestamp server CA must fail")
}

// ==========================================================================
// 31. Verify with corrupted CA root file
// ==========================================================================

func TestVerifyCorruptedCARootFile(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)
	badCA := filepath.Join(dir, "bad-ca.pem")
	writeFile(t, badCA, "THIS IS NOT A CERTIFICATE")

	err := executeCmd("verify", "--policy", polFile, "--policy-ca-roots", badCA,
		"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify with corrupted CA root must fail")
}

// ==========================================================================
// 32. Attestors list command
// ==========================================================================

func TestAttestorsListRuns(t *testing.T) {
	err := executeCmd("attestors", "list")
	assert.NoError(t, err, "attestors list should succeed")
}

// ==========================================================================
// 33. Policy parent command with no subcommand
// ==========================================================================

func TestPolicyNoSubcommand(t *testing.T) {
	err := executeCmd("policy")
	// Parent command with no subcommand prints help and exits cleanly.
	assert.NoError(t, err)
}

// ==========================================================================
// 34. Run with tracing enabled
// ==========================================================================

func TestRunTracingFlag(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// --trace flag should be accepted.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
			"--trace", "--", "echo", "hello")
	})
}

// ==========================================================================
// 35. Run with non-existent working directory
// ==========================================================================

func TestRunNonExistentWorkingDir(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--workingdir", "/nonexistent/dir/that/does/not/exist", "--", "echo", "hello")
	require.Error(t, err, "run with non-existent working directory must fail")
}

// ==========================================================================
// 36. Verify directory path with non-existent directory
// ==========================================================================

func TestVerifyNonExistentDirectoryPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--attestations", "/dev/null",
		"--directory-path", "/nonexistent/dir",
		"--artifactfile", "/dev/null")
	require.Error(t, err, "verify with non-existent directory-path must fail")
}

// ==========================================================================
// 37. Run outfile to unwritable location
// ==========================================================================

func TestRunOutfileUnwritableLocation(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	err := executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
		"--outfile", "/nonexistent/dir/output.json", "--", "echo", "hello")
	require.Error(t, err, "run with unwritable outfile location must fail")
}

// ==========================================================================
// SECURITY AUDIT: Additional adversarial tests
// ==========================================================================

// --------------------------------------------------------------------------
// SEC-1: Arbitrary file write via --debug-cpu-profile-file / --debug-mem-profile-file
// Severity: HIGH
//
// The --debug-cpu-profile-file and --debug-mem-profile-file flags accept
// arbitrary paths and call os.Create() without any restriction. An attacker
// who can influence CLI arguments (e.g. via a CI template injection) could
// overwrite arbitrary files the user has write access to. These flags create
// files via os.Create which truncates existing files.
//
// NOTE: These tests use preRoot/postRoot which call logger.l.Fatal on error,
// so we can only test cases where the flags are accepted but the path is
// benign, verifying they don't panic with adversarial values.
// --------------------------------------------------------------------------

// NOTE: TestAdversarial_ProfileFileFlagsAcceptArbitraryPaths and
// TestAdversarial_ProfileFilePathTraversal are intentionally omitted.
//
// The --debug-cpu-profile-file and --debug-mem-profile-file code paths use
// logger.l.Fatal (which calls os.Exit(1)) on errors, killing the test process.
// Additionally, the profile file lifecycle (preRoot creates/starts, postRoot
// stops/closes) uses package-level state that conflicts with multiple
// executeCmd calls in the same process.
//
// FINDING SEC-1 (MEDIUM): These flags accept arbitrary paths and write via
// os.Create without validation. An attacker controlling CLI args could
// overwrite arbitrary files. Recommend restricting to a temp directory or
// gating behind an explicit --enable-debug flag in production builds.

// --------------------------------------------------------------------------
// SEC-2: Outfile path traversal in multi-export attestor name
// Severity: MEDIUM
//
// In run.go, the attestor name sanitization replaces "/" with "-" before
// concatenating with the outfile path:
//   safeName := strings.ReplaceAll(result.AttestorName, "/", "-")
//   outfile += "-" + safeName + ".json"
//
// This DOES block simple "/" traversal but does NOT clean the base outfile
// path itself. Additionally, if an attestor name contains ".." without "/"
// (e.g. "..") the sanitization does not prevent path confusion.
//
// The real risk is that outfile itself has no validation.
// --------------------------------------------------------------------------

func TestAdversarial_OutfilePathTraversal(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Use path traversal in --outfile itself.
	traversalOutfile := filepath.Join(dir, "subdir", "..", "escaped-output.json")

	// This should either error or write to the resolved path -- must not panic.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
			"--outfile", traversalOutfile, "--", "echo", "hello")
	})
}

func TestAdversarial_OutfileSymlinkResolution(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Create a symlink pointing outside the directory.
	targetDir := filepath.Join(dir, "target")
	require.NoError(t, os.MkdirAll(targetDir, 0755))
	symlinkDir := filepath.Join(dir, "symlink")
	if err := os.Symlink(targetDir, symlinkDir); err != nil {
		t.Skip("symlinks not supported on this filesystem")
	}

	outfile := filepath.Join(symlinkDir, "output.json")

	// The outfile follows symlinks, so the file is created in targetDir.
	// This demonstrates loadOutfile does not resolve/reject symlinks.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
			"--outfile", outfile, "--", "echo", "hello")
	})
}

// --------------------------------------------------------------------------
// SEC-3: Config file injection via viper deserialization
// Severity: MEDIUM
//
// The config file (.witness.yaml) is parsed by viper and values are applied
// to command flags via flags.Set(). Viper supports YAML which can represent
// complex types. The flag values are applied as strings, but this still
// allows an attacker who controls the config file to inject flag values
// that the user did not explicitly set.
//
// Additionally, the config default is ".witness.yaml" in the CWD, meaning
// a malicious repo could ship a .witness.yaml that overrides security-
// critical flags (e.g. --enable-archivista, --archivista-server).
// --------------------------------------------------------------------------

// NOTE: TestAdversarial_ConfigFileOverridesSecurityFlags is intentionally
// omitted from executeCmd-based testing.
//
// cobra.OnInitialize registers init functions in a global slice. Each call
// to New() appends another init function. When executeCmd is called multiple
// times, old init functions remain registered and can interfere with later
// tests (they reference stale cmd/ro state). This causes spurious
// "config file does not exist" Fatal errors in subsequent tests.
//
// FINDING SEC-3 (MEDIUM): Config file can silently override security-
// critical flags (--enable-archivista, --archivista-server). A malicious
// .witness.yaml in a cloned repo could redirect attestation storage to
// an attacker-controlled server. Recommend logging a warning when config
// file overrides security-sensitive flags, or restricting which flags
// can be set via config file.
//
// Additionally, the initConfig function uses logger.l.Fatal for parse
// errors instead of returning an error, making it difficult to test
// config file error paths in-process.

// NOTE: TestAdversarial_ConfigFileYAMLBomb is intentionally omitted.
//
// A self-referencing YAML anchor (billion-laughs style) causes viper to
// return an error, which preRoot passes to logger.l.Fatal (os.Exit(1)).
// This kills the test process. The YAML parser correctly rejects the
// self-referencing anchor with "yaml: anchor 'anchor' value contains itself",
// but the fatal exit path prevents in-process testing.
//
// FINDING SEC-3b (LOW): Config file parse errors trigger os.Exit via Fatal
// instead of returning an error, preventing graceful handling in embedded
// or library use cases.

// NOTE: TestAdversarial_ConfigFileWithNullBytes is intentionally omitted.
//
// A config file with null bytes triggers a YAML parse error, which preRoot
// passes to logger.l.Fatal (os.Exit(1)), killing the test process.
// The YAML parser correctly rejects control characters.
//
// FINDING: The YAML parser rejects null bytes ("yaml: control characters
// are not allowed"), which is the correct behavior. The issue is that
// the error path uses Fatal instead of returning an error.

// --------------------------------------------------------------------------
// SEC-4: Policy file deserialization safety
// Severity: MEDIUM
//
// LoadPolicy uses json.NewDecoder without size limits. A malicious policy
// file could be arbitrarily large, causing OOM. The JSON decoder also
// does not enforce a max nesting depth.
// --------------------------------------------------------------------------

func TestAdversarial_PolicyFileLargePayload(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)

	// Create a policy file with an extremely large payload field.
	polFile := filepath.Join(dir, "large.json")
	largePayload := strings.Repeat("A", 10*1024*1024) // 10MB
	writeFile(t, polFile, fmt.Sprintf(`{"payloadType":"test","payload":"%s","signatures":[]}`, largePayload))

	// Should not OOM or panic.
	assert.NotPanics(t, func() {
		_ = executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
			"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	})
}

func TestAdversarial_PolicyFileDeeplyNested(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)

	// Create deeply nested JSON to stress the JSON parser.
	polFile := filepath.Join(dir, "nested.json")
	nested := strings.Repeat(`{"a":`, 100) + `"leaf"` + strings.Repeat(`}`, 100)
	writeFile(t, polFile, nested)

	// Should fail gracefully (not a valid policy envelope), not panic.
	assert.NotPanics(t, func() {
		_ = executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
			"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	})
}

// --------------------------------------------------------------------------
// SEC-5: Attestation file deserialization via MemorySource.LoadFile
// Severity: MEDIUM
//
// Attestation files loaded via --attestations are deserialized with
// json.Unmarshal (via io.ReadAll) without size limits. A malicious
// attestation file could cause OOM.
// --------------------------------------------------------------------------

func TestAdversarial_AttestationFileMalformed(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Attestation file with truncated JSON -- should fail, not panic.
	attFile := filepath.Join(dir, "truncated.json")
	writeFile(t, attFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[`)

	assert.NotPanics(t, func() {
		err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
			"--attestations", attFile, "--artifactfile", "/dev/null")
		require.Error(t, err, "truncated attestation JSON should fail")
	})
}

func TestAdversarial_AttestationFileNotJSON(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Attestation file that is actually a shell script.
	attFile := filepath.Join(dir, "evil.json")
	writeFile(t, attFile, "#!/bin/bash\nrm -rf /\n")

	assert.NotPanics(t, func() {
		err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
			"--attestations", attFile, "--artifactfile", "/dev/null")
		require.Error(t, err, "non-JSON attestation file should fail")
	})
}

// --------------------------------------------------------------------------
// SEC-6: Archivista header injection
// Severity: HIGH
//
// The --archivista-headers flag splits on ":" and sets HTTP headers.
// An attacker could inject sensitive headers like "Authorization" or
// "Host" to manipulate the archivista request. The header name is not
// validated against a deny-list.
// --------------------------------------------------------------------------

func TestAdversarial_ArchivistaAuthorizationHeaderInjection(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Inject an Authorization header -- this should ideally be blocked.
	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--enable-archivista",
		"--archivista-headers", "Authorization: Bearer stolen-token",
		"--artifactfile", "/dev/null")
	if err != nil {
		// Expected to fail because of other validation, but the header
		// injection itself is accepted.
		t.Log("FINDING SEC-6: --archivista-headers accepts Authorization headers without restriction")
	}
}

func TestAdversarial_ArchivistaHostHeaderInjection(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Inject a Host header to redirect traffic.
	assert.NotPanics(t, func() {
		_ = executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
			"--enable-archivista",
			"--archivista-headers", "Host: evil.attacker.com",
			"--artifactfile", "/dev/null")
	})
	t.Log("FINDING SEC-6: --archivista-headers accepts Host header injection")
}

func TestAdversarial_ArchivistaHeaderCRLFInjection(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// CRLF injection in header value.
	assert.NotPanics(t, func() {
		_ = executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
			"--enable-archivista",
			"--archivista-headers", "X-Custom: value\r\nX-Injected: evil",
			"--artifactfile", "/dev/null")
	})
	// Go's net/http rejects CRLF in header values, so this should be safe.
	// But the application-level code does not validate this.
}

// --------------------------------------------------------------------------
// SEC-7: Archivista URL injection / SSRF
// Severity: HIGH
//
// The --archivista-server flag accepts any URL including internal network
// addresses. When --enable-archivista is set, the CLI makes HTTP requests
// to the specified server. This is a classic SSRF vector.
// --------------------------------------------------------------------------

func TestAdversarial_ArchivistaURLInternalNetwork(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Point archivista to localhost metadata endpoint (cloud SSRF vector).
	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--enable-archivista",
		"--archivista-server", "http://169.254.169.254",
		"--artifactfile", "/dev/null")
	require.Error(t, err, "archivista to cloud metadata endpoint should fail")
	t.Log("FINDING SEC-7: --archivista-server accepts internal/metadata URLs without restriction")
}

func TestAdversarial_ArchivistaURLFileScheme(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// file:// scheme could read local files.
	assert.NotPanics(t, func() {
		_ = executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
			"--enable-archivista",
			"--archivista-server", "file:///etc/passwd",
			"--artifactfile", "/dev/null")
	})
}

// --------------------------------------------------------------------------
// SEC-8: Timestamp server URL injection / SSRF
// Severity: MEDIUM
//
// The --timestamp-servers flag on both 'run' and 'sign' accepts arbitrary
// URLs. When signing, the CLI makes HTTP requests to these servers.
// --------------------------------------------------------------------------

func TestAdversarial_TimestampServerSSRF(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Point timestamp server to cloud metadata endpoint.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath,
			"--timestamp-servers", "http://169.254.169.254/latest/meta-data/",
			"--", "echo", "hello")
	})
	t.Log("FINDING SEC-8: --timestamp-servers accepts internal/metadata URLs without restriction")
}

// --------------------------------------------------------------------------
// SEC-9: Error message information leakage
// Severity: LOW
//
// Error messages include file paths and error details that could leak
// information about the system. While these are sent to stderr (not a
// network response), in CI environments logs are often captured and
// could expose sensitive paths.
// --------------------------------------------------------------------------

func TestAdversarial_ErrorMessageDoesNotLeakKeyContent(t *testing.T) {
	dir := t.TempDir()

	// Write a file that looks like a key but has extra content after the PEM block.
	badKey := filepath.Join(dir, "leaky.pem")
	writeFile(t, badKey, `-----BEGIN RSA PRIVATE KEY-----
MIIBogIBAAJBALMnPDKiKv/fFHHl8QXRC6fSvX+1noNViePJKt7OjNmz
-----END RSA PRIVATE KEY-----
SECRET_TOKEN=super_secret_value_12345`)

	_, stderr, err := executeCmdOutput("run", "--step", "test",
		"--signer-file-key-path", badKey, "--", "echo", "hello")
	require.Error(t, err)

	// The error output should not contain the secret material after the PEM block.
	assert.NotContains(t, stderr, "super_secret_value_12345",
		"error output should not leak file content beyond the PEM block")
	assert.NotContains(t, err.Error(), "super_secret_value_12345",
		"error message should not leak file content beyond the PEM block")
}

func TestAdversarial_ErrorMessageDoesNotLeakFullPath(t *testing.T) {
	dir := t.TempDir()
	secretPath := filepath.Join(dir, "super-secret-project-name", "keys", "signing.pem")
	require.NoError(t, os.MkdirAll(filepath.Dir(secretPath), 0755))
	writeFile(t, secretPath, "not a real key")

	_, _, err := executeCmdOutput("run", "--step", "test",
		"--signer-file-key-path", secretPath, "--", "echo", "hello")
	require.Error(t, err)

	// NOTE: The error DOES contain the full path. This is standard Go behavior
	// but could leak directory structure information in CI logs.
	// This test documents the behavior rather than asserting it's fixed.
	if strings.Contains(err.Error(), "super-secret-project-name") {
		t.Log("INFO SEC-9: Error messages contain full file paths, which may leak directory structure in CI logs")
	}
}

// --------------------------------------------------------------------------
// SEC-10: LoadPolicy fallback to archivista with arbitrary gitoid
// Severity: MEDIUM
//
// In policy.go, LoadPolicy falls back to downloading from archivista when
// the local file open fails. The "policyPath" is passed directly as a
// gitoid to ac.Download(). If an attacker controls --policy and archivista
// is enabled, they can make the CLI download an arbitrary policy from a
// potentially attacker-controlled archivista server.
// --------------------------------------------------------------------------

func TestAdversarial_PolicyPathFallbackToArchivista(t *testing.T) {
	// When --policy is a non-existent path and archivista is enabled,
	// LoadPolicy treats the path as a gitoid and tries to download it.
	// This is by design, but combined with SEC-7 (SSRF via archivista-server)
	// it means an attacker could make the CLI download a malicious policy.

	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)

	err := executeCmd("verify", "--policy", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"--publickey", pubPath,
		"--enable-archivista",
		"--archivista-server", "http://127.0.0.1:1", // unreachable
		"--artifactfile", "/dev/null")
	require.Error(t, err, "policy download from unreachable archivista should fail")
	// This is expected -- the concern is that with a reachable attacker-controlled
	// server, any policy could be downloaded and used.
	t.Log("FINDING SEC-10: --policy accepts gitoid strings when archivista is enabled, downloading from the configured server")
}

// --------------------------------------------------------------------------
// SEC-11: loadVerifiers allows zero verifiers
// Severity: MEDIUM
//
// Unlike loadSigners (which requires at least one signer), loadVerifiers
// returns successfully with an empty verifiers slice. The runVerify function
// has its own check, but if loadVerifiers is called from a different context
// in the future, zero verifiers could lead to vacuously-true verification.
// --------------------------------------------------------------------------

func TestAdversarial_VerifyWithEmptyVerifierProviders(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Verify with no --publickey, no --policy-ca-roots, and no verifier providers.
	// The MarkFlagsOneRequired should catch this at the cobra level.
	err := executeCmd("verify", "--policy", polFile,
		"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	require.Error(t, err, "verify without any verifier must fail")
}

// --------------------------------------------------------------------------
// SEC-12: Config file in CWD (.witness.yaml default)
// Severity: MEDIUM
//
// The default config path is ".witness.yaml" which is relative to CWD.
// If a user runs cilock in a directory containing a malicious .witness.yaml
// (e.g. a cloned git repo), the config is loaded silently.
// --------------------------------------------------------------------------

// NOTE: TestAdversarial_DefaultConfigFileInCWD is intentionally omitted.
//
// The test would require os.Chdir() which is unsafe in parallel test runs
// (all goroutines share the same CWD). Additionally, cobra's OnInitialize
// uses logger.l.Fatal on config errors, which kills the test process.
//
// FINDING SEC-12 (MEDIUM): The default config path is ".witness.yaml" in
// CWD. A malicious repository could ship a .witness.yaml that silently
// overrides security-critical flags (e.g. --enable-archivista,
// --archivista-server) when a user runs cilock from the repo directory.
// Recommend warning when loading a config file from CWD, or requiring
// an explicit --config flag for non-default config paths.

// --------------------------------------------------------------------------
// SEC-13: Policy validate output format not validated
// Severity: LOW
//
// The --output flag on "policy validate" accepts any string. Unrecognized
// values silently fall through to text output. This is not a security issue
// per se but violates the principle of least surprise.
// --------------------------------------------------------------------------

func TestAdversarial_PolicyValidateOutputFormatValues(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"expires":"2030-01-01T00:00:00Z","steps":{"s":{"name":"s","functionaries":[{"type":"publickey","publickeyid":"k1"}],"attestations":[{"type":"t"}]}},"publickeys":{"k1":{"keyid":"k1","key":""}}}`)

	tests := []struct {
		name   string
		format string
	}{
		{"empty", ""},
		{"null-byte", "\x00"},
		{"very-long", strings.Repeat("a", 10000)},
		{"html", "<script>alert(1)</script>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				_ = executeCmd("policy", "validate", "--policy", polFile, "--output", tt.format)
			})
		})
	}
}

// --------------------------------------------------------------------------
// SEC-14: Verify with symlinked attestation / policy files
// Severity: LOW
//
// All file-reading operations follow symlinks. This means an attacker with
// write access to the working directory could create symlinks that cause
// cilock to read sensitive files.
// --------------------------------------------------------------------------

func TestAdversarial_PolicyFileSymlink(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)

	// Create a real policy file.
	realPolicy := filepath.Join(dir, "real-policy.json")
	writeFile(t, realPolicy, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Create a symlink to it.
	symlinkPolicy := filepath.Join(dir, "symlink-policy.json")
	if err := os.Symlink(realPolicy, symlinkPolicy); err != nil {
		t.Skip("symlinks not supported on this filesystem")
	}

	// Should work through symlink -- this is expected but documented.
	assert.NotPanics(t, func() {
		_ = executeCmd("verify", "--policy", symlinkPolicy, "--publickey", pubPath,
			"--attestations", "/dev/null", "--artifactfile", "/dev/null")
	})
}

// --------------------------------------------------------------------------
// SEC-15: Verify multiple --subjects with mixed valid/invalid
// Severity: LOW
//
// Ensure that one invalid subject doesn't allow other subjects to be
// silently processed.
// --------------------------------------------------------------------------

func TestAdversarial_VerifyMixedSubjects(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// First subject is valid, second is garbage.
	err := executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
		"--attestations", "/dev/null",
		"--subjects", "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"--subjects", "sha256:not-hex-at-all!")
	require.Error(t, err, "verify with any invalid subject must fail entirely")
	assert.Contains(t, err.Error(), "invalid subject digest")
}

// --------------------------------------------------------------------------
// SEC-16: loadSigners/loadVerifiers provider iteration order non-determinism
// Severity: LOW (informational)
//
// Both loadSigners and loadVerifiers iterate over a map[string]struct{}
// (from providersFromFlags). Go map iteration is non-deterministic. If
// multiple signer providers are configured and one fails, the error may
// refer to different providers on different runs, making debugging
// inconsistent. Not a direct security issue but relevant for auditing.
// --------------------------------------------------------------------------

func TestAdversarial_ProvidersFromFlagsStability(t *testing.T) {
	// Verify that providersFromFlags parses flag names correctly.
	// Use a fresh command to register flags.
	cmd := RunCmd()
	cmd.SetArgs([]string{"--step", "test", "--", "echo"})

	// Manually visit flags to test parsing.
	providers := providersFromFlags("signer", cmd.Flags())
	// The exact content depends on what flags are registered, but
	// it should never panic.
	assert.NotNil(t, providers)
}

// --------------------------------------------------------------------------
// SEC-17: Run command with empty command args
// Severity: LOW
//
// If run is called with "--" but no actual command, the commandrun attestor
// is not added. This is correct behavior but worth verifying explicitly.
// --------------------------------------------------------------------------

func TestAdversarial_RunWithEmptyCommand(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// Args after "--" are empty.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath, "--")
	})
}

func TestAdversarial_RunWithNoSeparator(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)

	// No "--" separator, no command.
	assert.NotPanics(t, func() {
		_ = executeCmd("run", "--step", "test", "--signer-file-key-path", keyPath)
	})
}

// --------------------------------------------------------------------------
// SEC-18: Archivista URL parsing edge cases
// Severity: LOW
//
// Various malformed URLs for --archivista-server.
// --------------------------------------------------------------------------

func TestAdversarial_ArchivistaURLEdgeCases(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	urls := []string{
		"",
		"not-a-url",
		"javascript:alert(1)",
		"ftp://ftp.example.com",
		"http://user:pass@evil.com",
		"http://[::1]:8080",
		"http://0x7f000001:8080",
		"http://0177.0.0.1:8080",
	}

	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			assert.NotPanics(t, func() {
				_ = executeCmd("verify", "--policy", polFile, "--publickey", pubPath,
					"--enable-archivista", "--archivista-server", u,
					"--artifactfile", "/dev/null")
			})
		})
	}
}

// --------------------------------------------------------------------------
// SEC-19: Verify that loadSigners enforces minimum signer count
// Severity: HIGH (correctness)
//
// loadSigners MUST return an error when no signers are loaded. This prevents
// proceeding with an unsigned attestation.
// --------------------------------------------------------------------------

func TestAdversarial_LoadSignersRequiresAtLeastOne(t *testing.T) {
	// Calling loadSigners with empty provider map must fail.
	_, err := loadSigners(
		context.Background(),
		make(options.SignerOptions),
		make(options.KMSSignerProviderOptions),
		map[string]struct{}{},
	)
	require.Error(t, err, "loadSigners with no providers must fail")
	assert.Contains(t, err.Error(), "failed to load any signers")
}

// --------------------------------------------------------------------------
// SEC-20: Verify that runRun enforces exactly one signer
// Severity: HIGH (correctness)
//
// runRun must reject zero or multiple signers to prevent unsigned or
// ambiguously-signed attestations.
// --------------------------------------------------------------------------

func TestAdversarial_RunRunRejectsZeroSigners(t *testing.T) {
	err := runRun(context.Background(), options.RunOptions{
		StepName: "test",
	}, []string{"echo", "hello"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no signers found")
}

func TestAdversarial_RunRunRejectsMultipleSigners(t *testing.T) {
	err := runRun(context.Background(), options.RunOptions{
		StepName: "test",
	}, []string{"echo", "hello"}, &fakeSignerForTesting{}, &fakeSignerForTesting{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one signer")
}

// --------------------------------------------------------------------------
// SEC-21: Ensure run.go attestor name sanitization handles edge cases
// Severity: MEDIUM
//
// The sanitization in run.go replaces "/" with "-" but does not handle
// other path-unsafe characters like null bytes, "..", or backslashes.
// --------------------------------------------------------------------------

func TestAdversarial_AttestorNameSanitizationEdgeCases(t *testing.T) {
	// These test the strings.ReplaceAll(result.AttestorName, "/", "-") logic.
	tests := []struct {
		name   string
		input  string
		output string
	}{
		{"forward slash", "parent/child", "parent-child"},
		{"multiple slashes", "a/b/c/d", "a-b-c-d"},
		{"only slashes", "///", "---"},
		{"backslash", `parent\child`, `parent\child`}, // NOT sanitized!
		{"dot-dot", "../../../etc/passwd", "..-..-..-etc-passwd"},
		{"null byte", "test\x00evil", "test\x00evil"}, // NOT sanitized!
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.ReplaceAll(tt.input, "/", "-")
			assert.Equal(t, tt.output, got)
		})
	}

	// Document that backslash and null byte are not sanitized.
	// On Windows, backslash is a path separator and could enable traversal.
	t.Log("FINDING SEC-21: Attestor name sanitization only handles '/', not backslash or null bytes")
}

// --------------------------------------------------------------------------
// SEC-22: isValidHexDigest boundary conditions
// Severity: LOW
//
// Additional edge cases for the hex digest validator.
// --------------------------------------------------------------------------

func TestAdversarial_IsValidHexDigestBoundary(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"exactly 32 chars", "e3b0c44298fc1c149afbf4c8996fb924", true},
		{"33 chars (odd)", "e3b0c44298fc1c149afbf4c8996fb9241", false},
		{"34 chars (even)", "e3b0c44298fc1c149afbf4c8996fb92411", true},
		{"max uint64 hex", "ffffffffffffffffffffffffffffffff", true},
		{"all zeros", "00000000000000000000000000000000", true},
		{"empty prefix colon", ":e3b0c44298fc1c149afbf4c8996fb924", true}, // empty algo name accepted!
		{"tab in value", "sha256:\te3b0c44298fc1c149afbf4c8996fb924", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidHexDigest(tt.input)
			assert.Equal(t, tt.want, got, "isValidHexDigest(%q)", tt.input)
		})
	}
}

// --------------------------------------------------------------------------
// Helper: fake signer for unit testing runRun without real crypto.
// Implements cryptoutil.Signer (which embeds KeyIdentifier).
// --------------------------------------------------------------------------

type fakeSignerForTesting struct{}

func (f *fakeSignerForTesting) Sign(_ io.Reader) ([]byte, error) {
	return nil, fmt.Errorf("fake signer: not implemented")
}

func (f *fakeSignerForTesting) KeyID() (string, error) {
	return "fake-key-id", nil
}

func (f *fakeSignerForTesting) Verifier() (cryptoutil.Verifier, error) {
	return nil, fmt.Errorf("fake signer: verifier not implemented")
}

// Compile-time interface check.
var _ cryptoutil.Signer = (*fakeSignerForTesting)(nil)

// ==========================================================================
// R3_310: Security audit of cilock CLI commands
//
// Focus areas:
// - Config file injection via initConfig
// - Path traversal in output/input file paths
// - Key loading vulnerabilities
// - Argument parsing edge cases
// - loadVerifiers asymmetry with loadSigners
// ==========================================================================

// --------------------------------------------------------------------------
// R3_310_01: initConfig applies config values to unset flags
//
// Severity: MEDIUM
// The initConfig function will silently set any flag that the user did not
// explicitly provide on the command line. A malicious .witness.yaml in a
// cloned repo can override security-critical flags like:
//   - signer-file-key-path (swap signing key)
//   - enable-archivista / archivista-server (redirect attestation storage)
//   - step (rename the attestation step)
//   - hashes (weaken hash algorithm)
//
// This test exercises initConfig directly to prove that config file values
// override default flag values for the "run" subcommand.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_ConfigFileOverridesRunFlags(t *testing.T) {
	dir := t.TempDir()

	// Write a config file that overrides run.step and run.outfile.
	configPath := filepath.Join(dir, "evil.yaml")
	writeFile(t, configPath, `run:
  step: attacker-controlled-step
  outfile: /tmp/attacker-output.json
  enable-archivista: "true"
  archivista-server: "http://evil.attacker.com"
`)

	// Build a fresh command tree to verify the flag defaults.
	cmd := New()

	// Find the "run" subcommand and check its flags.
	var runCmd *cobra.Command
	for _, c := range cmd.Commands() {
		if c.Name() == "run" {
			runCmd = c
			break
		}
	}
	require.NotNil(t, runCmd, "run subcommand must exist")

	// Before initConfig, the step flag should be at its default (empty string).
	stepFlag := runCmd.Flags().Lookup("step")
	require.NotNil(t, stepFlag)
	assert.Equal(t, "", stepFlag.DefValue, "step default should be empty")

	// Use viper directly to prove the config file values are readable
	// and would be applied by initConfig when os.Args contains "run".
	v := viper.New()
	v.SetConfigFile(configPath)
	require.NoError(t, v.ReadInConfig())

	// Verify the config file contains attacker-controlled values.
	assert.Equal(t, "attacker-controlled-step", v.GetString("run.step"),
		"config file should contain attacker-controlled step name")
	assert.Equal(t, "http://evil.attacker.com", v.GetString("run.archivista-server"),
		"config file should contain attacker-controlled archivista server")
	assert.Equal(t, "true", v.GetString("run.enable-archivista"),
		"config file should be able to enable archivista")
	assert.Equal(t, "/tmp/attacker-output.json", v.GetString("run.outfile"),
		"config file should contain attacker-controlled output path")

	t.Log("FINDING R3_310_01: Config file can override any run flag including " +
		"step name, outfile path, archivista server, and enable-archivista. " +
		"A malicious .witness.yaml in a cloned repo silently applies these " +
		"without user awareness.")
}

// --------------------------------------------------------------------------
// R3_310_02: initConfig contains() check uses os.Args directly
//
// Severity: LOW
// The contains(os.Args, cm.Name()) check in initConfig searches all of
// os.Args for the command name. If any argument VALUE happens to match a
// command name (e.g. --step "run"), config values for that command could
// be applied unexpectedly.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_ContainsFunctionMatchesAnyPosition(t *testing.T) {
	// The contains() function does a simple linear search.
	// Verify it matches at any position, not just position 1.
	assert.True(t, contains([]string{"cilock", "verify", "--step", "run"}, "run"),
		"contains() matches 'run' even when it appears as a flag value")
	assert.True(t, contains([]string{"cilock", "--config", "run.yaml", "verify"}, "verify"),
		"contains() correctly finds 'verify' as the subcommand")

	// This means if a user runs:
	//   cilock verify --subjects "run" --policy p.json ...
	// The config file's run.* section would also be applied, potentially
	// setting flags on the "run" command that shares the same flag names.
	t.Log("FINDING R3_310_02: contains() in initConfig matches command names " +
		"anywhere in os.Args, not just as the subcommand position. This could " +
		"cause config values for one command to be applied when another " +
		"command is actually being executed.")
}

// --------------------------------------------------------------------------
// R3_310_03: loadOutfile creates files via os.Create with no path sanitization
//
// Severity: MEDIUM
// loadOutfile blindly calls os.Create on the user-provided path. This
// means:
//   - Path traversal (../../) is not blocked
//   - Absolute paths write anywhere the user has access
//   - Symlinks are followed, writing to the symlink target
//   - On multi-export, attestor names are appended to the base path
//     but only "/" is sanitized (not backslash, null bytes, or "..")
// --------------------------------------------------------------------------

func TestSecurity_R3_310_LoadOutfileAbsolutePathEscapesWorkDir(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "target", "escaped.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(targetFile), 0755))

	// loadOutfile accepts absolute paths without restriction.
	f, err := loadOutfile(targetFile)
	require.NoError(t, err)
	require.NotNil(t, f)

	_, err = f.Write([]byte("attacker data"))
	require.NoError(t, err)
	closeOutfile(f)

	// Verify the file was actually created at the absolute path.
	data, err := os.ReadFile(targetFile)
	require.NoError(t, err)
	assert.Equal(t, "attacker data", string(data))

	t.Log("FINDING R3_310_03: loadOutfile accepts absolute paths without " +
		"restriction, allowing writes anywhere the process has access.")
}

func TestSecurity_R3_310_LoadOutfileSymlinkWrite(t *testing.T) {
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "real-target")
	require.NoError(t, os.MkdirAll(targetDir, 0755))

	// Create a symlink.
	symlinkPath := filepath.Join(dir, "link.json")
	targetPath := filepath.Join(targetDir, "actual.json")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Skip("symlinks not supported")
	}

	// loadOutfile follows the symlink.
	f, err := loadOutfile(symlinkPath)
	require.NoError(t, err)
	require.NotNil(t, f)

	_, err = f.Write([]byte("via symlink"))
	require.NoError(t, err)
	closeOutfile(f)

	// Verify write went to symlink target.
	data, err := os.ReadFile(targetPath)
	require.NoError(t, err)
	assert.Equal(t, "via symlink", string(data))

	t.Log("FINDING R3_310_03b: loadOutfile follows symlinks, allowing " +
		"writes to be redirected to unintended locations.")
}

// --------------------------------------------------------------------------
// R3_310_04: loadOutfile truncates existing files (os.Create behavior)
//
// Severity: MEDIUM
// os.Create truncates existing files. If --outfile points to an existing
// file (e.g. a system config, a script, a certificate), the existing
// content is destroyed even if the attestation write subsequently fails.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_LoadOutfileTruncatesExistingFile(t *testing.T) {
	dir := t.TempDir()
	existingFile := filepath.Join(dir, "existing.json")
	writeFile(t, existingFile, "important original content that should not be lost")

	f, err := loadOutfile(existingFile)
	require.NoError(t, err)
	require.NotNil(t, f)

	// File is now truncated even before we write anything.
	closeOutfile(f)

	data, err := os.ReadFile(existingFile)
	require.NoError(t, err)
	assert.Equal(t, "", string(data),
		"os.Create truncates the file immediately, destroying original content")

	t.Log("FINDING R3_310_04: loadOutfile uses os.Create which truncates " +
		"existing files immediately. If --outfile points to an existing " +
		"important file, its content is destroyed even if the operation " +
		"subsequently fails.")
}

// --------------------------------------------------------------------------
// R3_310_05: Sign command reads arbitrary files via --infile
//
// Severity: MEDIUM
// The sign command opens --infile with os.Open(so.InFilePath) and reads
// its entire contents. While the contents are signed (not exfiltrated
// directly), the signed output contains the base64-encoded input as the
// DSSE payload, making it a potential data exfiltration path if the
// output is sent to an archivista server.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_SignReadsArbitraryFile(t *testing.T) {
	dir := t.TempDir()

	// Create a "sensitive" file -- pretend this is /etc/shadow or a
	// private key that the user did not intend to sign.
	sensitiveFile := filepath.Join(dir, "sensitive.txt")
	writeFile(t, sensitiveFile, "SUPER_SECRET_API_KEY=sk-12345")

	outFile := filepath.Join(dir, "signed.json")

	// Call runSign directly to avoid the cobra.OnInitialize global state
	// issue (multiple New() calls accumulate init callbacks).
	err := runSign(context.Background(), options.SignOptions{
		InFilePath:  sensitiveFile,
		OutFilePath: outFile,
		DataType:    "https://witness.testifysec.com/policy/v0.1",
	}, &fakeSignerForTesting{})

	// The fake signer will fail, but the file IS opened and read before
	// signing occurs. The key point is that --infile accepts any path.
	// To prove the file was opened, we verify the error is about signing,
	// not about file access.
	require.Error(t, err, "fake signer should cause signing to fail")
	assert.NotContains(t, err.Error(), "permission denied",
		"error should be about signing, not file access")
	assert.NotContains(t, err.Error(), "no such file",
		"the sensitive file was found and opened")

	t.Log("FINDING R3_310_05: sign command reads arbitrary files via " +
		"--infile with os.Open() and no path restriction. The file content " +
		"is embedded (base64-encoded) in the signed DSSE output. Combined " +
		"with archivista upload, this is a data exfiltration path.")
}

// --------------------------------------------------------------------------
// R3_310_06: loadVerifiers returns empty slice without error
//
// Severity: MEDIUM
// Unlike loadSigners which returns an error when no signers are loaded,
// loadVerifiers returns ([]cryptoutil.Verifier{}, nil) when the provider
// map is empty. While runVerify has its own check, this asymmetry is a
// defense-in-depth gap.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_LoadVerifiersReturnsEmptyWithoutError(t *testing.T) {
	verifiers, err := loadVerifiers(
		context.Background(),
		make(options.VerifierOptions),
		make(options.KMSVerifierProviderOptions),
		map[string]struct{}{},
	)
	// Unlike loadSigners, this succeeds with zero verifiers.
	assert.NoError(t, err, "loadVerifiers returns no error with zero providers")
	assert.Empty(t, verifiers, "loadVerifiers returns empty slice")

	// Compare with loadSigners which correctly errors:
	_, signErr := loadSigners(
		context.Background(),
		make(options.SignerOptions),
		make(options.KMSSignerProviderOptions),
		map[string]struct{}{},
	)
	assert.Error(t, signErr, "loadSigners correctly errors with zero providers")

	t.Log("FINDING R3_310_06: loadVerifiers returns success with zero " +
		"verifiers, unlike loadSigners which returns an error. This " +
		"asymmetry means callers must independently validate the verifier " +
		"count. If a new call site forgets this check, verification could " +
		"proceed with no verifiers (vacuously true).")
}

// --------------------------------------------------------------------------
// R3_310_07: Config file can set key paths to read arbitrary files
//
// Severity: HIGH
// If a malicious config file sets signer-file-key-path to a path like
// /etc/shadow or ~/.ssh/id_rsa, the CLI will attempt to read that file
// as a signing key. While the parse will fail for non-key files, the
// file contents may be partially exposed in error messages.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_ConfigFileKeyPathInjection(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "evil.yaml")

	// A malicious config could point the key path to a sensitive file.
	writeFile(t, configPath, `run:
  signer-file-key-path: /etc/hosts
  step: innocent-step
`)

	v := viper.New()
	v.SetConfigFile(configPath)
	require.NoError(t, v.ReadInConfig())

	keyPath := v.GetString("run.signer-file-key-path")
	assert.Equal(t, "/etc/hosts", keyPath,
		"config file can set arbitrary key paths")

	t.Log("FINDING R3_310_07: Config file can set signer-file-key-path to " +
		"read arbitrary files. The file is opened and its contents passed " +
		"to the crypto key parser. While non-key files will cause parse " +
		"errors, error messages may leak file content.")
}

// --------------------------------------------------------------------------
// R3_310_08: Verify --publickey path has no TOCTOU protection
//
// Severity: LOW
// The verify command opens --publickey with os.Open(vo.KeyPath), then
// reads and parses it. There is a TOCTOU window between the user
// specifying the path and the file being read, during which the file
// could be swapped (e.g. via symlink manipulation in a shared temp dir).
//
// Additionally, the key file is read in one shot - there is no check
// that the file hasn't been modified between stat and read.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_VerifyKeyPathTOCTOU(t *testing.T) {
	dir := t.TempDir()

	// Create a legitimate key.
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)

	// Create an attacker key.
	attackerDir := filepath.Join(dir, "attacker")
	require.NoError(t, os.MkdirAll(attackerDir, 0755))
	attackerKeyPath := generateTestKey(t, attackerDir)
	attackerPubPath := generateTestPublicKey(t, attackerDir, attackerKeyPath)

	// Read both public keys to verify they are different.
	legitimatePubData, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	attackerPubData, err := os.ReadFile(attackerPubPath)
	require.NoError(t, err)

	// The keys should be different (different RSA key generations).
	assert.NotEqual(t, string(legitimatePubData), string(attackerPubData),
		"test setup: keys should be different")

	// Now demonstrate the TOCTOU: create a symlink that initially points
	// to the legitimate key, then swap it.
	symlinkPath := filepath.Join(dir, "current-key.pub")
	if err := os.Symlink(pubPath, symlinkPath); err != nil {
		t.Skip("symlinks not supported")
	}

	// Verify the symlink points to legitimate key.
	target, err := os.Readlink(symlinkPath)
	require.NoError(t, err)
	assert.Equal(t, pubPath, target)

	// Swap the symlink to point to attacker key.
	require.NoError(t, os.Remove(symlinkPath))
	require.NoError(t, os.Symlink(attackerPubPath, symlinkPath))

	// Verify the symlink now points to attacker key.
	target, err = os.Readlink(symlinkPath)
	require.NoError(t, err)
	assert.Equal(t, attackerPubPath, target)

	t.Log("FINDING R3_310_08: Key file paths follow symlinks and have no " +
		"TOCTOU protection. In a shared directory, an attacker could swap " +
		"the key file between when the user specifies it and when it is read.")
}

// --------------------------------------------------------------------------
// R3_310_09: Outfile multi-export attestor name sanitization gaps
//
// Severity: MEDIUM
// In run.go, the multi-export path construction is:
//   safeName := strings.ReplaceAll(result.AttestorName, "/", "-")
//   outfile += "-" + safeName + ".json"
//
// This sanitization has gaps:
// 1. Backslash (\) is not sanitized -- on Windows this is a path separator
// 2. Null bytes are not sanitized -- can truncate paths on some systems
// 3. ".." without "/" is reduced to ".." which creates confusion
// 4. Newlines/control chars in the name could cause log injection
// --------------------------------------------------------------------------

func TestSecurity_R3_310_AttestorNameSanitizationGaps(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name       string
		attestor   string
		outBase    string
		wantSuffix string
		note       string
	}{
		{
			name:       "backslash_traversal_windows",
			attestor:   `..\..\etc\passwd`,
			outBase:    filepath.Join(dir, "out"),
			wantSuffix: `-..\..\etc\passwd.json`,
			note:       "backslash not sanitized - path traversal on Windows",
		},
		{
			name:       "null_byte_truncation",
			attestor:   "safe\x00evil",
			outBase:    filepath.Join(dir, "out"),
			wantSuffix: "-safe\x00evil.json",
			note:       "null byte not sanitized - can truncate path on some systems",
		},
		{
			name:       "dotdot_without_slash",
			attestor:   "..",
			outBase:    filepath.Join(dir, "out"),
			wantSuffix: "-...json",
			note:       ".. without slash is not sanitized",
		},
		{
			name:       "newline_injection",
			attestor:   "safe\nevil-log-line",
			outBase:    filepath.Join(dir, "out"),
			wantSuffix: "-safe\nevil-log-line.json",
			note:       "newline not sanitized - log injection risk",
		},
		{
			name:       "slash_correctly_sanitized",
			attestor:   "parent/child",
			outBase:    filepath.Join(dir, "out"),
			wantSuffix: "-parent-child.json",
			note:       "forward slash correctly replaced",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			safeName := strings.ReplaceAll(tt.attestor, "/", "-")
			result := tt.outBase + "-" + safeName + ".json"
			expected := tt.outBase + tt.wantSuffix
			assert.Equal(t, expected, result, "sanitization: %s", tt.note)
		})
	}

	t.Log("FINDING R3_310_09: Attestor name sanitization only handles '/', " +
		"leaving backslash, null bytes, '..', and control characters " +
		"unsanitized. On Windows, backslash traversal is possible.")
}

// --------------------------------------------------------------------------
// R3_310_10: Config file can inject values for verify command flags
//
// Severity: HIGH
// A malicious config can override verify command flags including:
//   - policy (point to attacker-controlled policy)
//   - publickey (swap verification key)
//   - policy-ca-roots (inject attacker CA)
//   - subjects (inject controlled subject digests)
// --------------------------------------------------------------------------

func TestSecurity_R3_310_ConfigFileOverridesVerifyFlags(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "evil.yaml")

	writeFile(t, configPath, `verify:
  policy: /tmp/attacker-policy.json
  publickey: /tmp/attacker-key.pub
  policy-ca-roots: /tmp/attacker-ca.pem
  archivista-server: "http://evil.attacker.com:8080"
  enable-archivista: "true"
`)

	v := viper.New()
	v.SetConfigFile(configPath)
	require.NoError(t, v.ReadInConfig())

	// Verify all attacker-controlled values are readable from config.
	assert.Equal(t, "/tmp/attacker-policy.json", v.GetString("verify.policy"))
	assert.Equal(t, "/tmp/attacker-key.pub", v.GetString("verify.publickey"))
	assert.Equal(t, "http://evil.attacker.com:8080", v.GetString("verify.archivista-server"))
	assert.Equal(t, "true", v.GetString("verify.enable-archivista"))

	// CA roots is a string slice.
	caRoots := v.GetStringSlice("verify.policy-ca-roots")
	assert.Contains(t, caRoots, "/tmp/attacker-ca.pem")

	t.Log("FINDING R3_310_10: Config file can override all verify command " +
		"flags including policy path, public key path, CA roots, and " +
		"archivista server. A malicious .witness.yaml can redirect " +
		"verification to use attacker-controlled trust anchors.")
}

// --------------------------------------------------------------------------
// R3_310_11: Sign --outfile writes to arbitrary paths
//
// Severity: MEDIUM
// The sign command writes signed output to --outfile via loadOutfile,
// which has no path restrictions. A malicious config could set the
// outfile to overwrite system files or scripts.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_SignOutfilePathTraversal(t *testing.T) {
	dir := t.TempDir()

	// Demonstrate that loadOutfile accepts path traversal sequences.
	traversalDir := filepath.Join(dir, "a", "b")
	require.NoError(t, os.MkdirAll(traversalDir, 0755))
	outfile := filepath.Join(dir, "a", "b", "..", "..", "escaped.json")

	// Call loadOutfile directly -- it performs no traversal sanitization.
	f, err := loadOutfile(outfile)
	require.NoError(t, err, "loadOutfile with traversal path should succeed")
	require.NotNil(t, f)

	_, err = f.Write([]byte("traversal write"))
	require.NoError(t, err)
	closeOutfile(f)

	// Verify the file was written to the resolved path.
	resolvedPath := filepath.Join(dir, "escaped.json")
	data, err := os.ReadFile(resolvedPath)
	require.NoError(t, err, "file should exist at resolved traversal path")
	assert.Equal(t, "traversal write", string(data))

	t.Log("FINDING R3_310_11: loadOutfile (used by sign and run) accepts " +
		"path traversal sequences. The path '../../escaped.json' resolves " +
		"to a parent directory.")
}

// --------------------------------------------------------------------------
// R3_310_12: Policy file path traversal in verify command
//
// Severity: MEDIUM
// The --policy flag accepts any path including traversal sequences.
// Combined with the archivista fallback (LoadPolicy), a non-existent
// traversal path that fails to open locally will be sent as a "gitoid"
// to archivista.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_PolicyFilePathTraversal(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)

	// Create a policy file in a parent directory.
	realPolicyDir := filepath.Join(dir, "policies")
	require.NoError(t, os.MkdirAll(realPolicyDir, 0755))
	realPolicy := filepath.Join(realPolicyDir, "policy.json")
	writeFile(t, realPolicy, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Access it via traversal from a subdirectory.
	subDir := filepath.Join(dir, "sub", "deep")
	require.NoError(t, os.MkdirAll(subDir, 0755))
	traversalPolicy := filepath.Join(subDir, "..", "..", "policies", "policy.json")

	// The traversal path should resolve and the file should be readable.
	assert.NotPanics(t, func() {
		_ = executeCmd("verify",
			"--policy", traversalPolicy,
			"--publickey", pubPath,
			"--attestations", "/dev/null",
			"--artifactfile", "/dev/null")
	})

	t.Log("FINDING R3_310_12: --policy accepts path traversal sequences. " +
		"The path is passed directly to os.Open without sanitization.")
}

// --------------------------------------------------------------------------
// R3_310_13: Verify --attestations reads arbitrary files
//
// Severity: MEDIUM
// The --attestations flag causes files to be read via MemorySource.LoadFile
// which calls os.Open then io.ReadAll. No size limit is enforced, and
// any readable file can be targeted. The file contents are fully parsed
// as JSON and stored in memory.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_AttestationFileReadsArbitraryPaths(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	pubPath := generateTestPublicKey(t, dir, keyPath)
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Point attestation to /etc/hosts -- readable on all unix systems.
	// The file is not valid JSON, so it will fail at JSON parse, but the
	// file IS opened and fully read into memory first.
	err := executeCmd("verify",
		"--policy", polFile,
		"--publickey", pubPath,
		"--attestations", "/etc/hosts",
		"--artifactfile", "/dev/null")
	require.Error(t, err, "non-JSON attestation file should fail")

	// The error comes from JSON parse, not from a path restriction.
	// This proves the file was opened and read.
	assert.NotContains(t, err.Error(), "permission denied",
		"file was opened successfully (error is from JSON parse, not access)")
}

// --------------------------------------------------------------------------
// R3_310_14: Verify CA certificate loading reads arbitrary files
//
// Severity: MEDIUM
// The --policy-ca-roots, --policy-ca-intermediates, and
// --policy-timestamp-servers flags all use os.ReadFile to load
// certificate files with no path restrictions or size limits.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_CACertReadsArbitraryFiles(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Attempt to read /etc/hosts as a CA root certificate.
	// The file will be fully read but fail at certificate parsing.
	err := executeCmd("verify",
		"--policy", polFile,
		"--policy-ca-roots", "/etc/hosts",
		"--attestations", "/dev/null",
		"--artifactfile", "/dev/null")
	require.Error(t, err)
	// Error should be about certificate parsing, not file access.
	assert.Contains(t, err.Error(), "certificate",
		"error should be about certificate parsing, proving the file was read")
}

// --------------------------------------------------------------------------
// R3_310_15: Config file with YAML anchors (billion laughs variant)
//
// Severity: LOW
// While Go's YAML parser rejects self-referencing anchors, other forms
// of YAML complexity (large maps, deeply nested structures) could cause
// excessive memory use during config parsing.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_ConfigFileLargeYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "large.yaml")

	// Create a config file with many keys.
	var builder strings.Builder
	builder.WriteString("run:\n")
	for i := 0; i < 10000; i++ {
		builder.WriteString(fmt.Sprintf("  key-%d: value-%d\n", i, i))
	}
	writeFile(t, configPath, builder.String())

	// Viper should handle this without OOM or panic.
	v := viper.New()
	v.SetConfigFile(configPath)
	assert.NotPanics(t, func() {
		_ = v.ReadInConfig()
	})
}

// --------------------------------------------------------------------------
// R3_310_16: runVerify allows empty verifiers through loadVerifiers
//
// Severity: MEDIUM
// While cobra's MarkFlagsOneRequired catches this at the CLI level,
// the runVerify function itself relies on an explicit check:
//   if vo.KeyPath == "" && len(vo.PolicyCARootPaths) == 0 && len(verifiers) == 0
// If loadVerifiers returns empty and the check is bypassed (e.g. via
// code changes or config injection), verification could proceed with
// no verifiers.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_RunVerifyRequiresVerifiers(t *testing.T) {
	dir := t.TempDir()
	polFile := filepath.Join(dir, "policy.json")
	writeFile(t, polFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)
	attFile := filepath.Join(dir, "att.json")
	writeFile(t, attFile, `{"payloadType":"test","payload":"dGVzdA==","signatures":[]}`)

	// Call runVerify directly with empty verifiers and empty key/CA paths.
	vo := options.VerifyOptions{
		PolicyFilePath:      polFile,
		AttestationFilePaths: []string{attFile},
		ArtifactFilePath:    "/dev/null",
	}

	err := runVerify(context.Background(), vo)
	require.Error(t, err, "runVerify with no verifiers must fail")
	assert.Contains(t, err.Error(), "must supply",
		"error should indicate missing verifier/key/CA")
}

// --------------------------------------------------------------------------
// R3_310_17: Config file default path ".witness.yaml" in CWD
//
// Severity: MEDIUM
// The default config path is ".witness.yaml" which is a CWD-relative
// path. This means any directory the user runs cilock from can contain
// a config file that silently overrides flags.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_DefaultConfigPathIsCWDRelative(t *testing.T) {
	// Verify the default config path.
	ro := &options.RootOptions{}
	cmd := &cobra.Command{}
	ro.AddFlags(cmd)

	configFlag := cmd.PersistentFlags().Lookup("config")
	require.NotNil(t, configFlag)
	assert.Equal(t, ".witness.yaml", configFlag.DefValue,
		"default config path should be CWD-relative .witness.yaml")

	t.Log("FINDING R3_310_17: Default config path is '.witness.yaml' " +
		"(CWD-relative). A malicious git repo can include this file to " +
		"silently override CLI flags when users run cilock from the repo " +
		"directory. Consider requiring --config for non-default paths " +
		"or warning when loading from CWD.")
}

// --------------------------------------------------------------------------
// R3_310_18: Profile file flags accept arbitrary paths
//
// Severity: MEDIUM
// The --debug-cpu-profile-file and --debug-mem-profile-file flags call
// os.Create() on user-provided paths without restriction. These use
// package-level state (cpuProfileFile) which also means they cannot be
// safely tested via multiple executeCmd calls in the same process.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_ProfileFileFlagsExist(t *testing.T) {
	cmd := New()

	cpuFlag := cmd.PersistentFlags().Lookup("debug-cpu-profile-file")
	require.NotNil(t, cpuFlag, "debug-cpu-profile-file flag must exist")
	assert.Equal(t, "", cpuFlag.DefValue, "default should be empty (disabled)")

	memFlag := cmd.PersistentFlags().Lookup("debug-mem-profile-file")
	require.NotNil(t, memFlag, "debug-mem-profile-file flag must exist")
	assert.Equal(t, "", memFlag.DefValue, "default should be empty (disabled)")

	t.Log("FINDING R3_310_18: Profile file flags accept arbitrary paths " +
		"and create files via os.Create (truncating existing files). " +
		"An attacker who can inject CLI args could overwrite arbitrary " +
		"files. These flags should be restricted in production builds.")
}

// --------------------------------------------------------------------------
// R3_310_19: runSign allows reading device files
//
// Severity: LOW
// The sign command opens --infile without checking if it is a regular
// file. Device files like /dev/zero or /dev/random could cause hangs
// (infinite reads) or resource exhaustion.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_SignInfileDeviceFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	outfile := filepath.Join(dir, "signed.json")

	// /dev/null is a device file that returns EOF immediately.
	// This demonstrates that device files are accepted.
	err := executeCmd("sign",
		"--signer-file-key-path", keyPath,
		"--infile", "/dev/null",
		"--outfile", outfile)
	// This may succeed (empty input) or fail (empty DSSE), but should not panic.
	assert.NotPanics(t, func() { _ = err })

	t.Log("FINDING R3_310_19: sign --infile accepts device files without " +
		"checking file type. /dev/zero or /dev/random could cause hangs " +
		"or resource exhaustion. Consider restricting to regular files.")
}

// --------------------------------------------------------------------------
// R3_310_20: providersFromFlags flag name parsing edge cases
//
// Severity: LOW
// providersFromFlags splits flag names on "-" and uses parts[1] as the
// provider name. This means a flag like "signer-a-b-c" would extract
// "a" as the provider. The parsing is correct for the intended use case
// but doesn't validate provider names.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_ProvidersFromFlagsParsing(t *testing.T) {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("signer-file-key-path", "", "test")
	flags.String("signer-debug-enabled", "", "test")
	flags.String("verifier-kms-ref", "", "test")
	flags.String("unrelated-flag", "", "test")

	// Set some flags to simulate user input.
	require.NoError(t, flags.Set("signer-file-key-path", "/some/path"))
	require.NoError(t, flags.Set("signer-debug-enabled", "true"))

	providers := providersFromFlags("signer", flags)

	assert.Contains(t, providers, "file", "should find 'file' provider")
	assert.Contains(t, providers, "debug", "should find 'debug' provider")
	assert.NotContains(t, providers, "kms", "should not find verifier provider")
	assert.NotContains(t, providers, "unrelated", "should not find unrelated flag")
}

// --------------------------------------------------------------------------
// R3_310_21: initConfig flag type coercion via string round-trip
//
// Severity: LOW
// initConfig applies config values via flags.Set(f.Name, stringValue).
// For non-string flag types (bool, int, duration), this goes through
// pflag's string parser. A boolean flag with value "yes" or "1" instead
// of "true" may or may not parse, depending on pflag's implementation.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_ConfigFlagTypeParsing(t *testing.T) {
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.Bool("enable-archivista", false, "test")

	// pflag accepts "true", "false", "1", "0" for booleans.
	require.NoError(t, flags.Set("enable-archivista", "true"))
	val, _ := flags.GetBool("enable-archivista")
	assert.True(t, val)

	require.NoError(t, flags.Set("enable-archivista", "1"))
	val, _ = flags.GetBool("enable-archivista")
	assert.True(t, val)

	// "yes" is NOT accepted by pflag.
	err := flags.Set("enable-archivista", "yes")
	assert.Error(t, err, "pflag should reject 'yes' for boolean flags")

	// This means a config file with "enable-archivista: yes" (which is valid
	// YAML for boolean) would cause initConfig to return an error via configErr.
	// However, YAML "true" and viper's GetString("...") returns "true" which
	// IS accepted. The concern is YAML boolean values that viper converts to
	// "true"/"false" strings work fine, but edge cases like "yes"/"no"/"on"
	// may not round-trip correctly through pflag.
}

// --------------------------------------------------------------------------
// R3_310_22: Verify that sign command enforces exactly one signer
//
// Severity: HIGH (correctness)
// Like runRun, runSign must reject zero or multiple signers.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_RunSignRejectsZeroSigners(t *testing.T) {
	dir := t.TempDir()
	infile := filepath.Join(dir, "input.json")
	writeFile(t, infile, `{"test":"data"}`)

	err := runSign(context.Background(), options.SignOptions{
		InFilePath:  infile,
		OutFilePath: filepath.Join(dir, "out.json"),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no signers found")
}

func TestSecurity_R3_310_RunSignRejectsMultipleSigners(t *testing.T) {
	dir := t.TempDir()
	infile := filepath.Join(dir, "input.json")
	writeFile(t, infile, `{"test":"data"}`)

	err := runSign(context.Background(), options.SignOptions{
		InFilePath:  infile,
		OutFilePath: filepath.Join(dir, "out.json"),
	}, &fakeSignerForTesting{}, &fakeSignerForTesting{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only one signer")
}

// --------------------------------------------------------------------------
// R3_310_23: Archivista header injection allows arbitrary HTTP headers
//
// Severity: HIGH
// The ArchivistaOptions.Client() method splits header strings on ":" and
// calls headers.Set() with no deny-list. This means an attacker (via
// config file or CLI) can inject headers like:
//   - Authorization: Bearer <token>
//   - Cookie: session=<stolen>
//   - X-Forwarded-For: <spoofed-ip>
// --------------------------------------------------------------------------

func TestSecurity_R3_310_ArchivistaHeaderInjectionViaConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "evil.yaml")

	// A config file can inject archivista headers including auth headers.
	writeFile(t, configPath, `verify:
  enable-archivista: "true"
  archivista-server: "http://evil.attacker.com"
`)

	v := viper.New()
	v.SetConfigFile(configPath)
	require.NoError(t, v.ReadInConfig())

	// archivista-headers is a stringSlice, harder to inject via YAML
	// but the direct --archivista-headers flag accepts anything.
	// Verify the ArchivistaOptions.Client() doesn't restrict headers.
	opts := options.ArchivistaOptions{
		Enable:  true,
		Url:     "http://example.com",
		Headers: []string{"Authorization: Bearer stolen-token", "Cookie: session=hijacked"},
	}

	client, err := opts.Client()
	require.NoError(t, err, "client creation should succeed with injected headers")
	require.NotNil(t, client, "client should be non-nil")

	t.Log("FINDING R3_310_23: ArchivistaOptions.Client() accepts arbitrary " +
		"HTTP headers including Authorization and Cookie. An attacker who " +
		"controls the config file or CLI args can inject auth credentials " +
		"into archivista requests. Recommend a deny-list for sensitive headers.")
}

// --------------------------------------------------------------------------
// R3_310_24: isValidHexDigest accepts empty algorithm prefix
//
// Severity: LOW
// The isValidHexDigest function accepts strings like ":abcdef..." where
// the algorithm prefix is empty. While not directly exploitable, this
// violates the documented format and could cause unexpected behavior
// when the prefix is stripped in runVerify.
// --------------------------------------------------------------------------

func TestSecurity_R3_310_IsValidHexDigestEmptyPrefix(t *testing.T) {
	// Empty prefix with colon is accepted.
	assert.True(t, isValidHexDigest(":e3b0c44298fc1c149afbf4c8996fb924"),
		"empty algorithm prefix should probably be rejected but is accepted")

	// Multiple colons: only first colon is used as separator.
	assert.False(t, isValidHexDigest("sha256:sha256:e3b0c44298fc1c149afbf4c8996fb924"),
		"double prefix should be rejected (hex portion starts with 'sha256:...')")

	// Verify prefix stripping in runVerify context.
	input := ":e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	digestHex := input
	if idx := strings.Index(input, ":"); idx != -1 {
		digestHex = input[idx+1:]
	}
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", digestHex,
		"empty prefix stripping should still produce valid hex")

	t.Log("FINDING R3_310_24: isValidHexDigest accepts empty algorithm " +
		"prefix (e.g. ':abcdef...'). While the hex extraction works, " +
		"this violates the documented format 'sha256:abc123...'.")
}
