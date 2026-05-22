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

package cli

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Ensure dynamic signer flags (--signer-file-key-path) are registered.
	_ "github.com/aflock-ai/rookery/plugins/attestors/environment"
	_ "github.com/aflock-ai/rookery/plugins/attestors/git"
	_ "github.com/aflock-ai/rookery/plugins/attestors/material"
	_ "github.com/aflock-ai/rookery/plugins/attestors/product"
	_ "github.com/aflock-ai/rookery/plugins/signers/file"
)

// =============================================================================
// parseSubjectFlags unit tests
// =============================================================================

func TestParseSubjectFlags_Empty(t *testing.T) {
	got, err := parseSubjectFlags(nil)
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = parseSubjectFlags([]string{})
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestParseSubjectFlags_BareName_SynthesisesSHA256(t *testing.T) {
	got, err := parseSubjectFlags([]string{"product:62ee1b9d-aaaa-bbbb-cccc-dddddddddddd"})
	require.NoError(t, err)
	require.Len(t, got, 1)

	digest, ok := got["product:62ee1b9d-aaaa-bbbb-cccc-dddddddddddd"]
	require.True(t, ok, "subject name preserved verbatim")

	expected := sha256.Sum256([]byte("product:62ee1b9d-aaaa-bbbb-cccc-dddddddddddd"))
	assert.Equal(t,
		hex.EncodeToString(expected[:]),
		digest[cryptoutil.DigestValue{Hash: crypto.SHA256}],
	)
}

func TestParseSubjectFlags_ExplicitDigest(t *testing.T) {
	got, err := parseSubjectFlags([]string{
		"binary=sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	})
	require.NoError(t, err)
	require.Len(t, got, 1)

	digest, ok := got["binary"]
	require.True(t, ok)
	assert.Equal(t,
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		digest[cryptoutil.DigestValue{Hash: crypto.SHA256}],
	)
}

func TestParseSubjectFlags_Mixed(t *testing.T) {
	got, err := parseSubjectFlags([]string{
		"product:62ee1b9d",
		"aws:account:339150376714",
		"binary=sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
	})
	require.NoError(t, err)
	require.Len(t, got, 3)

	// Bare names synthesise sha256 of themselves, preserving colons in the name.
	_, ok := got["product:62ee1b9d"]
	assert.True(t, ok)
	_, ok = got["aws:account:339150376714"]
	assert.True(t, ok, "colon inside subject name is not a digest separator")
	_, ok = got["binary"]
	assert.True(t, ok)
}

func TestParseSubjectFlags_DuplicateName_Rejected(t *testing.T) {
	_, err := parseSubjectFlags([]string{
		"product:62ee1b9d",
		"product:62ee1b9d",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate name")
}

func TestParseSubjectFlags_WhitespaceSkipped(t *testing.T) {
	got, err := parseSubjectFlags([]string{
		"product:abc",
		"   ",
		"",
	})
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestParseSubjectFlags_InvalidDigest(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"empty name", "=sha256:aabb"},
		{"empty digest", "name="},
		{"missing colon", "name=notadigest"},
		{"empty hex", "name=sha256:"},
		{"non-hex digest", "name=sha256:zzzzzz"},
		{"unsupported hash", "name=bogushash:abab"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSubjectFlags([]string{tc.in})
			require.Error(t, err, tc.in)
		})
	}
}

// =============================================================================
// End-to-end: --subjects flag surfaces in the signed in-toto statement
// =============================================================================

// TestRunFlag_SubjectsAppearInStatement verifies that running cilock with
// --subjects results in the user-supplied subjects being present in the
// in-toto statement subject[] array of the collection envelope.
func TestRunFlag_SubjectsAppearInStatement(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	outfile := filepath.Join(dir, "attestation.json")

	// Explicitly disable the git attestor (default list includes it) — tests
	// run in a tmpdir which isn't a git repo, and git would fail the run.
	err := executeCmd(
		"run",
		"--step", "prowler-scan",
		"--signer-file-key-path", keyPath,
		"--outfile", outfile,
		"--attestations", "environment",
		"--subjects", "product:62ee1b9d-aaaa-bbbb-cccc-dddddddddddd",
		"--subjects", "aws:account:339150376714",
		"--subjects", "binary=sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		"--", "echo", "hello",
	)
	require.NoError(t, err)

	stmt := decodeStatement(t, outfile)

	names := make(map[string]intoto.Subject, len(stmt.Subject))
	for _, s := range stmt.Subject {
		names[s.Name] = s
	}

	// Bare-name subjects round-trip verbatim, with synthetic sha256 digests.
	prod, ok := names["product:62ee1b9d-aaaa-bbbb-cccc-dddddddddddd"]
	require.True(t, ok, "product:<uuid> subject missing; got %v", keysOf(names))
	expected := sha256.Sum256([]byte("product:62ee1b9d-aaaa-bbbb-cccc-dddddddddddd"))
	assert.Equal(t, hex.EncodeToString(expected[:]), prod.Digest["sha256"])

	aws, ok := names["aws:account:339150376714"]
	require.True(t, ok)
	assert.NotEmpty(t, aws.Digest["sha256"])

	// Explicit digest form stores the digest verbatim.
	bin, ok := names["binary"]
	require.True(t, ok)
	assert.Equal(t,
		"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		bin.Digest["sha256"],
	)
}

// TestRunFlag_SubjectsAreAdditive verifies that --subjects does NOT displace
// the subjects discovered by attestors — it's purely additive. Uses no
// attestors beyond the always-on product/material pair, then runs `echo` so
// commandrun doesn't produce any artifact subjects, and asserts the user's
// subject shows up alongside whatever product attestor reports.
func TestRunFlag_SubjectsAreAdditive(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	outfile := filepath.Join(dir, "attestation.json")

	// Create a file under the working dir so the product attestor has
	// something to attest — exercises the "additive" path where the
	// collection already has real subjects.
	workDir := filepath.Join(dir, "work")
	require.NoError(t, os.MkdirAll(workDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(workDir, "artifact.txt"), []byte("hello world"), 0o600))

	err := executeCmd(
		"run",
		"--step", "build",
		"--signer-file-key-path", keyPath,
		"--outfile", outfile,
		"--workingdir", workDir,
		"--attestations", "environment",
		"--subjects", "product:62ee1b9d",
		"--", "echo", "hello",
	)
	require.NoError(t, err)

	stmt := decodeStatement(t, outfile)
	require.NotEmpty(t, stmt.Subject, "statement must contain at least one subject")

	found := false
	for _, s := range stmt.Subject {
		if s.Name == "product:62ee1b9d" {
			found = true
			break
		}
	}
	assert.True(t, found, "user-supplied subject must appear in the statement alongside attestor-produced subjects; got %v", subjectNames(stmt.Subject))
}

// TestRunFlag_NoSubjectsFlag_BackwardCompat ensures that omitting --subjects
// leaves the attestation output unchanged from the pre-flag behaviour: only
// attestor-discovered subjects populate the statement.
func TestRunFlag_NoSubjectsFlag_BackwardCompat(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	outfile := filepath.Join(dir, "attestation.json")

	err := executeCmd(
		"run",
		"--step", "build",
		"--signer-file-key-path", keyPath,
		"--outfile", outfile,
		"--attestations", "environment",
		"--", "echo", "hello",
	)
	require.NoError(t, err)

	stmt := decodeStatement(t, outfile)
	for _, s := range stmt.Subject {
		// No user-supplied subjects ⇒ no bare-name entries like "product:*".
		assert.False(t, strings.HasPrefix(s.Name, "product:"),
			"unexpected injected subject %q found when --subjects not passed", s.Name)
	}
}

func TestRunFlag_InvalidSubjects_Fails(t *testing.T) {
	dir := t.TempDir()
	keyPath := generateTestKey(t, dir)
	outfile := filepath.Join(dir, "attestation.json")

	err := executeCmd(
		"run",
		"--step", "build",
		"--signer-file-key-path", keyPath,
		"--outfile", outfile,
		"--attestations", "environment",
		"--subjects", "name=sha256:zzzzzzzz", // non-hex digest
		"--", "echo", "hello",
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--subjects")
}

// =============================================================================
// Helpers
// =============================================================================

func decodeStatement(t *testing.T, envelopePath string) intoto.Statement {
	t.Helper()

	raw, err := os.ReadFile(envelopePath) //nolint:gosec // test fixture path
	require.NoError(t, err)

	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(raw, &env))

	// dsse.Envelope.Payload is []byte; Go's json package has already
	// base64-decoded it for us. It now holds the raw in-toto statement JSON.
	var stmt intoto.Statement
	require.NoError(t, json.Unmarshal(env.Payload, &stmt))
	return stmt
}

func subjectNames(subjects []intoto.Subject) []string {
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		out = append(out, s.Name)
	}
	return out
}

func keysOf(m map[string]intoto.Subject) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
