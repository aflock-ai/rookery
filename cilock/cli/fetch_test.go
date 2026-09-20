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

// jade:ring local

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fetchTestPlatform is a platform URL that can never be resolved or contacted.
// Passing it explicitly keeps these tests off the developer's real credential
// store and off network discovery: the platform is never the same origin as the
// httptest Archivista, so no session bearer is ever looked up.
const fetchTestPlatform = "https://platform.example.invalid"

// storedAttestationBytes builds an envelope the way a SERVER stored it, not the
// way Go re-marshals one: pretty-printed, keys out of struct order, and
// carrying a member dsse.Envelope has no field for. `cilock fetch` must
// reproduce these bytes exactly or the saved file will not re-hash to its
// gitoid.
func storedAttestationBytes(t *testing.T, predicate string) []byte {
	t.Helper()
	stmt := fmt.Sprintf(`{"_type":"https://in-toto.io/Statement/v0.1","subject":[{"name":"x","digest":{"sha256":"abc"}}],"predicateType":"https://example.com/test","predicate":%s}`, predicate)
	b64 := base64.StdEncoding.EncodeToString([]byte(stmt))
	return []byte(fmt.Sprintf(`{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "%s",
  "signatures": [{"keyid": "k", "sig": "c2ln"}],
  "extensions": {"storedBy": "archivista"}
}
`, b64))
}

// fetchTestServer serves the given gitoid→bytes map on /download/<gitoid> and
// 404s everything else, like Archivista does.
func fetchTestServer(t *testing.T, objects map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/download/")
		body, ok := objects[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func fetchArgs(srvURL string, rest ...string) []string {
	return append([]string{"fetch", "--platform-url", fetchTestPlatform, "--archivista-url", srvURL}, rest...)
}

// --- the exact-bytes contract -------------------------------------------------

func TestFetchWritesTheExactStoredBytesToStdout(t *testing.T) {
	stored := storedAttestationBytes(t, `{"ok":true}`)
	gid := bundleTestGitoid(stored)
	srv := fetchTestServer(t, map[string][]byte{gid: stored})

	stdout, _, err := executeCmdOutput(fetchArgs(srv.URL, gid)...)
	require.NoError(t, err)
	require.Equal(t, string(stored), stdout, "stdout must be the stored bytes byte-for-byte")
	require.Equal(t, gid, bundleTestGitoid([]byte(stdout)), "re-hashing stdout must reproduce the gitoid")
}

func TestFetchOutfileReHashesToTheGitoid(t *testing.T) {
	stored := storedAttestationBytes(t, `{"ok":true}`)
	gid := bundleTestGitoid(stored)
	srv := fetchTestServer(t, map[string][]byte{gid: stored})
	out := filepath.Join(t.TempDir(), "att.json")

	_, _, err := executeCmdOutput(fetchArgs(srv.URL, gid, "-o", out)...)
	require.NoError(t, err)

	got, err := os.ReadFile(out) //nolint:gosec // G304: test-controlled temp path
	require.NoError(t, err)
	require.Equal(t, stored, got)
	require.Equal(t, gid, bundleTestGitoid(got), "the saved file must re-hash to the gitoid it was fetched by")
}

// --- destination selection ----------------------------------------------------

func TestFetchRefusesMultipleGitoidsWithoutOutdir(t *testing.T) {
	a := bundleTestGitoid([]byte("a"))
	b := bundleTestGitoid([]byte("b"))
	err := executeCmd("fetch", a, b)
	require.Error(t, err)
	require.Contains(t, err.Error(), "--outdir", "the error must name the flag that fixes it")
}

func TestFetchRefusesMultipleGitoidsWithOutfile(t *testing.T) {
	a := bundleTestGitoid([]byte("a"))
	b := bundleTestGitoid([]byte("b"))
	err := executeCmd("fetch", a, b, "-o", filepath.Join(t.TempDir(), "x.json"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "--outdir")
}

func TestFetchRefusesOutfileAndOutdirTogether(t *testing.T) {
	dir := t.TempDir()
	err := executeCmd("fetch", bundleTestGitoid([]byte("a")), "-o", filepath.Join(dir, "x.json"), "--outdir", dir)
	require.Error(t, err)
	require.Contains(t, err.Error(), "outdir")
}

func TestFetchOutdirWritesOneFilePerGitoidWithAWindowsSafeName(t *testing.T) {
	first := storedAttestationBytes(t, `{"n":1}`)
	second := storedAttestationBytes(t, `{"n":2}`)
	gidA := bundleTestGitoid(first)
	gidB := bundleTestGitoid(second)
	srv := fetchTestServer(t, map[string][]byte{gidA: first, gidB: second})
	dir := t.TempDir()

	_, _, err := executeCmdOutput(fetchArgs(srv.URL, gidA, gidB, "--outdir", dir)...)
	require.NoError(t, err)

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, e := range entries {
		name := e.Name()
		// Windows has no ':' in filenames, and a path separator would escape
		// the chosen directory entirely.
		require.NotContains(t, name, ":", "filename must be safe on Windows")
		require.NotContains(t, name, "/")
		require.NotContains(t, name, `\`)
		require.NotContains(t, name, "..")
	}
	for gid, want := range map[string][]byte{gidA: first, gidB: second} {
		got, err := os.ReadFile(filepath.Join(dir, gid+".dsse.json")) //nolint:gosec // G304: test-controlled temp path
		require.NoError(t, err, "expected a file named after the gitoid")
		require.Equal(t, want, got)
		require.Equal(t, gid, bundleTestGitoid(got))
	}
}

// --- payload / predicate projections -----------------------------------------

func TestFetchPayloadWritesTheDecodedStatement(t *testing.T) {
	stored := storedAttestationBytes(t, `{"ok":true}`)
	gid := bundleTestGitoid(stored)
	srv := fetchTestServer(t, map[string][]byte{gid: stored})

	stdout, _, err := executeCmdOutput(fetchArgs(srv.URL, gid, "--payload")...)
	require.NoError(t, err)

	var stmt struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	require.NoError(t, json.Unmarshal([]byte(stdout), &stmt))
	require.Equal(t, "https://in-toto.io/Statement/v0.1", stmt.Type)
	require.Equal(t, "https://example.com/test", stmt.PredicateType)
	require.JSONEq(t, `{"ok":true}`, string(stmt.Predicate))
}

func TestFetchPredicateWritesOnlyThePredicate(t *testing.T) {
	stored := storedAttestationBytes(t, `{"ok":true,"nested":{"a":1}}`)
	gid := bundleTestGitoid(stored)
	srv := fetchTestServer(t, map[string][]byte{gid: stored})

	stdout, _, err := executeCmdOutput(fetchArgs(srv.URL, gid, "--predicate")...)
	require.NoError(t, err)
	require.JSONEq(t, `{"ok":true,"nested":{"a":1}}`, stdout)
	require.NotContains(t, stdout, "predicateType", "only the predicate member, not the statement around it")
}

func TestFetchPayloadAndPredicateAreMutuallyExclusive(t *testing.T) {
	err := executeCmd("fetch", bundleTestGitoid([]byte("a")), "--payload", "--predicate")
	require.Error(t, err)
	require.Contains(t, err.Error(), "predicate")
}

func TestFetchPredicateFailsAndWritesNothingWhenAbsent(t *testing.T) {
	// A DSSE envelope whose payload is not an in-toto statement at all.
	b64 := base64.StdEncoding.EncodeToString([]byte(`{"not":"a statement"}`))
	stored := []byte(fmt.Sprintf(`{"payloadType":"application/x-other","payload":"%s","signatures":[]}`, b64))
	gid := bundleTestGitoid(stored)
	srv := fetchTestServer(t, map[string][]byte{gid: stored})
	out := filepath.Join(t.TempDir(), "p.json")

	_, _, err := executeCmdOutput(fetchArgs(srv.URL, gid, "--predicate", "-o", out)...)
	require.Error(t, err)
	require.NoFileExists(t, out, "a missing predicate must not leave an empty file behind")
}

// --- integrity: nothing is written unless verification passed -----------------

func TestFetchLeavesNoFileOnAGitoidMismatch(t *testing.T) {
	stored := storedAttestationBytes(t, `{"ok":true}`)
	// The server answers every path with bytes that do NOT content-address to
	// the requested gitoid — an on-path server swapping in other evidence.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(stored)
	}))
	t.Cleanup(srv.Close)

	requested := bundleTestGitoid([]byte("a different object entirely"))
	out := filepath.Join(t.TempDir(), "att.json")
	stdout, _, err := executeCmdOutput(fetchArgs(srv.URL, requested, "-o", out)...)
	require.Error(t, err)
	require.Contains(t, err.Error(), requested, "the failure must name the gitoid")
	require.Contains(t, err.Error(), "gitoid mismatch")
	require.NoFileExists(t, out, "unverified bytes must never reach the destination")
	require.Empty(t, stdout)
}

func TestFetchLeavesNoFileOnANotFound(t *testing.T) {
	srv := fetchTestServer(t, nil)
	gid := bundleTestGitoid([]byte("absent"))
	out := filepath.Join(t.TempDir(), "att.json")

	_, _, err := executeCmdOutput(fetchArgs(srv.URL, gid, "-o", out)...)
	require.Error(t, err)
	require.Contains(t, err.Error(), gid, "the failure must name the gitoid")
	require.NoFileExists(t, out)
}

func TestFetchOutdirLeavesNoFileWhenOneGitoidFails(t *testing.T) {
	good := storedAttestationBytes(t, `{"n":1}`)
	gidGood := bundleTestGitoid(good)
	gidMissing := bundleTestGitoid([]byte("absent"))
	srv := fetchTestServer(t, map[string][]byte{gidGood: good})
	dir := t.TempDir()

	_, _, err := executeCmdOutput(fetchArgs(srv.URL, gidGood, gidMissing, "--outdir", dir)...)
	require.Error(t, err)
	require.Contains(t, err.Error(), gidMissing)
	require.NoFileExists(t, filepath.Join(dir, gidMissing+".dsse.json"))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.NotContains(t, e.Name(), "tmp", "no temp scratch file may survive a failure: %s", e.Name())
		require.True(t, strings.HasSuffix(e.Name(), ".dsse.json"), "unexpected leftover %s", e.Name())
	}
}

// --- existing-file policy (matches `cilock policy draft`) ---------------------

func TestFetchRefusesAnExistingOutfileWithoutForce(t *testing.T) {
	stored := storedAttestationBytes(t, `{"ok":true}`)
	gid := bundleTestGitoid(stored)
	srv := fetchTestServer(t, map[string][]byte{gid: stored})
	out := filepath.Join(t.TempDir(), "att.json")
	require.NoError(t, os.WriteFile(out, []byte("existing content"), 0o600))

	_, _, err := executeCmdOutput(fetchArgs(srv.URL, gid, "-o", out)...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "--force")
	// The refusal must name a flag `fetch` actually has. It shares the check
	// with `cilock policy draft`, whose flag is --output; a message telling a
	// fetch user to "choose another --output" sends them hunting through a
	// --help that has no such flag.
	require.Contains(t, err.Error(), "--outfile")
	require.NotContains(t, err.Error(), "--output ")
	require.False(t, strings.HasSuffix(err.Error(), "--output"))

	got, err := os.ReadFile(out) //nolint:gosec // G304: test-controlled temp path
	require.NoError(t, err)
	require.Equal(t, "existing content", string(got), "the existing file must be untouched")
}

func TestFetchRefusesAnExistingOutdirFileAndNamesOutdir(t *testing.T) {
	stored := storedAttestationBytes(t, `{"ok":true}`)
	gid := bundleTestGitoid(stored)
	srv := fetchTestServer(t, map[string][]byte{gid: stored})
	dir := t.TempDir()
	existing := filepath.Join(dir, gid+".dsse.json")
	require.NoError(t, os.WriteFile(existing, []byte("existing content"), 0o600))

	_, _, err := executeCmdOutput(fetchArgs(srv.URL, gid, "--outdir", dir)...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "--force")
	require.Contains(t, err.Error(), "--outdir")

	got, err := os.ReadFile(existing) //nolint:gosec // G304: test-controlled temp path
	require.NoError(t, err)
	require.Equal(t, "existing content", string(got))
}

func TestFetchForceOverwritesAnExistingOutfile(t *testing.T) {
	stored := storedAttestationBytes(t, `{"ok":true}`)
	gid := bundleTestGitoid(stored)
	srv := fetchTestServer(t, map[string][]byte{gid: stored})
	out := filepath.Join(t.TempDir(), "att.json")
	require.NoError(t, os.WriteFile(out, []byte("existing content"), 0o600))

	_, _, err := executeCmdOutput(fetchArgs(srv.URL, gid, "-o", out, "--force")...)
	require.NoError(t, err)
	got, err := os.ReadFile(out) //nolint:gosec // G304: test-controlled temp path
	require.NoError(t, err)
	require.Equal(t, stored, got)
}

func TestFetchForceKeepsTheExistingFileWhenTheFetchFails(t *testing.T) {
	srv := fetchTestServer(t, nil)
	gid := bundleTestGitoid([]byte("absent"))
	out := filepath.Join(t.TempDir(), "att.json")
	require.NoError(t, os.WriteFile(out, []byte("existing content"), 0o600))

	_, _, err := executeCmdOutput(fetchArgs(srv.URL, gid, "-o", out, "--force")...)
	require.Error(t, err)
	got, err := os.ReadFile(out) //nolint:gosec // G304: test-controlled temp path
	require.NoError(t, err)
	require.Equal(t, "existing content", string(got), "--force must not destroy the old file on a failed fetch")
}

// TestWriteFetchedFileRefusesToClobberWithoutForce exercises the write
// primitive directly. runFetch pre-flights the destination before it downloads
// anything, which means the O_EXCL refusal inside writeFetchedFile is never the
// first thing to fire in an end-to-end test — and an untested last line of
// defence is one that quietly stops existing. This is the race case: something
// created the path (or a symlink to somewhere else) after the pre-flight said
// it was free.
func TestWriteFetchedFileRefusesToClobberWithoutForce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.json")
	require.NoError(t, os.WriteFile(path, []byte("old"), 0o600))

	err := writeFetchedFile(path, []byte("new"), false)
	require.ErrorContains(t, err, "--force")
	got, err := os.ReadFile(path) //nolint:gosec // G304: test-controlled temp path
	require.NoError(t, err)
	require.Equal(t, "old", string(got))

	require.NoError(t, writeFetchedFile(path, []byte("new"), true))
	got, err = os.ReadFile(path) //nolint:gosec // G304: test-controlled temp path
	require.NoError(t, err)
	require.Equal(t, "new", string(got))
}

// --- argument format ----------------------------------------------------------

func TestFetchRejectsANonGitoidArgument(t *testing.T) {
	valid := bundleTestGitoid([]byte("a"))
	cases := []struct {
		name string
		arg  string
		hint string
	}{
		{"gitoid URI", "gitoid:blob:sha256:" + valid, valid},
		{"bare short hex", "abc123", ""},
		{"sha256 prefix", "sha256:" + valid, ""},
		{"uppercase", strings.ToUpper(valid), ""},
		{"path traversal", "../../etc/passwd", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := executeCmd("fetch", c.arg)
			require.Error(t, err)
			require.Contains(t, err.Error(), "gitoid")
			require.Contains(t, err.Error(), "64", "the message must state the expected form")
			if c.hint != "" {
				require.Contains(t, err.Error(), c.hint, "a gitoid URI should be told which part to pass")
			}
		})
	}
}

func TestFetchRequiresAtLeastOneGitoid(t *testing.T) {
	err := executeCmd("fetch")
	require.Error(t, err)
}

// --- trust language -----------------------------------------------------------

func TestFetchHelpSaysItDoesNotEstablishSignerTrust(t *testing.T) {
	stdout, _, err := executeCmdOutput("fetch", "--help")
	require.NoError(t, err)
	lower := strings.ToLower(stdout)
	require.Contains(t, lower, "content address", "help must say what IS verified")
	require.Contains(t, lower, "does not verify the signature", "help must say what is NOT verified")
	require.Contains(t, lower, "cilock verify", "help must point at the command that establishes signer trust")
}

// --- the library contract the command depends on ------------------------------

// TestFetchIsNotAwareOfAnyPredicateType pins the product requirement that this
// is a fetch for ANY attestation: the implementation must contain no
// predicate-, SARIF- or findings-specific branch.
func TestFetchIsNotAwareOfAnyPredicateType(t *testing.T) {
	src, err := os.ReadFile("fetch.go")
	require.NoError(t, err)
	for _, forbidden := range []string{"sarif", "SARIF", "finding", "Finding"} {
		require.NotContains(t, string(src), forbidden,
			"cilock fetch must stay generic over attestation type; found %q", forbidden)
	}
}

// TestFetchWritesNothingToStdoutOnFailure guards the pipe case: `cilock fetch
// <gitoid> > file.json` must not produce a truncated file from a partial write.
func TestFetchWritesNothingToStdoutOnFailure(t *testing.T) {
	stored := storedAttestationBytes(t, `{"ok":true}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(stored)
	}))
	t.Cleanup(srv.Close)

	var stdout bytes.Buffer
	cmd := New()
	cmd.SetArgs(fetchArgs(srv.URL, bundleTestGitoid([]byte("mismatch"))))
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	require.Error(t, cmd.Execute())
	require.Empty(t, stdout.String())
}
