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

package cli

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetCmdDownloadAndInstall(t *testing.T) {
	executable := []byte("#!/bin/sh\necho trusted fixture\n")
	artifact := tarGZTool(t, "fixture", executable)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		_, err := w.Write(artifact)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	home := t.TempDir()
	manifest := fixtureManifest(server.URL+"/fixture.tar.gz", bytesSHA256(artifact), bytesSHA256(executable))
	cmd := fixtureGetCmd(manifest, server.Client(), home)
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"fixture"})
	require.NoError(t, cmd.Execute())

	installed := filepath.Join(home, defaultToolDir, "fixture")
	got, err := os.ReadFile(installed)
	require.NoError(t, err)
	assert.Equal(t, executable, got)
	info, err := os.Stat(installed)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode().Perm()&0o111, "installed tool must be executable")
	assert.Contains(t, output.String(), "Installed fixture v1.2.3 to "+installed)
	assert.Contains(t, output.String(), filepath.Join(home, defaultToolDir)+":$PATH")
}

func TestGetCmdSHA256MismatchFailsClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte("untrusted bytes"))
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	dest := filepath.Join(t.TempDir(), "bin")
	manifest := fixtureManifest(server.URL+"/fixture", bytesSHA256([]byte("expected bytes")), "")
	cmd := fixtureGetCmd(manifest, server.Client(), t.TempDir())
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"fixture", "--dest", dest})
	err := cmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SHA-256 mismatch")
	assert.NoFileExists(t, filepath.Join(dest, "fixture"))

	entries, readErr := os.ReadDir(dest)
	require.NoError(t, readErr)
	assert.Empty(t, entries, "checksum failure must remove the temporary download")
}

func TestGetCmdUnknownToolListsAvailableTools(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unknown tool must not make a network request")
		http.Error(w, "unexpected request", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	manifest := fixtureManifest(server.URL+"/fixture", bytesSHA256([]byte("fixture")), "")
	cmd := fixtureGetCmd(manifest, server.Client(), t.TempDir())
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"not-a-tool"})
	err := cmd.Execute()
	require.Error(t, err)
	assert.EqualError(t, err, `unknown tool "not-a-tool" (available tools: fixture)`)
}

func TestGetCmdVerifyPassAndFail(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "--verify must not download", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	executable := []byte("trusted installed bytes")
	manifest := fixtureManifest(server.URL+"/fixture", bytesSHA256(executable), "")
	dest := filepath.Join(t.TempDir(), "bin")
	require.NoError(t, os.MkdirAll(dest, 0o755))
	installed := filepath.Join(dest, "fixture")
	require.NoError(t, os.WriteFile(installed, executable, 0o755))

	passCmd := fixtureGetCmd(manifest, server.Client(), t.TempDir())
	var output bytes.Buffer
	passCmd.SetOut(&output)
	passCmd.SetErr(&bytes.Buffer{})
	passCmd.SetArgs([]string{"fixture", "--dest", dest, "--verify"})
	require.NoError(t, passCmd.Execute())
	assert.Contains(t, output.String(), "Verified "+installed)
	assert.Zero(t, requests.Load(), "--verify must not download")

	require.NoError(t, os.WriteFile(installed, []byte("tampered"), 0o755))
	failCmd := fixtureGetCmd(manifest, server.Client(), t.TempDir())
	failCmd.SetOut(&bytes.Buffer{})
	failCmd.SetErr(&bytes.Buffer{})
	failCmd.SetArgs([]string{"fixture", "--dest", dest, "--verify"})
	err := failCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SHA-256 mismatch for installed fixture")
	assert.Zero(t, requests.Load(), "failed --verify must not download")
}

func TestEmbeddedGetManifestHasValidPins(t *testing.T) {
	manifest, err := parseToolManifest(embeddedGetManifest)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"syft", "zarf"}, manifestToolNames(manifest))
	for tool, versions := range manifest {
		for version, platforms := range versions {
			for platform, download := range platforms {
				parts := strings.Split(platform, "/")
				require.Len(t, parts, 2)
				require.NoError(t, validateToolDownload(tool, version, parts[0], parts[1], download))
			}
		}
	}
}

func manifestToolNames(manifest toolManifest) []string {
	names := make([]string, 0, len(manifest))
	for name := range manifest {
		names = append(names, name)
	}
	return names
}

func fixtureGetCmd(manifest []byte, client *http.Client, home string) *cobra.Command {
	return newGetCmd(getCommandConfig{
		manifest: manifest,
		goos:     "linux",
		goarch:   "amd64",
		client:   client,
		homeDir: func() (string, error) {
			return home, nil
		},
	})
}

func fixtureManifest(downloadURL, artifactSHA256, executableSHA256 string) []byte {
	executablePin := ""
	if executableSHA256 != "" {
		executablePin = "      executable_sha256: " + executableSHA256 + "\n"
	}
	return []byte(fmt.Sprintf(`fixture:
  v1.2.3:
    linux/amd64:
      url: %s
      sha256: %s
%s`, downloadURL, artifactSHA256, executablePin))
}

// TestGetCmdInstallsFromZIPForWindows covers the .zip extraction path the
// Windows Syft release uses: fixture.exe inside a ZIP, resolved with
// goos=windows, must extract, match the executable pin, and install as
// fixture.exe.
func TestGetCmdInstallsFromZIPForWindows(t *testing.T) {
	executable := []byte("MZ fake windows executable")
	artifact := zipTool(t, "fixture.exe", executable)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(artifact)
		assert.NoError(t, err)
	}))
	t.Cleanup(server.Close)

	home := t.TempDir()
	manifest := []byte(fmt.Sprintf(`fixture:
  v1.2.3:
    windows/amd64:
      url: %s
      sha256: %s
      executable_sha256: %s
`, server.URL+"/fixture.zip", bytesSHA256(artifact), bytesSHA256(executable)))
	cmd := newGetCmd(getCommandConfig{
		manifest: manifest,
		goos:     goosWindows,
		goarch:   "amd64",
		client:   server.Client(),
		homeDir: func() (string, error) {
			return home, nil
		},
	})
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"fixture"})
	require.NoError(t, cmd.Execute())

	installed := filepath.Join(home, defaultToolDir, "fixture.exe")
	got, err := os.ReadFile(installed)
	require.NoError(t, err)
	assert.Equal(t, executable, got)
}

func zipTool(t *testing.T, name string, contents []byte) []byte {
	t.Helper()
	var artifact bytes.Buffer
	zipWriter := zip.NewWriter(&artifact)
	entry, err := zipWriter.Create(name)
	require.NoError(t, err)
	_, err = entry.Write(contents)
	require.NoError(t, err)
	require.NoError(t, zipWriter.Close())
	return artifact.Bytes()
}

func tarGZTool(t *testing.T, name string, contents []byte) []byte {
	t.Helper()
	var artifact bytes.Buffer
	gzipWriter := gzip.NewWriter(&artifact)
	tarWriter := tar.NewWriter(gzipWriter)
	require.NoError(t, tarWriter.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o755,
		Size: int64(len(contents)),
	}))
	_, err := tarWriter.Write(contents)
	require.NoError(t, err)
	require.NoError(t, tarWriter.Close())
	require.NoError(t, gzipWriter.Close())
	return artifact.Bytes()
}

func bytesSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// TestReplaceInstalledToolWindowsRestoresOnFailure pins the Windows swap
// contract: when the final rename fails (staged file missing simulates an
// antivirus lock / race), the previous known-good binary must be restored,
// never left deleted.
func TestReplaceInstalledToolWindowsRestoresOnFailure(t *testing.T) {
	dir := t.TempDir()
	installed := filepath.Join(dir, "fixture.exe")
	require.NoError(t, os.WriteFile(installed, []byte("known-good"), 0o755))

	err := replaceInstalledTool(filepath.Join(dir, "missing-staged"), installed, goosWindows)
	require.Error(t, err, "swap must fail when the staged executable is unavailable")

	got, readErr := os.ReadFile(installed)
	require.NoError(t, readErr, "previous binary must still exist after a failed swap")
	assert.Equal(t, []byte("known-good"), got)
	_, statErr := os.Stat(installed + ".old")
	assert.True(t, os.IsNotExist(statErr), "no .old backup may linger after restore")
}
