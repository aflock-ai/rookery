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
	"compress/gzip"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	defaultToolDir = ".cilock/bin"
	missingSHA256  = "REPLACE_ME_SHA256"
	goosWindows    = "windows"

	// maxToolSize caps download and extraction sizes. The release artifact is
	// SHA-256-verified before extraction, so a decompression bomb requires a
	// compromised pin; the cap is defense in depth on top of that.
	maxToolSize = 2 << 30 // 2 GiB
)

//go:embed get-manifest.yaml
var embeddedGetManifest []byte

// toolManifest is deliberately keyed tool -> version -> os/arch. Keeping the
// version in the data, rather than in Go code, makes every URL and checksum
// reviewable in one place when a trusted tool is upgraded.
type toolManifest map[string]map[string]map[string]toolDownload

type toolDownload struct {
	URL              string `yaml:"url"`
	SHA256           string `yaml:"sha256"`
	ExecutableSHA256 string `yaml:"executable_sha256,omitempty"`
}

type getCommandConfig struct {
	manifest []byte
	goos     string
	goarch   string
	client   *http.Client
	homeDir  func() (string, error)
}

// GetCmd is `cilock get <tool>` — install a known trusted tool only after its
// release artifact matches the SHA-256 pin embedded in this cilock binary.
func GetCmd() *cobra.Command {
	return newGetCmd(getCommandConfig{
		manifest: embeddedGetManifest,
		goos:     runtime.GOOS,
		goarch:   runtime.GOARCH,
		client: &http.Client{
			Timeout: 10 * time.Minute,
		},
		homeDir: os.UserHomeDir,
	})
}

func newGetCmd(cfg getCommandConfig) *cobra.Command {
	var (
		destination string
		verifyOnly  bool
	)
	cmd := &cobra.Command{
		Use:   "get <tool>",
		Short: "Download and install SHA-256-pinned trusted tooling",
		Long: `get downloads a version pinned in cilock's embedded trusted-tool manifest,
verifies the release artifact before installing it, and fails closed if the
pin is absent or does not match. Use --verify to hash an existing installation
without downloading anything.`,
		Example: `  # Install the pinned Syft release to $HOME/.cilock/bin
  cilock get syft

  # Install Zarf in a different bin directory
  cilock get zarf --dest ./bin

  # Verify the installed Syft executable without downloading
  cilock get syft --verify`,
		DisableAutoGenTag: true,
		SilenceErrors:     true,
		SilenceUsage:      true,
		Args:              cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifest, err := parseToolManifest(cfg.manifest)
			if err != nil {
				return err
			}

			tool := strings.ToLower(args[0])
			version, download, err := resolveToolDownload(manifest, tool, cfg.goos, cfg.goarch)
			if err != nil {
				return err
			}
			if err := validateToolDownload(tool, version, cfg.goos, cfg.goarch, download); err != nil {
				return err
			}

			destDir, err := resolveToolDestination(destination, cfg.homeDir)
			if err != nil {
				return err
			}
			installedPath := filepath.Join(destDir, toolExecutableName(tool, cfg.goos))
			if verifyOnly {
				return verifyInstalledTool(cmd.OutOrStdout(), installedPath, tool, version, download)
			}

			if err := downloadAndInstallTool(cmd.Context(), cfg.client, installedPath, tool, version, cfg.goos, download); err != nil {
				return err
			}
			return writeToolInstallResult(cmd.OutOrStdout(), installedPath, destDir, tool, version, cfg.goos)
		},
	}
	cmd.Flags().StringVar(&destination, "dest", "", "Installation directory (default $HOME/.cilock/bin)")
	cmd.Flags().BoolVar(&verifyOnly, "verify", false, "Verify the installed binary against its embedded SHA-256 pin without downloading")
	return cmd
}

func parseToolManifest(data []byte) (toolManifest, error) {
	var manifest toolManifest
	if err := yaml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse embedded trusted-tool manifest: %w", err)
	}
	if len(manifest) == 0 {
		return nil, fmt.Errorf("embedded trusted-tool manifest is empty")
	}
	return manifest, nil
}

func resolveToolDownload(manifest toolManifest, tool, goos, goarch string) (string, toolDownload, error) {
	versions, ok := manifest[tool]
	if !ok {
		available := make([]string, 0, len(manifest))
		for name := range manifest {
			available = append(available, name)
		}
		sort.Strings(available)
		return "", toolDownload{}, fmt.Errorf("unknown tool %q (available tools: %s)", tool, strings.Join(available, ", "))
	}

	version, err := newestManifestVersion(versions)
	if err != nil {
		return "", toolDownload{}, fmt.Errorf("resolve %s version: %w", tool, err)
	}
	platform := goos + "/" + goarch
	download, ok := versions[version][platform]
	if !ok {
		platforms := make([]string, 0, len(versions[version]))
		for name := range versions[version] {
			platforms = append(platforms, name)
		}
		sort.Strings(platforms)
		return "", toolDownload{}, fmt.Errorf("%s %s is unavailable for %s (available platforms: %s)", tool, version, platform, strings.Join(platforms, ", "))
	}
	return version, download, nil
}

func newestManifestVersion(versions map[string]map[string]toolDownload) (string, error) {
	if len(versions) == 0 {
		return "", fmt.Errorf("no versions are pinned")
	}
	ordered := make([]string, 0, len(versions))
	for version := range versions {
		ordered = append(ordered, version)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return manifestVersionLess(ordered[i], ordered[j])
	})
	return ordered[len(ordered)-1], nil
}

// manifestVersionLess provides numeric ordering for the release versions used
// in the manifest (v1.10.0 sorts after v1.9.0). Unusual version strings fall
// back to lexical ordering so the selection remains deterministic.
func manifestVersionLess(left, right string) bool {
	lparts, lok := numericVersionParts(left)
	rparts, rok := numericVersionParts(right)
	if !lok || !rok {
		return left < right
	}
	length := max(len(lparts), len(rparts))
	for i := range length {
		var lpart, rpart int
		if i < len(lparts) {
			lpart = lparts[i]
		}
		if i < len(rparts) {
			rpart = rparts[i]
		}
		if lpart != rpart {
			return lpart < rpart
		}
	}
	return left < right
}

func numericVersionParts(version string) ([]int, bool) {
	version = strings.TrimPrefix(version, "v")
	version = strings.SplitN(version, "-", 2)[0]
	pieces := strings.Split(version, ".")
	parts := make([]int, len(pieces))
	for i, piece := range pieces {
		part, err := strconv.Atoi(piece)
		if err != nil {
			return nil, false
		}
		parts[i] = part
	}
	return parts, true
}

func validateToolDownload(tool, version, goos, goarch string, download toolDownload) error {
	prefix := fmt.Sprintf("%s %s for %s/%s", tool, version, goos, goarch)
	if download.URL == "" {
		return fmt.Errorf("%s has no download URL in the embedded manifest", prefix)
	}
	// Fail early on a malformed or non-http(s) URL: this is a trusted-tool
	// manifest, and a bad scheme would otherwise surface as a confusing
	// download error (or skew archive-kind detection).
	if u, err := url.Parse(download.URL); err != nil {
		return fmt.Errorf("%s has an unparseable download URL: %v", prefix, err)
	} else if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%s download URL must be http(s), got scheme %q", prefix, u.Scheme)
	}
	if !validSHA256(download.SHA256) {
		return fmt.Errorf("%s has a missing or invalid SHA-256 pin", prefix)
	}
	if download.ExecutableSHA256 != "" && !validSHA256(download.ExecutableSHA256) {
		return fmt.Errorf("%s has a missing or invalid installed-executable SHA-256 pin", prefix)
	}
	if toolArchiveKind(download.URL) != "" && !validSHA256(download.ExecutableSHA256) {
		return fmt.Errorf("%s has a missing or invalid installed-executable SHA-256 pin", prefix)
	}
	return nil
}

func validSHA256(pin string) bool {
	if pin == "" || pin == missingSHA256 || len(pin) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(pin)
	return err == nil
}

func resolveToolDestination(destination string, homeDir func() (string, error)) (string, error) {
	if destination != "" {
		return destination, nil
	}
	home, err := homeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory for default install destination: %w", err)
	}
	if home == "" {
		return "", fmt.Errorf("resolve home directory for default install destination: home directory is empty")
	}
	return filepath.Join(home, defaultToolDir), nil
}

func toolExecutableName(tool, goos string) string {
	if goos == goosWindows {
		return tool + ".exe"
	}
	return tool
}

func downloadAndInstallTool(ctx context.Context, client *http.Client, installedPath, tool, version, goos string, download toolDownload) error {
	if err := os.MkdirAll(filepath.Dir(installedPath), 0o755); err != nil { //nolint:gosec // G301: a user bin dir must be traversable to run tools from it
		return fmt.Errorf("create install directory: %w", err)
	}

	downloadFile, err := os.CreateTemp(filepath.Dir(installedPath), "."+tool+"-download-*")
	if err != nil {
		return fmt.Errorf("create temporary download file: %w", err)
	}
	downloadPath := downloadFile.Name()
	defer func() { _ = os.Remove(downloadPath) }()

	actual, err := fetchToolArtifact(ctx, client, download.URL, downloadFile)
	if err != nil {
		_ = downloadFile.Close()
		return fmt.Errorf("download %s %s: %w", tool, version, err)
	}
	if err := downloadFile.Close(); err != nil {
		return fmt.Errorf("close temporary download file: %w", err)
	}
	if !strings.EqualFold(actual, download.SHA256) {
		return fmt.Errorf("SHA-256 mismatch for %s %s release artifact: expected %s, got %s", tool, version, download.SHA256, actual)
	}

	stagedPath := downloadPath
	if kind := toolArchiveKind(download.URL); kind != "" {
		stagedPath, err = extractToolExecutable(downloadPath, filepath.Dir(installedPath), tool, goos, kind)
		if err != nil {
			return fmt.Errorf("extract verified %s %s release artifact: %w", tool, version, err)
		}
		defer func() { _ = os.Remove(stagedPath) }()

		actualExecutable, err := fileSHA256(stagedPath)
		if err != nil {
			return fmt.Errorf("hash extracted %s executable: %w", tool, err)
		}
		if !strings.EqualFold(actualExecutable, download.ExecutableSHA256) {
			return fmt.Errorf("SHA-256 mismatch for extracted %s %s executable: expected %s, got %s", tool, version, download.ExecutableSHA256, actualExecutable)
		}
	}

	if err := os.Chmod(stagedPath, 0o755); err != nil { //nolint:gosec // G302: making the installed tool executable is the point of `cilock get`
		return fmt.Errorf("make %s executable: %w", stagedPath, err)
	}
	if err := replaceInstalledTool(stagedPath, installedPath, goos); err != nil {
		return fmt.Errorf("install %s at %s: %w", tool, installedPath, err)
	}
	return nil
}

func fetchToolArtifact(ctx context.Context, client *http.Client, downloadURL string, destination io.Writer) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}

	hasher := sha256.New()
	if err := copyLimited(io.MultiWriter(destination, hasher), resp.Body); err != nil {
		return "", fmt.Errorf("write temporary download: %w", err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// copyLimited copies src to dst, failing closed once maxToolSize is exceeded.
func copyLimited(dst io.Writer, src io.Reader) error {
	written, err := io.Copy(dst, io.LimitReader(src, maxToolSize+1))
	if err != nil {
		return err
	}
	if written > maxToolSize {
		return fmt.Errorf("refusing to copy more than %d bytes", int64(maxToolSize))
	}
	return nil
}

func toolArchiveKind(downloadURL string) string {
	parsed, err := url.Parse(downloadURL)
	if err != nil {
		return ""
	}
	path := strings.ToLower(parsed.Path)
	switch {
	case strings.HasSuffix(path, ".tar.gz"):
		return "tar.gz"
	case strings.HasSuffix(path, ".zip"):
		return "zip"
	default:
		return ""
	}
}

func extractToolExecutable(archivePath, destinationDir, tool, goos, kind string) (string, error) {
	staged, err := os.CreateTemp(destinationDir, "."+tool+"-executable-*")
	if err != nil {
		return "", fmt.Errorf("create temporary executable file: %w", err)
	}
	stagedPath := staged.Name()
	keep := false
	defer func() {
		_ = staged.Close()
		if !keep {
			_ = os.Remove(stagedPath)
		}
	}()

	wanted := toolExecutableName(tool, goos)
	switch kind {
	case "tar.gz":
		err = extractToolFromTarGZ(archivePath, wanted, staged)
	case "zip":
		err = extractToolFromZIP(archivePath, wanted, staged)
	default:
		err = fmt.Errorf("unsupported archive type %q", kind)
	}
	if err != nil {
		return "", err
	}
	if err := staged.Close(); err != nil {
		return "", fmt.Errorf("close temporary executable file: %w", err)
	}
	keep = true
	return stagedPath, nil
}

func extractToolFromTarGZ(archivePath, wanted string, destination io.Writer) error {
	archive, err := os.Open(archivePath) //nolint:gosec // path is the private temporary download created above
	if err != nil {
		return err
	}
	defer func() { _ = archive.Close() }()
	gzipReader, err := gzip.NewReader(archive)
	if err != nil {
		return err
	}
	defer func() { _ = gzipReader.Close() }()
	// Cap the CUMULATIVE decompressed stream, not just the matched file:
	// tarReader.Next() decompresses and discards preceding entries, which
	// would otherwise bypass the size defense. Exceeding the cap surfaces
	// as an unexpected-EOF tar error (fail closed).
	tarReader := tar.NewReader(io.LimitReader(gzipReader, maxToolSize+1))
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if filepath.Base(header.Name) != wanted || header.Typeflag != tar.TypeReg {
			continue
		}
		return copyLimited(destination, tarReader)
	}
	return fmt.Errorf("archive does not contain regular file %q", wanted)
}

func extractToolFromZIP(archivePath, wanted string, destination io.Writer) error {
	archive, err := os.Open(archivePath) //nolint:gosec // path is the private temporary download created above
	if err != nil {
		return err
	}
	defer func() { _ = archive.Close() }()
	info, err := archive.Stat()
	if err != nil {
		return err
	}
	zipReader, err := zip.NewReader(archive, info.Size())
	if err != nil {
		return err
	}
	for _, file := range zipReader.File {
		if filepath.Base(file.Name) != wanted || !file.FileInfo().Mode().IsRegular() {
			continue
		}
		contents, err := file.Open()
		if err != nil {
			return err
		}
		copyErr := copyLimited(destination, contents)
		closeErr := contents.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}
	return fmt.Errorf("archive does not contain regular file %q", wanted)
}

// replaceInstalledTool swaps the staged executable into place. On Windows
// os.Rename cannot replace an existing file, so the old binary is first
// renamed to a .old backup and RESTORED if the swap fails — the previous
// known-good installation must never be destroyed by a failed install
// (antivirus locks, races). On success the backup is removed best-effort.
func replaceInstalledTool(stagedPath, installedPath, goos string) error {
	if goos != goosWindows {
		return os.Rename(stagedPath, installedPath) //nolint:gosec // G703: both paths are inside the user-chosen install directory
	}
	backupPath := installedPath + ".old"
	// A stale backup from a previous failed swap would make os.Rename fail on
	// Windows (destination exists) and block every future upgrade — clear it
	// best-effort first.
	_ = os.Remove(backupPath)
	backedUp := false
	switch err := os.Rename(installedPath, backupPath); {
	case err == nil:
		backedUp = true
	case !os.IsNotExist(err):
		return err
	}
	if err := os.Rename(stagedPath, installedPath); err != nil { //nolint:gosec // G703: both paths are inside the user-chosen install directory
		if backedUp {
			// Restore the last known-good binary; its error is secondary
			// to the install failure being returned.
			_ = os.Rename(backupPath, installedPath)
		}
		return err
	}
	if backedUp {
		_ = os.Remove(backupPath)
	}
	return nil
}

func verifyInstalledTool(output io.Writer, installedPath, tool, version string, download toolDownload) error {
	expected := download.SHA256
	if download.ExecutableSHA256 != "" {
		expected = download.ExecutableSHA256
	}
	actual, err := fileSHA256(installedPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("cannot verify %s: installed binary %s is absent", tool, installedPath)
		}
		return fmt.Errorf("hash installed %s binary %s: %w", tool, installedPath, err)
	}
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("SHA-256 mismatch for installed %s %s at %s: expected %s, got %s", tool, version, installedPath, expected, actual)
	}
	_, err = fmt.Fprintf(output, "Verified %s (%s %s, sha256:%s)\n", installedPath, tool, version, actual)
	return err
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path) //nolint:gosec // path is the selected installation or private temporary file
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	hasher := sha256.New()
	// Same 2 GiB fail-closed cap as copyLimited: --verify against a large or
	// accidentally-wrong file must not grind through unbounded disk I/O.
	written, err := io.Copy(hasher, io.LimitReader(file, maxToolSize+1))
	if err != nil {
		return "", err
	}
	if written > maxToolSize {
		return "", fmt.Errorf("refusing to hash more than %d bytes", int64(maxToolSize))
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeToolInstallResult(output io.Writer, installedPath, destDir, tool, version, goos string) error {
	if _, err := fmt.Fprintf(output, "Installed %s %s to %s\n", tool, version, installedPath); err != nil {
		return err
	}
	if goos == goosWindows {
		_, err := fmt.Fprintf(output, "Add %s to your PATH.\n", destDir)
		return err
	}
	_, err := fmt.Fprintf(output, "Add it to your PATH:\n  export PATH=\"%s:$PATH\"\n", destDir)
	return err
}
