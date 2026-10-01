// jade:ring local

// Copyright 2026 The Rookery Contributors
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

package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/stretchr/testify/require"
)

// The scope record says WHAT was read, but not HOW it was scanned. An
// allowlist of '.*' over a tree with a live key produced a strict-scope
// attestation with zero findings, and nothing in the signed predicate said so
// (testifysec/judge#9533). Whenever a scope is recorded, the effective
// scanner configuration is recorded with it, so a gate can refuse a widened
// one and treat an absent record as an older producer.

func runTreeScan(t *testing.T, dir string, opts ...Option) *Attestor {
	t.Helper()
	scan := New(append([]Option{WithScope(string(ScopeTree)), WithScanAttestations(false)}, opts...)...)
	ctx, err := attestation.NewContext("test", []attestation.Attestor{scan}, attestation.WithWorkingDir(dir))
	require.NoError(t, err)
	require.NoError(t, ctx.RunAttestors())
	return scan
}

func TestScopedScanRecordsTheDefaultConfiguration(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	scan := runTreeScan(t, dir)
	require.NotNil(t, scan.Scope)
	require.Equal(t, &ScanConfig{
		MaxFileSizeMB:   defaultMaxFileSizeMB,
		MaxDecodeLayers: defaultMaxDecodeLayers,
	}, scan.Scope.Config)

	raw, err := json.Marshal(scan)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"config":{"maxFileSizeMB":10,"maxDecodeLayers":3}`)
}

// The measured bypass: the allowlist hides the key, and now the predicate
// carries the allowlist that hid it.
func TestScopedScanRecordsTheCommandLineAllowlist(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"leak.txt": "token " + scopePAT + "\n"})
	scan := runTreeScan(t, dir, WithAllowList(&AllowList{Regexes: []string{".*"}}))
	require.Empty(t, scan.Findings, "the allowlist is what hides the key")
	require.Equal(t, &AllowList{Regexes: []string{".*"}}, scan.Scope.Config.Allowlist)
}

// A custom gitleaks config replaces the command-line allowlist entirely, so
// the effective configuration is the file, identified by its digest.
func TestScopedScanRecordsTheCustomConfigDigest(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	cfg := []byte("[[rules]]\nid = \"r\"\nregex = '''TEST_SECRET[=:]\\s*([0-9a-zA-Z]{16,})'''\nkeywords = [\"TEST_SECRET\"]\n")
	cfgPath := filepath.Join(t.TempDir(), "gitleaks.toml")
	require.NoError(t, os.WriteFile(cfgPath, cfg, 0o600))
	sum := sha256.Sum256(cfg)

	scan := runTreeScan(t, dir, WithConfigPath(cfgPath), WithAllowList(&AllowList{Regexes: []string{".*"}}))
	require.Equal(t, "sha256:"+hex.EncodeToString(sum[:]), scan.Scope.Config.ConfigDigest)
	require.Nil(t, scan.Scope.Config.Allowlist, "the command-line allowlist is ignored when a config file is used")
}

func TestScopedScanRecordsTheMaxFileSize(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"a.txt": "clean\n"})
	scan := runTreeScan(t, dir, WithMaxFileSize(500), WithMaxDecodeLayers(0))
	require.Equal(t, 500, scan.Scope.Config.MaxFileSizeMB)
	require.Equal(t, 0, scan.Scope.Config.MaxDecodeLayers)
}
