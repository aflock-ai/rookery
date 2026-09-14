// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

// jade:ring local

package cli

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation"
	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/fileinventory"
	"github.com/aflock-ai/rookery/attestation/intoto"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/auth"
	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
	"github.com/aflock-ai/rookery/plugins/attestors/product"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func inventoryProfile(t *testing.T, profile, budget string) {
	t.Helper()
	p, b := config.DefaultEvidenceProfile, config.DefaultProductInlineBytes
	t.Cleanup(func() { config.DefaultEvidenceProfile, config.DefaultProductInlineBytes = p, b })
	config.DefaultEvidenceProfile, config.DefaultProductInlineBytes = profile, budget
}

func inventoryRunFixture(t *testing.T) (options.RunOptions, cryptoutil.Signer, string) {
	t.Helper()
	state, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(state, 0o700))
	t.Setenv("CILOCK_STATE_DIR", state)
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
	work := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(work, "input"), []byte("source"), 0o600))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := cryptoutil.NewSigner(key, cryptoutil.SignWithHash(crypto.SHA256))
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	return options.RunOptions{StepName: "inventory-test", WorkingDir: work, OutFilePath: filepath.Join(t.TempDir(), "run.json"), OutputFormat: "json", CaptureMode: "walk", CacheDisableDefaults: true, CacheDisableEnvProbe: true}, signer, keyPath
}

func inventoryCapture(t *testing.T, run func() error) ([]byte, string, error) {
	t.Helper()
	dir := t.TempDir()
	out, err := os.Create(filepath.Join(dir, "stdout"))
	require.NoError(t, err)
	errout, err := os.Create(filepath.Join(dir, "stderr"))
	require.NoError(t, err)
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = out, errout
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr; _ = out.Close(); _ = errout.Close() }()
	runErr := run()
	stdout, err := os.ReadFile(out.Name())
	require.NoError(t, err)
	stderr, err := os.ReadFile(errout.Name())
	require.NoError(t, err)
	return stdout, string(stderr), runErr
}

func inventoryStatement(t *testing.T, path string, signer cryptoutil.Signer) intoto.Statement {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(body, &env))
	require.NotEmpty(t, env.Signatures)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	_, err = env.Verify(dsse.VerifyWithVerifiers(verifier))
	require.NoError(t, err, "persisted bytes must retain the workflow signature")
	var st intoto.Statement
	require.NoError(t, json.Unmarshal(env.Payload, &st))
	return st
}

func TestRunInventoryDefaultsAndRetention(t *testing.T) {
	for _, mode := range []string{"inline", "retained-material", "large", "duplicate", "automatic-directory", "legacy-inline", "legacy-manifest"} {
		t.Run(mode, func(t *testing.T) {
			inventoryProfile(t, "compact", "131072")
			ro, signer, _ := inventoryRunFixture(t)
			command := "printf output > product"
			if mode == "large" {
				config.DefaultProductInlineBytes = "1"
			}
			if mode == "duplicate" {
				command += "; cp product product-copy"
			}
			if mode == "retained-material" || mode == "legacy-manifest" || mode == "automatic-directory" {
				ro.MaterialManifest = true
			}
			if strings.HasPrefix(mode, "legacy") {
				config.DefaultEvidenceProfile = "legacy"
			}
			if mode == "automatic-directory" {
				ro.OutFilePath = ""
			}
			stdout, stderr, err := inventoryCapture(t, func() error {
				return runRun(t.Context(), ro, []string{"sh", "-c", command}, nil, nil, signer)
			})
			require.NoError(t, err)
			var summary options.RunSummary
			require.NoError(t, json.Unmarshal(stdout, &summary))
			require.False(t, summary.Uploaded)
			require.NotEmpty(t, summary.OutFile)
			if !strings.HasPrefix(mode, "legacy") {
				assertPrivateStorage(t, summary.OutFile, false)
				require.Len(t, summary.Inventories, 2)
			}
			st := inventoryStatement(t, summary.OutFile, signer)
			require.Equal(t, attestation.CollectionType, st.PredicateType)
			var col attestation.Collection
			require.NoError(t, json.Unmarshal(st.Predicate, &col))
			var mat *material.Attestor
			var prod *product.Attestor
			for _, a := range col.Attestations {
				switch a.Type {
				case material.Type:
					mat = a.Attestation.(*material.Attestor)
				case product.Type:
					prod = a.Attestation.(*product.Attestor)
				}
			}
			require.NotNil(t, mat)
			require.NotNil(t, prod)
			require.Equal(t, uint64(1), mat.TreeSize)
			require.Equal(t, uint64(1), prod.TreeSize, "unchanged input must not become a product")
			if strings.HasPrefix(mode, "legacy") {
				require.Nil(t, mat.InventoryReference())
				require.Nil(t, prod.InventoryReference())
				if ro.MaterialManifest {
					require.Equal(t, material.ManifestType, inventoryStatement(t, ro.OutFilePath+"-material-manifest.json", signer).PredicateType)
				}
				return
			}
			require.Empty(t, mat.Leaves())
			require.NotNil(t, mat.InventoryReference())
			if ro.MaterialManifest {
				require.Equal(t, "detached", mat.InventoryReference().State)
			} else {
				require.Equal(t, "omitted", mat.InventoryReference().State)
				require.Contains(t, stderr, "not retained")
			}
			if mode == "large" || mode == "duplicate" {
				require.NotNil(t, prod.InventoryReference())
				require.Empty(t, prod.Leaves())
				if mode == "duplicate" {
					require.Equal(t, 2, prod.InventoryReference().FileCount)
				}
			} else {
				require.Nil(t, prod.InventoryReference())
				require.Len(t, prod.Leaves(), 1)
			}
			for _, inv := range summary.Inventories {
				require.False(t, inv.Uploaded)
				require.Empty(t, inv.Gitoid)
				if inv.State != "detached" {
					continue
				}
				companion := inventoryStatement(t, inv.Path, signer)
				require.Equal(t, fileinventory.Type, companion.PredicateType)
				digest := sha256.Sum256(companion.Predicate)
				require.Equal(t, hex.EncodeToString(digest[:]), inv.Digest)
				require.Equal(t, len(companion.Predicate), inv.Bytes)
				assertPrivateStorage(t, inv.Path, false)
				require.Contains(t, stderr, inv.Path)
			}
			if mode == "automatic-directory" {
				require.True(t, strings.HasPrefix(summary.OutFile, filepath.Join(os.Getenv("CILOCK_STATE_DIR"), "evidence", "run-")))
				for _, dir := range []string{filepath.Dir(summary.OutFile), filepath.Dir(filepath.Dir(summary.OutFile))} {
					assertPrivateStorage(t, dir, true)
				}
			}
		})
	}
}

func TestRunInventoryUploadConsent(t *testing.T) {
	for _, mode := range []string{"collection-only", "consent", "both-consent", "failed-inventory", "failed-second", "failed-parent", "empty-gitoid", "legacy"} {
		t.Run(mode, func(t *testing.T) {
			inventoryProfile(t, "compact", "1")
			ro, signer, _ := inventoryRunFixture(t)
			ro.MaterialManifest = true
			ro.UploadInventories = mode != "collection-only"
			kinds := []string{"material"}
			if mode == "both-consent" || mode == "failed-second" {
				kinds = append(kinds, "product")
			} else {
				ro.NoDefaultAttestors = []string{"product"}
			}
			if mode == "legacy" {
				config.DefaultEvidenceProfile = "legacy"
				ro.UploadInventories = false
			}
			var uploaded []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var env dsse.Envelope
				if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				var st intoto.Statement
				if err := json.Unmarshal(env.Payload, &st); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				uploaded = append(uploaded, st.PredicateType)
				if st.PredicateType == fileinventory.Type {
					for _, kind := range kinds {
						_, err := os.Stat(ro.OutFilePath + "-" + kind + "-inventory.json")
						assert.NoError(t, err, "inventory must exist before any upload")
					}
					if _, err := os.Stat(ro.OutFilePath); !os.IsNotExist(err) {
						t.Error("parent persisted before required inventory upload succeeded")
					}
					var payload fileinventory.Payload
					assert.NoError(t, json.Unmarshal(st.Predicate, &payload))
					local, err := os.ReadFile(ro.OutFilePath + "-" + payload.Kind + "-inventory.json")
					if err != nil {
						t.Error(err)
					}
					body, err := json.Marshal(env)
					if err != nil || !bytes.Equal(local, body) {
						t.Error("uploaded inventory differs from the saved signed bytes")
					}
				}
				if (mode == "failed-inventory" && st.PredicateType == fileinventory.Type) || (mode == "failed-second" && len(uploaded) == 2) || (mode == "failed-parent" && st.PredicateType == attestation.CollectionType) {
					w.WriteHeader(400)
					return
				}
				if mode == "empty-gitoid" {
					_, _ = w.Write([]byte(`{}`))
					return
				}
				_, _ = fmt.Fprintf(w, `{"gitoid":"stored-%d"}`, len(uploaded))
			}))
			defer srv.Close()
			ro.ArchivistaOptions = options.ArchivistaOptions{Enable: true, Url: srv.URL}
			stdout, _, err := inventoryCapture(t, func() error {
				return runRun(t.Context(), ro, []string{"sh", "-c", "printf output > product"}, nil, nil, signer)
			})
			var summary options.RunSummary
			require.NoError(t, json.Unmarshal(stdout, &summary), "summary must survive upload failure")
			switch mode {
			case "collection-only":
				require.NoError(t, err)
				require.Equal(t, []string{attestation.CollectionType}, uploaded)
			case "consent":
				require.NoError(t, err)
				require.Equal(t, []string{fileinventory.Type, attestation.CollectionType}, uploaded)
			case "both-consent":
				require.NoError(t, err)
				require.Equal(t, []string{fileinventory.Type, fileinventory.Type, attestation.CollectionType}, uploaded)
			case "failed-inventory":
				require.Error(t, err)
				require.Equal(t, []string{fileinventory.Type}, uploaded)
				require.NoFileExists(t, ro.OutFilePath)
			case "empty-gitoid":
				require.ErrorContains(t, err, "no gitoid")
				require.Equal(t, []string{fileinventory.Type}, uploaded)
				require.NoFileExists(t, ro.OutFilePath)
			case "failed-second":
				require.Error(t, err)
				require.Equal(t, []string{fileinventory.Type, fileinventory.Type}, uploaded)
				require.NoFileExists(t, ro.OutFilePath)
			case "failed-parent":
				require.Error(t, err)
				require.False(t, summary.Uploaded)
			case "legacy":
				require.NoError(t, err)
				require.Equal(t, []string{material.ManifestType, attestation.CollectionType}, uploaded)
			}
			for _, inv := range summary.Inventories {
				if inv.State != "detached" {
					continue
				}
				require.FileExists(t, inv.Path, "retain every inventory before attempting any upload")
				wantUploaded := mode == "consent" || mode == "both-consent" || mode == "failed-parent" || (mode == "failed-second" && inv.Kind == "material")
				require.Equal(t, wantUploaded, inv.Uploaded)
				require.Equal(t, wantUploaded, inv.Gitoid != "")
			}
		})
	}
}

func TestRunInventoryRejectsBeforeCommand(t *testing.T) {
	for _, mode := range []string{"profile", "budget", "upload-disabled"} {
		t.Run(mode, func(t *testing.T) {
			inventoryProfile(t, "compact", "131072")
			ro, _, key := inventoryRunFixture(t)
			cmd := RunCmd()
			marker := filepath.Join(ro.WorkingDir, "executed")
			args := []string{"--offline", "--step", "probe", "-a", "material,product", "-k", key, "--workingdir", ro.WorkingDir}
			want := "compiled"
			switch mode {
			case "profile":
				config.DefaultEvidenceProfile = "broken"
			case "budget":
				config.DefaultProductInlineBytes = "-1"
			case "upload-disabled":
				args = append(args, "--upload-inventories", "--enable-archivista=false")
				want = "requires --enable-archivista"
			}
			cmd.SetArgs(append(args, "--", "touch", marker))
			require.ErrorContains(t, cmd.ExecuteContext(t.Context()), want)
			require.NoFileExists(t, marker)
		})
	}
}

func TestRunInventoryOutputFailures(t *testing.T) {
	for _, mode := range []string{"missing-parent", "symlink-sidecar", "existing-sidecar", "existing-parent", "state-symlink", "legacy-stdout"} {
		t.Run(mode, func(t *testing.T) {
			inventoryProfile(t, "compact", "131072")
			ro, signer, _ := inventoryRunFixture(t)
			ro.MaterialManifest = true
			sidecar := ro.OutFilePath + "-material-inventory.json"
			switch mode {
			case "missing-parent":
				ro.OutFilePath = filepath.Join(t.TempDir(), "missing", "run.json")
			case "symlink-sidecar":
				require.NoError(t, os.Symlink(filepath.Join(ro.WorkingDir, "input"), sidecar))
			case "existing-sidecar":
				require.NoError(t, os.WriteFile(sidecar, []byte("do not overwrite"), 0o600))
			case "existing-parent":
				require.NoError(t, os.WriteFile(ro.OutFilePath, []byte("previous evidence"), 0o600))
			case "state-symlink":
				require.NoError(t, os.Symlink(t.TempDir(), filepath.Join(os.Getenv("CILOCK_STATE_DIR"), "evidence")))
				ro.OutFilePath = ""
			case "legacy-stdout":
				config.DefaultEvidenceProfile = "legacy"
				ro.OutFilePath = ""
			}
			_, _, err := inventoryCapture(t, func() error { return runRun(t.Context(), ro, []string{"true"}, nil, nil, signer) })
			require.Error(t, err)
			if ro.OutFilePath != "" && mode != "existing-parent" {
				require.NoFileExists(t, ro.OutFilePath)
			}
			if mode == "existing-parent" {
				data, err := os.ReadFile(ro.OutFilePath)
				require.NoError(t, err)
				require.Equal(t, "previous evidence", string(data))
				require.NoFileExists(t, sidecar, "refuse ambiguous output paths before saving any inventory")
			}
			if mode == "legacy-stdout" {
				require.Contains(t, err.Error(), "--outfile is required")
			}
			input, err := os.ReadFile(filepath.Join(ro.WorkingDir, "input"))
			require.NoError(t, err)
			require.Equal(t, "source", string(input))
		})
	}
}

func TestRunInventoryStdoutWithoutCompanions(t *testing.T) {
	inventoryProfile(t, "compact", "131072")
	ro, signer, _ := inventoryRunFixture(t)
	ro.OutFilePath, ro.OutputFormat = "", "text"
	stdout, stderr, err := inventoryCapture(t, func() error { return runRun(t.Context(), ro, []string{"true"}, nil, nil, signer) })
	require.NoError(t, err)
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(stdout, &env))
	require.NotEmpty(t, env.Signatures)
	require.Contains(t, stderr, "material: omitted (1 files)")
	require.Contains(t, stderr, "product: empty (0 files)")
	require.NoDirExists(t, filepath.Join(os.Getenv("CILOCK_STATE_DIR"), "evidence"))
}

func TestRunInventoryEmptyMaterialRetentionDoesNotEnableLegacyExport(t *testing.T) {
	inventoryProfile(t, "compact", "131072")
	ro, signer, _ := inventoryRunFixture(t)
	require.NoError(t, os.Remove(filepath.Join(ro.WorkingDir, "input")))
	ro.OutFilePath, ro.MaterialManifest = "", true
	stdout, _, err := inventoryCapture(t, func() error { return runRun(t.Context(), ro, []string{"true"}, nil, nil, signer) })
	require.NoError(t, err)
	var summary options.RunSummary
	require.NoError(t, json.Unmarshal(stdout, &summary))
	require.Len(t, summary.Inventories, 2)
	for _, inv := range summary.Inventories {
		require.Equal(t, "empty", inv.State)
		require.Empty(t, inv.Path)
		require.Zero(t, inv.FileCount)
	}
	require.Empty(t, summary.OutFile)
	require.NoDirExists(t, filepath.Join(os.Getenv("CILOCK_STATE_DIR"), "evidence"))
}

func TestRunInventoryCompiledErrorsBeforeNetwork(t *testing.T) {
	inventoryProfile(t, "unknown", "131072")
	ro, _, _ := inventoryRunFixture(t)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer srv.Close()
	// A fake session would otherwise cause identity resolution to contact the
	// platform. Invalid compiled defaults must refuse even before that lookup.
	require.NoError(t, auth.Save(auth.Credential{PlatformURL: srv.URL, Token: "test-only", AuthMode: auth.AuthModeBrowser, ExpiresAt: time.Now().Add(time.Hour)}))
	for _, profile := range []string{"unknown", "compact"} {
		config.DefaultEvidenceProfile = profile
		if profile == "compact" {
			config.DefaultProductInlineBytes = "invalid"
		}
		cmd := RunCmd()
		cmd.SetArgs([]string{"--platform-url", srv.URL, "--step", "probe", "--workingdir", ro.WorkingDir, "--", "touch", filepath.Join(ro.WorkingDir, "executed")})
		require.ErrorContains(t, cmd.ExecuteContext(t.Context()), "compiled")
	}
	require.Zero(t, calls.Load())
	require.NoFileExists(t, filepath.Join(ro.WorkingDir, "executed"))
}

func TestRunInventoryRunCmdRegistry(t *testing.T) {
	inventoryProfile(t, "compact", "131072")
	ro, _, key := inventoryRunFixture(t)
	cmd := RunCmd()
	cmd.SetArgs([]string{"--offline", "--step", "probe", "-a", "material,product", "-k", key, "--workingdir", ro.WorkingDir, "--capture-mode", "walk", "--json", "--material-manifest", "--", "true"})
	stdout, _, err := inventoryCapture(t, func() error { return cmd.ExecuteContext(t.Context()) })
	require.NoError(t, err)
	var summary options.RunSummary
	require.NoError(t, json.Unmarshal(stdout, &summary))
	require.False(t, summary.Uploaded)
	require.Len(t, summary.Inventories, 2)
	require.Equal(t, "detached", summary.Inventories[0].State)
	require.FileExists(t, summary.Inventories[0].Path)
}

func TestRunInventoryCompactChainProfile(t *testing.T) {
	for _, tt := range []struct {
		name, profile                 string
		flags                         []string
		retain, upload, store, refuse bool
	}{
		{"chain", "compact-chain", nil, true, true, true, false},
		{"stock", "compact", nil, false, false, true, false},
		{"no-retention", "compact-chain", []string{"--material-manifest=false"}, false, true, true, false},
		{"no-upload", "compact-chain", []string{"--upload-inventories=false"}, true, false, true, false},
		{"both-disabled", "compact-chain", []string{"--material-manifest=false", "--upload-inventories=false"}, false, false, true, false},
		{"offline", "compact-chain", []string{"--offline"}, true, false, false, false},
		{"platform-disabled", "compact-chain", nil, true, false, false, false},
		{"explicit-upload-offline", "compact-chain", []string{"--offline", "--upload-inventories"}, true, true, false, true},
		{"invalid-profile", "unknown", nil, false, false, true, true},
		{"invalid-budget", "compact-chain", nil, false, false, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			inventoryProfile(t, tt.profile, "131072")
			if tt.name == "invalid-budget" {
				config.DefaultProductInlineBytes = "invalid"
			}
			ro, signer, key := inventoryRunFixture(t)
			var uploaded []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/upload" {
					t.Errorf("unexpected request: %s", r.URL.Path)
					w.WriteHeader(400)
					return
				}
				var env dsse.Envelope
				if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				var st intoto.Statement
				if err := json.Unmarshal(env.Payload, &st); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				label := st.PredicateType
				if st.PredicateType == fileinventory.Type {
					var inv fileinventory.Payload
					if err := json.Unmarshal(st.Predicate, &inv); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					label = "inventory:" + inv.Kind
				}
				uploaded = append(uploaded, label)
				_, _ = fmt.Fprintf(w, `{"gitoid":"stored-%d"}`, len(uploaded))
			}))
			defer srv.Close()
			// Disable hosted providers, but explicitly enable our test store in
			// online cases. No inventory flags are needed for the chain profile.
			args := []string{"--platform-url", "", "--step", "chain", "-a", "material,product", "-k", key,
				"--workingdir", ro.WorkingDir, "--capture-mode", "walk", "--cache-disable-defaults", "--cache-disable-env-probe",
				"--json", "--archivista-server", srv.URL}
			if tt.store {
				args = append(args, "--enable-archivista")
			}
			args = append(args, tt.flags...)
			args = append(args, "--", "sh", "-c", "printf artifact > product; cp product product-copy")
			cmd := RunCmd()
			cmd.SetArgs(args)
			stdout, _, err := inventoryCapture(t, func() error { return cmd.ExecuteContext(t.Context()) })
			srv.Close() // Join handlers before inspecting the recorded requests.
			if tt.refuse {
				require.Error(t, err)
				require.Empty(t, uploaded)
				require.NoFileExists(t, filepath.Join(ro.WorkingDir, "product"))
				if strings.HasPrefix(tt.name, "invalid") {
					require.Contains(t, err.Error(), "compiled")
				} else {
					require.Contains(t, err.Error(), "requires --enable-archivista")
				}
				return
			}
			require.NoError(t, err)
			var summary options.RunSummary
			require.NoError(t, json.Unmarshal(stdout, &summary))
			require.Equal(t, tt.store, summary.Uploaded)
			require.Len(t, summary.Inventories, 2)
			var expected []string
			if tt.upload && tt.store {
				if tt.retain {
					expected = append(expected, "inventory:material")
				}
				expected = append(expected, "inventory:product")
			}
			if tt.store {
				expected = append(expected, attestation.CollectionType)
			}
			require.Equal(t, expected, uploaded)
			for _, inv := range summary.Inventories {
				if inv.Kind == "material" && !tt.retain {
					require.Equal(t, "omitted", inv.State)
					require.Empty(t, inv.Path)
					require.False(t, inv.Uploaded)
					continue
				}
				require.Equal(t, "detached", inv.State)
				require.Equal(t, tt.upload && tt.store, inv.Uploaded)
				require.Equal(t, fileinventory.Type, inventoryStatement(t, inv.Path, signer).PredicateType)
				if inv.Kind == "product" {
					require.Equal(t, 2, inv.FileCount)
				} else {
					require.Equal(t, 1, inv.FileCount)
				}
			}
			parent := inventoryStatement(t, summary.OutFile, signer)
			var collection attestation.Collection
			require.NoError(t, json.Unmarshal(parent.Predicate, &collection))
			for _, a := range collection.Attestations {
				if a.Type == material.Type {
					require.IsType(t, material.New(), a.Attestation)
				}
				if a.Type == product.Type {
					require.IsType(t, product.New(), a.Attestation)
				}
			}
		})
	}
}

func TestRunInventoryAutomaticCollectionUpload(t *testing.T) {
	inventoryProfile(t, "compact", "131072")
	ro, signer, key := inventoryRunFixture(t)
	var uploaded []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/archivista/upload" {
			t.Errorf("unexpected network request: %s", r.URL.Path)
			w.WriteHeader(400)
			return
		}
		var env dsse.Envelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		var st intoto.Statement
		if err := json.Unmarshal(env.Payload, &st); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		uploaded = append(uploaded, st.PredicateType)
		_, _ = w.Write([]byte(`{"gitoid":"parent-stored"}`))
	}))
	defer srv.Close()
	require.NoError(t, auth.Save(auth.Credential{PlatformURL: srv.URL, Token: "test-only", AuthMode: auth.AuthModeBrowser, ExpiresAt: time.Now().Add(time.Hour)}))
	cmd := &cobra.Command{}
	work, out := ro.WorkingDir, ro.OutFilePath
	ro.AddFlags(cmd)
	require.NoError(t, cmd.ParseFlags([]string{"--platform-url", srv.URL, "--step", "probe", "-a", "material,product", "-k", key, "--workingdir", work, "--outfile", out, "--capture-mode", "walk", "--json", "--material-manifest"}))
	require.NoError(t, cmd.PreRunE(cmd, nil))
	ro.ResolvePlatformDefaults(cmd)
	require.True(t, ro.ArchivistaOptions.Enable, "fake stored session should auto-enable collection upload")
	require.False(t, ro.UploadInventories)
	ro.TimestampServers = nil // Upload lifecycle seam; no TSA is needed for this test.
	stdout, _, err := inventoryCapture(t, func() error {
		return runRun(t.Context(), ro, []string{"sh", "-c", "printf output > product"}, nil, nil, signer)
	})
	require.NoError(t, err)
	require.Equal(t, []string{attestation.CollectionType}, uploaded, "automatic collection upload must not consent to inventory upload")
	var summary options.RunSummary
	require.NoError(t, json.Unmarshal(stdout, &summary))
	require.True(t, summary.Uploaded)
	require.Len(t, summary.Inventories, 2)
	for _, inv := range summary.Inventories {
		if inv.Kind == "material" {
			require.Equal(t, "detached", inv.State, "registry defaults must not overwrite the compiled representation")
			require.False(t, inv.Uploaded)
			require.FileExists(t, inv.Path)
		}
	}
}

func TestRunInventoryPredicateTypeControlsLifecycle(t *testing.T) {
	for _, mode := range []string{"modern-renamed", "legacy-misnamed", "missing", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			inventoryProfile(t, "compact", "131072")
			ro, signer, _ := inventoryRunFixture(t)
			mat := material.New(material.WithCompactInventory(true))
			if mode == "legacy-misnamed" {
				mat = material.New(material.WithManifest(true))
			}
			results, err := workflow.RunWithExports("probe", workflow.RunWithSigners(signer), workflow.RunWithAttestors([]attestation.Attestor{mat}), workflow.RunWithAttestationOpts(attestation.WithWorkingDir(ro.WorkingDir)))
			require.NoError(t, err)
			require.Len(t, results, 2)
			summary := buildRunSummary(ro, nil, []attestation.Attestor{mat}, results, nil, "", nil)
			results[0].AttestorName = "unrelated/name"
			switch mode {
			case "legacy-misnamed":
				results[0].AttestorName = "material/inventory"
			case "missing":
				results = results[1:]
			case "duplicate":
				results = append(results, results[0])
			}
			var types []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var env dsse.Envelope
				if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				var st intoto.Statement
				if err := json.Unmarshal(env.Payload, &st); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				types = append(types, st.PredicateType)
				_, _ = w.Write([]byte(`{"gitoid":"stored"}`))
			}))
			defer srv.Close()
			ro.ArchivistaOptions = options.ArchivistaOptions{Enable: true, Url: srv.URL}
			if mode == "modern-renamed" {
				results[0], results[1] = results[1], results[0]
			}
			err = persistRunResults(t.Context(), &ro, results, summary, true)
			if mode == "missing" || mode == "duplicate" {
				require.Error(t, err)
				require.Empty(t, types)
				require.NoFileExists(t, ro.OutFilePath)
				return
			}
			require.NoError(t, err)
			if mode == "legacy-misnamed" {
				require.Equal(t, []string{material.ManifestType, attestation.CollectionType}, types)
			} else {
				require.Equal(t, []string{attestation.CollectionType}, types)
				require.FileExists(t, summary.Inventories[0].Path)
				require.False(t, summary.Inventories[0].Uploaded)
			}
		})
	}
}
