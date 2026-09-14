// Copyright 2026 TestifySec, Inc.
// SPDX-License-Identifier: Apache-2.0

// jade:ring local

package options

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aflock-ai/rookery/cilock/internal/config"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestRunInventoryConsentFlag(t *testing.T) {
	var ro RunOptions
	cmd := &cobra.Command{}
	ro.AddFlags(cmd)
	require.False(t, ro.UploadInventories)
	require.NoError(t, cmd.ParseFlags([]string{"--upload-inventories"}))
	require.True(t, ro.UploadInventories)
	require.False(t, ro.MaterialManifest, "upload consent must not enable material retention")
}

func TestRunInventoryCompiledChainDefaults(t *testing.T) {
	profile, budget := config.DefaultEvidenceProfile, config.DefaultProductInlineBytes
	t.Cleanup(func() { config.DefaultEvidenceProfile, config.DefaultProductInlineBytes = profile, budget })
	config.DefaultProductInlineBytes = "131072"
	for _, tt := range []struct {
		name, profile  string
		flags          []string
		retain, upload bool
	}{
		{"stock", "compact", nil, false, false},
		{"chain", "compact-chain", nil, true, true},
		{"legacy", "legacy", nil, false, false},
		{"no-retention", "compact-chain", []string{"--material-manifest=false"}, false, true},
		{"no-upload", "compact-chain", []string{"--upload-inventories=false"}, true, false},
		{"offline", "compact-chain", []string{"--offline"}, true, false},
		{"platform-disabled", "compact-chain", []string{"--platform-url", ""}, true, false},
		{"store-disabled", "compact-chain", []string{"--platform-url", "https://inventory-test.invalid", "--enable-archivista=false"}, true, false},
		{"explicit-upload-store-disabled", "compact-chain", []string{"--platform-url", "https://inventory-test.invalid", "--enable-archivista=false", "--upload-inventories"}, true, true},
		{"explicit-offline-upload", "compact-chain", []string{"--offline", "--upload-inventories"}, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config.DefaultEvidenceProfile = tt.profile
			var ro RunOptions
			cmd := &cobra.Command{}
			ro.AddFlags(cmd)
			require.NoError(t, cmd.ParseFlags(tt.flags))
			if ro.Offline || cmd.Flags().Changed("platform-url") {
				ro.ResolvePlatformDefaults(cmd)
			}
			require.Equal(t, tt.retain, ro.MaterialManifest)
			require.Equal(t, tt.upload, ro.UploadInventories)
			require.False(t, ro.ArchivistaOptions.Enable, "the build profile must not enable a network destination")
			require.Nil(t, cmd.Flags().Lookup("evidence-profile"), "profile selection stays build-time only")
		})
	}
}

func TestRunInventoryCompiledPreflight(t *testing.T) {
	profile := config.DefaultEvidenceProfile
	t.Cleanup(func() { config.DefaultEvidenceProfile = profile })
	config.DefaultEvidenceProfile = "invalid"
	var ro RunOptions
	ran := false
	cmd := &cobra.Command{RunE: func(*cobra.Command, []string) error { ran = true; return nil }}
	ro.AddFlags(cmd)
	cmd.SetArgs([]string{"--step", "probe"})
	require.ErrorContains(t, cmd.ExecuteContext(t.Context()), "compiled evidence profile")
	require.False(t, ran, "every RunOptions command must refuse before its identity resolution")
}

func TestRunInventorySummaryStates(t *testing.T) {
	s := RunSummary{Inventories: []RunInventory{
		{Kind: "material", State: "omitted", FileCount: 3},
		{Kind: "product", State: "detached", FileCount: 2, Path: "/private/inventory\x1b.json", Digest: "digest", Bytes: 200},
	}}
	var out bytes.Buffer
	require.NoError(t, s.WriteJSON(&out))
	var decoded map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &decoded))
	entries := decoded["inventories"].([]any)
	require.Equal(t, false, entries[1].(map[string]any)["uploaded"])
	require.NotContains(t, entries[0].(map[string]any), "path")
	out.Reset()
	s.WriteHuman(&out)
	require.Contains(t, out.String(), "material: omitted")
	require.Contains(t, out.String(), "not retained")
	require.Contains(t, out.String(), `/private/inventory\x1b.json`)
	require.NotContains(t, out.String(), "\x1b")
	require.NotContains(t, out.String(), "inventory uploaded")
	s.Inventories[1].Uploaded, s.Inventories[1].Gitoid = true, "stored-id"
	out.Reset()
	s.WriteHuman(&out)
	require.Contains(t, out.String(), "inventory uploaded: stored-id")
}

func TestRunInventoryFailedUploadSummaryDoesNotClaimDisabled(t *testing.T) {
	s := RunSummary{ArchivistaURL: "https://store.example", Uploaded: false}
	var out bytes.Buffer
	s.WriteHuman(&out)
	require.NotContains(t, out.String(), "DISABLED", "absence of a successful store is not proof that upload was disabled")
	require.Contains(t, out.String(), "NO evidence stored for the collection")
}
