// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/chain"
	"github.com/stretchr/testify/require"
)

func writeSidecarFile(t *testing.T, dir, step string, sc chain.ChainSidecar) string {
	t.Helper()
	body, err := json.Marshal(sc)
	require.NoError(t, err)
	p := filepath.Join(dir, step+".chain.json")
	require.NoError(t, os.WriteFile(p, body, 0o600))
	return p
}

func TestFilesystemChainSidecarSource_HappyPath(t *testing.T) {
	dir := t.TempDir()
	want := chain.ChainSidecar{
		SchemaVersion: chain.ChainSidecarSchemaVersion,
		SourceStep: chain.SourceStepRef{
			StepName:       "source",
			EnvelopeDigest: "deadbeef",
			MerkleRoot:     "feedface",
			TreeSize:       3,
			Domain:         "rookery-product/v0.3",
		},
	}
	writeSidecarFile(t, dir, "build", want)

	src := NewFilesystemChainSidecarSource(dir)
	got, err := src.LookupChainSidecar(context.Background(), "build", "source", "deadbeef")
	require.NoError(t, err)
	require.NotNil(t, got)
	require.Equal(t, want.SourceStep.EnvelopeDigest, got.SourceStep.EnvelopeDigest)
}

func TestFilesystemChainSidecarSource_NotPresent_ReturnsNilNoError(t *testing.T) {
	src := NewFilesystemChainSidecarSource(t.TempDir())
	got, err := src.LookupChainSidecar(context.Background(), "build", "source", "deadbeef")
	require.NoError(t, err)
	require.Nil(t, got, "missing sidecar must be (nil, nil) — verifier falls through to legacy comparison")
}

func TestFilesystemChainSidecarSource_EmptyDir_Disabled(t *testing.T) {
	src := NewFilesystemChainSidecarSource("")
	got, err := src.LookupChainSidecar(context.Background(), "build", "source", "deadbeef")
	require.NoError(t, err)
	require.Nil(t, got, "empty Dir must short-circuit to disabled source")
}

func TestFilesystemChainSidecarSource_RefusesPathTraversal(t *testing.T) {
	src := NewFilesystemChainSidecarSource(t.TempDir())
	_, err := src.LookupChainSidecar(context.Background(), "../etc/passwd", "source", "deadbeef")
	require.Error(t, err)
	require.Contains(t, err.Error(), "path-bearing step name")
}

func TestFilesystemChainSidecarSource_WrongEnvelopeDigest(t *testing.T) {
	dir := t.TempDir()
	writeSidecarFile(t, dir, "build", chain.ChainSidecar{
		SchemaVersion: chain.ChainSidecarSchemaVersion,
		SourceStep: chain.SourceStepRef{
			StepName:       "source",
			EnvelopeDigest: "aaaa", // sidecar claims this upstream envelope
			MerkleRoot:     "feedface",
			TreeSize:       3,
		},
	})

	src := NewFilesystemChainSidecarSource(dir)
	_, err := src.LookupChainSidecar(context.Background(), "build", "source", "bbbb") // verifier expects different
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "binds to envelope") || strings.Contains(err.Error(), "envelope"),
		"expected envelope-mismatch diagnostic, got: %v", err)
}

func TestFilesystemChainSidecarSource_WrongSourceStepName(t *testing.T) {
	dir := t.TempDir()
	writeSidecarFile(t, dir, "build", chain.ChainSidecar{
		SchemaVersion: chain.ChainSidecarSchemaVersion,
		SourceStep: chain.SourceStepRef{
			StepName:       "vendor", // sidecar's claimed source
			EnvelopeDigest: "deadbeef",
		},
	})

	src := NewFilesystemChainSidecarSource(dir)
	_, err := src.LookupChainSidecar(context.Background(), "build", "source", "deadbeef") // policy edge says upstream is "source"
	require.Error(t, err)
	require.Contains(t, err.Error(), "sourceStep")
}

func TestFilesystemChainSidecarSource_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "build.chain.json"), []byte("not json"), 0o600))
	src := NewFilesystemChainSidecarSource(dir)
	_, err := src.LookupChainSidecar(context.Background(), "build", "source", "deadbeef")
	require.Error(t, err)
}
