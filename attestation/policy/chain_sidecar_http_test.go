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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/chain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPChainSidecarSource_HappyPath(t *testing.T) {
	want := chain.ChainSidecar{
		SchemaVersion: chain.ChainSidecarSchemaVersion,
		SourceStep: chain.SourceStepRef{
			StepName:       "source",
			EnvelopeDigest: "deadbeef",
			MerkleRoot:     "feedface",
			TreeSize:       3,
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/sidecar/deadbeef.chain.json", r.URL.Path,
			"URL template must substitute {envelopeDigest}")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	src := NewHTTPChainSidecarSource(srv.URL + "/sidecar/{envelopeDigest}.chain.json")
	got, err := src.LookupChainSidecar(context.Background(), "build", "source", "deadbeef")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, want.SourceStep.EnvelopeDigest, got.SourceStep.EnvelopeDigest)
}

func TestHTTPChainSidecarSource_404_ReturnsNilNoError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer srv.Close()

	src := NewHTTPChainSidecarSource(srv.URL + "/sidecar/{envelopeDigest}.chain.json")
	got, err := src.LookupChainSidecar(context.Background(), "build", "source", "missing")
	require.NoError(t, err)
	assert.Nil(t, got, "404 must surface as (nil, nil) so the verifier falls through")
}

func TestHTTPChainSidecarSource_500_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	src := NewHTTPChainSidecarSource(srv.URL + "/sidecar/{envelopeDigest}.chain.json")
	_, err := src.LookupChainSidecar(context.Background(), "build", "source", "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status 500")
}

func TestHTTPChainSidecarSource_Disabled_WhenURLEmpty(t *testing.T) {
	src := NewHTTPChainSidecarSource("")
	got, err := src.LookupChainSidecar(context.Background(), "build", "source", "x")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestHTTPChainSidecarSource_HeadersForwarded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer xyz", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(chain.ChainSidecar{SchemaVersion: chain.ChainSidecarSchemaVersion})
	}))
	defer srv.Close()

	src := NewHTTPChainSidecarSource(srv.URL + "/x/{envelopeDigest}")
	src.Headers = map[string]string{"Authorization": "Bearer xyz"}
	_, err := src.LookupChainSidecar(context.Background(), "build", "source", "abc")
	require.NoError(t, err)
}

func TestHTTPChainSidecarSource_WrongEnvelopeBinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(chain.ChainSidecar{
			SchemaVersion: chain.ChainSidecarSchemaVersion,
			SourceStep:    chain.SourceStepRef{StepName: "source", EnvelopeDigest: "aaa"},
		})
	}))
	defer srv.Close()

	src := NewHTTPChainSidecarSource(srv.URL + "/x/{envelopeDigest}")
	_, err := src.LookupChainSidecar(context.Background(), "build", "source", "bbb")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binds to envelope")
}

func TestMultiChainSidecarSource_FirstNonNilWins(t *testing.T) {
	// First source has nothing (filesystem with no file).
	first := NewFilesystemChainSidecarSource(t.TempDir())
	// Second source serves the sidecar.
	want := chain.ChainSidecar{
		SchemaVersion: chain.ChainSidecarSchemaVersion,
		SourceStep:    chain.SourceStepRef{StepName: "source", EnvelopeDigest: "abc"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()
	second := NewHTTPChainSidecarSource(srv.URL + "/{envelopeDigest}")

	multi := NewMultiChainSidecarSource(first, second)
	got, err := multi.LookupChainSidecar(context.Background(), "build", "source", "abc")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "abc", got.SourceStep.EnvelopeDigest)
}

func TestMultiChainSidecarSource_ErrorAbortsChain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "broken", http.StatusInternalServerError)
	}))
	defer srv.Close()
	first := NewHTTPChainSidecarSource(srv.URL + "/{envelopeDigest}")
	second := NewFilesystemChainSidecarSource(t.TempDir()) // never reached

	multi := NewMultiChainSidecarSource(first, second)
	_, err := multi.LookupChainSidecar(context.Background(), "build", "source", "x")
	require.Error(t, err, "first-source error must abort, not silently fall through to second")
	assert.True(t, strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "broken"))
}
