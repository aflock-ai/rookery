// jade:ring local

// Copyright 2026 The Aflock Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/workflow"
	"github.com/aflock-ai/rookery/cilock/internal/options"
	"github.com/stretchr/testify/require"
)

const retainStatement = `{"_type":"https://in-toto.io/Statement/v0.1","predicateType":"https://witness.dev/attestations/collection/v0.1","subject":[],"predicate":{}}`

func retainResults() []workflow.RunResult {
	return []workflow.RunResult{{SignedEnvelope: dsse.Envelope{Payload: []byte(retainStatement), PayloadType: "application/vnd.in-toto+json"}}}
}

func isolateRetainStore(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GITHUB_ACTIONS", "")
}

func TestUnstoredEnvelopeIsKeptOnDiskWhenNoOutfileIsGiven(t *testing.T) {
	isolateRetainStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Invalid API credential", http.StatusUnauthorized)
	}))
	defer srv.Close()

	ro := options.RunOptions{PlatformURL: srv.URL}
	ro.ArchivistaOptions = options.ArchivistaOptions{Enable: true, Url: srv.URL}
	err := persistRunResults(t.Context(), &ro, retainResults(), &options.RunSummary{}, false)
	require.Error(t, err)

	msg := err.Error()
	require.Contains(t, msg, "signed envelope kept at ")
	require.Contains(t, msg, "--data-binary @")
	require.Contains(t, msg, srv.URL+"/upload")
	start := strings.Index(msg, "signed envelope kept at ") + len("signed envelope kept at ")
	kept, _, _ := strings.Cut(msg[start:], "\n")
	body, readErr := os.ReadFile(kept)
	require.NoError(t, readErr)
	var env dsse.Envelope
	require.NoError(t, json.Unmarshal(body, &env))
	require.JSONEq(t, retainStatement, string(env.Payload))
}

func TestUnstoredEnvelopeNamesTheOperatorsOutfile(t *testing.T) {
	isolateRetainStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadRequest)
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "run.json")
	ro := options.RunOptions{PlatformURL: srv.URL, OutFilePath: out}
	ro.ArchivistaOptions = options.ArchivistaOptions{Enable: true, Url: srv.URL}
	err := persistRunResults(t.Context(), &ro, retainResults(), &options.RunSummary{}, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "signed envelope kept at "+out)
	require.FileExists(t, out)
}

func TestRetainedEvidenceErrorSaysWhenNothingWasKept(t *testing.T) {
	err := retainedEvidenceError(errors.New("cause"), "", "https://x")
	require.ErrorContains(t, err, "could NOT be kept")
	require.ErrorContains(t, err, "cause")
}

func TestUploadSurvivesAnExpiredFirstTokenThroughTheRefresh(t *testing.T) {
	isolateRetainStore(t)
	var fresh atomic.Bool
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		if r.Header.Get("Authorization") != "Bearer fresh" {
			http.Error(w, "Invalid API credential", http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"gitoid":"stored"}`))
	}))
	defer srv.Close()

	token := "expired"
	ro := options.RunOptions{PlatformURL: srv.URL}
	ro.ArchivistaOptions = options.ArchivistaOptions{
		Enable:          true,
		Url:             srv.URL,
		AuthTokenSource: func() (string, error) { return token, nil },
		AuthRefresh:     func() error { token = "fresh"; fresh.Store(true); return nil },
	}
	require.NoError(t, persistRunResults(t.Context(), &ro, retainResults(), &options.RunSummary{}, false))
	require.True(t, fresh.Load())
	require.EqualValues(t, 2, atomic.LoadInt64(&calls))
}
