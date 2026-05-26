// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package policy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aflock-ai/rookery/attestation/chain"
)

// TestHTTPChainSidecarSource_DefaultsApplied asserts the default
// constructor honours the compiled-in DefaultHTTPChainSidecarTimeout
// and DefaultHTTPChainSidecarMaxBytes constants. If either default
// drifts, the regression test fails — flagging the change for
// review against docs/configuration.md.
func TestHTTPChainSidecarSource_DefaultsApplied(t *testing.T) {
	s := NewHTTPChainSidecarSource("https://example.test/{envelopeDigest}")
	if s.Client.Timeout != DefaultHTTPChainSidecarTimeout {
		t.Fatalf("default client timeout: got %v, want %v", s.Client.Timeout, DefaultHTTPChainSidecarTimeout)
	}
	if s.MaxBodyBytes != DefaultHTTPChainSidecarMaxBytes {
		t.Fatalf("default max body: got %d, want %d", s.MaxBodyBytes, DefaultHTTPChainSidecarMaxBytes)
	}
}

// TestHTTPChainSidecarSource_OverrideTimeoutAndMaxBytes covers the
// --chain-sidecar-http-timeout and --chain-sidecar-http-max-bytes
// CLI flag plumbing path.
func TestHTTPChainSidecarSource_OverrideTimeoutAndMaxBytes(t *testing.T) {
	custom := NewHTTPChainSidecarSourceWithOptions("https://example.test/{envelopeDigest}", 5*time.Second, 1<<20)
	if custom.Client.Timeout != 5*time.Second {
		t.Fatalf("override timeout: got %v, want 5s", custom.Client.Timeout)
	}
	if custom.MaxBodyBytes != 1<<20 {
		t.Fatalf("override max body: got %d, want %d", custom.MaxBodyBytes, 1<<20)
	}

	// Zero values fall back to defaults — the helper must never produce
	// an unbounded source.
	zero := NewHTTPChainSidecarSourceWithOptions("https://example.test/{envelopeDigest}", 0, 0)
	if zero.Client.Timeout != DefaultHTTPChainSidecarTimeout {
		t.Fatalf("zero timeout did not fall back to default")
	}
	if zero.MaxBodyBytes != DefaultHTTPChainSidecarMaxBytes {
		t.Fatalf("zero max body did not fall back to default")
	}
}

// TestHTTPChainSidecarSource_MaxBodyEnforced verifies the operator's
// --chain-sidecar-http-max-bytes cap is actually enforced at read
// time. A server returning a body LARGER than the cap must produce
// a JSON decode error (the truncated body is not a valid sidecar).
func TestHTTPChainSidecarSource_MaxBodyEnforced(t *testing.T) {
	huge := chain.ChainSidecar{
		SchemaVersion: chain.ChainSidecarSchemaVersion,
		SourceStep: chain.SourceStepRef{
			StepName:       "source",
			EnvelopeDigest: "deadbeef",
			MerkleRoot:     "feedface",
			TreeSize:       1,
		},
	}
	body, err := json.Marshal(huge)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	// Cap of 4 bytes — far smaller than the body — so the reader will
	// see truncated JSON and fail to decode. This exercises the
	// MaxBodyBytes path.
	s := NewHTTPChainSidecarSourceWithOptions(srv.URL+"/{envelopeDigest}", 30*time.Second, 4)
	_, err = s.LookupChainSidecar(context.Background(), "downstream", "source", "deadbeef")
	if err == nil {
		t.Fatal("expected error from truncated body when --chain-sidecar-http-max-bytes is small")
	}
	if !strings.Contains(err.Error(), "decode body") {
		t.Fatalf("expected decode-body error, got: %v", err)
	}
}
