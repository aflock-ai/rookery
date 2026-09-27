// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aflock-ai/rookery/attestation/dsse"
	"github.com/aflock-ai/rookery/attestation/intoto"
	inclusionproof "github.com/aflock-ai/rookery/plugins/attestors/inclusion-proof"
	"github.com/aflock-ai/rookery/plugins/attestors/material"
)

// The companion size guards. Every path that reads or indexes a companion
// must refuse an oversized one BEFORE reading, decoding, compacting or
// hashing it: the advertised resource ceiling (inclusionproof.MaxManifestBytes)
// is only real if it is enforced ahead of the allocation it bounds. The tests
// fake size — a sparse file whose inode reports one byte over the file
// ceiling while holding no data, and small in-memory limits — so nothing here
// allocates the ceiling.

// TestReadCompanionFileRefusesBySizeBeforeReading: a sparse file that STATS
// over the real file ceiling (the predicate limit carried through base64 and
// the envelope, see companionCeilings) is refused from its size alone. If the
// guard read first, this test would allocate the better part of a gigabyte;
// it does not.
func TestReadCompanionFileRefusesBySizeBeforeReading(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json-material-manifest.json")
	f, err := os.Create(path) //nolint:gosec // test fixture under t.TempDir
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(companionFileLimit + 1); err != nil {
		t.Fatalf("truncate (sparse): %v", err)
	}
	_ = f.Close()

	_, err = readCompanionFile(path)
	if !errors.Is(err, errCompanionTooLarge) {
		t.Fatalf("a companion whose inode size exceeds the file ceiling must be refused before reading, got %v", err)
	}
	if !strings.Contains(err.Error(), "MaxManifestBytes") {
		t.Fatalf("the refusal must name the limit: %v", err)
	}

	// The manifest index reads only what discovery decoded, and discovery
	// reads through the bounded reader: the oversized file is refused there,
	// for the size, so nothing of it reaches the index.
	if _, err := readSidecar(path, "manifest"); !errors.Is(err, errCompanionTooLarge) {
		t.Fatalf("sidecar discovery must refuse a companion over the limit for its size, got %v", err)
	}
	// Discovery next to the bundle keeps it only as a named reject, so
	// nothing of it reaches the index and a refusal can say why.
	set, err := discoverSidecarSet(filepath.Join(filepath.Dir(path), "bundle.json"))
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(set.found) != 0 || len(set.rejected) != 1 || !errors.Is(set.rejected[0].reason, errCompanionTooLarge) {
		t.Fatalf("discovery must reject the oversized companion for its size, got found=%d rejected=%+v", len(set.found), set.rejected)
	}
	ix, _ := sidecarManifests(set.found)
	if len(ix) != 0 {
		t.Fatalf("the manifest index read a companion over the limit: %d entries", len(ix))
	}
}

// TestReadCompanionFileBoundsTheReadItself: the stat is not the only guard.
// A file that is within the limit at stat time but streams more than the
// limit (here: the limit is lowered to a few bytes after the file exists)
// is still refused, by one byte over, never by reading everything.
func TestReadCompanionFileBoundsTheReadItself(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bundle.json-material-manifest.json")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 64)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	prev := companionFileLimit
	companionFileLimit = 63
	t.Cleanup(func() { companionFileLimit = prev })

	if _, err := readCompanionFile(path); !errors.Is(err, errCompanionTooLarge) {
		t.Fatalf("64 bytes against a 63-byte limit must be refused, got %v", err)
	}
	companionFileLimit = 64
	if data, err := readCompanionFile(path); err != nil || len(data) != 64 {
		t.Fatalf("64 bytes against a 64-byte limit must read in full, got len=%d err=%v", len(data), err)
	}
}

// TestReadBoundedRefusesOverflow pins the stream reader used for sources
// without a size: it reads limit+1 at most and refuses on the extra byte.
func TestReadBoundedRefusesOverflow(t *testing.T) {
	if _, err := readBounded(strings.NewReader(strings.Repeat("y", 11)), 10); !errors.Is(err, errCompanionTooLarge) {
		t.Fatalf("11 bytes against a 10-byte limit must be refused, got %v", err)
	}
	data, err := readBounded(strings.NewReader(strings.Repeat("y", 10)), 10)
	if err != nil || len(data) != 10 {
		t.Fatalf("10 bytes against a 10-byte limit must read in full, got len=%d err=%v", len(data), err)
	}
}

// TestIndexSkipsOversizedCompanionsBeforeHashing: an envelope already in
// memory (loaded via --attestations / a bundle) whose payload or predicate
// exceeds the limit is not decoded, compacted or hashed — it is simply not
// indexed. The same envelope under a limit that admits it IS indexed, which
// is what proves the guard, not the fixture, made the difference.
func TestIndexSkipsOversizedCompanionsBeforeHashing(t *testing.T) {
	predicate, digest, _ := buildManifestSidecarBytes(t, map[string]string{
		"bin/app": manifestTestDigest("app-binary"),
	})
	payload, err := json.Marshal(intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: material.ManifestType,
		Predicate:     json.RawMessage(predicate),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	env := dsse.Envelope{PayloadType: intoto.PayloadType, Payload: payload}

	prevPred, prevPay := companionPredicateLimit, companionPayloadLimit
	t.Cleanup(func() { companionPredicateLimit, companionPayloadLimit = prevPred, prevPay })

	// Control: admitted under a limit that fits it.
	companionPredicateLimit, companionPayloadLimit = len(predicate), len(payload)
	if ix := indexMaterialManifests([]dsse.Envelope{env}); len(ix) != 1 || ix[digest] == nil {
		t.Fatalf("a manifest within the limits must be indexed under its digest, got %d entries", len(ix))
	}

	// One byte under the predicate size: skipped before compaction/hash.
	companionPredicateLimit, companionPayloadLimit = len(predicate)-1, len(payload)
	if ix := indexMaterialManifests([]dsse.Envelope{env}); len(ix) != 0 {
		t.Fatalf("a manifest predicate over the limit was compacted and hashed into the index: %d entries", len(ix))
	}

	// One byte under the payload size: skipped before base64/JSON decoding.
	companionPredicateLimit, companionPayloadLimit = len(predicate), len(payload)-1
	if ix := indexMaterialManifests([]dsse.Envelope{env}); len(ix) != 0 {
		t.Fatalf("a payload over the limit was decoded into the index: %d entries", len(ix))
	}
}

// TestCompanionCeilingsAdmitEveryManifestTheProducerMayEmit: the producer's
// limit is on the COMPACT PREDICATE (inclusionproof.MaxManifestBytes). On its
// way to disk that predicate is framed in a statement, base64-encoded into a
// DSSE payload, and wrapped in an envelope with signatures — so a file-size
// ceiling equal to the predicate limit refuses every conforming manifest above
// roughly three quarters of it. Each consumer ceiling must be the predicate
// limit carried through that encoding, not the predicate limit reused in a
// different unit.
func TestCompanionCeilingsAdmitEveryManifestTheProducerMayEmit(t *testing.T) {
	// Production values, by arithmetic: no allocation of the real limit.
	wantPayload := base64.StdEncoding.EncodedLen(inclusionproof.MaxManifestBytes)
	if companionPayloadLimit < wantPayload {
		t.Errorf("companionPayloadLimit %d cannot hold the base64 of a %d-byte predicate (%d)", companionPayloadLimit, inclusionproof.MaxManifestBytes, wantPayload)
	}
	if companionFileLimit < int64(wantPayload) {
		t.Errorf("companionFileLimit %d is below the base64 payload of a predicate at the producer's limit (%d): a conforming manifest above ~3/4 of MaxManifestBytes would be refused on disk", companionFileLimit, wantPayload)
	}
	if companionPredicateLimit != inclusionproof.MaxManifestBytes {
		t.Errorf("companionPredicateLimit %d != MaxManifestBytes %d", companionPredicateLimit, inclusionproof.MaxManifestBytes)
	}

	// The same derivation, exercised end to end at a small scale: a real
	// envelope whose predicate is EXACTLY the (scaled) producer limit, with a
	// signature block of realistic size, must be readable from disk and
	// indexable — through the production reader and index, with every ceiling
	// derived from the one limit by the production function.
	predicate, digest, _ := buildManifestSidecarBytes(t, map[string]string{
		"bin/app": manifestTestDigest("app-binary"),
		"bin/lib": manifestTestDigest("lib-binary"),
	})
	payload, err := json.Marshal(intoto.Statement{
		Type:          "https://in-toto.io/Statement/v0.1",
		PredicateType: material.ManifestType,
		Predicate:     json.RawMessage(predicate),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Payload is the raw statement: encoding/json base64-encodes the []byte on
	// the wire, which is exactly the expansion the file ceiling must absorb.
	env := dsse.Envelope{
		PayloadType: intoto.PayloadType,
		Payload:     payload,
		Signatures: []dsse.Signature{{
			KeyID:       "companion-limit-test",
			Signature:   bytes.Repeat([]byte{0xab}, 64),
			Certificate: bytes.Repeat([]byte{0xcd}, 2048),
		}},
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json-material-manifest.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	prevPred, prevPay, prevFile := companionPredicateLimit, companionPayloadLimit, companionFileLimit
	t.Cleanup(func() {
		companionPredicateLimit, companionPayloadLimit, companionFileLimit = prevPred, prevPay, prevFile
	})
	companionPredicateLimit = len(predicate)
	companionPayloadLimit, companionFileLimit = companionCeilings(len(predicate))

	if _, err := readCompanionFile(path); err != nil {
		t.Fatalf("a companion carrying a predicate exactly at the producer's limit must be readable, got %v", err)
	}
	side, err := readSidecar(path, "manifest")
	if err != nil {
		t.Fatalf("sidecar discovery refused a companion whose predicate is exactly at the producer's limit: %v", err)
	}
	if side.predicateType != material.ManifestType {
		t.Fatalf("discovery read predicate type %q, want %q", side.predicateType, material.ManifestType)
	}
	ix, _ := sidecarManifests([]sidecarSummary{side})
	if len(ix) != 1 || ix[digest] == nil {
		t.Fatalf("the manifest index dropped a companion at the producer's limit: %d entries", len(ix))
	}
	if ix2 := indexMaterialManifests([]dsse.Envelope{env}); len(ix2) != 1 || ix2[digest] == nil {
		t.Fatalf("the in-memory index dropped an envelope at the producer's limit: %d entries", len(ix2))
	}
}
