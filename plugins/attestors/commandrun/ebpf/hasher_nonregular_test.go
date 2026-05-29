// Copyright 2026 The Rookery Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package ebpf

import (
	"crypto"
	"os"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestHashOpenatEvent_NonRegularTagged asserts that hashing an openat of a
// non-regular file (/dev/null — a char device every build opens) yields
// NonRegular=true, so the dispatcher suppresses it instead of recording a
// spurious "unhashed open" gap. Char devices have no hashable content and
// are not materials.
func TestHashOpenatEvent_NonRegularTagged(t *testing.T) {
	hf := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	// FD=-1 forces the path-based hasher (hashViaPath), which stats the
	// path and refuses non-regular files.
	res := HashOpenatEvent(&OpenatEvent{Path: "/dev/null", FD: -1}, hf)
	if !res.NonRegular {
		t.Fatalf("/dev/null should be tagged NonRegular; got status=%q reason=%q", res.Status, res.Reason)
	}
	if res.Status != TOCTOUError {
		t.Errorf("expected TOCTOUError status for non-regular, got %q", res.Status)
	}
}

// TestHashOpenatEvent_RegularFileNotTagged is the control: a real regular
// file must NOT be flagged NonRegular.
func TestHashOpenatEvent_RegularFileNotTagged(t *testing.T) {
	hf := []cryptoutil.DigestValue{{Hash: crypto.SHA256}}
	f := t.TempDir() + "/material.txt"
	if err := os.WriteFile(f, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := HashOpenatEvent(&OpenatEvent{Path: f, FD: -1}, hf)
	if res.NonRegular {
		t.Fatalf("regular file wrongly tagged NonRegular; reason=%q", res.Reason)
	}
}
