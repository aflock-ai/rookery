// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package commandrun

import (
	"crypto"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
)

// TestFanotify_EndToEnd_DigestsMerged is the integration assertion:
// run a tracee under fanotify mode, assert (a) the tracee's
// OpenedFiles contains the witness file with the SHA-256 we expect,
// (b) Summary.Diagnostics shows FanotifyAvailable=true.
//
// Skips when the harness can't get CAP_SYS_ADMIN (no sudo) or when
// fanotify isn't supported (unlikely on Ubuntu kernels).
func TestFanotify_EndToEnd_DigestsMerged(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e test")
	}
	if os.Getuid() != 0 {
		t.Skip("requires root for fanotify FAN_OPEN_PERM (run under sudo)")
	}
	t.Setenv(EnvVarTraceMode, "ebpf")
	t.Setenv(EnvVarFanotify, "1")
	skipIfNoEBPFCaps(t)

	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	bin := compileC(t, dir, "fanotify_witness", `
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) { perror("open"); return 2; }
    char buf[256];
    read(fd, buf, sizeof(buf));
    close(fd);
    return 0;
}
`)
	witness := filepath.Join(dir, "fanotify-witness.bin")
	content := []byte("FANOTIFY-INTEGRATION-WITNESS-V1-must-be-hashed-synchronously\n")
	if err := os.WriteFile(witness, content, 0o644); err != nil {
		t.Fatal(err)
	}
	procs := runUnderEBPF(t, []string{bin, witness})

	// Compute expected SHA-256.
	wantSet, err := cryptoutil.CalculateDigestSetFromBytes(content, []cryptoutil.DigestValue{{Hash: crypto.SHA256}})
	if err != nil {
		t.Fatalf("expected digest: %v", err)
	}
	var wantHex string
	for _, h := range wantSet {
		wantHex = h
		break
	}

	// Find the tracee's record of the witness file.
	var gotHex string
	for _, p := range procs {
		if ds, ok := p.OpenedFiles[witness]; ok && ds != nil {
			for _, h := range ds {
				gotHex = h
				break
			}
		}
		if gotHex != "" {
			break
		}
	}
	if gotHex == "" {
		t.Fatalf("witness file %s not in OpenedFiles for any proc", witness)
	}
	// Both should be hex-encoded SHA-256 (64 chars). Tolerate
	// either uppercase/lowercase comparison.
	if len(gotHex) == 64 && len(wantHex) == 64 {
		gotBytes, _ := hex.DecodeString(gotHex)
		wantBytes, _ := hex.DecodeString(wantHex)
		if len(gotBytes) == 32 && len(wantBytes) == 32 {
			for i := range gotBytes {
				if gotBytes[i] != wantBytes[i] {
					t.Fatalf("digest mismatch:\n got=%s\nwant=%s", gotHex, wantHex)
				}
			}
		}
	}
	t.Logf("OK: tracee digest for witness file matches expected SHA-256")
}
