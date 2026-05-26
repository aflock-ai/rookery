// Copyright 2026 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//go:build linux

package commandrun

import (
	"crypto"
	"errors"
	"os"
	"sync/atomic"
	"syscall"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/aflock-ai/rookery/attestation/log"
)

// EnvVarFsVerity controls opportunistic fs-verity sealing of product
// files. Values:
//   - "" / "0" / "off": disabled
//   - "auto": probe at startup; seal each product where supported
//   - "1" / "on": REQUIRE successful probe; error if FS doesn't support
const EnvVarFsVerity = "CILOCK_FSVERITY"

// fsVerityState tracks the trace-wide fs-verity sealing operation.
// Probed once at trace start; the per-product seal calls consult
// Available to skip the ioctl entirely on unsupported filesystems.
type fsVerityState struct {
	Available    bool
	ProbeError   error
	Sealed       atomic.Uint64
	SealFailures atomic.Uint64
	Skipped      atomic.Uint64
}

// probeFsVerity decides whether to enable fs-verity sealing for
// this trace. Returns nil + state when disabled; state with
// Available=true when the FS supports it; error when explicitly
// required but unsupported.
func probeFsVerity(workspaceDir string) (*fsVerityState, error) {
	mode := os.Getenv(EnvVarFsVerity)
	switch mode {
	case "", "0", "off":
		return nil, nil
	case tokenAuto, "1", "on":
		// continue
	default:
		log.Debugf("(fsverity) unknown %s=%q; disabled", EnvVarFsVerity, mode)
		return nil, nil
	}
	required := mode == "1" || mode == "on"
	state := &fsVerityState{}
	if err := cryptoutil.VeritySupported(workspaceDir); err != nil {
		state.ProbeError = err
		if required {
			return nil, &fsVerityUnavailableError{cause: err}
		}
		log.Debugf("(fsverity) probe failed (auto-mode): %v", err)
		return state, nil
	}
	state.Available = true
	log.Debugf("(fsverity) probe OK on %s; sealing enabled", workspaceDir)
	return state, nil
}

// sealProduct opportunistically enables fs-verity on the given path
// and reads back the Merkle root. Returns the hex digest on success
// (suitable for storing in DigestSet with src: "fs-verity"), or
// empty string if sealing wasn't possible.
//
// Errors are non-fatal: we always update counters and return the
// caller's previous digest as fallback. Fs-verity is a strict
// upgrade — if it works, great; if not, the streaming digest stands.
func (s *fsVerityState) sealProduct(path string) string {
	if s == nil || !s.Available {
		if s != nil {
			s.Skipped.Add(1)
		}
		return ""
	}
	if err := cryptoutil.EnableVerity(path, 0); err != nil {
		// EEXIST means already enabled — proceed to read.
		if !errors.Is(err, syscall.EEXIST) {
			// Other errors: log + bail. Common: EOPNOTSUPP on some
			// specific file (e.g., not on the verity-enabled FS).
			s.SealFailures.Add(1)
			log.Debugf("(fsverity) EnableVerity %s: %v", path, err)
			return ""
		}
	}
	hex, err := cryptoutil.VerityHexDigest(path)
	if err != nil || hex == "" {
		s.SealFailures.Add(1)
		log.Debugf("(fsverity) MeasureVerity %s: %v", path, err)
		return ""
	}
	s.Sealed.Add(1)
	return hex
}

// fsVeritySHA256DigestValue is the cryptoutil.DigestValue used to
// tag fs-verity Merkle roots in OpenedFiles / WrittenDigests. The
// Hash is SHA-256 (the kernel default fs-verity algorithm). We
// distinguish via map convention: a non-empty entry under this
// key paired with the existing streaming SHA-256 entry signals
// "kernel-rooted Merkle root captured."
func fsVeritySHA256DigestValue() cryptoutil.DigestValue {
	return cryptoutil.DigestValue{Hash: crypto.SHA256, GitOID: false}
}

type fsVerityUnavailableError struct {
	cause error
}

func (e *fsVerityUnavailableError) Error() string {
	return "fs-verity required but unsupported on workspace FS: " + e.cause.Error()
}

func (e *fsVerityUnavailableError) Unwrap() error { return e.cause }
